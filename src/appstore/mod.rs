// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! App Store — browse and install popular applications with one click
//!
//! Supports three deployment targets:
//! - Docker containers (pull image, create container with preconfigured settings)
//! - LXC containers (create from template, run setup commands)
//! - Bare metal (install packages directly on the host)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;


// ─── Manifest types ───

/// How to install an app via Docker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerTarget {
    pub image: String,
    pub ports: Vec<String>,
    pub env: Vec<String>,
    pub volumes: Vec<String>,
    /// Optional secondary containers (e.g. a database)
    #[serde(default)]
    pub sidecars: Vec<DockerSidecar>,
    /// Files to seed into the container's volumes before the first
    /// start. Use for apps that crash-loop without a config (Frigate
    /// with no `/config/config.yml`, Home Assistant, Zigbee2MQTT, etc.)
    #[serde(default)]
    pub seed_files: Vec<SeedFile>,
    /// Command arguments passed after the image name — i.e. the
    /// `CMD` override for images whose ENTRYPOINT expects positional
    /// arguments. Example: cloudflared's image has ENTRYPOINT
    /// `cloudflared` and no default CMD; deploying it without any
    /// `cmd` starts the binary with no subcommand and it exits
    /// immediately. Setting `cmd = ["tunnel", "--no-autoupdate",
    /// "run"]` + an env var for the token gives the operator a
    /// working tunnel without them having to drop to a shell. Each
    /// element becomes its own CLI arg (no shell quoting), and
    /// `${...}` substitutions from `user_inputs` work the same way
    /// they do in `env`.
    #[serde(default)]
    pub cmd: Vec<String>,
}

/// A dummy config file the installer drops into a named volume before
/// the first start so the container doesn't crash-loop on missing
/// config. `container_path` is the absolute path inside the container
/// (e.g. `/config/config.yml`). The file is only written if it
/// doesn't already exist, so reinstalls/upgrades don't stomp user
/// edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedFile {
    pub container_path: String,
    pub content: String,
}

/// A secondary container bundled with the main app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSidecar {
    pub name_suffix: String,
    pub image: String,
    pub ports: Vec<String>,
    pub env: Vec<String>,
    pub volumes: Vec<String>,
    /// Command override — equivalent to the main container's `cmd`.
    /// Lets a sidecar run the same base image as the primary with a
    /// different entrypoint (e.g. Mastodon's `sidekiq` worker, or
    /// Authentik's `worker` command) without needing a second image.
    /// Also covers databases that need flags — Mongo for Rocket.Chat
    /// needs `--replSet rs0 --oplogSize 128`.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Post-install exec — commands run via `docker exec` against
    /// this sidecar once after install completes. The typical use
    /// is initialising a database: Mongo `rs.initiate()`, Postgres
    /// `CREATE DATABASE`, etc. Runs once at install time only.
    #[serde(default)]
    pub post_install_exec: Vec<Vec<String>>,
}

/// How to install an app in an LXC container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LxcTarget {
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    /// Commands to run inside the container after creation
    pub setup_commands: Vec<String>,
}

/// How to install an app as a KVM virtual machine
/// (ISO-based installers — PBS, pfSense, OPNsense, HAOS, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmTarget {
    /// Direct URL to the installer ISO
    pub iso_url: String,
    /// Memory in MB (default; user can override)
    pub memory_mb: u32,
    /// vCPU count (default; user can override)
    pub cores: u32,
    /// OS disk size in GB (default; user can override)
    pub disk_gb: u32,
    /// Optional data-disk default size in GB. Apps like PBS want a small
    /// OS disk plus a large backup-storage disk; this sets the default
    /// size the UI suggests when one is presented. `None` means the app
    /// only needs a single disk and no data-disk field is shown.
    #[serde(default)]
    pub data_disk_gb: Option<u32>,
    /// Human-readable label for the data disk field (e.g. "Backup storage")
    #[serde(default)]
    pub data_disk_label: Option<String>,
    /// VGA mode — "std" for graphical installers
    #[serde(default = "default_vm_vga")]
    pub vga: String,
}

fn default_vm_vga() -> String { "std".to_string() }

/// How to install an app directly on the host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BareMetalTarget {
    /// Debian/Ubuntu packages
    pub packages_debian: Vec<String>,
    /// RHEL/Fedora packages
    pub packages_redhat: Vec<String>,
    /// Optional post-install commands
    pub post_install: Vec<String>,
    /// Systemd service name to enable/start
    pub service: Option<String>,
}

/// A user-facing input field shown in the install wizard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInput {
    pub id: String,
    pub label: String,
    pub input_type: String, // "text", "password", "number", "select"
    pub default: Option<String>,
    pub required: bool,
    pub placeholder: Option<String>,
    /// For select type
    #[serde(default)]
    pub options: Vec<String>,
}

/// Full app manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    pub id: String,
    pub name: String,
    pub icon: String,         // emoji or SVG icon name
    pub category: String,
    pub description: String,
    pub website: Option<String>,
    pub docker: Option<DockerTarget>,
    pub lxc: Option<LxcTarget>,
    pub bare_metal: Option<BareMetalTarget>,
    #[serde(default)]
    pub vm: Option<VmTarget>,
    #[serde(default)]
    pub user_inputs: Vec<UserInput>,
}

/// Tracking record of an installed app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub install_id: String,
    pub app_id: String,
    pub app_name: String,
    pub target: String,           // "docker", "lxc", "bare"
    pub container_name: Option<String>,
    pub installed_at: String,
    /// Any sidecar container names
    #[serde(default)]
    pub sidecar_names: Vec<String>,
    /// How this app was deployed: "docker-run" (default, single
    /// container via `docker create/start`, the original behaviour) or
    /// "docker-compose" (rendered YAML under
    /// ~/wolfstack/compose/stacks/{compose_stack_name} and lifecycled
    /// via `docker compose …`). Missing in older records ⇒ docker-run.
    #[serde(default = "default_deployment_type")]
    pub deployment_type: String,
    /// The compose project name used for `docker compose -p …`.
    /// Format: `appstore-{install_id}`. `None` for non-compose
    /// deployments.
    #[serde(default)]
    pub compose_stack_name: Option<String>,
}

fn default_deployment_type() -> String { "docker-run".to_string() }

// ─── Installed apps persistence ───

fn installed_file() -> String { crate::paths::get().appstore_installed }

fn load_installed() -> Vec<InstalledApp> {
    let mut installed: Vec<InstalledApp> = std::fs::read_to_string(installed_file())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Merge any pending installs from terminal-based installations
    merge_pending_installs(&mut installed);

    installed
}

fn save_installed(apps: &[InstalledApp]) {
    let _ = std::fs::create_dir_all(&crate::paths::get().appstore_dir);
    let _ = std::fs::write(installed_file(), serde_json::to_string_pretty(apps).unwrap_or_default());
}

// ─── Public API ───

/// List all available apps, optionally filtered by query and/or category
/// Build-once cache of the catalogue. The catalogue is immutable
/// static data, but `built_in_catalogue()` constructs 533 manifests —
/// thousands of heap allocations and a ~332 KB stack frame on aarch64
/// (measured in the shipped v25.2.56 binary with objdump). The list
/// endpoint used to rebuild it 534× PER REQUEST (once for the list +
/// once per app via has_compose_template → get_app): ~4.5 million
/// allocations of synchronous work ON the async worker thread. Fast
/// desktops hid it (~0.3 s); on small ARM boards it blocked the event
/// loop long enough that the connection died mid-response and Chrome
/// reported "Failed to fetch" (xavierasx's NanoPi R3S, 2026-07-14).
static CATALOGUE: std::sync::LazyLock<Vec<AppManifest>> =
    std::sync::LazyLock::new(built_in_catalogue);

/// The full catalogue, built once per process.
pub fn catalogue() -> &'static [AppManifest] {
    &CATALOGUE
}

pub fn list_apps(query: Option<&str>, category: Option<&str>) -> Vec<AppManifest> {
    // Filter FIRST, clone only the matches — the unfiltered case still
    // clones all 533, but that's one clone per request, not 534 full
    // catalogue rebuilds (see CATALOGUE above).
    catalogue().iter().filter(|app| {
        let q_match = query.is_none_or(|q| {
            let q = q.to_lowercase();
            app.name.to_lowercase().contains(&q) ||
            app.description.to_lowercase().contains(&q) ||
            app.id.to_lowercase().contains(&q)
        });
        let c_match = category.is_none_or(|c| {
            c.eq_ignore_ascii_case("all") || app.category.eq_ignore_ascii_case(c)
        });
        q_match && c_match
    }).cloned().collect()
}

/// Get a single app by ID
pub fn get_app(id: &str) -> Option<AppManifest> {
    catalogue().iter().find(|a| a.id == id).cloned()
}

/// List installed apps
pub fn list_installed_apps() -> Vec<InstalledApp> {
    load_installed()
}

/// Container-side ports we treat as "likely a web UI", most-preferred first.
/// Used to pick which of an app's published ports the browser-open icon
/// should target when an app exposes several. Not exhaustive — the actual
/// confirmation is an HTTP probe; this only orders the candidates.
const WEB_LIKELY_PORTS: &[u16] = &[
    80, 443, 8080, 8000, 3000, 8443, 8096, 9000, 5000, 8123, 3001, 2283, 8081, 9090,
];

/// Parse the CONTAINER side of a manifest port string ("host:container",
/// "host:container/proto", or bare "container"/"container/proto").
fn manifest_container_port(spec: &str) -> Option<u16> {
    let spec = spec.split('/').next().unwrap_or(spec); // drop /tcp etc.
    let container = spec.rsplit(':').next().unwrap_or(spec); // right of last ':'
    container.trim().parse::<u16>().ok()
}

/// Infer the container-side web-UI port for an app's Docker target from its
/// declared `ports`: prefer a recognisably-web port, else the first port.
/// Returns None when the app declares no ports. This is the "App Store first"
/// source — it tells the open-in-browser feature which port to try before
/// falling back to a live port scan.
pub fn docker_web_container_port(app_id: &str) -> Option<u16> {
    let app = get_app(app_id)?;
    let d = app.docker.as_ref()?;
    let ports: Vec<u16> = d.ports.iter().filter_map(|p| manifest_container_port(p)).collect();
    if ports.is_empty() {
        return None;
    }
    WEB_LIKELY_PORTS
        .iter()
        .find(|w| ports.contains(w))
        .copied()
        .or_else(|| ports.first().copied())
}

/// Resolve the App-Store-known web port for a running container, by matching
/// it to its install record. Returns the container-side web port (the caller
/// maps it to the live host port for Docker, or hits it directly on the
/// container IP for LXC). None when the container wasn't installed from the
/// store or the app declares no web port.
pub fn web_container_port_for(container_name: &str) -> Option<u16> {
    let installed = load_installed();
    let rec = installed
        .iter()
        .find(|a| a.container_name.as_deref() == Some(container_name))?;
    // Today we can infer the web port for Docker apps from their declared
    // ports. LXC apps declare no ports, so they fall through to the live
    // probe (common web ports on the container IP).
    docker_web_container_port(&rec.app_id)
}

/// Reject an install/prepare that's missing any parameter the app declares as
/// `required` (e.g. a database server password). Defends the API even when the
/// UI's own required-field check is bypassed. Whitespace-only counts as missing.
pub fn validate_required_inputs(
    app_id: &str,
    user_inputs: &HashMap<String, String>,
) -> Result<(), String> {
    let app = get_app(app_id).ok_or_else(|| format!("App '{}' not found", app_id))?;
    let missing: Vec<String> = app.user_inputs.iter()
        .filter(|inp| inp.required
            && user_inputs.get(&inp.id).map(|v| v.trim()).unwrap_or("").is_empty())
        .map(|inp| inp.label.clone())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("Missing required parameter(s): {}", missing.join(", ")))
    }
}

/// Install an app
pub fn install_app(
    app_id: &str,
    target: &str,
    container_name: &str,
    user_inputs: &HashMap<String, String>,
    custom_ports: Option<&[String]>,
    deployment_type: Option<&str>,
) -> Result<String, String> {
    // Never install without the parameters the app requires (e.g. a DB password).
    validate_required_inputs(app_id, user_inputs)?;
    let mut app = get_app(app_id).ok_or_else(|| format!("App '{}' not found", app_id))?;

    // Override manifest ports with custom ports if provided
    if let Some(ports) = custom_ports
        && let Some(ref mut docker) = app.docker {
            docker.ports = ports.to_vec();
        }

    // Generate the install_id up-front — compose uses it as the stack
    // name so the dir and project name are known before we write the
    // YAML.
    let install_id = format!("{}_{}", app_id, chrono_timestamp());
    let chosen_deployment = deployment_type.unwrap_or("docker-run");
    let mut sidecar_names: Vec<String> = Vec::new();
    let mut resolved_deployment = "docker-run".to_string();
    let mut compose_stack_name: Option<String> = None;
    let mut persisted_container_name: Option<String> = Some(container_name.to_string());

    let result = match target {
        "docker" if chosen_deployment == "docker-compose" => {
            // Opt-in Compose path. Resolve the template — either
            // hand-crafted in the override map or synthesised from
            // the DockerTarget. Only fails when the app has no
            // Docker target at all (LXC-only / VM-only), which the
            // frontend already refuses to offer but the backend
            // checks defensively.
            if !has_compose_template(&app.id) {
                return Err("This app can't be installed via Docker Compose".to_string());
            }
            let stack_name = format!("appstore-{}", install_id);
            let msg = install_compose(&app, &stack_name, user_inputs)?;
            resolved_deployment = "docker-compose".to_string();
            compose_stack_name = Some(stack_name);
            // Compose installs don't own a single container name; the
            // compose project owns many containers named by service.
            persisted_container_name = None;
            msg
        }
        "docker" => install_docker(&app, container_name, user_inputs, &mut sidecar_names)?,
        "lxc" => install_lxc(&app, container_name, user_inputs)?,
        "bare" => install_bare_metal(&app, user_inputs)?,
        "vm" => install_vm(&app, container_name, user_inputs)?,
        _ => return Err(format!("Unknown install target: {}", target)),
    };

    // Track the installation
    let mut installed = load_installed();
    installed.push(InstalledApp {
        install_id: install_id.clone(),
        app_id: app_id.to_string(),
        app_name: app.name.clone(),
        target: target.to_string(),
        container_name: persisted_container_name,
        installed_at: chrono_timestamp(),
        sidecar_names,
        deployment_type: resolved_deployment,
        compose_stack_name,
    });
    save_installed(&installed);


    Ok(result)
}

/// Uninstall an app by its install ID. For compose-deployed apps the
/// caller is expected to have obtained user confirmation to wipe
/// volumes (the UI enforces the typed-YES modal); this function just
/// executes `docker compose down -v` when invoked.
pub fn uninstall_app(install_id: &str) -> Result<String, String> {
    let mut installed = load_installed();
    let idx = installed.iter().position(|a| a.install_id == install_id)
        .ok_or_else(|| format!("Install ID '{}' not found", install_id))?;

    let app = installed.remove(idx);

    // Compose-backed apps don't have a single container to remove — we
    // tear down the whole project.
    if app.deployment_type == "docker-compose" {
        if let Some(ref stack) = app.compose_stack_name {
            uninstall_compose(stack)?;
        }
        save_installed(&installed);
        return Ok(format!("{} has been uninstalled", app.app_name));
    }

    // Remove the container/packages
    match app.target.as_str() {
        "docker" => {
            if let Some(ref name) = app.container_name {
                let _ = crate::containers::docker_stop(name);
                let _ = crate::containers::docker_remove_permanent(name);
            }
            // Remove sidecars
            for sidecar in &app.sidecar_names {
                let _ = crate::containers::docker_stop(sidecar);
                let _ = crate::containers::docker_remove_permanent(sidecar);
            }
        }
        "lxc" => {
            if let Some(ref name) = app.container_name {
                let _ = crate::containers::lxc_stop(name);
                let _ = crate::containers::lxc_destroy(name);
            }
        }
        "bare" => {
            // We don't auto-remove packages for safety
            return Err("Bare metal apps must be manually uninstalled".to_string());
        }
        _ => {}
    }

    save_installed(&installed);
    Ok(format!("{} has been uninstalled", app.app_name))
}

// ─── Install implementations ───

fn install_docker(
    app: &AppManifest,
    container_name: &str,
    user_inputs: &HashMap<String, String>,
    sidecar_names: &mut Vec<String>,
) -> Result<String, String> {
    let docker = app.docker.as_ref()
        .ok_or("This app doesn't support Docker installation")?;

    // Auto-allocate a WolfNet IP for this container
    let wolfnet_ip = crate::containers::next_available_wolfnet_ip();


    // Install sidecars first (e.g. database). Sidecars can now carry
    // a `cmd` override (needed for Mongo --replSet, Authentik worker,
    // Mastodon sidekiq, etc.) and a `post_install_exec` list (one-shot
    // `docker exec` commands like `mongosh --eval rs.initiate()`).
    for sidecar in &docker.sidecars {
        let sidecar_name = format!("{}-{}", container_name, sidecar.name_suffix);
        let env = substitute_inputs(&sidecar.env, user_inputs);
        let cmd = substitute_inputs(&sidecar.cmd, user_inputs);

        crate::containers::docker_pull(&sidecar.image)?;

        crate::containers::docker_create_with_cmd(
            &sidecar_name,
            &sidecar.image,
            &sidecar.ports,
            &env,
            None,  // no WolfNet IP for sidecars
            None,  // no memory limit
            None,  // no CPU limit
            None,  // no storage limit
            &sidecar.volumes,
            &cmd,
        )?;
        sidecar_names.push(sidecar_name.clone());

        // Run post-install exec commands, if any. These need the
        // sidecar up, so start it first, give it a moment to settle,
        // then exec the commands and leave it running. The main app
        // starts after all sidecars and their inits are finished.
        if !sidecar.post_install_exec.is_empty() {
            crate::containers::docker_start(&sidecar_name)?;
            // Poll briefly for the container to accept exec — avoids
            // racing databases that take a second or two to bind.
            std::thread::sleep(std::time::Duration::from_secs(3));
            for raw_argv in &sidecar.post_install_exec {
                let argv = substitute_inputs(raw_argv, user_inputs);
                let mut cmd = std::process::Command::new("docker");
                cmd.arg("exec").arg(&sidecar_name);
                for a in &argv { cmd.arg(a); }
                // Best-effort: failure here (e.g. replSet already
                // initiated on a retry) shouldn't roll the install back.
                let _ = cmd.output();
            }
        }
    }

    // Pull the main image

    crate::containers::docker_pull(&docker.image)?;

    // Seed dummy config files BEFORE creating the main container.
    // Some images (Misskey, Frigate, Home Assistant) crash-loop on
    // a missing /config file; writing it up-front unbricks first-run.
    // The content is put through substitute_inputs so placeholders
    // like ${DB_PASSWORD} or ${CONTAINER_NAME} resolve the same way
    // env / cmd do.
    for seed in &docker.seed_files {
        // Match the seed's container_path against a volume whose
        // target is a prefix, e.g. `/misskey/.config/default.yml`
        // under `misskey_files:/misskey`. Named volumes need to
        // exist before a throwaway alpine writer can mount them.
        let matched = docker.volumes.iter().find_map(|spec| {
            let (host, target) = spec.split_once(':')?;
            if seed.container_path == target
                || seed.container_path.starts_with(&format!("{}/", target))
            {
                Some((host.to_string(), target.to_string()))
            } else { None }
        });
        let Some((source, mount)) = matched else { continue };
        let Some(rel) = seed.container_path.strip_prefix(&format!("{}/", mount)) else { continue };
        if rel.is_empty() || source.is_empty() { continue; }
        let content = substitute_inputs(
            std::slice::from_ref(&seed.content), user_inputs,
        ).into_iter().next().unwrap_or_default();
        // Create the named volume (no-op if exists) then write via
        // a throwaway alpine container. `[ -f … ] ||` preserves an
        // existing user edit on reinstall.
        if !source.starts_with('/') {
            let _ = std::process::Command::new("docker")
                .args(["volume", "create", &source])
                .output();
        }
        let sh = format!(
            "mkdir -p \"$(dirname /seed/{rel})\" && [ -f /seed/{rel} ] || printf %s \"$SEED_CONTENT\" > /seed/{rel}",
            rel = rel,
        );
        let _ = std::process::Command::new("docker")
            .args(["run", "--rm", "-v", &format!("{}:/seed", source),
                   "-e", &format!("SEED_CONTENT={}", content),
                   "alpine", "sh", "-c", &sh])
            .output();
    }

    // Substitute user inputs into env vars AND the cmd — same
    // ${PLACEHOLDER} syntax, same user_inputs map.
    let env = substitute_inputs(&docker.env, user_inputs);
    let cmd = substitute_inputs(&docker.cmd, user_inputs);

    // Create the container (not started)

    crate::containers::docker_create_with_cmd(
        container_name,
        &docker.image,
        &docker.ports,
        &env,
        wolfnet_ip.as_deref(),
        None,
        None,
        None,
        &docker.volumes,
        &cmd,
    )?;

    let mut msg = format!("{} configured as Docker container '{}' (stopped)", app.name, container_name);
    if let Some(ref ip) = wolfnet_ip {
        msg.push_str(&format!(" — WolfNet IP: {}", ip));
    }
    if !sidecar_names.is_empty() {
        msg.push_str(&format!(" (with sidecars: {})", sidecar_names.join(", ")));
    }
    Ok(msg)
}

// ─── Compose deployment (opt-in) ────────────────────────────────────────
//
// Compose-backed appstore installs live under the same directory as
// user-created compose stacks (/etc/wolfstack/compose/{name}) so they
// appear on the existing Compose Stacks page with an `appstore-`
// prefix in the name. This means the generic compose lifecycle
// endpoints (start, stop, logs, etc.) already manage them for free —
// we only need to own create and delete.
//
// Compose templates are kept in a separate lookup rather than as a
// field on DockerTarget. That lets authors add compose support to
// any app incrementally without touching the hundreds of existing
// catalog literals (Rust struct literals need every field set; the
// separate lookup keeps compose opt-in with zero ripple).

/// Hand-crafted compose YAML for apps that want a richer stack than
/// synthesis can produce (custom healthchecks, depends_on, multiple
/// named networks, etc.). Returns None for apps without a crafted
/// template — the install path then falls back to synthesising one
/// from the DockerTarget manifest. Template syntax is
/// `${user_input_id}` substitution, same rules as env / cmd.
pub fn handcrafted_compose_template(_app_id: &str) -> Option<&'static str> {
    None
}

/// Resolve the compose template for an app. Preference order:
///
/// 1. A hand-crafted template in `handcrafted_compose_template`.
/// 2. A template synthesised from `DockerTarget` — image, ports,
///    env, volumes and sidecars — covering the common case
///    automatically.
///
/// `None` is returned only when the app has no Docker target at all
/// (LXC / bare-metal / VM installs, which can't go through compose).
pub fn resolve_compose_template(app_id: &str) -> Option<String> {
    if let Some(s) = handcrafted_compose_template(app_id) {
        return Some(s.to_string());
    }
    let app = get_app(app_id)?;
    let docker = app.docker.as_ref()?;
    Some(synthesise_compose_template(app_id, docker))
}

/// True when the given app has compose available (hand-crafted or
/// synthesisable). Used by the frontend-facing manifest to surface a
/// "Deploy with Compose" option. Mirrors resolve_compose_template's
/// semantics (handcrafted, else any Docker target synthesises) without
/// building the template string or cloning the manifest — this runs
/// once per app in the list endpoint's annotation loop.
pub fn has_compose_template(app_id: &str) -> bool {
    handcrafted_compose_template(app_id).is_some()
        || catalogue().iter().any(|a| a.id == app_id && a.docker.is_some())
}

/// Generate a minimal docker-compose.yml from a DockerTarget. Covers
/// image / ports / env / volumes for the main service, plus one
/// service per sidecar. Named volumes referenced by a service are
/// declared at the top level so `docker compose up` creates them.
///
/// This is a starting point the user can edit via the "Edit compose"
/// button — anything fancier (healthchecks, depends_on chains,
/// custom networks) lives in the hand-crafted override map above.
fn synthesise_compose_template(app_id: &str, d: &DockerTarget) -> String {
    let main_name = "${CONTAINER_NAME}";
    let mut out = String::new();
    out.push_str("# Auto-generated docker-compose.yml for ");
    out.push_str(app_id);
    out.push_str(".\n");
    out.push_str("# Edit freely. Save writes this file; click \"Up\" in Compose Stacks\n");
    out.push_str("# to apply it (`docker compose up -d`) and inject any vault secrets.\n");
    out.push_str("services:\n");

    // Main service.
    out.push_str(&render_compose_service(main_name, &d.image, &d.ports, &d.env, &d.volumes, &d.cmd));

    // Sidecars. `cmd` is honoured so Mongo replSet flags, Mastodon
    // sidekiq, Authentik worker, etc. render correctly.
    for s in &d.sidecars {
        let svc_name = format!("${{CONTAINER_NAME}}-{}", s.name_suffix);
        out.push_str(&render_compose_service(&svc_name, &s.image, &s.ports, &s.env, &s.volumes, &s.cmd));
    }

    // Collect named volumes referenced by any service. A named volume
    // is a volume whose host side doesn't start with "/" or "./" —
    // i.e. a Docker-managed named volume rather than a bind mount.
    let mut named: std::collections::BTreeSet<String> = Default::default();
    let mut collect = |vols: &[String]| {
        for v in vols {
            if let Some(host) = v.split(':').next() {
                let h = host.trim();
                if !h.is_empty() && !h.starts_with('/') && !h.starts_with('.') {
                    named.insert(h.to_string());
                }
            }
        }
    };
    collect(&d.volumes);
    for s in &d.sidecars { collect(&s.volumes); }
    if !named.is_empty() {
        out.push_str("volumes:\n");
        for v in &named {
            out.push_str(&format!("  {}: {{}}\n", v));
        }
    }
    out
}

fn render_compose_service(
    name: &str,
    image: &str,
    ports: &[String],
    env: &[String],
    volumes: &[String],
    cmd: &[String],
) -> String {
    let mut s = String::new();
    s.push_str(&format!("  {}:\n", name));
    s.push_str(&format!("    image: {}\n", image));
    s.push_str(&format!("    container_name: {}\n", name));
    s.push_str("    restart: unless-stopped\n");
    if !ports.is_empty() {
        s.push_str("    ports:\n");
        for p in ports {
            s.push_str(&format!("      - \"{}\"\n", yaml_double_quoted(p)));
        }
    }
    if !env.is_empty() {
        s.push_str("    environment:\n");
        for e in env {
            // KEY=VALUE → - "KEY=VALUE" (fully escaped so newlines,
            // quotes, backslashes and control chars in the value can't
            // break out of the quoted string).
            s.push_str(&format!("      - \"{}\"\n", yaml_double_quoted(e)));
        }
    }
    if !volumes.is_empty() {
        s.push_str("    volumes:\n");
        for v in volumes {
            s.push_str(&format!("      - \"{}\"\n", yaml_double_quoted(v)));
        }
    }
    if !cmd.is_empty() {
        s.push_str("    command:\n");
        for c in cmd {
            s.push_str(&format!("      - \"{}\"\n", yaml_double_quoted(c)));
        }
    }
    s
}

/// Escape a string so it can be safely embedded inside a YAML
/// double-quoted scalar. Follows the YAML 1.2 spec for double-quoted
/// escape sequences: `\\`, `\"`, `\n`, `\r`, `\t`, plus `\xNN` for
/// any other control character. Keeps everything else literal so
/// unicode passes through untouched.
fn yaml_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn appstore_compose_dir(stack: &str) -> std::path::PathBuf {
    // Same configurable root the standalone Compose page uses (Settings → File
    // Locations → "Compose Directory"), so appstore stacks and operator stacks
    // never diverge — appstore-* stacks stay visible on the Compose page even
    // when the directory is moved off the default.
    std::path::PathBuf::from(crate::paths::get().compose_dir).join(stack)
}

fn appstore_compose_file(stack: &str) -> std::path::PathBuf {
    appstore_compose_dir(stack).join("docker-compose.yml")
}

fn install_compose(
    app: &AppManifest,
    stack_name: &str,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    app.docker.as_ref()
        .ok_or("This app doesn't support Docker installation")?;
    let template = resolve_compose_template(&app.id)
        .ok_or("This app doesn't provide a Docker Compose template")?;

    // Render ${...} placeholders using the same substitution rules as
    // env/cmd so users see consistent behaviour between run and
    // compose modes.
    let rendered = substitute_inputs(&[template], user_inputs)
        .into_iter().next().unwrap_or_default();

    let dir = appstore_compose_dir(stack_name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create compose dir: {}", e))?;
    std::fs::write(appstore_compose_file(stack_name), &rendered)
        .map_err(|e| format!("write compose file: {}", e))?;

    // Bring the stack up. If compose fails (bad image, port
    // conflict, invalid YAML…), roll back: tear down anything that
    // did start and remove the stack directory so the next install
    // attempt gets a clean slate. Without this the user is left with
    // an orphaned directory under /etc/wolfstack/compose that they'd
    // have to clean up manually.
    let warning = match compose_up(stack_name) {
        Ok(w) => w,
        Err(e) => {
        let file = appstore_compose_file(stack_name);
        // Best effort: if compose isn't resolvable there is nothing running to
        // tear down anyway, and the caller already has the real error.
        if let Ok(mut cmd) = crate::containers::compose_cmd() {
            let _ = cmd
                .args(["-f", &file.to_string_lossy(), "down", "-v", "--remove-orphans"])
                .envs(crate::api::compose_secrets_env())
                .current_dir(&dir)
                .output();
        }
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
        }
    };

    Ok(format!("{} deployed via Docker Compose (stack {}){}", app.name, stack_name, warning))
}

fn uninstall_compose(stack_name: &str) -> Result<String, String> {
    let file = appstore_compose_file(stack_name);
    if file.exists() {
        // `down -v` removes the containers *and* the named volumes
        // the compose file declared. UI guards this behind a typed-YES
        // modal so the user has acknowledged the data loss.
        let mut cmd = crate::containers::compose_cmd()?;
        cmd.args(["-f", &file.to_string_lossy(), "down", "-v", "--remove-orphans"]);
        let out = cmd
            .envs(crate::api::compose_secrets_env())
            .current_dir(appstore_compose_dir(stack_name))
            .output()
            .map_err(|e| format!("docker compose down failed to start: {}", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Don't abort uninstall — we still want the stack dir
            // cleaned up and the InstalledApp record removed. Log to
            // the caller so the message reaches the operator.
            eprintln!("[appstore] compose down warning for {}: {}", stack_name, stderr);
        }
    }
    // Remove the stack directory so a re-install of the same app gets
    // a clean slate. If this fails we return the error — the install
    // record has already been cleared from the list by the caller.
    let _ = std::fs::remove_dir_all(appstore_compose_dir(stack_name));
    Ok(format!("Compose stack {} removed", stack_name))
}

/// `docker compose up -d` for an App Store stack. On success returns the
/// warning suffix to append to the caller's message: empty when every
/// `${KEY}` resolved, otherwise the list compose substituted a blank string
/// for (it only warns, then starts the stack degraded — see
/// `api::parse_undefined_compose_vars`).
fn compose_up(stack_name: &str) -> Result<String, String> {
    let file = appstore_compose_file(stack_name);
    // Secrets-Manager entries ride in as process env so `${KEY}` references
    // in the compose YAML resolve — same injection as the Compose page
    // (api::compose_secrets_env), no divergence between the two surfaces.
    let mut cmd = crate::containers::compose_cmd()?;
    cmd.args(["-f", &file.to_string_lossy(), "up", "-d", "--remove-orphans"]);
    let out = cmd
        .envs(crate::api::compose_secrets_env())
        .current_dir(appstore_compose_dir(stack_name))
        .output()
        .map_err(|e| format!("docker compose up failed to start: {}", e))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!("docker compose up failed: {}", stderr.trim()));
    }
    let unset = crate::api::parse_undefined_compose_vars(&stderr);
    if unset.is_empty() {
        return Ok(String::new());
    }
    Ok(format!(
        ". WARNING: {} resolved to an empty string — not in this host's Secrets Manager, \
         so the stack is running with blank values",
        unset.iter().map(|v| format!("${{{}}}", v)).collect::<Vec<_>>().join(", ")
    ))
}

/// Read the on-disk compose file for a compose-backed install. Looks
/// up the install by id, resolves the stack name, and returns the
/// YAML. Returns an error if the install doesn't exist or wasn't a
/// compose install.
pub fn read_compose_file(install_id: &str) -> Result<String, String> {
    let installed = load_installed();
    let app = installed.iter().find(|a| a.install_id == install_id)
        .ok_or_else(|| format!("Install ID '{}' not found", install_id))?;
    if app.deployment_type != "docker-compose" {
        return Err("This app was not deployed via Docker Compose".to_string());
    }
    let stack = app.compose_stack_name.as_ref()
        .ok_or("Compose stack name missing from install record")?;
    std::fs::read_to_string(appstore_compose_file(stack))
        .map_err(|e| format!("read compose file: {}", e))
}

/// Overwrite the compose file and re-run `docker compose up -d`.
pub fn write_compose_file(install_id: &str, new_yaml: &str) -> Result<String, String> {
    let installed = load_installed();
    let app = installed.iter().find(|a| a.install_id == install_id)
        .ok_or_else(|| format!("Install ID '{}' not found", install_id))?;
    if app.deployment_type != "docker-compose" {
        return Err("This app was not deployed via Docker Compose".to_string());
    }
    let stack = app.compose_stack_name.clone()
        .ok_or("Compose stack name missing from install record")?;
    let dir = appstore_compose_dir(&stack);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create compose dir: {}", e))?;
    std::fs::write(appstore_compose_file(&stack), new_yaml)
        .map_err(|e| format!("write compose file: {}", e))?;
    let warning = compose_up(&stack)?;
    Ok(format!("{} compose file saved and stack reloaded{}", app.app_name, warning))
}

fn install_lxc(
    app: &AppManifest,
    container_name: &str,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    let lxc = app.lxc.as_ref()
        .ok_or("This app doesn't support LXC installation")?;

    // Auto-allocate a WolfNet IP
    let wolfnet_ip = crate::containers::next_available_wolfnet_ip();

    // If GRID_HOSTNAME input is empty/missing, use the allocated WolfNet IP
    let mut inputs = user_inputs.clone();
    if let Some(ref wn_ip) = wolfnet_ip {
        let hostname = inputs.get("GRID_HOSTNAME").map(|s| s.trim().to_string()).unwrap_or_default();
        if hostname.is_empty() {
            inputs.insert("GRID_HOSTNAME".to_string(), wn_ip.clone());
        }
    }
    let user_inputs = &inputs;


    // Create the container

    crate::containers::lxc_create(
        container_name,
        &lxc.distribution,
        &lxc.release,
        &lxc.architecture,
        None, // default storage
        None, // default template cache
    )?;

    // Write WolfNet IP file so it's pre-assigned
    if let Some(ref ip) = wolfnet_ip {
        let wolfnet_dir = format!("{}/{}/.wolfnet", crate::containers::lxc_base_dir(container_name), container_name);
        let _ = std::fs::create_dir_all(&wolfnet_dir);
        let _ = std::fs::write(format!("{}/ip", wolfnet_dir), ip);
    }

    // Apps that need extra resources
    if app.id == "opensimngc" {
        let settings = crate::containers::LxcSettingsUpdate {
            memory_limit: Some("4096M".into()),
            swap_limit: Some("2048M".into()),
            cpus: Some("2".into()),
            ..Default::default()
        };
        let _ = crate::containers::lxc_update_settings(container_name, &settings);
    }

    // Apps that need special LXC device access
    let needs_tun = matches!(app.id.as_str(), "wolfdisk" | "wireguard" | "tailscale");
    let needs_fuse = matches!(app.id.as_str(), "wolfdisk");
    if needs_tun || needs_fuse {
        let settings = crate::containers::LxcSettingsUpdate {
            tun_enabled: if needs_tun { Some(true) } else { None },
            fuse_enabled: if needs_fuse { Some(true) } else { None },
            ..Default::default()
        };
        if let Err(e) = crate::containers::lxc_update_settings(container_name, &settings) {
            eprintln!("Warning: Failed to apply LXC features for {}: {}", container_name, e);
        }
    }

    // Start the container temporarily to run setup commands

    crate::containers::lxc_start(container_name)?;

    // Wait for the container to boot
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Run setup commands inside the container
    let commands = substitute_inputs(&lxc.setup_commands, user_inputs);
    for cmd in &commands {

        let output = std::process::Command::new("lxc-attach")
            .args(["-n", container_name, "--", "sh", "-c", cmd])
            .output()
            .map_err(|e| format!("Failed to run setup command: {}", e))?;

        if !output.status.success() {
            let _stderr = String::from_utf8_lossy(&output.stderr);

        }
    }

    // Stop the container — it's configured but not running

    let _ = crate::containers::lxc_stop(container_name);

    let mut msg = format!("{} configured as LXC container '{}' (stopped)", app.name, container_name);
    if let Some(ref ip) = wolfnet_ip {
        msg.push_str(&format!(" — WolfNet IP: {}", ip));
    }
    msg.push_str(". Start the container when ready.");
    Ok(msg)
}

fn install_bare_metal(
    app: &AppManifest,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    let bare = app.bare_metal.as_ref()
        .ok_or("This app doesn't support bare metal installation")?;

    // Detect distro inline (installer::pkg_install_cmd is private)
    let is_debian = std::path::Path::new("/etc/debian_version").exists();
    let is_redhat = std::path::Path::new("/etc/redhat-release").exists()
        || std::path::Path::new("/etc/fedora-release").exists();

    let (pkg_cmd, install_flag) = if is_debian {
        ("apt-get", "install")
    } else if is_redhat {
        ("dnf", "install")
    } else {
        ("apt-get", "install") // fallback
    };

    let packages = if is_debian {
        &bare.packages_debian
    } else if is_redhat {
        &bare.packages_redhat
    } else {
        &bare.packages_debian // fallback
    };

    if !packages.is_empty() {

        let output = std::process::Command::new(pkg_cmd)
            .arg(install_flag)
            .arg("-y")
            .args(packages)
            .output()
            .map_err(|e| format!("Package install failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Package install failed: {}", stderr));
        }
    }

    // Run post-install commands
    let commands = substitute_inputs(&bare.post_install, user_inputs);
    for cmd in &commands {

        let output = std::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .map_err(|e| format!("Post-install command failed: {}", e))?;

        if !output.status.success() {
            let _stderr = String::from_utf8_lossy(&output.stderr);

        }
    }

    // Enable and start the service
    if let Some(ref service) = bare.service {
        let _ = std::process::Command::new("systemctl")
            .args(["enable", "--now", service])
            .output();
    }

    Ok(format!("{} installed on host", app.name))
}

/// Given an ISO URL that 404s (e.g. Debian's `current/` symlink rolling
/// from 13.4.0 to 13.5.0, or a Proxmox `_latest.iso` alias being retired),
/// scrape the parent directory's HTML index and pick the newest file
/// carrying the same name template with a bumped version number.
///
/// The version number in the original filename is located and treated as
/// a hole: everything before it is a fixed prefix, everything after is a
/// fixed suffix. We then match directory entries against `<prefix><ver><suffix>`
/// exactly and pick the highest `<ver>` by numeric comparison. Anchoring on
/// both prefix and suffix is what keeps us from picking sibling variants
/// that share a prefix — `debian-edu-13.5.0-amd64-netinst.iso` and
/// `debian-mac-13.5.0-...` live in the same directory as the plain
/// `debian-13.5.0-amd64-netinst.iso` we actually want.
///
/// Handles hyphen-delimited names (Debian/Ubuntu: `debian-13.4.0-amd64-netinst.iso`)
/// and underscore-delimited names (Proxmox: `proxmox-ve_9.1-1.iso`) alike.
/// Returns None if the directory can't be fetched, the filename has no
/// dotted version to anchor on, or nothing matches the template.
fn resolve_latest_iso(original_url: &str) -> Option<String> {
    let last_slash = original_url.rfind('/')?;
    let base = &original_url[..=last_slash];

    let output = std::process::Command::new("wget")
        .args(["-q", "-O", "-", base])
        .output()
        .ok()?;
    if !output.status.success() { return None; }
    let html = String::from_utf8_lossy(&output.stdout);

    pick_latest_iso_from_listing(original_url, &html)
}

/// Pure core of [`resolve_latest_iso`] — given the original URL and the
/// fetched directory HTML, return the newest matching ISO URL (or None).
/// Split out from the network fetch so it can be unit-tested offline.
fn pick_latest_iso_from_listing(original_url: &str, html: &str) -> Option<String> {
    // Split `https://host/dir/file.iso` into (`https://host/dir/`, `file`)
    let last_slash = original_url.rfind('/')?;
    let base = &original_url[..=last_slash];
    let file = &original_url[last_slash + 1..];

    // Locate the dotted version number embedded in the filename — the
    // `13.4.0` in `debian-13.4.0-amd64-netinst.iso` or the `9.1` in
    // `proxmox-ve_9.1-1.iso`. Requires at least one dot so we don't latch
    // onto a stray single digit (e.g. the `64` in `64bit`).
    let ver_re = regex::Regex::new(r"\d+(?:\.\d+)+").ok()?;
    let m = ver_re.find(file)?;
    let prefix = &file[..m.start()];
    let suffix = &file[m.end()..];

    // Exact template match: same prefix, a dotted version capture, same suffix.
    let pat = format!(
        "^{}({}){}$",
        regex::escape(prefix),
        r"\d+(?:\.\d+)+",
        regex::escape(suffix),
    );
    let entry_re = regex::Regex::new(&pat).ok()?;

    // Pick the entry with the highest version by component-wise numeric
    // comparison (`13.10.0` > `13.9.0`, which a lexical sort gets wrong).
    let mut best: Option<(Vec<u64>, String)> = None;
    for part in html.split("href=\"").skip(1) {
        if let Some(end) = part.find('"') {
            let href = &part[..end];
            if let Some(caps) = entry_re.captures(href) {
                let ver: Vec<u64> = caps[1]
                    .split('.')
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let is_newer = best.as_ref().is_none_or(|(b, _)| ver > *b);
                if is_newer {
                    best = Some((ver, href.to_string()));
                }
            }
        }
    }
    let (_, latest) = best?;
    Some(format!("{}{}", base, latest))
}

/// Streaming variant of install_vm. Emits progress lines into the given
/// channel so an SSE endpoint can forward them to the UI — download bytes
/// polled every second from the partial file, allocation/create/start
/// stages each emit a line. Same work as install_vm otherwise; we keep
/// both so non-streaming callers (tests, node-to-node) stay simple.
pub fn install_vm_streamed(
    app: &AppManifest,
    vm_name: &str,
    user_inputs: &HashMap<String, String>,
    tx: std::sync::mpsc::Sender<String>,
) -> Result<String, String> {
    let vm = app.vm.as_ref()
        .ok_or("This app doesn't support VM installation")?;

    let _ = tx.send(format!("Installing {} as a VM", app.name));

    let iso_dir = "/var/lib/wolfstack/iso";
    std::fs::create_dir_all(iso_dir)
        .map_err(|e| format!("Failed to create ISO dir: {}", e))?;
    let iso_path = format!("{}/{}.iso", iso_dir, app.id);

    if std::path::Path::new(&iso_path).exists() {
        let _ = tx.send(format!(
            "ISO already cached at {} — reusing (skipping download)",
            iso_path
        ));
    } else {
        // Try the manifest URL; fall back to the directory-index resolver if it 404s.
        let first_err = download_iso_with_progress(&vm.iso_url, &iso_path, &tx).err();
        if let Some(err) = first_err {
            let _ = std::fs::remove_file(&iso_path);
            let _ = tx.send(format!(
                "First URL failed ({}). Scraping parent directory for a newer version...",
                err
            ));
            match resolve_latest_iso(&vm.iso_url) {
                Some(resolved) => {
                    let _ = tx.send(format!("Resolved newer ISO URL: {}", resolved));
                    if let Err(e) = download_iso_with_progress(&resolved, &iso_path, &tx) {
                        let _ = std::fs::remove_file(&iso_path);
                        return Err(format!(
                            "Failed to download ISO from {} (also tried {}): {}",
                            vm.iso_url, resolved, e
                        ));
                    }
                }
                None => {
                    return Err(format!(
                        "Failed to download ISO from {} (couldn't resolve a newer version either): {}",
                        vm.iso_url, err
                    ));
                }
            }
        }
        let _ = tx.send(format!("ISO downloaded to {}", iso_path));
    }

    let _ = tx.send("Allocating WolfNet IP...".into());
    let mut wolfnet_ip = crate::containers::next_available_wolfnet_ip();
    if let Some(ref ip) = wolfnet_ip {
        let _ = tx.send(format!("Allocated WolfNet IP {}", ip));
    } else {
        let _ = tx.send("No WolfNet IP available — guest will use user-mode NAT".into());
    }

    let storage_path = user_inputs
        .get("storage_path")
        .filter(|s| !s.trim().is_empty())
        .cloned();

    let parse_u32 = |key: &str, default: u32| -> u32 {
        user_inputs
            .get(key)
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default)
    };
    let cores = parse_u32("cores", vm.cores);
    let memory_mb = parse_u32("memory_mb", vm.memory_mb);
    let disk_gb = parse_u32("disk_gb", vm.disk_gb);
    let data_disk_gb: Option<u32> = if vm.data_disk_gb.is_some() {
        user_inputs
            .get("data_disk_gb")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .or(vm.data_disk_gb)
            .filter(|&v| v > 0)
    } else {
        None
    };

    let mut cfg = crate::vms::manager::VmConfig::new(
        vm_name.to_string(),
        cores,
        memory_mb,
        disk_gb,
    );
    cfg.iso_path = Some(iso_path);
    cfg.wolfnet_ip = wolfnet_ip.clone();
    cfg.storage_path = storage_path.clone();
    cfg.auto_start = false;

    if let Some(sz) = data_disk_gb {
        let disk_storage = storage_path
            .clone()
            .unwrap_or_else(|| "/var/lib/wolfstack/vms".to_string());
        cfg.extra_disks.push(crate::vms::manager::StorageVolume {
            name: format!("{}-data", vm_name),
            size_gb: sz,
            storage_path: disk_storage,
            format: "qcow2".to_string(),
            bus: "virtio".to_string(),
        });
        let _ = tx.send(format!("Added data disk: {} GB", sz));
    }

    // Firewall apps (OPNsense) need a WAN NIC in addition to the LAN one.
    // Two LAN modes are supported:
    //
    //   A. Default (lan_interface unset): LAN = WolfNet TAP (net0 = vtnet0
    //      with a DHCP-assigned WolfNet IP). Good for staging/learning;
    //      limited in practice because WolfNet is point-to-point routed
    //      rather than a shared L2 segment, so other WolfStack VMs can't
    //      reach the firewall's WebGUI via LAN.
    //
    //   B. Physical LAN passthrough (lan_interface set to a host iface
    //      name): LAN = that physical NIC (net1 = vtnet0), WolfNet TAP
    //      is skipped entirely. OPNsense serves a real L2 LAN segment
    //      on that physical interface. User assigns LAN IP manually in
    //      the installer/console (typically 192.168.1.1/24).
    //
    // WAN is always a passthrough of the host's default-route interface.
    let lan_interface: Option<String> = user_inputs.get("lan_interface")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let wan_interface: Option<String> = if app.id == "opnsense" {
        let wan = crate::networking::detect_primary_interface();

        // Mode B: physical LAN passthrough. Drop WolfNet, add LAN first
        // (so it becomes vtnet0) and WAN second (vtnet1).
        if let Some(lan) = lan_interface.as_ref() {
            if lan == &wan {
                return Err(format!(
                    "LAN and WAN interfaces are the same ('{}'). OPNsense needs two distinct physical NICs — or leave lan_interface blank to use WolfNet for LAN.",
                    lan
                ));
            }
            cfg.wolfnet_ip = None;       // mode B skips WolfNet for LAN
            cfg.skip_default_nic = true; // and skips the net0 NAT fallback,
                                         // so extra_nics[0] becomes vtnet0
            wolfnet_ip = None;           // (and clear from the payload/modal)
            cfg.extra_nics.push(crate::vms::manager::NicConfig {
                model: "virtio".into(),
                mac: None,
                bridge: None,
                passthrough_interface: Some(lan.clone()),
            });
            let _ = tx.send(format!(
                "LAN NIC = physical interface '{}' (vtnet0 inside the guest) — configure LAN IP manually via OPNsense console",
                lan
            ));
        }

        // WAN is always added. In mode A it becomes vtnet1 (after WolfNet
        // net0); in mode B it becomes vtnet1 (after the LAN extra NIC).
        cfg.extra_nics.push(crate::vms::manager::NicConfig {
            model: "virtio".into(),
            mac: None,
            bridge: None,
            passthrough_interface: Some(wan.clone()),
        });
        let _ = tx.send(format!(
            "WAN NIC bridged to host interface '{}' (vtnet1 inside the guest)",
            wan
        ));
        Some(wan)
    } else {
        None
    };

    let _ = tx.send(format!(
        "Creating VM '{}' ({} cores, {} MB RAM, {} GB OS disk)...",
        vm_name, cores, memory_mb, disk_gb
    ));
    let vmm = crate::vms::manager::VmManager::new();
    vmm.create_vm(cfg)?;
    let _ = tx.send("VM created. Starting...".into());
    vmm.start_vm(vm_name)?;
    let _ = tx.send("VM running.".into());

    // Free the ISO once the VM is up. PBS ISOs are ~1 GB, OPNsense ~700 MB,
    // pfSense ~500 MB — they pile up quickly across a busy install history.
    // The running QEMU process keeps an open fd to the file, so the bytes
    // aren't reclaimed until the user reboots/stops the VM (which they'll
    // do post-install anyway). Re-installing the same app re-downloads the
    // ISO; the user opted into that trade by asking for cleanup.
    let iso_at = format!("/var/lib/wolfstack/iso/{}.iso", app.id);
    if let Ok(meta) = std::fs::metadata(&iso_at) {
        let mb = meta.len() / 1_048_576;
        match std::fs::remove_file(&iso_at) {
            Ok(_) => { let _ = tx.send(format!("Cleaned up ISO ({} MB freed once the VM stops/reboots)", mb)); }
            Err(e) => { let _ = tx.send(format!("Note: couldn't remove ISO {}: {}", iso_at, e)); }
        }
    }

    // Every VM install emits a structured `[vm-network]` payload so the
    // frontend can show a sticky "your VM's IP details" modal BEFORE the
    // user opens VNC. The task log mirrors the same info for history.
    // Per-app `steps` cover the installer-specific bits (static-IP prompts
    // for PBS/PVE/Harvester/TrueNAS/OPNsense; DHCP auto-pickup for the
    // rest).
    let gateway = wolfnet_ip.as_ref().and_then(|ip| {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            Some(format!("{}.{}.{}.254", parts[0], parts[1], parts[2]))
        } else {
            None
        }
    });

    let (installer_mode, steps): (&str, Vec<String>) = match app.id.as_str() {
        "pbs" => ("static", vec![
            "Installer boot menu - 'Install Proxmox Backup Server (Graphical)'. NOT 'Automatic installation' (that needs an answer file).".into(),
            "Target harddisk - pick the smaller disk (OS disk). ZFS/ext4 defaults.".into(),
            "Country/timezone/password/email - your choice.".into(),
            "Management Network Configuration - enter the IP/gateway/DNS shown below (overwrite any 192.168.100.x placeholders).".into(),
            "Review - Install. When it reboots, unset the ISO in VM Settings.".into(),
        ]),
        "proxmox-ve" => ("static", vec![
            "Installer boot menu - 'Install Proxmox VE (Graphical)'.".into(),
            "Target harddisk - defaults are fine. Country/timezone/password/email.".into(),
            "Management Network Configuration - enter the IP/gateway/DNS shown below.".into(),
            "Review - Install. When it reboots, unset the ISO in VM Settings.".into(),
            "WebGUI at https://<IP>:8006 - login 'root' + your install password.".into(),
        ]),
        "opnsense" => {
            // Steps vary by LAN mode:
            //   A (WolfNet LAN)      — user pastes WolfNet IP into OPNsense
            //                          console so the WebGUI is reachable
            //                          from the host at that IP. WolfNet is
            //                          point-to-point, so OTHER VMs on
            //                          WolfNet cannot reach the WebGUI
            //                          directly — this mode is for staging.
            //   B (physical LAN NIC) — user picks their own LAN IP (e.g.
            //                          192.168.1.1), the firewall serves
            //                          that real L2 segment. Production use.
            let steps: Vec<String> = if lan_interface.is_some() {
                vec![
                    format!("LAN = physical NIC '{}' (vtnet0), WAN = physical NIC '{}' (vtnet1). OPNsense serves a real L2 LAN segment on the LAN NIC.",
                        lan_interface.as_ref().unwrap(),
                        wan_interface.as_deref().unwrap_or("?")),
                    "Wait ~60s for the live console login prompt.".into(),
                    "Log in as 'installer' / 'opnsense' to start the guided installer.".into(),
                    "Keymap - Continue - pick ZFS or UFS - pick the disk - Install.".into(),
                    "Set the root password. Reboot. Unset the ISO in VM Settings.".into(),
                    "Console option 1 'Assign interfaces' - confirm LAN=vtnet0, WAN=vtnet1.".into(),
                    "Console option 2 'Set interface IP address' - set LAN to whatever subnet you want (typically 192.168.1.1/24). Leave WAN as DHCP.".into(),
                    "Any device plugged into the physical LAN NIC will now get a DHCP lease from OPNsense on that subnet.".into(),
                    "WebGUI at https://<LAN-IP> - login 'root' / 'opnsense' (change on first login).".into(),
                ]
            } else {
                vec![
                    "LAN = WolfNet TAP (vtnet0), WAN = physical uplink (vtnet1). NOTE: WolfNet is point-to-point — OTHER WolfStack VMs cannot reach this firewall's WebGUI on the LAN side. For production use, set 'lan_interface' to pass a physical NIC through as LAN.".into(),
                    "Wait ~60s for the live console login prompt.".into(),
                    "Log in as 'installer' / 'opnsense' to start the guided installer.".into(),
                    "Keymap - Continue - pick ZFS or UFS - pick the disk - Install.".into(),
                    "Set the root password. Reboot. Unset the ISO in VM Settings.".into(),
                    "Console option 1 'Assign interfaces' - confirm LAN=vtnet0, WAN=vtnet1.".into(),
                    "Console option 2 'Set interface IP address' - set LAN (vtnet0) to the IP/gateway below (NOT the default 192.168.1.1). Leave WAN as DHCP.".into(),
                    "WebGUI at https://<LAN-IP> from the host itself (ssh in + curl, or VNC). From other WolfStack VMs use the WolfNet IP directly.".into(),
                ]
            };
            ("static", steps)
        },
        "harvester" => ("static", vec![
            "Installer boot menu - 'Harvester Installer'.".into(),
            "'Create a new Harvester cluster' on the first node.".into(),
            "Management interface - use the IP/gateway/DNS shown below. Cluster VIP needs a separate free IP (not the same as management).".into(),
            "Set a cluster token (remember it for adding more nodes) and admin password.".into(),
            "WebGUI at https://<VIP> - initial bootstrap takes 10-15 minutes after reboot.".into(),
        ]),
        "truenas-scale" => ("dhcp", vec![
            "Installer menu - 'Install/Upgrade'. Pick the smaller (boot) disk.".into(),
            "Choose 'Administrative user' (default 'truenas_admin'). Set its password.".into(),
            "EFI/swap defaults. Install and reboot. Unset the ISO in VM Settings.".into(),
            "First boot gets a DHCP lease (the IP below). To set it static: console menu option 1 'Configure Network Interfaces' and enter the values below.".into(),
            "WebGUI at http://<IP> - login 'truenas_admin' + your password. Configure the data disk under Storage.".into(),
        ]),
        // Everyone else - Ubuntu/Debian/Mint/Fedora/Rocky/Alma/Alpine/
        // EndeavourOS/CachyOS installers all default to DHCP, so they pick
        // up the WolfNet lease automatically. The IP is shown so the user
        // knows where to reach the VM after install.
        _ => ("dhcp", vec![
            "The installer defaults to DHCP - it will pick up the IP shown below automatically.".into(),
            "Follow the installer prompts (keyboard, timezone, disk, user account).".into(),
            "After install reboots, the VM is reachable at the IP below (SSH / WebGUI).".into(),
            "Unset the ISO in VM Settings so subsequent boots skip the installer.".into(),
        ]),
    };

    let sep = "=".repeat(63);
    let _ = tx.send(sep.clone());
    let _ = tx.send(format!("{} installer - open VNC on the VM:", app.name));
    for (i, step) in steps.iter().enumerate() {
        let _ = tx.send(format!("  {}. {}", i + 1, step));
    }
    if let Some(ref ip) = wolfnet_ip {
        let gw = gateway.clone().unwrap_or_else(|| "(see VM details)".into());
        let _ = tx.send(format!(
            "  Network: IP {}/24  Gateway {}  DNS 8.8.8.8",
            ip, gw
        ));
    } else {
        let _ = tx.send(
            "  Network: no WolfNet IP allocated - use the IP/gateway your network provides".into(),
        );
    }
    let _ = tx.send(sep);

    // Structured payload picked up by the frontend and rendered as a
    // sticky modal. Emitted for EVERY VM install.
    // Extra NICs (e.g. OPNsense WAN, and in LAN-passthrough mode also
    // the LAN NIC) — shown as a secondary block in the modal so the
    // user understands the guest has multiple interfaces and which is
    // which.
    let extra_nics = if let Some(wan) = wan_interface.as_ref() {
        let mut nics = Vec::new();
        if let Some(lan) = lan_interface.as_ref() {
            // Mode B: LAN is a physical NIC; include it first (vtnet0).
            nics.push(serde_json::json!({
                "label": "LAN (vtnet0)",
                "description": format!(
                    "Bridged to physical host interface '{}'. Configure a LAN IP in the OPNsense console (typically 192.168.1.1/24). Any device plugged into that NIC gets DHCP from the firewall.",
                    lan
                ),
                "mode": "manual",
            }));
        }
        nics.push(serde_json::json!({
            "label": "WAN (vtnet1)",
            "description": format!(
                "Bridged to host interface '{}'. Gets its IP via DHCP from your upstream network — this is the firewall's external side.",
                wan
            ),
            "mode": "dhcp",
        }));
        Some(serde_json::Value::Array(nics))
    } else {
        None
    };

    let payload = serde_json::json!({
        "app_id": app.id,
        "app_name": app.name,
        "vm_name": vm_name,
        "ip": wolfnet_ip,
        "cidr": wolfnet_ip.as_ref().map(|ip| format!("{}/24", ip)),
        "gateway": gateway,
        "dns": "8.8.8.8",
        "installer_mode": installer_mode,
        "steps": steps,
        "extra_nics": extra_nics,
        "vnc_hint": format!("Open VNC on VM '{}' to start the installer", vm_name),
    });
    let _ = tx.send(format!("[vm-network] {}", payload));

    let done_msg = format!("{} VM '{}' created and started.", app.name, vm_name);
    let _ = tx.send(done_msg.clone());
    Ok(done_msg)
}

/// If `url` ends in a compressed-archive suffix we can decompress,
/// return that suffix (including the leading dot). OPNsense ships
/// `.iso.bz2`, Alpine physical images can be `.iso.gz`, HAOS-style
/// qcow2 images use `.xz`. The downloader uses this to fetch to
/// `{dest}{suffix}` and then decompress to `{dest}`.
fn compressed_suffix(url: &str) -> Option<&'static str> {
    if url.ends_with(".bz2") { Some(".bz2") }
    else if url.ends_with(".xz") { Some(".xz") }
    else if url.ends_with(".gz") { Some(".gz") }
    else { None }
}

/// Any ISO under this size is assumed to be a truncated download, an HTML
/// error page, or a captive-portal redirect. Every ISO we actually ship
/// is 65 MB+ (Alpine virt is the smallest at ~67 MB), so 10 MB is a safe
/// lower bound that catches every real failure mode we've seen in the
/// wild.
const MIN_ISO_SIZE_BYTES: u64 = 10 * 1_048_576;

/// Check a host tool exists before we need it. `bunzip2`, `xz`, `gunzip`
/// are pre-installed on almost every Linux but we'd rather fail fast with
/// a clear message than download a 500 MB archive and then discover we
/// can't decompress it. Returns the path to the tool if found, None if
/// missing.
fn find_tool(tool: &str) -> Option<String> {
    std::process::Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Decompressor binary name for a given suffix, plus a user-facing
/// package hint for the "please install X" error message.
fn decompressor_for(suffix: &str) -> Option<(&'static str, &'static str)> {
    match suffix {
        ".bz2" => Some(("bunzip2", "bzip2")),
        ".xz"  => Some(("xz",      "xz-utils / xz")),
        ".gz"  => Some(("gunzip",  "gzip")),
        _ => None,
    }
}

/// Bytes available on the filesystem holding `path`. Returns None if we
/// can't determine it (older systems without GNU df --output). The check
/// is best-effort: we never refuse to try on uncertainty, only on hard
/// evidence of insufficient space.
fn available_disk_bytes(path: &str) -> Option<u64> {
    let out = std::process::Command::new("df")
        .args(["--output=avail", "-B1", path])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().nth(1).and_then(|l| l.trim().parse::<u64>().ok())
}

/// Human-friendly megabyte rendering for error messages.
fn mb(bytes: u64) -> String { format!("{} MB", bytes / 1_048_576) }

/// Decompress `compressed` (e.g. foo.iso.bz2) in place, producing the
/// file with the suffix stripped (foo.iso). The underlying tool
/// (bunzip2/xz/gunzip) already writes to the suffix-stripped name and
/// removes the input, so this helper just runs the tool and checks
/// status. The `-f` flag lets it overwrite an existing target from a
/// previous interrupted install.
fn decompress_in_place(compressed: &str, suffix: &str) -> Result<(), String> {
    let (cmd, args): (&str, Vec<&str>) = match suffix {
        ".bz2" => ("bunzip2", vec!["-f", compressed]),
        ".xz"  => ("xz",      vec!["-d", "-f", compressed]),
        ".gz"  => ("gunzip",  vec!["-f", compressed]),
        other  => return Err(format!("decompress: unknown suffix {}", other)),
    };
    let output = std::process::Command::new(cmd)
        .args(&args)
        .output()
        .map_err(|e| format!("failed to run {}: {}", cmd, e))?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with status {:?}: {}",
            cmd,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Download a URL to `dest` via wget with full diagnostics, progress,
/// sanity checks, and compressed-archive handling. Designed to make the
/// failure modes we've actually seen in production (silent zero-byte
/// wget "success", HTML captive-portal pages, missing bunzip2, disk
/// full mid-download) impossible to hit without a clear error message.
///
/// Returns Err with a diagnostic string on any failure. On success,
/// `dest` is guaranteed to be a file of at least MIN_ISO_SIZE_BYTES.
/// On failure, any partial files at `dest` or `{dest}{suffix}` are
/// removed so a retry starts clean.
///
/// If `url` ends in `.bz2`/`.xz`/`.gz` the compressed archive is
/// downloaded to `{dest}{suffix}` and decompressed in place.
fn download_iso_with_progress(
    url: &str,
    dest: &str,
    tx: &std::sync::mpsc::Sender<String>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    // ── Preflight: tool availability ──
    // If we need a decompressor, check it's on $PATH before burning
    // 500 MB of bandwidth on an archive we can't open.
    let suffix = compressed_suffix(url);
    if let Some(sfx) = suffix {
        let (tool, pkg) = decompressor_for(sfx).unwrap();
        if find_tool(tool).is_none() {
            return Err(format!(
                "'{}' is not installed on this host, but the ISO URL is {}. Install the '{}' package and retry.",
                tool, sfx, pkg
            ));
        }
    }
    if find_tool("wget").is_none() {
        return Err("'wget' is not installed on this host. Install the 'wget' package and retry.".into());
    }

    let wget_target = match suffix {
        Some(sfx) => format!("{}{}", dest, sfx),
        None => dest.to_string(),
    };

    // ── HEAD for total size (best-effort) ──
    let total_bytes: Option<u64> = std::process::Command::new("curl")
        .args(["-sIL", url])
        .output()
        .ok()
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            text.lines()
                .filter_map(|l| {
                    let lower = l.to_ascii_lowercase();
                    if lower.starts_with("content-length:") {
                        l.split_once(':').map(|x| x.1).and_then(|v| v.trim().parse::<u64>().ok())
                    } else {
                        None
                    }
                })
                .next_back()
        });

    // ── Preflight: disk space ──
    // Need: compressed archive size + decompressed size + 10% slack.
    // For `.bz2` typical ratio is 2x, `.xz` up to 5x, `.gz` ~3x. Pick
    // the worst case per suffix so we err on the side of caution. If
    // we don't know total_bytes (server didn't send Content-Length)
    // we skip the check and rely on the post-download size validation.
    let parent = std::path::Path::new(dest).parent()
        .and_then(|p| p.to_str())
        .unwrap_or("/");
    if let (Some(sz), Some(free)) = (total_bytes, available_disk_bytes(parent)) {
        let decompressed_multiplier = match suffix {
            Some(".bz2") => 3,   // compressed + ~2x decompressed
            Some(".xz")  => 6,   // compressed + ~5x decompressed
            Some(".gz")  => 4,   // compressed + ~3x decompressed
            _ => 1,              // no decompression
        };
        let needed = sz.saturating_mul(decompressed_multiplier) + sz / 10;
        if free < needed {
            return Err(format!(
                "Not enough free disk space at {}. Need ~{} (download + decompression + 10% slack), have {}. Free some space and retry.",
                parent, mb(needed), mb(free)
            ));
        }
        let _ = tx.send(format!(
            "Disk check: {} free at {} ({} needed). OK.",
            mb(free), parent, mb(needed)
        ));
    }

    if let Some(sz) = total_bytes {
        let _ = tx.send(format!("Downloading {} ({})...", url, mb(sz)));
    } else {
        let _ = tx.send(format!("Downloading {} (size unknown)...", url));
    }

    // ── Fetch ──
    // Drop -q so wget's own diagnostics are captured. Use -nv
    // (non-verbose) to silence per-byte chatter but keep error
    // messages. Redirect stderr to a log file so we can surface it on
    // failure — without this, silent 0-exit partial downloads are
    // indistinguishable from success.
    let log_path = format!("{}.wget.log", wget_target);
    let log_file = std::fs::File::create(&log_path)
        .map_err(|e| format!("Failed to create wget log file: {}", e))?;
    let mut child = std::process::Command::new("wget")
        .args(["-nv", "--tries=3", "--timeout=60", "-O", &wget_target, url])
        .stderr(log_file.try_clone().map_err(|e| format!("Failed to clone log fd: {}", e))?)
        .spawn()
        .map_err(|e| format!("Failed to run wget: {}", e))?;

    // Progress poller — runs until `done` flips, emits a line per second.
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();
    let dest_clone = wget_target.clone();
    let tx_clone = tx.clone();
    let started = Instant::now();
    let poller = std::thread::spawn(move || {
        let mut last_bytes: u64 = 0;
        while !done_clone.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            if done_clone.load(Ordering::Relaxed) { break; }
            let size = std::fs::metadata(&dest_clone).map(|m| m.len()).unwrap_or(0);
            if size == 0 { continue; }
            let mb_size = size / 1_048_576;
            let rate_bps = size.saturating_sub(last_bytes);
            last_bytes = size;
            let rate_mbs = rate_bps as f64 / 1_048_576.0;
            let elapsed = started.elapsed().as_secs();
            let msg = if let Some(total) = total_bytes {
                let pct = (size as f64 / total as f64 * 100.0).min(100.0) as u32;
                format!(
                    "Downloading: {} MB / {} MB ({}%) at {:.1} MB/s — {}s elapsed",
                    mb_size, total / 1_048_576, pct, rate_mbs, elapsed
                )
            } else {
                format!(
                    "Downloading: {} MB at {:.1} MB/s — {}s elapsed",
                    mb_size, rate_mbs, elapsed
                )
            };
            if tx_clone.send(msg).is_err() { break; }
        }
    });

    let status = child.wait().map_err(|e| format!("wget wait failed: {}", e))?;
    done.store(true, Ordering::Relaxed);
    let _ = poller.join();

    // Read wget's stderr log for diagnostics — needed whether we
    // succeeded or not (a "successful" wget might still have written
    // an HTML error page, which we catch below via size validation).
    let wget_log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let _ = std::fs::remove_file(&log_path);

    // Cleanup helper — the function's contract is "no partial files
    // on Err". Without this, a retry would see the stale file at
    // `dest` or `wget_target` and skip the download.
    let cleanup = || {
        let _ = std::fs::remove_file(&wget_target);
        let _ = std::fs::remove_file(dest);
    };

    if !status.success() {
        cleanup();
        let tail = wget_log.lines().rev().take(5).collect::<Vec<_>>();
        let tail_rev: Vec<&str> = tail.into_iter().rev().collect();
        return Err(format!(
            "wget failed (exit {:?}). Last output: {}",
            status.code(),
            if tail_rev.is_empty() { "(no output captured)".to_string() } else { tail_rev.join(" | ") }
        ));
    }

    // ── Post-download size sanity check ──
    // wget can exit 0 with a tiny HTML error page (captive portals,
    // Cloudflare blocks, mirror-moved redirects to HTML indexes).
    // Every ISO we ship is 65 MB+, so anything below 10 MB is a
    // broken download, not a valid image.
    let downloaded_size = std::fs::metadata(&wget_target)
        .map(|m| m.len())
        .unwrap_or(0);
    if downloaded_size < MIN_ISO_SIZE_BYTES {
        cleanup();
        return Err(format!(
            "Downloaded file from {} is only {} — expected an ISO (>{}). The mirror likely returned an error page or the URL has moved. Check the URL manually.",
            url, mb(downloaded_size), mb(MIN_ISO_SIZE_BYTES)
        ));
    }

    // ── Decompress (if needed) and re-validate size ──
    if let Some(sfx) = suffix {
        let _ = tx.send(format!("Decompressing {} archive ({} MB)...", sfx, downloaded_size / 1_048_576));
        if let Err(e) = decompress_in_place(&wget_target, sfx) {
            cleanup();
            return Err(format!("Decompression failed: {}", e));
        }
        let decompressed_size = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
        if decompressed_size < MIN_ISO_SIZE_BYTES {
            cleanup();
            return Err(format!(
                "Decompressed output at {} is only {} — expected an ISO. The archive is corrupt or the source was wrong.",
                dest, mb(decompressed_size)
            ));
        }
        let _ = tx.send(format!("Decompression complete ({} MB).", decompressed_size / 1_048_576));
    }

    Ok(())
}

/// Install an ISO-based VM app. The only user choice is the storage location
/// (defaults to /var/lib/wolfstack/vms). Everything else — memory, cores, disk
/// size, WolfNet IP allocation, TAP setup, VNC — comes from the manifest +
/// auto-allocated defaults, and the VM auto-starts into its GUI installer.
fn install_vm(
    app: &AppManifest,
    vm_name: &str,
    user_inputs: &HashMap<String, String>,
) -> Result<String, String> {
    let vm = app.vm.as_ref()
        .ok_or("This app doesn't support VM installation")?;

    // Download the ISO to a shared pool, once. Re-use on subsequent installs.
    let iso_dir = "/var/lib/wolfstack/iso";
    std::fs::create_dir_all(iso_dir)
        .map_err(|e| format!("Failed to create ISO dir: {}", e))?;
    let iso_path = format!("{}/{}.iso", iso_dir, app.id);
    if !std::path::Path::new(&iso_path).exists() {
        // Delegate to the streaming downloader (preflight checks, size
        // validation, disk-space guard, wget diagnostics) — it does all
        // the same work, and a discarded channel is cheap enough.
        // Proxmox-style fallback: if the pinned URL 404s, scrape the
        // parent directory for a newer version and retry.
        let (tx, _rx) = std::sync::mpsc::channel::<String>();
        let mut effective_url = vm.iso_url.clone();
        if let Err(first_err) = download_iso_with_progress(&effective_url, &iso_path, &tx) {
            if let Some(resolved) = resolve_latest_iso(&vm.iso_url) {
                effective_url = resolved;
                if let Err(retry_err) = download_iso_with_progress(&effective_url, &iso_path, &tx) {
                    return Err(format!(
                        "Failed to download ISO from {} (also tried {}): {}",
                        vm.iso_url, effective_url, retry_err
                    ));
                }
            } else {
                return Err(format!(
                    "Failed to download ISO from {} (couldn't resolve latest version either): {}",
                    vm.iso_url, first_err
                ));
            }
        }
    }

    // Auto-allocate a WolfNet IP so the VM is reachable across the cluster
    // as soon as the guest's NIC comes up (static config inside the guest).
    let wolfnet_ip = crate::containers::next_available_wolfnet_ip();

    let storage_path = user_inputs
        .get("storage_path")
        .filter(|s| !s.trim().is_empty())
        .cloned();

    // Allow the user to override the manifest defaults. Parsed as u32; fall
    // back to the manifest default on parse error / empty / zero so the form
    // can't accidentally create a 0-byte VM.
    let parse_u32 = |key: &str, default: u32| -> u32 {
        user_inputs
            .get(key)
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default)
    };
    let cores = parse_u32("cores", vm.cores);
    let memory_mb = parse_u32("memory_mb", vm.memory_mb);
    let disk_gb = parse_u32("disk_gb", vm.disk_gb);
    // Data disk: only attach one if the manifest opted in. 0 means "no data
    // disk" even if the manifest default was set — gives the user an explicit
    // opt-out in the UI.
    let data_disk_gb: Option<u32> = if vm.data_disk_gb.is_some() {
        user_inputs
            .get("data_disk_gb")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .or(vm.data_disk_gb)
            .filter(|&v| v > 0)
    } else {
        None
    };

    let mut cfg = crate::vms::manager::VmConfig::new(
        vm_name.to_string(),
        cores,
        memory_mb,
        disk_gb,
    );
    cfg.iso_path = Some(iso_path);
    cfg.wolfnet_ip = wolfnet_ip.clone();
    cfg.storage_path = storage_path.clone();
    cfg.auto_start = false;

    // Attach a second disk for bulk data storage (e.g. PBS backups). Lives
    // on the same storage pool the OS disk was placed on — users who want a
    // different location for backups can add another disk via the VM edit
    // dialog after install.
    if let Some(sz) = data_disk_gb {
        let disk_storage = storage_path
            .clone()
            .unwrap_or_else(|| "/var/lib/wolfstack/vms".to_string());
        cfg.extra_disks.push(crate::vms::manager::StorageVolume {
            name: format!("{}-data", vm_name),
            size_gb: sz,
            storage_path: disk_storage,
            format: "qcow2".to_string(),
            bus: "virtio".to_string(),
        });
    }

    let vmm = crate::vms::manager::VmManager::new();
    vmm.create_vm(cfg)?;
    vmm.start_vm(vm_name)?;

    // Same ISO cleanup as install_vm_streamed — see comment there.
    let iso_at = format!("/var/lib/wolfstack/iso/{}.iso", app.id);
    let _ = std::fs::remove_file(&iso_at);

    let ip_msg = wolfnet_ip
        .map(|ip| format!(" WolfNet IP {} will be served via DHCP to the VM's NIC (TAP backend).", ip))
        .unwrap_or_else(|| String::from(" (no WolfNet IP assigned — guest will use user-mode NAT.)"));
    // Nudge the user past the PBS installer's "Automatic installation"
    // menu entry, which needs an answer file we don't ship and drops to
    // a debug shell when DHCP doesn't find one.
    let installer_tip = if app.id == "pbs" {
        " Open VNC to finish setup: at the PBS installer menu pick **Install Proxmox Backup Server (Graphical)** — NOT 'Automatic installation' (that one needs an answer file). \
         After install completes and PBS reboots, its web UI is on https://<WolfNet-IP>:8007. \
         To expose externally, add an IP mapping in Networking → IP Mappings — use a SOURCE port other than 8007 (e.g. 8107 → 8007) if this host also runs Proxmox VE (8007 is spiceproxy there)."
    } else {
        " Open VNC to complete the installer."
    };
    Ok(format!(
        "{} VM '{}' created and started.{}{}",
        app.name, vm_name, installer_tip, ip_msg
    ))
}

// ─── Helpers ───

/// Replace ${VAR} placeholders with user input values (shell-escaped for safety)
fn substitute_inputs(templates: &[String], inputs: &HashMap<String, String>) -> Vec<String> {
    templates.iter().map(|t| {
        let mut result = t.clone();
        for (key, value) in inputs {
            result = result.replace(&format!("${{{}}}", key), &shell_escape(value));
        }
        result
    }).collect()
}

/// Simple timestamp for IDs
fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{}", secs)
}

/// Shell-escape a string for safe inclusion in a bash script
fn shell_escape(s: &str) -> String {
    if s.is_empty() { return "''".to_string(); }
    // If safe characters only, return as-is
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+".contains(c)) {
        return s.to_string();
    }
    // Otherwise, single-quote it (escaping any embedded single quotes)
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ─── Pending install registration ───

fn pending_dir() -> String { crate::paths::get().appstore_pending_dir }

/// Merge any pending install registrations into the installed list.
/// Called automatically by load_installed().
fn merge_pending_installs(installed: &mut Vec<InstalledApp>) {
    let pending_dir_str = pending_dir();
    let pending_dir = std::path::Path::new(&pending_dir_str);
    if !pending_dir.is_dir() { return; }

    let entries: Vec<_> = match std::fs::read_dir(pending_dir) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(_) => return,
    };

    let mut changed = false;
    for entry in entries {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") { continue; }

        if let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(app) = serde_json::from_str::<InstalledApp>(&content) {
                // Avoid duplicates
                if !installed.iter().any(|a| a.install_id == app.install_id) {
                    installed.push(app);
                    changed = true;
                }
            }
        let _ = std::fs::remove_file(&path);
    }

    if changed {
        save_installed(installed);
    }
}

/// Startup reconciliation: adopt any native `lxc-create` LXC containers the
/// pre-fix App Store installer left orphaned on a Proxmox host into PVE, so
/// the set of containers WolfStack tracks matches what Proxmox shows.
///
/// Before the fix, installing an LXC app on a Proxmox host ran `lxc-create`
/// instead of `pct create`, producing a container PVE never registered —
/// invisible in the Proxmox UI and in WolfStack's own container view. This
/// pass tars each such orphan's rootfs and re-creates it through `pct` so it
/// becomes a first-class PVE container, then re-points the matching
/// Installed-Apps record at the new VMID.
///
/// Safe to call on every startup: a no-op off Proxmox and when there are no
/// orphans, and adoption is idempotent (an already-adopted container is
/// skipped because PVE then owns its hostname).
pub fn reconcile_orphaned_lxc() {
    if !crate::containers::is_proxmox() { return; }

    let orphans = crate::containers::list_native_lxc_orphans();
    if orphans.is_empty() { return; }

    tracing::info!(
        "Found {} native LXC container(s) not registered with Proxmox — adopting into PVE so they appear in the Proxmox UI",
        orphans.len()
    );

    let mut installed = load_installed();
    let mut registry_changed = false;

    for name in &orphans {
        match crate::containers::pct_adopt_native_orphan(name) {
            Ok(vmid) => {
                tracing::info!("Adopted orphaned LXC container '{}' into Proxmox as VMID {}", name, vmid);
                // Re-point any matching Installed-Apps record at the VMID so
                // WolfStack's own view stays consistent with Proxmox.
                for entry in installed.iter_mut() {
                    if entry.target == "lxc" && entry.container_name.as_deref() == Some(name.as_str()) {
                        entry.container_name = Some(vmid.clone());
                        registry_changed = true;
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Could not adopt orphaned LXC container '{}' into Proxmox: {}", name, e);
            }
        }
    }

    if registry_changed {
        save_installed(&installed);
    }
}

// ─── Live terminal install: script generation ───

/// Remap a Docker volume spec to use a custom storage path.
/// Named volumes like `vol_name:/path` become bind mounts at `<base>/vol_name:/path`.
/// Absolute host paths like `/host/path:/container` are left unchanged.
fn remap_volume(vol: &str, storage_base: &str) -> String {
    if let Some(colon_pos) = vol.find(':') {
        let host_part = &vol[..colon_pos];
        let rest = &vol[colon_pos..];  // includes the colon
        if host_part.starts_with('/') || host_part.starts_with('.') {
            // Already an absolute or relative path — leave as-is
            vol.to_string()
        } else {
            // Named volume — convert to bind mount at storage path
            format!("{}/{}{}", storage_base.trim_end_matches('/'), host_part, rest)
        }
    } else {
        // No colon — anonymous volume, leave as-is
        vol.to_string()
    }
}

/// Prefix a Docker named volume with the container name so two
/// independent installs of the same app (say, two Frigates) don't
/// share the same volume at the daemon's global namespace. Bind
/// mounts and anonymous volumes pass through untouched. Used only
/// when the install has no custom storage path — with a storage path,
/// remap_volume already isolates by putting the bind mount under
/// `<base>/appstore/<container_name>/`.
fn prefix_named_volume(vol: &str, container_name: &str) -> String {
    if let Some(colon_pos) = vol.find(':') {
        let host_part = &vol[..colon_pos];
        let rest = &vol[colon_pos..];
        if host_part.starts_with('/') || host_part.starts_with('.') {
            vol.to_string()
        } else {
            format!("{}_{}{}", container_name, host_part, rest)
        }
    } else {
        vol.to_string()
    }
}

/// Extract the container-side target path from a Docker volume spec
/// (`SRC:TARGET[:MODE]`). Used to dedupe volumes: if a user extra
/// mounts to the same TARGET as a manifest default, the user's choice
/// wins. Returned target is trimmed of trailing slashes so `/foo` and
/// `/foo/` compare equal. Returns None for anonymous volumes or specs
/// we can't parse — those get skipped by the dedupe step.
fn volume_target(vol: &str) -> Option<String> {
    let mut parts = vol.splitn(3, ':');
    parts.next()?;
    let target = parts.next()?;
    if target.is_empty() { return None; }
    Some(target.trim_end_matches('/').to_string())
}

/// Shell helper injected once per generated install script. Picks the
/// next free TCP/UDP host port starting at the requested base by
/// checking kernel listeners via `ss` and existing Docker-bound ports
/// via `docker ps`, plus an in-script allocation set so two ports in
/// the same manifest don't get assigned the same remap.
const PORT_HELPER_SH: &str = r#"# ─── WolfStack app-store port collision helper ───
__WS_ALLOCATED_PORTS=""
__ws_find_free_port() {
    local port="$1"
    local proto="${2:-tcp}"
    local ss_flag="-tnlH"
    [ "$proto" = "udp" ] && ss_flag="-unlH"
    local limit=$((port + 200))
    while [ "$port" -lt "$limit" ] && [ "$port" -lt 65535 ]; do
        case " $__WS_ALLOCATED_PORTS " in *" $proto:$port "*) port=$((port+1)); continue ;; esac
        if ss $ss_flag 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port$"; then
            port=$((port+1)); continue
        fi
        if docker ps --format '{{.Ports}}' 2>/dev/null | grep -qE ":$port->"; then
            port=$((port+1)); continue
        fi
        __WS_ALLOCATED_PORTS="$__WS_ALLOCATED_PORTS $proto:$port"
        echo "$port"; return
    done
    echo "$1"
}
"#;

/// For one docker port spec, emit the shell that resolves a free host
/// port into `$__PORT_<idx>` and return the `-p …` flag that uses it.
/// Specs we don't know how to remap safely (IP-bound, ranges, no host
/// side) come back untouched via shell_escape.
fn emit_port_flag(script: &mut String, spec: &str, counter: &mut usize) -> String {
    let (core, proto_suffix) = match spec.rsplit_once('/') {
        Some((c, p)) if p == "tcp" || p == "udp" => (c, p),
        _ => (spec, ""),
    };
    let parts: Vec<&str> = core.split(':').collect();
    let (host_str, container_str) = match parts.as_slice() {
        [h, c] => (*h, *c),
        _ => return format!(" -p {}", shell_escape(spec)),
    };
    if host_str.is_empty() || container_str.is_empty()
        || host_str.contains('-') || container_str.contains('-')
        || host_str.parse::<u16>().is_err()
        || container_str.parse::<u16>().is_err()
    {
        return format!(" -p {}", shell_escape(spec));
    }
    let proto = if proto_suffix.is_empty() { "tcp" } else { proto_suffix };
    let idx = *counter;
    *counter += 1;
    script.push_str(&format!(
        "__PORT_{idx}=$(__ws_find_free_port {host} {proto})\n",
        idx = idx, host = host_str, proto = proto,
    ));
    // Well-known service-port hint: when AdGuard-style apps land on a
    // router node, port 53 is already owned by dnsmasq on the LAN iface
    // and a remap to 5454 is technically fine but users don't always
    // realise LAN clients can still reach the app via the container IP
    // on port 53 internally. Same story for HTTP(S).
    let hint = match host_str {
        "53" => " (point your DNS forwarder at the container IP on port 53, not the host port)",
        "80" | "443" => " (reverse-proxy or update the URL to the new host port)",
        _ => "",
    };
    script.push_str(&format!(
        "[ \"$__PORT_{idx}\" != \"{host}\" ] && echo -e \"  \\033[0;33m⚠ {proto_up} port {host} busy — using $__PORT_{idx}{hint}\\033[0m\"\n",
        idx = idx, host = host_str, proto_up = proto.to_ascii_uppercase(), hint = hint,
    ));
    let suffix = if proto_suffix.is_empty() { String::new() } else { format!("/{}", proto_suffix) };
    // Intentionally NOT shell_escape'd — we built every character and
    // need `${__PORT_N}` expanded by bash at run-time.
    format!(" -p ${{__PORT_{}}}:{}{}", idx, container_str, suffix)
}

/// Prepare an install script for live terminal execution.
/// Returns (session_id, script_path) on success.
pub fn prepare_install(
    app_id: &str,
    target: &str,
    container_name: &str,
    user_inputs: &HashMap<String, String>,
    storage_path: Option<&str>,
    custom_ports: Option<&[String]>,
    extra_env: Option<&[String]>,
    extra_volumes: Option<&[String]>,
    memory_limit: Option<&str>,
    cpu_limit: Option<&str>,
) -> Result<(String, String), String> {
    // Never prepare an install without the parameters the app requires.
    validate_required_inputs(app_id, user_inputs)?;
    let mut app = get_app(app_id).ok_or_else(|| format!("App '{}' not found", app_id))?;

    // Override manifest ports with custom ports if provided
    if let Some(ports) = custom_ports
        && let Some(ref mut docker) = app.docker {
            docker.ports = ports.to_vec();
        }

    let session_id = format!("{}_{}", app_id, chrono_timestamp());
    let script_path = format!("/tmp/wolfstack-appinstall-{}.sh", session_id);

    let mut script = String::from("#!/bin/bash\nset -e\nexport DEBIAN_FRONTEND=noninteractive\n\n");

    let mut sidecar_names: Vec<String> = Vec::new();

    // Identifier recorded for this install. Defaults to the human name the
    // operator chose; the Proxmox LXC branch overrides it with the assigned
    // VMID, because on a PVE host every subsequent container action (start,
    // stop, console, uninstall) addresses the container by VMID, not hostname.
    let mut register_container_name = container_name.to_string();

    match target {
        "docker" => {
            let docker = app.docker.as_ref()
                .ok_or("This app doesn't support Docker installation")?;

            let wolfnet_ip = crate::containers::next_available_wolfnet_ip();

            // Compute storage base for volume remapping.
            // On Proxmox, storage_path may be a storage ID (e.g. "R1-SDD") — resolve to filesystem path.
            let vol_base = storage_path.map(|sp| {
                let resolved = if sp.starts_with('/') {
                    sp.to_string()
                } else if crate::containers::is_proxmox() {
                    crate::containers::pvesm_resolve_path(sp)
                        .unwrap_or_else(|| format!("/{}", sp))
                } else {
                    format!("/{}", sp)
                };
                format!("{}/appstore/{}", resolved.trim_end_matches('/'), container_name)
            });

            script.push_str(&format!(
                "echo -e '\\033[1;36m━━━ Installing {} via Docker ━━━\\033[0m'\n\n",
                app.name
            ));

            // Shell-side helper for port collision checking. Declared
            // once up-front so every port flag that follows (main
            // container + sidecars) shares an allocation set.
            script.push_str(PORT_HELPER_SH);
            script.push('\n');

            // Create storage directory if using custom storage
            if let Some(ref base) = vol_base {
                script.push_str(&format!("mkdir -p {}\n", shell_escape(base)));
                script.push_str(&format!(
                    "echo -e '\\033[0;36m  Storage: {}\\033[0m'\n\n",
                    base
                ));
            }

            let mut port_counter: usize = 0;

            // Sidecars first
            for sidecar in &docker.sidecars {
                let sidecar_name = format!("{}-{}", container_name, sidecar.name_suffix);
                let env = substitute_inputs(&sidecar.env, user_inputs);

                script.push_str(&format!(
                    "echo -e '\\033[1;33m▸ Pulling sidecar image: {}\\033[0m'\n",
                    sidecar.image
                ));
                script.push_str(&format!("docker pull {}\n\n", shell_escape(&sidecar.image)));

                script.push_str(&format!(
                    "echo -e '\\033[1;33m▸ Creating sidecar container: {}\\033[0m'\n",
                    sidecar_name
                ));

                // Resolve port flags BEFORE appending the docker create
                // line so the `__PORT_N=…` assignments appear first.
                let port_flags: Vec<String> = sidecar.ports.iter()
                    .map(|p| emit_port_flag(&mut script, p, &mut port_counter))
                    .collect();

                let mut create_args = format!("docker create --name {} -it --restart unless-stopped", shell_escape(&sidecar_name));
                // DNS: inject real upstream servers to avoid 127.0.0.53 stub problem
                for dns in crate::containers::docker_dns::get_docker_dns_servers() {
                    create_args.push_str(&format!(" --dns {}", shell_escape(&dns)));
                }
                for flag in &port_flags {
                    create_args.push_str(flag);
                }
                for e in &env {
                    create_args.push_str(&format!(" -e {}", shell_escape(e)));
                }
                for v in &sidecar.volumes {
                    // With vol_base: remap to a per-container bind
                    // mount. Without: prefix the named volume with the
                    // MAIN container name (not the sidecar suffix) so a
                    // DB sidecar and its app share the same data vol.
                    let vol = match vol_base.as_deref() {
                        Some(base) => remap_volume(v, base),
                        None => prefix_named_volume(v, container_name),
                    };
                    create_args.push_str(&format!(" -v {}", shell_escape(&vol)));
                }
                create_args.push_str(&format!(" {}", shell_escape(&sidecar.image)));
                // Sidecar cmd (after image). Same substitution rules as
                // the main container — ${USER_INPUT_ID} placeholders.
                let sidecar_cmd = substitute_inputs(&sidecar.cmd, user_inputs);
                for a in &sidecar_cmd {
                    create_args.push_str(&format!(" {}", shell_escape(a)));
                }
                script.push_str(&format!("{}\n\n", create_args));

                // Post-install exec (one-shot docker exec commands, eg
                // Mongo rs.initiate()). Wrapped in a start + sleep so
                // the sidecar is actually up before the exec.
                if !sidecar.post_install_exec.is_empty() {
                    script.push_str(&format!("docker start {}\nsleep 3\n", shell_escape(&sidecar_name)));
                    for raw_argv in &sidecar.post_install_exec {
                        let argv = substitute_inputs(raw_argv, user_inputs);
                        let mut line = format!("docker exec {}", shell_escape(&sidecar_name));
                        for a in &argv { line.push_str(&format!(" {}", shell_escape(a))); }
                        script.push_str(&format!("{} || true\n", line));
                    }
                    script.push('\n');
                }

                sidecar_names.push(sidecar_name);
            }

            // Main image
            script.push_str(&format!(
                "echo -e '\\033[1;33m▸ Pulling image: {}\\033[0m'\n",
                docker.image
            ));
            script.push_str(&format!("docker pull {}\n\n", shell_escape(&docker.image)));

            // Build the effective volume set for the main container,
            // keyed by the container-side target path. This is where
            // user extras override manifest defaults: picking a bind
            // mount at `/media/frigate` on the install dialog must
            // REPLACE the manifest's `frigate_media:/media/frigate`,
            // not stack alongside it — Docker happily accepts two -v
            // flags for the same target but then silently picks one,
            // which is what produced the "original assignment wins"
            // bug users kept hitting on the Frigate install.
            //
            // BTreeMap keeps emission order deterministic (alphabetic
            // by target) which makes install scripts reproducible.
            use std::collections::BTreeMap;
            let mut vol_map: BTreeMap<String, String> = BTreeMap::new();
            for v in &docker.volumes {
                let remapped = match vol_base.as_deref() {
                    Some(base) => remap_volume(v, base),
                    None => prefix_named_volume(v, container_name),
                };
                if let Some(target) = volume_target(&remapped) {
                    vol_map.insert(target, remapped);
                }
            }
            if let Some(extras) = extra_volumes {
                const BLOCKED_PREFIXES: &[&str] = &["/etc/shadow", "/etc/passwd", "/proc", "/sys"];
                for v in extras {
                    let trimmed = v.trim();
                    if trimmed.is_empty() || !trimmed.contains(':') { continue; }
                    let host_path = trimmed.split(':').next().unwrap_or("");
                    if BLOCKED_PREFIXES.iter().any(|b| host_path.starts_with(b)) { continue; }
                    if let Some(target) = volume_target(trimmed) {
                        vol_map.insert(target, trimmed.to_string());
                    }
                }
            }

            // Seed dummy config files into volumes BEFORE the
            // container is created, so apps like Frigate that crash-
            // loop on missing config come up cleanly the first time.
            // Matched against vol_map (the RESOLVED post-override
            // set) — a user extra that replaces /config with a host
            // bind mount means the seed lands in the user's directory
            // and the old named volume is correctly left alone.
            if !docker.seed_files.is_empty() {
                script.push_str("echo -e '\\033[1;33m▸ Seeding default config files\\033[0m'\n");
                for seed in &docker.seed_files {
                    // Find the volume whose container-side mount point
                    // is a prefix of this seed file's path.
                    let mut match_entry: Option<(String, String)> = None;
                    for (target, spec) in &vol_map {
                        if seed.container_path == *target
                            || seed.container_path.starts_with(&format!("{}/", target))
                        {
                            // Source is everything before the first ':' —
                            // a host path (starts with /) or a named volume.
                            let source = spec.split(':').next().unwrap_or("").to_string();
                            match_entry = Some((source, target.clone()));
                            break;
                        }
                    }
                    let Some((source, mount)) = match_entry else { continue };
                    let rel = seed.container_path.strip_prefix(&format!("{}/", mount))
                        .unwrap_or("");
                    if rel.is_empty() || source.is_empty() { continue; }
                    // Ensure the named volume exists up-front (a bind-
                    // mount dir is auto-created by `docker run -v`).
                    if !source.starts_with('/') {
                        script.push_str(&format!(
                            "docker volume create {} >/dev/null\n",
                            shell_escape(&source),
                        ));
                    }
                    // Write the file via a throwaway alpine container
                    // that mounts the volume. The `[ -f … ]` test skips
                    // the write when the file already exists so user
                    // edits survive a reinstall. Content goes through
                    // substitute_inputs so `${VAR}` placeholders resolve
                    // (Misskey seeds ${DB_PASSWORD} into its config.yml).
                    let seeded_content = substitute_inputs(
                        std::slice::from_ref(&seed.content), user_inputs,
                    ).into_iter().next().unwrap_or_default();
                    script.push_str(&format!(
                        "docker run --rm -v {}:/seed -e SEED_CONTENT={} alpine sh -c '\
                         mkdir -p \"$(dirname /seed/{})\" && \
                         [ -f /seed/{} ] || printf %s \"$SEED_CONTENT\" > /seed/{}'\n",
                        shell_escape(&source),
                        shell_escape(&seeded_content),
                        rel, rel, rel,
                    ));
                }
                script.push('\n');
            }

            // Create main container
            script.push_str(&format!(
                "echo -e '\\033[1;33m▸ Creating container: {}\\033[0m'\n",
                container_name
            ));

            let env = substitute_inputs(&docker.env, user_inputs);
            // Resolve main-container port flags first so their
            // `__PORT_N=…` assignments get written to the script
            // ahead of the `docker create` line below.
            let main_port_flags: Vec<String> = docker.ports.iter()
                .map(|p| emit_port_flag(&mut script, p, &mut port_counter))
                .collect();

            let mut create_args = format!("docker create --name {} -it --restart unless-stopped", shell_escape(container_name));
            // DNS: inject real upstream servers to avoid 127.0.0.53 stub problem
            for dns in crate::containers::docker_dns::get_docker_dns_servers() {
                create_args.push_str(&format!(" --dns {}", shell_escape(&dns)));
            }
            // Resource limits (validated: memory must be digits+unit, cpu must be a number)
            if let Some(mem) = memory_limit {
                let mem = mem.trim();
                if !mem.is_empty() {
                    // Must match e.g. "512m", "2g", "1024k", "1073741824"
                    let valid = mem.len() <= 20 && mem.chars().all(|c| c.is_ascii_digit() || "kmgbKMGB".contains(c));
                    if valid {
                        create_args.push_str(&format!(" --memory {}", shell_escape(mem)));
                    }
                }
            }
            if let Some(cpu) = cpu_limit {
                let cpu = cpu.trim();
                if !cpu.is_empty() {
                    // Must match e.g. "0.5", "2", "1.5"
                    let valid = cpu.len() <= 10 && cpu.chars().all(|c| c.is_ascii_digit() || c == '.');
                    if valid {
                        create_args.push_str(&format!(" --cpus {}", shell_escape(cpu)));
                    }
                }
            }
            for flag in &main_port_flags {
                create_args.push_str(flag);
            }
            for e in &env {
                create_args.push_str(&format!(" -e {}", shell_escape(e)));
            }
            // Extra user-specified env vars (key must be a valid env var name)
            if let Some(extras) = extra_env {
                for e in extras {
                    let trimmed = e.trim();
                    if let Some(eq_pos) = trimmed.find('=') {
                        let key = &trimmed[..eq_pos];
                        if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                           && key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                            create_args.push_str(&format!(" -e {}", shell_escape(trimmed)));
                        }
                    }
                }
            }
            // Emit the resolved volume set built above (manifest
            // defaults with user extras overriding by container-side
            // target). Earlier versions emitted manifest volumes and
            // user extras as separate -v flag groups; Docker accepts
            // both but the two pointing at the same target silently
            // collided. The dedupe happens in vol_map construction.
            for vol in vol_map.values() {
                create_args.push_str(&format!(" -v {}", shell_escape(vol)));
            }
            if let Some(ref ip) = wolfnet_ip {
                create_args.push_str(&format!(" --label wolfnet.ip={}", ip));
            }
            create_args.push_str(&format!(" {}", shell_escape(&docker.image)));
            script.push_str(&format!("{}\n\n", create_args));

            if let Some(ref ip) = wolfnet_ip {
                script.push_str(&format!(
                    "echo -e '\\033[0;36m  WolfNet IP: {}\\033[0m'\n",
                    ip
                ));
            }
        }
        "lxc" => {
            let lxc = app.lxc.as_ref()
                .ok_or("This app doesn't support LXC installation")?;

            if crate::containers::is_proxmox() {
                // ── Proxmox host ──
                // A native `lxc-create` container is invisible to PVE (it has
                // no /etc/pve/lxc/<vmid>.conf and no VMID), so it never shows
                // in the Proxmox UI and WolfStack's own `pct list`-based view
                // can't see it either. Create the container through the SAME
                // `pct` path the Containers page uses, then have the generated
                // script only start it, run the app's setup commands via
                // `pct exec`, and stop it. The create happens here (inside
                // web::block on the API side) rather than in the script so the
                // container is a first-class PVE container from birth.
                let wolfnet_ip = crate::containers::next_available_wolfnet_ip();

                // Parse optional memory/CPU exactly like the direct LXC-create
                // endpoint ("512m"/"2g"/"1024" -> MB; integer cores).
                let memory_mb = memory_limit.and_then(|m| {
                    let m = m.trim().to_lowercase();
                    if m.ends_with('g') { m.trim_end_matches('g').parse::<u32>().ok().map(|v| v * 1024) }
                    else if m.ends_with('m') { m.trim_end_matches('m').parse::<u32>().ok() }
                    else { m.parse::<u32>().ok() }
                });
                let cpu_cores = cpu_limit.and_then(|c| c.trim().parse::<u32>().ok());

                // The install modal's storage picker sends `s.path || s.id`,
                // so a dir-type storage arrives as a filesystem path — but
                // `pct create --storage` wants a storage ID. Map a path back to
                // its PVE storage ID; an ID passes straight through; anything
                // unmappable (e.g. a WolfStack mount) falls back to the default.
                let pct_storage: Option<String> = match storage_path {
                    Some(sp) if !sp.is_empty() => {
                        if sp.starts_with('/') {
                            crate::containers::pvesm_resolve_id(sp)
                        } else {
                            Some(sp.to_string())
                        }
                    }
                    _ => None,
                };

                // Create now. pct_create_api downloads the template on first
                // use, attaches the WolfNet NIC + marker, and returns the VMID.
                let (vmid, create_msg) = crate::containers::pct_create_api(
                    container_name, &lxc.distribution, &lxc.release, &lxc.architecture,
                    pct_storage.as_deref(), None, None, memory_mb, cpu_cores, wolfnet_ip.as_deref(),
                    "wolfnet", None, None, None,
                )?;

                // Record the install against the VMID — that's how every later
                // action will find this container on a PVE host.
                register_container_name = vmid.to_string();

                script.push_str(&format!(
                    "echo -e '\\033[1;36m━━━ Installing {} via LXC (Proxmox VMID {}) ━━━\\033[0m'\n\n",
                    app.name, vmid
                ));
                script.push_str(&format!(
                    "echo -e '\\033[0;32m  {}\\033[0m'\n\n",
                    create_msg.replace('\'', "'\\''")
                ));

                // Start so setup commands can run inside the container. The
                // container already exists in PVE (created above), so these
                // steps are best-effort + visible rather than fatal: under the
                // script's `set -e`, a non-zero `pct start`/`pct exec` would
                // otherwise abort before the install-registration block at the
                // bottom runs, leaving a container PVE shows but WolfStack
                // can't track or uninstall.
                script.push_str("echo -e '\\033[1;33m▸ Starting container...\\033[0m'\n");
                script.push_str(&format!(
                    "pct start {} || echo -e '\\033[0;31m  ⚠ Failed to start container — it exists in Proxmox but setup may be incomplete\\033[0m'\n",
                    vmid
                ));
                script.push_str("echo 'Waiting for container to boot...'\nsleep 3\n\n");

                let commands = substitute_inputs(&lxc.setup_commands, user_inputs);
                if !commands.is_empty() {
                    script.push_str("echo -e '\\033[1;33m▸ Running setup commands...\\033[0m'\n");
                    for cmd in &commands {
                        script.push_str(&format!(
                            "echo -e '\\033[0;90m  $ {}\\033[0m'\n",
                            cmd.replace('\'', "'\\''")
                        ));
                        script.push_str(&format!(
                            "pct exec {} -- sh -c {} || echo -e '\\033[0;31m  ⚠ setup command failed (continuing)\\033[0m'\n",
                            vmid, shell_escape(cmd)
                        ));
                    }
                    script.push('\n');
                }

                // Stop — configured but not running, matching the native path.
                script.push_str("echo -e '\\033[1;33m▸ Stopping container...\\033[0m'\n");
                script.push_str(&format!("pct stop {} 2>/dev/null || true\n\n", vmid));

                if let Some(ref ip) = wolfnet_ip {
                    script.push_str(&format!(
                        "echo -e '\\033[0;36m  WolfNet IP: {}\\033[0m'\n",
                        ip
                    ));
                }
            } else {
                // ── Standalone host (no Proxmox) — native LXC tooling ──
                let wolfnet_ip = crate::containers::next_available_wolfnet_ip();

                script.push_str(&format!(
                    "echo -e '\\033[1;36m━━━ Installing {} via LXC ━━━\\033[0m'\n\n",
                    app.name
                ));

                // Create container
                script.push_str(&format!(
                    "echo -e '\\033[1;33m▸ Creating LXC container: {}\\033[0m'\n",
                    container_name
                ));
                let lxc_path_flag = storage_path.map(|sp| format!(" -P {}", shell_escape(sp))).unwrap_or_default();
                script.push_str(&format!(
                    "lxc-create -t download -n {}{} -- -d {} -r {} -a {}\n\n",
                    shell_escape(container_name),
                    lxc_path_flag,
                    shell_escape(&lxc.distribution),
                    shell_escape(&lxc.release),
                    shell_escape(&lxc.architecture),
                ));

                // Write WolfNet IP
                if let Some(ref ip) = wolfnet_ip {
                    let base = crate::containers::lxc_base_dir(container_name);
                    script.push_str(&format!(
                        "mkdir -p {}/{}/.wolfnet\n",
                        shell_escape(&base), shell_escape(container_name)
                    ));
                    script.push_str(&format!(
                        "echo {} > {}/{}/.wolfnet/ip\n\n",
                        shell_escape(ip), shell_escape(&base), shell_escape(container_name)
                    ));
                }

                // Start container
                script.push_str(
                    "echo -e '\\033[1;33m▸ Starting container...\\033[0m'\n"
                );
                script.push_str(&format!("lxc-start -n {}\n", shell_escape(container_name)));
                script.push_str("echo 'Waiting for container to boot...'\nsleep 3\n\n");

                // Setup commands
                let commands = substitute_inputs(&lxc.setup_commands, user_inputs);
                if !commands.is_empty() {
                    script.push_str("echo -e '\\033[1;33m▸ Running setup commands...\\033[0m'\n");
                    for cmd in &commands {
                        script.push_str(&format!(
                            "echo -e '\\033[0;90m  $ {}\\033[0m'\n",
                            cmd.replace('\'', "'\\''")
                        ));
                        script.push_str(&format!(
                            "lxc-attach -n {} -- sh -c {}\n",
                            shell_escape(container_name), shell_escape(cmd)
                        ));
                    }
                    script.push('\n');
                }

                // Stop container
                script.push_str(
                    "echo -e '\\033[1;33m▸ Stopping container...\\033[0m'\n"
                );
                script.push_str(&format!("lxc-stop -n {} 2>/dev/null || true\n\n", shell_escape(container_name)));

                if let Some(ref ip) = wolfnet_ip {
                    script.push_str(&format!(
                        "echo -e '\\033[0;36m  WolfNet IP: {}\\033[0m'\n",
                        ip
                    ));
                }
            }
        }
        "bare" => {
            let bare = app.bare_metal.as_ref()
                .ok_or("This app doesn't support bare metal installation")?;

            script.push_str(&format!(
                "echo -e '\\033[1;36m━━━ Installing {} on this host ━━━\\033[0m'\n\n",
                app.name
            ));

            // Detect distro and install packages
            let is_debian = std::path::Path::new("/etc/debian_version").exists();
            let packages = if is_debian { &bare.packages_debian } else { &bare.packages_redhat };
            let pkg_cmd = if is_debian { "apt-get" } else { "dnf" };

            if !packages.is_empty() {
                script.push_str("echo -e '\\033[1;33m▸ Installing packages...\\033[0m'\n");
                let pkg_list: Vec<String> = packages.iter().map(|p| shell_escape(p)).collect();
                script.push_str(&format!("{} install -y {}\n\n", pkg_cmd, pkg_list.join(" ")));
            }

            // Post-install commands
            let commands = substitute_inputs(&bare.post_install, user_inputs);
            if !commands.is_empty() {
                script.push_str("echo -e '\\033[1;33m▸ Running post-install configuration...\\033[0m'\n");
                for cmd in &commands {
                    script.push_str(&format!(
                        "echo -e '\\033[0;90m  $ {}\\033[0m'\n",
                        cmd.replace('\'', "'\\''")
                    ));
                    script.push_str(&format!("sh -c {}\n", shell_escape(cmd)));
                }
                script.push('\n');
            }

            // Enable service
            if let Some(ref service) = bare.service {
                script.push_str(&format!(
                    "echo -e '\\033[1;33m▸ Enabling service: {}\\033[0m'\n",
                    service
                ));
                script.push_str(&format!("systemctl enable --now {}\n\n", shell_escape(service)));
            }
        }
        _ => return Err(format!("Unknown install target: {}", target)),
    }

    // Register the installation by writing a pending file
    let installed_app = InstalledApp {
        install_id: session_id.clone(),
        app_id: app_id.to_string(),
        app_name: app.name.clone(),
        target: target.to_string(),
        container_name: Some(register_container_name.clone()),
        installed_at: chrono_timestamp(),
        sidecar_names,
        deployment_type: "docker-run".to_string(),
        compose_stack_name: None,
    };
    let pending_json = serde_json::to_string_pretty(&installed_app).unwrap_or_default();

    let pdir = pending_dir();
    script.push_str(&format!(
        "# Register the installation\nmkdir -p {}\n", pdir
    ));
    script.push_str(&format!(
        "cat > {}/{}.json << 'WOLFSTACK_REGISTER'\n{}\nWOLFSTACK_REGISTER\n\n",
        pdir, session_id, pending_json
    ));

    script.push_str("echo ''\n");
    script.push_str("echo -e '\\033[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m'\n");
    script.push_str(&format!(
        "echo -e '\\033[1;32m  ✅ {} installed successfully!\\033[0m'\n",
        app.name
    ));
    script.push_str("echo -e '\\033[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m'\n");
    script.push_str("echo -e '\\033[0;36m  Container is stopped — start it when ready.\\033[0m'\n");
    script.push_str("echo -e '\\033[0;90m  You can close this terminal now.\\033[0m'\n");

    // Write the script
    std::fs::write(&script_path, &script)
        .map_err(|e| format!("Failed to write install script: {}", e))?;

    // Make executable
    let _ = std::process::Command::new("chmod")
        .args(["+x", &script_path])
        .output();

    Ok((session_id, script_path))
}

// ─── Built-in Catalogue ───

pub fn built_in_catalogue() -> Vec<AppManifest> {
    vec![
        AppManifest {
            id: "pbs".into(),
            name: "Proxmox Backup Server".into(),
            icon: "💾".into(),
            category: "Backup".into(),
            description: "Dedicated backup server for VMs, containers, and files. Installs as a KVM VM with a WolfNet IP auto-assigned via DHCP. In the installer menu pick 'Install Proxmox Backup Server (Graphical)' — skip 'Automatic installation' which needs an answer file.".into(),
            website: Some("https://www.proxmox.com/proxmox-backup-server".into()),
            docker: None,
            lxc: None,
            bare_metal: None,
            vm: Some(VmTarget {
                // Known-good pin; install_vm auto-resolves a newer version
                // by scraping the directory index if this 404s (Proxmox ships
                // no stable `_latest.iso` alias — file name carries the ver).
                iso_url: "https://enterprise.proxmox.com/iso/proxmox-backup-server_4.1-1.iso".into(),
                memory_mb: 4096,
                cores: 2,
                // Small OS disk (PBS installs in ~4 GB — 16 gives plenty of headroom)
                disk_gb: 16,
                // Separate data disk for backups — 200 GB default, user should
                // usually crank this up to match their workload.
                data_disk_gb: Some(200),
                data_disk_label: Some("Backup storage disk (GB)".into()),
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput {
                    id: "disk_gb".into(),
                    label: "OS disk (GB)".into(),
                    input_type: "number".into(),
                    default: Some("16".into()),
                    required: false,
                    placeholder: Some("16".into()),
                    options: vec![],
                },
                UserInput {
                    id: "data_disk_gb".into(),
                    label: "Backup storage disk (GB)".into(),
                    input_type: "number".into(),
                    default: Some("200".into()),
                    required: false,
                    placeholder: Some("200".into()),
                    options: vec![],
                },
            ],
        },

        // ─── ISO-based VM apps ───
        // Firewall, hypervisors, NAS, Linux server distros. All install as
        // KVM VMs via the PBS pattern: download ISO, create VM, auto-start,
        // user finishes the installer over VNC. URLs are pinned to a known
        // version; `resolve_latest_iso` rescrapes the directory for a newer
        // image (matching prefix + version + suffix) if the pin 404s, which
        // is how a rolling distro like Debian self-heals when `current/`
        // bumps. OPNsense ships .iso.bz2 — the downloader decompresses in place.

        AppManifest {
            id: "opnsense".into(),
            name: "OPNsense".into(),
            icon: "🛡️".into(),
            category: "Firewall".into(),
            description: "Open-source firewall & routing platform (FreeBSD-based). Always gets a WAN NIC bridged to the host's uplink. LAN has TWO modes: leave 'LAN NIC' blank for WolfNet (quick/staging — but other WolfStack VMs cannot reach the WebGUI because WolfNet is point-to-point-routed, not a shared LAN), or set 'LAN NIC' to a spare physical host interface to get a real L2 LAN segment (production use). Live installer login 'installer' / 'opnsense'; WebGUI defaults 'root' / 'opnsense' — change on first login.".into(),
            website: Some("https://opnsense.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://mirror.dns-root.de/opnsense/releases/26.1.2/OPNsense-26.1.2-dvd-amd64.iso.bz2".into(),
                memory_mb: 2048,
                cores: 2,
                disk_gb: 20,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("2048".into()), required: false, placeholder: Some("2048".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("20".into()), required: false, placeholder: Some("20".into()), options: vec![] },
                UserInput {
                    id: "lan_interface".into(),
                    label: "LAN NIC (optional, blank = WolfNet)".into(),
                    input_type: "text".into(),
                    default: None,
                    required: false,
                    placeholder: Some("e.g. enp2s0 — spare host NIC for the firewall's LAN side".into()),
                    options: vec![],
                },
            ],
        },

        AppManifest {
            id: "proxmox-ve".into(),
            name: "Proxmox VE".into(),
            icon: "🧱".into(),
            category: "Virtualization".into(),
            description: "Complete server virtualization platform (KVM + LXC) with web GUI, live migration, and clustering. Nested virtualization should be enabled on the host for the guest to run VMs. In the installer pick the graphical option and follow the prompts.".into(),
            website: Some("https://www.proxmox.com/proxmox-ve".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://enterprise.proxmox.com/iso/proxmox-ve_9.1-1.iso".into(),
                memory_mb: 8192,
                cores: 4,
                disk_gb: 64,
                data_disk_gb: Some(200),
                data_disk_label: Some("VM storage disk (GB)".into()),
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("4".into()), required: false, placeholder: Some("4".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("8192".into()), required: false, placeholder: Some("8192".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "OS disk (GB)".into(), input_type: "number".into(), default: Some("64".into()), required: false, placeholder: Some("64".into()), options: vec![] },
                UserInput { id: "data_disk_gb".into(), label: "VM storage disk (GB)".into(), input_type: "number".into(), default: Some("200".into()), required: false, placeholder: Some("200".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "harvester".into(),
            name: "Harvester".into(),
            icon: "🌾".into(),
            category: "Virtualization".into(),
            description: "SUSE/Rancher hyper-converged infrastructure (Kubernetes + KubeVirt). MINIMUM SPECS: 8 CPU cores, 32 GB RAM, 250 GB disk, and nested virtualization enabled on the host. Defaults match the minimum — you can lower them for evaluation but the installer may refuse.".into(),
            website: Some("https://harvesterhci.io".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://releases.rancher.com/harvester/v1.7.1/harvester-v1.7.1-amd64.iso".into(),
                memory_mb: 32768,
                cores: 8,
                disk_gb: 250,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores (min 8)".into(), input_type: "number".into(), default: Some("8".into()), required: false, placeholder: Some("8".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory MB (min 32768)".into(), input_type: "number".into(), default: Some("32768".into()), required: false, placeholder: Some("32768".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk GB (min 250)".into(), input_type: "number".into(), default: Some("250".into()), required: false, placeholder: Some("250".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "truenas-scale".into(),
            name: "TrueNAS Community Edition".into(),
            icon: "🗄️".into(),
            category: "Storage".into(),
            description: "Open-source NAS with ZFS, snapshots, replication, and a full web UI. Official minimum is 16 GB RAM. The OS installs to the small boot disk; the large data disk becomes your storage pool (configure after install under Storage → Pools).".into(),
            website: Some("https://www.truenas.com/truenas-community-edition/".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://download.sys.truenas.net/TrueNAS-SCALE-Goldeye/25.10.2.1/TrueNAS-SCALE-25.10.2.1.iso".into(),
                memory_mb: 16384,
                cores: 4,
                disk_gb: 32,
                data_disk_gb: Some(500),
                data_disk_label: Some("Storage pool disk (GB)".into()),
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("4".into()), required: false, placeholder: Some("4".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory MB (min 16384)".into(), input_type: "number".into(), default: Some("16384".into()), required: false, placeholder: Some("16384".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Boot disk (GB)".into(), input_type: "number".into(), default: Some("32".into()), required: false, placeholder: Some("32".into()), options: vec![] },
                UserInput { id: "data_disk_gb".into(), label: "Storage pool disk (GB)".into(), input_type: "number".into(), default: Some("500".into()), required: false, placeholder: Some("500".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "ubuntu-server".into(),
            name: "Ubuntu Server 24.04 LTS".into(),
            icon: "🐧".into(),
            category: "Operating System".into(),
            description: "Ubuntu Server 24.04 LTS (Noble Numbat). Long-term support through 2029, subiquity text-mode installer. Defaults sized for a lightweight server workload — scale up for database / app workloads.".into(),
            website: Some("https://ubuntu.com/server".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://releases.ubuntu.com/24.04/ubuntu-24.04.4-live-server-amd64.iso".into(),
                memory_mb: 2048,
                cores: 2,
                disk_gb: 25,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("2048".into()), required: false, placeholder: Some("2048".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("25".into()), required: false, placeholder: Some("25".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "debian-server".into(),
            name: "Debian 13 (netinst)".into(),
            icon: "🌀".into(),
            category: "Operating System".into(),
            description: "Debian 13 'Trixie' network installer. The ISO is small (~750 MB) because packages are pulled over the network during install — the VM needs outbound internet to finish. Pick a mirror close to you when prompted.".into(),
            website: Some("https://www.debian.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso".into(),
                memory_mb: 1024,
                cores: 1,
                disk_gb: 20,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("1".into()), required: false, placeholder: Some("1".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("1024".into()), required: false, placeholder: Some("1024".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("20".into()), required: false, placeholder: Some("20".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "rocky-linux".into(),
            name: "Rocky Linux 9".into(),
            icon: "🪨".into(),
            category: "Operating System".into(),
            description: "Enterprise Linux rebuild (bug-for-bug compatible with RHEL 9). Community-driven, led by one of the original CentOS founders. Uses the Anaconda graphical installer.".into(),
            website: Some("https://rockylinux.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9-latest-x86_64-minimal.iso".into(),
                memory_mb: 2048,
                cores: 2,
                disk_gb: 20,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("2048".into()), required: false, placeholder: Some("2048".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("20".into()), required: false, placeholder: Some("20".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "almalinux".into(),
            name: "AlmaLinux 9".into(),
            icon: "🏔️".into(),
            category: "Operating System".into(),
            description: "Enterprise Linux rebuild (1:1 binary compatible with RHEL 9). Backed by CloudLinux and the AlmaLinux Foundation. Uses the Anaconda graphical installer.".into(),
            website: Some("https://almalinux.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://repo.almalinux.org/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-minimal.iso".into(),
                memory_mb: 2048,
                cores: 2,
                disk_gb: 20,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("2048".into()), required: false, placeholder: Some("2048".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("20".into()), required: false, placeholder: Some("20".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "fedora-server".into(),
            name: "Fedora Server 43".into(),
            icon: "🎩".into(),
            category: "Operating System".into(),
            description: "Fedora Server — community-driven, leading-edge kernel and toolchain, six-month release cadence. Uses the Anaconda graphical installer. Typically what RHEL becomes in a year or two.".into(),
            website: Some("https://fedoraproject.org/server/".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Server/x86_64/iso/Fedora-Server-dvd-x86_64-43-1.6.iso".into(),
                memory_mb: 2048,
                cores: 2,
                disk_gb: 20,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("2048".into()), required: false, placeholder: Some("2048".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("20".into()), required: false, placeholder: Some("20".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "alpine".into(),
            name: "Alpine Linux (virt)".into(),
            icon: "🏕️".into(),
            category: "Operating System".into(),
            description: "Security-oriented, lightweight (~67 MB ISO) Linux based on musl libc and BusyBox. The 'virt' flavour is stripped down for VM use. At the login prompt use 'root' (no password) and run 'setup-alpine' to install.".into(),
            website: Some("https://alpinelinux.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-virt-3.23.3-x86_64.iso".into(),
                memory_mb: 512,
                cores: 1,
                disk_gb: 4,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("1".into()), required: false, placeholder: Some("1".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("512".into()), required: false, placeholder: Some("512".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("4".into()), required: false, placeholder: Some("4".into()), options: vec![] },
            ],
        },

        // Desktop Linux variants — larger RAM/disk defaults because they
        // run a full desktop environment. All installable over VNC.

        AppManifest {
            id: "ubuntu-desktop".into(),
            name: "Ubuntu Desktop 24.04 LTS".into(),
            icon: "🖥️".into(),
            category: "Desktop OS".into(),
            description: "Ubuntu Desktop 24.04 LTS with GNOME. Long-term support through 2029. The live ISO also installs — pick 'Install Ubuntu' from the welcome dialog.".into(),
            website: Some("https://ubuntu.com/desktop".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://releases.ubuntu.com/24.04/ubuntu-24.04.4-desktop-amd64.iso".into(),
                memory_mb: 4096,
                cores: 2,
                disk_gb: 40,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("4096".into()), required: false, placeholder: Some("4096".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("40".into()), required: false, placeholder: Some("40".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "linux-mint".into(),
            name: "Linux Mint 22.3 (Cinnamon)".into(),
            icon: "🌿".into(),
            category: "Desktop OS".into(),
            description: "Ubuntu-LTS-based desktop with the Cinnamon environment. Friendly defaults for new Linux users, supported through 2029. Live ISO includes an installer icon on the desktop.".into(),
            website: Some("https://linuxmint.com".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://mirrors.edge.kernel.org/linuxmint/stable/22.3/linuxmint-22.3-cinnamon-64bit.iso".into(),
                memory_mb: 4096,
                cores: 2,
                disk_gb: 40,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("4096".into()), required: false, placeholder: Some("4096".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("40".into()), required: false, placeholder: Some("40".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "fedora-workstation".into(),
            name: "Fedora Workstation 43".into(),
            icon: "🎨".into(),
            category: "Desktop OS".into(),
            description: "Fedora Workstation with GNOME — showcase for newest GNOME, kernel, and toolchain. Red Hat's upstream desktop platform. Live ISO includes a 'Install to Hard Drive' shortcut.".into(),
            website: Some("https://fedoraproject.org/workstation/".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Workstation/x86_64/iso/Fedora-Workstation-Live-43-1.6.x86_64.iso".into(),
                memory_mb: 4096,
                cores: 2,
                disk_gb: 40,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("4096".into()), required: false, placeholder: Some("4096".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("40".into()), required: false, placeholder: Some("40".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "kubuntu".into(),
            name: "Kubuntu 24.04 LTS".into(),
            icon: "🅺".into(),
            category: "Desktop OS".into(),
            description: "Ubuntu 24.04 LTS with the KDE Plasma desktop. Officially recognised Ubuntu flavour, LTS through 2029. Pick 'Install Kubuntu' from the welcome dialog.".into(),
            website: Some("https://kubuntu.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://cdimage.ubuntu.com/kubuntu/releases/24.04/release/kubuntu-24.04.4-desktop-amd64.iso".into(),
                memory_mb: 4096,
                cores: 2,
                disk_gb: 40,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("4096".into()), required: false, placeholder: Some("4096".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("40".into()), required: false, placeholder: Some("40".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "debian-desktop".into(),
            name: "Debian 13 GNOME (live)".into(),
            icon: "🌀".into(),
            category: "Desktop OS".into(),
            description: "Debian 13 'Trixie' live+installer image with GNOME. Unlike netinst, packages are on the ISO — no network needed to complete install. Click 'Install Debian' inside the live session.".into(),
            website: Some("https://www.debian.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/debian-live-13.5.0-amd64-gnome.iso".into(),
                memory_mb: 4096,
                cores: 2,
                disk_gb: 40,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("4096".into()), required: false, placeholder: Some("4096".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("40".into()), required: false, placeholder: Some("40".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "endeavouros".into(),
            name: "EndeavourOS".into(),
            icon: "🚀".into(),
            category: "Desktop OS".into(),
            description: "Arch Linux rolling release with an easy Calamares installer and a choice of desktop environments at install time. Closer to pure Arch than most derivatives — ideal for learning the AUR, pacman, and rolling updates.".into(),
            website: Some("https://endeavouros.com".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://mirror.alpix.eu/endeavouros/iso/EndeavourOS_Titan-2026.03.06.iso".into(),
                memory_mb: 4096,
                cores: 2,
                disk_gb: 40,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("4096".into()), required: false, placeholder: Some("4096".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("40".into()), required: false, placeholder: Some("40".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "cachyos".into(),
            name: "CachyOS".into(),
            icon: "⚡".into(),
            category: "Desktop OS".into(),
            description: "Performance-optimised Arch Linux derivative — packages compiled with x86-64-v3/v4 and full LTO, BORE CPU scheduler, and a choice of desktops (KDE, GNOME, Xfce, i3, Hyprland...) at install. ~10% faster than vanilla Arch in their benchmarks.".into(),
            website: Some("https://cachyos.org".into()),
            docker: None, lxc: None, bare_metal: None,
            vm: Some(VmTarget {
                iso_url: "https://sourceforge.net/projects/cachyos-arch/files/gui-installer/desktop/260308/cachyos-desktop-linux-260308.iso/download".into(),
                memory_mb: 4096,
                cores: 2,
                disk_gb: 40,
                data_disk_gb: None,
                data_disk_label: None,
                vga: "std".into(),
            }),
            user_inputs: vec![
                UserInput { id: "cores".into(), label: "CPU cores".into(), input_type: "number".into(), default: Some("2".into()), required: false, placeholder: Some("2".into()), options: vec![] },
                UserInput { id: "memory_mb".into(), label: "Memory (MB)".into(), input_type: "number".into(), default: Some("4096".into()), required: false, placeholder: Some("4096".into()), options: vec![] },
                UserInput { id: "disk_gb".into(), label: "Disk (GB)".into(), input_type: "number".into(), default: Some("40".into()), required: false, placeholder: Some("40".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "superset".into(),
            name: "Apache Superset".into(),
            icon: "🔬".into(),
            category: "Analytics".into(),
            description: "Enterprise business intelligence and data exploration platform".into(),
            website: Some("https://superset.apache.org".into()),
            docker: Some(DockerTarget {
                image: "apache/superset:latest".into(),
                ports: vec!["8088:8088".into()],
                env: vec![
                    "SUPERSET_SECRET_KEY=${SECRET_KEY}".into(),
                ],
                volumes: vec!["superset_data:/app/superset_home".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Application secret key".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "appwrite".into(),
            name: "Appwrite".into(),
            icon: "🏗️".into(),
            category: "Dev Tools".into(),
            description: "Backend server for web, mobile, and Flutter developers".into(),
            website: Some("https://appwrite.io".into()),
            docker: Some(DockerTarget {
                image: "appwrite/appwrite:latest".into(),
                ports: vec!["8686:80".into()],
                env: vec![],
                volumes: vec!["appwrite_data:/storage".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        // Authentik — server + worker (same image, different cmd) +
        // Postgres + Redis. The server handles HTTP; the worker runs
        // Celery migrations and background tasks. Without the worker
        // logins stall forever.
        AppManifest {
            id: "authentik".into(),
            name: "Authentik".into(),
            icon: "🛡️".into(),
            category: "Security".into(),
            description: "Identity provider with SSO, MFA, and user management".into(),
            website: Some("https://goauthentik.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/goauthentik/server:latest".into(),
                ports: vec!["9003:9000".into(), "9444:9443".into()],
                env: vec![
                    "AUTHENTIK_SECRET_KEY=${SECRET_KEY}".into(),
                    "AUTHENTIK_POSTGRESQL__HOST=${CONTAINER_NAME}-db".into(),
                    "AUTHENTIK_POSTGRESQL__USER=authentik".into(),
                    "AUTHENTIK_POSTGRESQL__PASSWORD=${DB_PASSWORD}".into(),
                    "AUTHENTIK_POSTGRESQL__NAME=authentik".into(),
                    "AUTHENTIK_REDIS__HOST=${CONTAINER_NAME}-redis".into(),
                ],
                volumes: vec![
                    "authentik_media:/media".into(),
                    "authentik_templates:/templates".into(),
                ],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(),
                        image: "postgres:16-alpine".into(),
                        ports: vec![],
                        env: vec![
                            "POSTGRES_USER=authentik".into(),
                            "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                            "POSTGRES_DB=authentik".into(),
                        ],
                        volumes: vec!["authentik_db:/var/lib/postgresql/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "redis".into(),
                        image: "redis:7-alpine".into(),
                        ports: vec![],
                        env: vec![],
                        volumes: vec!["authentik_redis:/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "worker".into(),
                        image: "ghcr.io/goauthentik/server:latest".into(),
                        ports: vec![],
                        env: vec![
                            "AUTHENTIK_SECRET_KEY=${SECRET_KEY}".into(),
                            "AUTHENTIK_POSTGRESQL__HOST=${CONTAINER_NAME}-db".into(),
                            "AUTHENTIK_POSTGRESQL__USER=authentik".into(),
                            "AUTHENTIK_POSTGRESQL__PASSWORD=${DB_PASSWORD}".into(),
                            "AUTHENTIK_POSTGRESQL__NAME=authentik".into(),
                            "AUTHENTIK_REDIS__HOST=${CONTAINER_NAME}-redis".into(),
                        ],
                        volumes: vec![
                            "authentik_media:/media".into(),
                            "authentik_templates:/templates".into(),
                        ],
                        cmd: vec!["worker".into()],
                        post_install_exec: vec![],
                    },
                ],
                seed_files: vec![], cmd: vec!["server".into()],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Long random string (50+ chars)".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Postgres password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "caprover".into(),
            name: "CapRover".into(),
            icon: "🚀".into(),
            category: "PaaS".into(),
            description: "Easy app/database deployment & server management — PaaS on your server".into(),
            website: Some("https://caprover.com".into()),
            docker: Some(DockerTarget {
                image: "caprover/caprover:latest".into(),
                ports: vec!["3000:3000".into(), "80:80".into(), "443:443".into()],
                env: vec![],
                volumes: vec!["/var/run/docker.sock:/var/run/docker.sock".into(), "/captain:/captain".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "certbot".into(),
            name: "Certbot".into(),
            icon: "🔒".into(),
            category: "Wolf".into(),
            description: "Let's Encrypt certificate manager — free automatic HTTPS for your domains".into(),
            website: Some("https://certbot.eff.org".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y certbot".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["certbot".into()],
                packages_redhat: vec!["certbot".into()],
                post_install: vec![],
                service: None,
            }),
            vm: None, user_inputs: vec![],
        },

        // ── Container Orchestration ──

        AppManifest {
            id: "cockroachdb".into(),
            name: "CockroachDB".into(),
            icon: "🪳".into(),
            category: "Database".into(),
            description: "Distributed SQL database for global, cloud-native applications".into(),
            website: Some("https://www.cockroachlabs.com".into()),
            docker: Some(DockerTarget {
                image: "cockroachdb/cockroach:latest".into(),
                ports: vec!["26257:26257".into(), "8888:8080".into()],
                env: vec![],
                volumes: vec!["cockroach_data:/cockroach/cockroach-data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "code-server".into(),
            name: "Code Server".into(),
            icon: "💻".into(),
            category: "Dev Tools".into(),
            description: "VS Code in the browser — code from anywhere".into(),
            website: Some("https://coder.com".into()),
            docker: Some(DockerTarget {
                image: "lscr.io/linuxserver/code-server:latest".into(),
                ports: vec!["8443:8443".into()],
                env: vec![
                    "PASSWORD=${PASSWORD}".into(),
                    "PUID=1000".into(),
                    "PGID=1000".into(),
                    "TZ=UTC".into(),
                ],
                volumes: vec!["code_server_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "PASSWORD".into(), label: "Access Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password to access the IDE".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "coolify".into(),
            name: "Coolify".into(),
            icon: "🧊".into(),
            category: "PaaS".into(),
            description: "Self-hosted Heroku/Netlify/Vercel alternative with Git push deploys".into(),
            website: Some("https://coolify.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/coollabsio/coolify:latest".into(),
                ports: vec!["8000:8000".into(), "6001:6001".into(), "6002:6002".into()],
                env: vec![],
                volumes: vec!["coolify_data:/data/coolify".into(), "/var/run/docker.sock:/var/run/docker.sock:ro".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "crowdsec".into(),
            name: "CrowdSec".into(),
            icon: "🛡️".into(),
            category: "Security".into(),
            description: "Collaborative intrusion prevention — crowd-sourced threat intelligence".into(),
            website: Some("https://www.crowdsec.net".into()),
            docker: Some(DockerTarget {
                image: "crowdsecurity/crowdsec:latest".into(),
                ports: vec!["8585:8080".into(), "6060:6060".into()],
                env: vec![],
                volumes: vec!["crowdsec_data:/var/lib/crowdsec/data".into(), "crowdsec_config:/etc/crowdsec".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -s https://install.crowdsec.net | bash".into(),
                ],
                service: Some("crowdsec".into()),
            }),
            vm: None, user_inputs: vec![],
        },

        // ── Communication ──

        AppManifest {
            id: "dify".into(),
            name: "Dify".into(),
            icon: "✨".into(),
            category: "AI / ML".into(),
            description: "LLM app development platform — build AI workflows visually".into(),
            website: Some("https://dify.ai".into()),
            docker: Some(DockerTarget {
                image: "langgenius/dify-api:latest".into(),
                ports: vec!["3006:5001".into()],
                env: vec![
                    "SECRET_KEY=${SECRET_KEY}".into(),
                ],
                volumes: vec!["dify_data:/app/api/storage".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Application secret key".into()), options: vec![] },
            ],
        },

        // ── Analytics ──

        AppManifest {
            id: "dokku".into(),
            name: "Dokku".into(),
            icon: "🐳".into(),
            category: "PaaS".into(),
            description: "Open-source PaaS — mini Heroku on your own server".into(),
            website: Some("https://dokku.com".into()),
            docker: None,
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -fsSL https://packagecloud.io/dokku/dokku/gpgkey | gpg --dearmor -o /usr/share/keyrings/dokku-archive-keyring.gpg".into(),
                    "echo 'deb [signed-by=/usr/share/keyrings/dokku-archive-keyring.gpg] https://packagecloud.io/dokku/dokku/ubuntu/ jammy main' | tee /etc/apt/sources.list.d/dokku.list".into(),
                    "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y dokku".into(),
                    "dokku plugin:install-dependencies --core".into(),
                ],
                service: None,
            }),
            vm: None, user_inputs: vec![],
        },

        // ── CI/CD ──

        AppManifest {
            id: "drone".into(),
            name: "Drone CI".into(),
            icon: "🤖".into(),
            category: "CI/CD".into(),
            description: "Container-native continuous integration platform".into(),
            website: Some("https://www.drone.io".into()),
            docker: Some(DockerTarget {
                image: "drone/drone:latest".into(),
                ports: vec!["8180:80".into(), "8143:443".into()],
                env: vec![
                    "DRONE_SERVER_HOST=${DRONE_HOST}".into(),
                    "DRONE_SERVER_PROTO=https".into(),
                    "DRONE_RPC_SECRET=${RPC_SECRET}".into(),
                ],
                volumes: vec!["drone_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DRONE_HOST".into(), label: "Server Hostname".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. drone.example.com".into()), options: vec![] },
                UserInput { id: "RPC_SECRET".into(), label: "RPC Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Shared secret between server and runners".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "elasticsearch".into(),
            name: "Elasticsearch".into(),
            icon: "🔎".into(),
            category: "Database".into(),
            description: "Distributed search and analytics engine for all types of data".into(),
            website: Some("https://www.elastic.co/elasticsearch".into()),
            docker: Some(DockerTarget {
                image: "docker.elastic.co/elasticsearch/elasticsearch:8.13.0".into(),
                ports: vec!["9200:9200".into(), "9300:9300".into()],
                env: vec![
                    "discovery.type=single-node".into(),
                    "ELASTIC_PASSWORD=${ELASTIC_PASSWORD}".into(),
                    "xpack.security.enabled=true".into(),
                ],
                volumes: vec!["es_data:/usr/share/elasticsearch/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ELASTIC_PASSWORD".into(), label: "Elastic Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for elastic user".into()), options: vec![] },
            ],
        },

        // ── Monitoring (additions) ──

        AppManifest {
            id: "flowise".into(),
            name: "Flowise".into(),
            icon: "🌊".into(),
            category: "AI / ML".into(),
            description: "Drag-and-drop LLM flow builder for chatbots and AI agents".into(),
            website: Some("https://flowiseai.com".into()),
            docker: Some(DockerTarget {
                image: "flowiseai/flowise:latest".into(),
                ports: vec!["3005:3000".into()],
                env: vec![],
                volumes: vec!["flowise_data:/root/.flowise".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        // ── CMS & Publishing ──

        AppManifest {
            id: "galera-cluster".into(),
            name: "Galera Cluster".into(),
            icon: "🔄".into(),
            category: "Database".into(),
            description: "Synchronous multi-master replication for MariaDB — true high availability".into(),
            website: Some("https://galeracluster.com".into()),
            docker: Some(DockerTarget {
                image: "mariadb:11".into(),
                ports: vec!["3306:3306".into(), "4567:4567".into(), "4568:4568".into(), "4444:4444".into()],
                env: vec![
                    "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                    "MYSQL_INITDB_SKIP_TZINFO=1".into(),
                    "MARIADB_GALERA_CLUSTER_NAME=${CLUSTER_NAME}".into(),
                    "MARIADB_GALERA_CLUSTER_ADDRESS=gcomm://".into(),
                ],
                volumes: vec!["galera_data:/var/lib/mysql".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Root password".into()), options: vec![] },
                UserInput { id: "CLUSTER_NAME".into(), label: "Cluster Name".into(), input_type: "text".into(), default: Some("wolfstack_galera".into()), required: true, placeholder: None, options: vec![] },
            ],
        },


        AppManifest {
            id: "ghost".into(),
            name: "Ghost".into(),
            icon: "👻".into(),
            category: "CMS".into(),
            description: "Professional publishing platform for blogs and newsletters".into(),
            website: Some("https://ghost.org".into()),
            docker: Some(DockerTarget {
                image: "ghost:5-alpine".into(),
                ports: vec!["2368:2368".into()],
                env: vec![
                    "url=${SITE_URL}".into(),
                ],
                volumes: vec!["ghost_data:/var/lib/ghost/content".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SITE_URL".into(), label: "Site URL".into(), input_type: "text".into(), default: Some("http://localhost:2368".into()), required: true, placeholder: Some("e.g. https://blog.example.com".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "gitea".into(),
            name: "Gitea".into(),
            icon: "🍵".into(),
            category: "Dev Tools".into(),
            description: "Lightweight self-hosted Git service".into(),
            website: Some("https://gitea.io".into()),
            docker: Some(DockerTarget {
                image: "gitea/gitea:latest".into(),
                ports: vec!["3001:3000".into(), "2222:22".into()],
                env: vec![
                    "USER_UID=1000".into(),
                    "USER_GID=1000".into(),
                ],
                volumes: vec!["gitea_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Monitoring ──

        AppManifest {
            id: "gitlab-runner".into(),
            name: "GitLab Runner".into(),
            icon: "🦊".into(),
            category: "CI/CD".into(),
            description: "Run CI/CD jobs for GitLab pipelines".into(),
            website: Some("https://docs.gitlab.com/runner/".into()),
            docker: Some(DockerTarget {
                image: "gitlab/gitlab-runner:latest".into(),
                ports: vec![],
                env: vec![],
                volumes: vec!["gitlab_runner_config:/etc/gitlab-runner".into(), "/var/run/docker.sock:/var/run/docker.sock".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Automation ──

        AppManifest {
            id: "grafana".into(),
            name: "Grafana".into(),
            icon: "📊".into(),
            category: "Monitoring".into(),
            description: "Beautiful analytics and monitoring dashboards".into(),
            website: Some("https://grafana.com".into()),
            docker: Some(DockerTarget {
                image: "grafana/grafana:latest".into(),
                ports: vec!["3000:3000".into()],
                env: vec![
                    "GF_SECURITY_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["grafana_data:/var/lib/grafana".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
            ],
        },


        AppManifest {
            id: "homeassistant".into(),
            name: "Home Assistant".into(),
            icon: "🏠".into(),
            category: "Other".into(),
            description: "Open-source home automation platform".into(),
            website: Some("https://www.home-assistant.io".into()),
            docker: Some(DockerTarget {
                image: "homeassistant/home-assistant:stable".into(),
                ports: vec!["8123:8123".into()],
                env: vec!["TZ=UTC".into()],
                volumes: vec!["homeassistant_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "wolfproxy".into(),
            name: "WolfProxy".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "Reverse proxy with built-in firewall and automatic SSL via Let's Encrypt".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl".into(),
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/wolfproxy/main/setup.sh | bash".into(),
                    "systemctl enable wolfproxy".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/wolfproxy/main/setup.sh | bash".into(),
                ],
                service: Some("wolfproxy".into()),
            }),
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "hoppscotch".into(),
            name: "Hoppscotch".into(),
            icon: "🦗".into(),
            category: "Dev Tools".into(),
            description: "Open-source API development ecosystem — Postman alternative".into(),
            website: Some("https://hoppscotch.io".into()),
            docker: Some(DockerTarget {
                image: "hoppscotch/hoppscotch:latest".into(),
                ports: vec!["3012:3000".into()],
                env: vec![],
                volumes: vec!["hoppscotch_data:/app/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "huginn".into(),
            name: "Huginn".into(),
            icon: "🤖".into(),
            category: "Automation".into(),
            description: "Build agents that perform automated tasks online — IFTTT on your server".into(),
            website: Some("https://github.com/huginn/huginn".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/huginn/huginn:latest".into(),
                ports: vec!["3003:3000".into()],
                env: vec![],
                volumes: vec!["huginn_data:/var/lib/mysql".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── AI / ML ──

        AppManifest {
            id: "immich".into(),
            name: "Immich".into(),
            icon: "📷".into(),
            category: "Media".into(),
            description: "Self-hosted Google Photos alternative — fast, beautiful photo management".into(),
            website: Some("https://immich.app".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/immich-app/immich-server:latest".into(),
                ports: vec!["2283:2283".into()],
                env: vec![
                    "DB_PASSWORD=${DB_PASSWORD}".into(),
                ],
                volumes: vec!["immich_upload:/usr/src/app/upload".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "tensorchord/pgvecto-rs:pg16-v0.2.1".into(),
                    ports: vec![],
                    env: vec![
                        "POSTGRES_DB=immich".into(),
                        "POSTGRES_USER=postgres".into(),
                        "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["immich_db:/var/lib/postgresql/data".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },

        // ── File Sync ──

        AppManifest {
            id: "influxdb".into(),
            name: "InfluxDB".into(),
            icon: "📈".into(),
            category: "Database".into(),
            description: "Time-series database purpose-built for metrics, events, and IoT data".into(),
            website: Some("https://www.influxdata.com".into()),
            docker: Some(DockerTarget {
                image: "influxdb:2".into(),
                ports: vec!["8086:8086".into()],
                env: vec![
                    "DOCKER_INFLUXDB_INIT_MODE=setup".into(),
                    "DOCKER_INFLUXDB_INIT_USERNAME=${ADMIN_USER}".into(),
                    "DOCKER_INFLUXDB_INIT_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "DOCKER_INFLUXDB_INIT_ORG=${ORG_NAME}".into(),
                    "DOCKER_INFLUXDB_INIT_BUCKET=${BUCKET_NAME}".into(),
                ],
                volumes: vec!["influxdb_data:/var/lib/influxdb2".into(), "influxdb_config:/etc/influxdb2".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 8 characters".into()), options: vec![] },
                UserInput { id: "ORG_NAME".into(), label: "Organisation".into(), input_type: "text".into(), default: Some("wolfstack".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "BUCKET_NAME".into(), label: "Default Bucket".into(), input_type: "text".into(), default: Some("default".into()), required: true, placeholder: None, options: vec![] },
            ],
        },


        AppManifest {
            id: "jellyfin".into(),
            name: "Jellyfin".into(),
            icon: "🎬".into(),
            category: "Media".into(),
            description: "Free software media system for streaming movies and TV".into(),
            website: Some("https://jellyfin.org".into()),
            docker: Some(DockerTarget {
                image: "jellyfin/jellyfin:latest".into(),
                ports: vec!["8096:8096".into(), "8920:8920".into(), "7359:7359/udp".into()],
                env: vec![],
                volumes: vec!["jellyfin_config:/config".into(), "jellyfin_cache:/cache".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Other ──

        AppManifest {
            id: "keycloak".into(),
            name: "Keycloak".into(),
            icon: "🔑".into(),
            category: "Security".into(),
            // Keycloak 17+ needs an explicit `start` or `start-dev`
            // command — the bare image exits with "Please specify a
            // command". start-dev uses the in-container H2 DB, good
            // enough for a one-click demo; production users should
            // switch to `start` + a Postgres sidecar.
            description: "Enterprise identity and access management — SSO for your apps. Dev mode — data is stored in H2 locally; use Compose mode for production Postgres.".into(),
            website: Some("https://www.keycloak.org".into()),
            docker: Some(DockerTarget {
                image: "quay.io/keycloak/keycloak:latest".into(),
                ports: vec!["8484:8080".into()],
                env: vec![
                    "KEYCLOAK_ADMIN=${ADMIN_USER}".into(),
                    "KEYCLOAK_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "KC_HTTP_RELATIVE_PATH=/".into(),
                ],
                volumes: vec!["keycloak_data:/opt/keycloak/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec!["start-dev".into()],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Keycloak admin password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "kubernetes".into(),
            name: "Kubernetes (K3s)".into(),
            icon: "☸️".into(),
            category: "Container Orchestration".into(),
            description: "Lightweight Kubernetes — production-ready K8s in a single binary".into(),
            website: Some("https://k3s.io".into()),
            docker: Some(DockerTarget {
                image: "rancher/k3s:latest".into(),
                ports: vec!["6443:6443".into(), "80:80".into(), "443:443".into()],
                env: vec![
                    "K3S_TOKEN=${K3S_TOKEN}".into(),
                ],
                volumes: vec!["k3s_data:/var/lib/rancher/k3s".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sfL https://get.k3s.io | sh -".into(),
                ],
                service: Some("k3s".into()),
            }),
            vm: None, user_inputs: vec![
                UserInput { id: "K3S_TOKEN".into(), label: "Cluster Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Shared secret for joining nodes".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "mariadb".into(),
            name: "MariaDB".into(),
            icon: "🐬".into(),
            category: "Database".into(),
            description: "Community-developed fork of MySQL — fast, stable, and open source".into(),
            website: Some("https://mariadb.org".into()),
            docker: Some(DockerTarget {
                image: "mariadb:11".into(),
                ports: vec!["3306:3306".into()],
                env: vec![
                    "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                    "MYSQL_DATABASE=${DB_NAME}".into(),
                ],
                volumes: vec!["mariadb_data:/var/lib/mysql".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y mariadb-server".into(),
                    "sed -i 's/bind-address.*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf".into(),
                    "systemctl enable mariadb".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["mariadb-server".into()],
                packages_redhat: vec!["mariadb-server".into()],
                post_install: vec!["systemctl enable mariadb".into()],
                service: Some("mariadb".into()),
            }),
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Root password".into()), options: vec![] },
                UserInput { id: "DB_NAME".into(), label: "Database Name".into(), input_type: "text".into(), default: Some("mydb".into()), required: false, placeholder: None, options: vec![] },
            ],
        },


        AppManifest {
            id: "matrix-synapse".into(),
            name: "Matrix (Synapse)".into(),
            icon: "🔗".into(),
            category: "Communication".into(),
            description: "Decentralized, end-to-end encrypted messaging and collaboration".into(),
            website: Some("https://matrix.org".into()),
            docker: Some(DockerTarget {
                image: "matrixdotorg/synapse:latest".into(),
                ports: vec!["8008:8008".into(), "8448:8448".into()],
                env: vec![
                    "SYNAPSE_SERVER_NAME=${SERVER_NAME}".into(),
                    "SYNAPSE_REPORT_STATS=no".into(),
                ],
                volumes: vec!["synapse_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. matrix.example.com".into()), options: vec![] },
            ],
        },

        // ── Project Management ──

        AppManifest {
            id: "mattermost".into(),
            name: "Mattermost".into(),
            icon: "💬".into(),
            category: "Communication".into(),
            description: "Secure messaging for teams — open-source and self-hosted".into(),
            website: Some("https://mattermost.com".into()),
            docker: Some(DockerTarget {
                image: "mattermost/mattermost-team-edition:latest".into(),
                ports: vec!["8065:8065".into()],
                env: vec![
                    "MM_SQLSETTINGS_DRIVERNAME=postgres".into(),
                    "MM_SQLSETTINGS_DATASOURCE=postgres://mattermost:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/mattermost?sslmode=disable".into(),
                ],
                volumes: vec!["mattermost_data:/mattermost/data".into(), "mattermost_config:/mattermost/config".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "postgres:16-alpine".into(),
                    ports: vec![],
                    env: vec![
                        "POSTGRES_DB=mattermost".into(),
                        "POSTGRES_USER=mattermost".into(),
                        "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["mattermost_db:/var/lib/postgresql/data".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "meilisearch".into(),
            name: "Meilisearch".into(),
            icon: "🔍".into(),
            category: "Database".into(),
            description: "Lightning fast, typo-tolerant search engine".into(),
            website: Some("https://www.meilisearch.com".into()),
            docker: Some(DockerTarget {
                image: "getmeili/meilisearch:latest".into(),
                ports: vec!["7700:7700".into()],
                env: vec![
                    "MEILI_MASTER_KEY=${MASTER_KEY}".into(),
                ],
                volumes: vec!["meilisearch_data:/meili_data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MASTER_KEY".into(), label: "Master Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("API master key (min 16 chars)".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "metabase".into(),
            name: "Metabase".into(),
            icon: "📉".into(),
            category: "Analytics".into(),
            description: "Business intelligence dashboards and data exploration for everyone".into(),
            website: Some("https://www.metabase.com".into()),
            docker: Some(DockerTarget {
                image: "metabase/metabase:latest".into(),
                ports: vec!["3008:3000".into()],
                env: vec![],
                volumes: vec!["metabase_data:/metabase-data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Security ──

        AppManifest {
            id: "minio".into(),
            name: "MinIO".into(),
            icon: "📦".into(),
            category: "Storage".into(),
            description: "High-performance S3-compatible object storage".into(),
            website: Some("https://min.io".into()),
            docker: Some(DockerTarget {
                image: "minio/minio:latest".into(),
                ports: vec!["9001:9001".into(), "9002:9000".into()],
                env: vec![
                    "MINIO_ROOT_USER=${ADMIN_USER}".into(),
                    "MINIO_ROOT_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["minio_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Root Username".into(), input_type: "text".into(), default: Some("minioadmin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 8 characters".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "mongodb".into(),
            name: "MongoDB".into(),
            icon: "🍃".into(),
            category: "Database".into(),
            description: "Document-oriented NoSQL database for modern applications".into(),
            website: Some("https://www.mongodb.com".into()),
            docker: Some(DockerTarget {
                image: "mongo:7".into(),
                ports: vec!["27017:27017".into()],
                env: vec![
                    "MONGO_INITDB_ROOT_USERNAME=${DB_USER}".into(),
                    "MONGO_INITDB_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                ],
                volumes: vec!["mongo_data:/data/db".into(), "mongo_config:/data/configdb".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "mysql".into(),
            name: "MySQL".into(),
            icon: "🐬".into(),
            category: "Database".into(),
            description: "The world's most popular open-source relational database".into(),
            website: Some("https://www.mysql.com".into()),
            docker: Some(DockerTarget {
                image: "mysql:8.4".into(),
                ports: vec!["3307:3306".into()],
                env: vec![
                    "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                    "MYSQL_DATABASE=${DB_NAME}".into(),
                ],
                volumes: vec!["mysql_data:/var/lib/mysql".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y default-mysql-server".into(),
                    "sed -i 's/bind-address.*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf || true".into(),
                    "systemctl enable mysql".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["mysql-server".into()],
                packages_redhat: vec!["mysql-server".into()],
                post_install: vec!["systemctl enable mysqld".into()],
                service: Some("mysqld".into()),
            }),
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Root password".into()), options: vec![] },
                UserInput { id: "DB_NAME".into(), label: "Database Name".into(), input_type: "text".into(), default: Some("mydb".into()), required: false, placeholder: None, options: vec![] },
            ],
        },


        AppManifest {
            id: "n8n".into(),
            name: "n8n".into(),
            icon: "⚡".into(),
            category: "Automation".into(),
            description: "Workflow automation platform — open-source Zapier alternative".into(),
            website: Some("https://n8n.io".into()),
            docker: Some(DockerTarget {
                image: "n8nio/n8n:latest".into(),
                ports: vec!["5678:5678".into()],
                env: vec![],
                volumes: vec!["n8n_data:/home/node/.n8n".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for n8n UI".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "netdata".into(),
            name: "Netdata".into(),
            icon: "📡".into(),
            category: "Monitoring".into(),
            description: "Real-time performance and health monitoring for systems and apps".into(),
            website: Some("https://www.netdata.cloud".into()),
            docker: Some(DockerTarget {
                image: "netdata/netdata:latest".into(),
                ports: vec!["19999:19999".into()],
                env: vec![],
                volumes: vec!["netdata_config:/etc/netdata".into(), "netdata_lib:/var/lib/netdata".into(), "netdata_cache:/var/cache/netdata".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -fsSL https://get.netdata.cloud/kickstart.sh | bash".into(),
                ],
                service: Some("netdata".into()),
            }),
            vm: None, user_inputs: vec![],
        },

        // ── Dev Tools (additions) ──

        AppManifest {
            id: "nextcloud".into(),
            name: "Nextcloud".into(),
            icon: "☁️".into(),
            category: "Web".into(),
            description: "Self-hosted cloud storage, file sync, and collaboration platform".into(),
            website: Some("https://nextcloud.com".into()),
            docker: Some(DockerTarget {
                image: "nextcloud:latest".into(),
                ports: vec!["8081:80".into()],
                env: vec![
                    "MYSQL_HOST=${CONTAINER_NAME}-db".into(),
                    "MYSQL_DATABASE=nextcloud".into(),
                    "MYSQL_USER=nextcloud".into(),
                    "MYSQL_PASSWORD=${DB_PASSWORD}".into(),
                    "NEXTCLOUD_ADMIN_USER=${ADMIN_USER}".into(),
                    "NEXTCLOUD_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["nextcloud_data:/var/www/html".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:11".into(),
                    ports: vec![],
                    env: vec![
                        "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                        "MYSQL_DATABASE=nextcloud".into(),
                        "MYSQL_USER=nextcloud".into(),
                        "MYSQL_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["nextcloud_db:/var/lib/mysql".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Database password".into()), options: vec![] },
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "nginx".into(),
            name: "Nginx".into(),
            icon: "🔀".into(),
            category: "Networking".into(),
            description: "High-performance web server and reverse proxy".into(),
            website: Some("https://nginx.org".into()),
            docker: Some(DockerTarget {
                image: "nginx:alpine".into(),
                ports: vec!["8082:80".into(), "8443:443".into()],
                env: vec![],
                volumes: vec!["nginx_html:/usr/share/nginx/html".into(), "nginx_conf:/etc/nginx".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["nginx".into()],
                packages_redhat: vec!["nginx".into()],
                post_install: vec![],
                service: Some("nginx".into()),
            }),
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "nocodb".into(),
            name: "NocoDB".into(),
            icon: "📊".into(),
            category: "Dev Tools".into(),
            description: "Open-source Airtable alternative — turn any database into a spreadsheet".into(),
            website: Some("https://nocodb.com".into()),
            docker: Some(DockerTarget {
                image: "nocodb/nocodb:latest".into(),
                ports: vec!["8686:8080".into()],
                env: vec![],
                volumes: vec!["nocodb_data:/usr/app/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Networking (additions) ──

        AppManifest {
            id: "nomad".into(),
            name: "Nomad".into(),
            icon: "📦".into(),
            category: "Container Orchestration".into(),
            description: "HashiCorp workload orchestrator for containers and non-containerized apps".into(),
            website: Some("https://www.nomadproject.io".into()),
            docker: Some(DockerTarget {
                image: "hashicorp/nomad:latest".into(),
                ports: vec!["4646:4646".into(), "4647:4647".into(), "4648:4648".into()],
                env: vec![],
                volumes: vec!["nomad_data:/nomad/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── PaaS & Deployment ──

        AppManifest {
            id: "ollama".into(),
            name: "Ollama".into(),
            icon: "🦙".into(),
            category: "AI / ML".into(),
            description: "Run large language models locally — Llama, Mistral, Gemma and more".into(),
            website: Some("https://ollama.com".into()),
            docker: Some(DockerTarget {
                image: "ollama/ollama:latest".into(),
                ports: vec!["11434:11434".into()],
                env: vec![],
                volumes: vec!["ollama_data:/root/.ollama".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -fsSL https://ollama.com/install.sh | sh".into(),
                ],
                service: Some("ollama".into()),
            }),
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "open-webui".into(),
            name: "Open WebUI".into(),
            icon: "🧠".into(),
            category: "AI / ML".into(),
            description: "ChatGPT-style interface for local LLMs — works with Ollama".into(),
            website: Some("https://openwebui.com".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/open-webui/open-webui:main".into(),
                ports: vec!["3004:8080".into()],
                env: vec![],
                volumes: vec!["open_webui_data:/app/backend/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "pihole".into(),
            name: "Pi-hole".into(),
            icon: "🕳️".into(),
            category: "Networking".into(),
            description: "Network-wide ad blocker and DNS sinkhole".into(),
            website: Some("https://pi-hole.net".into()),
            docker: Some(DockerTarget {
                image: "pihole/pihole:latest".into(),
                ports: vec!["53:53/tcp".into(), "53:53/udp".into(), "8084:80".into()],
                env: vec![
                    "WEBPASSWORD=${ADMIN_PASSWORD}".into(),
                    "TZ=UTC".into(),
                ],
                volumes: vec!["pihole_config:/etc/pihole".into(), "pihole_dnsmasq:/etc/dnsmasq.d".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Web admin password".into()), options: vec![] },
            ],
        },

        // ── Media ──

        AppManifest {
            id: "plane".into(),
            name: "Plane".into(),
            icon: "✈️".into(),
            category: "Project Management".into(),
            description: "Open-source Jira/Linear alternative — issue tracking and project planning".into(),
            website: Some("https://plane.so".into()),
            docker: Some(DockerTarget {
                image: "makeplane/plane-frontend:latest".into(),
                ports: vec!["3010:3000".into()],
                env: vec![],
                volumes: vec!["plane_data:/app/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "plausible".into(),
            name: "Plausible Analytics".into(),
            icon: "📊".into(),
            category: "Analytics".into(),
            description: "Privacy-friendly Google Analytics alternative — no cookies".into(),
            website: Some("https://plausible.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/plausible/community-edition:latest".into(),
                ports: vec!["8282:8000".into()],
                env: vec![
                    "BASE_URL=${BASE_URL}".into(),
                    "SECRET_KEY_BASE=${SECRET_KEY}".into(),
                ],
                volumes: vec!["plausible_data:/var/lib/plausible".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "BASE_URL".into(), label: "Base URL".into(), input_type: "text".into(), default: Some("http://localhost:8282".into()), required: true, placeholder: Some("e.g. https://analytics.example.com".into()), options: vec![] },
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("64-character secret".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "pocketbase".into(),
            name: "PocketBase".into(),
            icon: "📱".into(),
            category: "Dev Tools".into(),
            description: "Open-source backend in a single file — SQLite + Auth + Realtime".into(),
            website: Some("https://pocketbase.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/muchobien/pocketbase:latest".into(),
                ports: vec!["8090:8090".into()],
                env: vec![],
                volumes: vec!["pocketbase_data:/pb_data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Search ──

        AppManifest {
            id: "portainer".into(),
            name: "Portainer".into(),
            icon: "🐳".into(),
            category: "Other".into(),
            description: "Docker management UI with container visualization".into(),
            website: Some("https://portainer.io".into()),
            docker: Some(DockerTarget {
                image: "portainer/portainer-ce:latest".into(),
                ports: vec!["9000:9000".into(), "9443:9443".into()],
                env: vec![],
                volumes: vec!["/var/run/docker.sock:/var/run/docker.sock".into(), "portainer_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "postgres".into(),
            name: "PostgreSQL".into(),
            icon: "🐘".into(),
            category: "Database".into(),
            description: "Powerful, reliable, open-source relational database".into(),
            website: Some("https://www.postgresql.org".into()),
            docker: Some(DockerTarget {
                image: "postgres:16".into(),
                ports: vec!["5432:5432".into()],
                env: vec![
                    "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    "POSTGRES_USER=${DB_USER}".into(),
                ],
                volumes: vec!["postgres_data:/var/lib/postgresql/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["postgresql".into()],
                packages_redhat: vec!["postgresql-server".into()],
                post_install: vec!["postgresql-setup --initdb || true".into()],
                service: Some("postgresql".into()),
            }),
            vm: None, user_inputs: vec![
                UserInput { id: "DB_USER".into(), label: "Username".into(), input_type: "text".into(), default: Some("postgres".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Database password".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "prometheus".into(),
            name: "Prometheus".into(),
            icon: "🔥".into(),
            category: "Monitoring".into(),
            description: "Systems and service monitoring with time-series database".into(),
            website: Some("https://prometheus.io".into()),
            docker: Some(DockerTarget {
                image: "prom/prometheus:latest".into(),
                ports: vec!["9090:9090".into()],
                env: vec![],
                // Mount the config dir as a named volume so we can seed
                // a minimal prometheus.yml into it before first start —
                // otherwise the container exits immediately with
                // "error loading config: open /etc/prometheus/prometheus.yml".
                volumes: vec!["prometheus_data:/prometheus".into(), "prometheus_config:/etc/prometheus".into()],
                sidecars: vec![],
                seed_files: vec![SeedFile {
                    container_path: "/etc/prometheus/prometheus.yml".into(),
                    content: "global:\n  scrape_interval: 15s\n\nscrape_configs:\n  - job_name: prometheus\n    static_configs:\n      - targets: ['localhost:9090']\n".into(),
                }], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Database ──

        AppManifest {
            id: "redis".into(),
            name: "Redis".into(),
            icon: "⚡".into(),
            category: "Database".into(),
            description: "In-memory data store used as cache, message broker, and database".into(),
            website: Some("https://redis.io".into()),
            docker: Some(DockerTarget {
                image: "redis:7-alpine".into(),
                ports: vec!["6379:6379".into()],
                env: vec![],
                volumes: vec!["redis_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["redis-server".into()],
                packages_redhat: vec!["redis".into()],
                post_install: vec![],
                service: Some("redis-server".into()),
            }),
            vm: None, user_inputs: vec![],
        },


        // Rocket.Chat — Mongo must be started with `--replSet rs0`
        // and then have `rs.initiate()` run once before the app will
        // accept traffic. Sidecar `cmd` handles the flag; sidecar
        // `post_install_exec` runs the one-shot `rs.initiate()` via
        // `mongosh`.
        AppManifest {
            id: "rocketchat".into(),
            name: "Rocket.Chat".into(),
            icon: "💬".into(),
            category: "Communication".into(),
            description: "Team communication platform — open-source Slack alternative".into(),
            website: Some("https://rocket.chat".into()),
            docker: Some(DockerTarget {
                image: "rocketchat/rocket.chat:latest".into(),
                ports: vec!["3009:3000".into()],
                env: vec![
                    "MONGO_URL=mongodb://${CONTAINER_NAME}-db:27017/rocketchat?replicaSet=rs0".into(),
                    "MONGO_OPLOG_URL=mongodb://${CONTAINER_NAME}-db:27017/local?replicaSet=rs0".into(),
                    "ROOT_URL=${ROOT_URL}".into(),
                ],
                volumes: vec!["rocketchat_uploads:/app/uploads".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mongo:6".into(),
                    ports: vec![],
                    env: vec![],
                    volumes: vec!["rocketchat_db:/data/db".into()],
                    cmd: vec!["--replSet".into(), "rs0".into(), "--oplogSize".into(), "128".into()],
                    // Member hostname must be what the app container
                    // uses to connect — localhost won't resolve from
                    // inside rocketchat's network namespace.
                    post_install_exec: vec![
                        vec!["mongosh".into(), "--eval".into(), "rs.initiate({_id:'rs0',members:[{_id:0,host:'${CONTAINER_NAME}-db:27017'}]})".into()],
                    ],
                }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ROOT_URL".into(), label: "Root URL".into(), input_type: "text".into(), default: Some("http://localhost:3009".into()), required: true, placeholder: Some("e.g. https://chat.example.com".into()), options: vec![] },
            ],
        },


        AppManifest {
            id: "sqlite-web".into(),
            name: "SQLite Web".into(),
            icon: "🪶".into(),
            category: "Database".into(),
            description: "Web-based SQLite database browser and manager in a container".into(),
            website: Some("https://github.com/nicois/sqlite-web".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/nicois/sqlite-web:latest".into(),
                ports: vec!["8085:8080".into()],
                env: vec![],
                volumes: vec!["sqlite_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Networking ──

        AppManifest {
            id: "strapi".into(),
            name: "Strapi".into(),
            icon: "🚀".into(),
            category: "CMS".into(),
            description: "Leading open-source headless CMS — 100% JavaScript/TypeScript".into(),
            website: Some("https://strapi.io".into()),
            docker: Some(DockerTarget {
                image: "naskio/strapi:latest".into(),
                ports: vec!["1337:1337".into()],
                env: vec![],
                volumes: vec!["strapi_data:/srv/app".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Photo & Media ──

        // (duplicate Supabase entry removed — there's a proper LXC-
        // backed one earlier in the list with the full stack.)

        AppManifest {
            id: "syncthing".into(),
            name: "Syncthing".into(),
            icon: "🔄".into(),
            category: "Other".into(),
            description: "Continuous peer-to-peer file synchronization between devices".into(),
            website: Some("https://syncthing.net".into()),
            docker: Some(DockerTarget {
                image: "syncthing/syncthing:latest".into(),
                ports: vec!["8384:8384".into(), "22000:22000/tcp".into(), "22000:22000/udp".into(), "21027:21027/udp".into()],
                env: vec![],
                volumes: vec!["syncthing_data:/var/syncthing".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["syncthing".into()],
                packages_redhat: vec!["syncthing".into()],
                post_install: vec![],
                service: Some("syncthing@root".into()),
            }),
            vm: None, user_inputs: vec![],
        },

        // ── Backend / BaaS ──

        AppManifest {
            id: "taiga".into(),
            name: "Taiga".into(),
            icon: "🌲".into(),
            category: "Project Management".into(),
            description: "Agile project management for cross-functional teams".into(),
            website: Some("https://taiga.io".into()),
            docker: Some(DockerTarget {
                image: "taigaio/taiga-back:latest".into(),
                ports: vec!["8686:8000".into()],
                env: vec![],
                volumes: vec!["taiga_data:/taiga-back/media".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "traefik".into(),
            name: "Traefik".into(),
            icon: "🚦".into(),
            category: "Networking".into(),
            description: "Modern reverse proxy and load balancer with auto SSL".into(),
            website: Some("https://traefik.io".into()),
            docker: Some(DockerTarget {
                image: "traefik:v3.0".into(),
                ports: vec!["80:80".into(), "443:443".into(), "8083:8080".into()],
                env: vec![],
                volumes: vec!["/var/run/docker.sock:/var/run/docker.sock:ro".into(), "traefik_data:/etc/traefik".into()],
                sidecars: vec![],
                // Traefik boots without a static config (uses defaults)
                // but the dashboard is disabled unless explicitly on.
                // Ship a minimal traefik.yml that enables the dashboard
                // and the docker provider so the image is useful out
                // of the box.
                seed_files: vec![SeedFile {
                    container_path: "/etc/traefik/traefik.yml".into(),
                    content: "api:\n  dashboard: true\n  insecure: true\n\nentryPoints:\n  web:\n    address: ':80'\n  websecure:\n    address: ':443'\n\nproviders:\n  docker:\n    exposedByDefault: false\n".into(),
                }], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "umami".into(),
            name: "Umami".into(),
            icon: "📈".into(),
            category: "Analytics".into(),
            description: "Simple, fast, privacy-focused website analytics".into(),
            website: Some("https://umami.is".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/umami-software/umami:postgresql-latest".into(),
                ports: vec!["3007:3000".into()],
                env: vec![
                    "DATABASE_URL=postgresql://umami:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/umami".into(),
                ],
                volumes: vec![],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "postgres:16-alpine".into(),
                    ports: vec![],
                    env: vec![
                        "POSTGRES_DB=umami".into(),
                        "POSTGRES_USER=umami".into(),
                        "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["umami_db:/var/lib/postgresql/data".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },


        // (duplicate Uptime Kuma entry removed — there's one further
        // down under "Trending & Self-Hosted Favourites" with Docker +
        // LXC install paths. This Docker-only copy shadowed it via
        // get_app's first-match and rendered twice in the store UI.)

        // (duplicate Vaultwarden entry removed — there's one further
        // down with Docker + LXC install paths.)

        AppManifest {
            id: "wireguard".into(),
            name: "WireGuard".into(),
            icon: "🔒".into(),
            category: "Networking".into(),
            description: "Fast, modern VPN using state-of-the-art cryptography".into(),
            website: Some("https://www.wireguard.com".into()),
            docker: None,
            lxc: None,
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["wireguard".into(), "wireguard-tools".into()],
                packages_redhat: vec!["wireguard-tools".into()],
                post_install: vec![
                    "wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey".into(),
                    "chmod 600 /etc/wireguard/privatekey".into(),
                ],
                service: Some("wg-quick@wg0".into()),
            }),
            vm: None, user_inputs: vec![],
        },

        // ── Database (additions) ──

        AppManifest {
            id: "wolfdisk".into(),
            name: "WolfDisk".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "Distributed filesystem for seamless storage across your cluster".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl fuse3".into(),
                    // setup.sh installs the binary, writes /etc/systemd/system/
                    // wolfdisk.service, then enables + starts it. The separate
                    // `systemctl enable wolfdisk` that used to follow here threw
                    // "Unit wolfdisk.service not found" whenever setup.sh failed
                    // before the service block — masking the real error. Let
                    // setup.sh own the whole install.
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/wolfdisk/setup.sh | bash".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/wolfdisk/setup.sh | bash".into(),
                ],
                service: Some("wolfdisk".into()),
            }),
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "wolfscale".into(),
            name: "WolfScale".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "MariaDB-compatible distributed database with automatic replication".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl".into(),
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/setup.sh | bash -s -- --component wolfscale".into(),
                    "systemctl enable wolfscale".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/setup.sh | bash -s -- --component wolfscale".into(),
                ],
                service: Some("wolfscale".into()),
            }),
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "wolfserve".into(),
            name: "WolfServe".into(),
            icon: "🐺".into(),
            category: "Wolf".into(),
            description: "High-performance web server for static sites and applications".into(),
            website: Some("https://wolf.uk.com".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl".into(),
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/wolfserve/main/setup.sh | bash".into(),
                    "systemctl enable wolfserve".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec![],
                packages_redhat: vec![],
                post_install: vec![
                    "curl -sSL https://raw.githubusercontent.com/intelligentwolf/wolfserve/main/setup.sh | bash".into(),
                ],
                service: Some("wolfserve".into()),
            }),
            vm: None, user_inputs: vec![],
        },


        AppManifest {
            id: "woodpecker".into(),
            name: "Woodpecker CI".into(),
            icon: "🪶".into(),
            category: "CI/CD".into(),
            description: "Lightweight CI/CD engine with great extensibility".into(),
            website: Some("https://woodpecker-ci.org".into()),
            docker: Some(DockerTarget {
                image: "woodpeckerci/woodpecker-server:latest".into(),
                ports: vec!["8200:8000".into()],
                env: vec![
                    "WOODPECKER_OPEN=true".into(),
                    "WOODPECKER_ADMIN=${ADMIN_USER}".into(),
                ],
                volumes: vec!["woodpecker_data:/var/lib/woodpecker".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
            ],
        },


        AppManifest {
            id: "wordpress".into(),
            name: "WordPress".into(),
            icon: "🌐".into(),
            category: "Web".into(),
            description: "The world's most popular CMS for blogs and websites".into(),
            website: Some("https://wordpress.org".into()),
            docker: Some(DockerTarget {
                image: "wordpress:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec![
                    "WORDPRESS_DB_HOST=${CONTAINER_NAME}-db".into(),
                    "WORDPRESS_DB_USER=wordpress".into(),
                    "WORDPRESS_DB_PASSWORD=${DB_PASSWORD}".into(),
                    "WORDPRESS_DB_NAME=wordpress".into(),
                ],
                volumes: vec!["wordpress_data:/var/www/html".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:11".into(),
                    ports: vec![],
                    env: vec![
                        "MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(),
                        "MYSQL_DATABASE=wordpress".into(),
                        "MYSQL_USER=wordpress".into(),
                        "MYSQL_PASSWORD=${DB_PASSWORD}".into(),
                    ],
                    volumes: vec!["wordpress_db:/var/lib/mysql".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y apache2 php php-mysql php-gd php-xml php-mbstring mariadb-server curl".into(),
                    "systemctl start mariadb".into(),
                    "mysql -e \"CREATE DATABASE wordpress; CREATE USER 'wordpress'@'localhost' IDENTIFIED BY '${DB_PASSWORD}'; GRANT ALL ON wordpress.* TO 'wordpress'@'localhost'; FLUSH PRIVILEGES;\"".into(),
                    "cd /var/www/html && curl -sL https://wordpress.org/latest.tar.gz | tar xz --strip-components=1".into(),
                    "chown -R www-data:www-data /var/www/html".into(),
                    "systemctl enable apache2 mariadb".into(),
                ],
            }),
            bare_metal: Some(BareMetalTarget {
                packages_debian: vec!["apache2".into(), "php".into(), "php-mysql".into(), "php-gd".into(), "php-xml".into(), "php-mbstring".into(), "mariadb-server".into()],
                packages_redhat: vec!["httpd".into(), "php".into(), "php-mysqlnd".into(), "php-gd".into(), "php-xml".into(), "php-mbstring".into(), "mariadb-server".into()],
                post_install: vec![
                    "systemctl enable --now mariadb".into(),
                    "cd /var/www/html && curl -sL https://wordpress.org/latest.tar.gz | tar xz --strip-components=1 && chown -R www-data:www-data /var/www/html".into(),
                ],
                service: Some("apache2".into()),
            }),
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Strong password for the database".into()), options: vec![] },
            ],
        },

        // ── New: Trending & Self-Hosted Favourites ──

        AppManifest {
            id: "uptime-kuma".into(),
            name: "Uptime Kuma".into(),
            icon: "📈".into(),
            category: "Monitoring".into(),
            description: "Self-hosted uptime monitoring tool with beautiful status pages".into(),
            website: Some("https://github.com/louislam/uptime-kuma".into()),
            docker: Some(DockerTarget {
                image: "louislam/uptime-kuma:latest".into(),
                ports: vec!["3001:3001".into()],
                env: vec![],
                volumes: vec!["uptime_kuma_data:/app/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "git clone https://github.com/louislam/uptime-kuma.git /opt/uptime-kuma".into(),
                    "cd /opt/uptime-kuma && npm run setup".into(),
                    "cat > /etc/systemd/system/uptime-kuma.service << 'EOF'\n[Unit]\nDescription=Uptime Kuma\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/uptime-kuma\nExecStart=/usr/bin/node server/server.js\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable uptime-kuma".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "vaultwarden".into(),
            name: "Vaultwarden".into(),
            icon: "🔐".into(),
            category: "Security".into(),
            description: "Lightweight Bitwarden-compatible password manager server".into(),
            website: Some("https://github.com/dani-garcia/vaultwarden".into()),
            docker: Some(DockerTarget {
                image: "vaultwarden/server:latest".into(),
                ports: vec!["8780:80".into()],
                env: vec![
                    "ADMIN_TOKEN=${ADMIN_TOKEN}".into(),
                ],
                volumes: vec!["vaultwarden_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl wget libssl3 ca-certificates".into(),
                    "mkdir -p /opt/vaultwarden /var/lib/vaultwarden".into(),
                    // Arch-aware: vaultwarden names assets by `uname -m` (x86_64 / aarch64).
                    "wget -O /tmp/vw.tar.gz https://github.com/dani-garcia/vaultwarden/releases/latest/download/vaultwarden-linux-$(uname -m).tar.gz || echo 'Download may require manual setup'".into(),
                    "cat > /etc/systemd/system/vaultwarden.service << 'EOF'\n[Unit]\nDescription=Vaultwarden\nAfter=network.target\n[Service]\nEnvironment=DATA_FOLDER=/var/lib/vaultwarden\nEnvironment=ADMIN_TOKEN=${ADMIN_TOKEN}\nExecStart=/opt/vaultwarden/vaultwarden\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable vaultwarden".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_TOKEN".into(), label: "Admin Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Secret token for admin panel access".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "paperless-ngx".into(),
            name: "Paperless-ngx".into(),
            icon: "📄".into(),
            category: "Productivity".into(),
            // Paperless-ngx refuses to start without a Redis broker
            // for its Celery workers. SQLite is bundled so we don't
            // need a Postgres sidecar — Redis alone unbricks the
            // single-container install.
            description: "Document management system that transforms physical documents into a searchable archive".into(),
            website: Some("https://docs.paperless-ngx.com".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/paperless-ngx/paperless-ngx:latest".into(),
                ports: vec!["8777:8000".into()],
                env: vec![
                    "PAPERLESS_SECRET_KEY=${SECRET_KEY}".into(),
                    "PAPERLESS_ADMIN_USER=admin".into(),
                    "PAPERLESS_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "PAPERLESS_REDIS=redis://${CONTAINER_NAME}-redis:6379".into(),
                ],
                volumes: vec!["paperless_data:/usr/src/paperless/data".into(), "paperless_media:/usr/src/paperless/media".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "redis".into(),
                    image: "redis:7-alpine".into(),
                    ports: vec![],
                    env: vec![],
                    volumes: vec!["paperless_redis:/data".into()],
                 cmd: vec![], post_install_exec: vec![] }],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y python3 python3-pip python3-venv redis-server imagemagick gnupg2 curl".into(),
                    "pip3 install paperless-ngx || echo 'Install via Docker recommended for production'".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Application secret key".into()), options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for admin user".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "opencti".into(),
            name: "OpenCTI".into(),
            icon: "🔍".into(),
            category: "Security".into(),
            description: "Open Cyber Threat Intelligence Platform — knowledge management for threat analysis".into(),
            website: Some("https://github.com/OpenCTI-Platform/opencti".into()),
            docker: Some(DockerTarget {
                image: "opencti/platform:latest".into(),
                ports: vec!["8787:8080".into()],
                env: vec![
                    "OPENCTI_ADMIN_EMAIL=${ADMIN_EMAIL}".into(),
                    "OPENCTI_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "OPENCTI_ADMIN_TOKEN=${ADMIN_TOKEN}".into(),
                ],
                volumes: vec!["opencti_data:/opt/opencti/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git nodejs npm python3 python3-pip".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs".into(),
                    "git clone https://github.com/OpenCTI-Platform/opencti.git /opt/opencti".into(),
                    "cd /opt/opencti && npm install".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_EMAIL".into(), label: "Admin Email".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("admin@example.com".into()), options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Strong admin password".into()), options: vec![] },
                UserInput { id: "ADMIN_TOKEN".into(), label: "Admin API Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("UUID for API access".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "outline".into(),
            name: "Outline".into(),
            icon: "📝".into(),
            category: "Productivity".into(),
            description: "Beautiful wiki and knowledge base for growing teams — Notion alternative".into(),
            website: Some("https://getoutline.com".into()),
            // Docker mode: the Postgres and Redis sidecars it depends
            // on are now properly declared. Outline runs its own DB
            // migration on first boot so no post-install step needed.
            docker: Some(DockerTarget {
                image: "outlinewiki/outline:latest".into(),
                ports: vec!["3003:3000".into()],
                env: vec![
                    "SECRET_KEY=${SECRET_KEY}".into(),
                    "UTILS_SECRET=${UTILS_SECRET}".into(),
                    "DATABASE_URL=postgres://outline:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/outline".into(),
                    "REDIS_URL=redis://${CONTAINER_NAME}-redis:6379".into(),
                    "URL=${URL}".into(),
                    "PGSSLMODE=disable".into(),
                ],
                volumes: vec!["outline_data:/var/lib/outline/data".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(),
                        image: "postgres:15-alpine".into(),
                        ports: vec![],
                        env: vec![
                            "POSTGRES_USER=outline".into(),
                            "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                            "POSTGRES_DB=outline".into(),
                        ],
                        volumes: vec!["outline_db:/var/lib/postgresql/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "redis".into(),
                        image: "redis:7-alpine".into(),
                        ports: vec![],
                        env: vec![],
                        volumes: vec!["outline_redis:/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                ],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs postgresql redis-server".into(),
                    "systemctl enable postgresql redis-server".into(),
                    "systemctl start postgresql redis-server".into(),
                    "su - postgres -c \"createuser outline && createdb -O outline outline\"".into(),
                    "git clone https://github.com/outline/outline.git /opt/outline".into(),
                    "cd /opt/outline && npm install && npm run build".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Long random hex string (openssl rand -hex 32)".into()), options: vec![] },
                UserInput { id: "UTILS_SECRET".into(), label: "Utils Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Another random hex string".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
                UserInput { id: "URL".into(), label: "Public URL".into(), input_type: "text".into(), default: Some("http://localhost:3003".into()), required: true, placeholder: Some("e.g. https://wiki.example.com".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "supabase".into(),
            name: "Supabase".into(),
            icon: "⚡".into(),
            category: "Dev Tools".into(),
            description: "Open-source Firebase alternative. LXC install only — the Supabase stack is Postgres + Kong + auth + realtime + storage + studio, not a single container.".into(),
            website: Some("https://supabase.com".into()),
            // Docker mode previously shipped only `supabase/studio`
            // pointed at a non-existent `http://localhost:8000` Kong
            // gateway — nothing to log into. LXC path runs the full
            // upstream compose stack inside the container.
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git docker.io docker-compose".into(),
                    "git clone --depth 1 https://github.com/supabase/supabase.git /opt/supabase".into(),
                    "cd /opt/supabase/docker && cp .env.example .env".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ANON_KEY".into(), label: "Anonymous Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Supabase anonymous API key".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "stirling-pdf".into(),
            name: "Stirling PDF".into(),
            icon: "📑".into(),
            category: "Productivity".into(),
            description: "Self-hosted PDF manipulation tool — merge, split, convert, compress and more".into(),
            website: Some("https://github.com/Stirling-Tools/Stirling-PDF".into()),
            docker: Some(DockerTarget {
                image: "frooodle/s-pdf:latest".into(),
                ports: vec!["8484:8080".into()],
                env: vec![],
                volumes: vec!["stirling_data:/usr/share/tesseract-ocr".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git openjdk-17-jre-headless libreoffice-core".into(),
                    "git clone https://github.com/Stirling-Tools/Stirling-PDF.git /opt/stirling-pdf".into(),
                    "cd /opt/stirling-pdf && ./gradlew build -x test || echo 'Build may require additional setup'".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "flagsmith".into(),
            name: "Flagsmith".into(),
            icon: "🚩".into(),
            category: "Dev Tools".into(),
            description: "Open-source feature flag and remote configuration service".into(),
            website: Some("https://flagsmith.com".into()),
            docker: Some(DockerTarget {
                image: "flagsmith/flagsmith:latest".into(),
                ports: vec!["8600:8000".into()],
                env: vec![],
                volumes: vec!["flagsmith_data:/var/lib/flagsmith".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git python3 python3-pip python3-venv postgresql".into(),
                    "systemctl enable --now postgresql".into(),
                    "su - postgres -c \"createuser flagsmith && createdb -O flagsmith flagsmith\"".into(),
                    "git clone https://github.com/Flagsmith/flagsmith.git /opt/flagsmith".into(),
                    "cd /opt/flagsmith/api && python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "infisical".into(),
            name: "Infisical".into(),
            icon: "🔑".into(),
            category: "Security".into(),
            description: "Open-source secret management platform — sync secrets across your team and infrastructure".into(),
            website: Some("https://infisical.com".into()),
            docker: Some(DockerTarget {
                image: "infisical/infisical:latest".into(),
                ports: vec!["8585:8080".into()],
                env: vec![
                    "ENCRYPTION_KEY=${ENCRYPTION_KEY}".into(),
                ],
                volumes: vec!["infisical_data:/var/lib/infisical".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs mongodb-org || apt-get install -y nodejs".into(),
                    "git clone https://github.com/Infisical/infisical.git /opt/infisical".into(),
                    "cd /opt/infisical && npm install".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ENCRYPTION_KEY".into(), label: "Encryption Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("128-bit hex encryption key".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "it-tools".into(),
            name: "IT Tools".into(),
            icon: "🧰".into(),
            category: "Dev Tools".into(),
            description: "Collection of handy online tools for developers — converters, generators, formatters".into(),
            website: Some("https://github.com/CorentinTh/it-tools".into()),
            docker: Some(DockerTarget {
                image: "corentinth/it-tools:latest".into(),
                ports: vec!["8383:80".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "git clone https://github.com/CorentinTh/it-tools.git /opt/it-tools".into(),
                    "cd /opt/it-tools && npm install && npm run build".into(),
                    "apt-get install -y nginx".into(),
                    "cp -r /opt/it-tools/dist/* /var/www/html/".into(),
                    "systemctl enable nginx".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "searxng".into(),
            name: "SearXNG".into(),
            icon: "🌍".into(),
            category: "Privacy".into(),
            description: "Privacy-respecting, hackable metasearch engine aggregating results from 70+ search services".into(),
            website: Some("https://searxng.org".into()),
            docker: Some(DockerTarget {
                image: "searxng/searxng:latest".into(),
                ports: vec!["8282:8080".into()],
                env: vec![],
                volumes: vec!["searxng_data:/etc/searxng".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y python3 python3-pip python3-venv git".into(),
                    "git clone https://github.com/searxng/searxng.git /opt/searxng".into(),
                    "cd /opt/searxng && python3 -m venv venv && . venv/bin/activate && pip install -e .".into(),
                    "cat > /etc/systemd/system/searxng.service << 'EOF'\n[Unit]\nDescription=SearXNG\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/searxng\nExecStart=/opt/searxng/venv/bin/python -m searx.webapp\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable searxng".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "excalidraw".into(),
            name: "Excalidraw".into(),
            icon: "🎨".into(),
            category: "Productivity".into(),
            description: "Virtual whiteboard for sketching hand-drawn like diagrams — collaborative".into(),
            website: Some("https://excalidraw.com".into()),
            docker: Some(DockerTarget {
                image: "excalidraw/excalidraw:latest".into(),
                ports: vec!["8686:80".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "git clone https://github.com/excalidraw/excalidraw.git /opt/excalidraw".into(),
                    "cd /opt/excalidraw && npm install && npm run build:app".into(),
                    "apt-get install -y nginx".into(),
                    "cp -r /opt/excalidraw/build/* /var/www/html/".into(),
                    "systemctl enable nginx".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "rallly".into(),
            name: "Rallly".into(),
            icon: "📅".into(),
            category: "Productivity".into(),
            description: "Self-hosted Doodle alternative — schedule group meetings without the back and forth".into(),
            website: Some("https://rallly.co".into()),
            docker: Some(DockerTarget {
                image: "lukevella/rallly:latest".into(),
                ports: vec!["3007:3000".into()],
                env: vec![
                    "SECRET_PASSWORD=${SECRET_KEY}".into(),
                    "DATABASE_URL=postgres://rallly:${DB_PASSWORD}@${CONTAINER_NAME}-db:5432/rallly".into(),
                ],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git postgresql".into(),
                    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -".into(),
                    "apt-get install -y nodejs".into(),
                    "systemctl enable --now postgresql".into(),
                    "su - postgres -c \"createuser rallly && createdb -O rallly rallly\"".into(),
                    "git clone https://github.com/lukevella/rallly.git /opt/rallly".into(),
                    "cd /opt/rallly && npm install && npm run build".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "zitadel".into(),
            name: "Zitadel".into(),
            icon: "🛂".into(),
            category: "Security".into(),
            description: "Cloud-native identity management — SSO, MFA, and user management in one platform".into(),
            website: Some("https://zitadel.com".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/zitadel/zitadel:latest".into(),
                ports: vec!["8282:8080".into()],
                env: vec![
                    "ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME=admin".into(),
                    "ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD=${ADMIN_PASSWORD}".into(),
                ],
                volumes: vec!["zitadel_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl wget".into(),
                    // Arch-aware: zitadel names assets amd64 / arm64.
                    "A=$(uname -m); case $A in x86_64) A=amd64;; aarch64) A=arm64;; esac; wget -O /tmp/zitadel.tar.gz https://github.com/zitadel/zitadel/releases/latest/download/zitadel-linux-$A.tar.gz".into(),
                    "mkdir -p /opt/zitadel && tar xzf /tmp/zitadel.tar.gz -C /opt/zitadel".into(),
                    "cat > /etc/systemd/system/zitadel.service << 'EOF'\n[Unit]\nDescription=Zitadel Identity Platform\nAfter=network.target\n[Service]\nExecStart=/opt/zitadel/zitadel start-from-init --masterkey \"MasterkeyNeedsToHave32Chars!!\" --tlsMode disabled\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable zitadel".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Initial admin password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "changedetection".into(),
            name: "Changedetection.io".into(),
            icon: "👁️".into(),
            category: "Monitoring".into(),
            description: "Website change detection and monitoring — get notified when web pages change".into(),
            website: Some("https://changedetection.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/dgtlmoon/changedetection.io:latest".into(),
                ports: vec!["5000:5000".into()],
                env: vec![],
                volumes: vec!["changedetection_data:/datastore".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y python3 python3-pip python3-venv git".into(),
                    "git clone https://github.com/dgtlmoon/changedetection.io.git /opt/changedetection".into(),
                    "cd /opt/changedetection && python3 -m venv venv && . venv/bin/activate && pip install -e .".into(),
                    "cat > /etc/systemd/system/changedetection.service << 'EOF'\n[Unit]\nDescription=Changedetection.io\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/changedetection\nExecStart=/opt/changedetection/venv/bin/changedetection.io -d /var/lib/changedetection -p 5000\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "mkdir -p /var/lib/changedetection".into(),
                    "systemctl enable changedetection".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "picoclaw".into(),
            name: "PicoClaw".into(),
            icon: "🦞".into(),
            category: "AI / ML".into(),
            description: "Ultra-efficient AI assistant in Go — tiny footprint, deploys anywhere, 10MB RAM, 1s boot".into(),
            website: Some("https://github.com/sipeed/picoclaw".into()),
            docker: Some(DockerTarget {
                image: "sipeed/picoclaw:latest".into(),
                ports: vec!["8686:8686".into()],
                env: vec![],
                volumes: vec!["picoclaw_config:/app/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    "apt-get update && apt-get install -y curl git make gcc".into(),
                    // Arch-aware: the Go toolchain names releases amd64 / arm64.
                    "A=$(uname -m); case $A in x86_64) A=amd64;; aarch64) A=arm64;; esac; curl -fsSL https://go.dev/dl/go1.22.0.linux-$A.tar.gz | tar -C /usr/local -xzf -".into(),
                    "export PATH=$PATH:/usr/local/go/bin && git clone https://github.com/sipeed/picoclaw.git /opt/picoclaw".into(),
                    "cd /opt/picoclaw && export PATH=$PATH:/usr/local/go/bin && make deps && make build".into(),
                    "cp /opt/picoclaw/config/config.example.json /opt/picoclaw/config/config.json".into(),
                    "cat > /etc/systemd/system/picoclaw.service << 'EOF'\n[Unit]\nDescription=PicoClaw AI Assistant\nAfter=network.target\n[Service]\nWorkingDirectory=/opt/picoclaw\nExecStart=/opt/picoclaw/picoclaw\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF".into(),
                    "systemctl enable picoclaw".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        // ─── Gaming Servers ───

        AppManifest {
            id: "minecraft-java".into(),
            name: "Minecraft: Java Edition".into(),
            icon: "⛏️".into(),
            category: "Gaming".into(),
            description: "Minecraft Java Edition server — supports Vanilla, Paper, Forge, Fabric and more".into(),
            website: Some("https://docker-minecraft-server.readthedocs.io".into()),
            docker: Some(DockerTarget {
                image: "itzg/minecraft-server:latest".into(),
                ports: vec!["25565:25565".into()],
                env: vec![
                    "EULA=TRUE".into(),
                    "TYPE=${SERVER_TYPE}".into(),
                    "VERSION=LATEST".into(),
                    "MEMORY=2G".into(),
                    "DIFFICULTY=normal".into(),
                    "MAX_PLAYERS=20".into(),
                    "MOTD=${MOTD}".into(),
                    "MODE=survival".into(),
                    "ENABLE_RCON=true".into(),
                    "RCON_PASSWORD=${RCON_PASSWORD}".into(),
                    "ONLINE_MODE=true".into(),
                ],
                volumes: vec!["minecraft_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_TYPE".into(), label: "Server Type".into(), input_type: "select".into(), default: Some("VANILLA".into()), required: false, placeholder: None, options: vec!["VANILLA".into(), "PAPER".into(), "FABRIC".into(), "FORGE".into(), "SPIGOT".into()] },
                UserInput { id: "MOTD".into(), label: "Server Message (MOTD)".into(), input_type: "text".into(), default: Some("A Minecraft Server".into()), required: false, placeholder: Some("Message of the Day".into()), options: vec![] },
                UserInput { id: "RCON_PASSWORD".into(), label: "RCON Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Remote console password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "minecraft-bedrock".into(),
            name: "Minecraft: Bedrock Edition".into(),
            icon: "🧱".into(),
            category: "Gaming".into(),
            description: "Minecraft Bedrock server for Xbox, PlayStation, Switch, and mobile clients".into(),
            website: Some("https://github.com/itzg/docker-minecraft-bedrock-server".into()),
            docker: Some(DockerTarget {
                image: "itzg/minecraft-bedrock-server:latest".into(),
                ports: vec!["19132:19132/udp".into()],
                env: vec![
                    "EULA=TRUE".into(),
                    "SERVER_NAME=${SERVER_NAME}".into(),
                    "GAMEMODE=survival".into(),
                    "DIFFICULTY=easy".into(),
                    "MAX_PLAYERS=10".into(),
                    "ONLINE_MODE=true".into(),
                ],
                volumes: vec!["bedrock_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("Bedrock Server".into()), required: false, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "valheim".into(),
            name: "Valheim".into(),
            icon: "⚔️".into(),
            category: "Gaming".into(),
            description: "Valheim dedicated server with automatic updates, backups, and mod support".into(),
            website: Some("https://github.com/lloesche/valheim-server-docker".into()),
            docker: Some(DockerTarget {
                image: "lloesche/valheim-server:latest".into(),
                ports: vec!["2456-2458:2456-2458/udp".into()],
                env: vec![
                    "SERVER_NAME=${SERVER_NAME}".into(),
                    "WORLD_NAME=Dedicated".into(),
                    "SERVER_PASS=${SERVER_PASS}".into(),
                    "SERVER_PUBLIC=true".into(),
                    "BACKUPS=true".into(),
                    "TZ=Etc/UTC".into(),
                ],
                volumes: vec!["valheim_config:/config".into(), "valheim_data:/opt/valheim".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("My Valheim Server".into()), required: false, placeholder: None, options: vec![] },
                UserInput { id: "SERVER_PASS".into(), label: "Server Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 5 characters".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "terraria".into(),
            name: "Terraria (TShock)".into(),
            icon: "🌳".into(),
            category: "Gaming".into(),
            description: "Terraria server with TShock mod support and REST API".into(),
            website: Some("https://github.com/ryshe/terraria".into()),
            docker: Some(DockerTarget {
                image: "ryshe/terraria:latest".into(),
                ports: vec!["7777:7777".into()],
                env: vec![],
                volumes: vec!["terraria_worlds:/root/.local/share/Terraria/Worlds".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "palworld".into(),
            name: "Palworld".into(),
            icon: "🦎".into(),
            category: "Gaming".into(),
            description: "Palworld dedicated server with RCON, REST API, and automatic backups".into(),
            website: Some("https://github.com/thijsvanloef/palworld-server-docker".into()),
            docker: Some(DockerTarget {
                image: "thijsvanloef/palworld-server-docker:latest".into(),
                ports: vec!["8211:8211/udp".into(), "27015:27015/udp".into(), "25575:25575".into()],
                env: vec![
                    "PUID=1000".into(),
                    "PGID=1000".into(),
                    "PLAYERS=16".into(),
                    "MULTITHREADING=true".into(),
                    "SERVER_NAME=${SERVER_NAME}".into(),
                    "SERVER_PASSWORD=${SERVER_PASS}".into(),
                    "ADMIN_PASSWORD=${ADMIN_PASS}".into(),
                    "COMMUNITY=false".into(),
                    "RCON_ENABLED=true".into(),
                    "RCON_PORT=25575".into(),
                ],
                volumes: vec!["palworld_data:/palworld".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("Palworld Server".into()), required: false, placeholder: None, options: vec![] },
                UserInput { id: "SERVER_PASS".into(), label: "Server Password".into(), input_type: "password".into(), default: None, required: false, placeholder: Some("Leave blank for no password".into()), options: vec![] },
                UserInput { id: "ADMIN_PASS".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("RCON/admin password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "factorio".into(),
            name: "Factorio".into(),
            icon: "🏭".into(),
            category: "Gaming".into(),
            description: "Factorio headless dedicated server with mod and save management".into(),
            website: Some("https://github.com/factoriotools/factorio-docker".into()),
            docker: Some(DockerTarget {
                image: "factoriotools/factorio:stable".into(),
                ports: vec!["34197:34197/udp".into(), "27015:27015".into()],
                env: vec![
                    "LOAD_LATEST_SAVE=true".into(),
                    "GENERATE_NEW_SAVE=true".into(),
                    "UPDATE_MODS_ON_START=false".into(),
                ],
                volumes: vec!["factorio_data:/factorio".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "cs2".into(),
            name: "Counter-Strike 2".into(),
            icon: "🔫".into(),
            category: "Gaming".into(),
            description: "Counter-Strike 2 dedicated server — requires a Steam Game Server Login Token".into(),
            website: Some("https://github.com/CM2Walki/CS2".into()),
            docker: Some(DockerTarget {
                image: "cm2network/cs2:latest".into(),
                ports: vec!["27015:27015/tcp".into(), "27015:27015/udp".into()],
                env: vec![
                    "SRCDS_TOKEN=${SRCDS_TOKEN}".into(),
                    "CS2_SERVERNAME=${SERVER_NAME}".into(),
                    "CS2_PORT=27015".into(),
                    "CS2_RCONPW=${RCON_PASS}".into(),
                    "CS2_PW=${SERVER_PASS}".into(),
                    "CS2_MAXPLAYERS=10".into(),
                    "CS2_GAMETYPE=0".into(),
                    "CS2_GAMEMODE=1".into(),
                    "CS2_STARTMAP=de_inferno".into(),
                ],
                volumes: vec!["cs2_data:/home/steam/cs2-dedicated".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SRCDS_TOKEN".into(), label: "Steam GSLT Token".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("From steamcommunity.com/dev/managegameservers".into()), options: vec![] },
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("CS2 Server".into()), required: false, placeholder: None, options: vec![] },
                UserInput { id: "RCON_PASS".into(), label: "RCON Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Remote console password".into()), options: vec![] },
                UserInput { id: "SERVER_PASS".into(), label: "Server Password".into(), input_type: "password".into(), default: None, required: false, placeholder: Some("Leave blank for public".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "rust-game".into(),
            name: "Rust".into(),
            icon: "🪓".into(),
            category: "Gaming".into(),
            description: "Rust dedicated server with web RCON, Oxide mod support, and Rust+ companion app".into(),
            website: Some("https://github.com/Didstopia/rust-server".into()),
            docker: Some(DockerTarget {
                image: "didstopia/rust-server:latest".into(),
                ports: vec!["28015:28015/tcp".into(), "28015:28015/udp".into(), "28016:28016".into(), "8080:8080".into()],
                env: vec![
                    "RUST_SERVER_NAME=${SERVER_NAME}".into(),
                    "RUST_SERVER_SEED=12345".into(),
                    "RUST_SERVER_WORLDSIZE=3500".into(),
                    "RUST_SERVER_MAXPLAYERS=50".into(),
                    "RUST_RCON_WEB=1".into(),
                    "RUST_RCON_PORT=28016".into(),
                    "RUST_RCON_PASSWORD=${RCON_PASS}".into(),
                    "RUST_SERVER_SAVE_INTERVAL=600".into(),
                ],
                volumes: vec!["rust_data:/steamcmd/rust".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("Rust Server".into()), required: false, placeholder: None, options: vec![] },
                UserInput { id: "RCON_PASS".into(), label: "RCON Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Web RCON password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "ark-survival".into(),
            name: "ARK: Survival Evolved".into(),
            icon: "🦖".into(),
            category: "Gaming".into(),
            description: "ARK dedicated server with automatic updates and backups".into(),
            website: Some("https://github.com/hermsi1337/docker-ark-server".into()),
            docker: Some(DockerTarget {
                image: "hermsi/ark-server:latest".into(),
                ports: vec!["7777:7777/udp".into(), "7778:7778/udp".into(), "27015:27015/udp".into(), "27020:27020".into()],
                env: vec![
                    "SESSION_NAME=${SERVER_NAME}".into(),
                    "SERVER_MAP=TheIsland".into(),
                    "SERVER_PASSWORD=${SERVER_PASS}".into(),
                    "ADMIN_PASSWORD=${ADMIN_PASS}".into(),
                    "MAX_PLAYERS=20".into(),
                    "UPDATE_ON_START=true".into(),
                    "BACKUP_ON_STOP=true".into(),
                ],
                volumes: vec!["ark_data:/app".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Session Name".into(), input_type: "text".into(), default: Some("ARK Docker Server".into()), required: false, placeholder: None, options: vec![] },
                UserInput { id: "SERVER_PASS".into(), label: "Server Password".into(), input_type: "password".into(), default: None, required: false, placeholder: Some("Leave blank for no password".into()), options: vec![] },
                UserInput { id: "ADMIN_PASS".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin/RCON password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "satisfactory".into(),
            name: "Satisfactory".into(),
            icon: "🔧".into(),
            category: "Gaming".into(),
            description: "Satisfactory dedicated server with automatic updates and autosave".into(),
            website: Some("https://github.com/wolveix/satisfactory-server".into()),
            docker: Some(DockerTarget {
                image: "wolveix/satisfactory-server:latest".into(),
                ports: vec!["7777:7777/tcp".into(), "7777:7777/udp".into()],
                env: vec![
                    "MAXPLAYERS=4".into(),
                    "PGID=1000".into(),
                    "PUID=1000".into(),
                    "AUTOPAUSE=true".into(),
                    "AUTOSAVEINTERVAL=300".into(),
                    "AUTOSAVENUM=5".into(),
                ],
                volumes: vec!["satisfactory_data:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "project-zomboid".into(),
            name: "Project Zomboid".into(),
            icon: "🧟".into(),
            category: "Gaming".into(),
            description: "Project Zomboid dedicated server with mod support and Steam Workshop integration".into(),
            website: Some("https://github.com/Renegade-Master/zomboid-dedicated-server".into()),
            docker: Some(DockerTarget {
                image: "renegademaster/zomboid-dedicated-server:latest".into(),
                ports: vec!["16261:16261/udp".into(), "16262:16262/udp".into()],
                env: vec![
                    "ADMIN_USERNAME=admin".into(),
                    "ADMIN_PASSWORD=${ADMIN_PASS}".into(),
                    "SERVER_NAME=${SERVER_NAME}".into(),
                    "SERVER_PASSWORD=${SERVER_PASS}".into(),
                    "MAX_PLAYERS=16".into(),
                    "MAX_RAM=4096m".into(),
                    "PAUSE_ON_EMPTY=true".into(),
                ],
                volumes: vec!["zomboid_server:/home/steam/ZomboidDedicatedServer".into(), "zomboid_data:/home/steam/Zomboid".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("Zomboid Server".into()), required: false, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASS".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
                UserInput { id: "SERVER_PASS".into(), label: "Server Password".into(), input_type: "password".into(), default: None, required: false, placeholder: Some("Leave blank for no password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "7dtd".into(),
            name: "7 Days to Die".into(),
            icon: "💀".into(),
            category: "Gaming".into(),
            description: "7 Days to Die dedicated server with web admin panel and mod support".into(),
            website: Some("https://github.com/vinanrra/Docker-7DaysToDie".into()),
            docker: Some(DockerTarget {
                image: "vinanrra/7dtd-server:latest".into(),
                ports: vec!["26900:26900/tcp".into(), "26900-26902:26900-26902/udp".into(), "8080:8080".into(), "8081:8081".into()],
                env: vec![
                    "START_MODE=1".into(),
                    "VERSION=stable".into(),
                    "PUID=1000".into(),
                    "PGID=1000".into(),
                    "TimeZone=Etc/UTC".into(),
                    "BACKUP=YES".into(),
                ],
                volumes: vec![
                    "7dtd_server:/home/sdtdserver/serverfiles".into(),
                    "7dtd_saves:/home/sdtdserver/.local/share/7DaysToDie".into(),
                    "7dtd_logs:/home/sdtdserver/log".into(),
                    "7dtd_backups:/home/sdtdserver/lgsm/backup".into(),
                ],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None,
            bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ── Games ──

        AppManifest {
            id: "opensimngc".into(),
            name: "OpenSimulator NGC".into(),
            icon: "🌐".into(),
            category: "Gaming".into(),
            description: "OpenSimulator Next Generation — run your own virtual world grid (Second Life compatible). Includes MariaDB, .NET 8, and full grid configuration.".into(),
            website: Some("https://github.com/OpenSim-NGC/OpenSim-Tranquillity".into()),
            docker: None,
            lxc: Some(LxcTarget {
                distribution: "debian".into(),
                release: "bookworm".into(),
                architecture: crate::containers::host_container_arch().into(),
                setup_commands: vec![
                    // Install dependencies
                    "apt-get update && apt-get install -y curl git wget mariadb-server libgdiplus screen".into(),

                    // Install .NET 8 SDK
                    "wget https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh && chmod +x /tmp/dotnet-install.sh && /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet && ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet".into(),

                    // Start and configure MariaDB
                    "service mariadb start".into(),
                    "mysql -e \"CREATE DATABASE IF NOT EXISTS opensim CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;\"".into(),
                    "mysql -e \"CREATE USER IF NOT EXISTS 'opensim'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';\"".into(),
                    "mysql -e \"GRANT ALL PRIVILEGES ON opensim.* TO 'opensim'@'localhost'; FLUSH PRIVILEGES;\"".into(),
                    // Enable MariaDB on boot
                    "systemctl enable mariadb".into(),

                    // Clone and build OpenSimNGC
                    "git clone https://github.com/OpenSim-NGC/OpenSim-Tranquillity.git /opt/opensim".into(),
                    "cd /opt/opensim && dotnet restore && dotnet build -c Release -o /opt/opensim/bin".into(),

                    // Generate OpenSim.ini from template
                    concat!(
                        "cat > /opt/opensim/bin/OpenSim.ini << 'OSINI'\n",
                        "[Const]\n",
                        "    BaseHostname = \"${GRID_HOSTNAME}\"\n",
                        "    BaseURL = http://${Const|BaseHostname}\n",
                        "    PublicPort = \"${GRID_PORT}\"\n",
                        "    PrivURL = ${Const|BaseURL}\n",
                        "    PrivatePort = \"8003\"\n",
                        "\n",
                        "[Startup]\n",
                        "    ConsolePrompt = \"Region (\\R) \"\n",
                        "    region_info_source = \"filesystem\"\n",
                        "    save_crashes = false\n",
                        "    crash_dir = \"crashes\"\n",
                        "    PIDFile = \"/opt/opensim/bin/opensim.pid\"\n",
                        "\n",
                        "[Map]\n",
                        "    GenerateMaptiles = true\n",
                        "    MapImageModule = \"MapImageModule\"\n",
                        "\n",
                        "[Network]\n",
                        "    http_listener_port = ${Const|PublicPort}\n",
                        "    ExternalHostNameForLSL = ${Const|BaseHostname}\n",
                        "\n",
                        "[Architecture]\n",
                        "    Include-Architecture = \"config-include/Standalone.ini\"\n",
                        "OSINI"
                    ).into(),

                    // Generate StandaloneCommon.ini with MariaDB connection
                    concat!(
                        "cat > /opt/opensim/bin/config-include/StandaloneCommon.ini << 'SCINI'\n",
                        "[DatabaseService]\n",
                        "    StorageProvider = \"OpenSim.Data.MySQL.dll\"\n",
                        "    ConnectionString = \"Data Source=localhost;Database=opensim;User ID=opensim;Password=${DB_PASSWORD};Old Guids=true;SslMode=None;\"\n",
                        "\n",
                        "[Hypergrid]\n",
                        "    HomeURI = \"${Const|BaseURL}:${Const|PublicPort}\"\n",
                        "\n",
                        "[Modules]\n",
                        "    AssetCaching = \"FlotsamAssetCache\"\n",
                        "    Include-FlotsamCache = \"config-include/FlotsamCache.ini\"\n",
                        "\n",
                        "[AssetService]\n",
                        "    DefaultAssetLoader = \"OpenSim.Framework.AssetLoader.Filesystem.dll\"\n",
                        "    AssetLoaderArgs = \"assets/AssetSets.xml\"\n",
                        "\n",
                        "[GridService]\n",
                        "    StorageProvider = \"OpenSim.Data.MySQL.dll:MySqlRegionData\"\n",
                        "    Region_${REGION_NAME} = \"DefaultRegion, FallbackRegion\"\n",
                        "\n",
                        "[LibraryModule]\n",
                        "    LibrariesXMLFile = \"./inventory/Libraries.xml\"\n",
                        "\n",
                        "[LoginService]\n",
                        "    WelcomeMessage = \"Welcome to ${GRID_NAME}!\"\n",
                        "    AllowRemoteSetLoginLevel = \"false\"\n",
                        "\n",
                        "[MapImageService]\n",
                        "    TilesStoragePath = \"maptiles\"\n",
                        "\n",
                        "[UserProfilesService]\n",
                        "    Enabled = true\n",
                        "SCINI"
                    ).into(),

                    // Generate FlotsamCache.ini
                    "cp /opt/opensim/bin/config-include/FlotsamCache.ini.example /opt/opensim/bin/config-include/FlotsamCache.ini".into(),

                    // Generate Region UUID if set to 'auto'
                    "if [ \"${REGION_UUID}\" = 'auto' ] || [ -z \"${REGION_UUID}\" ]; then export REGION_UUID=$(cat /proc/sys/kernel/random/uuid); fi".into(),

                    // Generate Regions.ini
                    concat!(
                        "cat > /opt/opensim/bin/Regions/Regions.ini << 'REGINI'\n",
                        "[${REGION_NAME}]\n",
                        "RegionUUID = ${REGION_UUID}\n",
                        "Location = 1000,1000\n",
                        "InternalAddress = 0.0.0.0\n",
                        "InternalPort = ${GRID_PORT}\n",
                        "AllowAlternatePorts = False\n",
                        "ExternalHostName = ${GRID_HOSTNAME}\n",
                        "MaxPrims = 15000\n",
                        "MaxAgents = 100\n",
                        "REGINI"
                    ).into(),

                    // Create maptiles directory
                    "mkdir -p /opt/opensim/bin/maptiles".into(),

                    // Create estate setup script that runs on first launch
                    concat!(
                        "cat > /opt/opensim/bin/setup-estate.txt << 'ESTATE'\n",
                        "create estate ${ESTATE_NAME} ${ESTATE_OWNER_FIRST} ${ESTATE_OWNER_LAST}\n",
                        "ESTATE"
                    ).into(),

                    // Create systemd service
                    concat!(
                        "cat > /etc/systemd/system/opensim.service << 'SVC'\n",
                        "[Unit]\n",
                        "Description=OpenSimulator NGC\n",
                        "After=network.target mariadb.service\n",
                        "Wants=mariadb.service\n",
                        "\n",
                        "[Service]\n",
                        "Type=simple\n",
                        "WorkingDirectory=/opt/opensim/bin\n",
                        "ExecStart=/usr/local/bin/dotnet OpenSim.dll\n",
                        "Restart=on-failure\n",
                        "RestartSec=10\n",
                        "\n",
                        "[Install]\n",
                        "WantedBy=multi-user.target\n",
                        "SVC"
                    ).into(),
                    "systemctl daemon-reload && systemctl enable opensim".into(),

                    // Print connection info
                    "echo ''".into(),
                    "echo '========================================='".into(),
                    "echo '  OpenSimulator NGC Setup Complete!'".into(),
                    "echo '========================================='".into(),
                    "echo ''".into(),
                    "echo '  Grid Name:    ${GRID_NAME}'".into(),
                    "echo '  Region:       ${REGION_NAME}'".into(),
                    "echo '  Address:      ${GRID_HOSTNAME}:${GRID_PORT}'".into(),
                    "echo '  Login URI:    http://${GRID_HOSTNAME}:${GRID_PORT}'".into(),
                    "echo '  Database:     opensim@localhost (MariaDB)'".into(),
                    "echo ''".into(),
                    "echo '  To start:     systemctl start opensim'".into(),
                    "echo '  To stop:      systemctl stop opensim'".into(),
                    "echo '  Console:      screen -r opensim'".into(),
                    "echo ''".into(),
                    "echo '  On first run you will be asked to create an'".into(),
                    "echo '  estate owner account (avatar name + password).'".into(),
                    "echo ''".into(),
                    "echo '  Connect with a viewer (Firestorm, etc) using:'".into(),
                    "echo '    Login URI: http://${GRID_HOSTNAME}:${GRID_PORT}'".into(),
                    "echo '========================================='".into(),
                ],
            }),
            bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput {
                    id: "GRID_NAME".into(),
                    label: "Grid Name".into(),
                    input_type: "text".into(),
                    default: Some("My Grid".into()),
                    required: true,
                    placeholder: Some("Name of your virtual world grid".into()),
                    options: vec![],
                },
                UserInput {
                    id: "REGION_NAME".into(),
                    label: "Region Name".into(),
                    input_type: "text".into(),
                    default: Some("Welcome".into()),
                    required: true,
                    placeholder: Some("Name of the default region".into()),
                    options: vec![],
                },
                UserInput {
                    id: "GRID_HOSTNAME".into(),
                    label: "Grid Hostname / IP".into(),
                    input_type: "text".into(),
                    default: None,
                    required: false,
                    placeholder: Some("Leave blank to auto-assign a WolfNet IP".into()),
                    options: vec![],
                },
                UserInput {
                    id: "GRID_PORT".into(),
                    label: "Grid Port".into(),
                    input_type: "text".into(),
                    default: Some("9000".into()),
                    required: true,
                    placeholder: Some("Main grid port".into()),
                    options: vec![],
                },
                UserInput {
                    id: "DB_PASSWORD".into(),
                    label: "Database Password".into(),
                    input_type: "password".into(),
                    default: None,
                    required: true,
                    placeholder: Some("Password for the opensim MariaDB user".into()),
                    options: vec![],
                },
                UserInput {
                    id: "ESTATE_NAME".into(),
                    label: "Estate Name".into(),
                    input_type: "text".into(),
                    default: Some("My Estate".into()),
                    required: true,
                    placeholder: Some("Name of the default estate".into()),
                    options: vec![],
                },
                UserInput {
                    id: "ESTATE_OWNER_FIRST".into(),
                    label: "Estate Owner First Name".into(),
                    input_type: "text".into(),
                    default: Some("Admin".into()),
                    required: true,
                    placeholder: Some("Avatar first name".into()),
                    options: vec![],
                },
                UserInput {
                    id: "ESTATE_OWNER_LAST".into(),
                    label: "Estate Owner Last Name".into(),
                    input_type: "text".into(),
                    default: Some("Admin".into()),
                    required: true,
                    placeholder: Some("Avatar last name".into()),
                    options: vec![],
                },
                UserInput {
                    id: "REGION_UUID".into(),
                    label: "Region UUID".into(),
                    input_type: "text".into(),
                    default: Some("auto".into()),
                    required: false,
                    placeholder: Some("Leave as 'auto' to generate".into()),
                    options: vec![],
                },
            ],
        },


        // ─── Media & Entertainment ───

        AppManifest {
            id: "plex".into(),
            name: "Plex Media Server".into(),
            icon: "🎬".into(),
            category: "Media".into(),
            description: "Stream your personal media collection to any device".into(),
            website: Some("https://plex.tv".into()),
            docker: Some(DockerTarget {
                image: "plexinc/pms-docker:latest".into(),
                ports: vec!["32400:32400".into()],
                env: vec!["PLEX_CLAIM=${CLAIM_TOKEN}".into()],
                volumes: vec!["plex_config:/config".into(), "plex_transcode:/transcode".into(), "${MEDIA_PATH}:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "CLAIM_TOKEN".into(), label: "Plex Claim Token".into(), input_type: "text".into(), default: None, required: false, placeholder: Some("From plex.tv/claim (optional)".into()), options: vec![] },
                UserInput { id: "MEDIA_PATH".into(), label: "Media Path".into(), input_type: "text".into(), default: Some("/opt/media".into()), required: true, placeholder: Some("Path to your media files".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "emby".into(),
            name: "Emby".into(),
            icon: "📺".into(),
            category: "Media".into(),
            description: "Personal media server with live TV and DVR support".into(),
            website: Some("https://emby.media".into()),
            docker: Some(DockerTarget {
                image: "emby/embyserver:latest".into(),
                ports: vec!["8096:8096".into(), "8920:8920".into()],
                env: vec![],
                volumes: vec!["emby_config:/config".into(), "${MEDIA_PATH}:/media".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "Media Path".into(), input_type: "text".into(), default: Some("/opt/media".into()), required: true, placeholder: Some("Path to your media files".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "sonarr".into(),
            name: "Sonarr".into(),
            icon: "📡".into(),
            category: "Media".into(),
            description: "TV series management and automatic downloading".into(),
            website: Some("https://sonarr.tv".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/sonarr:latest".into(),
                ports: vec!["8989:8989".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["sonarr_config:/config".into(), "${MEDIA_PATH}:/tv".into(), "${DOWNLOAD_PATH}:/downloads".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "TV Shows Path".into(), input_type: "text".into(), default: Some("/opt/media/tv".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "radarr".into(),
            name: "Radarr".into(),
            icon: "🎥".into(),
            category: "Media".into(),
            description: "Movie collection manager and automatic downloading".into(),
            website: Some("https://radarr.video".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/radarr:latest".into(),
                ports: vec!["7878:7878".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["radarr_config:/config".into(), "${MEDIA_PATH}:/movies".into(), "${DOWNLOAD_PATH}:/downloads".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "Movies Path".into(), input_type: "text".into(), default: Some("/opt/media/movies".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "lidarr".into(),
            name: "Lidarr".into(),
            icon: "🎵".into(),
            category: "Media".into(),
            description: "Music collection manager and automatic downloading".into(),
            website: Some("https://lidarr.audio".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/lidarr:latest".into(),
                ports: vec!["8686:8686".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["lidarr_config:/config".into(), "${MEDIA_PATH}:/music".into(), "${DOWNLOAD_PATH}:/downloads".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "Music Path".into(), input_type: "text".into(), default: Some("/opt/media/music".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "prowlarr".into(),
            name: "Prowlarr".into(),
            icon: "🔍".into(),
            category: "Media".into(),
            description: "Indexer manager for Sonarr, Radarr, and Lidarr".into(),
            website: Some("https://prowlarr.com".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/prowlarr:latest".into(),
                ports: vec!["9696:9696".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["prowlarr_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "bazarr".into(),
            name: "Bazarr".into(),
            icon: "💬".into(),
            category: "Media".into(),
            description: "Automatic subtitle downloading for Sonarr and Radarr".into(),
            website: Some("https://www.bazarr.media".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/bazarr:latest".into(),
                ports: vec!["6767:6767".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["bazarr_config:/config".into(), "${MEDIA_PATH}:/media".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "Media Path".into(), input_type: "text".into(), default: Some("/opt/media".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "overseerr".into(),
            name: "Overseerr".into(),
            icon: "🎟️".into(),
            category: "Media".into(),
            description: "Media request and discovery tool for Plex".into(),
            website: Some("https://overseerr.dev".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/overseerr:latest".into(),
                ports: vec!["5055:5055".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["overseerr_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "tautulli".into(),
            name: "Tautulli".into(),
            icon: "📊".into(),
            category: "Media".into(),
            description: "Monitoring and tracking tool for Plex Media Server".into(),
            website: Some("https://tautulli.com".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/tautulli:latest".into(),
                ports: vec!["8181:8181".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["tautulli_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "navidrome".into(),
            name: "Navidrome".into(),
            icon: "🎶".into(),
            category: "Media".into(),
            description: "Modern music server and streamer compatible with Subsonic/Airsonic".into(),
            website: Some("https://www.navidrome.org".into()),
            docker: Some(DockerTarget {
                image: "deluan/navidrome:latest".into(),
                ports: vec!["4533:4533".into()],
                env: vec![],
                volumes: vec!["navidrome_data:/data".into(), "${MUSIC_PATH}:/music:ro".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MUSIC_PATH".into(), label: "Music Path".into(), input_type: "text".into(), default: Some("/opt/media/music".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "audiobookshelf".into(),
            name: "Audiobookshelf".into(),
            icon: "🎧".into(),
            category: "Media".into(),
            description: "Self-hosted audiobook and podcast server".into(),
            website: Some("https://www.audiobookshelf.org".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/advplyr/audiobookshelf:latest".into(),
                ports: vec!["13378:80".into()],
                env: vec![],
                volumes: vec!["audiobookshelf_config:/config".into(), "audiobookshelf_metadata:/metadata".into(), "${AUDIOBOOKS_PATH}:/audiobooks".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "AUDIOBOOKS_PATH".into(), label: "Audiobooks Path".into(), input_type: "text".into(), default: Some("/opt/media/audiobooks".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "calibre-web".into(),
            name: "Calibre-Web".into(),
            icon: "📚".into(),
            category: "Media".into(),
            description: "Web-based ebook reader and library management".into(),
            website: Some("https://github.com/janeczku/calibre-web".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/calibre-web:latest".into(),
                ports: vec!["8083:8083".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["calibre_config:/config".into(), "${BOOKS_PATH}:/books".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "BOOKS_PATH".into(), label: "Books Path".into(), input_type: "text".into(), default: Some("/opt/media/books".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "kavita".into(),
            name: "Kavita".into(),
            icon: "📖".into(),
            category: "Media".into(),
            description: "Fast, feature-rich comic/manga/book server".into(),
            website: Some("https://www.kavitareader.com".into()),
            docker: Some(DockerTarget {
                image: "jvmilazz0/kavita:latest".into(),
                ports: vec!["5000:5000".into()],
                env: vec![],
                volumes: vec!["kavita_config:/kavita/config".into(), "${LIBRARY_PATH}:/manga".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "LIBRARY_PATH".into(), label: "Library Path".into(), input_type: "text".into(), default: Some("/opt/media/manga".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "stash".into(),
            name: "Stash".into(),
            icon: "🗂️".into(),
            category: "Media".into(),
            description: "Media organizer with tagging, filtering, and metadata scraping".into(),
            website: Some("https://stashapp.cc".into()),
            docker: Some(DockerTarget {
                image: "stashapp/stash:latest".into(),
                ports: vec!["9999:9999".into()],
                env: vec![],
                volumes: vec!["stash_config:/root/.stash".into(), "${MEDIA_PATH}:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "Media Path".into(), input_type: "text".into(), default: Some("/opt/media".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        // ─── Productivity & Documents ───

        AppManifest {
            id: "photoprism".into(),
            name: "PhotoPrism".into(),
            icon: "📷".into(),
            category: "Productivity".into(),
            description: "AI-powered photo management with face recognition and search".into(),
            website: Some("https://photoprism.app".into()),
            docker: Some(DockerTarget {
                image: "photoprism/photoprism:latest".into(),
                ports: vec!["2342:2342".into()],
                env: vec!["PHOTOPRISM_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(), "PHOTOPRISM_ORIGINALS_LIMIT=10000".into(), "PHOTOPRISM_DATABASE_DRIVER=sqlite".into()],
                volumes: vec!["photoprism_storage:/photoprism/storage".into(), "${PHOTOS_PATH}:/photoprism/originals".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Initial admin password".into()), options: vec![] },
                UserInput { id: "PHOTOS_PATH".into(), label: "Photos Path".into(), input_type: "text".into(), default: Some("/opt/photos".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        AppManifest {
            id: "bookstack".into(),
            name: "BookStack".into(),
            icon: "📕".into(),
            category: "Productivity".into(),
            description: "Simple and free wiki and documentation platform".into(),
            website: Some("https://www.bookstackapp.com".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/bookstack:latest".into(),
                ports: vec!["6875:80".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "DB_HOST=bookstack-db".into(), "DB_DATABASE=bookstack".into(), "DB_USER=bookstack".into(), "DB_PASS=${DB_PASSWORD}".into(), "APP_URL=http://localhost:6875".into()],
                volumes: vec!["bookstack_config:/config".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:10".into(),
                    ports: vec![],
                    env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=bookstack".into(), "MYSQL_USER=bookstack".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()],
                    volumes: vec!["bookstack_db:/var/lib/mysql".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Database password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "wikijs".into(),
            name: "Wiki.js".into(),
            icon: "📝".into(),
            category: "Productivity".into(),
            description: "Modern and powerful wiki built on Node.js".into(),
            website: Some("https://js.wiki".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/requarks/wiki:2".into(),
                ports: vec!["3000:3000".into()],
                env: vec!["DB_TYPE=sqlite".into(), "DB_FILEPATH=/data/wiki.sqlite".into()],
                volumes: vec!["wikijs_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "hedgedoc".into(),
            name: "HedgeDoc".into(),
            icon: "🦔".into(),
            category: "Productivity".into(),
            description: "Real-time collaborative markdown editor".into(),
            website: Some("https://hedgedoc.org".into()),
            docker: Some(DockerTarget {
                image: "quay.io/hedgedoc/hedgedoc:latest".into(),
                ports: vec!["3000:3000".into()],
                env: vec!["CMD_DB_URL=sqlite:///data/hedgedoc.sqlite".into(), "CMD_ALLOW_ANONYMOUS=false".into()],
                volumes: vec!["hedgedoc_data:/data".into(), "hedgedoc_uploads:/hedgedoc/public/uploads".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "trilium".into(),
            name: "Trilium Notes".into(),
            icon: "🌳".into(),
            category: "Productivity".into(),
            description: "Hierarchical note-taking app with rich editing and scripting".into(),
            website: Some("https://github.com/zadam/trilium".into()),
            docker: Some(DockerTarget {
                image: "zadam/trilium:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec![],
                volumes: vec!["trilium_data:/home/node/trilium-data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "joplin-server".into(),
            name: "Joplin Server".into(),
            icon: "📓".into(),
            category: "Productivity".into(),
            description: "Sync server for Joplin note-taking apps".into(),
            website: Some("https://joplinapp.org".into()),
            docker: Some(DockerTarget {
                image: "joplin/server:latest".into(),
                ports: vec!["22300:22300".into()],
                env: vec!["APP_BASE_URL=http://localhost:22300".into(), "DB_CLIENT=sqlite3".into()],
                volumes: vec!["joplin_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "tandoor".into(),
            name: "Tandoor Recipes".into(),
            icon: "🍳".into(),
            category: "Productivity".into(),
            description: "Recipe management and meal planning".into(),
            website: Some("https://tandoor.dev".into()),
            docker: Some(DockerTarget {
                image: "vabene1111/recipes:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec!["SECRET_KEY=${SECRET_KEY}".into(), "DB_ENGINE=django.db.backends.sqlite3".into()],
                volumes: vec!["tandoor_static:/opt/recipes/staticfiles".into(), "tandoor_media:/opt/recipes/mediafiles".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
            ],
        },

        // ─── Dev Tools ───

        AppManifest {
            id: "registry".into(),
            name: "Docker Registry".into(),
            icon: "📦".into(),
            category: "Dev Tools".into(),
            description: "Private Docker image registry".into(),
            website: Some("https://hub.docker.com/_/registry".into()),
            docker: Some(DockerTarget {
                image: "registry:2".into(),
                ports: vec!["5000:5000".into()],
                env: vec![],
                volumes: vec!["registry_data:/var/lib/registry".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "verdaccio".into(),
            name: "Verdaccio".into(),
            icon: "📗".into(),
            category: "Dev Tools".into(),
            description: "Lightweight private npm registry".into(),
            website: Some("https://verdaccio.org".into()),
            docker: Some(DockerTarget {
                image: "verdaccio/verdaccio:latest".into(),
                ports: vec!["4873:4873".into()],
                env: vec![],
                volumes: vec!["verdaccio_storage:/verdaccio/storage".into(), "verdaccio_conf:/verdaccio/conf".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "adminer".into(),
            name: "Adminer".into(),
            icon: "🗄️".into(),
            category: "Database".into(),
            description: "Database management in a single PHP file — MySQL, PostgreSQL, SQLite, and more".into(),
            website: Some("https://www.adminer.org".into()),
            docker: Some(DockerTarget {
                image: "adminer:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "pgadmin".into(),
            name: "pgAdmin".into(),
            icon: "🐘".into(),
            category: "Database".into(),
            description: "Web-based PostgreSQL administration tool".into(),
            website: Some("https://www.pgadmin.org".into()),
            docker: Some(DockerTarget {
                image: "dpage/pgadmin4:latest".into(),
                ports: vec!["5050:80".into()],
                env: vec!["PGADMIN_DEFAULT_EMAIL=${ADMIN_EMAIL}".into(), "PGADMIN_DEFAULT_PASSWORD=${ADMIN_PASSWORD}".into()],
                volumes: vec!["pgadmin_data:/var/lib/pgadmin".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_EMAIL".into(), label: "Admin Email".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("admin@example.com".into()), options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 6 characters".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "redis-commander".into(),
            name: "Redis Commander".into(),
            icon: "🔴".into(),
            category: "Database".into(),
            description: "Web management tool for Redis".into(),
            website: Some("https://github.com/joeferner/redis-commander".into()),
            docker: Some(DockerTarget {
                image: "rediscommander/redis-commander:latest".into(),
                ports: vec!["8081:8081".into()],
                env: vec!["REDIS_HOSTS=${REDIS_HOST}".into()],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "REDIS_HOST".into(), label: "Redis Host".into(), input_type: "text".into(), default: Some("local:redis:6379".into()), required: true, placeholder: Some("label:host:port".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "mongo-express".into(),
            name: "Mongo Express".into(),
            icon: "🍃".into(),
            category: "Database".into(),
            description: "Web-based MongoDB admin interface".into(),
            website: Some("https://github.com/mongo-express/mongo-express".into()),
            docker: Some(DockerTarget {
                image: "mongo-express:latest".into(),
                ports: vec!["8081:8081".into()],
                env: vec!["ME_CONFIG_MONGODB_URL=${MONGO_URL}".into()],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "MONGO_URL".into(), label: "MongoDB URL".into(), input_type: "text".into(), default: Some("mongodb://mongo:27017".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        // ─── Networking ───

        AppManifest {
            id: "adguard".into(),
            name: "AdGuard Home".into(),
            icon: "🛡️".into(),
            category: "Networking".into(),
            description: "Network-wide ad and tracker blocking DNS server".into(),
            website: Some("https://adguard.com/adguard-home.html".into()),
            docker: Some(DockerTarget {
                image: "adguard/adguardhome:latest".into(),
                ports: vec!["3000:3000".into(), "53:53/udp".into(), "53:53/tcp".into()],
                env: vec![],
                volumes: vec!["adguard_work:/opt/adguardhome/work".into(), "adguard_conf:/opt/adguardhome/conf".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "nginx-proxy-manager".into(),
            name: "Nginx Proxy Manager".into(),
            icon: "🔀".into(),
            category: "Networking".into(),
            description: "Reverse proxy with a simple web UI and free SSL certificates".into(),
            website: Some("https://nginxproxymanager.com".into()),
            docker: Some(DockerTarget {
                image: "jc21/nginx-proxy-manager:latest".into(),
                ports: vec!["80:80".into(), "443:443".into(), "81:81".into()],
                env: vec![],
                volumes: vec!["npm_data:/data".into(), "npm_letsencrypt:/etc/letsencrypt".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "netbird".into(),
            name: "NetBird".into(),
            icon: "🐦".into(),
            category: "Networking".into(),
            description: "WireGuard-based mesh VPN with SSO and access control".into(),
            website: Some("https://netbird.io".into()),
            docker: Some(DockerTarget {
                image: "netbirdio/netbird:latest".into(),
                ports: vec!["51820:51820/udp".into()],
                env: vec!["NB_SETUP_KEY=${SETUP_KEY}".into()],
                volumes: vec!["netbird_config:/etc/netbird".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SETUP_KEY".into(), label: "Setup Key".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("From NetBird dashboard".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "tailscale".into(),
            name: "Tailscale".into(),
            icon: "🔗".into(),
            category: "Networking".into(),
            description: "Zero-config WireGuard VPN mesh network".into(),
            website: Some("https://tailscale.com".into()),
            docker: Some(DockerTarget {
                image: "tailscale/tailscale:latest".into(),
                ports: vec![],
                env: vec!["TS_AUTHKEY=${AUTH_KEY}".into(), "TS_STATE_DIR=/var/lib/tailscale".into()],
                volumes: vec!["tailscale_state:/var/lib/tailscale".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "AUTH_KEY".into(), label: "Auth Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("From Tailscale admin console".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "speedtest-tracker".into(),
            name: "Speedtest Tracker".into(),
            icon: "🚀".into(),
            category: "Networking".into(),
            description: "Continuously track your internet speed and display results".into(),
            website: Some("https://github.com/alexjustesen/speedtest-tracker".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/speedtest-tracker:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "DB_CONNECTION=sqlite".into()],
                volumes: vec!["speedtest_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ─── Home / IoT ───

        AppManifest {
            id: "nodered".into(),
            name: "Node-RED".into(),
            icon: "🔴".into(),
            category: "Automation".into(),
            description: "Low-code programming for event-driven automation and IoT".into(),
            website: Some("https://nodered.org".into()),
            docker: Some(DockerTarget {
                image: "nodered/node-red:latest".into(),
                ports: vec!["1880:1880".into()],
                env: vec![],
                volumes: vec!["nodered_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "mosquitto".into(),
            name: "Eclipse Mosquitto".into(),
            icon: "🦟".into(),
            category: "Automation".into(),
            description: "Lightweight MQTT message broker for IoT".into(),
            website: Some("https://mosquitto.org".into()),
            docker: Some(DockerTarget {
                image: "eclipse-mosquitto:latest".into(),
                ports: vec!["1883:1883".into(), "9001:9001".into()],
                env: vec![],
                volumes: vec!["mosquitto_config:/mosquitto/config".into(), "mosquitto_data:/mosquitto/data".into(), "mosquitto_log:/mosquitto/log".into()],
                sidecars: vec![],
                // Mosquitto refuses to start without a mosquitto.conf
                // — seed a minimal anonymous listener so the broker
                // comes up on port 1883 for local testing. Users
                // should tighten this (disable `allow_anonymous`,
                // add a password file) for production.
                seed_files: vec![SeedFile {
                    container_path: "/mosquitto/config/mosquitto.conf".into(),
                    content: "listener 1883\nallow_anonymous true\npersistence true\npersistence_location /mosquitto/data/\nlog_dest file /mosquitto/log/mosquitto.log\n".into(),
                }], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "zigbee2mqtt".into(),
            name: "Zigbee2MQTT".into(),
            icon: "📡".into(),
            category: "Automation".into(),
            description: "Bridge Zigbee devices to MQTT without proprietary hubs".into(),
            website: Some("https://www.zigbee2mqtt.io".into()),
            docker: Some(DockerTarget {
                image: "koenkk/zigbee2mqtt:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec![],
                volumes: vec!["zigbee2mqtt_data:/app/data".into()],
                sidecars: vec![],
                // Zigbee2MQTT exits on boot if /app/data/configuration.yaml
                // is missing. Seed a stub that points at the local
                // Mosquitto broker (users running Zigbee2MQTT almost
                // always run Mosquitto alongside it) and enables the
                // web frontend. The user edits from the web UI.
                seed_files: vec![SeedFile {
                    container_path: "/app/data/configuration.yaml".into(),
                    content: "homeassistant: false\npermit_join: false\n\nmqtt:\n  base_topic: zigbee2mqtt\n  server: mqtt://localhost:1883\n\nserial:\n  port: /dev/ttyACM0\n\nfrontend:\n  port: 8080\n".into(),
                }], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "frigate".into(),
            name: "Frigate".into(),
            icon: "📹".into(),
            category: "Automation".into(),
            description: "NVR with real-time AI object detection for security cameras".into(),
            website: Some("https://frigate.video".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/blakeblackshear/frigate:stable".into(),
                ports: vec!["5000:5000".into(), "8554:8554".into(), "8555:8555/tcp".into(), "8555:8555/udp".into()],
                env: vec![],
                volumes: vec!["frigate_config:/config".into(), "frigate_media:/media/frigate".into()],
                sidecars: vec![],
                // Frigate refuses to start without /config/config.yml
                // and ends up in a docker restart loop. Seed a minimal
                // stub with one disabled dummy camera so the container
                // comes up; the user edits it from the Frigate web UI.
                seed_files: vec![SeedFile {
                    container_path: "/config/config.yml".into(),
                    content: "mqtt:\n  enabled: False\n\ncameras:\n  dummy_camera:\n    enabled: False\n    ffmpeg:\n      inputs:\n        - path: rtsp://127.0.0.1:554/dummy\n          roles:\n            - detect\n    detect:\n      enabled: False\n".into(),
                }], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "esphome".into(),
            name: "ESPHome".into(),
            icon: "💡".into(),
            category: "Automation".into(),
            description: "Firmware for ESP8266/ESP32 microcontrollers with Home Assistant integration".into(),
            website: Some("https://esphome.io".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/esphome/esphome:latest".into(),
                ports: vec!["6052:6052".into()],
                env: vec![],
                volumes: vec!["esphome_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "scrypted".into(),
            name: "Scrypted".into(),
            icon: "🏠".into(),
            category: "Automation".into(),
            description: "Home video integration platform for HomeKit, Google Home, and Alexa".into(),
            website: Some("https://www.scrypted.app".into()),
            docker: Some(DockerTarget {
                image: "koush/scrypted:latest".into(),
                ports: vec!["10443:10443".into()],
                env: vec![],
                volumes: vec!["scrypted_data:/server/volume".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ─── Monitoring ───

        AppManifest {
            id: "loki".into(),
            name: "Grafana Loki".into(),
            icon: "📋".into(),
            category: "Monitoring".into(),
            description: "Horizontally-scalable log aggregation system by Grafana".into(),
            website: Some("https://grafana.com/oss/loki/".into()),
            docker: Some(DockerTarget {
                image: "grafana/loki:latest".into(),
                ports: vec!["3100:3100".into()],
                env: vec![],
                volumes: vec!["loki_data:/loki".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "healthchecks".into(),
            name: "Healthchecks".into(),
            icon: "💓".into(),
            category: "Monitoring".into(),
            description: "Cron job and background task monitoring with alerts".into(),
            website: Some("https://healthchecks.io".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/healthchecks:latest".into(),
                ports: vec!["8000:8000".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "SITE_ROOT=http://localhost:8000".into(), "SECRET_KEY=${SECRET_KEY}".into()],
                volumes: vec!["healthchecks_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "gatus".into(),
            name: "Gatus".into(),
            icon: "🟢".into(),
            category: "Monitoring".into(),
            description: "Automated endpoint health monitoring with alerting".into(),
            website: Some("https://gatus.io".into()),
            docker: Some(DockerTarget {
                image: "twinproduction/gatus:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec![],
                volumes: vec!["gatus_config:/config".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "glances".into(),
            name: "Glances".into(),
            icon: "👁️".into(),
            category: "Monitoring".into(),
            description: "Cross-platform system monitoring tool with web UI".into(),
            website: Some("https://nicolargo.github.io/glances/".into()),
            docker: Some(DockerTarget {
                image: "nicolargo/glances:latest-full".into(),
                ports: vec!["61208:61208".into()],
                env: vec!["GLANCES_OPT=-w".into()],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ─── Security ───

        AppManifest {
            id: "authelia".into(),
            name: "Authelia".into(),
            icon: "🔐".into(),
            category: "Security".into(),
            description: "SSO and 2FA authentication server for reverse proxies".into(),
            website: Some("https://www.authelia.com".into()),
            docker: Some(DockerTarget {
                image: "authelia/authelia:latest".into(),
                ports: vec!["9091:9091".into()],
                env: vec![],
                volumes: vec!["authelia_config:/config".into()],
                sidecars: vec![],
                // Authelia crash-loops without /config/configuration.yml
                // plus a users_database. Seed both with placeholder
                // secrets — users MUST change these before putting
                // this in front of real traffic (warning in the stub).
                seed_files: vec![
                    SeedFile {
                        container_path: "/config/configuration.yml".into(),
                        content: "# WARNING: placeholder secrets — change before use!\nserver:\n  address: 'tcp://:9091'\n\nlog:\n  level: info\n\ntotp:\n  issuer: authelia.local\n\nauthentication_backend:\n  file:\n    path: /config/users_database.yml\n\naccess_control:\n  default_policy: one_factor\n\nsession:\n  name: authelia_session\n  secret: CHANGE_ME_SESSION_SECRET_MIN_64_CHARS_REQUIRED_FOR_PRODUCTION_USE\n  expiration: 1h\n  inactivity: 5m\n  cookies:\n    - domain: example.com\n      authelia_url: https://auth.example.com\n\nstorage:\n  encryption_key: CHANGE_ME_STORAGE_ENCRYPTION_KEY_MIN_20_CHARS\n  local:\n    path: /config/db.sqlite3\n\nnotifier:\n  filesystem:\n    filename: /config/notification.txt\n\nidentity_validation:\n  reset_password:\n    jwt_secret: CHANGE_ME_JWT_SECRET_FOR_PASSWORD_RESET_TOKENS\n".into(),
                    },
                    SeedFile {
                        container_path: "/config/users_database.yml".into(),
                        // Default admin / authelia (argon2id hash). User MUST rotate this.
                        content: "users:\n  admin:\n    displayname: 'Admin User'\n    # password: 'authelia' — CHANGE THIS IMMEDIATELY\n    password: '$argon2id$v=19$m=65536,t=3,p=4$cmVwbGFjZXRoaXNzYWx0$GIhbSvmSPLkA47vJDIdaBu0XwvrrY1SOZgY6+1aORCY'\n    email: admin@example.com\n    groups:\n      - admins\n".into(),
                    },
                ], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "wazuh".into(),
            name: "Wazuh".into(),
            icon: "🔒".into(),
            category: "Security".into(),
            description: "Open-source security platform — SIEM, XDR, intrusion detection".into(),
            website: Some("https://wazuh.com".into()),
            docker: Some(DockerTarget {
                image: "wazuh/wazuh-manager:latest".into(),
                ports: vec!["1514:1514/udp".into(), "1515:1515".into(), "55000:55000".into()],
                env: vec![],
                volumes: vec!["wazuh_api:/var/ossec/api/configuration".into(), "wazuh_etc:/var/ossec/etc".into(), "wazuh_logs:/var/ossec/logs".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ─── Communication ───

        AppManifest {
            id: "element-web".into(),
            name: "Element Web".into(),
            icon: "💬".into(),
            category: "Communication".into(),
            description: "Matrix web client for decentralised encrypted messaging".into(),
            website: Some("https://element.io".into()),
            docker: Some(DockerTarget {
                image: "vectorim/element-web:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // Stalwart — modern all-in-one mail server (SMTP/IMAP/POP3/JMAP/
        // ManageSieve) in a single Rust binary. Ports, volumes and the
        // recovery-admin env are from the official docker docs
        // (stalw.art/docs/install/platform/docker). STALWART_RECOVERY_ADMIN
        // sets the initial admin up front (admin:<password>) instead of
        // making the operator grep the bootstrap password out of the logs.
        AppManifest {
            id: "stalwart".into(),
            name: "Stalwart Mail Server".into(),
            icon: "📬".into(),
            category: "Communication".into(),
            description: "All-in-one secure mail server — SMTP, IMAP, POP3, JMAP & ManageSieve in one Rust binary".into(),
            website: Some("https://stalw.art".into()),
            docker: Some(DockerTarget {
                image: "stalwartlabs/stalwart:latest".into(),
                // HTTPS/admin+JMAP, HTTP admin, SMTP (25/587/465),
                // IMAP (143/993), POP3 (110/995), ManageSieve (4190).
                ports: vec![
                    "443:443".into(), "8080:8080".into(),
                    "25:25".into(), "587:587".into(), "465:465".into(),
                    "143:143".into(), "993:993".into(),
                    "110:110".into(), "995:995".into(),
                    "4190:4190".into(),
                ],
                env: vec!["STALWART_RECOVERY_ADMIN=admin:${ADMIN_PASSWORD}".into()],
                volumes: vec![
                    "stalwart_etc:/etc/stalwart".into(),
                    "stalwart_data:/var/lib/stalwart".into(),
                ],
                sidecars: vec![], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None,
            user_inputs: vec![UserInput {
                id: "ADMIN_PASSWORD".into(),
                label: "Admin Password".into(),
                input_type: "password".into(),
                default: None,
                required: true,
                placeholder: Some("Password for the 'admin' account".into()),
                options: vec![],
            }],
        },

        AppManifest {
            id: "gotify".into(),
            name: "Gotify".into(),
            icon: "🔔".into(),
            category: "Communication".into(),
            description: "Self-hosted push notification server with REST API".into(),
            website: Some("https://gotify.net".into()),
            docker: Some(DockerTarget {
                image: "gotify/server:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec![],
                volumes: vec!["gotify_data:/app/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "ntfy".into(),
            name: "ntfy".into(),
            icon: "📢".into(),
            category: "Communication".into(),
            description: "Simple push notifications via HTTP PUT/POST".into(),
            website: Some("https://ntfy.sh".into()),
            docker: Some(DockerTarget {
                image: "binwiederhier/ntfy:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec![],
                volumes: vec!["ntfy_cache:/var/cache/ntfy".into(), "ntfy_etc:/etc/ntfy".into()],
                sidecars: vec![],
                seed_files: vec![],
                // The image's ENTRYPOINT is bare `ntfy` — with no
                // command it prints help and exits 0, so the container
                // died instantly as previously shipped (verified live
                // 2026-07-13, ntfy 2.26.0). `serve` starts the server.
                cmd: vec!["serve".into()],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "slack-alternative".into(),
            name: "Zulip".into(),
            icon: "💬".into(),
            category: "Communication".into(),
            description: "Threaded team chat with topic-based organisation".into(),
            website: Some("https://zulip.com".into()),
            docker: Some(DockerTarget {
                image: "zulip/docker-zulip:latest".into(),
                ports: vec!["8080:80".into(), "8443:443".into()],
                env: vec!["SETTING_EXTERNAL_HOST=${DOMAIN}".into(), "SECRETS_secret_key=${SECRET_KEY}".into()],
                volumes: vec!["zulip_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DOMAIN".into(), label: "Domain".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. chat.example.com".into()), options: vec![] },
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
            ],
        },

        // ─── CMS & Web ───

        AppManifest {
            id: "directus".into(),
            name: "Directus".into(),
            icon: "🐰".into(),
            category: "CMS".into(),
            description: "Headless CMS with a REST and GraphQL API for any SQL database".into(),
            website: Some("https://directus.io".into()),
            docker: Some(DockerTarget {
                image: "directus/directus:latest".into(),
                ports: vec!["8055:8055".into()],
                env: vec!["ADMIN_EMAIL=${ADMIN_EMAIL}".into(), "ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(), "DB_CLIENT=sqlite3".into(), "DB_FILENAME=/directus/database/data.db".into()],
                volumes: vec!["directus_database:/directus/database".into(), "directus_uploads:/directus/uploads".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_EMAIL".into(), label: "Admin Email".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("admin@example.com".into()), options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "payload".into(),
            name: "Payload CMS".into(),
            icon: "🏗️".into(),
            category: "CMS".into(),
            description: "Headless CMS and application framework built with TypeScript".into(),
            website: Some("https://payloadcms.com".into()),
            docker: Some(DockerTarget {
                image: "payloadcms/payload:latest".into(),
                ports: vec!["3000:3000".into()],
                env: vec!["PAYLOAD_SECRET=${SECRET_KEY}".into(), "DATABASE_URI=file:./payload.db".into()],
                volumes: vec!["payload_data:/home/node/app/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Payload Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "plone".into(),
            name: "Plone".into(),
            icon: "🌐".into(),
            category: "CMS".into(),
            description: "Enterprise CMS built on Python with workflow and security".into(),
            website: Some("https://plone.org".into()),
            docker: Some(DockerTarget {
                image: "plone/plone-backend:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec!["SITE=Plone".into()],
                volumes: vec!["plone_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "listmonk".into(),
            name: "Listmonk".into(),
            icon: "📧".into(),
            category: "Communication".into(),
            description: "Self-hosted newsletter and mailing list manager".into(),
            website: Some("https://listmonk.app".into()),
            docker: Some(DockerTarget {
                image: "listmonk/listmonk:latest".into(),
                ports: vec!["9000:9000".into()],
                env: vec![],
                volumes: vec!["listmonk_data:/listmonk".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "postgres:15-alpine".into(),
                    ports: vec![],
                    env: vec!["POSTGRES_DB=listmonk".into(), "POSTGRES_USER=listmonk".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()],
                    volumes: vec!["listmonk_db:/var/lib/postgresql/data".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },

        // ─── Privacy ───

        AppManifest {
            id: "piped".into(),
            name: "Piped".into(),
            icon: "▶️".into(),
            category: "Privacy".into(),
            description: "Privacy-friendly YouTube frontend with no ads or tracking".into(),
            website: Some("https://github.com/TeamPiped/Piped".into()),
            docker: Some(DockerTarget {
                image: "1337kavin/piped-frontend:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "libreddit".into(),
            name: "Redlib".into(),
            icon: "🔶".into(),
            category: "Privacy".into(),
            description: "Private Reddit frontend with no JavaScript, ads, or tracking".into(),
            website: Some("https://github.com/redlib-org/redlib".into()),
            docker: Some(DockerTarget {
                image: "quay.io/redlib/redlib:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec![],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "invidious".into(),
            name: "Invidious".into(),
            icon: "📺".into(),
            category: "Privacy".into(),
            description: "Alternative YouTube frontend focused on privacy".into(),
            website: Some("https://invidious.io".into()),
            docker: Some(DockerTarget {
                image: "quay.io/invidious/invidious:latest".into(),
                ports: vec!["3000:3000".into()],
                env: vec!["INVIDIOUS_CONFIG=db:\\n  dbname: invidious\\n  user: kemal\\n  password: kemal\\n  host: invidious-db\\n  port: 5432".into()],
                volumes: vec![],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "postgres:15-alpine".into(),
                    ports: vec![],
                    env: vec!["POSTGRES_DB=invidious".into(), "POSTGRES_USER=kemal".into(), "POSTGRES_PASSWORD=kemal".into()],
                    volumes: vec!["invidious_db:/var/lib/postgresql/data".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        // ─── Backup & Storage ───

        AppManifest {
            id: "duplicati".into(),
            name: "Duplicati".into(),
            icon: "💾".into(),
            category: "Other".into(),
            description: "Encrypted backup to cloud storage (S3, Backblaze, Google Drive, etc)".into(),
            website: Some("https://www.duplicati.com".into()),
            docker: Some(DockerTarget {
                image: "linuxserver/duplicati:latest".into(),
                ports: vec!["8200:8200".into()],
                env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()],
                volumes: vec!["duplicati_config:/config".into(), "${BACKUP_SOURCE}:/source:ro".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "BACKUP_SOURCE".into(), label: "Source Path".into(), input_type: "text".into(), default: Some("/".into()), required: true, placeholder: Some("Path to back up".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "filebrowser".into(),
            name: "File Browser".into(),
            icon: "📁".into(),
            category: "Other".into(),
            description: "Web file manager with sharing, users, and media playback".into(),
            website: Some("https://filebrowser.org".into()),
            docker: Some(DockerTarget {
                image: "filebrowser/filebrowser:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec![],
                volumes: vec!["filebrowser_db:/database".into(), "${ROOT_PATH}:/srv".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ROOT_PATH".into(), label: "Root Directory".into(), input_type: "text".into(), default: Some("/".into()), required: true, placeholder: Some("Directory to browse".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "seafile".into(),
            name: "Seafile".into(),
            icon: "☁️".into(),
            category: "Productivity".into(),
            description: "File sync and share with built-in wiki and knowledge management".into(),
            website: Some("https://www.seafile.com".into()),
            docker: Some(DockerTarget {
                image: "seafileltd/seafile-mc:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec!["SEAFILE_ADMIN_EMAIL=${ADMIN_EMAIL}".into(), "SEAFILE_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(), "DB_HOST=seafile-db".into(), "DB_ROOT_PASSWD=${DB_PASSWORD}".into()],
                volumes: vec!["seafile_data:/shared".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:10".into(),
                    ports: vec![],
                    env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into()],
                    volumes: vec!["seafile_db:/var/lib/mysql".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_EMAIL".into(), label: "Admin Email".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("admin@example.com".into()), options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB root password".into()), options: vec![] },
            ],
        },

        // ─── Analytics ───

        AppManifest {
            id: "matomo".into(),
            name: "Matomo".into(),
            icon: "📈".into(),
            category: "Analytics".into(),
            description: "Privacy-focused web analytics — Google Analytics alternative".into(),
            website: Some("https://matomo.org".into()),
            docker: Some(DockerTarget {
                image: "matomo:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec!["MATOMO_DATABASE_HOST=matomo-db".into(), "MATOMO_DATABASE_DBNAME=matomo".into(), "MATOMO_DATABASE_USERNAME=matomo".into(), "MATOMO_DATABASE_PASSWORD=${DB_PASSWORD}".into()],
                volumes: vec!["matomo_data:/var/www/html".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:10".into(),
                    ports: vec![],
                    env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=matomo".into(), "MYSQL_USER=matomo".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()],
                    volumes: vec!["matomo_db:/var/lib/mysql".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] },
            ],
        },

        AppManifest {
            id: "posthog".into(),
            name: "PostHog".into(),
            icon: "🦔".into(),
            category: "Analytics".into(),
            description: "Product analytics, session recording, feature flags, and A/B testing".into(),
            website: Some("https://posthog.com".into()),
            docker: Some(DockerTarget {
                image: "posthog/posthog:latest".into(),
                ports: vec!["8000:8000".into()],
                env: vec!["SECRET_KEY=${SECRET_KEY}".into(), "DATABASE_URL=sqlite:////data/posthog.db".into()],
                volumes: vec!["posthog_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
            ],
        },

        // ─── Project Management ───

        AppManifest {
            id: "vikunja".into(),
            name: "Vikunja".into(),
            icon: "✅".into(),
            category: "Project Management".into(),
            description: "Open-source task management and to-do list app".into(),
            website: Some("https://vikunja.io".into()),
            docker: Some(DockerTarget {
                image: "vikunja/vikunja:latest".into(),
                ports: vec!["3456:3456".into()],
                env: vec![],
                volumes: vec!["vikunja_files:/app/vikunja/files".into(), "vikunja_db:/db".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "wekan".into(),
            name: "WeKan".into(),
            icon: "📋".into(),
            category: "Project Management".into(),
            description: "Open-source kanban board — Trello alternative".into(),
            website: Some("https://wekan.github.io".into()),
            docker: Some(DockerTarget {
                image: "wekanteam/wekan:latest".into(),
                ports: vec!["8080:8080".into()],
                env: vec!["MONGO_URL=mongodb://wekan-db:27017/wekan".into(), "ROOT_URL=http://localhost:8080".into()],
                volumes: vec!["wekan_data:/data".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mongo:6".into(),
                    ports: vec![],
                    env: vec![],
                    volumes: vec!["wekan_db:/data/db".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "leantime".into(),
            name: "Leantime".into(),
            icon: "📐".into(),
            category: "Project Management".into(),
            description: "Strategic project management for non-project managers".into(),
            website: Some("https://leantime.io".into()),
            docker: Some(DockerTarget {
                image: "leantime/leantime:latest".into(),
                ports: vec!["8080:80".into()],
                env: vec!["LEAN_DB_HOST=leantime-db".into(), "LEAN_DB_DATABASE=leantime".into(), "LEAN_DB_USER=lean".into(), "LEAN_DB_PASSWORD=${DB_PASSWORD}".into()],
                volumes: vec!["leantime_data:/var/www/html/userfiles".into()],
                sidecars: vec![DockerSidecar {
                    name_suffix: "db".into(),
                    image: "mariadb:10".into(),
                    ports: vec![],
                    env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=leantime".into(), "MYSQL_USER=lean".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()],
                    volumes: vec!["leantime_db:/var/lib/mysql".into()],
                 cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] },
            ],
        },

        // ─── CI/CD ───

        AppManifest {
            id: "jenkins".into(),
            name: "Jenkins".into(),
            icon: "🤵".into(),
            category: "CI/CD".into(),
            description: "Extensible open-source automation server for CI/CD".into(),
            website: Some("https://www.jenkins.io".into()),
            docker: Some(DockerTarget {
                image: "jenkins/jenkins:lts".into(),
                ports: vec!["8080:8080".into(), "50000:50000".into()],
                env: vec![],
                volumes: vec!["jenkins_home:/var/jenkins_home".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "sonarqube".into(),
            name: "SonarQube".into(),
            icon: "🔎".into(),
            category: "Dev Tools".into(),
            description: "Continuous code quality and security analysis".into(),
            website: Some("https://www.sonarqube.org".into()),
            docker: Some(DockerTarget {
                image: "sonarqube:community".into(),
                ports: vec!["9000:9000".into()],
                env: vec![],
                volumes: vec!["sonarqube_data:/opt/sonarqube/data".into(), "sonarqube_logs:/opt/sonarqube/logs".into(), "sonarqube_extensions:/opt/sonarqube/extensions".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "act-runner".into(),
            name: "Gitea Act Runner".into(),
            icon: "🏃".into(),
            category: "CI/CD".into(),
            description: "CI/CD runner for Gitea Actions (GitHub Actions compatible)".into(),
            website: Some("https://gitea.com/gitea/act_runner".into()),
            docker: Some(DockerTarget {
                image: "gitea/act_runner:latest".into(),
                ports: vec![],
                env: vec!["GITEA_INSTANCE_URL=${GITEA_URL}".into(), "GITEA_RUNNER_REGISTRATION_TOKEN=${REG_TOKEN}".into()],
                volumes: vec!["act_runner_data:/data".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![
                UserInput { id: "GITEA_URL".into(), label: "Gitea URL".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. http://gitea:3000".into()), options: vec![] },
                UserInput { id: "REG_TOKEN".into(), label: "Registration Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("From Gitea runner settings".into()), options: vec![] },
            ],
        },

        // ─── AI / ML ───

        AppManifest {
            id: "localai".into(),
            name: "LocalAI".into(),
            icon: "🤖".into(),
            category: "AI / ML".into(),
            description: "OpenAI-compatible local AI inference server — run LLMs privately".into(),
            website: Some("https://localai.io".into()),
            docker: Some(DockerTarget {
                image: "localai/localai:latest-cpu".into(),
                ports: vec!["8080:8080".into()],
                env: vec![],
                volumes: vec!["localai_models:/models".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "stable-diffusion".into(),
            name: "Stable Diffusion WebUI".into(),
            icon: "🎨".into(),
            category: "AI / ML".into(),
            description: "AI image generation with a browser-based interface".into(),
            website: Some("https://github.com/AUTOMATIC1111/stable-diffusion-webui".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/ai-dock/stable-diffusion-webui:latest-cpu".into(),
                ports: vec!["7860:7860".into()],
                env: vec![],
                volumes: vec!["sd_models:/opt/stable-diffusion-webui/models".into(), "sd_outputs:/opt/stable-diffusion-webui/outputs".into()],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },

        AppManifest {
            id: "whisper".into(),
            name: "Whisper ASR".into(),
            icon: "🎤".into(),
            category: "AI / ML".into(),
            description: "OpenAI Whisper speech-to-text server with API".into(),
            website: Some("https://github.com/ahmetoner/whisper-asr-webservice".into()),
            docker: Some(DockerTarget {
                image: "onerahmet/openai-whisper-asr-webservice:latest-cpu".into(),
                ports: vec!["9000:9000".into()],
                env: vec!["ASR_MODEL=base".into()],
                volumes: vec![],
                sidecars: vec![],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None,
            vm: None, user_inputs: vec![],
        },


        // ═══════════════════════════════════════════════════════════════
        // Batch 2 — 332 additional apps to reach 500 total
        // ═══════════════════════════════════════════════════════════════

        // ─── Media (batch 2) ───

        AppManifest { id: "airsonic".into(), name: "Airsonic Advanced".into(), icon: "🎵".into(), category: "Media".into(),
            description: "Web-based music streamer with transcoding and podcast support".into(),
            website: Some("https://github.com/airsonic-advanced/airsonic-advanced".into()),
            docker: Some(DockerTarget { image: "airsonicadvanced/airsonic-advanced:latest".into(), ports: vec!["4040:4040".into()], env: vec![], volumes: vec!["airsonic_data:/var/airsonic".into(), "${MUSIC_PATH}:/music:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "MUSIC_PATH".into(), label: "Music Path".into(), input_type: "text".into(), default: Some("/opt/media/music".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "funkwhale".into(), name: "Funkwhale".into(), icon: "🐋".into(), category: "Media".into(),
            description: "Social music platform — listen, share, and discover music".into(),
            website: Some("https://funkwhale.audio".into()),
            docker: Some(DockerTarget { image: "funkwhale/all-in-one:latest".into(), ports: vec!["5000:80".into()], env: vec![], volumes: vec!["funkwhale_data:/data".into(), "${MUSIC_PATH}:/music:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "MUSIC_PATH".into(), label: "Music Path".into(), input_type: "text".into(), default: Some("/opt/media/music".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "dim".into(), name: "Dim".into(), icon: "🎞️".into(), category: "Media".into(),
            description: "Self-hosted media manager for movies and TV shows".into(),
            website: Some("https://github.com/Dusk-Labs/dim".into()),
            docker: Some(DockerTarget { image: "ghcr.io/dusk-labs/dim:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["dim_config:/opt/dim/config".into(), "${MEDIA_PATH}:/media".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "Media Path".into(), input_type: "text".into(), default: Some("/opt/media".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "tubesync".into(), name: "TubeSync".into(), icon: "📥".into(), category: "Media".into(),
            description: "Automatically download YouTube channels and playlists".into(),
            website: Some("https://github.com/meeb/tubesync".into()),
            docker: Some(DockerTarget { image: "ghcr.io/meeb/tubesync:latest".into(), ports: vec!["4848:4848".into()], env: vec![], volumes: vec!["tubesync_config:/config".into(), "tubesync_downloads:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "readarr".into(), name: "Readarr".into(), icon: "📖".into(), category: "Media".into(),
            description: "Ebook and audiobook collection manager for the Servarr stack".into(),
            website: Some("https://readarr.com".into()),
            docker: Some(DockerTarget { image: "linuxserver/readarr:develop".into(), ports: vec!["8787:8787".into()], env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()], volumes: vec!["readarr_config:/config".into(), "${BOOKS_PATH}:/books".into(), "${DOWNLOAD_PATH}:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "BOOKS_PATH".into(), label: "Books Path".into(), input_type: "text".into(), default: Some("/opt/media/books".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "komga".into(), name: "Komga".into(), icon: "📚".into(), category: "Media".into(),
            description: "Media server for comics, mangas, and magazines".into(),
            website: Some("https://komga.org".into()),
            docker: Some(DockerTarget { image: "gotson/komga:latest".into(), ports: vec!["25600:25600".into()], env: vec![], volumes: vec!["komga_config:/config".into(), "${LIBRARY_PATH}:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "LIBRARY_PATH".into(), label: "Library Path".into(), input_type: "text".into(), default: Some("/opt/media/comics".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "photoview".into(), name: "Photoview".into(), icon: "🖼️".into(), category: "Media".into(),
            description: "Simple photo gallery with face detection and EXIF parsing".into(),
            website: Some("https://photoview.github.io".into()),
            docker: Some(DockerTarget { image: "viktorstrate/photoview:latest".into(), ports: vec!["8080:80".into()], env: vec!["PHOTOVIEW_SQLITE_PATH=/data/photoview.db".into()], volumes: vec!["photoview_data:/data".into(), "${PHOTOS_PATH}:/photos:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "PHOTOS_PATH".into(), label: "Photos Path".into(), input_type: "text".into(), default: Some("/opt/photos".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "lychee".into(), name: "Lychee".into(), icon: "🍒".into(), category: "Media".into(),
            description: "Beautiful photo management and sharing tool".into(),
            website: Some("https://lychee.electerious.com".into()),
            docker: Some(DockerTarget { image: "lycheeorg/lychee:latest".into(), ports: vec!["8090:80".into()], env: vec!["DB_CONNECTION=sqlite".into(), "DB_DATABASE=/data/lychee.sqlite".into()], volumes: vec!["lychee_config:/conf".into(), "lychee_uploads:/uploads".into(), "lychee_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "miniflux".into(), name: "Miniflux".into(), icon: "📰".into(), category: "Media".into(),
            description: "Minimalist and opinionated RSS/Atom feed reader".into(),
            website: Some("https://miniflux.app".into()),
            docker: Some(DockerTarget { image: "miniflux/miniflux:latest".into(), ports: vec!["8080:8080".into()], env: vec!["DATABASE_URL=postgres://miniflux:${DB_PASSWORD}@miniflux-db/miniflux?sslmode=disable".into(), "CREATE_ADMIN=1".into(), "ADMIN_USERNAME=admin".into(), "ADMIN_PASSWORD=${ADMIN_PASSWORD}".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=miniflux".into(), "POSTGRES_USER=miniflux".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["miniflux_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "freshrss".into(), name: "FreshRSS".into(), icon: "📰".into(), category: "Media".into(),
            description: "Self-hosted RSS aggregator with a clean web interface".into(),
            website: Some("https://freshrss.org".into()),
            docker: Some(DockerTarget { image: "freshrss/freshrss:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["freshrss_data:/var/www/FreshRSS/data".into(), "freshrss_extensions:/var/www/FreshRSS/extensions".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "wallabag".into(), name: "Wallabag".into(), icon: "📑".into(), category: "Media".into(),
            description: "Read-it-later app — save and organize web articles".into(),
            website: Some("https://wallabag.org".into()),
            docker: Some(DockerTarget { image: "wallabag/wallabag:latest".into(), ports: vec!["8080:80".into()], env: vec!["SYMFONY__ENV__DOMAIN_NAME=http://localhost:8080".into()], volumes: vec!["wallabag_data:/var/www/wallabag/data".into(), "wallabag_images:/var/www/wallabag/web/assets/images".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Productivity (batch 2) ───

        AppManifest { id: "onlyoffice".into(), name: "ONLYOFFICE Docs".into(), icon: "📄".into(), category: "Productivity".into(),
            description: "Online office suite — documents, spreadsheets, presentations".into(),
            website: Some("https://www.onlyoffice.com".into()),
            docker: Some(DockerTarget { image: "onlyoffice/documentserver:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["onlyoffice_data:/var/www/onlyoffice/Data".into(), "onlyoffice_log:/var/log/onlyoffice".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "collabora".into(), name: "Collabora Online".into(), icon: "📝".into(), category: "Productivity".into(),
            description: "LibreOffice-based online document editing for Nextcloud and others".into(),
            website: Some("https://www.collaboraoffice.com".into()),
            docker: Some(DockerTarget { image: "collabora/code:latest".into(), ports: vec!["9980:9980".into()], env: vec!["extra_params=--o:ssl.enable=false".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "cryptpad".into(), name: "CryptPad".into(), icon: "🔒".into(), category: "Productivity".into(),
            description: "End-to-end encrypted collaboration suite — docs, sheets, kanban, forms".into(),
            website: Some("https://cryptpad.org".into()),
            docker: Some(DockerTarget { image: "promasu/cryptpad:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["cryptpad_blob:/cryptpad/blob".into(), "cryptpad_block:/cryptpad/block".into(), "cryptpad_data:/cryptpad/datastore".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "vikunja-cal".into(), name: "Radicale".into(), icon: "📅".into(), category: "Productivity".into(),
            description: "Lightweight CalDAV and CardDAV server for contacts and calendars".into(),
            website: Some("https://radicale.org".into()),
            docker: Some(DockerTarget { image: "tomsquest/docker-radicale:latest".into(), ports: vec!["5232:5232".into()], env: vec![], volumes: vec!["radicale_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "baikal".into(), name: "Baikal".into(), icon: "📇".into(), category: "Productivity".into(),
            description: "CalDAV and CardDAV server with a simple admin interface".into(),
            website: Some("https://sabre.io/baikal/".into()),
            docker: Some(DockerTarget { image: "ckulka/baikal:nginx".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["baikal_config:/var/www/baikal/config".into(), "baikal_data:/var/www/baikal/Specific".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "linkwarden".into(), name: "Linkwarden".into(), icon: "🔖".into(), category: "Productivity".into(),
            description: "Bookmark manager with collaboration and archiving".into(),
            website: Some("https://linkwarden.app".into()),
            docker: Some(DockerTarget { image: "ghcr.io/linkwarden/linkwarden:latest".into(), ports: vec!["3000:3000".into()], env: vec!["DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@linkwarden-db:5432/linkwarden".into(), "NEXTAUTH_SECRET=${SECRET_KEY}".into(), "NEXTAUTH_URL=http://localhost:3000".into()], volumes: vec!["linkwarden_data:/data".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=linkwarden".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["linkwarden_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret".into()), options: vec![] },
            ],
        },
        AppManifest { id: "shiori".into(), name: "Shiori".into(), icon: "📌".into(), category: "Productivity".into(),
            description: "Simple bookmark manager with full text search".into(),
            website: Some("https://github.com/go-shiori/shiori".into()),
            docker: Some(DockerTarget { image: "ghcr.io/go-shiori/shiori:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["shiori_data:/shiori".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "docuseal".into(), name: "DocuSeal".into(), icon: "✍️".into(), category: "Productivity".into(),
            description: "Digital document signing — DocuSign alternative".into(),
            website: Some("https://www.docuseal.co".into()),
            docker: Some(DockerTarget { image: "docuseal/docuseal:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["docuseal_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "invoice-ninja".into(), name: "Invoice Ninja".into(), icon: "💰".into(), category: "Productivity".into(),
            description: "Invoicing, payments, and time tracking for freelancers".into(),
            website: Some("https://invoiceninja.com".into()),
            docker: Some(DockerTarget { image: "invoiceninja/invoiceninja:latest".into(), ports: vec!["8080:80".into()], env: vec!["APP_KEY=${APP_KEY}".into(), "DB_HOST=invoiceninja-db".into(), "DB_DATABASE=ninja".into(), "DB_USERNAME=ninja".into(), "DB_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["invoiceninja_public:/var/www/app/public".into(), "invoiceninja_storage:/var/www/app/storage".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "mariadb:10".into(), ports: vec![], env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=ninja".into(), "MYSQL_USER=ninja".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["invoiceninja_db:/var/lib/mysql".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "APP_KEY".into(), label: "App Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("base64:... (32-char random)".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "kimai".into(), name: "Kimai".into(), icon: "⏱️".into(), category: "Productivity".into(),
            description: "Time tracking for teams and freelancers".into(),
            website: Some("https://www.kimai.org".into()),
            docker: Some(DockerTarget { image: "kimai/kimai2:latest".into(), ports: vec!["8001:8001".into()], env: vec!["DATABASE_URL=sqlite:////opt/kimai/var/data/kimai.sqlite".into()], volumes: vec!["kimai_data:/opt/kimai/var/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Dev Tools (batch 2) ───

        AppManifest { id: "gitlab".into(), name: "GitLab CE".into(), icon: "🦊".into(), category: "Dev Tools".into(),
            description: "Complete DevOps platform — Git hosting, CI/CD, issue tracking".into(),
            website: Some("https://about.gitlab.com".into()),
            docker: Some(DockerTarget { image: "gitlab/gitlab-ce:latest".into(), ports: vec!["8080:80".into(), "8443:443".into(), "2222:22".into()], env: vec![], volumes: vec!["gitlab_config:/etc/gitlab".into(), "gitlab_logs:/var/log/gitlab".into(), "gitlab_data:/var/opt/gitlab".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "forgejo".into(), name: "Forgejo".into(), icon: "🏗️".into(), category: "Dev Tools".into(),
            description: "Community-driven Git forge — lightweight GitLab alternative".into(),
            website: Some("https://forgejo.org".into()),
            docker: Some(DockerTarget { image: "codeberg.org/forgejo/forgejo:latest".into(), ports: vec!["3000:3000".into(), "2222:22".into()], env: vec![], volumes: vec!["forgejo_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "coder".into(), name: "Coder".into(), icon: "💻".into(), category: "Dev Tools".into(),
            description: "Remote development environments on your infrastructure".into(),
            website: Some("https://coder.com".into()),
            docker: Some(DockerTarget { image: "ghcr.io/coder/coder:latest".into(), ports: vec!["7080:7080".into()], env: vec!["CODER_ACCESS_URL=http://localhost:7080".into()], volumes: vec!["coder_data:/home/coder/.config/coderv2".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "devcontainers".into(), name: "OpenVSCode Server".into(), icon: "📟".into(), category: "Dev Tools".into(),
            description: "VS Code in the browser — run from your server".into(),
            website: Some("https://github.com/gitpod-io/openvscode-server".into()),
            docker: Some(DockerTarget { image: "gitpod/openvscode-server:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["openvscode_data:/home/workspace".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "httpbin".into(), name: "httpbin".into(), icon: "🌐".into(), category: "Dev Tools".into(),
            description: "HTTP request and response testing service".into(),
            website: Some("https://httpbin.org".into()),
            docker: Some(DockerTarget { image: "kennethreitz/httpbin:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "mailhog".into(), name: "MailHog".into(), icon: "📬".into(), category: "Dev Tools".into(),
            description: "Email testing tool — catches outgoing SMTP mail for inspection".into(),
            website: Some("https://github.com/mailhog/MailHog".into()),
            docker: Some(DockerTarget { image: "mailhog/mailhog:latest".into(), ports: vec!["1025:1025".into(), "8025:8025".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "swagger-editor".into(), name: "Swagger Editor".into(), icon: "📋".into(), category: "Dev Tools".into(),
            description: "Browser-based OpenAPI/Swagger specification editor".into(),
            website: Some("https://swagger.io".into()),
            docker: Some(DockerTarget { image: "swaggerapi/swagger-editor:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "snippet-box".into(), name: "Snippet Box".into(), icon: "📋".into(), category: "Dev Tools".into(),
            description: "Simple code snippet organiser with syntax highlighting".into(),
            website: Some("https://github.com/pawelmalak/snippet-box".into()),
            docker: Some(DockerTarget { image: "pawelmalak/snippet-box:latest".into(), ports: vec!["5000:5000".into()], env: vec![], volumes: vec!["snippetbox_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "kroki".into(), name: "Kroki".into(), icon: "📊".into(), category: "Dev Tools".into(),
            description: "Unified API for diagrams — PlantUML, Mermaid, GraphViz, and more".into(),
            website: Some("https://kroki.io".into()),
            docker: Some(DockerTarget { image: "yuzutech/kroki:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "act".into(), name: "Nektos Act".into(), icon: "🎭".into(), category: "Dev Tools".into(),
            description: "Run GitHub Actions locally for testing workflows".into(),
            website: Some("https://github.com/nektos/act".into()),
            docker: Some(DockerTarget { image: "catthehacker/ubuntu:act-latest".into(), ports: vec![], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Database (batch 2) ───

        AppManifest { id: "clickhouse".into(), name: "ClickHouse".into(), icon: "🏎️".into(), category: "Database".into(),
            description: "Column-oriented OLAP database for real-time analytics".into(),
            website: Some("https://clickhouse.com".into()),
            docker: Some(DockerTarget { image: "clickhouse/clickhouse-server:latest".into(), ports: vec!["8123:8123".into(), "9000:9000".into()], env: vec![], volumes: vec!["clickhouse_data:/var/lib/clickhouse".into(), "clickhouse_logs:/var/log/clickhouse-server".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "cassandra".into(), name: "Apache Cassandra".into(), icon: "👁️".into(), category: "Database".into(),
            description: "Distributed NoSQL database for massive scalability".into(),
            website: Some("https://cassandra.apache.org".into()),
            docker: Some(DockerTarget { image: "cassandra:latest".into(), ports: vec!["9042:9042".into()], env: vec![], volumes: vec!["cassandra_data:/var/lib/cassandra".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "neo4j".into(), name: "Neo4j".into(), icon: "🕸️".into(), category: "Database".into(),
            description: "Graph database platform for connected data".into(),
            website: Some("https://neo4j.com".into()),
            docker: Some(DockerTarget { image: "neo4j:latest".into(), ports: vec!["7474:7474".into(), "7687:7687".into()], env: vec!["NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}".into()], volumes: vec!["neo4j_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "NEO4J_PASSWORD".into(), label: "Neo4j Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 8 characters".into()), options: vec![] },
            ],
        },
        AppManifest { id: "surrealdb".into(), name: "SurrealDB".into(), icon: "🚀".into(), category: "Database".into(),
            description: "Multi-model database — documents, graph, SQL, and real-time".into(),
            website: Some("https://surrealdb.com".into()),
            docker: Some(DockerTarget { image: "surrealdb/surrealdb:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["surrealdb_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "valkey".into(), name: "Valkey".into(), icon: "🔑".into(), category: "Database".into(),
            description: "Open-source Redis fork — high-performance key-value store".into(),
            website: Some("https://valkey.io".into()),
            docker: Some(DockerTarget { image: "valkey/valkey:latest".into(), ports: vec!["6379:6379".into()], env: vec![], volumes: vec!["valkey_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "keydb".into(), name: "KeyDB".into(), icon: "⚡".into(), category: "Database".into(),
            description: "Multi-threaded Redis-compatible database with active replication".into(),
            website: Some("https://docs.keydb.dev".into()),
            docker: Some(DockerTarget { image: "eqalpha/keydb:latest".into(), ports: vec!["6379:6379".into()], env: vec![], volumes: vec!["keydb_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "dragonfly".into(), name: "Dragonfly".into(), icon: "🐉".into(), category: "Database".into(),
            description: "Modern Redis/Memcached replacement — 25x faster".into(),
            website: Some("https://dragonflydb.io".into()),
            docker: Some(DockerTarget { image: "docker.dragonflydb.io/dragonflydb/dragonfly:latest".into(), ports: vec!["6379:6379".into()], env: vec![], volumes: vec!["dragonfly_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "questdb".into(), name: "QuestDB".into(), icon: "📈".into(), category: "Database".into(),
            description: "High-performance time series database with SQL".into(),
            website: Some("https://questdb.io".into()),
            docker: Some(DockerTarget { image: "questdb/questdb:latest".into(), ports: vec!["9000:9000".into(), "9009:9009".into(), "8812:8812".into()], env: vec![], volumes: vec!["questdb_data:/var/lib/questdb".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "timescaledb".into(), name: "TimescaleDB".into(), icon: "⏰".into(), category: "Database".into(),
            description: "PostgreSQL extension for time-series data at scale".into(),
            website: Some("https://www.timescale.com".into()),
            docker: Some(DockerTarget { image: "timescale/timescaledb:latest-pg15".into(), ports: vec!["5432:5432".into()], env: vec!["POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["timescaledb_data:/var/lib/postgresql/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "arangodb".into(), name: "ArangoDB".into(), icon: "🥑".into(), category: "Database".into(),
            description: "Multi-model database — documents, graphs, and key-value".into(),
            website: Some("https://arangodb.com".into()),
            docker: Some(DockerTarget { image: "arangodb:latest".into(), ports: vec!["8529:8529".into()], env: vec!["ARANGO_ROOT_PASSWORD=${ROOT_PASSWORD}".into()], volumes: vec!["arangodb_data:/var/lib/arangodb3".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ROOT_PASSWORD".into(), label: "Root Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("ArangoDB root password".into()), options: vec![] },
            ],
        },

        // ─── Networking (batch 2) ───

        AppManifest { id: "pihole-unbound".into(), name: "Pi-hole + Unbound".into(), icon: "🔒".into(), category: "Networking".into(),
            description: "Ad-blocking DNS with recursive DNS resolver for maximum privacy".into(),
            website: Some("https://pi-hole.net".into()),
            docker: Some(DockerTarget { image: "cbcrowe/pihole-unbound:latest".into(), ports: vec!["53:53/tcp".into(), "53:53/udp".into(), "8080:80".into()], env: vec!["WEBPASSWORD=${ADMIN_PASSWORD}".into(), "TZ=UTC".into()], volumes: vec!["pihole_unbound_etc:/etc/pihole".into(), "pihole_unbound_dns:/etc/dnsmasq.d".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Web Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Pi-hole admin password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "technitium".into(), name: "Technitium DNS".into(), icon: "🌐".into(), category: "Networking".into(),
            description: "Authoritative and recursive DNS server with ad blocking".into(),
            website: Some("https://technitium.com/dns/".into()),
            docker: Some(DockerTarget { image: "technitium/dns-server:latest".into(), ports: vec!["5380:5380".into(), "53:53/udp".into(), "53:53/tcp".into()], env: vec![], volumes: vec!["technitium_data:/etc/dns".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "ddclient".into(), name: "ddclient".into(), icon: "🔄".into(), category: "Networking".into(),
            description: "Dynamic DNS client for Cloudflare, Namecheap, DuckDNS, etc".into(),
            website: Some("https://ddclient.net".into()),
            docker: Some(DockerTarget { image: "linuxserver/ddclient:latest".into(), ports: vec![], env: vec!["PUID=1000".into(), "PGID=1000".into(), "TZ=UTC".into()], volumes: vec!["ddclient_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "duckdns".into(), name: "DuckDNS".into(), icon: "🦆".into(), category: "Networking".into(),
            description: "Free dynamic DNS — keep a domain pointed at your changing IP".into(),
            website: Some("https://www.duckdns.org".into()),
            docker: Some(DockerTarget { image: "linuxserver/duckdns:latest".into(), ports: vec![], env: vec!["SUBDOMAINS=${SUBDOMAIN}".into(), "TOKEN=${DUCKDNS_TOKEN}".into(), "TZ=UTC".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "SUBDOMAIN".into(), label: "Subdomain".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("Your DuckDNS subdomain".into()), options: vec![] },
                UserInput { id: "DUCKDNS_TOKEN".into(), label: "DuckDNS Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("From duckdns.org".into()), options: vec![] },
            ],
        },
        AppManifest { id: "caddy".into(), name: "Caddy".into(), icon: "🔒".into(), category: "Networking".into(),
            description: "Web server with automatic HTTPS via Let's Encrypt".into(),
            website: Some("https://caddyserver.com".into()),
            docker: Some(DockerTarget { image: "caddy:latest".into(), ports: vec!["80:80".into(), "443:443".into()], env: vec![], volumes: vec!["caddy_data:/data".into(), "caddy_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "haproxy".into(), name: "HAProxy".into(), icon: "⚖️".into(), category: "Networking".into(),
            description: "Reliable high-performance TCP/HTTP load balancer".into(),
            website: Some("https://www.haproxy.org".into()),
            docker: Some(DockerTarget { image: "haproxy:latest".into(), ports: vec!["80:80".into(), "443:443".into(), "8404:8404".into()], env: vec![], volumes: vec!["haproxy_config:/usr/local/etc/haproxy:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "ntopng".into(), name: "ntopng".into(), icon: "📡".into(), category: "Networking".into(),
            description: "Web-based network traffic monitoring and analysis".into(),
            website: Some("https://www.ntop.org".into()),
            docker: Some(DockerTarget { image: "ntop/ntopng:stable".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["ntopng_data:/var/lib/ntopng".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Security (batch 2) ───

        AppManifest { id: "fail2ban".into(), name: "Fail2ban".into(), icon: "🚫".into(), category: "Security".into(),
            description: "Intrusion prevention — bans IPs with too many failed login attempts".into(),
            website: Some("https://www.fail2ban.org".into()),
            docker: Some(DockerTarget { image: "crazymax/fail2ban:latest".into(), ports: vec![], env: vec!["TZ=UTC".into()], volumes: vec!["fail2ban_data:/data".into(), "/var/log:/var/log:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "clamav".into(), name: "ClamAV".into(), icon: "🦠".into(), category: "Security".into(),
            description: "Open-source antivirus engine for file scanning".into(),
            website: Some("https://www.clamav.net".into()),
            docker: Some(DockerTarget { image: "clamav/clamav:latest".into(), ports: vec!["3310:3310".into()], env: vec![], volumes: vec!["clamav_data:/var/lib/clamav".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "trivy".into(), name: "Trivy".into(), icon: "🔍".into(), category: "Security".into(),
            description: "Container and filesystem vulnerability scanner".into(),
            website: Some("https://trivy.dev".into()),
            docker: Some(DockerTarget { image: "aquasec/trivy:latest".into(), ports: vec![], env: vec![], volumes: vec!["trivy_cache:/root/.cache/trivy".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "defectdojo".into(), name: "DefectDojo".into(), icon: "🐛".into(), category: "Security".into(),
            description: "Application security management and vulnerability tracking".into(),
            website: Some("https://www.defectdojo.org".into()),
            docker: Some(DockerTarget { image: "defectdojo/defectdojo-django:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["defectdojo_data:/app/media".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "headscale".into(), name: "Headscale".into(), icon: "🐍".into(), category: "Security".into(),
            description: "Self-hosted Tailscale control server".into(),
            website: Some("https://github.com/juanfont/headscale".into()),
            docker: Some(DockerTarget { image: "headscale/headscale:latest".into(), ports: vec!["8080:8080".into(), "9090:9090".into()], env: vec![], volumes: vec!["headscale_data:/var/lib/headscale".into(), "headscale_config:/etc/headscale".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Monitoring (batch 2) ───

        AppManifest { id: "beszel".into(), name: "Beszel".into(), icon: "📊".into(), category: "Monitoring".into(),
            description: "Lightweight server monitoring with Docker stats and alerts".into(),
            website: Some("https://github.com/henrygd/beszel".into()),
            docker: Some(DockerTarget { image: "henrygd/beszel:latest".into(), ports: vec!["8090:8090".into()], env: vec![], volumes: vec!["beszel_data:/beszel_data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "dozzle".into(), name: "Dozzle".into(), icon: "🪵".into(), category: "Monitoring".into(),
            description: "Real-time Docker container log viewer in the browser".into(),
            website: Some("https://dozzle.dev".into()),
            docker: Some(DockerTarget { image: "amir20/dozzle:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["/var/run/docker.sock:/var/run/docker.sock:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "watchtower".into(), name: "Watchtower".into(), icon: "🗼".into(), category: "Monitoring".into(),
            description: "Automatically update running Docker containers to latest images".into(),
            website: Some("https://containrrr.dev/watchtower/".into()),
            docker: Some(DockerTarget { image: "containrrr/watchtower:latest".into(), ports: vec![], env: vec!["WATCHTOWER_CLEANUP=true".into(), "WATCHTOWER_SCHEDULE=0 0 4 * * *".into()], volumes: vec!["/var/run/docker.sock:/var/run/docker.sock".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "diun".into(), name: "Diun".into(), icon: "🔔".into(), category: "Monitoring".into(),
            description: "Docker image update notifier — alerts when images have updates".into(),
            website: Some("https://crazymax.dev/diun/".into()),
            docker: Some(DockerTarget { image: "crazymax/diun:latest".into(), ports: vec![], env: vec!["LOG_LEVEL=info".into(), "LOG_JSON=false".into()], volumes: vec!["diun_data:/data".into(), "/var/run/docker.sock:/var/run/docker.sock:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "scrutiny".into(), name: "Scrutiny".into(), icon: "💽".into(), category: "Monitoring".into(),
            description: "Hard drive S.M.A.R.T. monitoring with web dashboard".into(),
            website: Some("https://github.com/AnalogJ/scrutiny".into()),
            docker: Some(DockerTarget { image: "ghcr.io/analogj/scrutiny:master-omnibus".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["scrutiny_config:/opt/scrutiny/config".into(), "scrutiny_db:/opt/scrutiny/influxdb".into(), "/run/udev:/run/udev:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "monitoror".into(), name: "Monitoror".into(), icon: "📺".into(), category: "Monitoring".into(),
            description: "Unified monitoring wallboard — CI, HTTP, port checks on a TV dashboard".into(),
            website: Some("https://monitoror.com".into()),
            docker: Some(DockerTarget { image: "monitoror/monitoror:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["monitoror_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Automation (batch 2) ───

        AppManifest { id: "activepieces".into(), name: "Activepieces".into(), icon: "🧩".into(), category: "Automation".into(),
            description: "No-code automation — Zapier alternative with 200+ integrations".into(),
            website: Some("https://www.activepieces.com".into()),
            docker: Some(DockerTarget { image: "activepieces/activepieces:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["activepieces_data:/root/.activepieces".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "windmill".into(), name: "Windmill".into(), icon: "🌀".into(), category: "Automation".into(),
            description: "Developer-first workflow engine — scripts, flows, and apps".into(),
            website: Some("https://windmill.dev".into()),
            docker: Some(DockerTarget { image: "ghcr.io/windmill-labs/windmill:main".into(), ports: vec!["8000:8000".into()], env: vec!["DATABASE_URL=postgres://postgres:${DB_PASSWORD}@windmill-db/windmill".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=windmill".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["windmill_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "automatisch".into(), name: "Automatisch".into(), icon: "⚙️".into(), category: "Automation".into(),
            description: "Open-source Zapier alternative — connect apps and automate workflows".into(),
            website: Some("https://automatisch.io".into()),
            docker: Some(DockerTarget { image: "automatischio/automatisch:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["automatisch_data:/automatisch/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Communication (batch 2) ───

        AppManifest { id: "revolt".into(), name: "Revolt".into(), icon: "💬".into(), category: "Communication".into(),
            description: "User-first chat platform — Discord alternative".into(),
            website: Some("https://revolt.chat".into()),
            docker: Some(DockerTarget { image: "ghcr.io/revoltchat/server:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["revolt_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "mumble".into(), name: "Mumble Server".into(), icon: "🎙️".into(), category: "Communication".into(),
            description: "Low-latency voice chat for gaming and teams".into(),
            website: Some("https://www.mumble.info".into()),
            docker: Some(DockerTarget { image: "mumblevoip/mumble-server:latest".into(), ports: vec!["64738:64738".into(), "64738:64738/udp".into()], env: vec!["MUMBLE_SUPERUSER_PASSWORD=${ADMIN_PASSWORD}".into()], volumes: vec!["mumble_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "SuperUser Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Server admin password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "teamspeak".into(), name: "TeamSpeak".into(), icon: "🎧".into(), category: "Communication".into(),
            description: "Voice communication for gaming and professional use".into(),
            website: Some("https://teamspeak.com".into()),
            docker: Some(DockerTarget { image: "teamspeak:latest".into(), ports: vec!["9987:9987/udp".into(), "10011:10011".into(), "30033:30033".into()], env: vec!["TS3SERVER_LICENSE=accept".into()], volumes: vec!["teamspeak_data:/var/ts3server".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "typebot".into(), name: "Typebot".into(), icon: "🤖".into(), category: "Communication".into(),
            description: "Conversational forms and chatbot builder".into(),
            website: Some("https://typebot.io".into()),
            docker: Some(DockerTarget { image: "baptistearno/typebot-builder:latest".into(), ports: vec!["3000:3000".into()], env: vec!["NEXTAUTH_URL=http://localhost:3000".into(), "DATABASE_URL=file:/data/typebot.db".into()], volumes: vec!["typebot_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── CMS (batch 2) ───

        AppManifest { id: "wagtail".into(), name: "Wagtail".into(), icon: "🐦".into(), category: "CMS".into(),
            description: "Django-based CMS used by Google, NASA, and Mozilla".into(),
            website: Some("https://wagtail.org".into()),
            docker: Some(DockerTarget { image: "wagtail/wagtail:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["wagtail_data:/app/media".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "grav".into(), name: "Grav".into(), icon: "🚀".into(), category: "CMS".into(),
            description: "Modern flat-file CMS — no database required".into(),
            website: Some("https://getgrav.org".into()),
            docker: Some(DockerTarget { image: "linuxserver/grav:latest".into(), ports: vec!["8080:80".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["grav_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "keystone".into(), name: "KeystoneJS".into(), icon: "🔑".into(), category: "CMS".into(),
            description: "Programmable headless CMS and GraphQL API built with TypeScript".into(),
            website: Some("https://keystonejs.com".into()),
            docker: Some(DockerTarget { image: "keystonejs/keystone:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["keystone_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Web (batch 2) ───

        AppManifest { id: "apache".into(), name: "Apache HTTP Server".into(), icon: "🪶".into(), category: "Web".into(),
            description: "The world's most popular open-source web server".into(),
            website: Some("https://httpd.apache.org".into()),
            docker: Some(DockerTarget { image: "httpd:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["apache_htdocs:/usr/local/apache2/htdocs".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "lighttpd".into(), name: "lighttpd".into(), icon: "💡".into(), category: "Web".into(),
            description: "Fast and lightweight web server optimised for speed".into(),
            website: Some("https://www.lighttpd.net".into()),
            docker: Some(DockerTarget { image: "sebp/lighttpd:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["lighttpd_htdocs:/var/www/localhost/htdocs".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "staticweb".into(), name: "Static Web Server".into(), icon: "📄".into(), category: "Web".into(),
            description: "Blazing fast static file server written in Rust".into(),
            website: Some("https://static-web-server.net".into()),
            docker: Some(DockerTarget { image: "joseluisq/static-web-server:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["${WEB_ROOT}:/public:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "WEB_ROOT".into(), label: "Web Root".into(), input_type: "text".into(), default: Some("/opt/www".into()), required: true, placeholder: Some("Path to serve".into()), options: vec![] },
            ],
        },

        // ─── Privacy (batch 2) ───

        AppManifest { id: "whoogle".into(), name: "Whoogle".into(), icon: "🔍".into(), category: "Privacy".into(),
            description: "Google search results without ads, JavaScript, or tracking".into(),
            website: Some("https://github.com/benbusby/whoogle-search".into()),
            docker: Some(DockerTarget { image: "benbusby/whoogle-search:latest".into(), ports: vec!["5000:5000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "librex".into(), name: "LibreX".into(), icon: "🔎".into(), category: "Privacy".into(),
            description: "Privacy-respecting meta search engine".into(),
            website: Some("https://github.com/hnhx/librex".into()),
            docker: Some(DockerTarget { image: "librex/librex:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "nitter".into(), name: "Nitter".into(), icon: "🐦".into(), category: "Privacy".into(),
            description: "Privacy-friendly Twitter/X frontend — no JavaScript or tracking".into(),
            website: Some("https://github.com/zedeus/nitter".into()),
            docker: Some(DockerTarget { image: "zedeus/nitter:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "teddit".into(), name: "Teddit".into(), icon: "🔶".into(), category: "Privacy".into(),
            description: "Privacy-focused Reddit frontend with minimal JavaScript".into(),
            website: Some("https://codeberg.org/teddit/teddit".into()),
            docker: Some(DockerTarget { image: "teddit/teddit:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "rimgo".into(), name: "Rimgo".into(), icon: "🖼️".into(), category: "Privacy".into(),
            description: "Privacy-friendly Imgur frontend".into(),
            website: Some("https://codeberg.org/video-hierarchie/rimgo".into()),
            docker: Some(DockerTarget { image: "codeberg.org/video-hierarchie/rimgo:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── AI / ML (batch 2) ───

        AppManifest { id: "text-gen-webui".into(), name: "Text Generation WebUI".into(), icon: "💬".into(), category: "AI / ML".into(),
            description: "Web UI for running large language models locally (oobabooga)".into(),
            website: Some("https://github.com/oobabooga/text-generation-webui".into()),
            docker: Some(DockerTarget { image: "atinoda/text-generation-webui:default-cpu".into(), ports: vec!["7860:7860".into(), "5000:5000".into()], env: vec![], volumes: vec!["textgen_models:/app/models".into(), "textgen_loras:/app/loras".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "jan".into(), name: "Jan".into(), icon: "🧠".into(), category: "AI / ML".into(),
            description: "Run AI models offline — ChatGPT alternative that runs locally".into(),
            website: Some("https://jan.ai".into()),
            docker: Some(DockerTarget { image: "ghcr.io/janhq/jan:latest".into(), ports: vec!["1337:1337".into()], env: vec![], volumes: vec!["jan_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "langflow".into(), name: "Langflow".into(), icon: "🔗".into(), category: "AI / ML".into(),
            description: "Visual framework for building multi-agent AI applications".into(),
            website: Some("https://langflow.org".into()),
            docker: Some(DockerTarget { image: "langflowai/langflow:latest".into(), ports: vec!["7860:7860".into()], env: vec![], volumes: vec!["langflow_data:/app/langflow".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "anything-llm".into(), name: "AnythingLLM".into(), icon: "🤖".into(), category: "AI / ML".into(),
            description: "All-in-one AI app — chat with documents, use any LLM".into(),
            website: Some("https://anythingllm.com".into()),
            docker: Some(DockerTarget { image: "mintplexlabs/anythingllm:latest".into(), ports: vec!["3001:3001".into()], env: vec![], volumes: vec!["anythingllm_data:/app/server/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Other / Utility ───

        AppManifest { id: "homepage".into(), name: "Homepage".into(), icon: "🏠".into(), category: "Other".into(),
            description: "Modern application dashboard with service integrations".into(),
            website: Some("https://gethomepage.dev".into()),
            docker: Some(DockerTarget { image: "ghcr.io/gethomepage/homepage:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["homepage_config:/app/config".into(), "/var/run/docker.sock:/var/run/docker.sock:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "homarr".into(), name: "Homarr".into(), icon: "🏡".into(), category: "Other".into(),
            description: "Customisable dashboard for your server with drag-and-drop widgets".into(),
            website: Some("https://homarr.dev".into()),
            docker: Some(DockerTarget { image: "ghcr.io/ajnart/homarr:latest".into(), ports: vec!["7575:7575".into()], env: vec![], volumes: vec!["homarr_config:/app/data/configs".into(), "homarr_icons:/app/public/icons".into(), "/var/run/docker.sock:/var/run/docker.sock:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "dashy".into(), name: "Dashy".into(), icon: "🚀".into(), category: "Other".into(),
            description: "Feature-rich personal dashboard with themes and widgets".into(),
            website: Some("https://dashy.to".into()),
            docker: Some(DockerTarget { image: "lissy93/dashy:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["dashy_config:/app/user-data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "flame".into(), name: "Flame".into(), icon: "🔥".into(), category: "Other".into(),
            description: "Self-hosted start page for your server with bookmarks and apps".into(),
            website: Some("https://github.com/pawelmalak/flame".into()),
            docker: Some(DockerTarget { image: "pawelmalak/flame:latest".into(), ports: vec!["5005:5005".into()], env: vec![], volumes: vec!["flame_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "linkding".into(), name: "Linkding".into(), icon: "🔗".into(), category: "Other".into(),
            description: "Minimal bookmark manager with tags and full-text search".into(),
            website: Some("https://github.com/sissbruecker/linkding".into()),
            docker: Some(DockerTarget { image: "sissbruecker/linkding:latest".into(), ports: vec!["9090:9090".into()], env: vec![], volumes: vec!["linkding_data:/etc/linkding/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "cyberchef".into(), name: "CyberChef".into(), icon: "🧑‍🍳".into(), category: "Other".into(),
            description: "The Cyber Swiss Army Knife — encode, decode, encrypt, compress".into(),
            website: Some("https://github.com/gchq/CyberChef".into()),
            docker: Some(DockerTarget { image: "mpepping/cyberchef:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "snapdrop".into(), name: "Snapdrop".into(), icon: "📲".into(), category: "Other".into(),
            description: "Local file sharing in the browser — AirDrop for any device".into(),
            website: Some("https://snapdrop.net".into()),
            docker: Some(DockerTarget { image: "linuxserver/snapdrop:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "pairdrop".into(), name: "PairDrop".into(), icon: "📤".into(), category: "Other".into(),
            description: "Local file sharing — Snapdrop successor with rooms and pairing".into(),
            website: Some("https://pairdrop.net".into()),
            docker: Some(DockerTarget { image: "linuxserver/pairdrop:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "send".into(), name: "Send".into(), icon: "📨".into(), category: "Other".into(),
            description: "End-to-end encrypted file sharing — Firefox Send fork".into(),
            website: Some("https://github.com/timvisee/send".into()),
            docker: Some(DockerTarget { image: "registry.gitlab.com/timvisee/send:latest".into(), ports: vec!["1443:1443".into()], env: vec![], volumes: vec!["send_uploads:/uploads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "privatebin".into(), name: "PrivateBin".into(), icon: "📋".into(), category: "Other".into(),
            description: "Zero-knowledge encrypted pastebin".into(),
            website: Some("https://privatebin.info".into()),
            docker: Some(DockerTarget { image: "privatebin/nginx-fpm-alpine:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["privatebin_data:/srv/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "rustdesk".into(), name: "RustDesk Server".into(), icon: "🖥️".into(), category: "Other".into(),
            description: "Self-hosted remote desktop — TeamViewer/AnyDesk alternative".into(),
            website: Some("https://rustdesk.com".into()),
            docker: Some(DockerTarget { image: "rustdesk/rustdesk-server:latest".into(), ports: vec!["21115:21115".into(), "21116:21116".into(), "21116:21116/udp".into(), "21117:21117".into(), "21118:21118".into(), "21119:21119".into()], env: vec![], volumes: vec!["rustdesk_data:/root".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "meshcentral".into(), name: "MeshCentral".into(), icon: "🌐".into(), category: "Other".into(),
            description: "Full computer management — remote desktop, file transfer, terminal".into(),
            website: Some("https://meshcentral.com".into()),
            docker: Some(DockerTarget { image: "ghcr.io/ylianst/meshcentral:latest".into(), ports: vec!["8086:443".into()], env: vec![], volumes: vec!["meshcentral_data:/opt/meshcentral/meshcentral-data".into(), "meshcentral_files:/opt/meshcentral/meshcentral-files".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "guacamole".into(), name: "Apache Guacamole".into(), icon: "🥑".into(), category: "Other".into(),
            // The upstream guacamole/guacamole image is a Tomcat webapp
            // with no bundled auth backend — it has no login screen at
            // all unless you wire it up to a Postgres/MySQL DB with the
            // schema pre-loaded and GUACAMOLE_HOME configured. The
            // previous manifest paired it with a bare guacd sidecar and
            // no DB, so every install was dead on arrival.
            // jasonbean/guacamole bundles guacd + PostgreSQL + schema
            // into one container — the right shape for a one-click
            // app-store install. Default credentials: guacadmin /
            // guacadmin (change on first login).
            description: "Clientless remote desktop gateway — RDP, VNC, SSH in the browser. Default login: guacadmin / guacadmin".into(),
            website: Some("https://guacamole.apache.org".into()),
            docker: Some(DockerTarget { image: "jasonbean/guacamole:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["guacamole_data:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Gaming (batch 2) ───

        AppManifest { id: "crafty".into(), name: "Crafty Controller".into(), icon: "⛏️".into(), category: "Gaming".into(),
            description: "Minecraft server manager — multiple servers, backups, scheduling".into(),
            website: Some("https://craftycontrol.com".into()),
            docker: Some(DockerTarget { image: "registry.gitlab.com/crafty-controller/crafty-4:latest".into(), ports: vec!["8443:8443".into(), "25565:25565".into()], env: vec![], volumes: vec!["crafty_data:/crafty/data".into(), "crafty_servers:/crafty/servers".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "pterodactyl".into(), name: "Pterodactyl Panel".into(), icon: "🦖".into(), category: "Gaming".into(),
            description: "Game server management panel — Minecraft, CS2, Rust, ARK, and more".into(),
            website: Some("https://pterodactyl.io".into()),
            docker: Some(DockerTarget { image: "ghcr.io/pterodactyl/panel:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["pterodactyl_data:/app/var".into(), "pterodactyl_nginx:/etc/nginx/http.d".into(), "pterodactyl_logs:/app/storage/logs".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "pelican".into(), name: "Pelican Panel".into(), icon: "🐦".into(), category: "Gaming".into(),
            description: "Next-gen game server management — Pterodactyl successor".into(),
            website: Some("https://pelican.dev".into()),
            docker: Some(DockerTarget { image: "ghcr.io/pelican-dev/panel:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["pelican_data:/app/var".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "linuxgsm".into(), name: "LinuxGSM".into(), icon: "🎮".into(), category: "Gaming".into(),
            description: "Command-line tool for managing game servers — 120+ games".into(),
            website: Some("https://linuxgsm.com".into()),
            docker: Some(DockerTarget { image: "gameservermanagers/linuxgsm-docker:latest".into(), ports: vec!["27015:27015".into(), "27015:27015/udp".into()], env: vec!["GAMESERVER=${GAME}".into()], volumes: vec!["linuxgsm_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "GAME".into(), label: "Game Server".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. csgoserver, rustserver".into()), options: vec![] },
            ],
        },
        AppManifest { id: "enshrouded".into(), name: "Enshrouded".into(), icon: "⚔️".into(), category: "Gaming".into(),
            description: "Enshrouded dedicated server — survival action RPG".into(),
            website: Some("https://enshrouded.com".into()),
            docker: Some(DockerTarget { image: "sknnr/enshrouded-dedicated-server:latest".into(), ports: vec!["15636:15636/udp".into(), "15637:15637/udp".into()], env: vec!["SERVER_NAME=${SERVER_NAME}".into(), "SERVER_PASSWORD=${SERVER_PASS}".into()], volumes: vec!["enshrouded_data:/home/steam/enshrouded".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("Enshrouded Server".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "SERVER_PASS".into(), label: "Server Password".into(), input_type: "password".into(), default: None, required: false, placeholder: Some("Leave blank for no password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "vrising".into(), name: "V Rising".into(), icon: "🧛".into(), category: "Gaming".into(),
            description: "V Rising dedicated server — vampire survival game".into(),
            website: Some("https://playvrising.com".into()),
            docker: Some(DockerTarget { image: "trueosiris/vrising:latest".into(), ports: vec!["9876:9876/udp".into(), "9877:9877/udp".into()], env: vec!["SERVER_NAME=${SERVER_NAME}".into()], volumes: vec!["vrising_data:/mnt/vrising/server".into(), "vrising_saves:/mnt/vrising/persistentdata".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "SERVER_NAME".into(), label: "Server Name".into(), input_type: "text".into(), default: Some("V Rising Server".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "vintage-story".into(), name: "Vintage Story".into(), icon: "🏕️".into(), category: "Gaming".into(),
            description: "Vintage Story dedicated server — sandbox survival crafting".into(),
            website: Some("https://www.vintagestory.at".into()),
            docker: Some(DockerTarget { image: "devidian/vintagestory:latest".into(), ports: vec!["42420:42420".into()], env: vec![], volumes: vec!["vintagestory_data:/gamedata".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "corekeeper".into(), name: "Core Keeper".into(), icon: "⛏️".into(), category: "Gaming".into(),
            description: "Core Keeper dedicated server — underground survival mining".into(),
            website: Some("https://www.pugstorm.com/corekeeper".into()),
            docker: Some(DockerTarget { image: "escaping/core-keeper-dedicated:latest".into(), ports: vec![], env: vec!["WORLD_NAME=${WORLD_NAME}".into()], volumes: vec!["corekeeper_data:/home/steam/core-keeper-dedicated".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "WORLD_NAME".into(), label: "World Name".into(), input_type: "text".into(), default: Some("Core Keeper World".into()), required: true, placeholder: None, options: vec![] },
            ],
        },

        // ─── Container Orchestration ───

        AppManifest { id: "rancher".into(), name: "Rancher".into(), icon: "🐄".into(), category: "Container Orchestration".into(),
            description: "Multi-cluster Kubernetes management platform".into(),
            website: Some("https://rancher.com".into()),
            docker: Some(DockerTarget { image: "rancher/rancher:latest".into(), ports: vec!["8443:443".into()], env: vec![], volumes: vec!["rancher_data:/var/lib/rancher".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "k3s".into(), name: "K3s".into(), icon: "⚓".into(), category: "Container Orchestration".into(),
            description: "Lightweight Kubernetes distribution for edge and IoT".into(),
            website: Some("https://k3s.io".into()),
            docker: Some(DockerTarget { image: "rancher/k3s:latest".into(), ports: vec!["6443:6443".into(), "8080:80".into(), "8443:443".into()], env: vec![], volumes: vec!["k3s_data:/var/lib/rancher/k3s".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── PaaS ───

        AppManifest { id: "kubero".into(), name: "Kubero".into(), icon: "🐙".into(), category: "PaaS".into(),
            description: "Heroku-like PaaS for Kubernetes — git push to deploy".into(),
            website: Some("https://www.kubero.dev".into()),
            docker: Some(DockerTarget { image: "ghcr.io/kubero-dev/kubero:latest".into(), ports: vec!["2000:2000".into()], env: vec![], volumes: vec!["kubero_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Additional utility apps ───

        AppManifest { id: "homer".into(), name: "Homer".into(), icon: "🏠".into(), category: "Other".into(),
            description: "Dead simple static dashboard generated from YAML config".into(),
            website: Some("https://github.com/bastienwirtz/homer".into()),
            docker: Some(DockerTarget { image: "b4bz/homer:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["homer_assets:/www/assets".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "organizr".into(), name: "Organizr".into(), icon: "📱".into(), category: "Other".into(),
            description: "HTPC/homelab organisation dashboard with tab integration".into(),
            website: Some("https://organizr.app".into()),
            docker: Some(DockerTarget { image: "organizr/organizr:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["organizr_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "tasks-md".into(), name: "tasks.md".into(), icon: "✅".into(), category: "Productivity".into(),
            description: "Markdown-based task board with drag and drop".into(),
            website: Some("https://github.com/BaldissaraMatworkhub/tasks.md".into()),
            docker: Some(DockerTarget { image: "baldissaramatworkhub/tasks.md:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["tasksmd_data:/tasks".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "traggo".into(), name: "Traggo".into(), icon: "⏲️".into(), category: "Productivity".into(),
            description: "Tag-based time tracking with calendar and dashboard".into(),
            website: Some("https://traggo.net".into()),
            docker: Some(DockerTarget { image: "traggo/server:latest".into(), ports: vec!["3030:3030".into()], env: vec!["TRAGGO_DEFAULT_USER_NAME=admin".into(), "TRAGGO_DEFAULT_USER_PASS=${ADMIN_PASSWORD}".into()], volumes: vec!["traggo_data:/opt/traggo/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Admin password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "kopia".into(), name: "Kopia".into(), icon: "📦".into(), category: "Other".into(),
            description: "Fast and encrypted backup tool with deduplication and web UI".into(),
            website: Some("https://kopia.io".into()),
            docker: Some(DockerTarget { image: "kopia/kopia:latest".into(), ports: vec!["51515:51515".into()], env: vec!["KOPIA_PASSWORD=${REPO_PASSWORD}".into()], volumes: vec!["kopia_config:/app/config".into(), "kopia_cache:/app/cache".into(), "kopia_logs:/app/logs".into(), "${BACKUP_SOURCE}:/data:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "REPO_PASSWORD".into(), label: "Repository Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Encryption password for backup repo".into()), options: vec![] },
                UserInput { id: "BACKUP_SOURCE".into(), label: "Backup Source".into(), input_type: "text".into(), default: Some("/".into()), required: true, placeholder: Some("Path to back up".into()), options: vec![] },
            ],
        },
        AppManifest { id: "restic-rest".into(), name: "Restic REST Server".into(), icon: "💾".into(), category: "Other".into(),
            description: "Backend server for Restic backups with web UI".into(),
            website: Some("https://restic.net".into()),
            docker: Some(DockerTarget { image: "restic/rest-server:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["restic_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "browserless".into(), name: "Browserless".into(), icon: "🌐".into(), category: "Dev Tools".into(),
            description: "Headless Chrome as a service — screenshots, PDFs, scraping".into(),
            website: Some("https://browserless.io".into()),
            docker: Some(DockerTarget { image: "browserless/chrome:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "memos".into(), name: "Memos".into(), icon: "📝".into(), category: "Productivity".into(),
            description: "Privacy-first lightweight note-taking service".into(),
            website: Some("https://usememos.com".into()),
            docker: Some(DockerTarget { image: "neosmemo/memos:stable".into(), ports: vec!["5230:5230".into()], env: vec![], volumes: vec!["memos_data:/var/opt/memos".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "flatnotes".into(), name: "Flatnotes".into(), icon: "📒".into(), category: "Productivity".into(),
            description: "Flat-file note taking with full text search and tagging".into(),
            website: Some("https://github.com/dullage/flatnotes".into()),
            docker: Some(DockerTarget { image: "dullage/flatnotes:latest".into(), ports: vec!["8080:8080".into()], env: vec!["FLATNOTES_AUTH_TYPE=password".into(), "FLATNOTES_USERNAME=admin".into(), "FLATNOTES_PASSWORD=${ADMIN_PASSWORD}".into()], volumes: vec!["flatnotes_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Login password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "bentos".into(), name: "Bento".into(), icon: "🍱".into(), category: "Other".into(),
            description: "Customisable link-in-bio page for your socials".into(),
            website: Some("https://github.com/migueravila/Bento".into()),
            docker: Some(DockerTarget { image: "lewisdoesstuff/bento:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "littlelink".into(), name: "LittleLink".into(), icon: "🔗".into(), category: "Other".into(),
            description: "Self-hosted Linktree alternative — link page for your socials".into(),
            website: Some("https://littlelink.io".into()),
            docker: Some(DockerTarget { image: "ghcr.io/techno-tim/littlelink-server:latest".into(), ports: vec!["8080:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "yourls".into(), name: "YOURLS".into(), icon: "🔗".into(), category: "Other".into(),
            description: "Your Own URL Shortener — track clicks and analytics".into(),
            website: Some("https://yourls.org".into()),
            docker: Some(DockerTarget { image: "yourls:latest".into(), ports: vec!["8080:80".into()], env: vec!["YOURLS_DB_HOST=yourls-db".into(), "YOURLS_DB_PASS=${DB_PASSWORD}".into(), "YOURLS_SITE=http://localhost:8080".into(), "YOURLS_USER=admin".into(), "YOURLS_PASS=${ADMIN_PASSWORD}".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "mariadb:10".into(), ports: vec![], env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=yourls".into()], volumes: vec!["yourls_db:/var/lib/mysql".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("YOURLS admin password".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "shlink".into(), name: "Shlink".into(), icon: "🔗".into(), category: "Other".into(),
            description: "URL shortener with REST API, QR codes, and visit tracking".into(),
            website: Some("https://shlink.io".into()),
            docker: Some(DockerTarget { image: "shlinkio/shlink:stable".into(), ports: vec!["8080:8080".into()], env: vec!["DEFAULT_DOMAIN=localhost:8080".into(), "IS_HTTPS_ENABLED=false".into()], volumes: vec!["shlink_data:/etc/shlink/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "lldap".into(), name: "LLDAP".into(), icon: "👥".into(), category: "Security".into(),
            description: "Light LDAP server for authentication — simple admin panel".into(),
            website: Some("https://github.com/lldap/lldap".into()),
            docker: Some(DockerTarget { image: "lldap/lldap:latest".into(), ports: vec!["3890:3890".into(), "17170:17170".into()], env: vec!["LLDAP_LDAP_BASE_DN=dc=example,dc=com".into(), "LLDAP_JWT_SECRET=${JWT_SECRET}".into()], volumes: vec!["lldap_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "JWT_SECRET".into(), label: "JWT Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
            ],
        },
        AppManifest { id: "vault".into(), name: "HashiCorp Vault".into(), icon: "🔐".into(), category: "Security".into(),
            description: "Secrets management, encryption, and identity-based access".into(),
            website: Some("https://www.vaultproject.io".into()),
            docker: Some(DockerTarget { image: "hashicorp/vault:latest".into(), ports: vec!["8200:8200".into()], env: vec!["VAULT_DEV_ROOT_TOKEN_ID=${ROOT_TOKEN}".into()], volumes: vec!["vault_data:/vault/file".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ROOT_TOKEN".into(), label: "Root Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Dev mode root token".into()), options: vec![] },
            ],
        },
        AppManifest { id: "step-ca".into(), name: "Smallstep CA".into(), icon: "🔏".into(), category: "Security".into(),
            description: "Private certificate authority for TLS, SSH, and mTLS".into(),
            website: Some("https://smallstep.com".into()),
            docker: Some(DockerTarget { image: "smallstep/step-ca:latest".into(), ports: vec!["9000:9000".into()], env: vec![], volumes: vec!["step_ca_data:/home/step".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },


        // ═══════════════════════════════════════════════════════════════
        // Batch 3 — fill to 500
        // ═══════════════════════════════════════════════════════════════

        // ─── Media (batch 3) ───

        AppManifest { id: "owncast".into(), name: "Owncast".into(), icon: "📡".into(), category: "Media".into(),
            description: "Self-hosted live streaming server — Twitch alternative".into(),
            website: Some("https://owncast.online".into()),
            docker: Some(DockerTarget { image: "owncast/owncast:latest".into(), ports: vec!["8080:8080".into(), "1935:1935".into()], env: vec![], volumes: vec!["owncast_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "peertube".into(), name: "PeerTube".into(), icon: "▶️".into(), category: "Media".into(),
            description: "Decentralised video hosting — YouTube alternative".into(),
            website: Some("https://joinpeertube.org".into()),
            docker: Some(DockerTarget { image: "chocobozzz/peertube:production-bookworm".into(), ports: vec!["9000:9000".into()], env: vec!["PEERTUBE_DB_HOSTNAME=peertube-db".into(), "PEERTUBE_DB_USERNAME=peertube".into(), "PEERTUBE_DB_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["peertube_data:/data".into(), "peertube_config:/config".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=peertube".into(), "POSTGRES_USER=peertube".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["peertube_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "medusa".into(), name: "Medusa".into(), icon: "📺".into(), category: "Media".into(),
            description: "Automatic video library manager for TV shows".into(),
            website: Some("https://pymedusa.com".into()),
            docker: Some(DockerTarget { image: "linuxserver/medusa:latest".into(), ports: vec!["8081:8081".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["medusa_config:/config".into(), "${MEDIA_PATH}:/tv".into(), "${DOWNLOAD_PATH}:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "MEDIA_PATH".into(), label: "TV Path".into(), input_type: "text".into(), default: Some("/opt/media/tv".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "sabnzbd".into(), name: "SABnzbd".into(), icon: "📥".into(), category: "Media".into(),
            description: "Usenet binary newsreader with web interface".into(),
            website: Some("https://sabnzbd.org".into()),
            docker: Some(DockerTarget { image: "linuxserver/sabnzbd:latest".into(), ports: vec!["8080:8080".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["sabnzbd_config:/config".into(), "${DOWNLOAD_PATH}:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "transmission".into(), name: "Transmission".into(), icon: "🔽".into(), category: "Media".into(),
            description: "Lightweight BitTorrent client with web interface".into(),
            website: Some("https://transmissionbt.com".into()),
            docker: Some(DockerTarget { image: "linuxserver/transmission:latest".into(), ports: vec!["9091:9091".into(), "51413:51413".into(), "51413:51413/udp".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["transmission_config:/config".into(), "${DOWNLOAD_PATH}:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "qbittorrent".into(), name: "qBittorrent".into(), icon: "🔽".into(), category: "Media".into(),
            description: "Feature-rich BitTorrent client with web UI".into(),
            website: Some("https://www.qbittorrent.org".into()),
            docker: Some(DockerTarget { image: "linuxserver/qbittorrent:latest".into(), ports: vec!["8080:8080".into(), "6881:6881".into(), "6881:6881/udp".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["qbittorrent_config:/config".into(), "${DOWNLOAD_PATH}:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "jackett".into(), name: "Jackett".into(), icon: "🧥".into(), category: "Media".into(),
            description: "API proxy for torrent indexers — works with Sonarr, Radarr".into(),
            website: Some("https://github.com/Jackett/Jackett".into()),
            docker: Some(DockerTarget { image: "linuxserver/jackett:latest".into(), ports: vec!["9117:9117".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["jackett_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "flaresolverr".into(), name: "FlareSolverr".into(), icon: "☁️".into(), category: "Media".into(),
            description: "Proxy to bypass Cloudflare protection for indexers".into(),
            website: Some("https://github.com/FlareSolverr/FlareSolverr".into()),
            docker: Some(DockerTarget { image: "ghcr.io/flaresolverr/flaresolverr:latest".into(), ports: vec!["8191:8191".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "requestrr".into(), name: "Requestrr".into(), icon: "🤖".into(), category: "Media".into(),
            description: "Discord chatbot for requesting movies and TV via Sonarr/Radarr".into(),
            website: Some("https://github.com/darkalfx/requestrr".into()),
            docker: Some(DockerTarget { image: "darkalfx/requestrr:latest".into(), ports: vec!["4545:4545".into()], env: vec![], volumes: vec!["requestrr_config:/root/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Productivity (batch 3) ───

        AppManifest { id: "papermerge".into(), name: "Papermerge".into(), icon: "📄".into(), category: "Productivity".into(),
            description: "Document management with OCR — digitise your paper documents".into(),
            website: Some("https://papermerge.com".into()),
            docker: Some(DockerTarget { image: "papermerge/papermerge:latest".into(), ports: vec!["12000:80".into()], env: vec![], volumes: vec!["papermerge_data:/var/media".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "drawio".into(), name: "draw.io".into(), icon: "📐".into(), category: "Productivity".into(),
            description: "Diagram editor for flowcharts, UML, network diagrams, and more".into(),
            website: Some("https://www.drawio.com".into()),
            docker: Some(DockerTarget { image: "jgraph/drawio:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "etherpad".into(), name: "Etherpad".into(), icon: "📝".into(), category: "Productivity".into(),
            description: "Real-time collaborative text editor — Google Docs alternative".into(),
            website: Some("https://etherpad.org".into()),
            docker: Some(DockerTarget { image: "etherpad/etherpad:latest".into(), ports: vec!["9001:9001".into()], env: vec![], volumes: vec!["etherpad_data:/opt/etherpad-lite/var".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "weblate".into(), name: "Weblate".into(), icon: "🌍".into(), category: "Productivity".into(),
            description: "Web-based translation management with version control".into(),
            website: Some("https://weblate.org".into()),
            docker: Some(DockerTarget { image: "weblate/weblate:latest".into(), ports: vec!["8080:8080".into()], env: vec!["WEBLATE_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(), "POSTGRES_HOST=weblate-db".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["weblate_data:/app/data".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["weblate_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Weblate admin password".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },

        // ─── Dev Tools (batch 3) ───

        AppManifest { id: "harbor".into(), name: "Harbor".into(), icon: "⚓".into(), category: "Dev Tools".into(),
            description: "Enterprise container registry with vulnerability scanning".into(),
            website: Some("https://goharbor.io".into()),
            docker: Some(DockerTarget { image: "goharbor/harbor-core:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["harbor_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "nexus".into(), name: "Sonatype Nexus".into(), icon: "📦".into(), category: "Dev Tools".into(),
            description: "Repository manager for Maven, npm, Docker, PyPI, and more".into(),
            website: Some("https://www.sonatype.com/products/sonatype-nexus-repository".into()),
            docker: Some(DockerTarget { image: "sonatype/nexus3:latest".into(), ports: vec!["8081:8081".into()], env: vec![], volumes: vec!["nexus_data:/nexus-data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "minio-console".into(), name: "MinIO Console".into(), icon: "💿".into(), category: "Dev Tools".into(),
            description: "Web-based management UI for MinIO S3 storage".into(),
            website: Some("https://min.io".into()),
            docker: Some(DockerTarget { image: "minio/console:latest".into(), ports: vec!["9090:9090".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "pypiserver".into(), name: "PyPI Server".into(), icon: "🐍".into(), category: "Dev Tools".into(),
            description: "Private Python package index — host your own PyPI".into(),
            website: Some("https://github.com/pypiserver/pypiserver".into()),
            docker: Some(DockerTarget { image: "pypiserver/pypiserver:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["pypi_packages:/data/packages".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "renovate".into(), name: "Renovate".into(), icon: "🔄".into(), category: "Dev Tools".into(),
            description: "Automated dependency updates for Git repositories".into(),
            website: Some("https://www.mend.io/renovate/".into()),
            docker: Some(DockerTarget { image: "renovate/renovate:latest".into(), ports: vec![], env: vec!["RENOVATE_TOKEN=${GIT_TOKEN}".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "GIT_TOKEN".into(), label: "Git Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("GitHub/GitLab personal access token".into()), options: vec![] },
            ],
        },

        // ─── Networking (batch 3) ───

        AppManifest { id: "unifi".into(), name: "UniFi Controller".into(), icon: "📶".into(), category: "Networking".into(),
            description: "Ubiquiti UniFi network management controller".into(),
            website: Some("https://ui.com".into()),
            docker: Some(DockerTarget { image: "linuxserver/unifi-network-application:latest".into(), ports: vec!["8443:8443".into(), "3478:3478/udp".into(), "10001:10001/udp".into(), "8080:8080".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["unifi_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "omada".into(), name: "TP-Link Omada Controller".into(), icon: "📶".into(), category: "Networking".into(),
            description: "TP-Link Omada SDN controller for managing EAP access points".into(),
            website: Some("https://www.tp-link.com/us/omada-sdn/".into()),
            docker: Some(DockerTarget { image: "mbentley/omada-controller:latest".into(), ports: vec!["8088:8088".into(), "8043:8043".into(), "27001:27001/udp".into(), "27002:27002".into()], env: vec!["TZ=UTC".into()], volumes: vec!["omada_data:/opt/tplink/EAPController/data".into(), "omada_logs:/opt/tplink/EAPController/logs".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "netbox".into(), name: "NetBox".into(), icon: "🗺️".into(), category: "Networking".into(),
            description: "IP address management and data centre infrastructure modelling".into(),
            website: Some("https://netbox.dev".into()),
            docker: Some(DockerTarget { image: "netboxcommunity/netbox:latest".into(), ports: vec!["8080:8080".into()], env: vec!["SUPERUSER_NAME=admin".into(), "SUPERUSER_PASSWORD=${ADMIN_PASSWORD}".into(), "SUPERUSER_EMAIL=admin@example.com".into()], volumes: vec!["netbox_media:/opt/netbox/netbox/media".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=netbox".into(), "POSTGRES_USER=netbox".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["netbox_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("NetBox admin password".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "librespeed".into(), name: "LibreSpeed".into(), icon: "⚡".into(), category: "Networking".into(),
            description: "Self-hosted internet speed test with no Flash, no Java".into(),
            website: Some("https://librespeed.org".into()),
            docker: Some(DockerTarget { image: "linuxserver/librespeed:latest".into(), ports: vec!["8080:80".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["librespeed_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Security (batch 3) ───

        AppManifest { id: "keeweb".into(), name: "KeeWeb".into(), icon: "🔑".into(), category: "Security".into(),
            description: "Web-based KeePass password manager".into(),
            website: Some("https://keeweb.info".into()),
            docker: Some(DockerTarget { image: "ghcr.io/keeweb/keeweb:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "passbolt".into(), name: "Passbolt".into(), icon: "🔐".into(), category: "Security".into(),
            description: "Team password manager with sharing and auditing".into(),
            website: Some("https://www.passbolt.com".into()),
            docker: Some(DockerTarget { image: "passbolt/passbolt:latest-ce".into(), ports: vec!["8080:80".into(), "8443:443".into()], env: vec!["DATASOURCES_DEFAULT_HOST=passbolt-db".into(), "DATASOURCES_DEFAULT_PASSWORD=${DB_PASSWORD}".into(), "DATASOURCES_DEFAULT_DATABASE=passbolt".into(), "DATASOURCES_DEFAULT_USERNAME=passbolt".into(), "APP_FULL_BASE_URL=http://localhost:8080".into()], volumes: vec!["passbolt_gpg:/etc/passbolt/gpg".into(), "passbolt_jwt:/etc/passbolt/jwt".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "mariadb:10".into(), ports: vec![], env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=passbolt".into(), "MYSQL_USER=passbolt".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["passbolt_db:/var/lib/mysql".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "grype".into(), name: "Grype".into(), icon: "🔍".into(), category: "Security".into(),
            description: "Container image vulnerability scanner by Anchore".into(),
            website: Some("https://github.com/anchore/grype".into()),
            docker: Some(DockerTarget { image: "anchore/grype:latest".into(), ports: vec![], env: vec![], volumes: vec!["grype_db:/root/.cache/grype".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Monitoring (batch 3) ───

        AppManifest { id: "grafana-alloy".into(), name: "Grafana Alloy".into(), icon: "📊".into(), category: "Monitoring".into(),
            description: "OpenTelemetry collector for metrics, logs, and traces".into(),
            website: Some("https://grafana.com/oss/alloy/".into()),
            docker: Some(DockerTarget { image: "grafana/alloy:latest".into(), ports: vec!["12345:12345".into()], env: vec![], volumes: vec!["alloy_data:/var/lib/alloy".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "alertmanager".into(), name: "Alertmanager".into(), icon: "🚨".into(), category: "Monitoring".into(),
            description: "Prometheus alert routing, deduplication, and notification".into(),
            website: Some("https://prometheus.io/docs/alerting/latest/alertmanager/".into()),
            docker: Some(DockerTarget { image: "prom/alertmanager:latest".into(), ports: vec!["9093:9093".into()], env: vec![], volumes: vec!["alertmanager_data:/alertmanager".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "jaeger".into(), name: "Jaeger".into(), icon: "🔎".into(), category: "Monitoring".into(),
            description: "Distributed tracing platform for microservices".into(),
            website: Some("https://www.jaegertracing.io".into()),
            docker: Some(DockerTarget { image: "jaegertracing/all-in-one:latest".into(), ports: vec!["16686:16686".into(), "14268:14268".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "zipkin".into(), name: "Zipkin".into(), icon: "🔬".into(), category: "Monitoring".into(),
            description: "Distributed tracing system for latency troubleshooting".into(),
            website: Some("https://zipkin.io".into()),
            docker: Some(DockerTarget { image: "openzipkin/zipkin:latest".into(), ports: vec!["9411:9411".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Automation (batch 3) ───

        AppManifest { id: "healthcheck-ping".into(), name: "Healthchecks.io (self-hosted)".into(), icon: "🏓".into(), category: "Automation".into(),
            description: "Cron job monitor — alerts when scheduled tasks don't run".into(),
            website: Some("https://healthchecks.io".into()),
            docker: Some(DockerTarget { image: "healthchecks/healthchecks:latest".into(), ports: vec!["8000:8000".into()], env: vec!["SECRET_KEY=${SECRET_KEY}".into(), "ALLOWED_HOSTS=*".into()], volumes: vec!["healthchecks_v2_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Django secret key".into()), options: vec![] },
            ],
        },
        AppManifest { id: "kestra".into(), name: "Kestra".into(), icon: "🌊".into(), category: "Automation".into(),
            description: "Declarative data orchestration and scheduling platform".into(),
            website: Some("https://kestra.io".into()),
            docker: Some(DockerTarget { image: "kestra/kestra:latest".into(), ports: vec!["8080:8080".into(), "8081:8081".into()], env: vec![], volumes: vec!["kestra_data:/app/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Communication (batch 3) ───

        // Flarum — crazymax/flarum bundles nginx + php-fpm + SQLite
        // in one image, so it's a true single-container install.
        AppManifest { id: "flarum".into(), name: "Flarum".into(), icon: "💬".into(), category: "Communication".into(),
            description: "Lightweight, modern community forum — all-in-one image with bundled SQLite".into(),
            website: Some("https://flarum.org".into()),
            docker: Some(DockerTarget { image: "crazymax/flarum:latest".into(), ports: vec!["8000:8000".into()], env: vec!["FLARUM_BASE_URL=${BASE_URL}".into()], volumes: vec!["flarum_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "BASE_URL".into(), label: "Base URL".into(), input_type: "text".into(), default: Some("http://localhost:8000".into()), required: true, placeholder: Some("e.g. https://forum.example.com".into()), options: vec![] },
            ],
        },

        // Discourse — upstream only ships a `base` image that their
        // `launcher` script rebuilds into a custom per-host image.
        // Bitnami packages a runnable app + separate Postgres + Redis
        // which is the closest we can get to one-click.
        AppManifest { id: "discourse".into(), name: "Discourse".into(), icon: "💬".into(), category: "Communication".into(),
            description: "Modern community forum and discussion platform".into(),
            website: Some("https://www.discourse.org".into()),
            docker: Some(DockerTarget {
                image: "bitnami/discourse:latest".into(),
                ports: vec!["8480:3000".into()],
                env: vec![
                    "DISCOURSE_DATABASE_HOST=${CONTAINER_NAME}-db".into(),
                    "DISCOURSE_DATABASE_NAME=discourse".into(),
                    "DISCOURSE_DATABASE_USER=discourse".into(),
                    "DISCOURSE_DATABASE_PASSWORD=${DB_PASSWORD}".into(),
                    "DISCOURSE_REDIS_HOST=${CONTAINER_NAME}-redis".into(),
                    "DISCOURSE_HOST=${HOST}".into(),
                    "DISCOURSE_USERNAME=${ADMIN_USER}".into(),
                    "DISCOURSE_PASSWORD=${ADMIN_PASSWORD}".into(),
                    "DISCOURSE_EMAIL=admin@localhost".into(),
                ],
                volumes: vec!["discourse_data:/bitnami/discourse".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(),
                        image: "bitnami/postgresql:15".into(),
                        ports: vec![],
                        env: vec![
                            "POSTGRESQL_USERNAME=discourse".into(),
                            "POSTGRESQL_PASSWORD=${DB_PASSWORD}".into(),
                            "POSTGRESQL_DATABASE=discourse".into(),
                            "POSTGRESQL_POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                        ],
                        volumes: vec!["discourse_db:/bitnami/postgresql".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "redis".into(),
                        image: "bitnami/redis:7".into(),
                        ports: vec![],
                        env: vec!["ALLOW_EMPTY_PASSWORD=yes".into()],
                        volumes: vec!["discourse_redis:/bitnami/redis/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                ],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "HOST".into(), label: "Hostname".into(), input_type: "text".into(), default: Some("localhost".into()), required: true, placeholder: Some("e.g. forum.example.com".into()), options: vec![] },
                UserInput { id: "ADMIN_USER".into(), label: "Admin Username".into(), input_type: "text".into(), default: Some("admin".into()), required: true, placeholder: None, options: vec![] },
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 10 characters".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Postgres password".into()), options: vec![] },
            ],
        },

        // Chatwoot — Rails app + Postgres + Redis + Sidekiq worker
        // (same image, different cmd). The app runs migrations on
        // first boot via its bundled docker-entrypoint.
        AppManifest { id: "chatwoot".into(), name: "Chatwoot".into(), icon: "💬".into(), category: "Communication".into(),
            description: "Customer engagement platform — live chat, email, social".into(),
            website: Some("https://www.chatwoot.com".into()),
            docker: Some(DockerTarget {
                image: "chatwoot/chatwoot:latest".into(),
                ports: vec!["3030:3000".into()],
                env: vec![
                    "SECRET_KEY_BASE=${SECRET_KEY}".into(),
                    "FRONTEND_URL=${FRONTEND_URL}".into(),
                    "POSTGRES_HOST=${CONTAINER_NAME}-db".into(),
                    "POSTGRES_USERNAME=chatwoot".into(),
                    "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                    "POSTGRES_DATABASE=chatwoot".into(),
                    "REDIS_URL=redis://${CONTAINER_NAME}-redis:6379".into(),
                    "RAILS_ENV=production".into(),
                    "NODE_ENV=production".into(),
                    "INSTALLATION_ENV=docker".into(),
                ],
                volumes: vec!["chatwoot_storage:/app/storage".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(),
                        image: "postgres:15-alpine".into(),
                        ports: vec![],
                        env: vec![
                            "POSTGRES_USER=chatwoot".into(),
                            "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                            "POSTGRES_DB=chatwoot".into(),
                        ],
                        volumes: vec!["chatwoot_db:/var/lib/postgresql/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "redis".into(),
                        image: "redis:7-alpine".into(),
                        ports: vec![],
                        env: vec![],
                        volumes: vec!["chatwoot_redis:/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "sidekiq".into(),
                        image: "chatwoot/chatwoot:latest".into(),
                        ports: vec![],
                        env: vec![
                            "SECRET_KEY_BASE=${SECRET_KEY}".into(),
                            "FRONTEND_URL=${FRONTEND_URL}".into(),
                            "POSTGRES_HOST=${CONTAINER_NAME}-db".into(),
                            "POSTGRES_USERNAME=chatwoot".into(),
                            "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                            "POSTGRES_DATABASE=chatwoot".into(),
                            "REDIS_URL=redis://${CONTAINER_NAME}-redis:6379".into(),
                            "RAILS_ENV=production".into(),
                            "NODE_ENV=production".into(),
                            "INSTALLATION_ENV=docker".into(),
                        ],
                        volumes: vec!["chatwoot_storage:/app/storage".into()],
                        cmd: vec!["bundle".into(), "exec".into(), "sidekiq".into(), "-C".into(), "config/sidekiq.yml".into()],
                        post_install_exec: vec![],
                    },
                ],
                seed_files: vec![],
                // `db:chatwoot_prepare` is idempotent — creates schema
                // on first install, runs any pending migrations on
                // subsequent starts. Without this the web container
                // starts but every request 500s on missing tables.
                cmd: vec!["sh".into(), "-c".into(), "bundle exec rails db:chatwoot_prepare && bundle exec rails server -b 0.0.0.0 -p 3000".into()],
            }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key Base".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Long random hex (64 chars)".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Postgres password".into()), options: vec![] },
                UserInput { id: "FRONTEND_URL".into(), label: "Frontend URL".into(), input_type: "text".into(), default: Some("http://localhost:3030".into()), required: true, placeholder: Some("e.g. https://chat.example.com".into()), options: vec![] },
            ],
        },

        // ─── CMS (batch 3) ───

        AppManifest { id: "hugo".into(), name: "Hugo".into(), icon: "📝".into(), category: "CMS".into(),
            description: "Fast static site generator — build blogs and docs".into(),
            website: Some("https://gohugo.io".into()),
            docker: Some(DockerTarget { image: "klakegg/hugo:latest".into(), ports: vec!["1313:1313".into()], env: vec![], volumes: vec!["hugo_site:/src".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "writefreely".into(), name: "WriteFreely".into(), icon: "✍️".into(), category: "CMS".into(),
            description: "Minimalist, federated blogging platform".into(),
            website: Some("https://writefreely.org".into()),
            docker: Some(DockerTarget { image: "writeas/writefreely:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["writefreely_data:/go/keys".into(), "writefreely_db:/go/db".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── AI / ML (batch 3) ───

        AppManifest { id: "privateGPT".into(), name: "PrivateGPT".into(), icon: "🔒".into(), category: "AI / ML".into(),
            description: "Chat with your documents privately — no data leaves your server".into(),
            website: Some("https://privategpt.dev".into()),
            docker: Some(DockerTarget { image: "ghcr.io/zylon-ai/private-gpt:latest".into(), ports: vec!["8001:8001".into()], env: vec![], volumes: vec!["privategpt_data:/home/worker/app/local_data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "litellm".into(), name: "LiteLLM".into(), icon: "⚡".into(), category: "AI / ML".into(),
            description: "Unified API proxy for 100+ LLM providers — OpenAI compatible".into(),
            website: Some("https://litellm.ai".into()),
            docker: Some(DockerTarget { image: "ghcr.io/berriai/litellm:main-latest".into(), ports: vec!["4000:4000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "label-studio".into(), name: "Label Studio".into(), icon: "🏷️".into(), category: "AI / ML".into(),
            description: "Data labeling tool for machine learning — images, text, audio".into(),
            website: Some("https://labelstud.io".into()),
            docker: Some(DockerTarget { image: "heartexlabs/label-studio:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["labelstudio_data:/label-studio/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "jupyter".into(), name: "Jupyter Notebook".into(), icon: "📓".into(), category: "AI / ML".into(),
            description: "Interactive computing notebooks for data science and ML".into(),
            website: Some("https://jupyter.org".into()),
            docker: Some(DockerTarget { image: "jupyter/scipy-notebook:latest".into(), ports: vec!["8888:8888".into()], env: vec![], volumes: vec!["jupyter_work:/home/jovyan/work".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "mlflow".into(), name: "MLflow".into(), icon: "📊".into(), category: "AI / ML".into(),
            description: "ML lifecycle management — tracking, model registry, deployment".into(),
            website: Some("https://mlflow.org".into()),
            docker: Some(DockerTarget { image: "ghcr.io/mlflow/mlflow:latest".into(), ports: vec!["5000:5000".into()], env: vec![], volumes: vec!["mlflow_data:/mlflow".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Other (batch 3) ───

        AppManifest { id: "photostructure".into(), name: "PhotoStructure".into(), icon: "🖼️".into(), category: "Other".into(),
            description: "Automatic photo and video organiser with deduplication".into(),
            website: Some("https://photostructure.com".into()),
            docker: Some(DockerTarget { image: "photostructure/server:latest".into(), ports: vec!["1787:1787".into()], env: vec![], volumes: vec!["photostructure_lib:/ps/library".into(), "${PHOTOS_PATH}:/ps/scan:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "PHOTOS_PATH".into(), label: "Photos Path".into(), input_type: "text".into(), default: Some("/opt/photos".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "upsnap".into(), name: "UpSnap".into(), icon: "💤".into(), category: "Other".into(),
            description: "Wake-on-LAN dashboard — wake sleeping devices from the browser".into(),
            website: Some("https://github.com/seriousm4x/UpSnap".into()),
            docker: Some(DockerTarget { image: "ghcr.io/seriousm4x/upsnap:latest".into(), ports: vec!["8090:8090".into()], env: vec![], volumes: vec!["upsnap_data:/app/pb_data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "openspeedtest".into(), name: "OpenSpeedTest".into(), icon: "🏎️".into(), category: "Other".into(),
            description: "HTML5 network speed test — no Flash, no plugins".into(),
            website: Some("https://openspeedtest.com".into()),
            docker: Some(DockerTarget { image: "openspeedtest/latest:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "whoami".into(), name: "Whoami".into(), icon: "❓".into(), category: "Other".into(),
            description: "Tiny Go web server that prints request headers — great for testing".into(),
            website: Some("https://github.com/traefik/whoami".into()),
            docker: Some(DockerTarget { image: "traefik/whoami:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "answer".into(), name: "Answer".into(), icon: "❓".into(), category: "Other".into(),
            description: "Q&A platform for teams — Stack Overflow alternative".into(),
            website: Some("https://answer.dev".into()),
            docker: Some(DockerTarget { image: "answerdev/answer:latest".into(), ports: vec!["9080:80".into()], env: vec![], volumes: vec!["answer_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "maybe".into(), name: "Maybe".into(), icon: "💸".into(), category: "Other".into(),
            description: "Personal finance and wealth management dashboard".into(),
            website: Some("https://maybe.co".into()),
            docker: Some(DockerTarget { image: "ghcr.io/maybe-finance/maybe:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["maybe_data:/rails/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "actual-budget".into(), name: "Actual Budget".into(), icon: "💰".into(), category: "Other".into(),
            description: "Privacy-focused personal budgeting with envelope budgeting".into(),
            website: Some("https://actualbudget.org".into()),
            docker: Some(DockerTarget { image: "actualbudget/actual-server:latest".into(), ports: vec!["5006:5006".into()], env: vec![], volumes: vec!["actual_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "firefly".into(), name: "Firefly III".into(), icon: "🔥".into(), category: "Other".into(),
            description: "Personal finance manager with budgets, charts, and reports".into(),
            website: Some("https://www.firefly-iii.org".into()),
            docker: Some(DockerTarget { image: "fireflyiii/core:latest".into(), ports: vec!["8080:8080".into()], env: vec!["APP_KEY=${APP_KEY}".into(), "DB_CONNECTION=sqlite".into(), "DB_DATABASE=/var/www/html/storage/database/database.sqlite".into()], volumes: vec!["firefly_upload:/var/www/html/storage/upload".into(), "firefly_db:/var/www/html/storage/database".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "APP_KEY".into(), label: "App Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Exactly 32 characters".into()), options: vec![] },
            ],
        },

        // ─── Gaming (batch 3) ───

        AppManifest { id: "foundry-vtt".into(), name: "Foundry VTT".into(), icon: "🎲".into(), category: "Gaming".into(),
            description: "Virtual tabletop for D&D, Pathfinder, and other RPGs".into(),
            website: Some("https://foundryvtt.com".into()),
            docker: Some(DockerTarget { image: "felddy/foundryvtt:release".into(), ports: vec!["30000:30000".into()], env: vec!["FOUNDRY_USERNAME=${FOUNDRY_USER}".into(), "FOUNDRY_PASSWORD=${FOUNDRY_PASS}".into()], volumes: vec!["foundryvtt_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "FOUNDRY_USER".into(), label: "Foundry Username".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("foundryvtt.com account username".into()), options: vec![] },
                UserInput { id: "FOUNDRY_PASS".into(), label: "Foundry Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("foundryvtt.com account password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "avorion".into(), name: "Avorion".into(), icon: "🚀".into(), category: "Gaming".into(),
            description: "Avorion dedicated server — space sandbox building game".into(),
            website: Some("https://www.avorion.net".into()),
            docker: Some(DockerTarget { image: "rfvgyhn/avorion:latest".into(), ports: vec!["27000:27000".into(), "27003:27003".into(), "27020:27020".into(), "27021:27021".into()], env: vec![], volumes: vec!["avorion_data:/home/steam/avorion-server".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "stationeers".into(), name: "Stationeers".into(), icon: "🛸".into(), category: "Gaming".into(),
            description: "Stationeers dedicated server — space station building sim".into(),
            website: Some("https://store.steampowered.com/app/544550/Stationeers/".into()),
            docker: Some(DockerTarget { image: "hetsh/stationeers:latest".into(), ports: vec!["27016:27016/udp".into()], env: vec!["WORLD_NAME=${WORLD_NAME}".into()], volumes: vec!["stationeers_data:/stationeers".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "WORLD_NAME".into(), label: "World Name".into(), input_type: "text".into(), default: Some("MyWorld".into()), required: true, placeholder: None, options: vec![] },
            ],
        },
        AppManifest { id: "unturned".into(), name: "Unturned".into(), icon: "🧟".into(), category: "Gaming".into(),
            description: "Unturned dedicated server — zombie survival sandbox".into(),
            website: Some("https://smartlydressedgames.com".into()),
            docker: Some(DockerTarget { image: "cm2network/unturned:latest".into(), ports: vec!["27015:27015/udp".into(), "27016:27016/udp".into()], env: vec![], volumes: vec!["unturned_data:/home/steam/unturned-dedicated".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "dont-starve".into(), name: "Don't Starve Together".into(), icon: "🔥".into(), category: "Gaming".into(),
            description: "Don't Starve Together dedicated server — survival co-op".into(),
            website: Some("https://www.klei.com/games/dont-starve-together".into()),
            docker: Some(DockerTarget { image: "jamesits/dst-server:latest".into(), ports: vec!["10999:10999/udp".into()], env: vec!["DST_CLUSTER_TOKEN=${CLUSTER_TOKEN}".into()], volumes: vec!["dst_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "CLUSTER_TOKEN".into(), label: "Cluster Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("From Klei account".into()), options: vec![] },
            ],
        },

        // ─── Project Management (batch 3) ───

        AppManifest { id: "openproject".into(), name: "OpenProject".into(), icon: "📊".into(), category: "Project Management".into(),
            description: "Project management with Gantt charts, agile boards, and time tracking".into(),
            website: Some("https://www.openproject.org".into()),
            docker: Some(DockerTarget { image: "openproject/openproject:latest".into(), ports: vec!["8080:80".into()], env: vec!["OPENPROJECT_SECRET_KEY_BASE=${SECRET_KEY}".into()], volumes: vec!["openproject_pgdata:/var/openproject/pgdata".into(), "openproject_assets:/var/openproject/assets".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] },
            ],
        },
        AppManifest { id: "kanboard".into(), name: "Kanboard".into(), icon: "📌".into(), category: "Project Management".into(),
            description: "Simple and efficient kanban project management".into(),
            website: Some("https://kanboard.org".into()),
            docker: Some(DockerTarget { image: "kanboard/kanboard:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["kanboard_data:/var/www/app/data".into(), "kanboard_plugins:/var/www/app/plugins".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Analytics (batch 3) ───

        AppManifest { id: "goatcounter".into(), name: "GoatCounter".into(), icon: "🐐".into(), category: "Analytics".into(),
            description: "Simple web analytics — privacy-friendly, no cookies".into(),
            website: Some("https://www.goatcounter.com".into()),
            docker: Some(DockerTarget { image: "baethon/goatcounter:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["goatcounter_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },
        AppManifest { id: "ackee".into(), name: "Ackee".into(), icon: "📈".into(), category: "Analytics".into(),
            description: "Privacy-focused analytics without cookies — Node.js based".into(),
            website: Some("https://ackee.electerious.com".into()),
            docker: Some(DockerTarget { image: "electerious/ackee:latest".into(), ports: vec!["3000:3000".into()], env: vec!["ACKEE_MONGODB=mongodb://ackee-db:27017/ackee".into(), "ACKEE_USERNAME=admin".into(), "ACKEE_PASSWORD=${ADMIN_PASSWORD}".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "mongo:6".into(), ports: vec![], env: vec![], volumes: vec!["ackee_db:/data/db".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Ackee admin password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "fathom".into(), name: "Fathom Lite".into(), icon: "📊".into(), category: "Analytics".into(),
            description: "Simple, privacy-first website analytics".into(),
            website: Some("https://usefathom.com".into()),
            docker: Some(DockerTarget { image: "usefathom/fathom:latest".into(), ports: vec!["8080:8080".into()], env: vec!["FATHOM_SERVER_ADDR=:8080".into()], volumes: vec!["fathom_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── CI/CD (batch 3) ───

        AppManifest { id: "concourse".into(), name: "Concourse CI".into(), icon: "✈️".into(), category: "CI/CD".into(),
            description: "Pipeline-based CI/CD system with reproducible builds".into(),
            website: Some("https://concourse-ci.org".into()),
            docker: Some(DockerTarget { image: "concourse/concourse:latest".into(), ports: vec!["8080:8080".into()], env: vec!["CONCOURSE_ADD_LOCAL_USER=admin:${ADMIN_PASSWORD}".into(), "CONCOURSE_MAIN_TEAM_LOCAL_USER=admin".into(), "CONCOURSE_EXTERNAL_URL=http://localhost:8080".into(), "CONCOURSE_POSTGRES_HOST=concourse-db".into(), "CONCOURSE_POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=concourse".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["concourse_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Concourse admin password".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] },
            ],
        },
        AppManifest { id: "buildkite-agent".into(), name: "Buildkite Agent".into(), icon: "🏗️".into(), category: "CI/CD".into(),
            description: "Self-hosted CI/CD agent for Buildkite pipelines".into(),
            website: Some("https://buildkite.com".into()),
            docker: Some(DockerTarget { image: "buildkite/agent:latest".into(), ports: vec![], env: vec!["BUILDKITE_AGENT_TOKEN=${AGENT_TOKEN}".into()], volumes: vec!["buildkite_builds:/buildkite/builds".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "AGENT_TOKEN".into(), label: "Agent Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("From Buildkite dashboard".into()), options: vec![] },
            ],
        },

        // ─── PaaS (batch 3) ───

        AppManifest { id: "piku".into(), name: "Piku".into(), icon: "🐡".into(), category: "PaaS".into(),
            description: "Heroku-like deployment to your own server — git push to deploy".into(),
            website: Some("https://piku.github.io".into()),
            docker: Some(DockerTarget { image: "piku/piku:latest".into(), ports: vec!["9080:80".into(), "2222:22".into()], env: vec![], volumes: vec!["piku_data:/home/piku".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },

        // ─── Container Orchestration (batch 3) ───

        AppManifest { id: "consul".into(), name: "HashiCorp Consul".into(), icon: "🏛️".into(), category: "Container Orchestration".into(),
            description: "Service mesh, discovery, and configuration for distributed systems".into(),
            website: Some("https://www.consul.io".into()),
            docker: Some(DockerTarget { image: "hashicorp/consul:latest".into(), ports: vec!["8500:8500".into(), "8600:8600/udp".into()], env: vec![], volumes: vec!["consul_data:/consul/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![],
        },


        // ═══════════════════════════════════════════════════════════════
        // Batch 4 — final push to 500
        // ═══════════════════════════════════════════════════════════════

        AppManifest { id: "podgrab".into(), name: "Podgrab".into(), icon: "🎙️".into(), category: "Media".into(), description: "Podcast manager and downloader with web UI".into(), website: Some("https://github.com/akhilrex/podgrab".into()), docker: Some(DockerTarget { image: "akhilrex/podgrab:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["podgrab_config:/config".into(), "podgrab_assets:/assets".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "castopod".into(), name: "Castopod".into(), icon: "🎙️".into(), category: "Media".into(), description: "Podcast hosting platform with ActivityPub federation".into(), website: Some("https://castopod.org".into()), docker: Some(DockerTarget { image: "castopod/castopod:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["castopod_data:/var/www/castopod/public/media".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "pinchflat".into(), name: "Pinchflat".into(), icon: "📺".into(), category: "Media".into(), description: "Self-hosted YouTube channel downloader and media manager".into(), website: Some("https://github.com/kieraneglin/pinchflat".into()), docker: Some(DockerTarget { image: "ghcr.io/kieraneglin/pinchflat:latest".into(), ports: vec!["8945:8945".into()], env: vec![], volumes: vec!["pinchflat_config:/config".into(), "pinchflat_downloads:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "threadfin".into(), name: "Threadfin".into(), icon: "📺".into(), category: "Media".into(), description: "M3U proxy for IPTV — works with Plex, Emby, Jellyfin".into(), website: Some("https://github.com/Threadfin/Threadfin".into()), docker: Some(DockerTarget { image: "fyb3roptik/threadfin:latest".into(), ports: vec!["34400:34400".into()], env: vec![], volumes: vec!["threadfin_config:/home/threadfin/conf".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "jfa-go".into(), name: "jfa-go".into(), icon: "👥".into(), category: "Media".into(), description: "User management for Jellyfin with invite links".into(), website: Some("https://github.com/hrfee/jfa-go".into()), docker: Some(DockerTarget { image: "hrfee/jfa-go:latest".into(), ports: vec!["8056:8056".into()], env: vec![], volumes: vec!["jfago_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "standard-notes".into(), name: "Standard Notes".into(), icon: "📝".into(), category: "Productivity".into(), description: "End-to-end encrypted notes app with extensions".into(), website: Some("https://standardnotes.com".into()), docker: Some(DockerTarget { image: "standardnotes/server:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["standardnotes_data:/var/lib/server".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "silverbullet".into(), name: "SilverBullet".into(), icon: "🥈".into(), category: "Productivity".into(), description: "Note-taking app and personal knowledge management".into(), website: Some("https://silverbullet.md".into()), docker: Some(DockerTarget { image: "zefhemel/silverbullet:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["silverbullet_space:/space".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "logseq".into(), name: "Logseq".into(), icon: "📓".into(), category: "Productivity".into(), description: "Privacy-first knowledge management and collaboration platform".into(), website: Some("https://logseq.com".into()), docker: Some(DockerTarget { image: "ghcr.io/logseq/logseq-webapp:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "affine".into(), name: "AFFiNE".into(), icon: "📐".into(), category: "Productivity".into(), description: "Notion alternative — docs, whiteboards, and databases".into(), website: Some("https://affine.pro".into()), docker: Some(DockerTarget { image: "ghcr.io/toeverything/affine-graphql:stable".into(), ports: vec!["3010:3010".into()], env: vec![], volumes: vec!["affine_config:/root/.affine/config".into(), "affine_data:/root/.affine/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "huly".into(), name: "Huly".into(), icon: "🏢".into(), category: "Productivity".into(), description: "All-in-one project management — Linear, Jira, Notion alternative".into(), website: Some("https://huly.io".into()), docker: Some(DockerTarget { image: "hardcoreeng/huly:latest".into(), ports: vec!["8083:8083".into()], env: vec![], volumes: vec!["huly_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "gitness".into(), name: "Gitness".into(), icon: "🐙".into(), category: "Dev Tools".into(), description: "Open-source developer platform with Git hosting and CI/CD".into(), website: Some("https://gitness.com".into()), docker: Some(DockerTarget { image: "harness/gitness:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["gitness_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "gogs".into(), name: "Gogs".into(), icon: "🐸".into(), category: "Dev Tools".into(), description: "Painless self-hosted Git service — lightweight Gitea alternative".into(), website: Some("https://gogs.io".into()), docker: Some(DockerTarget { image: "gogs/gogs:latest".into(), ports: vec!["3000:3000".into(), "2222:22".into()], env: vec![], volumes: vec!["gogs_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "onedev".into(), name: "OneDev".into(), icon: "🔧".into(), category: "Dev Tools".into(), description: "Git server with CI/CD, issue tracking, and kanban boards".into(), website: Some("https://onedev.io".into()), docker: Some(DockerTarget { image: "1dev/server:latest".into(), ports: vec!["6610:6610".into(), "6611:6611".into()], env: vec![], volumes: vec!["onedev_data:/opt/onedev".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "sshwifty".into(), name: "Sshwifty".into(), icon: "🔌".into(), category: "Dev Tools".into(), description: "SSH and Telnet client in the browser".into(), website: Some("https://github.com/nirui/sshwifty".into()), docker: Some(DockerTarget { image: "niruix/sshwifty:latest".into(), ports: vec!["8182:8182".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "webssh".into(), name: "WebSSH".into(), icon: "💻".into(), category: "Dev Tools".into(), description: "Web-based SSH terminal".into(), website: Some("https://github.com/huashengdun/webssh".into()), docker: Some(DockerTarget { image: "snsyzb/webssh:latest".into(), ports: vec!["8888:8888".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "ferretdb".into(), name: "FerretDB".into(), icon: "🐾".into(), category: "Database".into(), description: "Open-source MongoDB alternative built on PostgreSQL".into(), website: Some("https://www.ferretdb.com".into()), docker: Some(DockerTarget { image: "ghcr.io/ferretdb/ferretdb:latest".into(), ports: vec!["27017:27017".into()], env: vec!["FERRETDB_POSTGRESQL_URL=postgres://postgres:${DB_PASSWORD}@ferretdb-db:5432/ferretdb".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=ferretdb".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["ferretdb_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] }] },
        AppManifest { id: "edgedb".into(), name: "EdgeDB".into(), icon: "🔺".into(), category: "Database".into(), description: "Next-gen database with a graph-relational model and EdgeQL".into(), website: Some("https://www.edgedb.com".into()), docker: Some(DockerTarget { image: "edgedb/edgedb:latest".into(), ports: vec!["5656:5656".into()], env: vec!["EDGEDB_SERVER_SECURITY=insecure_dev_mode".into()], volumes: vec!["edgedb_data:/var/lib/edgedb/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "rethinkdb".into(), name: "RethinkDB".into(), icon: "🔄".into(), category: "Database".into(), description: "Real-time database with change feeds for push architectures".into(), website: Some("https://rethinkdb.com".into()), docker: Some(DockerTarget { image: "rethinkdb:latest".into(), ports: vec!["8080:8080".into(), "28015:28015".into()], env: vec![], volumes: vec!["rethinkdb_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "couchdb".into(), name: "Apache CouchDB".into(), icon: "🛋️".into(), category: "Database".into(), description: "Document-oriented database with HTTP API and replication".into(), website: Some("https://couchdb.apache.org".into()), docker: Some(DockerTarget { image: "couchdb:latest".into(), ports: vec!["5984:5984".into()], env: vec!["COUCHDB_USER=admin".into(), "COUCHDB_PASSWORD=${ADMIN_PASSWORD}".into()], volumes: vec!["couchdb_data:/opt/couchdb/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("CouchDB admin password".into()), options: vec![] }] },
        AppManifest { id: "nats".into(), name: "NATS".into(), icon: "⚡".into(), category: "Database".into(), description: "Cloud-native messaging system for microservices".into(), website: Some("https://nats.io".into()), docker: Some(DockerTarget { image: "nats:latest".into(), ports: vec!["4222:4222".into(), "8222:8222".into()], env: vec![], volumes: vec!["nats_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "rabbitmq".into(), name: "RabbitMQ".into(), icon: "🐰".into(), category: "Database".into(), description: "Message broker with management UI — queues, topics, exchanges".into(), website: Some("https://www.rabbitmq.com".into()), docker: Some(DockerTarget { image: "rabbitmq:3-management".into(), ports: vec!["5672:5672".into(), "15672:15672".into()], env: vec!["RABBITMQ_DEFAULT_USER=admin".into(), "RABBITMQ_DEFAULT_PASS=${ADMIN_PASSWORD}".into()], volumes: vec!["rabbitmq_data:/var/lib/rabbitmq".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("RabbitMQ admin password".into()), options: vec![] }] },
        AppManifest { id: "kafka-ui".into(), name: "Kafka UI".into(), icon: "📊".into(), category: "Database".into(), description: "Web UI for Apache Kafka cluster management".into(), website: Some("https://github.com/provectus/kafka-ui".into()), docker: Some(DockerTarget { image: "provectuslabs/kafka-ui:latest".into(), ports: vec!["8080:8080".into()], env: vec!["KAFKA_CLUSTERS_0_NAME=local".into(), "KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS=${KAFKA_HOST}".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "KAFKA_HOST".into(), label: "Kafka Bootstrap Server".into(), input_type: "text".into(), default: Some("kafka:9092".into()), required: true, placeholder: None, options: vec![] }] },

        AppManifest { id: "wg-easy".into(), name: "WireGuard Easy".into(), icon: "🔒".into(), category: "Networking".into(), description: "WireGuard VPN with a simple web UI for managing clients".into(), website: Some("https://github.com/wg-easy/wg-easy".into()), docker: Some(DockerTarget { image: "ghcr.io/wg-easy/wg-easy:latest".into(), ports: vec!["51820:51820/udp".into(), "51821:51821".into()], env: vec!["WG_HOST=${PUBLIC_IP}".into(), "PASSWORD_HASH=${ADMIN_PASSWORD}".into()], volumes: vec!["wg_easy_data:/etc/wireguard".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "PUBLIC_IP".into(), label: "Public IP".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("Your server's public IP".into()), options: vec![] }, UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Web UI password".into()), options: vec![] }] },
        AppManifest { id: "openvas".into(), name: "OpenVAS".into(), icon: "🔍".into(), category: "Security".into(), description: "Full-featured vulnerability scanner and management".into(), website: Some("https://www.openvas.org".into()), docker: Some(DockerTarget { image: "greenbone/openvas-scanner:latest".into(), ports: vec!["9392:9392".into()], env: vec![], volumes: vec!["openvas_data:/var/lib/openvas".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "thelounge".into(), name: "The Lounge".into(), icon: "💬".into(), category: "Communication".into(), description: "Modern, self-hosted IRC client with web interface".into(), website: Some("https://thelounge.chat".into()), docker: Some(DockerTarget { image: "thelounge/thelounge:latest".into(), ports: vec!["9000:9000".into()], env: vec![], volumes: vec!["thelounge_data:/var/opt/thelounge".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "matterbridge".into(), name: "Matterbridge".into(), icon: "🌉".into(), category: "Communication".into(), description: "Bridge between IRC, Slack, Discord, Matrix, Telegram, and more".into(), website: Some("https://github.com/42wim/matterbridge".into()), docker: Some(DockerTarget { image: "42wim/matterbridge:latest".into(), ports: vec![], env: vec![], volumes: vec!["matterbridge_config:/etc/matterbridge".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "simplex".into(), name: "SimpleX Chat".into(), icon: "🔐".into(), category: "Communication".into(), description: "Privacy-first messaging — no user IDs, end-to-end encrypted".into(), website: Some("https://simplex.chat".into()), docker: Some(DockerTarget { image: "simplexchat/smp-server:latest".into(), ports: vec!["5223:5223".into()], env: vec![], volumes: vec!["simplex_data:/etc/opt/simplex".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "prometheus-node".into(), name: "Node Exporter".into(), icon: "📊".into(), category: "Monitoring".into(), description: "Prometheus exporter for hardware and OS metrics".into(), website: Some("https://prometheus.io".into()), docker: Some(DockerTarget { image: "prom/node-exporter:latest".into(), ports: vec!["9100:9100".into()], env: vec![], volumes: vec!["/proc:/host/proc:ro".into(), "/sys:/host/sys:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "cadvisor".into(), name: "cAdvisor".into(), icon: "📦".into(), category: "Monitoring".into(), description: "Container resource usage and performance monitoring".into(), website: Some("https://github.com/google/cadvisor".into()), docker: Some(DockerTarget { image: "gcr.io/cadvisor/cadvisor:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["/:/rootfs:ro".into(), "/var/run:/var/run:ro".into(), "/sys:/sys:ro".into(), "/var/lib/docker/:/var/lib/docker:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "victoriametrics".into(), name: "VictoriaMetrics".into(), icon: "📈".into(), category: "Monitoring".into(), description: "Fast and scalable time series database — Prometheus alternative".into(), website: Some("https://victoriametrics.com".into()), docker: Some(DockerTarget { image: "victoriametrics/victoria-metrics:latest".into(), ports: vec!["8428:8428".into()], env: vec![], volumes: vec!["victoriametrics_data:/victoria-metrics-data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "telegraf".into(), name: "Telegraf".into(), icon: "📡".into(), category: "Monitoring".into(), description: "Plugin-driven server agent for collecting metrics".into(), website: Some("https://www.influxdata.com/time-series-platform/telegraf/".into()), docker: Some(DockerTarget { image: "telegraf:latest".into(), ports: vec![], env: vec![], volumes: vec!["telegraf_config:/etc/telegraf".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "wakapi".into(), name: "Wakapi".into(), icon: "⏱️".into(), category: "Dev Tools".into(), description: "WakaTime-compatible coding statistics dashboard".into(), website: Some("https://wakapi.dev".into()), docker: Some(DockerTarget { image: "ghcr.io/muety/wakapi:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["wakapi_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "mermaid-live".into(), name: "Mermaid Live Editor".into(), icon: "🧜".into(), category: "Dev Tools".into(), description: "Live editor for Mermaid diagrams — flowcharts, sequence, gantt".into(), website: Some("https://mermaid.live".into()), docker: Some(DockerTarget { image: "ghcr.io/mermaid-js/mermaid-live-editor:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "wiki-md".into(), name: "Wiki.md".into(), icon: "📝".into(), category: "CMS".into(), description: "Minimal file-based wiki — just Markdown files, no database".into(), website: Some("https://github.com/niccokunzmann/wiki.md".into()), docker: Some(DockerTarget { image: "niccokunzmann/wiki.md:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["wikimd_data:/wiki".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "docmost".into(), name: "Docmost".into(), icon: "📖".into(), category: "CMS".into(), description: "Collaborative wiki and documentation — Notion/Confluence alternative".into(), website: Some("https://docmost.com".into()), docker: Some(DockerTarget { image: "docmost/docmost:latest".into(), ports: vec!["3000:3000".into()], env: vec!["APP_SECRET=${SECRET_KEY}".into()], volumes: vec!["docmost_data:/app/data/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "SECRET_KEY".into(), label: "App Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] }] },

        AppManifest { id: "pi-kvm".into(), name: "PiKVM".into(), icon: "🖥️".into(), category: "Other".into(), description: "Open-source IP-KVM for remote server management".into(), website: Some("https://pikvm.org".into()), docker: Some(DockerTarget { image: "pikvm/kvmd:latest".into(), ports: vec!["8080:80".into(), "8443:443".into()], env: vec![], volumes: vec!["pikvm_data:/etc/kvmd".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "netboot".into(), name: "Netboot.xyz".into(), icon: "🌐".into(), category: "Other".into(), description: "PXE boot server — boot any OS installer over the network".into(), website: Some("https://netboot.xyz".into()), docker: Some(DockerTarget { image: "linuxserver/netbootxyz:latest".into(), ports: vec!["3000:3000".into(), "69:69/udp".into(), "8080:80".into()], env: vec![], volumes: vec!["netboot_config:/config".into(), "netboot_assets:/assets".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "uptimerobot".into(), name: "Uptime Robot".into(), icon: "🤖".into(), category: "Other".into(), description: "Status page for Uptime Robot monitors".into(), website: Some("https://github.com/louislam/uptime-kuma".into()), docker: Some(DockerTarget { image: "louislam/uptime-kuma:latest".into(), ports: vec!["3001:3001".into()], env: vec![], volumes: vec!["uptimerobot_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "statping".into(), name: "Statping-ng".into(), icon: "📊".into(), category: "Other".into(), description: "Status page and monitoring for websites and applications".into(), website: Some("https://github.com/statping-ng/statping-ng".into()), docker: Some(DockerTarget { image: "adamboutcher/statping-ng:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["statping_data:/app".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "webtop".into(), name: "Webtop".into(), icon: "🖥️".into(), category: "Other".into(), description: "Full Linux desktop in the browser — Ubuntu, Fedora, Alpine".into(), website: Some("https://github.com/linuxserver/docker-webtop".into()), docker: Some(DockerTarget { image: "linuxserver/webtop:ubuntu-xfce".into(), ports: vec!["3000:3000".into(), "3001:3001".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["webtop_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "kasm".into(), name: "Kasm Workspaces".into(), icon: "🖥️".into(), category: "Other".into(), description: "Streaming containerised apps and desktops to the browser".into(), website: Some("https://kasmweb.com".into()), docker: Some(DockerTarget { image: "kasmweb/core:latest".into(), ports: vec!["443:443".into()], env: vec![], volumes: vec!["kasm_data:/opt/kasm".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "reactive-resume".into(), name: "Reactive Resume".into(), icon: "📄".into(), category: "Other".into(), description: "Beautiful resume builder with real-time preview".into(), website: Some("https://rxresu.me".into()), docker: Some(DockerTarget { image: "amruthpillai/reactive-resume:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "inventree".into(), name: "InvenTree".into(), icon: "📦".into(), category: "Other".into(), description: "Inventory management for electronics and parts".into(), website: Some("https://inventree.org".into()), docker: Some(DockerTarget { image: "inventree/inventree:stable".into(), ports: vec!["1337:8000".into()], env: vec!["INVENTREE_DB_ENGINE=sqlite3".into()], volumes: vec!["inventree_data:/home/inventree/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "snipe-it".into(), name: "Snipe-IT".into(), icon: "🏷️".into(), category: "Other".into(), description: "IT asset management — track hardware, software, licenses".into(), website: Some("https://snipeitapp.com".into()), docker: Some(DockerTarget { image: "snipe/snipe-it:latest".into(), ports: vec!["8080:80".into()], env: vec!["APP_KEY=${APP_KEY}".into(), "DB_HOST=snipeit-db".into(), "DB_DATABASE=snipeit".into(), "DB_USERNAME=snipeit".into(), "DB_PASSWORD=${DB_PASSWORD}".into(), "APP_URL=http://localhost:8080".into()], volumes: vec!["snipeit_data:/var/lib/snipeit".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "mariadb:10".into(), ports: vec![], env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=snipeit".into(), "MYSQL_USER=snipeit".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["snipeit_db:/var/lib/mysql".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "APP_KEY".into(), label: "App Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("base64:... (32-char random)".into()), options: vec![] }, UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] }] },
        AppManifest { id: "grocy".into(), name: "Grocy".into(), icon: "🛒".into(), category: "Other".into(), description: "Groceries and household management — shopping lists, recipes, stock".into(), website: Some("https://grocy.info".into()), docker: Some(DockerTarget { image: "linuxserver/grocy:latest".into(), ports: vec!["9283:80".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["grocy_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "mealie".into(), name: "Mealie".into(), icon: "🍽️".into(), category: "Other".into(), description: "Recipe management with meal planning and shopping lists".into(), website: Some("https://mealie.io".into()), docker: Some(DockerTarget { image: "ghcr.io/mealie-recipes/mealie:latest".into(), ports: vec!["9925:9000".into()], env: vec![], volumes: vec!["mealie_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "homebox".into(), name: "Homebox".into(), icon: "📦".into(), category: "Other".into(), description: "Home inventory management with labels and locations".into(), website: Some("https://hay-kot.github.io/homebox/".into()), docker: Some(DockerTarget { image: "ghcr.io/hay-kot/homebox:latest".into(), ports: vec!["7745:7745".into()], env: vec![], volumes: vec!["homebox_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "semaphore".into(), name: "Semaphore".into(), icon: "🏗️".into(), category: "Automation".into(), description: "Modern Ansible UI — run playbooks from the browser".into(), website: Some("https://www.semui.co".into()), docker: Some(DockerTarget { image: "semaphoreui/semaphore:latest".into(), ports: vec!["3000:3000".into()], env: vec!["SEMAPHORE_DB_DIALECT=bolt".into(), "SEMAPHORE_ADMIN_PASSWORD=${ADMIN_PASSWORD}".into(), "SEMAPHORE_ADMIN_NAME=admin".into(), "SEMAPHORE_ADMIN_EMAIL=admin@localhost".into(), "SEMAPHORE_ADMIN=admin".into()], volumes: vec!["semaphore_data:/var/lib/semaphore".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Semaphore admin password".into()), options: vec![] }] },
        // AWX removed — not distributed as a single container; the
        // upstream project only supports install via the AWX Operator
        // on Kubernetes. quay.io/awx/awx:latest pulls but won't run
        // standalone.
        AppManifest { id: "rundeck".into(), name: "Rundeck".into(), icon: "⚙️".into(), category: "Automation".into(), description: "Runbook automation — schedule and run operational tasks".into(), website: Some("https://www.rundeck.com".into()), docker: Some(DockerTarget { image: "rundeck/rundeck:latest".into(), ports: vec!["4440:4440".into()], env: vec![], volumes: vec!["rundeck_data:/home/rundeck/server/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // Mastodon — web + sidekiq worker + streaming + Postgres +
        // Redis. All three Mastodon containers run the same image with
        // different commands. Secrets (SECRET_KEY_BASE, OTP_SECRET,
        // VAPID keys) are collected up-front as user inputs.
        AppManifest { id: "mastodon".into(), name: "Mastodon".into(), icon: "🐘".into(), category: "Communication".into(),
            description: "Decentralised social network — Twitter/X alternative".into(),
            website: Some("https://joinmastodon.org".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/mastodon/mastodon:latest".into(),
                ports: vec!["3030:3000".into()],
                env: vec![
                    "LOCAL_DOMAIN=${LOCAL_DOMAIN}".into(),
                    "SINGLE_USER_MODE=false".into(),
                    "SECRET_KEY_BASE=${SECRET_KEY_BASE}".into(),
                    "OTP_SECRET=${OTP_SECRET}".into(),
                    "VAPID_PRIVATE_KEY=${VAPID_PRIVATE_KEY}".into(),
                    "VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY}".into(),
                    "DB_HOST=${CONTAINER_NAME}-db".into(),
                    "DB_USER=mastodon".into(),
                    "DB_NAME=mastodon".into(),
                    "DB_PASS=${DB_PASSWORD}".into(),
                    "REDIS_HOST=${CONTAINER_NAME}-redis".into(),
                    "RAILS_ENV=production".into(),
                ],
                volumes: vec!["mastodon_public:/mastodon/public/system".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(), image: "postgres:15-alpine".into(),
                        ports: vec![],
                        env: vec![
                            "POSTGRES_USER=mastodon".into(),
                            "POSTGRES_PASSWORD=${DB_PASSWORD}".into(),
                            "POSTGRES_DB=mastodon".into(),
                        ],
                        volumes: vec!["mastodon_db:/var/lib/postgresql/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "redis".into(), image: "redis:7-alpine".into(),
                        ports: vec![], env: vec![],
                        volumes: vec!["mastodon_redis:/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "sidekiq".into(), image: "ghcr.io/mastodon/mastodon:latest".into(),
                        ports: vec![],
                        env: vec![
                            "LOCAL_DOMAIN=${LOCAL_DOMAIN}".into(),
                            "SECRET_KEY_BASE=${SECRET_KEY_BASE}".into(),
                            "OTP_SECRET=${OTP_SECRET}".into(),
                            "VAPID_PRIVATE_KEY=${VAPID_PRIVATE_KEY}".into(),
                            "VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY}".into(),
                            "DB_HOST=${CONTAINER_NAME}-db".into(),
                            "DB_USER=mastodon".into(),
                            "DB_NAME=mastodon".into(),
                            "DB_PASS=${DB_PASSWORD}".into(),
                            "REDIS_HOST=${CONTAINER_NAME}-redis".into(),
                            "RAILS_ENV=production".into(),
                        ],
                        volumes: vec!["mastodon_public:/mastodon/public/system".into()],
                        cmd: vec!["bundle".into(), "exec".into(), "sidekiq".into()],
                        post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "streaming".into(), image: "ghcr.io/mastodon/mastodon-streaming:latest".into(),
                        ports: vec!["4040:4000".into()],
                        env: vec![
                            "LOCAL_DOMAIN=${LOCAL_DOMAIN}".into(),
                            "DB_HOST=${CONTAINER_NAME}-db".into(),
                            "DB_USER=mastodon".into(),
                            "DB_NAME=mastodon".into(),
                            "DB_PASS=${DB_PASSWORD}".into(),
                            "REDIS_HOST=${CONTAINER_NAME}-redis".into(),
                        ],
                        volumes: vec![],
                        cmd: vec![], post_install_exec: vec![],
                    },
                ],
                seed_files: vec![],
                // `db:prepare` is idempotent: creates the database on
                // first install, then only runs pending migrations on
                // subsequent starts. `db:migrate` alone would fail on
                // first boot because the DB doesn't exist yet.
                cmd: vec!["bash".into(), "-c".into(), "bundle exec rake db:prepare && bundle exec rails s -p 3000".into()],
            }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "LOCAL_DOMAIN".into(), label: "Instance Domain".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("e.g. social.example.com".into()), options: vec![] },
                UserInput { id: "SECRET_KEY_BASE".into(), label: "Secret Key Base".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("128-char hex (bundle exec rails secret)".into()), options: vec![] },
                UserInput { id: "OTP_SECRET".into(), label: "OTP Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("128-char hex (rails secret)".into()), options: vec![] },
                UserInput { id: "VAPID_PRIVATE_KEY".into(), label: "VAPID Private Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("rake mastodon:webpush:generate_vapid_key".into()), options: vec![] },
                UserInput { id: "VAPID_PUBLIC_KEY".into(), label: "VAPID Public Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("from same rake task".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Postgres password".into()), options: vec![] },
            ],
        },

        // Pixelfed — Laravel app + Postgres + Redis + horizon worker.
        AppManifest { id: "pixelfed".into(), name: "Pixelfed".into(), icon: "📸".into(), category: "Communication".into(),
            description: "Decentralised photo sharing — Instagram alternative".into(),
            website: Some("https://pixelfed.org".into()),
            docker: Some(DockerTarget {
                image: "zknt/pixelfed:latest".into(),
                ports: vec!["8088:80".into()],
                env: vec![
                    "APP_NAME=Pixelfed".into(),
                    "APP_URL=${APP_URL}".into(),
                    "APP_DOMAIN=${APP_DOMAIN}".into(),
                    "APP_KEY=${APP_KEY}".into(),
                    "DB_CONNECTION=pgsql".into(),
                    "DB_HOST=${CONTAINER_NAME}-db".into(),
                    "DB_PORT=5432".into(),
                    "DB_DATABASE=pixelfed".into(),
                    "DB_USERNAME=pixelfed".into(),
                    "DB_PASSWORD=${DB_PASSWORD}".into(),
                    "REDIS_HOST=${CONTAINER_NAME}-redis".into(),
                    "CACHE_DRIVER=redis".into(),
                    "QUEUE_DRIVER=redis".into(),
                    "SESSION_DRIVER=redis".into(),
                ],
                volumes: vec!["pixelfed_storage:/var/www/storage".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(), image: "postgres:15-alpine".into(),
                        ports: vec![],
                        env: vec!["POSTGRES_USER=pixelfed".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into(), "POSTGRES_DB=pixelfed".into()],
                        volumes: vec!["pixelfed_db:/var/lib/postgresql/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "redis".into(), image: "redis:7-alpine".into(),
                        ports: vec![], env: vec![],
                        volumes: vec!["pixelfed_redis:/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                ],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "APP_URL".into(), label: "App URL".into(), input_type: "text".into(), default: Some("http://localhost:8088".into()), required: true, placeholder: Some("e.g. https://pixel.example.com".into()), options: vec![] },
                UserInput { id: "APP_DOMAIN".into(), label: "Domain".into(), input_type: "text".into(), default: Some("localhost:8088".into()), required: true, placeholder: Some("e.g. pixel.example.com".into()), options: vec![] },
                UserInput { id: "APP_KEY".into(), label: "App Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("base64:… (32-byte random, `php artisan key:generate`)".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Postgres password".into()), options: vec![] },
            ],
        },

        // Lemmy — backend + lemmy-ui (separate image) + Postgres + pictrs.
        // The backend reads /config/config.hjson on startup and exits
        // if it's missing, so we seed a minimal file via seed_files.
        AppManifest { id: "lemmy".into(), name: "Lemmy".into(), icon: "🐭".into(), category: "Communication".into(),
            description: "Federated link aggregator — Reddit alternative".into(),
            website: Some("https://join-lemmy.org".into()),
            docker: Some(DockerTarget {
                image: "dessalines/lemmy:latest".into(),
                ports: vec!["8536:8536".into()],
                env: vec![
                    "LEMMY_CONFIG_LOCATION=/config/config.hjson".into(),
                    "RUST_LOG=warn".into(),
                ],
                volumes: vec!["lemmy_data:/config".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(), image: "postgres:15-alpine".into(),
                        ports: vec![],
                        env: vec!["POSTGRES_USER=lemmy".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into(), "POSTGRES_DB=lemmy".into()],
                        volumes: vec!["lemmy_db:/var/lib/postgresql/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "ui".into(), image: "dessalines/lemmy-ui:latest".into(),
                        ports: vec!["1235:1234".into()],
                        env: vec![
                            "LEMMY_UI_LEMMY_INTERNAL_HOST=${CONTAINER_NAME}:8536".into(),
                            "LEMMY_UI_LEMMY_EXTERNAL_HOST=${EXTERNAL_HOST}".into(),
                            "LEMMY_UI_HTTPS=false".into(),
                        ],
                        volumes: vec![],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "pictrs".into(), image: "asonix/pictrs:0.5".into(),
                        ports: vec![],
                        env: vec!["PICTRS__SERVER__API_KEY=${PICTRS_API_KEY}".into()],
                        volumes: vec!["lemmy_pictrs:/mnt".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                ],
                seed_files: vec![SeedFile {
                    container_path: "/config/config.hjson".into(),
                    content: "{\n  database: {\n    host: \"${CONTAINER_NAME}-db\"\n    port: 5432\n    user: \"lemmy\"\n    password: \"${DB_PASSWORD}\"\n    database: \"lemmy\"\n  }\n  hostname: \"${EXTERNAL_HOST}\"\n  bind: \"0.0.0.0\"\n  port: 8536\n  tls_enabled: false\n  pictrs: {\n    url: \"http://${CONTAINER_NAME}-pictrs:8080/\"\n    api_key: \"${PICTRS_API_KEY}\"\n  }\n}\n".into(),
                }],
                cmd: vec![],
            }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "EXTERNAL_HOST".into(), label: "External Hostname".into(), input_type: "text".into(), default: Some("localhost:1235".into()), required: true, placeholder: Some("e.g. lemmy.example.com".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Postgres password".into()), options: vec![] },
                UserInput { id: "PICTRS_API_KEY".into(), label: "Pictrs API Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random string for pictrs auth".into()), options: vec![] },
            ],
        },

        // Misskey — app + Postgres + Redis. The Misskey image does
        // NOT honour MISSKEY_* env vars for DB / URL; it reads its
        // config from /misskey/.config/default.yml. We seed that file
        // at install time so the single-container install actually
        // boots. Image lives at ghcr.io/misskey-dev, not docker.io.
        AppManifest { id: "misskey".into(), name: "Misskey".into(), icon: "🌟".into(), category: "Communication".into(),
            description: "Decentralised social media with customisable UI".into(),
            website: Some("https://misskey-hub.net".into()),
            docker: Some(DockerTarget {
                image: "ghcr.io/misskey-dev/misskey:latest".into(),
                ports: vec!["3033:3000".into()],
                env: vec![
                    "NODE_ENV=production".into(),
                ],
                volumes: vec!["misskey_files:/misskey/files".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "db".into(), image: "postgres:15-alpine".into(),
                        ports: vec![],
                        env: vec!["POSTGRES_USER=misskey".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into(), "POSTGRES_DB=misskey".into()],
                        volumes: vec!["misskey_db:/var/lib/postgresql/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "redis".into(), image: "redis:7-alpine".into(),
                        ports: vec![], env: vec![],
                        volumes: vec!["misskey_redis:/data".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                ],
                seed_files: vec![SeedFile {
                    container_path: "/misskey/.config/default.yml".into(),
                    content: "url: ${MISSKEY_URL}\nport: 3000\ndb:\n  host: ${CONTAINER_NAME}-db\n  port: 5432\n  db: misskey\n  user: misskey\n  pass: ${DB_PASSWORD}\nredis:\n  host: ${CONTAINER_NAME}-redis\n  port: 6379\nid: 'aidx'\n".into(),
                }],
                cmd: vec![],
            }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "MISSKEY_URL".into(), label: "Instance URL".into(), input_type: "text".into(), default: Some("http://localhost:3033".into()), required: true, placeholder: Some("e.g. https://misskey.example.com".into()), options: vec![] },
                UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Postgres password".into()), options: vec![] },
            ],
        },

        AppManifest { id: "supavisor".into(), name: "Supavisor".into(), icon: "🐘".into(), category: "Database".into(), description: "Scalable PostgreSQL connection pooler by Supabase".into(), website: Some("https://github.com/supabase/supavisor".into()), docker: Some(DockerTarget { image: "supabase/supavisor:latest".into(), ports: vec!["4000:4000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "pgbouncer".into(), name: "PgBouncer".into(), icon: "🏀".into(), category: "Database".into(), description: "Lightweight PostgreSQL connection pooler".into(), website: Some("https://www.pgbouncer.org".into()), docker: Some(DockerTarget { image: "edoburu/pgbouncer:latest".into(), ports: vec!["5432:5432".into()], env: vec!["DATABASE_URL=postgres://postgres:${DB_PASSWORD}@db:5432/postgres".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] }] },

        AppManifest { id: "crowdsec-console".into(), name: "CrowdSec Console".into(), icon: "🛡️".into(), category: "Security".into(), description: "CrowdSec dashboard — view blocked IPs and threat data".into(), website: Some("https://crowdsec.net".into()), docker: Some(DockerTarget { image: "crowdsecurity/crowdsec:latest".into(), ports: vec!["8080:8080".into(), "6060:6060".into()], env: vec![], volumes: vec!["crowdsec_data:/var/lib/crowdsec/data".into(), "crowdsec_config:/etc/crowdsec".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "gotenberg".into(), name: "Gotenberg".into(), icon: "📄".into(), category: "Dev Tools".into(), description: "API-based document conversion — HTML/Markdown/Office to PDF".into(), website: Some("https://gotenberg.dev".into()), docker: Some(DockerTarget { image: "gotenberg/gotenberg:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "docspell".into(), name: "Docspell".into(), icon: "📁".into(), category: "Productivity".into(), description: "Document management with full-text search and OCR".into(), website: Some("https://docspell.org".into()), docker: Some(DockerTarget { image: "docspell/restserver:latest".into(), ports: vec!["7880:7880".into()], env: vec![], volumes: vec!["docspell_data:/opt/docspell".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "crowdsec-hub".into(), name: "Maloja".into(), icon: "🎵".into(), category: "Media".into(), description: "Self-hosted music scrobble database — Last.fm alternative".into(), website: Some("https://github.com/krateng/maloja".into()), docker: Some(DockerTarget { image: "krateng/maloja:latest".into(), ports: vec!["42010:42010".into()], env: vec![], volumes: vec!["maloja_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "tdarr".into(), name: "Tdarr".into(), icon: "🎬".into(), category: "Media".into(), description: "Distributed transcoding — automatically convert media libraries".into(), website: Some("https://tdarr.io".into()), docker: Some(DockerTarget { image: "ghcr.io/haveagitgat/tdarr:latest".into(), ports: vec!["8265:8265".into(), "8266:8266".into()], env: vec![], volumes: vec!["tdarr_server:/app/server".into(), "tdarr_config:/app/configs".into(), "tdarr_logs:/app/logs".into(), "${MEDIA_PATH}:/media".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "MEDIA_PATH".into(), label: "Media Path".into(), input_type: "text".into(), default: Some("/opt/media".into()), required: true, placeholder: None, options: vec![] }] },

        AppManifest { id: "traggo-v2".into(), name: "Wakapi (coding stats)".into(), icon: "📊".into(), category: "Productivity".into(), description: "WakaTime-compatible coding activity dashboard".into(), website: Some("https://wakapi.dev".into()), docker: Some(DockerTarget { image: "ghcr.io/muety/wakapi:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["wakapi_v2_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "mirotalk".into(), name: "MiroTalk".into(), icon: "📹".into(), category: "Communication".into(), description: "WebRTC video calls — Zoom alternative, no account required".into(), website: Some("https://mirotalk.com".into()), docker: Some(DockerTarget { image: "mirotalk/p2p:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        // Jitsi Meet — 4 containers (web, prosody XMPP, jicofo focus,
        // jvb video bridge). Shared XMPP auth secrets make env setup
        // verbose; 10000/udp on jvb is what actually carries video.
        AppManifest { id: "jitsi".into(), name: "Jitsi Meet".into(), icon: "📞".into(), category: "Communication".into(),
            description: "Secure video conferencing — no account needed to join".into(),
            website: Some("https://jitsi.org".into()),
            docker: Some(DockerTarget {
                image: "jitsi/web:latest".into(),
                ports: vec!["8010:80".into(), "8453:443".into()],
                env: vec![
                    "ENABLE_AUTH=0".into(),
                    "ENABLE_GUESTS=1".into(),
                    "PUBLIC_URL=${PUBLIC_URL}".into(),
                    "XMPP_DOMAIN=meet.jitsi".into(),
                    "XMPP_AUTH_DOMAIN=auth.meet.jitsi".into(),
                    "XMPP_BOSH_URL_BASE=http://${CONTAINER_NAME}-prosody:5280".into(),
                    "XMPP_GUEST_DOMAIN=guest.meet.jitsi".into(),
                    "XMPP_MUC_DOMAIN=muc.meet.jitsi".into(),
                    "JICOFO_AUTH_USER=focus".into(),
                    "JVB_AUTH_USER=jvb".into(),
                    "TZ=UTC".into(),
                ],
                volumes: vec!["jitsi_web:/config".into()],
                sidecars: vec![
                    DockerSidecar {
                        name_suffix: "prosody".into(), image: "jitsi/prosody:latest".into(),
                        ports: vec![],
                        env: vec![
                            "XMPP_DOMAIN=meet.jitsi".into(),
                            "XMPP_AUTH_DOMAIN=auth.meet.jitsi".into(),
                            "XMPP_GUEST_DOMAIN=guest.meet.jitsi".into(),
                            "XMPP_MUC_DOMAIN=muc.meet.jitsi".into(),
                            "XMPP_INTERNAL_MUC_DOMAIN=internal-muc.meet.jitsi".into(),
                            "JICOFO_COMPONENT_SECRET=${JICOFO_COMPONENT_SECRET}".into(),
                            "JICOFO_AUTH_USER=focus".into(),
                            "JICOFO_AUTH_PASSWORD=${JICOFO_AUTH_PASSWORD}".into(),
                            "JVB_AUTH_USER=jvb".into(),
                            "JVB_AUTH_PASSWORD=${JVB_AUTH_PASSWORD}".into(),
                            "TZ=UTC".into(),
                        ],
                        volumes: vec!["jitsi_prosody_config:/config".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "jicofo".into(), image: "jitsi/jicofo:latest".into(),
                        ports: vec![],
                        env: vec![
                            "XMPP_DOMAIN=meet.jitsi".into(),
                            "XMPP_AUTH_DOMAIN=auth.meet.jitsi".into(),
                            "XMPP_INTERNAL_MUC_DOMAIN=internal-muc.meet.jitsi".into(),
                            "XMPP_SERVER=${CONTAINER_NAME}-prosody".into(),
                            "JICOFO_COMPONENT_SECRET=${JICOFO_COMPONENT_SECRET}".into(),
                            "JICOFO_AUTH_USER=focus".into(),
                            "JICOFO_AUTH_PASSWORD=${JICOFO_AUTH_PASSWORD}".into(),
                            "TZ=UTC".into(),
                        ],
                        volumes: vec!["jitsi_jicofo_config:/config".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                    DockerSidecar {
                        name_suffix: "jvb".into(), image: "jitsi/jvb:latest".into(),
                        ports: vec!["10000:10000/udp".into()],
                        env: vec![
                            "XMPP_AUTH_DOMAIN=auth.meet.jitsi".into(),
                            "XMPP_INTERNAL_MUC_DOMAIN=internal-muc.meet.jitsi".into(),
                            "XMPP_SERVER=${CONTAINER_NAME}-prosody".into(),
                            "JVB_AUTH_USER=jvb".into(),
                            "JVB_AUTH_PASSWORD=${JVB_AUTH_PASSWORD}".into(),
                            "JVB_PORT=10000".into(),
                            "TZ=UTC".into(),
                        ],
                        volumes: vec!["jitsi_jvb_config:/config".into()],
                        cmd: vec![], post_install_exec: vec![],
                    },
                ],
                seed_files: vec![], cmd: vec![],
            }),
            lxc: None, bare_metal: None, vm: None, user_inputs: vec![
                UserInput { id: "PUBLIC_URL".into(), label: "Public URL".into(), input_type: "text".into(), default: Some("http://localhost:8010".into()), required: true, placeholder: Some("e.g. https://meet.example.com".into()), options: vec![] },
                UserInput { id: "JICOFO_COMPONENT_SECRET".into(), label: "Jicofo Component Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random string (openssl rand -hex 16)".into()), options: vec![] },
                UserInput { id: "JICOFO_AUTH_PASSWORD".into(), label: "Jicofo Auth Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random string".into()), options: vec![] },
                UserInput { id: "JVB_AUTH_PASSWORD".into(), label: "JVB Auth Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random string".into()), options: vec![] },
            ],
        },

        AppManifest { id: "livebook".into(), name: "Livebook".into(), icon: "📓".into(), category: "AI / ML".into(), description: "Interactive Elixir notebooks for data exploration and ML".into(), website: Some("https://livebook.dev".into()), docker: Some(DockerTarget { image: "ghcr.io/livebook-dev/livebook:latest".into(), ports: vec!["8080:8080".into(), "8081:8081".into()], env: vec!["LIVEBOOK_PASSWORD=${PASSWORD}".into()], volumes: vec!["livebook_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "PASSWORD".into(), label: "Access Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Min 12 characters".into()), options: vec![] }] },
        AppManifest { id: "comfyui".into(), name: "ComfyUI".into(), icon: "🎨".into(), category: "AI / ML".into(), description: "Node-based Stable Diffusion UI for advanced workflows".into(), website: Some("https://github.com/comfyanonymous/ComfyUI".into()), docker: Some(DockerTarget { image: "ghcr.io/ai-dock/comfyui:latest-cpu".into(), ports: vec!["8188:8188".into()], env: vec![], volumes: vec!["comfyui_models:/opt/ComfyUI/models".into(), "comfyui_output:/opt/ComfyUI/output".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // cloudflared's image has ENTRYPOINT `cloudflared` with NO default CMD —
        // `docker run` without args just prints help and exits. The tunnel must
        // be started with `tunnel --no-autoupdate run` and a token. We set
        // TUNNEL_TOKEN via env (cloudflared reads it) AND pass the subcommand
        // explicitly via cmd so the container actually does something.
        AppManifest { id: "cloudflared".into(), name: "Cloudflare Tunnel".into(), icon: "☁️".into(), category: "Networking".into(), description: "Expose local services to the internet via Cloudflare — no port forwarding".into(), website: Some("https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/".into()), docker: Some(DockerTarget { image: "cloudflare/cloudflared:latest".into(), ports: vec![], env: vec!["TUNNEL_TOKEN=${TUNNEL_TOKEN}".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec!["tunnel".into(), "--no-autoupdate".into(), "run".into()] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "TUNNEL_TOKEN".into(), label: "Tunnel Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("From Cloudflare dashboard".into()), options: vec![] }] },
        AppManifest { id: "frp".into(), name: "frp".into(), icon: "🔌".into(), category: "Networking".into(), description: "Fast reverse proxy to expose local servers behind NAT/firewall".into(), website: Some("https://github.com/fatedier/frp".into()), docker: Some(DockerTarget { image: "snowdreamtech/frps:latest".into(), ports: vec!["7000:7000".into(), "7500:7500".into()], env: vec![], volumes: vec!["frp_config:/etc/frp".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "bore".into(), name: "Bore".into(), icon: "🕳️".into(), category: "Networking".into(), description: "Simple TCP tunnel to expose local ports — ngrok alternative".into(), website: Some("https://github.com/ekzhang/bore".into()), docker: Some(DockerTarget { image: "ekzhang/bore:latest".into(), ports: vec!["7835:7835".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "terraria-tshock".into(), name: "Terraria TShock".into(), icon: "⛏️".into(), category: "Gaming".into(), description: "Terraria server with TShock plugin framework".into(), website: Some("https://tshock.co".into()), docker: Some(DockerTarget { image: "ryshe/terraria:tshock-latest".into(), ports: vec!["7777:7777".into()], env: vec![], volumes: vec!["terraria_tshock_data:/root/.local/share/Terraria/Worlds".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "openttd".into(), name: "OpenTTD".into(), icon: "🚂".into(), category: "Gaming".into(), description: "Open-source Transport Tycoon Deluxe dedicated server".into(), website: Some("https://www.openttd.org".into()), docker: Some(DockerTarget { image: "bateau/openttd:latest".into(), ports: vec!["3979:3979/tcp".into(), "3979:3979/udp".into()], env: vec![], volumes: vec!["openttd_data:/home/openttd/.openttd".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "sonarr-v4".into(), name: "Whisparr".into(), icon: "📡".into(), category: "Media".into(), description: "Media manager for adult content — Servarr stack compatible".into(), website: Some("https://wiki.servarr.com/whisparr".into()), docker: Some(DockerTarget { image: "hotio/whisparr:latest".into(), ports: vec!["6969:6969".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["whisparr_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "recyclarr".into(), name: "Recyclarr".into(), icon: "♻️".into(), category: "Media".into(), description: "Auto-sync quality profiles for Sonarr and Radarr from TRaSH guides".into(), website: Some("https://recyclarr.dev".into()), docker: Some(DockerTarget { image: "ghcr.io/recyclarr/recyclarr:latest".into(), ports: vec![], env: vec![], volumes: vec!["recyclarr_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "apitable".into(), name: "APITable".into(), icon: "📊".into(), category: "Productivity".into(), description: "Airtable alternative — spreadsheet-database hybrid with API".into(), website: Some("https://apitable.com".into()), docker: Some(DockerTarget { image: "apitable/init-appdata:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["apitable_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "teable".into(), name: "Teable".into(), icon: "📋".into(), category: "Productivity".into(), description: "No-code database — Airtable alternative built on PostgreSQL".into(), website: Some("https://teable.io".into()), docker: Some(DockerTarget { image: "ghcr.io/teableio/teable:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["teable_data:/app/.assets".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "lobe-chat".into(), name: "Lobe Chat".into(), icon: "💬".into(), category: "AI / ML".into(), description: "Modern AI chat framework — multi-model, plugins, knowledge base".into(), website: Some("https://lobehub.com".into()), docker: Some(DockerTarget { image: "lobehub/lobe-chat:latest".into(), ports: vec!["3210:3210".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "rallly-v2".into(), name: "Cal.com".into(), icon: "📅".into(), category: "Productivity".into(), description: "Scheduling infrastructure — Calendly alternative".into(), website: Some("https://cal.com".into()), docker: Some(DockerTarget { image: "calcom/cal.com:latest".into(), ports: vec!["3000:3000".into()], env: vec!["NEXTAUTH_SECRET=${SECRET_KEY}".into(), "CALENDSO_ENCRYPTION_KEY=${ENC_KEY}".into(), "DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@calcom-db:5432/calcom".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=calcom".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["calcom_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "SECRET_KEY".into(), label: "NextAuth Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret".into()), options: vec![] }, UserInput { id: "ENC_KEY".into(), label: "Encryption Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("32-char random key".into()), options: vec![] }, UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] }] },


        // ═══════════════════════════════════════════════════════════════
        // Batch 5 — final 69 to reach 500
        // ═══════════════════════════════════════════════════════════════

        AppManifest { id: "libreoffice-online".into(), name: "LibreOffice Online".into(), icon: "📄".into(), category: "Productivity".into(), description: "Full LibreOffice suite accessible from the browser".into(), website: Some("https://www.libreoffice.org".into()), docker: Some(DockerTarget { image: "libreoffice/online:latest".into(), ports: vec!["9980:9980".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "xwiki".into(), name: "XWiki".into(), icon: "📝".into(), category: "CMS".into(), description: "Enterprise wiki with structured data and extensions".into(), website: Some("https://www.xwiki.org".into()), docker: Some(DockerTarget { image: "xwiki:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["xwiki_data:/usr/local/xwiki".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "dokuwiki".into(), name: "DokuWiki".into(), icon: "📝".into(), category: "CMS".into(), description: "Simple wiki that doesn't require a database".into(), website: Some("https://www.dokuwiki.org".into()), docker: Some(DockerTarget { image: "linuxserver/dokuwiki:latest".into(), ports: vec!["8080:80".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["dokuwiki_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "mediawiki".into(), name: "MediaWiki".into(), icon: "📖".into(), category: "CMS".into(), description: "The wiki software that powers Wikipedia".into(), website: Some("https://www.mediawiki.org".into()), docker: Some(DockerTarget { image: "mediawiki:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["mediawiki_data:/var/www/html".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "koel".into(), name: "Koel".into(), icon: "🎵".into(), category: "Media".into(), description: "Personal music streaming server with a sleek web UI".into(), website: Some("https://koel.dev".into()), docker: Some(DockerTarget { image: "hyzual/koel:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["koel_music:/music".into(), "koel_covers:/var/www/html/public/img/covers".into(), "koel_search:/var/www/html/storage/search-indexes".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "ampache".into(), name: "Ampache".into(), icon: "🎵".into(), category: "Media".into(), description: "Web-based audio/video streaming and file manager".into(), website: Some("https://ampache.org".into()), docker: Some(DockerTarget { image: "ampache/ampache:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["ampache_config:/var/www/config".into(), "ampache_data:/var/www/data".into(), "${MUSIC_PATH}:/media:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "MUSIC_PATH".into(), label: "Music Path".into(), input_type: "text".into(), default: Some("/opt/media/music".into()), required: true, placeholder: None, options: vec![] }] },

        AppManifest { id: "privatebin-v2".into(), name: "Hastebin".into(), icon: "📋".into(), category: "Dev Tools".into(), description: "Simple pastebin alternative — paste code and share a link".into(), website: Some("https://github.com/toptal/haste-server".into()), docker: Some(DockerTarget { image: "rlister/hastebin:latest".into(), ports: vec!["7777:7777".into()], env: vec![], volumes: vec!["hastebin_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "gitlist".into(), name: "Gitlist".into(), icon: "📂".into(), category: "Dev Tools".into(), description: "Elegant web interface for browsing Git repositories".into(), website: Some("https://gitlist.org".into()), docker: Some(DockerTarget { image: "gitlist/gitlist:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["${REPOS_PATH}:/var/www/gitlist/repos:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "REPOS_PATH".into(), label: "Repos Path".into(), input_type: "text".into(), default: Some("/opt/git".into()), required: true, placeholder: Some("Path to git repos".into()), options: vec![] }] },

        AppManifest { id: "redmine".into(), name: "Redmine".into(), icon: "🔴".into(), category: "Project Management".into(), description: "Flexible project management with issue tracking and Gantt charts".into(), website: Some("https://www.redmine.org".into()), docker: Some(DockerTarget { image: "redmine:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["redmine_data:/usr/src/redmine/files".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "zentao".into(), name: "ZenTao".into(), icon: "📊".into(), category: "Project Management".into(), description: "Agile project management with Scrum and Kanban support".into(), website: Some("https://www.zentao.pm".into()), docker: Some(DockerTarget { image: "easysoft/zentao:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["zentao_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "planka".into(), name: "Planka".into(), icon: "📋".into(), category: "Project Management".into(), description: "Real-time kanban board for workgroups — Trello alternative".into(), website: Some("https://planka.app".into()), docker: Some(DockerTarget { image: "ghcr.io/plankanban/planka:latest".into(), ports: vec!["1337:1337".into()], env: vec!["SECRET_KEY=${SECRET_KEY}".into(), "BASE_URL=http://localhost:1337".into(), "DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@planka-db/planka".into()], volumes: vec!["planka_avatars:/app/public/user-avatars".into(), "planka_bg:/app/public/project-background-images".into(), "planka_attachments:/app/private/attachments".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=planka".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["planka_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] }, UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] }] },

        AppManifest { id: "monica".into(), name: "Monica".into(), icon: "👤".into(), category: "Productivity".into(), description: "Personal CRM — remember everything about your contacts".into(), website: Some("https://www.monicahq.com".into()), docker: Some(DockerTarget { image: "monica:latest".into(), ports: vec!["8080:80".into()], env: vec!["APP_KEY=${APP_KEY}".into(), "DB_HOST=monica-db".into(), "DB_DATABASE=monica".into(), "DB_USERNAME=monica".into(), "DB_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["monica_data:/var/www/html/storage".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "mariadb:10".into(), ports: vec![], env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=monica".into(), "MYSQL_USER=monica".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["monica_db:/var/lib/mysql".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "APP_KEY".into(), label: "App Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("base64:... (32-char random)".into()), options: vec![] }, UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] }] },

        AppManifest { id: "traccar".into(), name: "Traccar".into(), icon: "📍".into(), category: "Other".into(), description: "GPS tracking server for vehicles, people, and assets".into(), website: Some("https://www.traccar.org".into()), docker: Some(DockerTarget { image: "traccar/traccar:latest".into(), ports: vec!["8082:8082".into(), "5055:5055".into()], env: vec![], volumes: vec!["traccar_data:/opt/traccar/data/database".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "haos".into(), name: "Home Assistant OS".into(), icon: "🏠".into(), category: "Automation".into(), description: "Home automation platform — 2000+ integrations".into(), website: Some("https://www.home-assistant.io".into()), docker: Some(DockerTarget { image: "ghcr.io/home-assistant/home-assistant:stable".into(), ports: vec!["8123:8123".into()], env: vec![], volumes: vec!["homeassistant_v2_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "miniflux-v2".into(), name: "Tiny Tiny RSS".into(), icon: "📰".into(), category: "Media".into(), description: "Web-based news feed reader and aggregator".into(), website: Some("https://tt-rss.org".into()), docker: Some(DockerTarget { image: "cthulhoo/ttrss-fpm-pgsql-static:latest".into(), ports: vec!["8280:80".into()], env: vec![], volumes: vec!["ttrss_data:/var/www/html".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "linkace".into(), name: "LinkAce".into(), icon: "🔗".into(), category: "Other".into(), description: "Bookmark archive with tags, lists, and monitoring".into(), website: Some("https://www.linkace.org".into()), docker: Some(DockerTarget { image: "linkace/linkace:latest".into(), ports: vec!["8080:80".into()], env: vec!["APP_KEY=${APP_KEY}".into(), "DB_HOST=linkace-db".into(), "DB_DATABASE=linkace".into(), "DB_USERNAME=linkace".into(), "DB_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["linkace_data:/app/storage".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "mariadb:10".into(), ports: vec![], env: vec!["MYSQL_ROOT_PASSWORD=${DB_PASSWORD}".into(), "MYSQL_DATABASE=linkace".into(), "MYSQL_USER=linkace".into(), "MYSQL_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["linkace_db:/var/lib/mysql".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "APP_KEY".into(), label: "App Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("base64:... (32-char random)".into()), options: vec![] }, UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("MariaDB password".into()), options: vec![] }] },

        AppManifest { id: "budibase".into(), name: "Budibase".into(), icon: "🏗️".into(), category: "Dev Tools".into(), description: "Low-code platform for building internal tools and admin panels".into(), website: Some("https://budibase.com".into()), docker: Some(DockerTarget { image: "budibase/budibase:latest".into(), ports: vec!["10000:80".into()], env: vec![], volumes: vec!["budibase_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "tooljet".into(), name: "ToolJet".into(), icon: "🔧".into(), category: "Dev Tools".into(), description: "Low-code platform for building internal tools with drag and drop".into(), website: Some("https://www.tooljet.com".into()), docker: Some(DockerTarget { image: "tooljet/tooljet:latest".into(), ports: vec!["3000:3000".into()], env: vec!["TOOLJET_HOST=http://localhost:3000".into(), "SECRET_KEY_BASE=${SECRET_KEY}".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret string".into()), options: vec![] }] },
        AppManifest { id: "appsmith".into(), name: "Appsmith".into(), icon: "🏗️".into(), category: "Dev Tools".into(), description: "Low-code platform for building admin panels and dashboards".into(), website: Some("https://www.appsmith.com".into()), docker: Some(DockerTarget { image: "appsmith/appsmith-ee:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["appsmith_data:/appsmith-stacks".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "nzbget".into(), name: "NZBGet".into(), icon: "📥".into(), category: "Media".into(), description: "Efficient Usenet downloader with web interface".into(), website: Some("https://nzbget.com".into()), docker: Some(DockerTarget { image: "linuxserver/nzbget:latest".into(), ports: vec!["6789:6789".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["nzbget_config:/config".into(), "${DOWNLOAD_PATH}:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] }] },
        AppManifest { id: "deluge".into(), name: "Deluge".into(), icon: "🔽".into(), category: "Media".into(), description: "Lightweight BitTorrent client with web interface and plugins".into(), website: Some("https://deluge-torrent.org".into()), docker: Some(DockerTarget { image: "linuxserver/deluge:latest".into(), ports: vec!["8112:8112".into(), "6881:6881".into(), "6881:6881/udp".into()], env: vec!["PUID=1000".into(), "PGID=1000".into()], volumes: vec!["deluge_config:/config".into(), "${DOWNLOAD_PATH}:/downloads".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "DOWNLOAD_PATH".into(), label: "Downloads Path".into(), input_type: "text".into(), default: Some("/opt/downloads".into()), required: true, placeholder: None, options: vec![] }] },

        AppManifest { id: "seafile-v2".into(), name: "Seafile Pro".into(), icon: "☁️".into(), category: "Productivity".into(), description: "Enterprise file sync with online editing and audit logs".into(), website: Some("https://www.seafile.com/en/product/private_server/".into()), docker: Some(DockerTarget { image: "seafileltd/seafile-mc:latest".into(), ports: vec!["8082:80".into()], env: vec![], volumes: vec!["seafile_pro_data:/shared".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "grafana-oncall".into(), name: "Grafana OnCall".into(), icon: "📟".into(), category: "Monitoring".into(), description: "On-call management and incident response for DevOps teams".into(), website: Some("https://grafana.com/oss/oncall/".into()), docker: Some(DockerTarget { image: "grafana/oncall:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["oncall_data:/var/lib/oncall".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "mimir".into(), name: "Grafana Mimir".into(), icon: "📈".into(), category: "Monitoring".into(), description: "Scalable long-term storage for Prometheus metrics".into(), website: Some("https://grafana.com/oss/mimir/".into()), docker: Some(DockerTarget { image: "grafana/mimir:latest".into(), ports: vec!["9009:9009".into()], env: vec![], volumes: vec!["mimir_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "tempo".into(), name: "Grafana Tempo".into(), icon: "🔎".into(), category: "Monitoring".into(), description: "Distributed tracing backend by Grafana".into(), website: Some("https://grafana.com/oss/tempo/".into()), docker: Some(DockerTarget { image: "grafana/tempo:latest".into(), ports: vec!["3200:3200".into(), "4317:4317".into()], env: vec![], volumes: vec!["tempo_data:/var/tempo".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "coder-v2".into(), name: "Theia IDE".into(), icon: "💻".into(), category: "Dev Tools".into(), description: "Cloud IDE framework — VS Code-like experience in the browser".into(), website: Some("https://theia-ide.org".into()), docker: Some(DockerTarget { image: "theiaide/theia:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["theia_workspace:/home/project".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "mayan-edms".into(), name: "Mayan EDMS".into(), icon: "📁".into(), category: "Productivity".into(), description: "Electronic document management with OCR and workflows".into(), website: Some("https://www.mayan-edms.com".into()), docker: Some(DockerTarget { image: "mayanedms/mayanedms:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["mayan_media:/var/lib/mayan".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "rallly-v3".into(), name: "Doodle Alternative (Rallly)".into(), icon: "📅".into(), category: "Productivity".into(), description: "Schedule group meetings — Doodle alternative".into(), website: Some("https://rallly.co".into()), docker: Some(DockerTarget { image: "lukevella/rallly:latest".into(), ports: vec!["3000:3000".into()], env: vec!["SECRET_PASSWORD=${SECRET_KEY}".into(), "DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@rallly-v3-db:5432/rallly".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=rallly".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["rallly_v3_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "SECRET_KEY".into(), label: "Secret".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret".into()), options: vec![] }, UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] }] },

        AppManifest { id: "squid".into(), name: "Squid Proxy".into(), icon: "🦑".into(), category: "Networking".into(), description: "Caching forward proxy for web content".into(), website: Some("https://www.squid-cache.org".into()), docker: Some(DockerTarget { image: "ubuntu/squid:latest".into(), ports: vec!["3128:3128".into()], env: vec![], volumes: vec!["squid_cache:/var/spool/squid".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "privoxy".into(), name: "Privoxy".into(), icon: "🛡️".into(), category: "Privacy".into(), description: "Non-caching web proxy with ad and tracker filtering".into(), website: Some("https://www.privoxy.org".into()), docker: Some(DockerTarget { image: "vimagick/privoxy:latest".into(), ports: vec!["8118:8118".into()], env: vec![], volumes: vec!["privoxy_config:/etc/privoxy".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "tor-relay".into(), name: "Tor Relay".into(), icon: "🧅".into(), category: "Privacy".into(), description: "Run a Tor relay to support anonymous internet access".into(), website: Some("https://community.torproject.org/relay/".into()), docker: Some(DockerTarget { image: "thetorproject/obfs4-bridge:latest".into(), ports: vec!["9001:9001".into(), "9030:9030".into()], env: vec![], volumes: vec!["tor_data:/var/lib/tor".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "snapcast".into(), name: "Snapcast".into(), icon: "🔊".into(), category: "Media".into(), description: "Synchronous multi-room audio streaming server".into(), website: Some("https://github.com/badaix/snapcast".into()), docker: Some(DockerTarget { image: "ghcr.io/badaix/snapcast:latest".into(), ports: vec!["1704:1704".into(), "1705:1705".into(), "1780:1780".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "synapse-admin".into(), name: "Synapse Admin".into(), icon: "🔧".into(), category: "Communication".into(), description: "Admin UI for Matrix Synapse homeserver management".into(), website: Some("https://github.com/Awesome-Technologies/synapse-admin".into()), docker: Some(DockerTarget { image: "awesometechnologies/synapse-admin:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "sftpgo".into(), name: "SFTPGo".into(), icon: "📂".into(), category: "Other".into(), description: "Full-featured SFTP/FTP/WebDAV server with web admin UI".into(), website: Some("https://sftpgo.com".into()), docker: Some(DockerTarget { image: "drakkan/sftpgo:latest".into(), ports: vec!["8080:8080".into(), "2022:2022".into()], env: vec![], volumes: vec!["sftpgo_data:/srv/sftpgo".into(), "sftpgo_home:/var/lib/sftpgo".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "filestash".into(), name: "Filestash".into(), icon: "📂".into(), category: "Other".into(), description: "Web file manager for FTP, SFTP, S3, Dropbox, and more".into(), website: Some("https://www.filestash.app".into()), docker: Some(DockerTarget { image: "machines/filestash:latest".into(), ports: vec!["8334:8334".into()], env: vec![], volumes: vec!["filestash_data:/app/data/state".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "etebase".into(), name: "Etebase".into(), icon: "🔐".into(), category: "Security".into(), description: "End-to-end encrypted backend for contacts, calendars, and tasks".into(), website: Some("https://www.etebase.com".into()), docker: Some(DockerTarget { image: "victorrds/etebase:latest".into(), ports: vec!["3735:3735".into()], env: vec![], volumes: vec!["etebase_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "bitwarden-rs".into(), name: "Bitwarden (official)".into(), icon: "🔐".into(), category: "Security".into(), description: "Official Bitwarden server for password management".into(), website: Some("https://bitwarden.com".into()), docker: Some(DockerTarget { image: "bitwarden/self-host:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["bitwarden_data:/etc/bitwarden".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "github-runner".into(), name: "GitHub Actions Runner".into(), icon: "🏃".into(), category: "CI/CD".into(), description: "Self-hosted runner for GitHub Actions workflows".into(), website: Some("https://github.com/actions/runner".into()), docker: Some(DockerTarget { image: "myoung34/github-runner:latest".into(), ports: vec![], env: vec!["RUNNER_NAME=${RUNNER_NAME}".into(), "ACCESS_TOKEN=${GH_TOKEN}".into(), "RUNNER_REPOSITORY_URL=${REPO_URL}".into()], volumes: vec!["github_runner_data:/tmp/runner".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "RUNNER_NAME".into(), label: "Runner Name".into(), input_type: "text".into(), default: Some("wolfstack-runner".into()), required: true, placeholder: None, options: vec![] }, UserInput { id: "GH_TOKEN".into(), label: "GitHub Token".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Personal access token".into()), options: vec![] }, UserInput { id: "REPO_URL".into(), label: "Repository URL".into(), input_type: "text".into(), default: None, required: true, placeholder: Some("https://github.com/owner/repo".into()), options: vec![] }] },

        AppManifest { id: "memos-v2".into(), name: "Blinko".into(), icon: "⚡".into(), category: "Productivity".into(), description: "Lightning-fast note capture with AI tagging".into(), website: Some("https://github.com/blinko-space/blinko".into()), docker: Some(DockerTarget { image: "blinkospace/blinko:latest".into(), ports: vec!["1234:1234".into()], env: vec![], volumes: vec!["blinko_data:/app/prisma".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        AppManifest { id: "hoarder".into(), name: "Hoarder".into(), icon: "🗃️".into(), category: "Productivity".into(), description: "Bookmark manager with AI tagging and full-text search".into(), website: Some("https://hoarder.app".into()), docker: Some(DockerTarget { image: "ghcr.io/hoarder-app/hoarder:latest".into(), ports: vec!["3000:3000".into()], env: vec!["NEXTAUTH_SECRET=${SECRET_KEY}".into()], volumes: vec!["hoarder_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "SECRET_KEY".into(), label: "Secret Key".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Random secret".into()), options: vec![] }] },

        AppManifest { id: "apisix".into(), name: "Apache APISIX".into(), icon: "🔀".into(), category: "Networking".into(), description: "Cloud-native API gateway with dynamic routing and plugins".into(), website: Some("https://apisix.apache.org".into()), docker: Some(DockerTarget { image: "apache/apisix:latest".into(), ports: vec!["9080:9080".into(), "9443:9443".into()], env: vec![], volumes: vec!["apisix_config:/usr/local/apisix/conf".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "kong".into(), name: "Kong Gateway".into(), icon: "🦍".into(), category: "Networking".into(), description: "Cloud-native API gateway and service mesh".into(), website: Some("https://konghq.com".into()), docker: Some(DockerTarget { image: "kong:latest".into(), ports: vec!["8000:8000".into(), "8443:8443".into(), "8001:8001".into()], env: vec!["KONG_DATABASE=off".into(), "KONG_PROXY_ACCESS_LOG=/dev/stdout".into(), "KONG_ADMIN_LISTEN=0.0.0.0:8001".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },


        // Final 30 to hit 500

        AppManifest { id: "immich-go".into(), name: "Immich Go".into(), icon: "📸".into(), category: "Media".into(), description: "CLI tool for bulk uploading photos to Immich".into(), website: Some("https://github.com/simulot/immich-go".into()), docker: Some(DockerTarget { image: "ghcr.io/simulot/immich-go:latest".into(), ports: vec![], env: vec![], volumes: vec!["${PHOTOS_PATH}:/import:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "PHOTOS_PATH".into(), label: "Photos Path".into(), input_type: "text".into(), default: Some("/opt/photos".into()), required: true, placeholder: None, options: vec![] }] },
        AppManifest { id: "feedbin".into(), name: "Feedbin".into(), icon: "📰".into(), category: "Media".into(), description: "Premium RSS reader with a clean design".into(), website: Some("https://feedbin.com".into()), docker: Some(DockerTarget { image: "feedbin/feedbin:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["feedbin_data:/app/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "readeck".into(), name: "Readeck".into(), icon: "📰".into(), category: "Media".into(), description: "Read-it-later and bookmark manager with full-text search".into(), website: Some("https://readeck.org".into()), docker: Some(DockerTarget { image: "codeberg.org/readeck/readeck:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["readeck_data:/readeck".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "outline-v2".into(), name: "AppFlowy".into(), icon: "📝".into(), category: "Productivity".into(), description: "Open-source Notion alternative with AI integration".into(), website: Some("https://appflowy.io".into()), docker: Some(DockerTarget { image: "appflowyio/appflowy-cloud:latest".into(), ports: vec!["8025:8025".into()], env: vec![], volumes: vec!["appflowy_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "capacity".into(), name: "Plane".into(), icon: "✈️".into(), category: "Project Management".into(), description: "Open-source project tracking — Jira alternative".into(), website: Some("https://plane.so".into()), docker: Some(DockerTarget { image: "makeplane/plane-frontend:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "yopass".into(), name: "Yopass".into(), icon: "🔐".into(), category: "Security".into(), description: "Share secrets securely — self-destructing encrypted messages".into(), website: Some("https://yopass.se".into()), docker: Some(DockerTarget { image: "jhaals/yopass:latest".into(), ports: vec!["1337:1337".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "infisical-v2".into(), name: "Doppler".into(), icon: "🔑".into(), category: "Security".into(), description: "Secrets management platform for dev teams".into(), website: Some("https://www.doppler.com".into()), docker: Some(DockerTarget { image: "dopplerhq/cli:latest".into(), ports: vec![], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "gitbucket".into(), name: "GitBucket".into(), icon: "🪣".into(), category: "Dev Tools".into(), description: "Git platform with issue tracking — runs on JVM".into(), website: Some("https://gitbucket.github.io".into()), docker: Some(DockerTarget { image: "gitbucket/gitbucket:latest".into(), ports: vec!["8080:8080".into(), "29418:29418".into()], env: vec![], volumes: vec!["gitbucket_data:/gitbucket".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "rstudio".into(), name: "RStudio Server".into(), icon: "📊".into(), category: "AI / ML".into(), description: "IDE for R statistical computing in the browser".into(), website: Some("https://posit.co/products/open-source/rstudio-server/".into()), docker: Some(DockerTarget { image: "rocker/rstudio:latest".into(), ports: vec!["8787:8787".into()], env: vec!["PASSWORD=${PASSWORD}".into()], volumes: vec!["rstudio_home:/home/rstudio".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "PASSWORD".into(), label: "Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("RStudio login password".into()), options: vec![] }] },
        AppManifest { id: "zeppelin".into(), name: "Apache Zeppelin".into(), icon: "📓".into(), category: "AI / ML".into(), description: "Web-based notebook for data analytics and visualisation".into(), website: Some("https://zeppelin.apache.org".into()), docker: Some(DockerTarget { image: "apache/zeppelin:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["zeppelin_notebook:/opt/zeppelin/notebook".into(), "zeppelin_logs:/opt/zeppelin/logs".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "openblocks".into(), name: "Lowcoder".into(), icon: "🏗️".into(), category: "Dev Tools".into(), description: "Low-code platform for building internal apps — Retool alternative".into(), website: Some("https://lowcoder.cloud".into()), docker: Some(DockerTarget { image: "lowcoderorg/lowcoder-ce:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["lowcoder_data:/lowcoder-stacks".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "unleash".into(), name: "Unleash".into(), icon: "🏴".into(), category: "Dev Tools".into(), description: "Feature flag management for progressive releases".into(), website: Some("https://www.getunleash.io".into()), docker: Some(DockerTarget { image: "unleashorg/unleash-server:latest".into(), ports: vec!["4242:4242".into()], env: vec!["DATABASE_URL=postgres://postgres:${DB_PASSWORD}@unleash-db/unleash".into()], volumes: vec![], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:15-alpine".into(), ports: vec![], env: vec!["POSTGRES_DB=unleash".into(), "POSTGRES_PASSWORD=${DB_PASSWORD}".into()], volumes: vec!["unleash_db:/var/lib/postgresql/data".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "DB_PASSWORD".into(), label: "Database Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("PostgreSQL password".into()), options: vec![] }] },
        AppManifest { id: "lago".into(), name: "Lago".into(), icon: "💰".into(), category: "Other".into(), description: "Open-source billing and usage-based pricing engine".into(), website: Some("https://www.getlago.com".into()), docker: Some(DockerTarget { image: "getlago/lago-api:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec!["lago_data:/app/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "cal-dav".into(), name: "DAViCal".into(), icon: "📅".into(), category: "Productivity".into(), description: "CalDAV server for shared calendars and scheduling".into(), website: Some("https://www.davical.org".into()), docker: Some(DockerTarget { image: "jsmitsnl/davical-docker:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec!["davical_data:/var/lib/postgresql".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "uptime-status".into(), name: "Upptime".into(), icon: "⬆️".into(), category: "Monitoring".into(), description: "GitHub-powered uptime monitor and status page".into(), website: Some("https://upptime.js.org".into()), docker: Some(DockerTarget { image: "upptime/upptime:latest".into(), ports: vec!["3000:3000".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "neko".into(), name: "Neko".into(), icon: "🐱".into(), category: "Other".into(), description: "Virtual browser — shared browsing sessions in real-time".into(), website: Some("https://neko.m1k1o.net".into()), docker: Some(DockerTarget { image: "m1k1o/neko:firefox".into(), ports: vec!["8080:8080".into(), "52000-52100:52000-52100/udp".into()], env: vec!["NEKO_SCREEN=1920x1080@30".into(), "NEKO_PASSWORD=${PASSWORD}".into(), "NEKO_PASSWORD_ADMIN=${ADMIN_PASSWORD}".into()], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![UserInput { id: "PASSWORD".into(), label: "Viewer Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for viewers".into()), options: vec![] }, UserInput { id: "ADMIN_PASSWORD".into(), label: "Admin Password".into(), input_type: "password".into(), default: None, required: true, placeholder: Some("Password for admin control".into()), options: vec![] }] },
        AppManifest { id: "komodo".into(), name: "Komodo".into(), icon: "🦎".into(), category: "Monitoring".into(), description: "Server and container monitoring with alerts and dashboards".into(), website: Some("https://komo.do".into()), docker: Some(DockerTarget { image: "ghcr.io/mbecker20/komodo:latest".into(), ports: vec!["9120:9120".into()], env: vec![], volumes: vec!["komodo_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "tianji".into(), name: "Tianji".into(), icon: "📊".into(), category: "Analytics".into(), description: "All-in-one insight tool — analytics, uptime, and server status".into(), website: Some("https://tianji.msgbyte.com".into()), docker: Some(DockerTarget { image: "moonrailgun/tianji:latest".into(), ports: vec!["12345:12345".into()], env: vec![], volumes: vec!["tianji_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "umami-v2".into(), name: "Shynet".into(), icon: "📊".into(), category: "Analytics".into(), description: "Privacy-friendly web analytics with no cookies or JS required".into(), website: Some("https://github.com/milesmcc/shynet".into()), docker: Some(DockerTarget { image: "milesmcc/shynet:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["shynet_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "dagu".into(), name: "Dagu".into(), icon: "📊".into(), category: "Automation".into(), description: "DAG-based job scheduler with web UI — cron alternative".into(), website: Some("https://dagu.readthedocs.io".into()), docker: Some(DockerTarget { image: "ghcr.io/dagu-org/dagu:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["dagu_data:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "gocd".into(), name: "GoCD".into(), icon: "🔄".into(), category: "CI/CD".into(), description: "Continuous delivery server with pipeline modelling".into(), website: Some("https://www.gocd.org".into()), docker: Some(DockerTarget { image: "gocd/gocd-server:latest".into(), ports: vec!["8153:8153".into(), "8154:8154".into()], env: vec![], volumes: vec!["gocd_data:/godata".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "portus".into(), name: "Gollum".into(), icon: "📖".into(), category: "CMS".into(), description: "Git-powered wiki — every page is a Markdown file in a repo".into(), website: Some("https://github.com/gollum/gollum".into()), docker: Some(DockerTarget { image: "gollumwiki/gollum:latest".into(), ports: vec!["4567:4567".into()], env: vec![], volumes: vec!["gollum_wiki:/wiki".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "element-call".into(), name: "Element Call".into(), icon: "📞".into(), category: "Communication".into(), description: "Decentralised video calling on Matrix — Zoom alternative".into(), website: Some("https://call.element.io".into()), docker: Some(DockerTarget { image: "vectorim/element-call:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "conduit".into(), name: "Conduit".into(), icon: "💬".into(), category: "Communication".into(), description: "Lightweight Matrix homeserver written in Rust".into(), website: Some("https://conduit.rs".into()), docker: Some(DockerTarget { image: "matrixconduit/matrix-conduit:latest".into(), ports: vec!["6167:6167".into()], env: vec!["CONDUIT_SERVER_NAME=localhost".into(), "CONDUIT_DATABASE_BACKEND=rocksdb".into()], volumes: vec!["conduit_data:/var/lib/matrix-conduit".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "miniboard".into(), name: "Miniboard".into(), icon: "📋".into(), category: "Project Management".into(), description: "Minimal kanban board — single binary, no dependencies".into(), website: Some("https://github.com/nicoschmitt/miniboard".into()), docker: Some(DockerTarget { image: "nicoschmitt/miniboard:latest".into(), ports: vec!["8080:8080".into()], env: vec![], volumes: vec!["miniboard_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "garage".into(), name: "Garage".into(), icon: "🏠".into(), category: "Storage".into(), description: "Lightweight S3-compatible distributed object storage".into(), website: Some("https://garagehq.deuxfleurs.fr".into()), docker: Some(DockerTarget { image: "dxflrs/garage:latest".into(), ports: vec!["3900:3900".into(), "3901:3901".into()], env: vec![], volumes: vec!["garage_data:/var/lib/garage/data".into(), "garage_meta:/var/lib/garage/meta".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "seaweedfs".into(), name: "SeaweedFS".into(), icon: "🌊".into(), category: "Storage".into(), description: "Distributed file system for billions of files — S3 compatible".into(), website: Some("https://github.com/seaweedfs/seaweedfs".into()), docker: Some(DockerTarget { image: "chrislusf/seaweedfs:latest".into(), ports: vec!["9333:9333".into(), "8080:8080".into(), "8888:8888".into()], env: vec![], volumes: vec!["seaweedfs_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "proxitok".into(), name: "ProxiTok".into(), icon: "🎵".into(), category: "Privacy".into(), description: "Privacy-friendly TikTok frontend — no tracking".into(), website: Some("https://github.com/pablouser1/ProxiTok".into()), docker: Some(DockerTarget { image: "ghcr.io/pablouser1/proxitok:latest".into(), ports: vec!["8080:80".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "bibliogram".into(), name: "Bibliogram".into(), icon: "📸".into(), category: "Privacy".into(), description: "Privacy-friendly Instagram frontend".into(), website: Some("https://git.sr.ht/~cadence/bibliogram".into()), docker: Some(DockerTarget { image: "quay.io/pussthecatorg/bibliogram:latest".into(), ports: vec!["10407:10407".into()], env: vec![], volumes: vec![], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "claude-code".into(), name: "Claude Code".into(), icon: "🤖".into(), category: "AI".into(), description: "Anthropic's agentic coding CLI — write, refactor, and debug code with Claude from the terminal".into(), website: Some("https://docs.anthropic.com/en/docs/claude-code".into()), docker: None, lxc: Some(LxcTarget { distribution: "debian".into(), release: "bookworm".into(), architecture: crate::containers::host_container_arch().into(), setup_commands: vec!["apt-get update && apt-get install -y curl".into(), "curl -fsSL https://deb.nodesource.com/setup_22.x | bash -".into(), "apt-get install -y nodejs".into(), "npm install -g @anthropic-ai/claude-code".into()] }), bare_metal: Some(BareMetalTarget { packages_debian: vec!["nodejs".into(), "npm".into()], packages_redhat: vec!["nodejs".into(), "npm".into()], post_install: vec!["npm install -g @anthropic-ai/claude-code".into()], service: None }), vm: None, user_inputs: vec![] },
        AppManifest { id: "openclaw".into(), name: "OpenClaw".into(), icon: "🐾".into(), category: "AI".into(), description: "Personal AI assistant with WhatsApp, Telegram, Discord, Slack integration and persistent memory".into(), website: Some("https://openclaw.ai".into()), docker: Some(DockerTarget { image: "ghcr.io/openclaw/openclaw:latest".into(), ports: vec!["18789:18789".into()], env: vec![], volumes: vec!["openclaw_config:/home/node/.openclaw".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // ── New additions — AI, Infrastructure, Business, Media, Security, Health ──

        // AI
        AppManifest { id: "librechat".into(), name: "LibreChat".into(), icon: "💬".into(), category: "AI".into(), description: "ChatGPT-like UI for Claude, GPT, Gemini, Ollama and other AI providers".into(), website: Some("https://librechat.ai".into()), docker: Some(DockerTarget { image: "ghcr.io/danny-avila/librechat:latest".into(), ports: vec!["3080:3080".into()], env: vec![], volumes: vec!["librechat_data:/app/data".into(), "librechat_logs:/app/api/logs".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "bolt-diy".into(), name: "Bolt.diy".into(), icon: "⚡".into(), category: "AI".into(), description: "AI-powered full-stack app builder in the browser — prompt to working app".into(), website: Some("https://github.com/stackblitz-labs/bolt.diy".into()), docker: Some(DockerTarget { image: "ghcr.io/stackblitz-labs/bolt.diy:latest".into(), ports: vec!["5173:5173".into()], env: vec![], volumes: vec!["bolt_data:/app/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "open-interpreter".into(), name: "Open Interpreter".into(), icon: "🖥️".into(), category: "AI".into(), description: "AI that runs code locally — natural language to Python, JavaScript, shell".into(), website: Some("https://openinterpreter.com".into()), docker: Some(DockerTarget { image: "ghcr.io/openinterpreter/open-interpreter:latest".into(), ports: vec!["8000:8000".into()], env: vec![], volumes: vec!["openinterpreter_data:/root/.openinterpreter".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // Infrastructure
        AppManifest { id: "dockge".into(), name: "Dockge".into(), icon: "🐋".into(), category: "Other".into(), description: "Docker Compose manager — create, edit, start and stop compose stacks from a clean UI".into(), website: Some("https://dockge.kuma.pet".into()), docker: Some(DockerTarget { image: "louislam/dockge:1".into(), ports: vec!["5001:5001".into()], env: vec![], volumes: vec!["/var/run/docker.sock:/var/run/docker.sock".into(), "dockge_data:/app/data".into(), "/opt/stacks:/opt/stacks".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "pangolin".into(), name: "Pangolin".into(), icon: "🦔".into(), category: "Networking".into(), description: "Self-hosted reverse proxy with tunnels — Cloudflare Tunnel alternative".into(), website: Some("https://github.com/fosrl/pangolin".into()), docker: Some(DockerTarget { image: "fosrl/pangolin:latest".into(), ports: vec!["443:443".into(), "80:80".into(), "8443:8443".into()], env: vec![], volumes: vec!["pangolin_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "cosmos".into(), name: "Cosmos".into(), icon: "🌌".into(), category: "Other".into(), description: "Self-hosted platform manager with automatic HTTPS, SSO, and container management".into(), website: Some("https://cosmos-cloud.io".into()), docker: Some(DockerTarget { image: "azukaar/cosmos-server:latest".into(), ports: vec!["80:80".into(), "443:443".into()], env: vec![], volumes: vec!["/var/run/docker.sock:/var/run/docker.sock".into(), "cosmos_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // Business / Productivity
        AppManifest { id: "twenty".into(), name: "Twenty CRM".into(), icon: "📇".into(), category: "Project Management".into(), description: "Open-source CRM — modern Salesforce alternative with clean UI".into(), website: Some("https://twenty.com".into()), docker: Some(DockerTarget { image: "twentycrm/twenty:latest".into(), ports: vec!["3000:3000".into()], env: vec!["SERVER_URL=http://localhost:3000".into()], volumes: vec!["twenty_data:/app/.local-storage".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "twentycrm/twenty-postgres:latest".into(), ports: vec![], env: vec!["POSTGRES_USER=twenty".into(), "POSTGRES_PASSWORD=twenty".into(), "POSTGRES_DB=default".into()], volumes: vec!["twenty_db:/bitnami/postgresql".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "appflowy".into(), name: "AppFlowy".into(), icon: "📝".into(), category: "Other".into(), description: "Open-source Notion alternative — notes, wikis, and project management".into(), website: Some("https://appflowy.io".into()), docker: Some(DockerTarget { image: "appflowyio/appflowy-cloud:latest".into(), ports: vec!["9025:9025".into()], env: vec![], volumes: vec!["appflowy_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "firefly-iii".into(), name: "Firefly III".into(), icon: "💰".into(), category: "Other".into(), description: "Personal finance manager — budgets, transactions, reports and charts".into(), website: Some("https://firefly-iii.org".into()), docker: Some(DockerTarget { image: "fireflyiii/core:latest".into(), ports: vec!["8084:8080".into()], env: vec!["APP_KEY=SomeRandomStringOf32CharsExactly".into(), "DB_CONNECTION=sqlite".into(), "TRUSTED_PROXIES=**".into()], volumes: vec!["firefly_upload:/var/www/html/storage/upload".into(), "firefly_db:/var/www/html/storage/database".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "erpnext".into(), name: "ERPNext".into(), icon: "🏢".into(), category: "Other".into(), description: "Full open-source ERP — accounting, inventory, HR, CRM, manufacturing".into(), website: Some("https://erpnext.com".into()), docker: Some(DockerTarget { image: "frappe/erpnext:latest".into(), ports: vec!["8082:8080".into()], env: vec![], volumes: vec!["erpnext_sites:/home/frappe/frappe-bench/sites".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "odoo".into(), name: "Odoo".into(), icon: "🏭".into(), category: "Other".into(), description: "Business suite — CRM, eCommerce, accounting, inventory, project management".into(), website: Some("https://www.odoo.com".into()), docker: Some(DockerTarget { image: "odoo:17".into(), ports: vec!["8069:8069".into()], env: vec![], volumes: vec!["odoo_data:/var/lib/odoo".into(), "odoo_config:/etc/odoo".into(), "odoo_addons:/mnt/extra-addons".into()], sidecars: vec![DockerSidecar { name_suffix: "db".into(), image: "postgres:16".into(), ports: vec![], env: vec!["POSTGRES_USER=odoo".into(), "POSTGRES_PASSWORD=odoo".into(), "POSTGRES_DB=postgres".into(), "PGDATA=/var/lib/postgresql/data/pgdata".into()], volumes: vec!["odoo_db:/var/lib/postgresql/data/pgdata".into()] , cmd: vec![], post_install_exec: vec![] }], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // Media / Home
        AppManifest { id: "notifiarr".into(), name: "Notifiarr".into(), icon: "🔔".into(), category: "Media".into(), description: "Notification aggregator for Sonarr, Radarr, Lidarr, Readarr and other *arr apps".into(), website: Some("https://notifiarr.com".into()), docker: Some(DockerTarget { image: "golift/notifiarr:latest".into(), ports: vec!["5454:5454".into()], env: vec![], volumes: vec!["notifiarr_config:/config".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "bar-assistant".into(), name: "Bar Assistant".into(), icon: "🍸".into(), category: "Other".into(), description: "Cocktail recipe manager and bar inventory tracker".into(), website: Some("https://barassistant.app".into()), docker: Some(DockerTarget { image: "barassistant/server:latest".into(), ports: vec!["8087:8080".into()], env: vec!["APP_URL=http://localhost:8087".into()], volumes: vec!["bar_data:/var/www/cocktails/storage".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // Security
        AppManifest { id: "falco".into(), name: "Falco".into(), icon: "🦅".into(), category: "Security".into(), description: "Runtime security and threat detection for containers and Kubernetes".into(), website: Some("https://falco.org".into()), docker: Some(DockerTarget { image: "falcosecurity/falco-no-driver:latest".into(), ports: vec!["8765:8765".into()], env: vec![], volumes: vec!["/proc:/host/proc:ro".into(), "/etc:/host/etc:ro".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },
        AppManifest { id: "dependency-track".into(), name: "Dependency-Track".into(), icon: "🔗".into(), category: "Security".into(), description: "Software supply chain security — track vulnerabilities in project dependencies".into(), website: Some("https://dependencytrack.org".into()), docker: Some(DockerTarget { image: "dependencytrack/bundled:latest".into(), ports: vec!["8081:8080".into()], env: vec![], volumes: vec!["deptrack_data:/data".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

        // Health
        AppManifest { id: "fasten-health".into(), name: "Fasten Health".into(), icon: "🏥".into(), category: "Other".into(), description: "Personal health record aggregator — pull medical records from hospitals and insurers".into(), website: Some("https://fastenhealth.com".into()), docker: Some(DockerTarget { image: "ghcr.io/fastenhealth/fasten-onprem:latest".into(), ports: vec!["9090:8080".into()], env: vec![], volumes: vec!["fasten_db:/opt/fasten/db".into()], sidecars: vec![], seed_files: vec![], cmd: vec![] }), lxc: None, bare_metal: None, vm: None, user_inputs: vec![] },

    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every app with a Docker target must resolve to a valid compose
    /// template — either hand-crafted or auto-synthesised. This
    /// catches a future manifest edit that breaks the compose path
    /// for even one app. LXC-only / bare-metal / VM-only apps are
    /// expected to return None.
    /// Catalogue ids must be unique: get_app resolves by first-match,
    /// has_compose_template scans all matches, and the list UI renders
    /// every entry — a duplicate id makes those three disagree and
    /// shows twice in the store (Uptime Kuma shipped duplicated until
    /// v25.2.57).
    #[test]
    fn catalogue_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        let dupes: Vec<&str> = catalogue().iter()
            .filter(|a| !seen.insert(a.id.as_str()))
            .map(|a| a.id.as_str())
            .collect();
        assert!(dupes.is_empty(), "duplicate catalogue ids: {:?}", dupes);
    }

    /// has_compose_template (and the inlined expression in the list
    /// endpoint) is an optimised mirror of resolve_compose_template —
    /// lock the equivalence so a future change to resolution rules
    /// can't silently diverge from the fast path.
    #[test]
    fn has_compose_template_matches_resolver() {
        for app in catalogue() {
            let fast = has_compose_template(&app.id);
            let canonical = resolve_compose_template(&app.id).is_some();
            assert_eq!(fast, canonical, "divergence for app '{}'", app.id);
            let inlined = handcrafted_compose_template(&app.id).is_some() || app.docker.is_some();
            assert_eq!(inlined, canonical, "inlined divergence for app '{}'", app.id);
        }
    }

    #[test]
    fn every_docker_app_has_compose_template() {
        let mut missing: Vec<String> = Vec::new();
        for app in built_in_catalogue() {
            if app.docker.is_some()
                && resolve_compose_template(&app.id).is_none() {
                    missing.push(app.id.clone());
                }
        }
        assert!(
            missing.is_empty(),
            "Apps with Docker target but no resolvable compose template: {:?}",
            missing,
        );
    }

    /// Every env / cmd ${VAR} placeholder must either be CONTAINER_NAME
    /// (injected by the API layer) or declared in the app's user_inputs
    /// list. A dangling ${FOO} leaves a literal "${FOO}" in the running
    /// container's env — the class of bug that made Outline and early
    /// Guacamole dead on arrival.
    #[test]
    fn every_placeholder_is_declared() {
        let mut dangling: Vec<(String, String)> = Vec::new();
        for app in built_in_catalogue() {
            let Some(docker) = &app.docker else { continue };
            let declared: std::collections::HashSet<String> = std::iter::once("CONTAINER_NAME".to_string())
                .chain(app.user_inputs.iter().map(|u| u.id.clone()))
                .collect();

            let mut strings: Vec<String> = Vec::new();
            strings.extend(docker.env.iter().cloned());
            strings.extend(docker.cmd.iter().cloned());
            for s in &docker.sidecars {
                strings.extend(s.env.iter().cloned());
                strings.extend(s.cmd.iter().cloned());
                for argv in &s.post_install_exec { strings.extend(argv.iter().cloned()); }
            }
            // Seed file contents — a stray ${FOO} in a YAML config
            // lands literally in the file if FOO isn't declared.
            for seed in &docker.seed_files {
                strings.push(seed.content.clone());
            }

            for s in &strings {
                let mut i = 0;
                while let Some(start) = s[i..].find("${") {
                    let abs = i + start + 2;
                    if let Some(end) = s[abs..].find('}') {
                        let name = &s[abs..abs + end];
                        if !declared.contains(name) {
                            dangling.push((app.id.clone(), name.to_string()));
                        }
                        i = abs + end + 1;
                    } else { break; }
                }
            }
        }
        assert!(
            dangling.is_empty(),
            "Apps referencing undeclared ${{VAR}} placeholders: {:?}",
            dangling,
        );
    }

    /// The reported Gary/KO4BSR bug: Debian's `current/` symlink rolled
    /// from 13.4.0 to 13.5.0, 404ing our pinned netinst URL. The resolver
    /// must rescrape the directory and pick `debian-13.5.0-amd64-netinst.iso`
    /// — NOT the sibling `debian-edu-` / `debian-mac-` variants that share
    /// the `debian-` prefix and live in the same listing.
    #[test]
    fn resolve_latest_iso_picks_bumped_debian_netinst() {
        let original = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.4.0-amd64-netinst.iso";
        let html = r#"
            <a href="debian-edu-13.5.0-amd64-netinst.iso">debian-edu</a>
            <a href="debian-mac-13.5.0-amd64-netinst.iso">debian-mac</a>
            <a href="debian-13.5.0-amd64-netinst.iso">debian</a>
            <a href="SHA256SUMS">checksums</a>
        "#;
        assert_eq!(
            pick_latest_iso_from_listing(original, html).as_deref(),
            Some("https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso"),
        );
    }

    /// Live (GNOME) image template, same rolling-`current` scenario.
    #[test]
    fn resolve_latest_iso_picks_bumped_debian_live() {
        let original = "https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/debian-live-13.4.0-amd64-gnome.iso";
        let html = r#"
            <a href="debian-live-13.5.0-amd64-kde.iso">kde</a>
            <a href="debian-live-13.5.0-amd64-gnome.iso">gnome</a>
            <a href="debian-live-13.5.0-amd64-xfce.iso">xfce</a>
        "#;
        assert_eq!(
            pick_latest_iso_from_listing(original, html).as_deref(),
            Some("https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/debian-live-13.5.0-amd64-gnome.iso"),
        );
    }

    /// Underscore-delimited Proxmox layout must still resolve (the case
    /// the original resolver was written for).
    #[test]
    fn resolve_latest_iso_handles_proxmox_underscore() {
        let original = "https://enterprise.proxmox.com/iso/proxmox-ve_9.1-1.iso";
        let html = r#"
            <a href="proxmox-ve_9.1-1.iso">9.1</a>
            <a href="proxmox-ve_9.2-1.iso">9.2</a>
        "#;
        assert_eq!(
            pick_latest_iso_from_listing(original, html).as_deref(),
            Some("https://enterprise.proxmox.com/iso/proxmox-ve_9.2-1.iso"),
        );
    }

    /// Numeric (not lexical) comparison: `13.10.0` must beat `13.9.0`.
    #[test]
    fn resolve_latest_iso_compares_versions_numerically() {
        let original = "https://example.org/iso/debian-13.4.0-amd64-netinst.iso";
        let html = r#"
            <a href="debian-13.9.0-amd64-netinst.iso">9</a>
            <a href="debian-13.10.0-amd64-netinst.iso">10</a>
        "#;
        assert_eq!(
            pick_latest_iso_from_listing(original, html).as_deref(),
            Some("https://example.org/iso/debian-13.10.0-amd64-netinst.iso"),
        );
    }

    /// No matching template in the listing → None (caller surfaces the
    /// original download error rather than a bogus URL).
    #[test]
    fn resolve_latest_iso_returns_none_when_nothing_matches() {
        let original = "https://example.org/iso/debian-13.4.0-amd64-netinst.iso";
        let html = r#"<a href="some-other-distro-1.0.iso">nope</a>"#;
        assert_eq!(pick_latest_iso_from_listing(original, html), None);
    }
}
