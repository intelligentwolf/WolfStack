// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Shared HTTP clients for VM migration. Two flavors because uploads
/// want a 1-hour total deadline but still a short connect_timeout so
/// an unreachable target fails fast. Per-migration Client builders
/// were leaking connection pools for every VM transfer attempt.
static VM_MIGRATION_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .connect_timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });
use crate::api::{
    AppState, MigrationTasks, require_auth, build_node_urls,
    migration_create, migration_update, migration_fail, migration_done, migration_progress,
};
use super::manager::{VmConfig, StorageVolume, UsbDevice, PciDevice};
use super::passthrough;
use crate::node_identity::PeerAuth;

/// Format a byte count for human display: "1.4 GB" / "812 MB" / etc.
fn format_bytes_human(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 { v /= 1024.0; i += 1; }
    if i == 0 { format!("{} B", b) } else { format!("{:.1} {}", v, UNITS[i]) }
}

/// Poll the VM export directory for the in-progress tar.gz and report
/// its growing size to the migration task. Runs until `stop` is set,
/// typically when the export completes. Expected archive size is raw
/// disk bytes; gzip typically yields ~50 % so the bar will appear to
/// stall near 50 % then jump — still better than no signal at all.
async fn poll_export_archive_size(
    tasks: MigrationTasks,
    tid: String,
    staging_dir: Option<String>,
    vm_name: String,
    expected_total: Option<u64>,
    stop: Arc<AtomicBool>,
) {
    let root = super::manager::migration_staging_root(staging_dir.as_deref())
        .join("wolfstack-vm-exports");
    let prefix = format!("vm-{}-", vm_name);
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let Ok(entries) = std::fs::read_dir(&root) else { continue; };
        let mut newest: Option<(std::time::SystemTime, u64)> = None;
        for entry in entries.flatten() {
            let Some(fname) = entry.file_name().to_str().map(|s| s.to_string()) else { continue; };
            if !fname.starts_with(&prefix) || !fname.ends_with(".tar.gz") { continue; }
            let Ok(md) = entry.metadata() else { continue; };
            let mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
            let size = md.len();
            if newest.map(|(t, _)| mtime > t).unwrap_or(true) {
                newest = Some((mtime, size));
            }
        }
        if let Some((_, size)) = newest {
            migration_progress(&tasks, &tid, Some(size), expected_total, None);
        }
    }
}

/// Build a reqwest body that streams `archive_bytes` in 4 MiB chunks
/// while updating the migration task's bytes_done counter. Each call
/// returns a fresh stream so callers can retry across multiple import
/// URLs without having to pre-clone the whole archive again. Reports
/// *reads-from-memory*, not TCP ACKs — on slow networks the reported
/// percent races ahead of actual wire transmission by up to one
/// kernel-TCP-buffer worth of bytes, which is acceptable feedback.
fn build_progress_body(
    archive_bytes: &[u8],
    total: u64,
    tasks: MigrationTasks,
    tid: String,
) -> (reqwest::Body, u64) {
    let archive = Arc::new(archive_bytes.to_vec());
    let chunk_size: usize = 4 * 1024 * 1024;
    let arc = archive.clone();
    let stream = futures::stream::unfold(0usize, move |pos| {
        let arc = arc.clone();
        let tasks = tasks.clone();
        let tid = tid.clone();
        async move {
            if pos >= arc.len() { return None; }
            let end = (pos + chunk_size).min(arc.len());
            let chunk = arc[pos..end].to_vec();
            let new_pos = end;
            migration_progress(&tasks, &tid, Some(new_pos as u64), Some(arc.len() as u64), None);
            Some((Ok::<Vec<u8>, std::io::Error>(chunk), new_pos))
        }
    });
    (reqwest::Body::wrap_stream(stream), total)
}

/// WolfHA lifecycle guard for VM endpoints.
///
/// A protected VM's disk layout and identity are replicated state — the
/// operations below would silently break the standbys (or start a second
/// copy of a takeover identity), so they are refused with the way out
/// spelled out. Mirrors the container guard in api::lxc action handling.
/// Returns Some(refusal) when `name` is WolfHA-managed as a VM here.
fn wolfha_vm_guard(name: &str, action: &str) -> Option<HttpResponse> {
    let store = crate::wolfha::HaStore::load();
    let entry = store.get(name)?;
    if entry.kind != crate::wolfha::SubjectKind::Vm {
        return None;
    }
    Some(match entry.role {
        crate::wolfha::HaRole::Replica => HttpResponse::Conflict().json(serde_json::json!({
            "error": format!(
                "'{}' is a WolfHA standby copy — {} it here would collide with the active copy. Use Promote on the WolfHA page instead (or Disable to release it).",
                name, action
            )
        })),
        crate::wolfha::HaRole::Primary => HttpResponse::Conflict().json(serde_json::json!({
            "error": format!(
                "'{}' is WolfHA-protected — {} would break its replicas. Disable WolfHA for this VM first, then try again.",
                name, action
            )
        })),
    })
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/vms")
            .route("", web::get().to(list_vms))
            .route("/wolfnet/health", web::get().to(wolfnet_health))
            .route("/prerequisites", web::get().to(vm_prerequisites))
            .route("/prerequisites/install", web::post().to(vm_prerequisites_install))
            .route("/create", web::post().to(create_vm))
            .route("/storage", web::get().to(list_storage))
            .route("/host-devices", web::get().to(host_devices))
            .route("/import-external", web::post().to(vm_import_external))
            .route("/discover-libvirt", web::get().to(discover_libvirt))
            .route("/adopt-libvirt", web::post().to(adopt_libvirt))
            .route("/{name}/action", web::post().to(vm_action))
            .route("/{name}/clone", web::post().to(vm_clone))
            .route("/{name}/logs", web::get().to(vm_logs))
            .route("/{name}/serial-status", web::get().to(vm_serial_status))
            .route("/{name}/add-serial", web::post().to(vm_add_serial))
            .route("/{name}/migrate", web::post().to(vm_migrate))
            .route("/{name}/migrate-external", web::post().to(vm_migrate_external))
            .route("/{name}/disk/migrate", web::post().to(vm_disk_migrate))
            .route("/{name}/volumes", web::post().to(add_volume))
            .route("/{name}/volumes/{vol}", web::delete().to(remove_volume))
            .route("/{name}/volumes/{vol}/resize", web::post().to(resize_volume))
            .route("/{name}/vnc-password", web::get().to(vm_vnc_password))
            .route("/{name}/start-command", web::get().to(vm_start_command))
            .route("/{name}", web::put().to(update_vm))
            .route("/{name}", web::delete().to(delete_vm))
            .route("/{name}", web::get().to(get_vm))
    );
}

/// GET /api/vms/prerequisites?uefi=1&tpm=1 — VM host preflight. Reports
/// each required/optional component (QEMU, qemu-img, OVMF, swtpm, KVM)
/// and whether it's installed, so the New VM UI can offer one-click
/// installs before a VM ever fails to start. `uefi`/`tpm` reflect the
/// form's Firmware / TPM toggles so components are marked required only
/// when the current config uses them.
async fn vm_prerequisites(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let truthy = |k: &str| matches!(query.get(k).map(|s| s.as_str()), Some("1") | Some("true"));
    let needs_uefi = truthy("uefi");
    let needs_tpm = truthy("tpm");
    // Filesystem probes only — cheap, but keep it off the async worker.
    let report = web::block(move || crate::vms::prereqs::check(needs_uefi, needs_tpm))
        .await
        .unwrap_or_else(|_| crate::vms::prereqs::PrereqReport {
            ready: false, proxmox: false, items: Vec::new(),
        });
    HttpResponse::Ok().json(report)
}

#[derive(serde::Deserialize)]
struct PrereqInstallRequest {
    /// Logical package keys to install (from the preflight's missing
    /// items). "kvm" and any non-installable key are ignored server-side.
    packages: Vec<String>,
}

/// POST /api/vms/prerequisites/install — install several VM prerequisite
/// packages in one call (the "Install missing components" button). Runs
/// each through the same allowlisted installer as /api/system/install-
/// package; returns a per-package result so the UI shows what succeeded.
async fn vm_prerequisites_install(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PrereqInstallRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let pkgs = body.into_inner().packages;
    if pkgs.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false, "error": "no packages specified",
        }));
    }
    let results = web::block(move || {
        pkgs.into_iter().map(|p| {
            // Never shell out for the non-installable capability key.
            if p == "kvm" || !crate::installer::packages::is_installable(&p) {
                return serde_json::json!({
                    "package": p, "success": false,
                    "error": "not installable on this host",
                });
            }
            match crate::installer::packages::install(&p) {
                Ok(r) => serde_json::json!({
                    "package": r.package, "success": r.success, "message": r.message,
                }),
                Err(e) => serde_json::json!({
                    "package": p, "success": false, "error": e,
                }),
            }
        }).collect::<Vec<_>>()
    }).await.unwrap_or_default();

    let ok = results.iter().all(|r| r.get("success").and_then(|v| v.as_bool()).unwrap_or(false));
    HttpResponse::Ok().json(serde_json::json!({ "success": ok, "results": results }))
}

/// GET /api/vms/host-devices — list USB + PCI devices on the host with IOMMU
/// info and VFIO preflight. Devices currently claimed by a VM configured in
/// WolfStack are tagged with `in_use_by` so the picker can grey them out.
async fn host_devices(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let vms = {
        let manager = state.vms.lock().unwrap();
        manager.list_vms()
    };
    let ownership = passthrough::build_ownership(&vms);
    let response = passthrough::list_host_devices(&ownership);
    HttpResponse::Ok().json(response)
}

async fn list_vms(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    // list_vms() runs qm/virsh/pgrep subprocesses; doing it inline (while holding
    // the std Mutex) blocked an actix request worker and serialised every VM
    // request behind it — under the page-load burst the list came up blank for
    // 10-20s. Offload to the blocking pool; the lock is taken inside it.
    let state = state.clone(); // clone the Arc-backed web::Data, lock inside the block
    match web::block(move || state.vms.lock().unwrap().list_vms()).await {
        Ok(vms) => {
            // Flag WolfHA standby copies the same way the LXC list does
            // (`ha_replica`) — the WolfHA protect dialog filters on it,
            // and the VM cards can label a dormant copy for what it is.
            // Injected at the JSON edge: VmConfig itself stays unchanged
            // so nothing extra is persisted into sidecar files.
            let store = crate::wolfha::HaStore::load();
            let out: Vec<serde_json::Value> = vms.into_iter().map(|vm| {
                let is_standby = store.get(&vm.name).map(|e| {
                    e.kind == crate::wolfha::SubjectKind::Vm
                        && e.role == crate::wolfha::HaRole::Replica
                }).unwrap_or(false);
                let mut v = serde_json::to_value(&vm).unwrap_or(serde_json::Value::Null);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("ha_replica".to_string(), serde_json::Value::Bool(is_standby));
                }
                v
            }).collect();
            HttpResponse::Ok().json(out)
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({"error": "vm list unavailable"})),
    }
}

/// GET /api/vms/wolfnet/health — per-VM WolfNet plumbing status.
///
/// Returns one entry per running VM that has a WolfNet IP, with the
/// outcome of every check the predictive analyzer runs (TAP up,
/// gateway IP assigned, dnsmasq alive bound to the right interface,
/// DHCP lease present). Operators get a one-call answer to "is the
/// VM's network actually working?" without grepping `ss -tlnp` or
/// guessing at pid files.
///
/// Lives next to `list_vms` because the data is per-VM and the
/// frontend's VM table can fold the health state into a status pill.
async fn wolfnet_health(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let vms = {
        let manager = state.vms.lock().unwrap();
        manager.list_vms()
    };
    let mut out: Vec<serde_json::Value> = Vec::new();
    for vm in vms {
        let wolfnet_ip = match vm.wolfnet_ip.as_deref() {
            Some(ip) if !ip.is_empty() => ip.to_string(),
            _ => continue, // skip VMs without WolfNet
        };
        // Pure inspection — safe to call from a request handler.
        let tap = crate::vms::manager::VmManager::tap_name(&vm.name);
        let health = crate::vms::manager::probe_wolfnet_tap_health(&tap, &wolfnet_ip);
        out.push(serde_json::json!({
            "vm": vm.name,
            "running": vm.running,
            "ok": health.ok(),
            "tap": health.tap,
            "gateway_ip": health.gateway_ip,
            "wolfnet_ip": health.wolfnet_ip,
            "tap_exists": health.tap_exists,
            "tap_up": health.tap_up,
            "gateway_assigned": health.gateway_assigned,
            "dnsmasq_pid": health.dnsmasq_pid,
            "dnsmasq_alive": health.dnsmasq_alive,
            "dnsmasq_owns_tap": health.dnsmasq_owns_tap,
            "lease_present": health.lease_present,
            "failures": health.failures,
        }));
    }
    HttpResponse::Ok().json(out)
}

/// List available storage locations on the host
async fn list_storage(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    let locations = manager.list_storage_locations();
    HttpResponse::Ok().json(locations)
}

#[derive(Deserialize)]
struct CreateVmDisk {
    name: String,
    size_gb: u32,
    #[serde(default = "default_storage")]
    storage_path: String,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default = "default_bus")]
    bus: String,
}

fn default_storage() -> String { "/var/lib/wolfstack/vms".to_string() }
fn default_format() -> String { "qcow2".to_string() }
fn default_bus() -> String { "virtio".to_string() }

#[derive(Deserialize)]
struct CreateVmRequest {
    name: String,
    cpus: u32,
    memory_mb: u32,
    disk_size_gb: u32,
    iso_path: Option<String>,
    wolfnet_ip: Option<String>,
    /// Storage path for the OS disk
    storage_path: Option<String>,
    /// Bus type for OS disk (virtio, ide, sata) — use ide for Windows
    #[serde(default = "default_os_bus")]
    os_disk_bus: String,
    /// Network adapter model (virtio, e1000, rtl8139) — use e1000 for Windows
    #[serde(default = "default_os_bus")]
    net_model: String,
    /// Optional path to VirtIO drivers ISO (for Windows + virtio disk)
    drivers_iso: Option<String>,
    /// Import a disk image (.img, .qcow2, .vmdk, .vdi) as the OS disk instead of creating an empty one
    import_image: Option<String>,
    /// Extra disks to create with the VM (Proxmox-style)
    #[serde(default)]
    extra_disks: Vec<CreateVmDisk>,
    /// Extra network interfaces (net1, net2, ...) for multi-NIC VMs
    #[serde(default)]
    extra_nics: Vec<super::manager::NicConfig>,
    /// USB devices to pass through from host
    #[serde(default)]
    usb_devices: Vec<UsbDevice>,
    /// PCI devices to pass through from host
    #[serde(default)]
    pci_devices: Vec<PciDevice>,
    /// BIOS type: "seabios" (legacy) or "ovmf" (UEFI/EFI)
    #[serde(default = "default_bios_type")]
    bios_type: String,
    /// Emulated TPM 2.0 (Windows 11 requires it). See `VmConfig::tpm`.
    #[serde(default)]
    tpm: bool,
    /// UEFI Secure Boot with MS keys pre-enrolled. See `VmConfig::secure_boot`.
    #[serde(default)]
    secure_boot: bool,
    /// Boot device order — see `VmConfig::boot_order`. Empty = backend default.
    #[serde(default)]
    boot_order: Vec<String>,
    /// Allow external VNC clients (native QEMU) — see `VmConfig::vnc_external`.
    #[serde(default)]
    vnc_external: bool,
    /// Primary-NIC network mode: "wolfnet" | "bridge" | "nat". Backwards-
    /// compatible: omit and the manager derives mode from `wolfnet_ip`.
    #[serde(default)]
    network_mode: Option<String>,
    /// Bridge name for `network_mode == "bridge"` (operator-picked vmbr0,
    /// vmbr<vlan>, lxcbr0, br-pt-*, …). The frontend writes `vmbr<vlan>`
    /// here after auto-creating a vSwitch VLAN attachment.
    #[serde(default)]
    bridge: Option<String>,
    /// IP-assignment hint for bridge mode: "dhcp" | "static" (UI only — the
    /// guest configures its own IP; persisted so the editor shows the
    /// operator's choice back).
    #[serde(default)]
    bridge_ip_mode: Option<String>,
    /// Static IP+CIDR for bridge mode when `bridge_ip_mode == "static"`.
    #[serde(default)]
    bridge_ip: Option<String>,
    /// Static gateway for bridge mode when `bridge_ip_mode == "static"`.
    #[serde(default)]
    bridge_gateway: Option<String>,
    /// The vSwitch selection behind `bridge`, when the VM is being created
    /// from the vSwitch preset. Persisted so the editor re-opens on the
    /// vSwitch card instead of inferring it from the bridge name.
    #[serde(default)]
    vsw_uplink: Option<String>,
    #[serde(default)]
    vsw_vlan: Option<u32>,
    /// Free-text operator notes / description. Defaults to empty.
    #[serde(default)]
    notes: String,
    /// Operator-supplied extra QEMU args (e.g. Windows-11 audio). Defaults to
    /// empty. Tokenised server-side with a shell-style splitter; the string is
    /// never passed through a shell.
    #[serde(default)]
    extra_qemu_args: String,
}

fn default_bios_type() -> String { "seabios".to_string() }

/// Reject media (ISO) paths that could break out of the comma-delimited
/// argument syntax the hypervisors use, or smuggle control characters.
/// `None`/empty is allowed (= no media / detach). Returns a ready 400 on
/// rejection. This is the single boundary guard covering all three
/// backends — safer than trying to comma-escape per-tool (their escaping
/// rules differ and aren't all reliable).
fn validate_media_path(path: Option<&str>, field: &str) -> Result<(), HttpResponse> {
    let p = match path { Some(p) => p, None => return Ok(()) };
    if p.contains(',') {
        return Err(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("{} can't contain a comma — the hypervisor reads it as a config separator. Rename the file or move it to a comma-free folder.", field)
        })));
    }
    if p.chars().any(|c| c.is_control()) {
        return Err(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("{} contains an invalid (control) character.", field)
        })));
    }
    Ok(())
}

fn default_os_bus() -> String { "virtio".to_string() }

async fn create_vm(req: HttpRequest, state: web::Data<AppState>, body: web::Json<CreateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }

    // Media paths are embedded in comma-delimited hypervisor args
    // (qm `--ideN <path>,media=cdrom`, virt-install `--disk ...,path=<path>`,
    // qemu `-drive file=<path>,...`), so a comma in the path would be parsed
    // as an extra config option — reject it at the boundary.
    if let Err(resp) = validate_media_path(body.iso_path.as_deref(), "ISO path") { return resp; }
    if let Err(resp) = validate_media_path(body.drivers_iso.as_deref(), "VirtIO drivers ISO path") { return resp; }

    let manager = state.vms.lock().unwrap();

    let mut config = VmConfig::new(
        body.name.clone(),
        body.cpus,
        body.memory_mb,
        body.disk_size_gb
    );
    config.iso_path = body.iso_path.clone();

    // WolfNet IP: use provided value, or None if not specified
    config.wolfnet_ip = match &body.wolfnet_ip {
        Some(ip) if !ip.is_empty() => Some(ip.clone()),
        _ => None,
    };
    config.storage_path = body.storage_path.clone();
    config.os_disk_bus = body.os_disk_bus.clone();
    config.net_model = body.net_model.clone();
    config.drivers_iso = body.drivers_iso.clone();
    config.bios_type = body.bios_type.clone();
    config.tpm = body.tpm;
    config.secure_boot = body.secure_boot;
    // TPM / Secure Boot only make sense with UEFI — Secure Boot is silently
    // ignored on SeaBIOS and a TPM without q35/OVMF is pointless. Enforce it
    // here so a direct API call can't produce a half-configured VM (the UI
    // already nudges the firmware dropdown to OVMF).
    if config.tpm || config.secure_boot {
        config.bios_type = "ovmf".to_string();
    }
    config.boot_order = body.boot_order.clone();
    config.vnc_external = body.vnc_external;
    config.notes = body.notes.clone();
    config.extra_qemu_args = body.extra_qemu_args.clone();

    // Network mode + bridge fields. Validate mode at the boundary so a
    // typo in the request can't silently fall through to the default
    // path; everything else is a free-form string that the manager
    // stores and read paths echo back.
    if let Some(ref nm) = body.network_mode {
        let allowed = matches!(nm.as_str(), "" | "wolfnet" | "bridge" | "nat");
        if !allowed {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("invalid network_mode '{}': expected wolfnet | bridge | nat", nm)
            }));
        }
        config.network_mode = if nm.is_empty() { None } else { Some(nm.clone()) };
    }
    config.bridge = body.bridge.clone().filter(|s| !s.is_empty());
    config.bridge_ip_mode = body.bridge_ip_mode.clone().filter(|s| !s.is_empty());
    config.bridge_ip = body.bridge_ip.clone().filter(|s| !s.is_empty());
    config.bridge_gateway = body.bridge_gateway.clone().filter(|s| !s.is_empty());
    // Only a complete uplink+VLAN pair marks this as a vSwitch VM; a half-set
    // pair would make the editor open a vSwitch card it can't populate.
    config.vsw_uplink = body.vsw_uplink.clone().filter(|s| !s.is_empty());
    config.vsw_vlan = body.vsw_vlan;
    if config.vsw_uplink.is_none() || config.vsw_vlan.is_none() {
        config.vsw_uplink = None;
        config.vsw_vlan = None;
    }

    // Bridge/NAT VMs carry no WolfNet IP — mirror the update path so a
    // create-with-bridge can't persist a stale/auto wolfnet_ip.
    if matches!(config.network_mode.as_deref(), Some("bridge") | Some("nat")) {
        config.wolfnet_ip = None;
    }

    // If importing a disk image, set it on the config
    if let Some(ref img) = body.import_image
        && !img.is_empty() {
            config.import_image = Some(img.clone());
        }

    // Convert extra disks from request to StorageVolume structs
    for disk in &body.extra_disks {
        config.extra_disks.push(StorageVolume {
            name: format!("{}-{}", body.name, disk.name),
            size_gb: disk.size_gb,
            storage_path: disk.storage_path.clone(),
            format: disk.format.clone(),
            bus: disk.bus.clone(),
        });
    }

    // Extra NICs (auto-generate MACs where missing)
    config.extra_nics = body.extra_nics.iter().map(|n| {
        let mut nic = n.clone();
        if nic.mac.is_none() || nic.mac.as_ref().map(|m| m.is_empty()).unwrap_or(false) {
            nic.mac = Some(super::manager::generate_mac());
        }
        nic
    }).collect();

    // USB/PCI passthrough devices
    config.usb_devices = body.usb_devices.clone();
    config.pci_devices = body.pci_devices.iter().map(|p| {
        let mut d = p.clone();
        if let Ok(norm) = passthrough::normalize_bdf(&d.bdf) {
            d.bdf = norm;
        }
        d
    }).collect();

    match manager.create_vm(config) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct UpdateVmRequest {
    cpus: Option<u32>,
    memory_mb: Option<u32>,
    disk_size_gb: Option<u32>,
    iso_path: Option<String>,
    wolfnet_ip: Option<String>,
    os_disk_bus: Option<String>,
    net_model: Option<String>,
    drivers_iso: Option<String>,
    auto_start: Option<bool>,
    bios_type: Option<String>,
    /// Emulated TPM 2.0 toggle. See `VmConfig::tpm`.
    tpm: Option<bool>,
    /// UEFI Secure Boot toggle. See `VmConfig::secure_boot`.
    secure_boot: Option<bool>,
    boot_order: Option<Vec<String>>,
    vnc_external: Option<bool>,
    extra_nics: Option<Vec<super::manager::NicConfig>>,
    usb_devices: Option<Vec<UsbDevice>>,
    pci_devices: Option<Vec<PciDevice>>,
    /// Primary-NIC network mode: "wolfnet" | "bridge" | "nat".
    network_mode: Option<String>,
    /// Bridge name for `network_mode == "bridge"`.
    bridge: Option<String>,
    bridge_ip_mode: Option<String>,
    bridge_ip: Option<String>,
    bridge_gateway: Option<String>,
    /// The vSwitch selection behind `bridge`, when the operator used the
    /// vSwitch preset. Persisted so the editor re-opens on the right card
    /// instead of guessing from the bridge name. Empty uplink clears it.
    vsw_uplink: Option<String>,
    vsw_vlan: Option<u32>,
    /// Free-text operator notes / description. Empty string clears it.
    notes: Option<String>,
    /// Operator-supplied extra QEMU args (e.g. Windows-11 audio). Empty
    /// string clears it. Tokenised server-side; never shell-evaluated.
    extra_qemu_args: Option<String>,
}

async fn update_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<UpdateVmRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    // Media paths go into comma-delimited hypervisor args — reject a comma
    // (config-separator injection) or control chars at the boundary.
    if let Err(resp) = validate_media_path(body.iso_path.as_deref(), "ISO path") { return resp; }
    if let Err(resp) = validate_media_path(body.drivers_iso.as_deref(), "VirtIO drivers ISO path") { return resp; }

    // Validate network_mode at the boundary (same as CreateVmRequest).
    if let Some(ref nm) = body.network_mode
        && !matches!(nm.as_str(), "" | "wolfnet" | "bridge" | "nat") {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("invalid network_mode '{}': expected wolfnet | bridge | nat", nm)
            }));
        }

    // WolfHA: a standby's definition is managed by the sync stream (any
    // edit here would be overwritten by the next round); on a protected
    // primary, ordinary edits replicate fine but the ones that break the
    // replication invariants are refused with the way out spelled out.
    {
        let store = crate::wolfha::HaStore::load();
        if let Some(e) = store.get(&name).filter(|e| e.kind == crate::wolfha::SubjectKind::Vm) {
            if e.role == crate::wolfha::HaRole::Replica {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": format!("'{}' is a WolfHA standby — its definition comes from the primary and edits here would be overwritten by the next sync. Edit the VM on its active node.", name)
                }));
            }
            if body.disk_size_gb.is_some() {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "this VM is WolfHA-protected and its standbys hold disks of the current size — resizing would break every incremental. Disable WolfHA, resize, then enable it again (which re-seeds at the new size)."
                }));
            }
            if body.tpm == Some(true) {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "this VM is WolfHA-protected — TPM state is not replicated, so a TPM cannot be added while HA is enabled. Disable WolfHA first."
                }));
            }
            if body.usb_devices.as_ref().is_some_and(|d| !d.is_empty())
                || body.pci_devices.as_ref().is_some_and(|d| !d.is_empty())
            {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "this VM is WolfHA-protected — passthrough hardware is attached to this host and cannot fail over. Disable WolfHA first."
                }));
            }
        }
    }

    let manager = state.vms.lock().unwrap();
    match manager.update_vm(&name, body.cpus, body.memory_mb, body.iso_path.clone(),
                            body.wolfnet_ip.clone(), body.disk_size_gb,
                            body.os_disk_bus.clone(), body.net_model.clone(),
                            body.drivers_iso.clone(), body.auto_start,
                            body.bios_type.clone(),
                            body.tpm, body.secure_boot,
                            body.extra_nics.clone(),
                            body.usb_devices.clone(),
                            body.pci_devices.clone(),
                            body.network_mode.clone(),
                            body.bridge.clone(),
                            body.bridge_ip_mode.clone(),
                            body.bridge_ip.clone(),
                            body.bridge_gateway.clone(),
                            body.vsw_uplink.clone(),
                            body.vsw_vlan,
                            body.boot_order.clone(),
                            body.vnc_external,
                            body.notes.clone(),
                            body.extra_qemu_args.clone()) {
        // Some(msg) is a non-fatal advisory (e.g. libvirt hardware edits that
        // apply on next boot) the UI shows next to the success toast.
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "success": true, "message": msg })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

async fn get_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.get_vm(&name) {
        Some(vm) => {
            // Attach the hypervisor backend so the editor can tailor its UI
            // (running-VM note wording, Proxmox OS-disk-bus lock).
            let platform = manager.vm_platform(&name);
            match serde_json::to_value(&vm) {
                Ok(mut v) => {
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("platform".to_string(), serde_json::json!(platform));
                    }
                    HttpResponse::Ok().json(v)
                }
                // Should never happen for a well-formed VmConfig; degrade
                // gracefully to the raw VM rather than an empty body.
                Err(_) => HttpResponse::Ok().json(vm),
            }
        }
        None => HttpResponse::NotFound().json(serde_json::json!({ "error": "VM not found" })),
    }
}

async fn delete_vm(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    // Deleting a protected primary would orphan its replicas (and the HA
    // entry would keep trying to sync a ghost); deleting a standby is the
    // WolfHA page's job (Disable, with or without removing copies).
    if let Some(refusal) = wolfha_vm_guard(&name, "deleting it") { return refusal; }
    let manager = state.vms.lock().unwrap();
    
    match manager.delete_vm(&name) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct VmActionRequest {
    action: String,
}

async fn vm_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<VmActionRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    // A start must not bring up a second copy of a WolfNet IP already live
    // elsewhere in the cluster. Read the IP under a brief lock, then release
    // it before the async cluster check (never hold the mutex across await).
    if body.action == "start" {
        let ip = {
            let manager = state.vms.lock().unwrap();
            manager.get_vm(&name).and_then(|c| c.wolfnet_ip)
        };
        if let Some(ip) = ip.filter(|s| !s.trim().is_empty())
            && let Some(holder) = crate::api::wolfnet_ip_active_elsewhere(&state, &ip).await
        {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": format!("WolfNet IP already in use: {} (active on {})", ip.trim(), holder)
            }));
        }
    }
    // A WolfHA standby VM carries its primary's MAC and IPs — hand-starting
    // it while the primary runs puts two identical machines on one L2.
    // Promotion (the WolfHA page) is the sanctioned way to start it.
    // Mirrors the LXC guard in api::mod.rs container actions.
    if matches!(body.action.as_str(), "start" | "restart" | "resume") {
        let store = crate::wolfha::HaStore::load();
        let is_standby = store.get(&name).map(|e| {
            e.kind == crate::wolfha::SubjectKind::Vm && e.role == crate::wolfha::HaRole::Replica
        }).unwrap_or(false);
        if is_standby {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": format!(
                    "'{}' is a WolfHA standby — starting it here would collide with the active copy. Use Promote on the WolfHA page instead.",
                    name
                )
            }));
        }
    }

    let manager = state.vms.lock().unwrap();

    let result = match body.action.as_str() {
        "start" => manager.start_vm(&name),
        // Graceful ACPI shutdown — tries to let the guest close cleanly.
        // qm / virsh / SIGTERM variants depending on backend.
        "stop" => manager.stop_vm(&name, false),
        // Power-yank — equivalent to the old `stop` behaviour. For when
        // the guest is wedged or the user needs an immediate halt.
        "force-stop" => manager.stop_vm(&name, true),
        // Reboot the guest (qm/virsh reboot; native QMP system_reset).
        "restart" => manager.restart_vm(&name),
        // Suspend/resume to RAM (qm/virsh suspend|resume; native QMP stop/cont).
        "pause" => manager.pause_vm(&name),
        "resume" => manager.resume_vm(&name),
        _ => Err(format!("Unknown action: {}", body.action)),
    };
    
    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct VmCloneRequest {
    new_name: String,
    /// Full clone copies the disk image(s); linked clone (Proxmox only)
    /// uses a thin overlay. libvirt's `virt-clone` is always full; native
    /// clones are always full (file copy of the qcow2). Defaults to full
    /// so a careless caller doesn't end up with a dangling backing chain.
    #[serde(default = "default_true")]
    full: bool,
}

fn default_true() -> bool { true }

/// POST /api/vms/{name}/clone — duplicate a VM on this host.
///
/// Dispatches by platform:
///   * Proxmox  → `qm clone <vmid> <new-vmid> --name <new-name> [--full 1]`
///   * libvirt  → `virt-clone --original <name> --name <new-name> --auto-clone`
///   * native   → file-copies the OS disk + extra disks, regenerates MACs,
///     writes a fresh JSON config with cleared runtime fields.
///
/// The clone runs synchronously (a full disk copy can take minutes on
/// large VMs), so the handler is wrapped in `web::block` to keep the
/// actix worker pool free.
async fn vm_clone(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VmCloneRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let new_name = body.new_name.clone();
    let full = body.full;

    // Plan FIRST under the lock, synchronously. prepare_clone is
    // fast (validation + a list_vms read) and its failures are all
    // user-input problems — return them as 400 so the frontend
    // distinguishes them from runtime errors. The lock is dropped
    // before we hand the plan off to the blocking executor.
    let plan = match state.vms.lock().unwrap().prepare_clone(&name, &new_name) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };

    // Execute the actual clone in a blocking task so the multi-minute
    // disk copy / qm clone / virt-clone subprocess doesn't block the
    // actix worker. Lock is already released; the executor owns the
    // plan and doesn't touch shared state.
    let result = web::block(move || super::manager::execute_clone(plan, &new_name, full)).await;

    match result {
        Ok(Ok(_))  => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
        Err(e)     => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("clone task failed: {}", e)
        })),
    }
}

async fn vm_logs(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let manager = state.vms.lock().unwrap();

    let log_path = manager.base_dir.join(format!("{}.log", name));
    let log_content = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|_| "No logs available for this VM.".to_string());

    HttpResponse::Ok().json(serde_json::json!({ "name": name, "logs": log_content }))
}

/// GET /api/vms/{name}/vnc-password — the external-VNC password for a VM
/// started with `vnc_external`. Authed. `null` when the VM isn't running
/// externally. Read from the runtime file (never the config), so it stays out
/// of config exports/backups. The browser console uses it to auth; the editor
/// shows it so the operator can connect an external VNC client.
async fn vm_vnc_password(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let (password, port, external) = {
        let manager = state.vms.lock().unwrap();
        let pw = manager.read_runtime_vnc_password(&name);
        let vm = manager.get_vm(&name);
        let port = vm.as_ref().and_then(|v| v.vnc_port);
        let external = vm.as_ref().map(|v| v.vnc_external).unwrap_or(false);
        (pw, port, external)
    };
    HttpResponse::Ok().json(serde_json::json!({
        "password": password,
        "vnc_port": port,
        "external": external,
    }))
}

/// GET /api/vms/{name}/start-command — the raw command WolfStack/the
/// hypervisor uses to start this VM, for display in the editor. Authed.
/// Returns `{ command, source }` where source is native|proxmox|libvirt.
/// Honest degradation: if a backend can't produce the command, `command`
/// carries a clear message (never a fabricated command) and HTTP stays 200.
async fn vm_start_command(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    let (command, source) = {
        let manager = state.vms.lock().unwrap();
        manager.start_command(&name)
    };
    HttpResponse::Ok().json(serde_json::json!({
        "command": command,
        "source": source,
    }))
}

/// GET /api/vms/{name}/serial-status — is this VM wired up for a serial
/// console (so `qm terminal` / `virsh console` / socat-to-serial-sock
/// actually has somewhere to attach)? Frontend calls this before opening
/// the terminal window so it can pop an "add serial console?" prompt when
/// missing, instead of dropping the user into a dead WebSocket.
async fn vm_serial_status(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    let backend = if crate::containers::is_proxmox() {
        "pve"
    } else if crate::containers::is_libvirt() {
        "libvirt"
    } else {
        "standalone"
    };

    let configured: bool;
    let running: bool;
    match backend {
        "pve" => {
            let manager = state.vms.lock().unwrap();
            let vmid = manager.qm_vmid_by_name(&name);
            drop(manager);
            let Some(vmid) = vmid else {
                return HttpResponse::NotFound().json(serde_json::json!({"error": format!("VM '{}' not found", name)}));
            };
            // `qm config` lists current config; a `serial0:` line means an
            // emulated UART is wired to a socket we can attach to.
            let cfg = std::process::Command::new("qm")
                .args(["config", &vmid.to_string()])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            configured = cfg.lines().any(|l| l.trim_start().starts_with("serial0:"));
            // Running = has an associated qemu process per `qm status`.
            let status = std::process::Command::new("qm")
                .args(["status", &vmid.to_string()])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            running = status.contains("running");
        }
        "libvirt" => {
            let xml = std::process::Command::new("virsh")
                .args(["dumpxml", &name])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            // `virsh console` wants a matching <serial>/<console> pair.
            // Some libvirt versions auto-mirror one from the other, but
            // the conservative answer is "both present". If either is
            // missing, vm_add_serial() will top up just the missing half.
            configured = xml.contains("<serial ") && xml.contains("<console ");
            let state = std::process::Command::new("virsh")
                .args(["domstate", &name])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            running = state.trim() == "running";
        }
        _ => {
            // Standalone QEMU. Three distinct states:
            //  - not running → configured=false,running=false ("start it first")
            //  - running, new QEMU spawn (has -chardev socket) → both true
            //  - running, old QEMU spawn from before the serial-socket wiring
            //    → process up, socket missing. Report running=true so the
            //    frontend skips the "start it first" path and falls into
            //    the "add serial console?" prompt (which returns a clear
            //    "restart the VM" message for standalone).
            let sock = format!("/var/lib/wolfstack/vms/{}.serial.sock", name);
            let sock_exists = std::path::Path::new(&sock).exists();
            let process_running = {
                let m = state.vms.lock().unwrap();
                m.check_running(&name)
            };
            running = process_running;
            configured = sock_exists;
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "backend": backend,
        "configured": configured,
        "running": running,
        "hint": "If the terminal stays blank after opening, the guest may need `console=ttyS0` on its kernel cmdline and a getty on ttyS0 — same setup as bare-metal serial consoles."
    }))
}

/// POST /api/vms/{name}/add-serial — add a serial console device to a VM
/// that doesn't have one. Takes effect on next boot for running VMs;
/// applies immediately for stopped ones. Standalone QEMU VMs already get
/// a serial socket at create time, so this endpoint only handles the
/// PVE and libvirt paths where a pre-existing VM may be missing one.
async fn vm_add_serial(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();

    if crate::containers::is_proxmox() {
        let vmid = {
            let m = state.vms.lock().unwrap();
            m.qm_vmid_by_name(&name)
        };
        let Some(vmid) = vmid else {
            return HttpResponse::NotFound().json(serde_json::json!({"error": format!("VM '{}' not found in Proxmox", name)}));
        };
        // Check running-ness so we can tell the user whether a reboot is
        // needed for the new device to show up in the guest.
        let running = std::process::Command::new("qm")
            .args(["status", &vmid.to_string()])
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
            .contains("running");

        let output = std::process::Command::new("qm")
            .args(["set", &vmid.to_string(), "--serial0", "socket"])
            .output()
            .map_err(|e| format!("Failed to run qm set: {}", e));
        match output {
            Ok(o) if o.status.success() => {
                HttpResponse::Ok().json(serde_json::json!({
                    "ok": true,
                    "message": "serial0 added (socket)",
                    "requires_reboot": running,
                }))
            }
            Ok(o) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("qm set failed: {}", String::from_utf8_lossy(&o.stderr).trim())
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
        }
    } else if crate::containers::is_libvirt() {
        // libvirt: a working serial setup wants a matching <serial>/<console>
        // pair — some libvirt versions auto-mirror, others reject a console
        // without an associated serial. We probe what's already there and
        // attach each missing half separately. Console devices aren't
        // hot-pluggable so we always write to the persisted XML (`--config`)
        // and tell the caller to reboot if the domain is currently up.
        let running = std::process::Command::new("virsh")
            .args(["domstate", &name])
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
            .trim() == "running";

        let xml_dump = std::process::Command::new("virsh")
            .args(["dumpxml", &name])
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let has_serial = xml_dump.contains("<serial ");
        let has_console = xml_dump.contains("<console ");

        // Build a list of (label, xml) pieces to attach. Skip anything
        // that's already present to avoid "device already exists" errors.
        let mut pieces: Vec<(&str, &str)> = Vec::new();
        if !has_serial {
            pieces.push(("serial",  "<serial type='pty'><target port='0'/></serial>"));
        }
        if !has_console {
            pieces.push(("console", "<console type='pty'><target type='serial' port='0'/></console>"));
        }

        // Shouldn't happen (caller checks configured=false before calling)
        // but handle gracefully if everything's already wired.
        if pieces.is_empty() {
            return HttpResponse::Ok().json(serde_json::json!({
                "ok": true,
                "message": "serial + console already configured",
                "requires_reboot": false,
            }));
        }

        let mut errors: Vec<String> = Vec::new();
        let mut attached: Vec<&str> = Vec::new();
        for (label, xml) in &pieces {
            let xml_path = format!("/tmp/wolfstack-{}-{}.xml", label, uuid::Uuid::new_v4());
            if let Err(e) = std::fs::write(&xml_path, xml) {
                errors.push(format!("write {} xml: {}", label, e));
                continue;
            }
            let out = std::process::Command::new("virsh")
                .args(["attach-device", &name, &xml_path, "--config"])
                .output();
            let _ = std::fs::remove_file(&xml_path);
            match out {
                Ok(o) if o.status.success() => attached.push(label),
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    // libvirt uses varying wording for "this device already
                    // exists in the config" — treat any such response as a
                    // no-op success rather than a hard failure.
                    let lower = stderr.to_lowercase();
                    if lower.contains("already exist") || lower.contains("duplicate") {
                        attached.push(label);
                    } else {
                        errors.push(format!("{}: {}", label, stderr.trim()));
                    }
                }
                Err(e) => errors.push(format!("{}: {}", label, e)),
            }
        }

        if !errors.is_empty() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("virsh attach-device failed: {}", errors.join("; "))
            }));
        }
        HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "message": format!("attached: {}", attached.join(", ")),
            "requires_reboot": running,
        }))
    } else {
        // Standalone QEMU wires the serial socket at start time (since the
        // change that added `-chardev socket ... -serial chardev:serial0`
        // to the spawn args). A running VM without a socket is one that
        // was started by an older WolfStack — stop and start it to pick
        // up the new args.
        let running = {
            let m = state.vms.lock().unwrap();
            m.check_running(&name)
        };
        if running {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "This VM was started before serial-console support was added. Stop and start it again to enable the terminal."
            }))
        } else {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Start the VM first — standalone QEMU creates its serial socket at boot time."
            }))
        }
    }
}

// ─── Storage Volume Endpoints ───

#[derive(Deserialize)]
struct AddVolumeRequest {
    name: String,
    size_gb: u32,
    storage_path: Option<String>,
    format: Option<String>,
    bus: Option<String>,
}

async fn add_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<AddVolumeRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let vm_name = path.into_inner();
    // WolfHA replicates the OS disk only (the one the dirty bitmap
    // tracks) — a data disk added now would silently not exist on the
    // standbys, and a failover would lose it.
    if let Some(refusal) = wolfha_vm_guard(&vm_name, "adding a data disk") { return refusal; }
    let manager = state.vms.lock().unwrap();

    match manager.add_volume(&vm_name, &body.name, body.size_gb, 
                             body.storage_path.as_deref(), body.format.as_deref(),
                             body.bus.as_deref()) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

async fn remove_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (vm_name, vol_name) = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.remove_volume(&vm_name, &vol_name, true) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct ResizeVolumeRequest {
    size_gb: u32,
}

async fn resize_volume(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>, body: web::Json<ResizeVolumeRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let (vm_name, vol_name) = path.into_inner();
    let manager = state.vms.lock().unwrap();

    match manager.resize_volume(&vm_name, &vol_name, body.size_gb) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "success": true })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

// ─── VM Migration Endpoints ───

#[derive(Deserialize)]
struct VmMigrateRequest {
    target_node: String,
    new_name: Option<String>,
    /// Destination storage path / PVE storage ID on the target node
    /// — where the final qcow2(s) end up after import.
    storage: Option<String>,
    /// Staging root on the SOURCE node for the export tarball. The
    /// default `/tmp` is often a small tmpfs; operators whose VMs
    /// don't fit can point this at a big disk (e.g. /var/wolftmp).
    #[serde(default)]
    staging_dir: Option<String>,
    /// Staging root on the TARGET node used by vm_import_external
    /// to extract + stage the incoming archive. Sent to the target
    /// as a `target_staging_dir` multipart field; fell back to
    /// $TMPDIR / /tmp on the target when absent.
    #[serde(default)]
    target_staging_dir: Option<String>,
    /// When true, the target node imports the VM as a PVE-managed VM
    /// via `qm create` + `qm importdisk`. Requires the target to be
    /// a Proxmox host and `storage` to be a PVE storage id.
    #[serde(default)]
    proxmox: bool,
    #[serde(default)]
    target_address: Option<String>,
    #[serde(default)]
    target_port: Option<u16>,
    /// Target's operator-configured migration address (its dedicated-NIC IP),
    /// forwarded by the UI from the master's full cluster view so the source
    /// uses the pinned NIC regardless of its own gossip view. Empty/absent ⇒
    /// use whatever this node already knows (`Node::migration_host`).
    #[serde(default)]
    target_migration_address: Option<String>,
}

#[derive(Deserialize)]
pub struct VmDiskMigrateRequest {
    /// Target storage path on the same node.
    pub target: String,
    /// Whether to delete source files after a successful copy.
    /// Default false — we keep the source so the operator can verify
    /// the new copy boots before reclaiming space.
    #[serde(default)]
    pub remove_source: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VmMigrateExternalRequest {
    target_url: String,
    target_token: String,
    new_name: Option<String>,
    storage: Option<String>,
    delete_source: Option<bool>, // accepted but ignored — source is never deleted
    /// Staging root on the source node — same semantics as vm_migrate.
    #[serde(default)]
    staging_dir: Option<String>,
    /// Staging root on the target — passed as target_staging_dir in the
    /// multipart upload so the target honours it during extraction.
    #[serde(default)]
    target_staging_dir: Option<String>,
    /// Request PVE-managed import on the target.
    #[serde(default)]
    proxmox: bool,
}

/// Intra-cluster migration preflight. Talks to the target node BEFORE
/// the source is stopped, so a failing check leaves the source running
/// and the operator can correct the input. Two checks today:
///
///   1. **Name collision** — `GET /api/vms` on the target. If a VM
///      with `new_name` already exists, refuse: importing on top of
///      it would either fail at import time or silently clobber the
///      existing config.
///   2. **Free space** — `GET /api/storage/list` on the target. If
///      `storage_id` is set and we can find a matching entry, we
///      require `available_bytes >= expected_total`. If `storage_id`
///      is empty (default) we skip the check; the operator has opted
///      out of picking a storage and the import logic will land it on
///      whatever default the target uses.
///
/// Errors are returned as human-readable strings; the caller writes
/// them straight into the migration task's `error` field.
async fn migrate_preflight_intra(
    client: &reqwest::Client,
    node: &crate::agent::Node,
    new_name: &str,
    storage_id: &str,
    expected_total: Option<u64>,
    cluster_secret: &str,
) -> Result<(), String> {
    // Preflight over the SAME host the upload will use (the migration NIC if
    // the operator pinned one) so an unreachable migration path fails here,
    // before the source VM is stopped — not mid-upload.
    let mig_host = node.migration_host();
    // ── 1. Name collision ───────────────────────────────────────────
    let vms_urls = build_node_urls(mig_host, node.port, "/api/vms");
    let mut last_err = String::new();
    let mut name_clash_checked = false;
    for url in &vms_urls {
        match client.get(url)
            .peer_auth(cluster_secret)
            .timeout(Duration::from_secs(10))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await
                    .map_err(|e| format!("parse target VM list: {}", e))?;
                let arr = body.as_array().cloned().unwrap_or_default();
                if arr.iter().any(|v| v.get("name").and_then(|n| n.as_str()) == Some(new_name)) {
                    return Err(format!(
                        "Target node '{}' already has a VM named '{}'. Pick a different new_name or remove the existing VM first.",
                        node.hostname.as_str(), new_name));
                }
                name_clash_checked = true;
                break;
            }
            Ok(r) => { last_err = format!("{}: HTTP {}", url, r.status()); }
            Err(e) => { last_err = format!("{}: {}", url, e); }
        }
    }
    if !name_clash_checked {
        return Err(format!("Pre-flight: could not list VMs on target — {}", last_err));
    }

    // ── 2. Free-space check (only when both storage and size known) ─
    let expected = match expected_total { Some(b) if b > 0 => b, _ => return Ok(()) };
    if storage_id.is_empty() { return Ok(()); }
    let storage_urls = build_node_urls(mig_host, node.port, "/api/storage/list");
    for url in &storage_urls {
        match client.get(url)
            .peer_auth(cluster_secret)
            .timeout(Duration::from_secs(10))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await
                    .map_err(|e| format!("parse target storage list: {}", e))?;
                let storages = body.get("storages").and_then(|s| s.as_array()).cloned().unwrap_or_default();
                let entry = storages.iter().find(|s| s.get("id").and_then(|i| i.as_str()) == Some(storage_id));
                let Some(entry) = entry else {
                    // Storage id we don't recognise — let the import
                    // surface a clear error rather than us guessing.
                    return Ok(());
                };
                let avail = entry.get("available_bytes").and_then(|a| a.as_u64()).unwrap_or(0);
                if avail < expected {
                    return Err(format!(
                        "Pre-flight: target storage '{}' has {} free, but the VM's disks total {}. Pick a larger storage or free space and retry.",
                        storage_id, format_bytes_human(avail), format_bytes_human(expected)));
                }
                return Ok(());
            }
            Ok(_) | Err(_) => { /* try next URL */ }
        }
    }
    // We failed to reach storage/list — non-fatal; the upload will
    // fail loudly later if space is really short.
    Ok(())
}

/// POST /api/vms/{name}/migrate — migrate VM to another cluster node.
/// Spawns a background task so the HTTP call returns immediately with a
/// `task_id`; the frontend polls `/api/migration/{id}/status` to drive
/// its progress bar. Phases are: `preflight` → `stopping` → `export` →
/// `upload` → `import` → `done` / `failed`.
async fn vm_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VmMigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    // Migration moves the disk out from under the replication chain and
    // the HA entry stays behind pointing at nothing.
    if let Some(refusal) = wolfha_vm_guard(&name, "migrating it") { return refusal; }
    let new_name = body.new_name.as_deref().unwrap_or(&name).to_string();

    // Resolve target node synchronously so bad targets produce a 4xx
    // rather than a task stuck in preflight.
    let mut node = match state.cluster.get_node(&body.target_node) {
        Some(n) => n,
        None => {
            if let Some(ref addr) = body.target_address {
                let port = body.target_port.unwrap_or(8553);
                tracing::info!("VM migrate: node '{}' not in cluster state, using fallback {}:{}", body.target_node, addr, port);
                crate::agent::Node {
                    pubkey: None,
                    manager: true,
                    id: body.target_node.clone(),
                    address: addr.clone(),
                    migration_address: None,
                    port,
                    hostname: addr.clone(),
                    is_self: false,
                    online: true,
                    node_type: "wolfstack".to_string(),
                    last_seen: 0,
                    metrics: None,
                    components: vec![],
                    docker_count: 0,
                    lxc_count: 0,
                    vm_count: 0,
                    compose_count: 0,
                    public_ip: None,
                    pve_token: None,
                    pve_fingerprint: None,
                    pve_node_name: None,
                    pve_cluster_name: None,
                    cluster_name: None,
                    join_verified: false,
                    has_docker: false,
                    has_lxc: false,
                    has_kvm: false,
                    login_disabled: false,
                    tls: false,
                    update_script: None,
                    self_id: None,
                    workload_subnets: Vec::new(),
                    site: None,
                    display_name: None,
                    roles: Vec::new(),
                }
            } else {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Target node not found"}));
            }
        }
    };
    if node.is_self {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot migrate to the same node"}));
    }
    // The UI passes the target's operator-configured migration address (from
    // the master's full cluster view) so the upload uses the pinned NIC even
    // when THIS (source) node's own gossip view of the target predates the
    // setting. Falls back to whatever this node already knows (migration_host).
    if let Some(ma) = body.target_migration_address.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        node.migration_address = Some(ma.to_string());
    }

    // Precompute the expected archive size (pre-compression) so the
    // export progress bar has a sensible denominator. gzip on qcow2
    // typically compresses to ~40-60% of raw, so the bar will appear
    // to stall around 50% — better than no signal at all.
    let expected_total: Option<u64> = super::manager::read_vm_config(&name)
        .ok()
        .map(|c| super::manager::total_disk_bytes(&c))
        .filter(|b| *b > 0);

    let tasks = state.migration_tasks.clone();
    let task_id = migration_create(&tasks);

    let tid = task_id.clone();
    let state_clone = state.clone();
    let storage_val = body.storage.as_deref().unwrap_or("").to_string();
    let staging_dir = body.staging_dir.clone();
    let tgt_staging_val = body.target_staging_dir.as_deref().unwrap_or("").to_string();
    let proxmox_val = body.proxmox;
    let target_label = body.target_node.clone();

    tokio::spawn(async move {
        // Preflight — refuse BEFORE stopping the source if the target
        // already has a VM by this name, or has visibly insufficient
        // space on the chosen storage. Both failures otherwise lead to
        // a long fruitless upload followed by an import error, with
        // the source uselessly stopped throughout. See
        // migrate_preflight_intra above for what's checked.
        migration_update(&state_clone.migration_tasks, &tid, "preflight",
            &format!("Pre-flight checks against '{}'…", target_label));
        let preflight_client = &*VM_MIGRATION_CLIENT;
        if let Err(e) = migrate_preflight_intra(
            preflight_client, &node, &new_name, &storage_val,
            expected_total, &state_clone.cluster_secret,
        ).await {
            migration_fail(&state_clone.migration_tasks, &tid, &e);
            return;
        }

        migration_update(&state_clone.migration_tasks, &tid, "stopping", &format!("Stopping VM '{}' for consistent export…", name));
        {
            let manager = state_clone.vms.lock().unwrap();
            if let Err(e) = manager.stop_vm(&name, true) {
                tracing::warn!("Failed to stop VM '{}' before migration: {}", name, e);
            }
        }

        migration_update(&state_clone.migration_tasks, &tid, "export",
            &format!("Packaging disk archive{}…",
                expected_total.map(|b| format!(" (~{})", format_bytes_human(b))).unwrap_or_default()));

        // The exporter writes into /<staging>/wolfstack-vm-exports/ and
        // names the tarball `vm-<name>-<timestamp>.tar.gz`. We can't
        // know the exact final name in advance, so the watcher globs
        // that directory for the newest file once it appears.
        let watcher_staging = staging_dir.clone();
        let watcher_name = name.clone();
        let watcher_tasks = state_clone.migration_tasks.clone();
        let watcher_tid = tid.clone();
        let watcher_expected = expected_total;
        let watcher_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher_flag = watcher_stop.clone();
        tokio::spawn(async move {
            poll_export_archive_size(
                watcher_tasks, watcher_tid, watcher_staging, watcher_name,
                watcher_expected, watcher_flag,
            ).await;
        });

        let export_result = {
            let name_owned = name.clone();
            let staging_owned = staging_dir.clone();
            tokio::task::spawn_blocking(move || {
                super::manager::export_vm_with_staging(&name_owned, staging_owned.as_deref())
            }).await.unwrap_or_else(|e| Err(format!("export task join: {}", e)))
        };
        watcher_stop.store(true, std::sync::atomic::Ordering::Relaxed);

        let archive_path = match export_result {
            Ok(p) => p,
            Err(e) => {
                let manager = state_clone.vms.lock().unwrap();
                let _ = manager.start_vm(&name);
                migration_fail(&state_clone.migration_tasks, &tid, &format!("Export failed: {}", e));
                return;
            }
        };

        // Source stays running from here — destination gets the consistent copy.
        {
            let manager = state_clone.vms.lock().unwrap();
            let _ = manager.start_vm(&name);
        }

        let archive_bytes = match std::fs::read(&archive_path) {
            Ok(b) => b,
            Err(e) => {
                super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
                migration_fail(&state_clone.migration_tasks, &tid, &format!("Read archive: {}", e));
                return;
            }
        };

        let total_bytes = archive_bytes.len() as u64;
        migration_update(&state_clone.migration_tasks, &tid, "upload",
            &format!("Uploading {} to {}…", format_bytes_human(total_bytes), target_label));
        migration_progress(&state_clone.migration_tasks, &tid, Some(0), Some(total_bytes), Some(0.0));

        // Bulk disk upload rides the migration NIC if the operator pinned one
        // (migration_host); otherwise the node's normal address.
        let mig_host = node.migration_host();
        let mut import_urls = if node.node_type == "proxmox" {
            let mut urls = build_node_urls(mig_host, 8553, "/api/vms/import-external");
            urls.extend(build_node_urls(mig_host, 8552, "/api/vms/import-external"));
            urls
        } else {
            build_node_urls(mig_host, node.port, "/api/vms/import-external")
        };
        // If a distinct migration NIC was pinned, append the node's normal
        // address as a fallback so a mis-pinned / unreachable fast path can't
        // fail the whole migration — it just reverts to the management path.
        if mig_host != node.address {
            if node.node_type == "proxmox" {
                import_urls.extend(build_node_urls(&node.address, 8553, "/api/vms/import-external"));
                import_urls.extend(build_node_urls(&node.address, 8552, "/api/vms/import-external"));
            } else {
                import_urls.extend(build_node_urls(&node.address, node.port, "/api/vms/import-external"));
            }
        }

        // Shared pool — see VM_MIGRATION_CLIENT. 1-hour total timeout
        // set per-request for the long upload; 5s connect_timeout is
        // baked into the client.
        let client = &*VM_MIGRATION_CLIENT;

        let file_name = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let mut last_err: Option<String> = None;
        let mut finished = false;

        for import_url in &import_urls {
            // Build a streaming body so upload progress is reported
            // per-chunk. The whole archive already lives in memory, so
            // we just slice it on the outgoing stream side.
            let (body, _total) = build_progress_body(
                &archive_bytes, total_bytes, state_clone.migration_tasks.clone(), tid.clone(),
            );
            let part = reqwest::multipart::Part::stream_with_length(body, total_bytes)
                .file_name(file_name.clone())
                .mime_str("application/octet-stream").unwrap_or_else(|_| reqwest::multipart::Part::text("".to_string()));

            let mut form = reqwest::multipart::Form::new()
                .text("new_name", new_name.clone())
                .text("storage", storage_val.clone())
                .part("archive", part);
            if !tgt_staging_val.is_empty() {
                form = form.text("target_staging_dir", tgt_staging_val.clone());
            }
            if proxmox_val {
                form = form.text("proxmox", "1".to_string());
            }

            match client.post(import_url)
                .peer_auth(state_clone.cluster_secret.clone())
                .timeout(Duration::from_secs(3600))
                .multipart(form)
                .send()
                .await
            {
                Ok(r) => {
                    super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
                    if r.status().is_success() {
                        // Drain any ack body so the socket returns
                        // to the pool.
                        let _ = r.bytes().await;
                        migration_done(&state_clone.migration_tasks, &tid,
                            &format!("VM '{}' transferred to '{}' on node '{}'. Destination is stopped — start it manually when ready.",
                                name, new_name, target_label));
                    } else {
                        let err_text = r.text().await.unwrap_or_default();
                        migration_fail(&state_clone.migration_tasks, &tid, &format!("Import on target failed: {}", err_text));
                    }
                    finished = true;
                    break;
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            }
        }

        if !finished {
            super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
            migration_fail(&state_clone.migration_tasks, &tid,
                &format!("Transfer to {} failed on all ports/protocols: {}",
                    node.address, last_err.unwrap_or_default()));
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "task_id": task_id,
        "message": "Migration started"
    }))
}

/// POST /api/vms/{name}/disk/migrate — move a stopped VM's disks to a
/// different storage path on the same node. Counterpart to the
/// `/api/containers/lxc/{name}/disk/migrate` endpoint for LXC; same
/// shape (`target` path + `remove_source` flag).
///
/// Spawns a background task and returns a `task_id` immediately so the
/// frontend can show a real progress bar instead of blocking on the
/// response. Native path polls the target file sizes; Proxmox path
/// shells out to `qm move_disk` with stderr streamed and scraped for
/// the `(NN.N%)` counter PVE prints.
async fn vm_disk_migrate(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VmDiskMigrateRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    // Moving the OS disk mid-chain would leave the replicas resolving a
    // path that exists only on the primary.
    if let Some(refusal) = wolfha_vm_guard(&name, "moving its storage") { return refusal; }
    let target = body.target.trim().to_string();
    let remove_source = body.remove_source;
    if target.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "target is required"}));
    }

    // Pre-read the config so the task_id-returning response can 404
    // cleanly and the bytes_total is known up front.
    let (expected_total, is_pve, pve_vmid) = match super::manager::read_vm_config(&name) {
        Ok(cfg) => {
            let vmid = cfg.vmid.filter(|_| crate::containers::is_proxmox());
            let total = super::manager::total_disk_bytes(&cfg);
            (total, vmid.is_some(), vmid)
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": e}));
        }
    };

    let tasks = state.migration_tasks.clone();
    let task_id = migration_create(&tasks);
    let tid = task_id.clone();
    let tasks_for_task = tasks.clone();

    tokio::spawn(async move {
        migration_update(&tasks_for_task, &tid, "disk_copy",
            &format!("Moving '{}' disks → {}{}…", name, target,
                if expected_total > 0 { format!(" ({})", format_bytes_human(expected_total)) } else { String::new() }));

        if is_pve {
            let vmid = pve_vmid.unwrap();
            let slots = match super::manager::pve_disk_slots_for_vmid(vmid, &target) {
                Ok(s) => s,
                Err(e) => {
                    migration_fail(&tasks_for_task, &tid, &format!("qm config: {}", e));
                    return;
                }
            };
            if slots.is_empty() {
                migration_fail(&tasks_for_task, &tid,
                    &format!("vmid {}: no disk slots needing migration — all disks already on '{}' (or no qcow/raw volumes found)",
                        vmid, target));
                return;
            }
            let slot_count = slots.len();
            let mut moved = Vec::new();
            for (idx, (slot, from)) in slots.iter().enumerate() {
                migration_update(&tasks_for_task, &tid, "disk_copy",
                    &format!("[{}/{}] Moving {} ({} → {})…", idx + 1, slot_count, slot, from, target));
                if let Err(e) = run_qm_move_disk_with_progress(
                    &tasks_for_task, &tid, vmid, slot, &target, remove_source,
                    DiskMoveProgress { slot_index: idx, slot_count },
                ).await {
                    migration_fail(&tasks_for_task, &tid,
                        &format!("qm move_disk {} {} → {} failed: {} (prior moved: [{}])",
                            vmid, slot, target, e, moved.join(", ")));
                    return;
                }
                moved.push(format!("{} ({}→{})", slot, from, target));
            }
            migration_done(&tasks_for_task, &tid,
                &format!("vmid {}: moved {} disk(s) to '{}' via qm move_disk [{}]",
                    vmid, moved.len(), target, moved.join(", ")));
            return;
        }

        // Native path: start a watcher on the target directory so the
        // operator sees bytes appear as fs::copy writes them.
        let watch_stop = Arc::new(AtomicBool::new(false));
        let watcher_flag = watch_stop.clone();
        let watcher_tasks = tasks_for_task.clone();
        let watcher_tid = tid.clone();
        let watcher_target = target.clone();
        let watcher_vm = name.clone();
        tokio::spawn(async move {
            poll_disk_copy_size(
                watcher_tasks, watcher_tid, watcher_target, watcher_vm,
                expected_total, watcher_flag,
            ).await;
        });

        let migrate_result = {
            let name_owned = name.clone();
            let target_owned = target.clone();
            tokio::task::spawn_blocking(move || {
                super::manager::migrate_storage(&name_owned, &target_owned, remove_source)
            }).await.unwrap_or_else(|e| Err(format!("migrate task join: {}", e)))
        };
        watch_stop.store(true, Ordering::Relaxed);

        match migrate_result {
            Ok(msg) => migration_done(&tasks_for_task, &tid, &msg),
            Err(e) => migration_fail(&tasks_for_task, &tid, &e),
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "task_id": task_id,
        "message": "Disk migration started"
    }))
}

/// Poll the target storage directory for a VM's migrated disk files
/// and report the sum of their sizes to the migration task. Used by
/// the native `fs::copy` disk-migrate path where there's no progress
/// stream from the copy itself — we watch the result instead. Stops
/// when `stop` is flipped (migration task has finished or failed).
async fn poll_disk_copy_size(
    tasks: MigrationTasks,
    tid: String,
    target_dir: String,
    vm_name: String,
    expected_total: u64,
    stop: Arc<AtomicBool>,
) {
    let target_path = std::path::Path::new(&target_dir);
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let Ok(entries) = std::fs::read_dir(target_path) else { continue; };
        let mut total: u64 = 0;
        // The OS disk is `<name>.qcow2`; extras are `<extraname>.<ext>`.
        // We can't easily distinguish extras vs pre-existing files, so
        // count files that were clearly just created: any file mtime'd
        // within the last 60 seconds, plus the OS-disk filename match.
        let os_disk_name = format!("{}.qcow2", vm_name);
        let now = std::time::SystemTime::now();
        for entry in entries.flatten() {
            let Some(fname) = entry.file_name().to_str().map(|s| s.to_string()) else { continue; };
            let Ok(md) = entry.metadata() else { continue; };
            let recent = md.modified().ok()
                .and_then(|t| now.duration_since(t).ok())
                .map(|d| d.as_secs() < 300)
                .unwrap_or(false);
            if fname == os_disk_name || recent {
                total += md.len();
            }
        }
        if expected_total > 0 {
            migration_progress(&tasks, &tid, Some(total), Some(expected_total), None);
        } else {
            migration_progress(&tasks, &tid, Some(total), None, None);
        }
    }
}

struct DiskMoveProgress {
    slot_index: usize,
    slot_count: usize,
}

/// Run `qm move_disk` for a single PVE disk slot, streaming its stderr
/// and parsing the `(NN.N%)` counter PVE prints. Per-slot progress is
/// mapped onto the overall percent so the bar advances smoothly across
/// multi-disk VMs: slot 2 of 4 at 50 % → overall 37.5 %.
async fn run_qm_move_disk_with_progress(
    tasks: &MigrationTasks,
    tid: &str,
    vmid: u32,
    slot: &str,
    target: &str,
    remove_source: bool,
    progress: DiskMoveProgress,
) -> Result<(), String> {
    let DiskMoveProgress { slot_index, slot_count } = progress;
    use tokio::process::Command as TokioCommand;
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut cmd = TokioCommand::new("qm");
    cmd.arg("move_disk").arg(vmid.to_string()).arg(slot).arg(target);
    if remove_source { cmd.arg("--delete").arg("1"); }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn qm: {}", e))?;
    let stdout = child.stdout.take().ok_or("missing stdout")?;
    let stderr = child.stderr.take().ok_or("missing stderr")?;

    let tasks_s = tasks.clone();
    let tid_s = tid.to_string();
    let stdout_reader = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            scan_pve_percent(&line, &tasks_s, &tid_s, slot_index, slot_count);
        }
    });

    let tasks_e = tasks.clone();
    let tid_e = tid.to_string();
    let mut captured_err = String::new();
    let stderr_reader = tokio::spawn(async move {
        let mut buf = String::new();
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            scan_pve_percent(&line, &tasks_e, &tid_e, slot_index, slot_count);
            buf.push_str(&line);
            buf.push('\n');
        }
        buf
    });

    let status = child.wait().await.map_err(|e| format!("qm wait: {}", e))?;
    let _ = stdout_reader.await;
    if let Ok(buf) = stderr_reader.await { captured_err = buf; }
    if !status.success() {
        return Err(captured_err.trim().to_string());
    }
    Ok(())
}

/// Scan a `qm move_disk` / `qm importdisk` output line for the
/// `(NN.N%)` counter and update the task's overall percent mapped
/// across multiple slots.
fn scan_pve_percent(
    line: &str,
    tasks: &MigrationTasks,
    tid: &str,
    slot_index: usize,
    slot_count: usize,
) {
    // Format: "transferred 4.0 GiB of 32.0 GiB (12.50%)" — we only
    // care about the bracketed percent. Avoid pulling in regex for
    // one pattern; a tiny hand-rolled scan is faster and clearer.
    if let Some(open) = line.rfind('(')
        && let Some(close) = line[open..].find('%') {
            let inside = &line[open + 1..open + close];
            if let Ok(p) = inside.trim().parse::<f64>() {
                let overall = (slot_index as f64 + p / 100.0) / slot_count.max(1) as f64 * 100.0;
                migration_progress(tasks, tid, None, None, Some(overall));
            }
        }
}

/// POST /api/vms/{name}/migrate-external — migrate VM to another cluster.
/// Returns a `task_id` immediately; progress is reported via
/// `/api/migration/{id}/status`.
async fn vm_migrate_external(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VmMigrateExternalRequest>,
) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let name = path.into_inner();
    if let Some(refusal) = wolfha_vm_guard(&name, "migrating it") { return refusal; }
    let new_name = body.new_name.as_deref().unwrap_or(&name).to_string();

    let expected_total: Option<u64> = super::manager::read_vm_config(&name)
        .ok()
        .map(|c| super::manager::total_disk_bytes(&c))
        .filter(|b| *b > 0);

    let tasks = state.migration_tasks.clone();
    let task_id = migration_create(&tasks);
    let tid = task_id.clone();
    let state_clone = state.clone();
    let target_url = body.target_url.clone();
    let target_token = body.target_token.clone();
    let storage_val = body.storage.as_deref().unwrap_or("").to_string();
    let staging_dir = body.staging_dir.clone();
    let tgt_staging_val = body.target_staging_dir.as_deref().unwrap_or("").to_string();
    let proxmox_val = body.proxmox;
    let target_label = target_url.replace("https://", "").replace("http://", "").split('/').next().unwrap_or(&target_url).to_string();

    tokio::spawn(async move {
        migration_update(&state_clone.migration_tasks, &tid, "preflight", &format!("Checking connectivity to {}…", target_label));
        let preflight_urls = crate::api::build_external_urls(&target_url, "/api/storage/list");
        let preflight_client = &*VM_MIGRATION_CLIENT;

        // Hit /api/storage/list — proves we can reach the target AND
        // (when the operator picked a storage) lets us check free
        // space before the upload starts. NOTE: /api/storage/list is
        // gated by require_auth, which today accepts X-WolfStack-Secret
        // (and session cookies) but NOT X-Transfer-Token. So this
        // check only succeeds when the external target shares our
        // cluster secret. If it doesn't, we abort here with a 403
        // — better than transferring multi-GB onto a target that
        // would reject the import anyway. The transfer token is sent
        // for future-proofing if storage_list ever accepts it.
        let mut storage_body: Option<serde_json::Value> = None;
        let mut preflight_err = String::new();
        for url in &preflight_urls {
            match preflight_client.get(url)
                .header("X-Transfer-Token", &target_token)
                .peer_auth(state_clone.cluster_secret.clone())
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    storage_body = resp.json::<serde_json::Value>().await.ok();
                    break;
                }
                Ok(resp) => { preflight_err = format!("{}: HTTP {}", url, resp.status()); }
                Err(e)   => { preflight_err = format!("{}: {}", url, e); }
            }
        }
        if storage_body.is_none() {
            migration_fail(&state_clone.migration_tasks, &tid,
                &format!("Pre-flight check failed — cannot reach destination: {}", preflight_err));
            return;
        }

        // Free-space check (best-effort — skip silently if we can't
        // resolve the storage id; the upload will fail loudly if
        // there really is no room).
        if let (Some(expected), false) = (expected_total, storage_val.is_empty())
            && let Some(body) = storage_body.as_ref() {
                let storages = body.get("storages").and_then(|s| s.as_array()).cloned().unwrap_or_default();
                if let Some(entry) = storages.iter().find(|s| s.get("id").and_then(|i| i.as_str()) == Some(storage_val.as_str())) {
                    let avail = entry.get("available_bytes").and_then(|a| a.as_u64()).unwrap_or(0);
                    if avail < expected {
                        migration_fail(&state_clone.migration_tasks, &tid, &format!(
                            "Pre-flight: target storage '{}' has {} free, but the VM's disks total {}. Pick a larger storage or free space and retry.",
                            storage_val, format_bytes_human(avail), format_bytes_human(expected)));
                        return;
                    }
                }
            }

        // Name-collision pre-flight is deliberately NOT done for
        // external migrations. `/api/vms` is guarded by `require_auth`,
        // which accepts the LOCAL cluster secret only — the external
        // target's secret will reject ours, and `X-Transfer-Token` is
        // not honoured by that endpoint. Rather than write a check
        // that always silently fails-open, we let the import on the
        // target surface the collision in its own error path. If a
        // future endpoint exposes a transfer-token-authed VM list,
        // wire it in here. (Intra-cluster migration DOES check this,
        // see migrate_preflight_intra.)

        migration_update(&state_clone.migration_tasks, &tid, "stopping", &format!("Stopping VM '{}' for consistent export…", name));
        {
            let manager = state_clone.vms.lock().unwrap();
            if let Err(e) = manager.stop_vm(&name, true) {
                tracing::warn!("Failed to stop VM '{}' before migration: {}", name, e);
            }
        }

        migration_update(&state_clone.migration_tasks, &tid, "export",
            &format!("Packaging disk archive{}…",
                expected_total.map(|b| format!(" (~{})", format_bytes_human(b))).unwrap_or_default()));

        let watcher_stop = Arc::new(AtomicBool::new(false));
        let watcher_flag = watcher_stop.clone();
        let watcher_tasks = state_clone.migration_tasks.clone();
        let watcher_tid = tid.clone();
        let watcher_staging = staging_dir.clone();
        let watcher_name = name.clone();
        let watcher_expected = expected_total;
        tokio::spawn(async move {
            poll_export_archive_size(
                watcher_tasks, watcher_tid, watcher_staging, watcher_name,
                watcher_expected, watcher_flag,
            ).await;
        });

        let export_result = {
            let name_owned = name.clone();
            let staging_owned = staging_dir.clone();
            tokio::task::spawn_blocking(move || {
                super::manager::export_vm_with_staging(&name_owned, staging_owned.as_deref())
            }).await.unwrap_or_else(|e| Err(format!("export task join: {}", e)))
        };
        watcher_stop.store(true, Ordering::Relaxed);

        let archive_path = match export_result {
            Ok(p) => p,
            Err(e) => {
                let manager = state_clone.vms.lock().unwrap();
                let _ = manager.start_vm(&name);
                migration_fail(&state_clone.migration_tasks, &tid, &format!("Export failed: {}", e));
                return;
            }
        };

        {
            let manager = state_clone.vms.lock().unwrap();
            let _ = manager.start_vm(&name);
        }

        let archive_bytes = match std::fs::read(&archive_path) {
            Ok(b) => b,
            Err(e) => {
                super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
                migration_fail(&state_clone.migration_tasks, &tid, &format!("Read archive: {}", e));
                return;
            }
        };

        let total_bytes = archive_bytes.len() as u64;
        migration_update(&state_clone.migration_tasks, &tid, "upload",
            &format!("Uploading {} to {}…", format_bytes_human(total_bytes), target_label));
        migration_progress(&state_clone.migration_tasks, &tid, Some(0), Some(total_bytes), Some(0.0));

        let import_urls = crate::api::build_external_urls(&target_url, "/api/vms/import-external");
        // Shared pool — see VM_MIGRATION_CLIENT. 1h timeout per-request.
        let client = &*VM_MIGRATION_CLIENT;
        let file_name = archive_path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let mut last_err: Option<String> = None;
        let mut finished = false;

        for import_url in &import_urls {
            let (body, _) = build_progress_body(
                &archive_bytes, total_bytes, state_clone.migration_tasks.clone(), tid.clone(),
            );
            let part = reqwest::multipart::Part::stream_with_length(body, total_bytes)
                .file_name(file_name.clone())
                .mime_str("application/octet-stream").unwrap_or_else(|_| reqwest::multipart::Part::text("".to_string()));

            let mut form = reqwest::multipart::Form::new()
                .text("new_name", new_name.clone())
                .text("storage", storage_val.clone())
                .part("archive", part);
            if !tgt_staging_val.is_empty() {
                form = form.text("target_staging_dir", tgt_staging_val.clone());
            }
            if proxmox_val {
                form = form.text("proxmox", "1".to_string());
            }

            match client.post(import_url)
                .header("X-Transfer-Token", &target_token)
                .peer_auth(state_clone.cluster_secret.clone())
                .timeout(Duration::from_secs(3600))
                .multipart(form)
                .send()
                .await
            {
                Ok(r) => {
                    super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
                    if r.status().is_success() {
                        let _ = r.bytes().await;
                        migration_done(&state_clone.migration_tasks, &tid,
                            &format!("VM '{}' transferred to {}. Destination is stopped — start it manually when ready.",
                                name, target_url));
                    } else {
                        let err = r.text().await.unwrap_or_default();
                        migration_fail(&state_clone.migration_tasks, &tid,
                            &format!("External import failed: {}", err));
                    }
                    finished = true;
                    break;
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            }
        }
        if !finished {
            super::manager::export_cleanup(archive_path.to_str().unwrap_or(""));
            migration_fail(&state_clone.migration_tasks, &tid,
                &format!("Transfer to {} failed on all ports: {}",
                    target_url, last_err.unwrap_or_default()));
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "task_id": task_id,
        "message": "Migration started"
    }))
}

/// POST /api/vms/import-external — receive a migrated VM (multipart upload)
/// Auth: X-WolfStack-Secret (intra-cluster) or X-Transfer-Token (cross-cluster)
async fn vm_import_external(
    req: HttpRequest,
    state: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> HttpResponse {
    // Auth: accept either cluster secret or transfer token
    // validate_inter_node_secret, not `==`: the latter missed the
    // on-disk secret (rejecting legitimate peers after a rotation) and
    // compared in non-constant time.
    let has_secret = req.headers().get("X-WolfStack-Secret")
        .and_then(|v| v.to_str().ok())
        .map(|v| crate::auth::validate_inter_node_secret_from(
            v, &state.cluster_secret, crate::api::peer_ip(&req)))
        .unwrap_or(false);

    let has_token = req.headers().get("X-Transfer-Token")
        .and_then(|v| v.to_str().ok())
        .map(crate::api::validate_transfer_token)
        .unwrap_or(false);

    if !has_secret && !has_token {
        // Fall back to session auth
        if let Err(resp) = require_auth(&req, &state) { return resp; }
    }

    use futures::StreamExt;

    // Respect TMPDIR so operators whose target `/tmp` is a small tmpfs
    // can point upload staging at a roomy disk via the wolfstack
    // systemd unit's `Environment=TMPDIR=/big/tmp` line. Guard against
    // an empty-string TMPDIR (systemd `Environment=TMPDIR=` to clear)
    // so we don't land on a relative path that makes create_dir_all
    // silently succeed against CWD.
    let import_dir = std::env::var("TMPDIR").ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("wolfstack-vm-imports");
    if let Err(e) = std::fs::create_dir_all(&import_dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!(
                "Failed to create upload staging directory {} (check TMPDIR or service permissions): {}",
                import_dir.display(), e
            )
        }));
    }

    let mut new_name: Option<String> = None;
    let mut storage: Option<String> = None;
    let mut archive_path: Option<std::path::PathBuf> = None;
    // New multipart fields — backward compatible (old clients don't send them).
    let mut target_staging_dir: Option<String> = None;
    let mut proxmox: bool = false;

    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Multipart error: {}", e)})),
        };

        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "new_name" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let val = String::from_utf8_lossy(&buf).trim().to_string();
                if !val.is_empty() { new_name = Some(val); }
            }
            "storage" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let val = String::from_utf8_lossy(&buf).trim().to_string();
                if !val.is_empty() { storage = Some(val); }
            }
            "target_staging_dir" => {
                // Source sends this so the target extracts the archive
                // under the operator's chosen staging root instead of
                // $TMPDIR / /tmp. Source staging is set separately on
                // the source vm_migrate call — this is strictly the
                // target side's extraction/upload directory.
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let val = String::from_utf8_lossy(&buf).trim().to_string();
                if !val.is_empty() { target_staging_dir = Some(val); }
            }
            "proxmox" => {
                let mut buf = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk { buf.extend_from_slice(&data); }
                }
                let val = String::from_utf8_lossy(&buf).trim().to_ascii_lowercase();
                proxmox = matches!(val.as_str(), "1" | "true" | "yes" | "on");
            }
            "archive" => {
                let fname = format!("vm-import-{}.tar.gz", uuid::Uuid::new_v4());
                let dest = import_dir.join(&fname);
                let mut file = match std::fs::File::create(&dest) {
                    Ok(f) => f,
                    Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to create temp file: {}", e)})),
                };
                use std::io::Write;
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk
                        && let Err(e) = file.write_all(&data) {
                            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Write failed: {}", e)}));
                        }
                }
                archive_path = Some(dest);
            }
            _ => { while field.next().await.is_some() {} }
        }
    }

    let archive = match archive_path {
        Some(p) => p,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "No archive uploaded"})),
    };

    // Choose the import path. `proxmox=true` routes to import_vm_proxmox
    // which creates a PVE-managed VM via qm create + qm importdisk.
    // Fall back to native import if the operator asked for PVE but
    // this host isn't Proxmox — surface the error instead of silently
    // creating a WolfStack-style VM.
    let result = if proxmox {
        if !crate::containers::is_proxmox() {
            Err("proxmox=true was requested but this host does not have Proxmox installed (`qm` not found)".to_string())
        } else {
            let sid = storage.as_deref().unwrap_or("").trim();
            if sid.is_empty() {
                Err("PVE storage id is required when proxmox=true (e.g. 'local-lvm')".to_string())
            } else {
                super::manager::import_vm_proxmox(
                    archive.to_str().unwrap_or(""),
                    new_name.as_deref(),
                    sid,
                    target_staging_dir.as_deref(),
                )
            }
        }
    } else {
        super::manager::import_vm_with_staging(
            archive.to_str().unwrap_or(""),
            new_name.as_deref(),
            storage.as_deref(),
            target_staging_dir.as_deref(),
        )
    };

    match result {
        Ok(msg) => {
            let _ = std::fs::remove_file(&archive);
            HttpResponse::Ok().json(serde_json::json!({"message": msg}))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&archive);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e}))
        }
    }
}

// ─── Libvirt VM Discovery & Adoption ───

/// GET /api/vms/discover-libvirt — discover VMs managed by libvirt
async fn discover_libvirt(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    HttpResponse::Ok().json(manager.discover_libvirt_vms())
}

#[derive(Deserialize)]
struct AdoptLibvirtRequest {
    name: String,
}

/// POST /api/vms/adopt-libvirt — adopt a libvirt VM into WolfStack
async fn adopt_libvirt(req: HttpRequest, state: web::Data<AppState>, body: web::Json<AdoptLibvirtRequest>) -> HttpResponse {
    if let Err(resp) = require_auth(&req, &state) { return resp; }
    let manager = state.vms.lock().unwrap();
    match manager.adopt_libvirt_vm(&body.name) {
        Ok(config) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("VM '{}' adopted successfully", config.name),
            "vm": config,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

#[cfg(test)]
mod media_path_validation_tests {
    use super::validate_media_path;

    #[test]
    fn allows_clean_paths_and_empty() {
        assert!(validate_media_path(Some("/mnt/wolfstack/nas/win11.iso"), "ISO").is_ok());
        assert!(validate_media_path(Some("/var/lib/vz/template/iso/ubuntu-24.04.iso"), "ISO").is_ok());
        assert!(validate_media_path(None, "ISO").is_ok());
        assert!(validate_media_path(Some(""), "ISO").is_ok());
    }

    #[test]
    fn rejects_comma_injection_and_control_chars() {
        // Comma = qm/virt-install/qemu config separator → injection vector.
        assert!(validate_media_path(Some("/mnt/nas/Windows 10, 22H2.iso"), "ISO").is_err());
        assert!(validate_media_path(Some("/x.iso,media=disk,cache=none"), "ISO").is_err());
        // Control chars / newline never belong in a media path.
        assert!(validate_media_path(Some("/mnt/nas/a\nb.iso"), "ISO").is_err());
        assert!(validate_media_path(Some("/mnt/nas/a\0b.iso"), "ISO").is_err());
    }
}
