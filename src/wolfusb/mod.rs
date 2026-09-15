// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfUSB Integration — USB device sharing across the cluster
//!
//! Uses the standalone `wolfusb` binary (https://github.com/intelligentwolf/wolfusb)
//! which provides USB-over-IP via libusb with its own authenticated protocol.
//!
//! Architecture:
//! - Each node runs `wolfusb server` (managed via systemd or direct spawn)
//! - WolfStack queries the local wolfusb server for device discovery
//! - Assignments are stored in WolfStack config and synced across the cluster
//! - Local passthrough uses /dev/bus/usb directly (Docker --device, LXC mount, QEMU)
//! - Remote access uses the wolfusb protocol with cluster secret as the auth key

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::OnceLock;
use tracing::{info, warn};

fn config_path() -> String { format!("{}/wolfusb.json", crate::paths::get().config_dir) }

/// Cluster secret stored at init time, used as the wolfusb auth key
static CLUSTER_SECRET: OnceLock<String> = OnceLock::new();

/// Initialize the WolfUSB module with the cluster secret (call from main.rs)
///
/// This runs synchronously on the caller's thread because the migration
/// MUST land before any other code path reads the config — attach/detach
/// resolvers only understand canonical port-path busids, so leaving a
/// legacy busid in the on-disk config through the boot window would let
/// an early API request mis-resolve. The migration is O(assignments ×
/// sysfs_devices), with sysfs entries being in-kernel reads — empirically
/// a handful of ms for the largest homelab we've seen. If startup time
/// ever becomes an issue, moving this to a spawned task that blocks the
/// first config-mutating API call is the right refactor.
pub fn init(cluster_secret: &str) {
    let _ = CLUSTER_SECRET.set(cluster_secret.to_string());
    let mut config = WolfUsbConfig::load();
    if migrate_assignments_to_port_paths(&mut config)
        && let Err(e) = config.save() {
            warn!("WolfUSB: failed to save migrated assignments: {}", e);
        }
}

fn get_secret() -> &'static str {
    CLUSTER_SECRET.get().map(|s| s.as_str()).unwrap_or("")
}

// ─── Configuration ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfUsbConfig {
    /// Whether WolfUSB sharing is enabled on this node
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// USB devices currently assigned to containers/VMs (local or remote)
    #[serde(default)]
    pub assignments: Vec<UsbAssignment>,
}

fn default_true() -> bool { true }

impl Default for WolfUsbConfig {
    fn default() -> Self {
        Self { enabled: true, assignments: Vec::new() }
    }
}

impl WolfUsbConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => {
                let c = Self::default();
                let _ = c.save();
                c
            }
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        let dir = std::path::Path::new(&path).parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }
}

/// Assignment of a USB device to a container/VM (possibly on another node)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbAssignment {
    /// USB bus ID string (e.g. "wolfusb-1-2")
    pub busid: String,
    /// Friendly label (e.g. "Logitech Webcam")
    #[serde(default)]
    pub label: String,
    /// Vendor:Product ID string (e.g. "046d:0825")
    #[serde(default)]
    pub usb_id: String,
    /// Node ID where the physical USB device is connected (source)
    pub source_node_id: String,
    /// Source node hostname (for display)
    #[serde(default)]
    pub source_hostname: String,
    /// Source node address (IP/hostname for wolfusb connection)
    pub source_address: String,
    /// Target type: "docker", "lxc", "vm"
    pub target_type: String,
    /// Target name (container/VM name)
    pub target_name: String,
    /// Node ID where the target container/VM runs
    pub target_node_id: String,
    /// Target node hostname (for display)
    #[serde(default)]
    pub target_hostname: String,
    /// Whether this assignment is currently active
    #[serde(default)]
    pub active: bool,
    /// WolfUSB session ID (returned by wolfusb attach, needed for detach)
    #[serde(default)]
    pub session_id: Option<u64>,
    /// Legacy field — kept for config compat
    #[serde(default)]
    pub virtual_busid: Option<String>,
}

// ─── USB Device Info ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    /// Bus ID (e.g. "wolfusb-1-2")
    pub busid: String,
    pub vendor_id: String,
    pub product_id: String,
    pub product: String,
    #[serde(default)]
    pub assigned_to: Option<String>,
}

// ─── WolfUSB Binary Management ───

/// Find the wolfusb binary
fn find_wolfusb_binary() -> Option<String> {
    // Check PATH
    if Command::new("sh").args(["-c", "command -v wolfusb"]).output()
        .map(|o| o.status.success()).unwrap_or(false)
    {
        return Some("wolfusb".to_string());
    }
    // Common locations
    for path in &["/usr/local/bin/wolfusb", "/usr/bin/wolfusb", "/opt/wolfusb/wolfusb"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Check if the wolfusb binary is available
pub fn is_wolfusb_available() -> bool {
    find_wolfusb_binary().is_some()
}

/// Get the installed wolfusb version string
pub fn get_wolfusb_version() -> Option<String> {
    let binary = find_wolfusb_binary()?;
    let output = Command::new(&binary).arg("--version").output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Kernel-side capability check for USB/IP passthrough.
///
/// WolfUSB relies on two in-tree Linux kernel modules:
///   - `vhci_hcd`: CLIENT side (target node) — virtual USB host controller
///     that presents remote devices as local USB devices.
///   - `usbip_host`: SERVER side (source node) — wolfusb hands the authenticated
///     TCP socket here; the kernel then drives every URB type including
///     isochronous (needed for webcams, USB audio, TV tuners).
///
/// These live in the "kernel-modules-extra" style package on most distros and
/// aren't installed by default. A node that's missing one can still act in
/// the other role, but a node missing both can't do USB passthrough at all.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct KernelModuleStatus {
    /// True if /sys/devices/platform/vhci_hcd.0 exists (client role works).
    pub vhci_hcd_loaded: bool,
    /// True if /sys/bus/usb/drivers/usbip-host exists (server role works).
    pub usbip_host_loaded: bool,
    /// Per-distro install hint shown to the operator when a module is missing.
    pub install_hint: String,
}

impl KernelModuleStatus {
    pub fn is_fully_ready(&self) -> bool {
        self.vhci_hcd_loaded && self.usbip_host_loaded
    }
}

pub fn kernel_module_status() -> KernelModuleStatus {
    let vhci = std::path::Path::new("/sys/devices/platform/vhci_hcd.0").is_dir();
    let host = std::path::Path::new("/sys/bus/usb/drivers/usbip-host").is_dir();
    let hint = if vhci && host {
        String::new()
    } else {
        distro_install_hint()
    };
    KernelModuleStatus {
        vhci_hcd_loaded: vhci,
        usbip_host_loaded: host,
        install_hint: hint,
    }
}

fn distro_install_hint() -> String {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let id_line = os.lines().find(|l| l.starts_with("ID=")).unwrap_or("");
    let like_line = os
        .lines()
        .find(|l| l.starts_with("ID_LIKE="))
        .unwrap_or("");
    let haystack = format!("{} {}", id_line, like_line).to_lowercase();
    if haystack.contains("arch") || haystack.contains("manjaro")
        || haystack.contains("cachyos") || haystack.contains("endeavouros")
    {
        "Arch-family kernels ship these modules by default. If missing, run \
         `sudo modprobe vhci-hcd usbip-host` — the package is the standard `linux` kernel.".into()
    } else if haystack.contains("fedora") || haystack.contains("rhel")
        || haystack.contains("centos") || haystack.contains("rocky")
        || haystack.contains("alma")
    {
        "Run `sudo dnf install kernel-modules-extra` and reboot. WolfStack's \
         setup.sh normally handles this — re-run `curl ... | sudo bash` to install.".into()
    } else if haystack.contains("debian") || haystack.contains("ubuntu")
        || haystack.contains("mint") || haystack.contains("pop")
        || haystack.contains("raspbian")
    {
        "Run `sudo apt install linux-modules-extra-$(uname -r)` then \
         `sudo modprobe vhci-hcd usbip-host`. WolfStack's setup.sh normally \
         handles this — re-run the installer to fix.".into()
    } else if haystack.contains("suse") || haystack.contains("sles") {
        "Run `sudo zypper install kernel-default-extra` and reboot.".into()
    } else {
        "Install your distro's kernel-modules-extra package, or rebuild the \
         kernel with CONFIG_USBIP_CORE, CONFIG_USBIP_VHCI_HCD, \
         CONFIG_USBIP_HOST enabled. Container-optimised cloud kernels (GCP \
         COS, Bottlerocket, Flatcar) don't support USB passthrough.".into()
    }
}

/// Run a wolfusb command with the cluster secret as auth key
fn run_wolfusb(args: &[&str]) -> Result<String, String> {
    let binary = find_wolfusb_binary()
        .ok_or_else(|| "wolfusb binary not found".to_string())?;

    let secret = get_secret();
    let mut cmd = Command::new(&binary);
    cmd.args(args);
    if !secret.is_empty() {
        cmd.arg("--key").arg(secret);
    }

    let output = cmd.output().map_err(|e| format!("Failed to run wolfusb: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("wolfusb failed: {}", stderr))
    }
}

/// Run a wolfusb command — try with key first, fall back to without key
fn run_wolfusb_with_fallback(args: &[&str]) -> Result<String, String> {
    let binary = find_wolfusb_binary()
        .ok_or_else(|| "wolfusb binary not found".to_string())?;

    let secret = get_secret();

    // Try with key if we have one
    if !secret.is_empty() {
        let output = Command::new(&binary).args(args).arg("--key").arg(secret)
            .output().map_err(|e| format!("Failed to run wolfusb: {}", e))?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    // Try without key (server may not require auth)
    let output = Command::new(&binary).args(args)
        .output().map_err(|e| format!("Failed to run wolfusb: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("wolfusb failed: {}", stderr))
    }
}

const WOLFUSB_SERVICE_UNIT: &str = "[Unit]\n\
Description=WolfUSB Server\n\
After=network.target\n\
\n\
[Service]\n\
Type=simple\n\
Environment=WOLFUSB_BIND=0.0.0.0\n\
Environment=WOLFUSB_PORT=3240\n\
EnvironmentFile=-/etc/wolfusb/wolfusb.env\n\
ExecStart=/usr/local/bin/wolfusb server --bind ${WOLFUSB_BIND} --port ${WOLFUSB_PORT}\n\
Restart=on-failure\n\
RestartSec=5\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";

/// Ensure the wolfusb server is running on this node with the cluster secret as its auth key.
/// Called at startup and whenever the cluster secret changes. Rewrites the env file and
/// restarts the service if the key doesn't match.
pub fn ensure_wolfusb_server() {
    use std::os::unix::fs::PermissionsExt;

    if !is_wolfusb_available() {
        warn!("WolfUSB: wolfusb binary not found — USB sharing unavailable");
        return;
    }

    let secret = get_secret();
    if secret.is_empty() {
        return;
    }

    // Write env file with current cluster secret
    let _ = std::fs::create_dir_all("/etc/wolfusb");
    let env_content = format!("WOLFUSB_BIND=0.0.0.0\nWOLFUSB_PORT=3240\nWOLFUSB_KEY={}\n", secret);
    let existing = std::fs::read_to_string("/etc/wolfusb/wolfusb.env").unwrap_or_default();
    let key_changed = existing != env_content;
    if key_changed {
        if let Err(e) = std::fs::write("/etc/wolfusb/wolfusb.env", &env_content) {
            warn!("WolfUSB: failed to write env file: {}", e);
            return;
        }
        let _ = std::fs::set_permissions("/etc/wolfusb/wolfusb.env",
            std::fs::Permissions::from_mode(0o600));
        info!("WolfUSB: updated /etc/wolfusb/wolfusb.env with cluster secret");
    }

    // Ensure systemd unit exists and is correct
    let unit_path = "/etc/systemd/system/wolfusb.service";
    let unit_existing = std::fs::read_to_string(unit_path).unwrap_or_default();
    if unit_existing != WOLFUSB_SERVICE_UNIT {
        if let Err(e) = std::fs::write(unit_path, WOLFUSB_SERVICE_UNIT) {
            warn!("WolfUSB: failed to write systemd unit: {}", e);
        } else {
            let _ = Command::new("systemctl").arg("daemon-reload").status();
            let _ = Command::new("systemctl").args(["enable", "wolfusb"]).status();
        }
    }

    // Restart if key changed, otherwise just ensure it's running
    if key_changed {
        info!("WolfUSB: restarting wolfusb service to apply new key");
        let _ = Command::new("systemctl").args(["restart", "wolfusb"]).status();
    } else {
        // Start if not already running
        let active = Command::new("systemctl").args(["is-active", "--quiet", "wolfusb"])
            .status().map(|s| s.success()).unwrap_or(false);
        if !active {
            let _ = Command::new("systemctl").args(["start", "wolfusb"]).status();
        }
    }
}

// ─── Device Operations ───

/// JSON structure returned by `wolfusb list --json`
#[derive(Debug, Deserialize)]
struct WolfUsbDeviceJson {
    device_id: WolfUsbDeviceIdJson,
    vendor_id: u16,
    product_id: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    #[allow(dead_code)]
    serial_number: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WolfUsbDeviceIdJson {
    bus_number: u8,
    address: u8,
}

/// Returns true if a USB bus number is a virtual vhci_hcd controller.
/// We skip those because devices on them are already being served by another
/// node — listing them as "local" here would let the user double-mount the
/// same physical device and save an incorrect source in the assignment.
fn is_virtual_bus(bus_number: u8) -> bool {
    let link = format!("/sys/bus/usb/devices/usb{}", bus_number);
    std::fs::read_link(&link)
        .map(|p| p.to_string_lossy().contains("vhci_hcd"))
        .unwrap_or(false)
}

/// List USB devices on this node. Returns (devices, wolfusb_working).
pub fn list_local_devices_with_status(config: &WolfUsbConfig) -> (Vec<UsbDevice>, bool) {
    // Try with key first, fall back to without key
    match run_wolfusb_with_fallback(&["list", "--server", "127.0.0.1:3240", "--json"]) {
        Ok(json_str) => {
            match serde_json::from_str::<Vec<WolfUsbDeviceJson>>(&json_str) {
                Ok(raw_devices) => {
                    // Walk sysfs once — we correlate each libusb device with
                    // its kernel port path so the busid we register is the
                    // stable sysfs name (e.g. "wolfusb-1-1.5" for a device
                    // behind a hub), not the synthetic bus-addr pair that
                    // changes on every replug and breaks usbip-host on hubs.
                    let sysfs = sysfs_list_devices();
                    let devices = raw_devices.into_iter()
                        .filter(|d| d.vendor_id != 0x1d6b) // Filter root hubs
                        .filter(|d| !is_virtual_bus(d.device_id.bus_number))
                        .map(|d| {
                            let port = sysfs.iter()
                                .find(|s| s.bus == d.device_id.bus_number
                                     && s.addr == d.device_id.address)
                                .map(|s| s.port_path.clone())
                                // Fall back to the legacy form if sysfs is
                                // unavailable (should not happen on Linux).
                                .unwrap_or_else(|| format!("{}-{}",
                                    d.device_id.bus_number, d.device_id.address));
                            let busid = format!("wolfusb-{}", port);
                            let usb_id = format!("{:04x}:{:04x}", d.vendor_id, d.product_id);
                            let product = match (&d.manufacturer, &d.product) {
                                (Some(m), Some(p)) => format!("{} : {} ({usb_id})", m, p),
                                (None, Some(p)) => format!("{} ({usb_id})", p),
                                (Some(m), None) => format!("{} ({usb_id})", m),
                                (None, None) => format!("USB Device ({usb_id})"),
                            };
                            // Match assignments by either busid (exact, post-
                            // migration) or usb_id (vendor:product, covers the
                            // pre-migration window where stored busid is still
                            // the old bus-addr form for this device).
                            let assigned = config.assignments.iter()
                                .find(|a| a.busid == busid || a.usb_id == usb_id)
                                .map(|a| format!("{}:{} on {}", a.target_type, a.target_name, a.target_hostname));
                            UsbDevice {
                                busid,
                                vendor_id: format!("{:04x}", d.vendor_id),
                                product_id: format!("{:04x}", d.product_id),
                                product,
                                assigned_to: assigned,
                            }
                        })
                        .collect();
                    (devices, true)
                }
                Err(e) => {
                    warn!("WolfUSB: failed to parse device list JSON: {}", e);
                    (Vec::new(), false)
                }
            }
        }
        Err(e) => {
            warn!("WolfUSB: wolfusb list failed: {}", e);
            (Vec::new(), false)
        }
    }
}

/// Rewrite legacy `wolfusb-X-Y` (bus-addr) busids in the assignment
/// config to their canonical `wolfusb-<port_path>` form, using a match
/// against currently-attached sysfs devices. Called once at startup and
/// again whenever the assignment list is loaded. Safe to re-run — a
/// busid whose port-path already matches the existing value is left
/// untouched. An assignment whose device isn't currently plugged in is
/// also left untouched (we'd have nothing stable to migrate to).
///
/// Returns `true` if at least one assignment was rewritten.
pub fn migrate_assignments_to_port_paths(config: &mut WolfUsbConfig) -> bool {
    let sysfs = sysfs_list_devices();
    // Early-out when sysfs has no real USB devices plugged in — there's
    // nothing stable to migrate TO. On a headless or embedded host with
    // only root hubs visible this is the common case and is expected;
    // legacy assignments stay as they are and will be migrated next
    // boot when the device reappears.
    if sysfs.is_empty() { return false; }
    let mut rewrote = 0usize;
    for a in config.assignments.iter_mut() {
        let port = busid_port_path(&a.busid);
        // If the busid already matches an exact sysfs port path, nothing to do.
        if sysfs.iter().any(|s| s.port_path == port) { continue; }

        // Pass 1 (PREFERRED): usb_id (vendor:product) lookup. Stable across
        // replugs and unambiguous when there's exactly one device of that
        // model plugged in. If two identical sticks are on the host we skip
        // — the operator must unassign + re-detect rather than let us guess.
        let mut target: Option<&SysfsUsbDevice> = None;
        if !a.usb_id.is_empty()
            && let Some((vid, pid)) = a.usb_id.split_once(':') {
                let matches: Vec<_> = sysfs.iter()
                    .filter(|s| s.id_vendor.eq_ignore_ascii_case(vid)
                             && s.id_product.eq_ignore_ascii_case(pid))
                    .collect();
                if matches.len() == 1 { target = Some(matches[0]); }
            }
        // Pass 2 (LEGACY ONLY): bus+addr lookup, but ONLY when the config
        // has no usb_id stored (truly old entries written before we tracked
        // it). If usb_id IS set and Pass 1 didn't match (stick unplugged
        // or ambiguous), we refuse to guess via bus+addr — a different
        // device coincidentally at that bus+addr would get wrongly migrated.
        if target.is_none() && a.usb_id.is_empty() {
            let parts: Vec<&str> = port.splitn(2, '-').collect();
            if parts.len() == 2
                && let (Ok(bus), Ok(addr)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
                    target = sysfs.iter().find(|s| s.bus == bus && s.addr == addr);
                }
        }
        let Some(dev) = target else { continue; };
        if dev.port_path == port { continue; } // already canonical
        let old = a.busid.clone();
        a.busid = format!("wolfusb-{}", dev.port_path);
        rewrote += 1;
        warn!("WolfUSB: migrated assignment busid {} -> {} (device at kernel port {})",
            old, a.busid, dev.port_path);
    }
    rewrote > 0
}

/// Extract the port-path part of a busid — everything after the
/// `wolfusb-` prefix. For post-migration busids this IS the kernel
/// sysfs directory name under `/sys/bus/usb/devices/` (e.g. `1-1.5`
/// for a device behind a hub). For pre-migration legacy busids it's
/// the bus-addr pair (e.g. `1-5`) which coincidentally equals the
/// sysfs name only for direct-attached devices.
fn busid_port_path(busid: &str) -> &str {
    busid.strip_prefix("wolfusb-").unwrap_or(busid)
}

/// One device entry reported by sysfs — we need this pair of facts
/// together in a bunch of call sites (attach, detach, dev_path, diagnose,
/// migration).
#[derive(Debug, Clone)]
struct SysfsUsbDevice {
    /// Kernel port path — the sysfs directory name itself (e.g. `1-1.5`).
    port_path: String,
    /// Current bus number. Can differ from the port-path prefix if the
    /// sysfs entry moved between roots, though in practice they match.
    bus: u8,
    /// Current device number. NOT stable across replugs — the same
    /// physical port can carry a different devnum after a disconnect.
    addr: u8,
    /// Vendor ID as four-hex-chars, for cross-matching against config.
    id_vendor: String,
    /// Product ID as four-hex-chars.
    id_product: String,
}

/// Walk `/sys/bus/usb/devices/`, skipping interface entries and root
/// hub synthetic names, and return one record per real USB device.
/// Cheap enough to call on every list / attach / diagnose — sysfs
/// lookups are in-memory kernel reads.
fn sysfs_list_devices() -> Vec<SysfsUsbDevice> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir("/sys/bus/usb/devices") {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Interface nodes (`1-1.5:1.0`) and synthetic root hubs (`usb1`)
        // aren't device nodes we want to expose.
        if name.contains(':') || name.starts_with("usb") { continue; }
        let path = entry.path();
        let Some(bus) = std::fs::read_to_string(path.join("busnum"))
            .ok().and_then(|s| s.trim().parse::<u8>().ok())
            else { continue; };
        let Some(addr) = std::fs::read_to_string(path.join("devnum"))
            .ok().and_then(|s| s.trim().parse::<u8>().ok())
            else { continue; };
        let id_vendor = std::fs::read_to_string(path.join("idVendor"))
            .map(|s| s.trim().to_string()).unwrap_or_default();
        let id_product = std::fs::read_to_string(path.join("idProduct"))
            .map(|s| s.trim().to_string()).unwrap_or_default();
        out.push(SysfsUsbDevice {
            port_path: name, bus, addr, id_vendor, id_product,
        });
    }
    out
}

/// Resolve a busid to the CURRENT (bus, addr) as reported by sysfs.
/// Re-reads each call because USB device numbers are not stable across
/// reconnects — the same physical port can carry a different devnum
/// after an unplug/replug. Accepts both the new (port-path) and legacy
/// (bus-addr) busid forms.
fn busid_to_bus_addr(busid: &str) -> Option<(u8, u8)> {
    let port = busid_port_path(busid);
    let devices = sysfs_list_devices();
    // Exact port_path match — the canonical post-migration path.
    if let Some(d) = devices.iter().find(|d| d.port_path == port) {
        return Some((d.bus, d.addr));
    }
    // No legacy bus+addr fallback: that would silently resolve to a
    // DIFFERENT device currently sitting at the same bus:addr after
    // a replug. Migration runs at startup (`init()`) to rewrite any
    // genuine legacy busid to its canonical port-path form; if the
    // device is unplugged at that point migration skips it, and this
    // resolver returns None so callers (attach/detach/diagnose) fail
    // cleanly with "busid not currently attached" rather than acting
    // on the wrong device.
    None
}

/// Find the /dev/bus/usb path for a device by busid. Resolves busid →
/// (bus, addr) via sysfs at call time, then returns the canonical
/// `/dev/bus/usb/BBB/AAA` path if the device is currently plugged in.
fn find_dev_path(busid: &str) -> Option<String> {
    let (bus, addr) = busid_to_bus_addr(busid)?;
    let path = format!("/dev/bus/usb/{:03}/{:03}", bus, addr);
    if std::path::Path::new(&path).exists() { Some(path) } else { None }
}

/// Kernel port path for a busid — returns the part after `wolfusb-`
/// when the sysfs entry exists under that name. Used by diagnose() to
/// surface the hub-attached mismatch clearly to operators.
fn sysfs_port_path_for(busid: &str) -> Option<String> {
    let port = busid_port_path(busid);
    let devices = sysfs_list_devices();
    if devices.iter().any(|d| d.port_path == port) {
        return Some(port.to_string());
    }
    // Legacy fallback — busid was "N-M" from an earlier build; walk
    // sysfs by (bus, addr) to find the real port path.
    let parts: Vec<&str> = port.splitn(2, '-').collect();
    if parts.len() == 2
        && let (Ok(bus), Ok(addr)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
            return devices.into_iter()
                .find(|d| d.bus == bus && d.addr == addr)
                .map(|d| d.port_path);
        }
    None
}

/// Kept for test-only use and legacy callers that want to parse a
/// bus-addr style busid. New code should go through `busid_to_bus_addr`
/// which resolves via sysfs and handles both formats.
#[cfg(test)]
fn parse_busid(busid: &str) -> Result<(u8, u8), String> {
    let stripped = busid.strip_prefix("wolfusb-").unwrap_or(busid);
    let parts: Vec<&str> = stripped.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid busid format: {}", busid));
    }
    let bus: u8 = parts[0].parse().map_err(|_| format!("Invalid bus number in {}", busid))?;
    let addr: u8 = parts[1].parse().map_err(|_| format!("Invalid address in {}", busid))?;
    Ok((bus, addr))
}

/// Attach to a remote USB device via wolfusb attach command.
/// Legacy path retained for compatibility — the new mount-based flow doesn't use this.
#[allow(dead_code)]
fn wolfusb_attach_device(source_address: &str, busid: &str) -> Result<u64, String> {
    let (bus, addr) = busid_to_bus_addr(busid)
        .ok_or_else(|| format!("busid {} not present on this host", busid))?;
    let server = format!("{}:3240", source_address);

    let output = run_wolfusb(&[
        "attach",
        "--server", &server,
        "--bus", &bus.to_string(),
        "--addr", &addr.to_string(),
    ])?;

    // Parse session_id from output: "Attached to X:Y, session_id = NNN"
    if let Some(sid_str) = output.split("session_id = ").nth(1)
        && let Ok(sid) = sid_str.trim().parse::<u64>() {
            return Ok(sid);
        }
    // If we can't parse the session_id, the attach still succeeded
    warn!("WolfUSB: attached but could not parse session_id from: {}", output.trim());
    Ok(0)
}

/// Detach from a remote USB device
fn wolfusb_detach_device(source_address: &str, busid: &str, session_id: u64) -> Result<(), String> {
    let (bus, addr) = busid_to_bus_addr(busid)
        .ok_or_else(|| format!("busid {} not present on this host", busid))?;
    let server = format!("{}:3240", source_address);

    run_wolfusb(&[
        "detach",
        "--server", &server,
        "--bus", &bus.to_string(),
        "--addr", &addr.to_string(),
        "--session-id", &session_id.to_string(),
    ])?;
    Ok(())
}

// ─── Recovery & diagnostics ───
//
// These functions power the "Re-attach" and "Diagnose" buttons in
// the WolfUSB page. The goal is to give operators a visible,
// step-by-step view of the passthrough chain so silent failures
// (usbip-server unreachable, device not exported, stale mount unit)
// stop being invisible.

/// One step in the diagnostic walk. `ok=false` with a meaningful
/// `detail` tells the operator exactly where the chain broke.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiagnosticStep {
    pub step: String,
    pub ok: bool,
    pub detail: String,
}

/// Walk the full passthrough chain for an assignment and report
/// per-step pass/fail. Read-only — safe to call repeatedly. Returns
/// the steps in order so the UI can render a checklist the operator
/// reads top-to-bottom.
pub fn diagnose(busid: &str) -> Vec<DiagnosticStep> {
    let mut out = Vec::new();
    let config = WolfUsbConfig::load();
    let Some(a) = config.assignments.iter().find(|a| a.busid == busid).cloned() else {
        out.push(DiagnosticStep {
            step: "Find assignment".into(),
            ok: false,
            detail: format!("No assignment exists for busid {} — was it unassigned from another node?", busid),
        });
        return out;
    };
    out.push(DiagnosticStep {
        step: "Find assignment".into(),
        ok: true,
        detail: format!(
            "source={} → target={} ({}:{})",
            a.source_hostname, a.target_hostname, a.target_type, a.target_name
        ),
    });

    let self_id = crate::agent::self_node_id();
    let source_is_self = a.source_node_id == self_id;
    let target_is_self = a.target_node_id == self_id;

    // Kernel modules — source needs usbip-host, target needs vhci_hcd.
    let kmod = kernel_module_status();
    if source_is_self {
        out.push(DiagnosticStep {
            step: "Source kernel modules".into(),
            ok: kmod.usbip_host_loaded,
            detail: if kmod.usbip_host_loaded {
                "usbip-host module loaded on this (source) node".into()
            } else {
                format!("usbip-host NOT loaded. {}", kmod.install_hint)
            },
        });
    }
    if target_is_self {
        out.push(DiagnosticStep {
            step: "Target kernel modules".into(),
            ok: kmod.vhci_hcd_loaded,
            detail: if kmod.vhci_hcd_loaded {
                "vhci_hcd module loaded on this (target) node".into()
            } else {
                format!("vhci_hcd NOT loaded. {}", kmod.install_hint)
            },
        });
    }

    // Source reachability — TCP probe the usbip port.
    if !a.source_address.is_empty() {
        let addr = format!("{}:3240", a.source_address);
        let reachable = std::net::TcpStream::connect_timeout(
            &match addr.parse::<std::net::SocketAddr>() {
                Ok(s) => s,
                // Fall back to DNS-resolving a hostname — we only do
                // this on failure to avoid the blocking path when the
                // address is a literal.
                Err(_) => match std::net::ToSocketAddrs::to_socket_addrs(&addr) {
                    Ok(mut iter) => match iter.next() {
                        Some(s) => s,
                        None => {
                            out.push(DiagnosticStep {
                                step: "Source reachable (port 3240)".into(),
                                ok: false,
                                detail: format!("could not resolve {}", a.source_address),
                            });
                            return out;
                        }
                    },
                    Err(e) => {
                        out.push(DiagnosticStep {
                            step: "Source reachable (port 3240)".into(),
                            ok: false,
                            detail: format!("DNS resolution failed for {}: {}", a.source_address, e),
                        });
                        return out;
                    }
                }
            },
            std::time::Duration::from_secs(3),
        ).is_ok();
        out.push(DiagnosticStep {
            step: "Source reachable (port 3240)".into(),
            ok: reachable,
            detail: if reachable {
                format!("TCP connect to {} succeeded", addr)
            } else {
                format!(
                    "Cannot reach {}. Is wolfusb-server running on the source? \
                     `systemctl status wolfusb` on {} will confirm.",
                    addr, a.source_hostname
                )
            },
        });
        // Ask the source's wolfusb server for the device list and
        // check the busid is in the inventory.
        if reachable {
            let listed = run_wolfusb_with_fallback(&[
                "list", "--server", &addr, "--json"
            ]);
            match listed {
                Ok(out_str) => {
                    // The JSON has {"bus_number":N,"address":M} — substring
                    // matching "wolfusb-N-M" against that text never hits.
                    // Parse the busid and check the structured fields.
                    // Resolve the busid against the SOURCE's sysfs via its
                    // wolfusb list JSON. When source_is_self we can cheat and
                    // use local sysfs; otherwise we only have the JSON, so we
                    // rely on bus+addr for the cross-check.
                    let (has_device, detail) = if source_is_self {
                        match busid_to_bus_addr(busid) {
                            Some((bus, addr_n)) => match serde_json::from_str::<Vec<WolfUsbDeviceJson>>(&out_str) {
                                Ok(list) => {
                                    let found = list.iter().any(|d|
                                        d.device_id.bus_number == bus
                                        && d.device_id.address == addr_n);
                                    if found {
                                        (true, format!("busid {} is in the source's exportable device list (resolves to bus={} addr={})", busid, bus, addr_n))
                                    } else {
                                        let seen: Vec<String> = list.iter()
                                            .map(|d| format!("{}-{}", d.device_id.bus_number, d.device_id.address))
                                            .collect();
                                        (false, format!(
                                            "Source resolved {} to bus:addr {}:{} but that pair is NOT in the wolfusb export list. \
                                             Source sees: [{}]. Device may be claimed by another driver. \
                                             Try Re-attach to force prepare-for-export.",
                                            busid, bus, addr_n, seen.join(", ")))
                                    }
                                }
                                Err(e) => (false, format!(
                                    "Could not parse source's wolfusb list JSON: {}", e)),
                            },
                            None => (false, format!(
                                "busid {} does not match any currently-attached USB device in sysfs — \
                                 was the stick unplugged? Replug and try again.", busid)),
                        }
                    } else {
                        // Remote source — can't query sysfs, but we can still
                        // look up the port path in the JSON by walking its
                        // fields. The JSON doesn't carry port_path, only bus+addr,
                        // so fall back to the legacy numeric parse here.
                        match busid_port_path(busid).splitn(2, '-').collect::<Vec<_>>().as_slice() {
                            [bus_s, addr_s] => match (bus_s.parse::<u8>(), addr_s.parse::<u8>()) {
                                (Ok(bus), Ok(addr_n)) => match serde_json::from_str::<Vec<WolfUsbDeviceJson>>(&out_str) {
                                    Ok(list) => {
                                        let found = list.iter().any(|d|
                                            d.device_id.bus_number == bus
                                            && d.device_id.address == addr_n);
                                        if found {
                                            (true, format!("busid {} is in the remote source's exportable device list", busid))
                                        } else {
                                            let seen: Vec<String> = list.iter()
                                                .map(|d| format!("{}-{}", d.device_id.bus_number, d.device_id.address))
                                                .collect();
                                            (false, format!(
                                                "Remote source lists bus:addr {}:{} as NOT exportable. \
                                                 Source sees: [{}]. Device may be behind a hub or claimed.",
                                                bus, addr_n, seen.join(", ")))
                                        }
                                    }
                                    Err(e) => (false, format!(
                                        "Could not parse source's wolfusb list JSON: {}", e)),
                                },
                                _ => (false, format!(
                                    "busid {} is in the new port-path format (contains a dot) — \
                                     can't remote-check a hub-attached device via wolfusb list yet. \
                                     Run Diagnose from the source node for a structured sysfs check.",
                                    busid)),
                            },
                            _ => (false, format!("malformed busid {}", busid)),
                        }
                    };
                    out.push(DiagnosticStep {
                        step: "Device exported on source".into(),
                        ok: has_device,
                        detail,
                    });
                }
                Err(e) => {
                    out.push(DiagnosticStep {
                        step: "Device exported on source".into(),
                        ok: false,
                        detail: format!("wolfusb list failed: {}", e),
                    });
                }
            }
        }
    }

    // If we're running on the source node, surface the kernel sysfs port
    // path. When this differs from the libusb bus:addr in the busid (e.g.
    // kernel says "1-1.5", WolfStack stored "wolfusb-1-5"), the stick is
    // behind a hub and usbip-host operations that take a kernel path will
    // fail even though the device is visible to libusb.
    if source_is_self {
        let stored = busid_port_path(busid);
        match sysfs_port_path_for(busid) {
            Some(port) => {
                let matches = port == stored;
                out.push(DiagnosticStep {
                    step: "Kernel sysfs port path".into(),
                    ok: matches,
                    detail: if matches {
                        format!("Kernel sees device at port {} — matches WolfStack busid.", port)
                    } else {
                        format!(
                            "Kernel sees device at port {}, WolfStack has it as {}. \
                             Pre-migration busid for a hub-attached device — restart WolfStack \
                             to auto-migrate, or unassign + re-detect on this node. Manual recovery: \
                             `usbip bind --busid={}` on source, `usbip attach -r <source_ip> -b {}` on target.",
                            port, stored, port, port
                        )
                    },
                    });
                }
                None => {
                    out.push(DiagnosticStep {
                        step: "Kernel sysfs port path".into(),
                        ok: false,
                        detail: format!(
                            "No /sys/bus/usb/devices entry resolves busid {}. \
                             The device may have been unplugged, or its address has changed \
                             since registration (USB device numbers are not stable across \
                             reconnects — the kernel port path stored in the busid is the \
                             stable identifier).",
                            busid
                        ),
                    });
                }
            }
    }

    // Target side — mount unit + host bus presence.
    if target_is_self {
        let unit_name = format!(
            "wolfusb-mount@{}-{}.service",
            busid.replace('-', "_"), a.target_name
        );
        let unit_active = Command::new("systemctl")
            .args(["is-active", "--quiet", &unit_name])
            .status().map(|s| s.success()).unwrap_or(false);
        let unit_exists = std::path::Path::new(
            &format!("/etc/systemd/system/{}", unit_name)
        ).exists();
        out.push(DiagnosticStep {
            step: "Mount unit on target".into(),
            ok: unit_exists && unit_active,
            detail: if unit_active {
                format!("systemd unit {} is active", unit_name)
            } else if unit_exists {
                format!(
                    "Mount unit {} exists but is NOT active. `journalctl -u {} -n 30` \
                     will show why it failed to start.",
                    unit_name, unit_name
                )
            } else {
                "No mount unit installed. Click Re-attach to install it, or \
                     reassign the device from the WolfUSB page.".to_string()
            },
        });
        // Final proof — is the device actually on the host's USB bus?
        let device_present = find_dev_path(busid).is_some();
        out.push(DiagnosticStep {
            step: "Device present on target bus".into(),
            ok: device_present,
            detail: if device_present {
                "Device found in /dev/bus/usb — QEMU's -device usb-host should find it".into()
            } else {
                "Device NOT on this host's USB bus. QEMU's -device usb-host will silently \
                 fail to bind it. This is the root cause for a VM that 'says passthrough' \
                 but doesn't actually have the device.".into()
            },
        });
    }

    out
}

/// Report for one step of a re-attach recovery run. Same shape as
/// DiagnosticStep but distinct so the UI can render them differently
/// (diagnose is passive, reattach is mutating).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReattachStep {
    pub step: String,
    pub ok: bool,
    pub detail: String,
}

/// Force-rerun the full attach chain for an existing assignment. Used
/// by the "Re-attach" button when a migration or mount failure has
/// left a passthrough stale. This function runs on the TARGET node
/// (the API layer proxies the call if needed). It:
///
/// 1. If cross-node: POSTs to source's /api/wolfusb/prepare-for-export
///    to ensure the device is unbound locally and usbip-bound.
/// 2. Stops+removes any stale mount unit for this busid+target.
/// 3. Runs attach_and_passthrough which re-installs the mount unit,
///    waits for the device to appear, and calls passthrough_to_vm /
///    passthrough_to_docker / passthrough_to_lxc.
///
/// Returns a vector of steps so the UI can show what succeeded and
/// where the chain broke.
pub fn reattach_local(busid: &str, source_bus_addr: Option<(u8, u8)>) -> Vec<ReattachStep> {
    let mut out = Vec::new();
    let config = WolfUsbConfig::load();
    let Some(a) = config.assignments.iter().find(|a| a.busid == busid).cloned() else {
        out.push(ReattachStep {
            step: "Find assignment".into(),
            ok: false,
            detail: format!("No assignment exists for busid {}", busid),
        });
        return out;
    };
    let self_id = crate::agent::self_node_id();
    if a.target_node_id != self_id {
        out.push(ReattachStep {
            step: "Locate target node".into(),
            ok: false,
            detail: format!(
                "Assignment target is {} but we're {} — the API should have \
                 proxied the reattach to the target node. This likely means \
                 the target is offline.",
                a.target_hostname, self_id
            ),
        });
        return out;
    }
    out.push(ReattachStep {
        step: "Locate target node".into(),
        ok: true,
        detail: format!("target is this node ({})", a.target_hostname),
    });

    // Stop any stale mount unit so attach_and_passthrough starts from
    // a clean slate. Failures here are non-fatal — either the unit
    // doesn't exist (nothing to stop) or it's already dead.
    let unit_name = format!(
        "wolfusb-mount@{}-{}.service",
        busid.replace('-', "_"), a.target_name
    );
    let _ = Command::new("systemctl").args(["stop", &unit_name]).status();
    let _ = Command::new("systemctl").args(["reset-failed", &unit_name]).status();
    out.push(ReattachStep {
        step: "Clean stale mount unit".into(),
        ok: true,
        detail: format!("systemctl stop {} (idempotent)", unit_name),
    });

    // The right path depends on whether source is local or remote.
    if a.source_node_id == self_id {
        // Local: device is physically here. Run the direct-passthrough
        // code, same as a fresh assignment.
        match local_passthrough(busid, &a.target_type, &a.target_name) {
            Ok(m) => out.push(ReattachStep {
                step: "Local passthrough".into(),
                ok: true,
                detail: m,
            }),
            Err(e) => out.push(ReattachStep {
                step: "Local passthrough".into(),
                ok: false,
                detail: e,
            }),
        }
        return out;
    }

    // Cross-node: we need the source to have the device usbip-bound
    // BEFORE we try attach_and_passthrough, otherwise usbip-attach
    // will silently fail. The API layer (not this function) is in
    // charge of calling source's prepare-for-export endpoint first
    // — we just assume that happened and try to attach.
    match attach_and_passthrough(&a.source_address, busid, &a.target_type, &a.target_name, source_bus_addr) {
        Ok(m) => out.push(ReattachStep {
            step: "Attach + passthrough".into(),
            ok: true,
            detail: m,
        }),
        Err(e) => out.push(ReattachStep {
            step: "Attach + passthrough".into(),
            ok: false,
            detail: e,
        }),
    }
    out
}

/// Look up (bus, addr) for a busid in the LOCAL sysfs. Used by the
/// API layer on the SOURCE node when answering a prepare-for-export
/// call from a cross-node target — the target needs these numbers to
/// build a valid `wolfusb mount --bus N --addr M` command, but it
/// can't look them up itself because the device only exists on the
/// source's bus. Wrapper around the private busid_to_bus_addr so
/// callers outside this module don't reach into sysfs directly.
pub fn bus_addr_for(busid: &str) -> Option<(u8, u8)> {
    busid_to_bus_addr(busid)
}

/// Prepare the LOCAL node to export a USB device via usbip. Called on
/// the SOURCE node by a TARGET node that's trying to attach cross-
/// node (typically after a VM migration).
///
/// Steps:
/// 1. Ensure the wolfusb server is running (systemd supervised).
/// 2. Confirm the device is actually present on the host bus.
/// 3. Confirm the kernel module usbip-host is loaded (required for
///    the server to hand the device to usbip-host).
/// 4. Return OK — the actual `usbip bind` happens when the target's
///    `wolfusb mount` connects and requests it.
///
/// Returns a list of steps so the target sees exactly what the source
/// did (or didn't) do. Safe to call repeatedly — everything here is
/// idempotent.
pub fn prepare_for_export(busid: &str) -> Vec<ReattachStep> {
    let mut out = Vec::new();
    // Step 1: wolfusb server. ensure_wolfusb_server is idempotent —
    // it installs the systemd unit if missing and starts it if not
    // running.
    ensure_wolfusb_server();
    let server_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "wolfusb.service"])
        .status().map(|s| s.success()).unwrap_or(false);
    out.push(ReattachStep {
        step: "wolfusb server".into(),
        ok: server_active,
        detail: if server_active {
            "systemd unit wolfusb.service is active".into()
        } else {
            "wolfusb.service failed to start. `journalctl -u wolfusb -n 40` for detail.".into()
        },
    });
    if !server_active { return out; }

    // Step 2: device present on our bus. If it was claimed by a dead
    // QEMU, the device will still be here but claimed by another
    // driver — the wolfusb server will try to re-bind it to usbip-
    // host when the target connects. If it's not here at all the
    // device was physically unplugged or moved to another host.
    let device_present = find_dev_path(busid).is_some();
    out.push(ReattachStep {
        step: "Device on local bus".into(),
        ok: device_present,
        detail: if device_present {
            format!("busid {} visible on /dev/bus/usb", busid)
        } else {
            format!(
                "busid {} is NOT on this host. Device may be unplugged, \
                 or on a different physical host.",
                busid
            )
        },
    });

    // Step 3: kernel module. Without usbip-host the server can't bind
    // devices for export, period.
    let kmod = kernel_module_status();
    out.push(ReattachStep {
        step: "Kernel module usbip-host".into(),
        ok: kmod.usbip_host_loaded,
        detail: if kmod.usbip_host_loaded {
            "usbip-host loaded".into()
        } else {
            format!("usbip-host NOT loaded. {}", kmod.install_hint)
        },
    });

    out
}

// ─── Install ───

/// Shell-escape a string for use inside single quotes
fn shell_escape_single(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}



/// Install or upgrade the wolfusb binary and set up the systemd service.
/// Writes the cluster secret to /etc/wolfusb/wolfusb.env as WOLFUSB_KEY so
/// the wolfusb server uses the same auth key as WolfStack.
pub async fn install_wolfusb() -> Result<String, String> {
    info!("WolfUSB: installing/upgrading wolfusb");
    let secret = get_secret().to_string();
    let script = format!(r#"
set -e

WOLFUSB_KEY_VALUE={secret_shell}

# ─── Install libusb (required by wolfusb) ───
if command -v pacman >/dev/null 2>&1; then
    echo "Installing libusb via pacman..."
    pacman -S --noconfirm libusb 2>/dev/null || true
elif command -v apt-get >/dev/null 2>&1; then
    echo "Installing libusb via apt..."
    apt-get update -qq && apt-get install -y libusb-1.0-0 2>/dev/null || true
elif command -v dnf >/dev/null 2>&1; then
    echo "Installing libusb via dnf..."
    dnf install -y libusbx 2>/dev/null || dnf install -y libusb1 2>/dev/null || true
elif command -v zypper >/dev/null 2>&1; then
    echo "Installing libusb via zypper..."
    zypper install -y libusb-1_0-0 2>/dev/null || true
fi

# ─── Stop existing service before upgrade ───
if systemctl is-active --quiet wolfusb 2>/dev/null; then
    echo "Stopping wolfusb service for upgrade..."
    systemctl stop wolfusb
fi

# ─── Show old version if upgrading ───
if command -v wolfusb >/dev/null 2>&1; then
    OLD_VER=$(wolfusb --version 2>/dev/null || echo "unknown")
    echo "Current version: $OLD_VER"
fi

# ─── Download and install latest wolfusb ───
echo "Downloading latest wolfusb..."
curl -fsSL https://raw.githubusercontent.com/intelligentwolf/wolfusb/main/setup.sh | bash

# ─── Show new version ───
if command -v wolfusb >/dev/null 2>&1; then
    NEW_VER=$(wolfusb --version 2>/dev/null || echo "unknown")
    echo "Installed version: $NEW_VER"
fi

# ─── Set up udev rules for USB access ───
mkdir -p /etc/udev/rules.d
echo 'SUBSYSTEM=="usb", MODE="0666", GROUP="plugdev"' > /etc/udev/rules.d/99-wolfusb.rules
udevadm control --reload-rules 2>/dev/null || true

# ─── Write env file with cluster secret as auth key ───
mkdir -p /etc/wolfusb
cat > /etc/wolfusb/wolfusb.env << ENV
WOLFUSB_BIND=0.0.0.0
WOLFUSB_PORT=3240
WOLFUSB_KEY=${{WOLFUSB_KEY_VALUE}}
ENV
chmod 600 /etc/wolfusb/wolfusb.env
echo "Wrote /etc/wolfusb/wolfusb.env with cluster auth key"

# ─── Install/overwrite systemd service (always, so EnvironmentFile is correct) ───
cat > /etc/systemd/system/wolfusb.service << 'UNIT'
[Unit]
Description=WolfUSB Server
After=network.target

[Service]
Type=simple
EnvironmentFile=-/etc/wolfusb/wolfusb.env
ExecStart=/usr/local/bin/wolfusb server --bind ${{WOLFUSB_BIND:-0.0.0.0}} --port ${{WOLFUSB_PORT:-3240}}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload

# ─── Enable and start (service will pick up the new WOLFUSB_KEY) ───
systemctl enable wolfusb 2>/dev/null || true
systemctl restart wolfusb 2>/dev/null || systemctl start wolfusb 2>/dev/null || true

echo "OK: wolfusb installation complete"
"#, secret_shell = shell_escape_single(&secret));

    let output = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .output()
        .await
        .map_err(|e| format!("Failed to run installer: {}", e))?;

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if is_wolfusb_available() {
        Ok(combined)
    } else {
        Err(format!("Installation may have partially succeeded:\n{}", combined))
    }
}

// ─── Assignment Operations ───

pub struct DeviceAssignmentRequest<'a> {
    pub busid: &'a str,
    pub label: &'a str,
    pub usb_id: &'a str,
    pub source_node_id: &'a str,
    pub source_hostname: &'a str,
    pub source_address: &'a str,
    pub target_type: &'a str,
    pub target_name: &'a str,
    pub target_node_id: &'a str,
    pub target_hostname: &'a str,
    pub is_local_source: bool,
}

/// Assign a USB device to a container/VM, potentially on a different node.
pub fn assign_device(config: &mut WolfUsbConfig, request: DeviceAssignmentRequest<'_>) -> Result<String, String> {
    let DeviceAssignmentRequest { busid, label, usb_id, source_node_id, source_hostname, source_address, target_type, target_name, target_node_id, target_hostname, is_local_source } = request;
    if !["docker", "lxc", "vm"].contains(&target_type) {
        return Err(format!("Invalid target type: {}", target_type));
    }

    // Remove any existing assignment for this device
    config.assignments.retain(|a| a.busid != busid || a.source_node_id != source_node_id);

    // For local same-node assignments, passthrough directly
    let is_local_target = target_node_id == source_node_id
        || (target_node_id.is_empty() && is_local_source);

    let msg = if is_local_source && is_local_target {
        match local_passthrough(busid, target_type, target_name) {
            Ok(m) => format!("USB device {} assigned to {}:{} (local)\n{}", busid, target_type, target_name, m),
            Err(e) => {
                warn!("WolfUSB: local passthrough failed: {}", e);
                format!("USB device {} assigned to {}:{} (passthrough pending: {})", busid, target_type, target_name, e)
            }
        }
    } else {
        format!("USB device {} from {} assigned to {}:{} on {}", busid, source_hostname, target_type, target_name, target_hostname)
    };

    // Store the assignment
    config.assignments.push(UsbAssignment {
        busid: busid.to_string(),
        label: label.to_string(),
        usb_id: usb_id.to_string(),
        source_node_id: source_node_id.to_string(),
        source_hostname: source_hostname.to_string(),
        source_address: source_address.to_string(),
        target_type: target_type.to_string(),
        target_name: target_name.to_string(),
        target_node_id: target_node_id.to_string(),
        target_hostname: target_hostname.to_string(),
        active: true,
        session_id: None,
        virtual_busid: None,
    });
    config.save().map_err(|e| format!("Failed to save config: {}", e))?;

    info!("WolfUSB: {}", msg);
    Ok(msg)
}

/// Remove a USB device assignment and clean up
pub fn unassign_device(config: &mut WolfUsbConfig, busid: &str, source_node_id: &str) -> Result<String, String> {
    let assignment = config.assignments.iter()
        .find(|a| a.busid == busid && a.source_node_id == source_node_id)
        .cloned();

    config.assignments.retain(|a| !(a.busid == busid && a.source_node_id == source_node_id));
    config.save().map_err(|e| format!("Failed to save config: {}", e))?;

    match assignment {
        Some(a) => {
            // Stop the mount unit (if one exists for this assignment)
            let unit_name = format!("wolfusb-mount@{}-{}.service",
                a.busid.replace('-', "_"), a.target_name);
            let _ = Command::new("systemctl").args(["stop", &unit_name]).status();
            let _ = Command::new("systemctl").args(["disable", &unit_name]).status();
            let _ = std::fs::remove_file(format!("/etc/systemd/system/{}", unit_name));
            let _ = Command::new("systemctl").arg("daemon-reload").status();

            // If this was a VM assignment, remove the udev rule that blocked
            // host drivers so the device works normally on the host again.
            if a.target_type == "vm"
                && let Some((v, p)) = a.usb_id.split_once(':') {
                    let rule_path = format!(
                        "/etc/udev/rules.d/99-wolfstack-vm-usb-{}-{}.rules",
                        v, p
                    );
                    let _ = std::fs::remove_file(&rule_path);
                    let _ = Command::new("udevadm")
                        .args(["control", "--reload-rules"])
                        .status();
                }

            // Release the device if we have a session
            if let Some(sid) = a.session_id
                && let Err(e) = wolfusb_detach_device(&a.source_address, &a.busid, sid) {
                    warn!("WolfUSB: detach failed (non-fatal): {}", e);
                }
            Ok(format!("USB device {} unassigned from {}:{}", a.busid, a.target_type, a.target_name))
        }
        None => Err("Device was not assigned".to_string()),
    }
}

/// Attach a remote USB device and passthrough to a container.
/// Called on the TARGET node (where the container/VM lives).
pub fn attach_and_passthrough(
    source_address: &str,
    busid: &str,
    target_type: &str,
    target_name: &str,
    source_bus_addr: Option<(u8, u8)>,
) -> Result<String, String> {
    // Snapshot existing USB devices so we can detect the new virtual one
    let before = lsusb_snapshot();

    // Start `wolfusb mount` as a long-lived systemd unit so it survives
    // wolfstack restarts and gets auto-restart on failure. For cross-
    // node attach the caller passes the SOURCE's bus+addr (looked up
    // via the source's prepare-for-export API) — the target's sysfs
    // doesn't have the device yet so a local lookup would fail.
    let unit_name = format!("wolfusb-mount@{}-{}.service", busid.replace('-', "_"), target_name);
    install_mount_unit(&unit_name, source_address, busid, source_bus_addr)?;

    let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    // `enable` so the mount auto-starts on reboot without needing wolfstack
    // to re-run restore_assignments. Combined with Restart=on-failure in the
    // unit itself, this makes USB passthrough survive reboots, network blips,
    // and server restarts on either end.
    let _ = Command::new("systemctl").args(["enable", &unit_name]).status();
    let start = Command::new("systemctl").args(["restart", &unit_name]).status()
        .map_err(|e| format!("Failed to start mount unit: {}", e))?;
    if !start.success() {
        return Err(format!("Failed to start {}", unit_name));
    }

    // Wait for the virtual USB device to appear. This must be generous: on a
    // FRESH attach the source binds the device to usbip-host on demand when the
    // mount first connects (a cold re-bind from its current driver + vhci
    // enumeration), and if that first connect races the just-started source
    // server it fails and systemd retries it RestartSec(2s) later. A short
    // window expired before the retry landed, so the FIRST attach reported
    // "did not appear" and only a second attempt succeeded (PapaSchlumpf
    // 2026-06-13). ~20s comfortably covers a cold bind plus a couple of retry
    // cycles, so the first attach succeeds.
    let mut dev_path = None;
    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(new_path) = find_new_device(&before) {
            dev_path = Some(new_path);
            break;
        }
    }

    let dev_path = match dev_path {
        Some(p) => p,
        None => {
            return Err(format!(
                "Virtual USB device did not appear after mount. \
                 The mount unit keeps retrying in the background — check: journalctl -u {} -n 30",
                unit_name
            ));
        }
    };

    // Update the assignment with the virtual dev path
    let mut config = WolfUsbConfig::load();
    if let Some(a) = config.assignments.iter_mut().find(|a| a.busid == busid) {
        a.virtual_busid = Some(dev_path.clone());
        a.active = true;
        let _ = config.save();
    }

    let mut result = format!("Mounted virtual USB device at {}", dev_path);

    // Pass into container/VM
    match target_type {
        "docker" => match passthrough_to_docker(target_name, &dev_path) {
            Ok(msg) => result.push_str(&format!("\n{}", msg)),
            Err(e) => result.push_str(&format!("\nDocker passthrough: {}", e)),
        },
        "lxc" => match passthrough_to_lxc(target_name, busid, &dev_path) {
            Ok(msg) => result.push_str(&format!("\n{}", msg)),
            Err(e) => result.push_str(&format!("\nLXC passthrough: {}", e)),
        },
        "vm" => match passthrough_to_vm(target_name, busid, &dev_path) {
            Ok(msg) => result.push_str(&format!("\n{}", msg)),
            Err(e) => result.push_str(&format!("\nVM passthrough: {}", e)),
        },
        _ => {}
    }

    Ok(result)
}

/// Snapshot current USB devices for before/after diff
fn lsusb_snapshot() -> Vec<String> {
    let output = match Command::new("lsusb").output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut paths = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let bus: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let addr: u32 = parts.get(3).and_then(|s| s.trim_end_matches(':').parse().ok()).unwrap_or(0);
            if bus > 0 && addr > 0 {
                paths.push(format!("/dev/bus/usb/{:03}/{:03}", bus, addr));
            }
        }
    }
    paths
}

/// Find a USB device that appeared since `before` was snapshotted
fn find_new_device(before: &[String]) -> Option<String> {
    let after = lsusb_snapshot();
    after.into_iter().find(|p| !before.contains(p))
}

/// Install a systemd unit for `wolfusb mount` so it runs as a supervised daemon.
/// `explicit_bus_addr`, when provided, bypasses the local sysfs lookup —
/// callers use this for cross-node attach where the device only exists
/// on the source's bus, not the target's. When None we fall back to a
/// local sysfs lookup (same-node passthrough, or a re-attach the target
/// has previously completed and still has a vhci entry for).
fn install_mount_unit(
    unit_name: &str, source_address: &str, busid: &str,
    explicit_bus_addr: Option<(u8, u8)>,
) -> Result<(), String> {
    // Resolve the busid to the device's current bus+addr. NOTE: these
    // are NOT stable across replugs; if the device is unplugged and
    // reconnected, the mount unit will be stale and Re-attach should
    // be run to regenerate it. Long-term fix is to teach wolfusb mount
    // to take a port path directly so this hardcoded numeric pair goes
    // away entirely.
    let (bus, addr) = match explicit_bus_addr {
        Some(pair) => pair,
        None => busid_to_bus_addr(busid)
            .ok_or_else(|| format!("busid {} is not currently attached on this host — replug and retry", busid))?,
    };
    let secret = get_secret();
    let unit_path = format!("/etc/systemd/system/{}", unit_name);
    let key_arg = if secret.is_empty() {
        String::new()
    } else {
        format!("--key '{}' ", secret.replace('\'', "'\\''"))
    };
    let unit_content = format!(
        "[Unit]\n\
         Description=WolfUSB Mount ({} from {})\n\
         After=network.target wolfusb.service\n\
         Wants=wolfusb.service\n\
         # Never stop retrying: when the SOURCE node reboots the mount drops,\n\
         # and a long outage would otherwise trip systemd's default start-rate\n\
         # limit and leave the unit dead forever (the device silently stops\n\
         # forwarding until a manual re-attach — PapaSchlumpf 2026-06-13).\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart=/usr/local/bin/wolfusb mount --server {}:3240 --bus {} --addr {} {}\n\
         # on-failure (not always): `wolfusb mount` exits NON-ZERO when the kernel\n\
         # releases the vhci port (source closed the connection / rebooted), so\n\
         # on-failure reconnects it; it exits 0 on a deliberate Ctrl-C detach, so\n\
         # on-failure leaves it stopped. A short RestartSec reconnects within\n\
         # seconds of the source coming back, with no operator action. (Requires\n\
         # wolfusb >= 0.5.1, which added the exit-on-port-loss behaviour; older\n\
         # binaries parked forever on disconnect and never triggered a restart.)\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        busid, source_address, source_address, bus, addr, key_arg
    );
    std::fs::write(&unit_path, unit_content)
        .map_err(|e| format!("Failed to write mount unit: {}", e))?;
    Ok(())
}

// ─── Local Device Passthrough ───

/// Pass a USB device into a local container/VM directly (same node)
pub fn local_passthrough(
    busid: &str,
    target_type: &str,
    target_name: &str,
) -> Result<String, String> {
    let dev_path = find_dev_path(busid)
        .ok_or_else(|| format!("Could not find device path for {}", busid))?;

    match target_type {
        "docker" => passthrough_to_docker(target_name, &dev_path),
        "lxc" => passthrough_to_lxc(target_name, busid, &dev_path),
        "vm" => passthrough_to_vm(target_name, busid, &dev_path),
        _ => Err(format!("Unknown target type: {}", target_type)),
    }
}

/// Passthrough a USB device into a Docker container by recreating it with --device
fn passthrough_to_docker(container_name: &str, dev_path: &str) -> Result<String, String> {
    let inspect = Command::new("docker").args(["inspect", "--format", "{{.State.Running}}", container_name])
        .output().map_err(|e| format!("docker inspect failed: {}", e))?;
    if !inspect.status.success() {
        return Err(format!("Container '{}' not found", container_name));
    }
    let was_running = String::from_utf8_lossy(&inspect.stdout).trim() == "true";

    // Check if device is already attached
    let inspect_json = Command::new("docker").args(["inspect", container_name])
        .output().map_err(|e| format!("docker inspect failed: {}", e))?;
    if inspect_json.status.success() {
        let text = String::from_utf8_lossy(&inspect_json.stdout);
        if text.contains(dev_path) {
            return Ok(format!("Device {} already attached to container {}", dev_path, container_name));
        }
    }

    if was_running {
        info!("WolfUSB: stopping {} to add USB device {}", container_name, dev_path);
        let _ = Command::new("docker").args(["stop", container_name]).output();
    }

    let backup_name = format!("{}_wolfusb_old", container_name);
    let _ = Command::new("docker").args(["rm", "-f", &backup_name]).output();

    let rename = Command::new("docker").args(["rename", container_name, &backup_name]).output()
        .map_err(|e| format!("Failed to rename container: {}", e))?;
    if !rename.status.success() {
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err(format!("Failed to rename container: {}", String::from_utf8_lossy(&rename.stderr)));
    }

    let insp = Command::new("docker").args(["inspect", &backup_name]).output()
        .map_err(|e| format!("Failed to inspect: {}", e))?;
    if !insp.status.success() {
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err("Failed to inspect container".to_string());
    }
    let insp_text = String::from_utf8_lossy(&insp.stdout);
    let inspect_arr: Vec<serde_json::Value> = serde_json::from_str(&insp_text).unwrap_or_default();
    let v = inspect_arr.first().cloned().unwrap_or(serde_json::Value::Null);

    let mut args = vec!["create".to_string(), "--name".to_string(), container_name.to_string()];

    let image = v.pointer("/Config/Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if image.is_empty() {
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err("Cannot determine container image".to_string());
    }

    // Restart policy
    let restart = v.pointer("/HostConfig/RestartPolicy/Name").and_then(|v| v.as_str()).unwrap_or("no");
    let rc = v.pointer("/HostConfig/RestartPolicy/MaximumRetryCount").and_then(|v| v.as_i64()).unwrap_or(0);
    args.push("--restart".to_string());
    args.push(if restart == "on-failure" && rc > 0 { format!("on-failure:{}", rc) } else { restart.to_string() });

    if v.pointer("/Config/Tty").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("-t".to_string()); }
    if v.pointer("/Config/OpenStdin").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("-i".to_string()); }
    if v.pointer("/HostConfig/Privileged").and_then(|v| v.as_bool()).unwrap_or(false) { args.push("--privileged".to_string()); }

    let net = v.pointer("/HostConfig/NetworkMode").and_then(|v| v.as_str()).unwrap_or("default");
    if net != "default" && net != "bridge" { args.push("--network".to_string()); args.push(net.to_string()); }

    if let Some(m) = v.pointer("/HostConfig/Memory").and_then(|v| v.as_i64()).filter(|m| *m > 0) {
        args.push("--memory".to_string()); args.push(format!("{}m", m / 1048576));
    }
    if let Some(c) = v.pointer("/HostConfig/NanoCpus").and_then(|v| v.as_i64()).filter(|c| *c > 0) {
        args.push("--cpus".to_string()); args.push(format!("{:.1}", c as f64 / 1e9));
    }
    if let Some(shm) = v.pointer("/HostConfig/ShmSize").and_then(|v| v.as_i64()).filter(|s| *s > 0 && *s != 67108864) {
        args.push("--shm-size".to_string()); args.push(format!("{}", shm));
    }

    let user = v.pointer("/Config/User").and_then(|v| v.as_str()).unwrap_or("");
    if !user.is_empty() { args.push("--user".to_string()); args.push(user.to_string()); }
    let workdir = v.pointer("/Config/WorkingDir").and_then(|v| v.as_str()).unwrap_or("");
    if !workdir.is_empty() { args.push("--workdir".to_string()); args.push(workdir.to_string()); }

    if let Some(caps) = v.pointer("/HostConfig/CapAdd").and_then(|v| v.as_array()) {
        for c in caps { if let Some(s) = c.as_str() { args.push("--cap-add".to_string()); args.push(s.to_string()); } }
    }
    if let Some(caps) = v.pointer("/HostConfig/CapDrop").and_then(|v| v.as_array()) {
        for c in caps { if let Some(s) = c.as_str() { args.push("--cap-drop".to_string()); args.push(s.to_string()); } }
    }

    // Preserve existing --device mounts, and bind the whole /dev/bus/usb
    // tree. Binding a single /dev/bus/usb/BBB/DDD path is fragile: many
    // USB devices re-enumerate with a different device number when they
    // load firmware (Google Coral: 1a6e:089a → 18d1:9302 after edgetpu
    // loads), or when the wolfusb-mount systemd unit restarts after a
    // blip. The container would lose access and the app (Frigate, etc.)
    // goes into a crash loop. Binding the whole tree + allowing all USB
    // devices at the cgroup level makes it robust to re-enumeration.
    let mut has_usb_bus = false;
    if let Some(devs) = v.pointer("/HostConfig/Devices").and_then(|v| v.as_array()) {
        for d in devs {
            let host = d.get("PathOnHost").and_then(|v| v.as_str()).unwrap_or("");
            let ctr = d.get("PathInContainer").and_then(|v| v.as_str()).unwrap_or("");
            if host.is_empty() {
                continue;
            }
            // Skip specific /dev/bus/usb/XXX/YYY paths — the tree-bind
            // below supersedes them and keeping both creates conflicts
            // when the device number changes.
            if host.starts_with("/dev/bus/usb/") {
                continue;
            }
            args.push("--device".to_string());
            args.push(format!("{}:{}", host, ctr));
            if host == "/dev/bus/usb" {
                has_usb_bus = true;
            }
        }
    }
    if !has_usb_bus {
        args.push("--device".to_string());
        args.push("/dev/bus/usb:/dev/bus/usb".to_string());
    }

    // Preserve existing cgroup rules, then ensure USB (major 189) is
    // allowed for any minor. Without this, Docker's default device cgroup
    // blocks access to USB devices that weren't present at container
    // creation, even if they're bind-mounted in later.
    let mut has_usb_cgroup = false;
    if let Some(rules) = v
        .pointer("/HostConfig/DeviceCgroupRules")
        .and_then(|v| v.as_array())
    {
        for r in rules {
            if let Some(s) = r.as_str() {
                args.push("--device-cgroup-rule".to_string());
                args.push(s.to_string());
                let norm = s.split_whitespace().collect::<Vec<_>>().join(" ");
                if norm.contains("c 189:") || norm.contains("c *:") {
                    has_usb_cgroup = true;
                }
            }
        }
    }
    if !has_usb_cgroup {
        args.push("--device-cgroup-rule".to_string());
        args.push("c 189:* rmw".to_string());
    }
    // dev_path is recorded but not passed as a specific --device; the
    // /dev/bus/usb tree-bind covers it and stays valid through re-enum.
    let _ = dev_path;

    // Volumes
    let binds: Vec<String> = v.pointer("/HostConfig/Binds")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    for b in &binds { args.push("-v".to_string()); args.push(b.clone()); }

    if let Some(mounts) = v.pointer("/Mounts").and_then(|v| v.as_array()) {
        for mount in mounts {
            if mount.get("Type").and_then(|v| v.as_str()) != Some("volume") { continue; }
            let vol_name = mount.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            let destination = mount.get("Destination").and_then(|v| v.as_str()).unwrap_or("");
            let rw = mount.get("RW").and_then(|v| v.as_bool()).unwrap_or(true);
            if vol_name.is_empty() || destination.is_empty() { continue; }
            if binds.iter().any(|b| b.starts_with(&format!("{}:", vol_name))) { continue; }
            let mode = if rw { "" } else { ":ro" };
            args.push("-v".to_string());
            args.push(format!("{}:{}{}", vol_name, destination, mode));
        }
    }

    if let Some(bindings) = v.pointer("/HostConfig/PortBindings").and_then(|v| v.as_object()) {
        for (container_port, host_list) in bindings {
            if let Some(arr) = host_list.as_array() {
                for binding in arr {
                    let host_ip = binding.get("HostIp").and_then(|v| v.as_str()).unwrap_or("");
                    let host_port = binding.get("HostPort").and_then(|v| v.as_str()).unwrap_or("");
                    if !host_port.is_empty() {
                        args.push("-p".to_string());
                        if host_ip.is_empty() || host_ip == "0.0.0.0" {
                            args.push(format!("{}:{}", host_port, container_port));
                        } else {
                            args.push(format!("{}:{}:{}", host_ip, host_port, container_port));
                        }
                    }
                }
            }
        }
    }

    if let Some(envs) = v.pointer("/Config/Env").and_then(|v| v.as_array()) {
        for e in envs { if let Some(s) = e.as_str() { args.push("-e".to_string()); args.push(s.to_string()); } }
    }
    if let Some(labels) = v.pointer("/Config/Labels").and_then(|v| v.as_object()) {
        for (k, lv) in labels { args.push("--label".to_string()); args.push(format!("{}={}", k, lv.as_str().unwrap_or(""))); }
    }

    let entrypoint: Vec<String> = v.pointer("/Config/Entrypoint")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if !entrypoint.is_empty() {
        args.push("--entrypoint".to_string());
        args.push(entrypoint[0].clone());
    }

    args.push(image);
    for ep_arg in entrypoint.iter().skip(1) { args.push(ep_arg.clone()); }
    if entrypoint.len() <= 1
        && let Some(cmds) = v.pointer("/Config/Cmd").and_then(|v| v.as_array()) {
            for c in cmds { if let Some(s) = c.as_str() { args.push(s.to_string()); } }
        }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let create = Command::new("docker").args(&args_ref).output()
        .map_err(|e| format!("docker create failed: {}", e))?;

    if !create.status.success() {
        let stderr = String::from_utf8_lossy(&create.stderr).trim().to_string();
        warn!("WolfUSB: Docker recreate failed, rolling back: {}", stderr);
        let _ = Command::new("docker").args(["rename", &backup_name, container_name]).output();
        if was_running { let _ = Command::new("docker").args(["start", container_name]).output(); }
        return Err(format!("Failed to recreate container: {}", stderr));
    }

    let _ = Command::new("docker").args(["rm", &backup_name]).output();
    if was_running {
        let _ = Command::new("docker").args(["start", container_name]).output();
    }

    info!("WolfUSB: Docker container {} recreated with USB device {}", container_name, dev_path);
    Ok(format!("Container '{}' recreated with USB device {}{}", container_name, dev_path,
        if was_running { " and started" } else { "" }))
}

/// Passthrough a USB device into an LXC container
fn passthrough_to_lxc(container_name: &str, busid: &str, dev_path: &str) -> Result<String, String> {
    let config_path = if crate::containers::is_proxmox() {
        let output = Command::new("pct").args(["set", container_name, "--dev0",
            &format!("{},mode=0660", dev_path)]).output()
            .map_err(|e| format!("pct set failed: {}", e))?;
        if output.status.success() {
            info!("WolfUSB: LXC {} configured with USB device {} via pct", container_name, dev_path);
            let _ = Command::new("pct").args(["reboot", container_name]).output();
            return Ok(format!("LXC '{}' configured with USB device {} and restarted", container_name, dev_path));
        }
        format!("/etc/pve/lxc/{}.conf", container_name)
    } else {
        format!("/var/lib/lxc/{}/config", container_name)
    };

    if !std::path::Path::new(&config_path).exists() {
        return Err(format!("LXC config not found at {}", config_path));
    }

    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
    // Look for our WolfUSB block — idempotent. Matching just on dev_path is
    // too narrow because the path changes if the device re-enumerates.
    if existing.contains("# WolfUSB: USB tree bind") {
        return Ok(format!(
            "USB tree-bind already configured in LXC {}",
            container_name
        ));
    }

    // Bind the whole /dev/bus/usb tree rather than a single path. The
    // specific dev_path can change when the device re-enumerates (Google
    // Coral switches from 1a6e:089a to 18d1:9302 after edgetpu firmware
    // loads, with a new device number), and binding the tree stays valid
    // regardless. Cgroup rule for USB major 189 lets the container read
    // whichever device number the kernel assigns.
    let entry = format!(
        "\n# WolfUSB: USB tree bind ({} initial path {})\n\
         lxc.cgroup2.devices.allow = c 189:* rwm\n\
         lxc.mount.entry = /dev/bus/usb dev/bus/usb none bind,optional,create=dir 0 0\n",
        busid, dev_path
    );

    std::fs::OpenOptions::new().append(true).open(&config_path)
        .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) })
        .map_err(|e| format!("Failed to update LXC config: {}", e))?;

    info!("WolfUSB: restarting LXC {} to apply USB device {}", container_name, dev_path);
    if crate::containers::is_proxmox() {
        let _ = Command::new("pct").args(["reboot", container_name]).output();
    } else {
        let _ = Command::new("lxc-stop").args(["-n", container_name]).output();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let _ = Command::new("lxc-start").args(["-n", container_name]).output();
    }

    Ok(format!("LXC '{}' configured with USB device {} and restarted", container_name, dev_path))
}

/// Note USB device availability for a VM
fn passthrough_to_vm(vm_name: &str, busid: &str, dev_path: &str) -> Result<String, String> {
    // Parse the USB vendor:product from the assignment.
    let (vendor_id, product_id) = read_usb_ids_from_devpath(dev_path)
        .ok_or_else(|| format!("Could not read vendor/product from {}", dev_path))?;

    // Install a udev rule that blocks host kernel drivers (uvcvideo,
    // snd-usb-audio, hid-generic, etc.) from auto-binding to this device
    // while it's passed to a VM. Without this, the host and QEMU fight
    // over the same device — QEMU's libusb-detach-kernel-driver loses the
    // race repeatedly and the VM sees a half-working device (webcam
    // enumerates but no frames, etc.).
    install_vm_passthrough_udev_rule(&vendor_id, &product_id)?;
    unbind_host_drivers_now(&vendor_id, &product_id);

    // Is this a Proxmox-managed VM? wolfstack can drive Proxmox hosts via
    // the `qm` CLI — those VMs live in /etc/pve/qemu-server/<vmid>.conf,
    // not in our native VM directory. If the VM name matches a qm entry,
    // use `qm set --usb<slot> host=vid:pid` which does a live hot-plug on
    // Proxmox 7+ (no restart needed).
    if let Some(vmid) = find_proxmox_vmid(vm_name) {
        return passthrough_to_proxmox_vm(vmid, vm_name, &vendor_id, &product_id, dev_path);
    }

    // Native wolfstack VM path.
    let vm_config_path = format!("/var/lib/wolfstack/vms/{}.json", vm_name);
    let mut config: serde_json::Value = match std::fs::read_to_string(&vm_config_path) {
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| format!("Failed to parse {}: {}", vm_config_path, e))?,
        Err(_) => {
            // Unknown VM (neither native nor Proxmox) — fall back to advisory.
            info!("WolfUSB: USB device {} ({}) available for VM {}", dev_path, busid, vm_name);
            return Ok(format!(
                "USB device {} available for VM '{}'. Add it in the VM's \
                 Passthrough settings and restart the VM.",
                dev_path, vm_name
            ));
        }
    };

    let entry = serde_json::json!({
        "vendor_id": vendor_id,
        "product_id": product_id,
        "host_bus": serde_json::Value::Null,
        "label": format!("WolfUSB: {}", busid),
    });

    let usb_devices = config.get_mut("usb_devices")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "VM config missing usb_devices array".to_string())?;

    let already = usb_devices.iter().any(|d| {
        d.get("vendor_id").and_then(|v| v.as_str()) == Some(vendor_id.as_str())
            && d.get("product_id").and_then(|v| v.as_str()) == Some(product_id.as_str())
    });
    if !already {
        usb_devices.push(entry);
    }

    std::fs::write(
        &vm_config_path,
        serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize VM config: {}", e))?,
    )
    .map_err(|e| format!("Failed to write {}: {}", vm_config_path, e))?;

    info!(
        "WolfUSB: added {}:{} to VM '{}' passthrough list",
        vendor_id, product_id, vm_name
    );

    // If the VM is running, try to hot-plug the device via QMP so the user
    // doesn't have to reboot Windows. Falls back to stop-and-autostart if
    // QMP isn't available (e.g. VMs spawned before v16.27 didn't have a
    // QMP socket).
    let running = Command::new("pgrep")
        .args(["-af", &format!("qemu-system.*-name {}", vm_name)])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    if !running {
        return Ok(format!(
            "USB device {} added to VM '{}' passthrough list. Start the VM \
             to attach it.",
            dev_path, vm_name
        ));
    }

    let qmp_path = format!("/run/wolfstack-qmp-{}.sock", vm_name);
    if std::path::Path::new(&qmp_path).exists() {
        match qmp_add_usb_host(&qmp_path, &vendor_id, &product_id) {
            Ok(()) => {
                info!(
                    "WolfUSB: hot-plugged {}:{} into VM '{}' via QMP",
                    vendor_id, product_id, vm_name
                );
                return Ok(format!(
                    "USB device {} hot-plugged into running VM '{}'. Windows \
                     should detect it as a newly-connected device within a \
                     few seconds.",
                    dev_path, vm_name
                ));
            }
            Err(e) => {
                warn!(
                    "WolfUSB: QMP hot-plug failed for VM '{}' ({}), falling \
                     back to restart",
                    vm_name, e
                );
            }
        }
    }

    // Fallback: stop the VM; auto_start brings it back with the new config.
    info!(
        "WolfUSB: VM '{}' has no QMP socket — stopping so it restarts with \
         the new USB passthrough (auto_start=true will bring it back up).",
        vm_name
    );
    let _ = Command::new("pkill")
        .args(["-f", &format!("qemu-system.*-name {}", vm_name)])
        .status();
    Ok(format!(
        "USB device {} added to VM '{}' passthrough list; VM stopped for \
         restart. It will restart automatically if auto_start is enabled. \
         (For hot-plug without restart, the VM must be started under \
         wolfstack v16.27+ which enables a QMP socket.)",
        dev_path, vm_name
    ))
}

/// Send a single command to QEMU's QMP socket and return its response. We
/// do the capability-negotiation handshake first (QMP requires it before
/// any real command).
fn qmp_send(socket_path: &str, command: &serde_json::Value) -> Result<serde_json::Value, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("QMP connect failed: {}", e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    // First line is the QMP greeting — discard.
    let mut greeting = String::new();
    reader.read_line(&mut greeting).map_err(|e| e.to_string())?;

    // Negotiate capabilities.
    writeln!(stream, "{{\"execute\":\"qmp_capabilities\"}}")
        .map_err(|e| e.to_string())?;
    let mut caps = String::new();
    reader.read_line(&mut caps).map_err(|e| e.to_string())?;

    // Send the real command.
    let cmd_line = command.to_string();
    writeln!(stream, "{}", cmd_line).map_err(|e| e.to_string())?;
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).map_err(|e| e.to_string())?;
    let resp: serde_json::Value = serde_json::from_str(resp_line.trim())
        .map_err(|e| format!("QMP returned non-JSON: {} ({})", resp_line, e))?;
    if let Some(err) = resp.get("error") {
        return Err(format!("QMP error: {}", err));
    }
    Ok(resp)
}

/// Hot-plug a USB device identified by vendor:product into a running QEMU
/// via its QMP socket. QMP expects vendorid/productid as unsigned integers,
/// not strings like "0x03f0" — older QEMU accepted strings but >= 10 rejects
/// them with "Parameter 'productid' expects uint64".
fn qmp_add_usb_host(socket_path: &str, vendor_id: &str, product_id: &str) -> Result<(), String> {
    let vid = u64::from_str_radix(vendor_id.trim_start_matches("0x"), 16)
        .map_err(|e| format!("invalid vendor_id '{}': {}", vendor_id, e))?;
    let pid = u64::from_str_radix(product_id.trim_start_matches("0x"), 16)
        .map_err(|e| format!("invalid product_id '{}': {}", product_id, e))?;
    let id = format!("wolfusb_{}_{}", vendor_id, product_id);
    // Hot-plug onto the xhci bus — VMs started by wolfstack v16.29+ have
    // qemu-xhci and this is where usb-host devices live. For older VMs
    // that only had `-usb` (UHCI 1.1), the QMP call will fail with an
    // invalid bus error; the caller then falls back to stop-and-restart
    // which picks up the new xhci startup.
    let cmd = serde_json::json!({
        "execute": "device_add",
        "arguments": {
            "driver": "usb-host",
            "id": id,
            "bus": "xhci.0",
            "vendorid": vid,
            "productid": pid,
        }
    });
    qmp_send(socket_path, &cmd)?;
    Ok(())
}

/// Write a udev rule that unbinds any host driver (uvcvideo, snd-usb-audio,
/// hid-generic, ...) the moment it binds to this vendor:product. That keeps
/// the device exclusively available for QEMU's `usb-host`, preventing the
/// concurrent-access fight that otherwise breaks UVC streaming and audio.
fn install_vm_passthrough_udev_rule(vendor_id: &str, product_id: &str) -> Result<(), String> {
    let rule_path = format!(
        "/etc/udev/rules.d/99-wolfstack-vm-usb-{}-{}.rules",
        vendor_id, product_id
    );
    // List of kernel drivers we proactively unbind. This is the common set
    // for peripherals users pass to VMs (webcams, audio, HID, storage).
    // If a device is bound to some other driver not in this list, QEMU's
    // libusb driver-detach should still handle it.
    let drivers = [
        "uvcvideo",
        "snd-usb-audio",
        "hid-generic",
        "usbhid",
        "usb-storage",
        "btusb",
    ];
    let mut rules = format!(
        "# Auto-generated by wolfstack — prevents host drivers from claiming\n\
         # {}:{} while it is assigned to a VM. Remove this file if the device\n\
         # is later reassigned away from VM passthrough.\n",
        vendor_id, product_id
    );
    for drv in drivers {
        rules.push_str(&format!(
            "ACTION==\"bind\", SUBSYSTEM==\"usb\", ENV{{DRIVER}}==\"{}\", \
             ATTRS{{idVendor}}==\"{}\", ATTRS{{idProduct}}==\"{}\", \
             RUN+=\"/bin/sh -c 'echo %k > /sys/bus/usb/drivers/{}/unbind'\"\n",
            drv, vendor_id, product_id, drv
        ));
    }
    std::fs::write(&rule_path, rules)
        .map_err(|e| format!("failed to write udev rule {}: {}", rule_path, e))?;
    let _ = Command::new("udevadm").args(["control", "--reload-rules"]).status();
    Ok(())
}

/// Force-unbind any currently-bound host driver on this vendor:product so
/// QEMU can grab the device immediately. Without this, the udev rule only
/// applies to future bind events — the existing binding stays.
fn unbind_host_drivers_now(vendor_id: &str, product_id: &str) {
    // Walk every interface whose parent has matching idVendor/idProduct.
    let entries = match std::fs::read_dir("/sys/bus/usb/devices") {
        Ok(e) => e,
        Err(_) => return,
    };
    for e in entries.flatten() {
        let p = e.path();
        // Interface entries contain ':' — that's what we unbind drivers from.
        let name = match p.file_name().and_then(|n| n.to_str()) {
            Some(n) if n.contains(':') => n.to_string(),
            _ => continue,
        };
        let parent = match name.split(':').next() {
            Some(x) => format!("/sys/bus/usb/devices/{}", x),
            None => continue,
        };
        let v = std::fs::read_to_string(format!("{}/idVendor", parent))
            .unwrap_or_default()
            .trim()
            .to_string();
        let pr = std::fs::read_to_string(format!("{}/idProduct", parent))
            .unwrap_or_default()
            .trim()
            .to_string();
        if v == vendor_id && pr == product_id
            && let Ok(driver) = std::fs::read_link(p.join("driver"))
                && let Some(drv_name) = driver.file_name().and_then(|n| n.to_str()) {
                    let unbind = format!("/sys/bus/usb/drivers/{}/unbind", drv_name);
                    let _ = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&unbind)
                        .and_then(|mut f| {
                            use std::io::Write;
                            f.write_all(name.as_bytes())
                        });
                }
    }
}

/// Look up a Proxmox VM id by name. Proxmox keys VMs by numeric VMID; the
/// human-friendly `name:` field is set via `qm set --name`. We match on both
/// so the user can reference either.
fn find_proxmox_vmid(vm_name: &str) -> Option<u32> {
    // `qm list` is only present on Proxmox hosts. Missing = not Proxmox.
    let out = Command::new("qm").arg("list").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines().skip(1) {
        // Format: "VMID   NAME   STATUS   MEM(MB)  BOOTDISK(GB)  PID"
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let vmid: u32 = match fields[0].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if fields[1] == vm_name || fields[0] == vm_name {
            return Some(vmid);
        }
    }
    None
}

/// Hot-plug a USB device into a Proxmox-managed VM. Proxmox 7+ turns
/// `qm set --usbN host=vid:pid` on a running VM into a live device_add
/// via QMP internally, so no restart needed.
fn passthrough_to_proxmox_vm(
    vmid: u32,
    vm_name: &str,
    vendor_id: &str,
    product_id: &str,
    dev_path: &str,
) -> Result<String, String> {
    let vmid_str = vmid.to_string();

    // Find the first free usb slot (usb0..usb4). Skip slots already holding
    // a different device — don't overwrite existing passthroughs.
    let cfg = Command::new("qm")
        .args(["config", &vmid_str])
        .output()
        .map_err(|e| format!("qm config failed: {}", e))?;
    if !cfg.status.success() {
        return Err(format!(
            "qm config {} failed: {}",
            vmid,
            String::from_utf8_lossy(&cfg.stderr).trim()
        ));
    }
    let cfg_text = String::from_utf8_lossy(&cfg.stdout);
    let wanted = format!("host={}:{}", vendor_id, product_id);

    // Already assigned? Idempotent success.
    if cfg_text
        .lines()
        .any(|l| l.starts_with("usb") && l.contains(&wanted))
    {
        return Ok(format!(
            "USB device {} is already attached to Proxmox VM {} ({})",
            dev_path, vm_name, vmid
        ));
    }

    let mut free_slot: Option<u8> = None;
    for i in 0..5u8 {
        let prefix = format!("usb{}:", i);
        if !cfg_text.lines().any(|l| l.starts_with(&prefix)) {
            free_slot = Some(i);
            break;
        }
    }
    let slot = free_slot.ok_or_else(|| {
        format!(
            "All 5 USB slots on Proxmox VM {} are occupied; remove one \
             before adding another.",
            vmid
        )
    })?;

    let out = Command::new("qm")
        .args([
            "set",
            &vmid_str,
            &format!("--usb{}", slot),
            &wanted,
        ])
        .output()
        .map_err(|e| format!("qm set failed: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "qm set --usb{} {} failed: {}",
            slot,
            wanted,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    info!(
        "WolfUSB: attached {} ({}:{}) to Proxmox VM {} as usb{}",
        dev_path, vendor_id, product_id, vmid, slot
    );
    Ok(format!(
        "USB device {} attached to Proxmox VM '{}' ({}) as usb{}. Hot-plug \
         is live on Proxmox 7+; on older Proxmox versions you may need to \
         reboot the VM.",
        dev_path, vm_name, vmid, slot
    ))
}

/// Read idVendor and idProduct from a /dev/bus/usb/XXX/YYY device path by
/// walking sysfs. Returns ("vvvv", "pppp") hex without 0x prefix, as stored
/// in VmConfig.usb_devices — matches how the UI saves manual VM USB entries.
fn read_usb_ids_from_devpath(dev_path: &str) -> Option<(String, String)> {
    // /dev/bus/usb/XXX/YYY → look up matching sysfs device.
    let parts: Vec<&str> = dev_path.trim_start_matches("/dev/bus/usb/").split('/').collect();
    if parts.len() != 2 { return None; }
    let bus: u32 = parts[0].parse().ok()?;
    let devnum: u32 = parts[1].parse().ok()?;
    for entry in std::fs::read_dir("/sys/bus/usb/devices").ok()? {
        let Ok(e) = entry else { continue };
        let path = e.path();
        let sys_bus = std::fs::read_to_string(path.join("busnum"))
            .ok().and_then(|s| s.trim().parse::<u32>().ok());
        let sys_dev = std::fs::read_to_string(path.join("devnum"))
            .ok().and_then(|s| s.trim().parse::<u32>().ok());
        if sys_bus == Some(bus) && sys_dev == Some(devnum) {
            let v = std::fs::read_to_string(path.join("idVendor")).ok()?.trim().to_string();
            let p = std::fs::read_to_string(path.join("idProduct")).ok()?.trim().to_string();
            return Some((v, p));
        }
    }
    None
}

// ─── Startup Restore & Container Event Hooks ───

/// Called on WolfStack startup. Re-establishes all assignments.
pub fn restore_assignments(self_node_id: &str) {
    let config = WolfUsbConfig::load();
    if !config.enabled || config.assignments.is_empty() { return; }
    if !is_wolfusb_available() { return; }

    info!("WolfUSB: restoring {} assignments on startup", config.assignments.len());
    ensure_wolfusb_server();

    for a in &config.assignments {
        // Target side: re-attach remote devices for containers on this node
        if a.target_node_id == self_node_id && a.source_node_id != self_node_id {
            // Boot-time restore runs from sync code and can't make an
            // HTTP round-trip to the source for bus+addr. We rely on
            // the existing mount unit (still installed on disk from
            // the previous attach) — attach_and_passthrough with
            // explicit=None falls back to local sysfs which works for
            // a vhci device left over from the last boot. If the device
            // was physically replugged between reboots the operator
            // will see it appear in the Re-attach dialog.
            match attach_and_passthrough(&a.source_address, &a.busid, &a.target_type, &a.target_name, None) {
                Ok(msg) => info!("WolfUSB: restored {} — {}", a.busid, msg),
                Err(e) => warn!("WolfUSB: failed to restore {}: {}", a.busid, e),
            }
        }
    }
}

/// Called when a container starts or restarts on this node.
pub fn on_container_started(container_name: &str, container_type: &str, self_node_id: &str) {
    let mut config = WolfUsbConfig::load();
    if !config.enabled || config.assignments.is_empty() { return; }

    let mut changed = false;

    for a in &mut config.assignments {
        if a.target_name != container_name || a.target_type != container_type { continue; }

        if a.target_node_id != self_node_id {
            info!("WolfUSB: container {} migrated to this node — re-routing USB {}", container_name, a.busid);
            a.target_node_id = self_node_id.to_string();
            a.target_hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| self_node_id.to_string());
            changed = true;
        }

        if a.source_node_id != self_node_id {
            if !a.source_address.is_empty() {
                // Container-restart restore — same constraint as the
                // boot-time path: we can't easily do an async HTTP
                // round-trip to the source from this sync event hook,
                // so fall back to the local sysfs lookup. The operator
                // can use Re-attach (which DOES query the source) if
                // the local fallback comes up empty.
                match attach_and_passthrough(&a.source_address, &a.busid, &a.target_type, &a.target_name, None) {
                    Ok(msg) => info!("WolfUSB: restored {} for {} — {}", a.busid, container_name, msg),
                    Err(e) => warn!("WolfUSB: failed to restore {} for {}: {}", a.busid, container_name, e),
                }
            }
        } else {
            match local_passthrough(&a.busid, &a.target_type, &a.target_name) {
                Ok(msg) => info!("WolfUSB: local passthrough {} for {} — {}", a.busid, container_name, msg),
                Err(e) => warn!("WolfUSB: local passthrough {} for {} failed: {}", a.busid, container_name, e),
            }
        }
    }

    if changed { let _ = config.save(); }
}

/// Merge assignments from a remote node's config into ours.
pub fn merge_remote_assignments(remote_assignments: &[UsbAssignment]) {
    let mut config = WolfUsbConfig::load();
    let mut changed = false;

    for ra in remote_assignments {
        let exists = config.assignments.iter().any(|a|
            a.busid == ra.busid && a.source_node_id == ra.source_node_id
        );
        if !exists {
            config.assignments.push(ra.clone());
            changed = true;
        } else {
            if let Some(existing) = config.assignments.iter_mut().find(|a|
                a.busid == ra.busid && a.source_node_id == ra.source_node_id
            )
                && (existing.target_node_id != ra.target_node_id
                    || existing.target_name != ra.target_name)
                {
                    *existing = ra.clone();
                    changed = true;
                }
        }
    }

    let self_id = crate::agent::self_node_id();
    let remote_busids: Vec<(&str, &str)> = remote_assignments.iter()
        .map(|a| (a.busid.as_str(), a.source_node_id.as_str()))
        .collect();
    let before = config.assignments.len();
    config.assignments.retain(|a| {
        if a.source_node_id == self_id { return true; }
        remote_busids.iter().any(|(b, s)| *b == a.busid && *s == a.source_node_id)
    });
    if config.assignments.len() != before { changed = true; }

    if changed { let _ = config.save(); }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_parse_busid_direct_attach() {
        // `wolfusb-1-5` under the legacy format maps to bus=1, addr=5.
        assert_eq!(parse_busid("wolfusb-1-5").unwrap(), (1, 5));
    }

    #[test]
    fn legacy_parse_busid_without_prefix() {
        assert_eq!(parse_busid("2-7").unwrap(), (2, 7));
    }

    #[test]
    fn legacy_parse_busid_rejects_port_path() {
        // `1-1.5` cannot parse as u8 addr; callers should go through
        // busid_to_bus_addr which handles both formats via sysfs.
        assert!(parse_busid("wolfusb-1-1.5").is_err());
    }

    #[test]
    fn busid_port_path_strips_prefix() {
        assert_eq!(busid_port_path("wolfusb-1-1.5"), "1-1.5");
        assert_eq!(busid_port_path("wolfusb-1-5"), "1-5");
        assert_eq!(busid_port_path("1-1.2.3"), "1-1.2.3");
    }

    #[test]
    fn migration_leaves_unmatched_config_untouched() {
        // With no matching sysfs device, migration is a no-op.
        let mut c = WolfUsbConfig {
            enabled: true,
            assignments: vec![UsbAssignment {
                busid: "wolfusb-99-99".into(),
                label: "fake".into(),
                usb_id: "dead:beef".into(),
                source_node_id: "n1".into(),
                source_hostname: "host".into(),
                source_address: "127.0.0.1".into(),
                target_type: "docker".into(),
                target_name: "c1".into(),
                target_node_id: "n1".into(),
                target_hostname: "host".into(),
                active: false,
                session_id: None,
                virtual_busid: None,
            }],
        };
        let before = c.assignments[0].busid.clone();
        migrate_assignments_to_port_paths(&mut c);
        assert_eq!(c.assignments[0].busid, before);
    }
}
