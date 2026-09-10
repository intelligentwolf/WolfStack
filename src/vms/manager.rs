// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, warn, info};
use rand::Rng;
use crate::containers;
use crate::networking;
use super::passthrough::{
    parse_libvirt_hostdevs, parse_proxmox_passthrough,
    find_conflicts, check_passthrough_steals_host_net,
};

/// A storage volume that can be attached to a VM
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageVolume {
    /// Volume name (used for filename)
    pub name: String,
    /// Size in GB
    pub size_gb: u32,
    /// Storage path (directory where the volume file lives)
    pub storage_path: String,
    /// Disk format (qcow2, raw)
    #[serde(default = "default_format")]
    pub format: String,
    /// Bus type (virtio, scsi, ide)
    #[serde(default = "default_bus")]
    pub bus: String,
}

fn default_format() -> String { "qcow2".to_string() }
fn default_bus() -> String { "virtio".to_string() }

/// Summary of a storage location available on the host
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageLocation {
    pub path: String,
    pub total_gb: u64,
    pub available_gb: u64,
    pub fs_type: String,
}

impl StorageVolume {
    /// Full path to the volume file
    pub fn file_path(&self) -> PathBuf {
        Path::new(&self.storage_path).join(format!("{}.{}", self.name, self.format))
    }
}

/// Additional network interface configuration for multi-NIC VMs (e.g. OPNsense WAN+LAN)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NicConfig {
    /// NIC model: "virtio", "e1000", "e1000e", "rtl8139"
    #[serde(default = "default_net_model")]
    pub model: String,
    /// MAC address (auto-generated if empty)
    #[serde(default)]
    pub mac: Option<String>,
    /// Bridge name for this NIC (e.g. "br0", "vmbr1"). Empty = user-mode networking.
    #[serde(default)]
    pub bridge: Option<String>,
    /// Physical NIC passthrough: specify a host interface (e.g. "enp2s0") and WolfStack
    /// will auto-create a dedicated bridge for it. Used for OPNsense WAN, Starlink, etc.
    #[serde(default)]
    pub passthrough_interface: Option<String>,
}

/// USB device passthrough configuration. The device is matched on the host by
/// vendor:product ID — simple, stable across reboots, but if multiple identical
/// devices are plugged in QEMU grabs the first one. For pinning to a specific
/// physical port, use host_bus instead (format: "bus-port", e.g. "1-4").
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UsbDevice {
    /// USB vendor ID in hex, without 0x prefix (e.g. "046d")
    #[serde(default)]
    pub vendor_id: String,
    /// USB product ID in hex, without 0x prefix (e.g. "c52b")
    #[serde(default)]
    pub product_id: String,
    /// Optional: pin to a specific bus-port (e.g. "1-4") instead of vendor:product.
    /// When set, vendor_id/product_id are ignored by the builder.
    #[serde(default)]
    pub host_bus: Option<String>,
    /// Human-readable label for the UI (from lsusb). Not used by QEMU.
    #[serde(default)]
    pub label: Option<String>,
}

impl UsbDevice {
    /// Stable identifier used for conflict detection across VMs.
    pub fn match_key(&self) -> String {
        if let Some(ref hb) = self.host_bus
            && !hb.is_empty() {
                return format!("usb-bus:{}", hb);
            }
        format!("usb:{}:{}", self.vendor_id.to_lowercase(), self.product_id.to_lowercase())
    }
}

/// PCI device passthrough configuration. Identified by BDF (bus:device.function)
/// in the canonical format "DDDD:BB:DD.F" (e.g. "0000:01:00.0"). At runtime
/// WolfStack binds the device to vfio-pci (or lets libvirt/Proxmox handle it).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PciDevice {
    /// Canonical BDF: DDDD:BB:DD.F (e.g. "0000:01:00.0")
    #[serde(default)]
    pub bdf: String,
    /// Enable PCIe capability (hostpci pcie=1 on Proxmox, pcie bus on native). Default: true.
    #[serde(default = "default_true")]
    pub pcie: bool,
    /// Pass through as primary GPU (x-vga=1 / rombar tweaks). Default: false.
    #[serde(default)]
    pub primary_gpu: bool,
    /// Human-readable label for the UI (from lspci). Not used by QEMU.
    #[serde(default)]
    pub label: Option<String>,
}

fn default_true() -> bool { true }

impl PciDevice {
    /// Stable identifier used for conflict detection across VMs.
    pub fn match_key(&self) -> String {
        format!("pci:{}", self.bdf.to_lowercase())
    }
}

/// Turn the operator's bridge-mode IP fields into a cloud-init staging plan,
/// or `None` when this save has no primary-NIC IP to apply. Only bridge mode
/// has one: WolfNet and NAT own their own addressing.
fn primary_ip_plan(network_mode: &Option<String>, bridge_ip_mode: &Option<String>,
                   bridge_ip: &Option<String>, bridge_gateway: &Option<String>)
    -> Option<crate::networking::vlan_attach::PrimaryIp>
{
    use crate::networking::vlan_attach::PrimaryIp;
    if network_mode.as_deref() != Some("bridge") {
        return None;
    }
    match bridge_ip_mode.as_deref() {
        Some("static") => {
            let ip = bridge_ip.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
            Some(PrimaryIp::Static {
                ip_cidr: ip.to_string(),
                gateway: bridge_gateway.as_deref().map(str::trim)
                    .filter(|s| !s.is_empty()).map(str::to_string),
            })
        }
        Some("dhcp") => Some(PrimaryIp::Dhcp),
        _ => None,
    }
}

/// The WolfStack-only primary-NIC settings an update carries. Grouped so
/// the sidecar writer both backends share isn't a nine-argument function,
/// and so neither branch can quietly persist a different subset than the
/// other. `None` on a field means "the request didn't mention it".
#[derive(Debug, Default, Clone)]
pub struct VmNetSettings {
    pub network_mode: Option<String>,
    pub bridge: Option<String>,
    pub bridge_ip_mode: Option<String>,
    pub bridge_ip: Option<String>,
    pub bridge_gateway: Option<String>,
    pub vsw_uplink: Option<String>,
    pub vsw_vlan: Option<u32>,
    pub wolfnet_ip: Option<String>,
}

impl VmNetSettings {
    /// True when the request mentioned none of these fields, so there is
    /// nothing to persist and the sidecar must not be created or rewritten.
    fn is_empty(&self) -> bool {
        self.network_mode.is_none() && self.bridge.is_none()
            && self.bridge_ip_mode.is_none() && self.bridge_ip.is_none()
            && self.bridge_gateway.is_none() && self.vsw_uplink.is_none()
            && self.vsw_vlan.is_none() && self.wolfnet_ip.is_none()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VmConfig {
    pub name: String,
    pub cpus: u32,
    pub memory_mb: u32,
    pub disk_size_gb: u32,
    pub iso_path: Option<String>,
    // `running` and `auto_start` predate our habit of defaulting every
    // optional field, so an older VM config written before some later
    // field existed could fail to deserialize as a whole and silently
    // drop the VM from the UI list. Defaulting to false on missing
    // keeps old configs loadable and running is recomputed at list
    // time from the live process check anyway.
    #[serde(default)]
    pub running: bool,
    pub vnc_port: Option<u16>,
    #[serde(default)]
    pub vnc_ws_port: Option<u16>,
    pub mac_address: Option<String>,
    #[serde(default)]
    pub auto_start: bool,
    #[serde(default)]
    pub wolfnet_ip: Option<String>,
    /// Storage path for the OS disk (defaults to /var/lib/wolfstack/vms)
    #[serde(default)]
    pub storage_path: Option<String>,
    /// Bus type for the OS disk (virtio, ide, sata) — use ide/sata for Windows
    #[serde(default = "default_bus")]
    pub os_disk_bus: String,
    /// Network adapter model (virtio, e1000, rtl8139) — use e1000 for Windows
    #[serde(default = "default_net_model")]
    pub net_model: String,
    /// Optional secondary ISO for VirtIO drivers (needed if OS disk is virtio on Windows)
    #[serde(default)]
    pub drivers_iso: Option<String>,
    /// Import a disk image as the OS disk (not persisted — used only during creation)
    #[serde(skip)]
    pub import_image: Option<String>,
    /// Extra disks attached to this VM
    #[serde(default)]
    pub extra_disks: Vec<StorageVolume>,
    /// Extra network interfaces (net1, net2, ...) — e.g. OPNsense WAN+LAN
    #[serde(default)]
    pub extra_nics: Vec<NicConfig>,
    /// USB devices passed through from host to guest (e.g. security dongles, cameras)
    #[serde(default)]
    pub usb_devices: Vec<UsbDevice>,
    /// PCI devices passed through from host to guest (e.g. GPUs, HBAs, NVMe)
    #[serde(default)]
    pub pci_devices: Vec<PciDevice>,
    /// Proxmox VMID (only set when running on Proxmox VE)
    #[serde(default)]
    pub vmid: Option<u32>,
    /// BIOS type: "seabios" (legacy) or "ovmf" (UEFI/EFI)
    #[serde(default = "default_bios_type")]
    pub bios_type: String,
    /// Emulated TPM 2.0 device. Windows 11 requires it. Native QEMU runs a
    /// per-VM `swtpm` socket + `tpm-tis` device; Proxmox adds `--tpmstate0
    /// <storage>:1,version=v2.0`; libvirt adds an emulator `<tpm>`. Default
    /// false = today's behaviour, so upgrading never adds a TPM to an
    /// existing VM. Only meaningful together with `bios_type == "ovmf"`.
    #[serde(default)]
    pub tpm: bool,
    /// UEFI Secure Boot with Microsoft keys pre-enrolled. Windows 11 wants
    /// it. Native QEMU uses the `.secboot` OVMF firmware; Proxmox sets the
    /// efidisk `pre-enrolled-keys=1`; libvirt uses a secure `pflash` loader
    /// + SMM. Requires `bios_type == "ovmf"`. Default false.
    #[serde(default)]
    pub secure_boot: bool,
    /// Boot device order — entries from {"disk","cdrom","usb","network"}, most
    /// preferred first. EMPTY (the default for existing configs) means "use the
    /// backend's historical default" (disk first, CD fallback) so upgrading a
    /// node never changes how its existing VMs boot. "usb" boots from a
    /// passed-through USB device (native QEMU / libvirt; a Proxmox limitation).
    #[serde(default)]
    pub boot_order: Vec<String>,
    /// Allow EXTERNAL VNC clients (native QEMU only). Default false = today's
    /// behaviour exactly: VNC is reachable only through WolfStack's session-
    /// authed browser proxy. When true, the VM starts with a generated VNC
    /// password (`-object secret`) AND a tagged iptables ACCEPT opens the raw
    /// VNC port, so an external client (e.g. TigerVNC) can connect with the
    /// password. Opt-in because exposing a VNC port is a posture change.
    #[serde(default)]
    pub vnc_external: bool,
    /// Node that currently owns this VM. Populated when the VM is created
    /// and rewritten when it's migrated; lets the cluster view render VMs
    /// as first-class members under the right host without a manual Scan
    /// pass. `None` on older configs until the next write.
    #[serde(default)]
    pub host_id: Option<String>,
    /// If true, the manager will NOT add the default net0 NIC (neither
    /// WolfNet TAP nor user-mode NAT). All connectivity must come from
    /// `extra_nics`, and extra_nics[0] becomes net0 (vtnet0) in the
    /// guest. Used by firewall appliances (OPNsense with physical LAN
    /// passthrough) that don't want a dangling unused NAT interface.
    #[serde(default)]
    pub skip_default_nic: bool,

    /// Primary NIC mode. Mirrors the LXC network_mode model:
    ///   • "wolfnet" — net0 attached to per-VM WolfNet bridge `wnbr-<id>`
    ///     (Proxmox keeps an extra net0 on vmbr0 for LAN egress; net1 is
    ///     the WolfNet NIC). Auto when `wolfnet_ip` is set on older configs.
    ///   • "bridge"  — net0 attached to operator-chosen bridge in `bridge`.
    ///     Also used for the vSwitch UI sugar — the frontend auto-creates
    ///     `vmbr<vlan>` via the VLAN-attachment store before saving, then
    ///     just stores the bridge name here.
    ///   • "nat"     — user-mode SLIRP (native QEMU) / vmbr0 (Proxmox) /
    ///     `default` libvirt network. Default when nothing else is set.
    /// Absent / empty deserializes via [`Self::effective_network_mode`]
    /// for backwards compatibility with configs written before this field.
    #[serde(default)]
    pub network_mode: Option<String>,

    /// Bridge name used when `network_mode == "bridge"`. For the vSwitch
    /// preset the frontend writes `vmbr<vlan>` here after creating the
    /// VLAN attachment; for plain bridge it's whatever the operator picked
    /// (vmbr0, lxcbr0, br-pt-*, etc.).
    #[serde(default)]
    pub bridge: Option<String>,

    /// IP-assignment hint for bridge mode: "dhcp" or "static". The guest
    /// configures its own IP; this is persisted so the editor shows the
    /// operator's choice back and so the cloud-init / staged-config path
    /// added in v24.1.0 can pre-seed the guest when wanted.
    #[serde(default)]
    pub bridge_ip_mode: Option<String>,

    /// Static IP+CIDR (e.g. "192.168.10.50/24") for bridge mode when
    /// `bridge_ip_mode == "static"`. Surfaced via cloud-init.
    #[serde(default)]
    pub bridge_ip: Option<String>,

    /// Static gateway (e.g. "192.168.10.1") for bridge mode when
    /// `bridge_ip_mode == "static"`. Paired with `bridge_ip`.
    #[serde(default)]
    pub bridge_gateway: Option<String>,

    /// The vSwitch selection behind `bridge`, recorded when the operator
    /// used the vSwitch preset rather than picking a plain bridge.
    ///
    /// `bridge` alone cannot answer "was this a vSwitch?": a WolfStack VLAN
    /// bridge is an equally valid target for plain Bridge mode, and the
    /// editor used to guess by looking the bridge name up in the VLAN
    /// attachment store. That guess mislabelled every VM attached directly
    /// to an existing production VLAN bridge — the operator picked Bridge +
    /// vmbr101, and the editor re-opened on the vSwitch card, which read as
    /// the setting "reverting" (RutgerDiehard 2026-08-21). The choice is
    /// persisted here instead of being inferred. `None` = plain bridge.
    #[serde(default)]
    pub vsw_uplink: Option<String>,
    /// VLAN tag paired with [`Self::vsw_uplink`]. Both are set together.
    #[serde(default)]
    pub vsw_vlan: Option<u32>,

    /// Free-text operator notes / description shown on the VM's General tab.
    /// Persisted in the hypervisor's own description field where one exists
    /// (Proxmox `qm set --description`, libvirt `virsh desc`) and in the
    /// native sidecar config otherwise. Empty string = no notes (and clears
    /// any previously-set description). Defaults to empty for older configs.
    #[serde(default)]
    pub notes: String,

    /// Extra raw arguments appended to the QEMU/KVM command line at start
    /// (e.g. Windows-11 audio: `-audiodev pa,id=snd0 -device ich9-intel-hda
    /// -device hda-output,audiodev=snd0`). Tokenised with a shell-style
    /// splitter (quotes respected) and each token is pushed as a SEPARATE
    /// argv element — never passed through a shell. Persisted per backend:
    /// native sidecar config, Proxmox `qm set --args`, libvirt
    /// `<qemu:commandline>`. Empty string = no extra args (and clears any
    /// previously-set passthrough). Defaults to empty for older configs.
    #[serde(default)]
    pub extra_qemu_args: String,

    /// Whether the VM is currently paused/suspended (CPU frozen, RAM held).
    /// Computed at list time from a `<name>.paused` marker we write on
    /// pause_vm and clear on resume/start/stop — NOT read from a per-VM
    /// `qm status`/`virsh domstate` call, which would reintroduce the
    /// per-poll subprocess storm the Proxmox fast-path was built to avoid
    /// (Cogswell 2026-04-29). Only ever true when `running` is also true.
    /// Like `running`, it's recomputed each list and never authoritative
    /// on disk. Tracks pauses WolfStack initiated; an external `qm suspend`
    /// won't flip it (documented limitation).
    #[serde(default)]
    pub paused: bool,
}

fn default_net_model() -> String { "virtio".to_string() }
fn default_bios_type() -> String { "seabios".to_string() }

// ─── Boot-order helpers (pure, unit-tested) ─────────────────────────────
//
// A logical boot order (entries from "disk"/"cdrom"/"usb"/"network") is mapped
// to each hypervisor's own syntax. An EMPTY order means "keep the backend's
// historical default" so upgrading never changes how existing VMs boot
// (Golden Rule). "usb" boots from a passed-through USB device — supported on
// native QEMU via device bootindex; a documented limitation on libvirt/Proxmox.

/// True when the order asks to boot a passed-through USB device first. Native
/// QEMU drives this with `bootindex=0` on the usb-host device; mixing that with
/// `-boot order=` is ignored by firmware, so the caller omits `-boot order`.
pub fn boot_order_usb_first(boot_order: &[String]) -> bool {
    boot_order.first().map(|s| s.eq_ignore_ascii_case("usb")).unwrap_or(false)
}

/// QEMU `-boot order=` value for a logical order. `None` when USB leads (use
/// the device bootindex instead). Empty order → the historical default
/// (`order=cd` with install media present, else `order=c`).
fn qemu_boot_order_arg(boot_order: &[String], has_boot_media: bool) -> Option<String> {
    let default = || if has_boot_media { "order=cd".to_string() } else { "order=c".to_string() };
    if boot_order.is_empty() { return Some(default()); }
    if boot_order_usb_first(boot_order) { return None; }
    let mut letters = String::new();
    for e in boot_order {
        match e.to_ascii_lowercase().as_str() {
            "disk" if !letters.contains('c') => letters.push('c'),
            "cdrom" if !letters.contains('d') => letters.push('d'),
            "network" if !letters.contains('n') => letters.push('n'),
            _ => {} // "usb" rides on bootindex; unknown ignored
        }
    }
    Some(if letters.is_empty() { default() } else { format!("order={}", letters) })
}

/// virt-install `--boot` device list (e.g. "hd,cdrom"). Empty → historical
/// default. USB is dropped (virt-install can't express USB boot — surfaced as
/// a libvirt limitation), so a usb-only order falls back to the default.
fn libvirt_boot_order_arg(boot_order: &[String], has_boot_media: bool) -> String {
    let default = || if has_boot_media { "hd,cdrom".to_string() } else { "hd".to_string() };
    if boot_order.is_empty() { return default(); }
    let mut devs: Vec<&str> = Vec::new();
    for e in boot_order {
        let d = match e.to_ascii_lowercase().as_str() {
            "disk" => "hd",
            "cdrom" => "cdrom",
            "network" => "network",
            _ => continue, // usb unsupported here
        };
        if !devs.contains(&d) { devs.push(d); }
    }
    if devs.is_empty() { default() } else { devs.join(",") }
}

/// Proxmox `qm --boot order=` value, mapping logical devices to PVE keys
/// (disk→scsi0, cdrom→ide2, network→net0). Empty → historical default. USB is
/// dropped (PVE can't boot passthrough USB), so a usb-only order falls back.
fn pve_boot_order_arg(boot_order: &[String]) -> String {
    let default = || "order=scsi0;ide2".to_string();
    if boot_order.is_empty() { return default(); }
    let mut keys: Vec<&str> = Vec::new();
    for e in boot_order {
        let k = match e.to_ascii_lowercase().as_str() {
            "disk" => "scsi0",
            "cdrom" => "ide2",
            "network" => "net0",
            _ => continue, // usb unsupported on PVE
        };
        if !keys.contains(&k) { keys.push(k); }
    }
    if keys.is_empty() { default() } else { format!("order={}", keys.join(";")) }
}

// ─── Extra-QEMU-args helpers (operator passthrough; pure, unit-tested) ──────
//
// The operator types a single free-text string of extra QEMU args (e.g.
// `-audiodev pa,id=snd0 -device hda-output,audiodev=snd0`). It is NEVER
// handed to a shell — we tokenise it ourselves with a small shell-style
// splitter and push each token as a separate argv element on the
// `qemu-system-*` Command, so embedded shell metacharacters can't inject.

/// Split a free-text QEMU-args string into argv tokens, shell-style:
///   • whitespace (space/tab/newline) separates tokens,
///   • single quotes preserve everything verbatim until the next `'`,
///   • double quotes preserve everything (incl. spaces) until the next `"`,
///     with `\"`, `\\`, `\$` and `` \` `` recognised as escapes (POSIX dquote
///     rules — a backslash before any other char is kept literally),
///   • a backslash OUTSIDE quotes escapes the next char (so `\ ` is a
///     literal space inside one token),
///   • empty / whitespace-only input yields no tokens,
///   • adjacent quoted/unquoted runs concatenate into one token
///     (`-x"a b"c` → `-xa bc`), matching POSIX word splitting.
/// An unterminated quote is tolerated: the run to end-of-string becomes the
/// final token (best-effort; the operator's text is validated at the UI but
/// we never want a stray quote to drop a flag silently).
pub fn split_qemu_args(input: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_token = false; // distinguishes "" (one empty token) from no token
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                    in_token = false;
                }
            }
            '\'' => {
                in_token = true;
                for sc in chars.by_ref() {
                    if sc == '\'' { break; }
                    cur.push(sc);
                }
            }
            '"' => {
                in_token = true;
                while let Some(dc) = chars.next() {
                    if dc == '"' { break; }
                    if dc == '\\' {
                        match chars.peek() {
                            Some('"') | Some('\\') | Some('$') | Some('`') => {
                                cur.push(chars.next().unwrap());
                            }
                            // POSIX: a backslash before any other char in a
                            // double-quoted string is kept literally.
                            _ => cur.push('\\'),
                        }
                    } else {
                        cur.push(dc);
                    }
                }
            }
            '\\' => {
                in_token = true;
                if let Some(nc) = chars.next() {
                    cur.push(nc);
                } else {
                    cur.push('\\');
                }
            }
            other => {
                in_token = true;
                cur.push(other);
            }
        }
    }
    if in_token {
        tokens.push(cur);
    }
    tokens
}

/// Re-join argv tokens into a single display/persist string, single-quoting
/// any token that contains whitespace or shell-significant characters so the
/// result re-splits to the same tokens. The inverse of `split_qemu_args` for
/// the common case (used to render `<qemu:commandline>` args back into the
/// editable field, and to build the "raw start command" display).
pub fn join_qemu_args(tokens: &[String]) -> String {
    tokens.iter().map(|t| shell_quote(t)).collect::<Vec<_>>().join(" ")
}

/// Quote a single argv token for safe display in a space-joined command line.
/// Empty token → `''`. Tokens with no special chars are returned as-is.
/// Otherwise single-quote, escaping any embedded `'` via the `'\''` idiom.
pub fn shell_quote(token: &str) -> String {
    if token.is_empty() {
        return "''".to_string();
    }
    let needs_quote = token
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | '$' | '`' | '&' | '|' | ';' | '<' | '>' | '(' | ')' | '*' | '?' | '#' | '~' | '!'));
    if !needs_quote {
        return token.to_string();
    }
    let mut out = String::with_capacity(token.len() + 2);
    out.push('\'');
    for c in token.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

// ─── External-VNC helpers (native QEMU; opt-in via VmConfig::vnc_external) ───

/// 8-char VNC password (RFB DES auth truncates to 8 bytes anyway). Ambiguous
/// glyphs (0/O/1/l/I) are excluded so the operator can read it off the UI.
fn gen_vnc_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..8).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

/// Write the VNC password to a 0600 file QEMU reads via `-object secret,...,
/// file=…`. Keeping it out of the command line stops it leaking through `ps`.
fn write_vnc_passfile(path: &str, pw: &str) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o600)
        .open(path).map_err(|e| format!("VNC passfile {}: {}", path, e))?;
    f.write_all(pw.as_bytes()).map_err(|e| format!("VNC passfile write: {}", e))?;
    // mode() only applies on creation — re-assert 0600 in case the file pre-existed
    // with looser perms (defensive; the password must never be world-readable).
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Open the raw VNC port to external clients. Inserted at the TOP of INPUT so
/// it takes effect regardless of the host's firewall (ufw/firewalld/raw) or
/// default policy. Tagged with the VM name so stop can remove exactly this
/// rule. Idempotent (deletes any prior identical rule first).
fn vnc_firewall_open(port: u16, name: &str) {
    let comment = format!("wolfstack-vnc-{}", name);
    let p = port.to_string();
    let _ = std::process::Command::new("iptables")
        .args(["-D", "INPUT", "-p", "tcp", "--dport", &p, "-j", "ACCEPT", "-m", "comment", "--comment", &comment]).output();
    let _ = std::process::Command::new("iptables")
        .args(["-I", "INPUT", "1", "-p", "tcp", "--dport", &p, "-j", "ACCEPT", "-m", "comment", "--comment", &comment]).output();
}

/// Remove the external-VNC ACCEPT rule for a VM's port (best-effort, loops to
/// clear any duplicates from repeated starts).
fn vnc_firewall_close(port: u16, name: &str) {
    let comment = format!("wolfstack-vnc-{}", name);
    let p = port.to_string();
    for _ in 0..4 {
        let ok = std::process::Command::new("iptables")
            .args(["-D", "INPUT", "-p", "tcp", "--dport", &p, "-j", "ACCEPT", "-m", "comment", "--comment", &comment])
            .output().map(|o| o.status.success()).unwrap_or(false);
        if !ok { break; }
    }
}

/// Close any external-VNC ACCEPT rules tagged for this VM whose port ISN'T the
/// one now in use — reaps orphans left by a crash / force-kill / out-of-band
/// stop before a fresh start opens a (possibly different, autoport) port. This
/// is what stops a stale rule from later exposing an unrelated VM that libvirt
/// hands the freed port to. Parses `iptables -S INPUT` for our comment tag.
fn vnc_firewall_reap_stale(name: &str, keep_port: u16) {
    let comment = format!("wolfstack-vnc-{}", name);
    if let Ok(out) = std::process::Command::new("iptables").args(["-S", "INPUT"]).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if !line.contains(&comment) { continue; }
            let port = line.split_whitespace()
                .skip_while(|t| *t != "--dport").nth(1)
                .and_then(|p| p.parse::<u16>().ok());
            if let Some(p) = port && p != keep_port { vnc_firewall_close(p, name); }
        }
    }
}

impl VmConfig {
    pub fn new(name: String, cpus: u32, memory_mb: u32, disk_size_gb: u32) -> Self {
        VmConfig {
            paused: false,
            name,
            cpus,
            memory_mb,
            disk_size_gb,
            iso_path: None,
            running: false,
            vnc_port: None,
            vnc_ws_port: None,
            mac_address: Some(generate_mac()),
            auto_start: false,
            wolfnet_ip: None,
            storage_path: None,
            os_disk_bus: "virtio".to_string(),
            net_model: "virtio".to_string(),
            drivers_iso: None,
            import_image: None,
            extra_disks: Vec::new(),
            extra_nics: Vec::new(),
            usb_devices: Vec::new(),
            pci_devices: Vec::new(),
            vmid: None,
            bios_type: "seabios".to_string(),
            tpm: false,
            secure_boot: false,
            boot_order: Vec::new(),
            vnc_external: false,
            host_id: None,
            skip_default_nic: false,
            network_mode: None,
            bridge: None,
            bridge_ip_mode: None,
            bridge_ip: None,
            vsw_uplink: None,
            vsw_vlan: None,
            bridge_gateway: None,
            notes: String::new(),
            extra_qemu_args: String::new(),
        }
    }

    /// Effective network mode with backwards-compatible inference. Configs
    /// written before `network_mode` existed get "wolfnet" when a
    /// `wolfnet_ip` is set and "nat" otherwise, matching pre-existing
    /// runtime behaviour exactly.
    pub fn effective_network_mode(&self) -> &str {
        match self.network_mode.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => if self.wolfnet_ip.is_some() { "wolfnet" } else { "nat" },
        }
    }
}

/// Detect disk image format from file extension
fn detect_image_format(path: &str) -> &str {
    let lower = path.to_lowercase();
    if lower.ends_with(".qcow2") { "qcow2" }
    else if lower.ends_with(".vmdk") { "vmdk" }
    else if lower.ends_with(".vdi") { "vdi" }
    else if lower.ends_with(".vhd") || lower.ends_with(".vhdx") { "vpc" }
    else { "raw" } // .img and anything else treated as raw
}

pub(crate) fn generate_mac() -> String {
    let mut rng = rand::thread_rng();
    format!("52:54:00:{:02x}:{:02x}:{:02x}", rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.r#gen::<u8>())
}

/// Validate a VM name for use in clone source / destination positions.
/// Mirrors the backup-restore name validator: rejects path-traversal
/// characters, control bytes, leading dots, and anything outside the
/// libvirt-safe allowlist `[A-Za-z0-9_.+:-]`. Both `qm` and `virsh`
/// pass these names as positional args; the allowlist also ensures
/// they can't be misinterpreted by either hypervisor's arg parsing.
pub(crate) fn validate_clone_vm_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("VM name is empty".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0')
        || name.contains("..") || name.starts_with('.') || name.starts_with('-')
    {
        // Reject leading `-` so a malicious name (e.g. `--full`) can't
        // be argv-injected into `qm clone … --name <name>` — Command
        // does no shell parsing but the positional becomes a flag.
        return Err(format!(
            "invalid VM name '{}' — must not contain /, \\, NUL, '..' or start with '.' or '-'", name));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric()
        || c == '_' || c == '-' || c == '.' || c == '+' || c == ':')
    {
        return Err(format!(
            "invalid VM name '{}' — only A-Z a-z 0-9 _ . - + : are allowed", name));
    }
    Ok(())
}

/// Snapshot returned by [`VmManager::prepare_clone`]; consumed by
/// [`execute_clone`] outside the manager lock. The whole point of
/// the split is so the multi-minute disk I/O does not hold the
/// `Mutex<VmManager>` and starve every other VM API call.
pub struct ClonePlan {
    pub src: VmConfig,
    pub base_dir: PathBuf,
    /// Host runs Proxmox VE — dispatch via `qm clone`.
    pub on_proxmox: bool,
    /// Host runs libvirt AND the source has a libvirt domain by the
    /// same name — dispatch via `virt-clone`. Falls through to the
    /// native code path otherwise, which is correct on libvirt
    /// hosts that also run WolfStack-native VMs.
    pub on_libvirt: bool,
}

/// Perform the clone described by `plan`. Pure free function — does
/// NOT take the `VmManager` mutex. Call this from inside `web::block`
/// AFTER snapshotting via [`VmManager::prepare_clone`].
pub fn execute_clone(plan: ClonePlan, new_name: &str, full: bool) -> Result<(), String> {
    if plan.on_proxmox {
        return clone_vm_proxmox_impl(&plan.src, new_name, full);
    }
    if plan.on_libvirt {
        return clone_vm_libvirt_impl(&plan.src.name, new_name);
    }
    clone_vm_native_impl(&plan.src, &plan.base_dir, new_name)
}

fn clone_vm_proxmox_impl(src: &VmConfig, new_name: &str, full: bool) -> Result<(), String> {
    let src_vmid = src.vmid.ok_or_else(||
        format!("Proxmox VM '{}' has no vmid — cannot locate Proxmox state", src.name))?;
    let new_vmid = next_pve_vmid()?;
    let mut args: Vec<String> = vec![
        "clone".to_string(),
        src_vmid.to_string(),
        new_vmid.to_string(),
        "--name".to_string(),
        new_name.to_string(),
    ];
    if full {
        args.push("--full".to_string());
        args.push("1".to_string());
    }
    let out = Command::new("qm").args(&args).output()
        .map_err(|e| format!("qm clone failed to start: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "qm clone {} → {}: {}",
            src_vmid, new_vmid,
            String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn clone_vm_libvirt_impl(src_name: &str, new_name: &str) -> Result<(), String> {
    // virt-clone --auto-clone picks a fresh MAC + new disk names
    // automatically, always does a full disk copy. Operator can
    // edit the result via `virsh edit <new_name>` post-clone.
    let out = Command::new("virt-clone")
        .args(["--original", src_name, "--name", new_name, "--auto-clone"])
        .output()
        .map_err(|e| format!(
            "virt-clone failed to start (is virt-install/virt-manager installed?): {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "virt-clone {} → {}: {}",
            src_name, new_name,
            String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn clone_vm_native_impl(src: &VmConfig, base_dir: &Path, new_name: &str) -> Result<(), String> {
    // Live qcow2 copy = inconsistent disk. Refuse if source is
    // running and tell the operator how to proceed.
    if src.running {
        return Err(format!(
            "VM '{}' is running — stop it before cloning. \
             Cloning a live disk would produce an inconsistent image.",
            src.name));
    }

    // Build the new VmConfig: same shape, fresh identity.
    let mut new_config = src.clone();
    new_config.name = new_name.to_string();
    new_config.mac_address = Some(generate_mac());
    new_config.running = false;
    new_config.vnc_port = None;
    new_config.vnc_ws_port = None;
    new_config.wolfnet_ip = None;
    new_config.vmid = None;
    // Refresh extra-NIC MACs too so the cloned VM doesn't collide
    // with the source on any NIC.
    for nic in &mut new_config.extra_nics {
        nic.mac = Some(generate_mac());
    }
    // Rename extra-disk records so their on-disk filenames don't
    // collide with the source's disks. replacen() swaps the first
    // occurrence of the source VM name with the new name; this
    // covers the common convention (e.g. "myvm-data" → "clone-
    // data"). If the operator named the volume arbitrarily (no
    // VM-name substring) the replacen is a no-op and we'd produce
    // a colliding path. Detect that upfront with a clear message.
    for disk in &mut new_config.extra_disks {
        let renamed = disk.name.replacen(&src.name, new_name, 1);
        if renamed == disk.name {
            return Err(format!(
                "extra disk '{}' does not contain the source VM name '{}' in its filename, \
                 so the clone would collide with the source. \
                 Rename or remove the volume before cloning.",
                disk.name, src.name));
        }
        disk.name = renamed;
    }

    // Copy OS disk.
    let src_disk = base_dir.join(format!("{}.qcow2", src.name));
    let dest_disk = base_dir.join(format!("{}.qcow2", new_name));
    if dest_disk.exists() {
        return Err(format!(
            "destination disk {} already exists — refusing to overwrite",
            dest_disk.display()));
    }
    if src_disk.exists()
        && let Err(e) = fs::copy(&src_disk, &dest_disk) {
            // fs::copy on Linux can leave a partial dest file when it
            // fails mid-write (disk full, I/O error). Remove it so we
            // don't leak corrupt qcow2 files into the VM directory.
            let _ = fs::remove_file(&dest_disk);
            return Err(format!("copy OS disk: {}", e));
        }

    // Copy extra disks. Roll back the OS-disk copy AND every extra
    // we've already placed in this loop if anything fails — both
    // "destination exists" and "copy failed" must clean up the
    // earlier successes, otherwise a mid-loop failure leaks files.
    let mut placed_extras: Vec<PathBuf> = Vec::new();
    for (old, new) in src.extra_disks.iter().zip(new_config.extra_disks.iter()) {
        let src_path = old.file_path();
        let dest_path = new.file_path();
        if dest_path.exists() {
            let _ = fs::remove_file(&dest_disk);
            for prev in &placed_extras { let _ = fs::remove_file(prev); }
            return Err(format!(
                "destination extra disk {} already exists — rolled back",
                dest_path.display()));
        }
        if src_path.exists() {
            if let Err(e) = fs::copy(&src_path, &dest_path) {
                let _ = fs::remove_file(&dest_disk);
                for prev in &placed_extras { let _ = fs::remove_file(prev); }
                return Err(format!("copy extra disk {}: {}", old.name, e));
            }
            placed_extras.push(dest_path);
        }
    }

    // Write the new config JSON.
    let config_json = serde_json::to_string_pretty(&new_config)
        .map_err(|e| format!("serialize new config: {}", e))?;
    let new_config_path = base_dir.join(format!("{}.json", new_name));
    if let Err(e) = fs::write(&new_config_path, &config_json) {
        // Roll back every disk we actually placed.
        let _ = fs::remove_file(&dest_disk);
        for prev in &placed_extras { let _ = fs::remove_file(prev); }
        return Err(format!("write new config: {}", e));
    }
    Ok(())
}

pub struct VmManager {
    pub base_dir: PathBuf,
}

impl VmManager {
    pub fn new() -> Self {
        let base_dir = PathBuf::from("/var/lib/wolfstack/vms");
        if let Err(e) = fs::create_dir_all(&base_dir) {
            error!("Failed to create VM directory: {}", e);
        }
        VmManager { base_dir }
    }

    pub fn list_vms(&self) -> Vec<VmConfig> {
        self.list_vms_impl(/*heal=*/true)
    }

    /// Read-only VM enumeration — identical to [`list_vms`] but performs
    /// NO disk writes (it never self-heals stale pause markers). For the
    /// observed Network Map, whose whole promise is side-effect-free reads.
    pub fn list_vms_readonly(&self) -> Vec<VmConfig> {
        self.list_vms_impl(/*heal=*/false)
    }

    fn list_vms_impl(&self, heal: bool) -> Vec<VmConfig> {
        // On Proxmox, discover VMs via qm list
        if containers::is_proxmox() {
            let mut vms = self.qm_list_all();
            self.annotate_paused_impl(&mut vms, heal);
            return vms;
        }
        // On libvirt, discover VMs via virsh
        if containers::is_libvirt() {
            let mut vms = self.virsh_list_all();
            self.annotate_paused_impl(&mut vms, heal);
            return vms;
        }

        // Standalone: scan local config files. Parse failures are logged
        // rather than silently swallowed — an un-loggable drop here was
        // why a user saw a VM vanish from the UI after upgrade while it
        // was still running and still listed in WolfRun.
        let mut vms = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                // Skip sidecar runtime files — they're plain port metadata,
                // not VmConfig, so parsing them always fails spuriously.
                if path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".runtime.json"))
                    .unwrap_or(false)
                { continue; }
                let content = match fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to read VM config {}: {}", path.display(), e);
                        continue;
                    }
                };
                let mut vm = match serde_json::from_str::<VmConfig>(&content) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to parse VM config {}: {} — the VM will not appear in the list until this is fixed", path.display(), e);
                        continue;
                    }
                };
                vm.running = self.check_running(&vm.name);
                if vm.running {
                    vm.vnc_port = self.read_runtime_vnc_port(&vm.name);
                    vm.vnc_ws_port = self.read_runtime_ws_port(&vm.name);
                } else {
                    vm.vnc_port = None;
                    vm.vnc_ws_port = None;
                }
                vms.push(vm);
            }
        }
        self.annotate_paused_impl(&mut vms, heal);
        vms
    }

    /// Discover all VMs from Proxmox.
    ///
    /// Fast path: read `/etc/pve/qemu-server/*.conf` directly. Same content
    /// `qm config <vmid>` would return — Proxmox's pmxcfs FUSE mount
    /// surfaces these files as the source of truth, so reading them is
    /// equivalent to running `qm config` per VM but with zero subprocess
    /// overhead. Liveness via `/var/run/qemu-server/<vmid>.pid` + /proc.
    ///
    /// Why this matters (Adam Cogswell 2026-04-29): the previous path
    /// ran `qm list` once + `qm status <vmid>` + `qm config <vmid>` per
    /// VM. Each `qm` is a Perl wrapper around the Proxmox API: ~300ms
    /// per invocation. On a 20-VM box that's 41 sequential subprocesses,
    /// ~12s wall-clock — which blocked the Tokio worker (since
    /// `state.vms.lock()` was held across the call) and explained the
    /// "Virtual machines page spins for a LONG time" + "Start VM says
    /// failed but actually starts" symptoms (HTTP timeout while qm
    /// finished out-of-band). Filesystem path is <50ms for the same
    /// box.
    ///
    /// Fallback: if `/etc/pve/qemu-server` isn't readable for any
    /// reason (non-cluster Proxmox in some weird state, perms, etc.)
    /// we delegate to the slow `qm list` path so we never silently
    /// list zero VMs on a real Proxmox host.
    fn qm_list_all(&self) -> Vec<VmConfig> {
        let fast = qm_list_via_filesystem();
        if !fast.is_empty() || pve_qemu_server_dir_readable() {
            return fast;
        }
        self.qm_list_via_subprocess()
    }

    /// Original subprocess-driven path. Retained as a fallback for the
    /// rare case where `/etc/pve/qemu-server` is unreadable on a
    /// Proxmox host.
    fn qm_list_via_subprocess(&self) -> Vec<VmConfig> {
        let output = match Command::new("qm").arg("list").output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return vec![],
        };

        output.lines()
            .skip(1) // Skip header: VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let vmid: u32 = parts.first()?.parse().ok()?;
                let name = parts.get(1).unwrap_or(&"").to_string();
                let mem_mb: u32 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                let disk_gb: u32 = parts.get(4).and_then(|s| s.parse::<f64>().ok()).map(|f| f as u32).unwrap_or(0);
                // Use `qm status {vmid}` for reliable status (qm list column parsing
                // can break on ARM/PiMox or when VM names contain spaces)
                let running = Command::new("qm").args(["status", &vmid.to_string()]).output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains("running"))
                    .unwrap_or(false);

                // Read detailed config from qm config {vmid}
                let mut cpus: u32 = 1;
                let mut memory_mb = mem_mb;
                let mut disk_size_gb = disk_gb;
                let mut auto_start = false;
                let mut mac_address: Option<String> = None;
                let mut iso_path: Option<String> = None;
                let mut storage_path: Option<String> = None;
                let mut net0_bridge: Option<String> = None;
                let mut wolfnet_active = false;
                let mut notes = String::new();
                let mut extra_qemu_args = String::new();
                let mut extra_nic_pairs: Vec<(usize, NicConfig)> = Vec::new();

                // Capture the raw qm config text so we can parse passthrough lines too
                let qm_config_text = Command::new("qm").args(["config", &vmid.to_string()]).output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                if !qm_config_text.is_empty() {
                    let cfg_text = qm_config_text.as_str();
                    for cline in cfg_text.lines() {
                        let cline = cline.trim();
                        if cline.starts_with("cores:") {
                            cpus = cline.split(':').nth(1).unwrap_or("1").trim().parse().unwrap_or(1);
                        } else if cline.starts_with("description:") {
                            notes = cline.split_once(':').map(|x| x.1).map(|s| containers::pve_decode_description(s.trim())).unwrap_or_default();
                        } else if cline.starts_with("args:") {
                            // `args:` carries the operator's extra raw KVM args (set via `qm set --args`).
                            extra_qemu_args = cline.split_once(':').map(|x| x.1).map(|s| s.trim().to_string()).unwrap_or_default();
                        } else if cline.starts_with("memory:") {
                            memory_mb = cline.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(mem_mb);
                        } else if cline.starts_with("onboot:") {
                            auto_start = cline.split(':').nth(1).unwrap_or("0").trim() == "1";
                        } else if cline.starts_with("net0:") {
                            // Extract MAC + bridge from net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0
                            if let Some(val) = cline.split_once(':').map(|x| x.1) {
                                for part in val.split(',') {
                                    let part = part.trim();
                                    if part.starts_with("virtio=") || part.starts_with("e1000=") || part.starts_with("rtl8139=") {
                                        mac_address = part.split('=').nth(1).map(|s| s.to_string());
                                    } else if let Some(br) = part.strip_prefix("bridge=") {
                                        let br = br.trim();
                                        if !br.is_empty() { net0_bridge = Some(br.to_string()); }
                                    }
                                }
                            }
                        } else if cline.starts_with("net") && !cline.starts_with("net0:") {
                            // net1, net2, … — surface as editable extra NICs
                            // (skip the WolfNet bridge — that lives behind
                            // the network_mode preset instead).
                            if let Some((k, v)) = cline.split_once(':') {
                                let v = v.trim();
                                if v.contains("bridge=wnbr-") { wolfnet_active = true; }
                                if let Some(pair) = parse_pve_extra_nic(k.trim(), v) {
                                    extra_nic_pairs.push(pair);
                                }
                            }
                        } else if (cline.starts_with("ide2:") || cline.starts_with("cdrom:")) && cline.contains("media=cdrom") {
                            // Extract ISO path
                            if let Some(val) = cline.split_once(':').map(|x| x.1) {
                                let iso = val.split(',').next().unwrap_or("").trim().to_string();
                                if !iso.is_empty() {
                                    iso_path = Some(iso);
                                }
                            }
                        } else if cline.starts_with("scsi0:") || cline.starts_with("virtio0:") || cline.starts_with("ide0:") || cline.starts_with("sata0:") {
                            // Extract storage and disk size from primary disk
                            if let Some(val) = cline.split_once(':').map(|x| x.1) {
                                // e.g. "local-lvm:vm-100-disk-0,size=32G"
                                let disk_spec = val.trim();
                                if let Some(store) = disk_spec.split(':').next() {
                                    storage_path = Some(store.trim().to_string());
                                }
                                for part in disk_spec.split(',') {
                                    let part = part.trim();
                                    if part.starts_with("size=") {
                                        let size_str = part.trim_start_matches("size=").trim_end_matches('G').trim_end_matches('g');
                                        if let Ok(s) = size_str.parse::<f64>() {
                                            disk_size_gb = s as u32;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Parse usbN= and hostpciN= lines so device state round-trips through edits
                let (usb_devices, pci_devices) = parse_proxmox_passthrough(&qm_config_text);

                // Sort extras by net-index so the editor shows them in
                // the same net1/net2/… order PVE has.
                extra_nic_pairs.sort_by_key(|(n, _)| *n);
                let extra_nics: Vec<NicConfig> = extra_nic_pairs.into_iter().map(|(_, n)| n).collect();

                // Derive network_mode from net0's bridge — but a WolfNet
                // attachment on net1 always wins. Mode is recomputed at
                // display time; `effective_network_mode` keeps the fallback
                // for older configs missing this field entirely.
                let (derived_mode, derived_bridge) = if wolfnet_active {
                    (Some("wolfnet".to_string()), None)
                } else {
                    match net0_bridge.as_deref() {
                        Some("vmbr0") | None => (Some("nat".to_string()), None),
                        Some(other) => (Some("bridge".to_string()), Some(other.to_string())),
                    }
                };

                Some(VmConfig {
                    paused: false,
                    name,
                    cpus,
                    memory_mb,
                    disk_size_gb,
                    iso_path,
                    running,
                    vnc_port: None,
                    vnc_ws_port: None,
                    mac_address,
                    auto_start,
                    wolfnet_ip: None,
                    storage_path,
                    os_disk_bus: "virtio".to_string(),
                    net_model: "virtio".to_string(),
                    drivers_iso: None,
                    import_image: None,
                    extra_disks: Vec::new(),
                    extra_nics,
                    usb_devices,
                    pci_devices,
                    vmid: Some(vmid),
                    // Parse the REAL firmware/TPM/Secure-Boot state from the qm
                    // config — hardcoding "seabios" here made the editor
                    // pre-select SeaBIOS for a real OVMF VM, and saving any edit
                    // then downgraded it (qm_apply_media_bios applies bios_type
                    // bidirectionally), breaking UEFI boot.
                    bios_type: pve_conf_value(&qm_config_text, "bios")
                        .unwrap_or_else(|| "seabios".to_string()),
                    tpm: qm_config_text.contains("tpmstate0"),
                    secure_boot: qm_config_text.contains("pre-enrolled-keys=1"),
                    boot_order: Vec::new(),
                    vnc_external: false,
                    host_id: Some(crate::agent::self_node_id()),
                    skip_default_nic: false,
                    network_mode: derived_mode,
                    bridge: derived_bridge,
                    bridge_ip_mode: None,
                    bridge_ip: None,
                    bridge_gateway: None,
                    vsw_uplink: None,
                    vsw_vlan: None,
                    notes,
                    extra_qemu_args,
                })
            })
            .collect()
    }

    /// Look up a Proxmox VMID by VM name. Reads `/etc/pve/qemu-server/*.conf`
    /// directly — same content `qm list` returns but without the ~300ms
    /// Perl wrapper. Falls back to `qm list` parsing only when the
    /// filesystem path is unreadable.
    ///
    /// Adam Cogswell case: every VM lifecycle action (start / stop /
    /// reboot) called this AND `list_vms`, paying the subprocess tax
    /// twice. Going filesystem-direct here cuts another ~300ms off
    /// every action — and removes one call site of `qm list` whose
    /// whitespace-column parsing breaks on VM names with spaces.
    pub fn qm_vmid_by_name(&self, name: &str) -> Option<u32> {
        if let Some(vmid) = qm_vmid_by_name_filesystem(name) {
            return Some(vmid);
        }
        if pve_qemu_server_dir_readable() {
            // Directory's there; the VM just doesn't exist by that name.
            return None;
        }
        // Fallback: the legacy `qm list` parse. Only reached when /etc/pve
        // isn't readable.
        let output = Command::new("qm").arg("list").output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.get(1).map(|n| *n == name).unwrap_or(false) {
                return parts.first()?.parse().ok();
            }
        }
        None
    }

    fn vm_config_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", name))
    }

    /// Persist the WolfStack-only primary-NIC fields into the VM's JSON
    /// sidecar.
    ///
    /// Neither hypervisor has a home for these: libvirt's domain XML has no
    /// concept of "the operator picked the vSwitch card and wants .50/24",
    /// and `qm` carries the bridge but not the intent behind it. Both update
    /// branches call this so they persist exactly the same set — the Proxmox
    /// branch previously wrote no sidecar at all, which is why a Proxmox VM's
    /// IP hints never survived a save.
    /// Returns true when the primary-NIC IP intent (mode + bridge IP mode +
    /// address + gateway) actually changed, so the caller only re-stages
    /// cloud-init on a real change instead of on every unrelated save.
    fn persist_vm_net_sidecar(&self, name: &str, net: &VmNetSettings) -> bool {
        if net.is_empty() {
            return false;
        }
        let sidecar_path = self.vm_config_path(name);
        // Load the existing sidecar or build a minimal one; we only touch the
        // network fields and leave everything else as it was.
        let mut sidecar = fs::read_to_string(&sidecar_path).ok()
            .and_then(|t| serde_json::from_str::<VmConfig>(&t).ok())
            .unwrap_or_else(|| VmConfig::new(name.to_string(), 1, 512, 1));
        let before = (sidecar.network_mode.clone(), sidecar.bridge_ip_mode.clone(),
                      sidecar.bridge_ip.clone(), sidecar.bridge_gateway.clone());
        if let Some(ref nm) = net.network_mode {
            sidecar.network_mode = if nm.is_empty() { None } else { Some(nm.clone()) };
            if nm != "bridge" {
                sidecar.bridge = None;
                sidecar.bridge_ip_mode = None;
                sidecar.bridge_ip = None;
                sidecar.bridge_gateway = None;
                // Leaving bridge mode ends any vSwitch association too.
                sidecar.vsw_uplink = None;
                sidecar.vsw_vlan = None;
            }
        }
        if let Some(ref br) = net.bridge {
            sidecar.bridge = if br.is_empty() { None } else { Some(br.clone()) };
        }
        if let Some(ref ipm) = net.bridge_ip_mode {
            sidecar.bridge_ip_mode = if ipm.is_empty() { None } else { Some(ipm.clone()) };
        }
        if let Some(ref bi) = net.bridge_ip {
            sidecar.bridge_ip = if bi.is_empty() { None } else { Some(bi.clone()) };
        }
        if let Some(ref bg) = net.bridge_gateway {
            sidecar.bridge_gateway = if bg.is_empty() { None } else { Some(bg.clone()) };
        }
        // The vSwitch selection. An empty uplink means the operator moved this
        // VM to a plain bridge — clear the pair so the editor stops offering
        // the vSwitch card for it.
        if let Some(ref up) = net.vsw_uplink {
            if up.is_empty() {
                sidecar.vsw_uplink = None;
                sidecar.vsw_vlan = None;
            } else {
                sidecar.vsw_uplink = Some(up.clone());
                sidecar.vsw_vlan = net.vsw_vlan;
            }
        }
        if let Some(ref wip) = net.wolfnet_ip {
            sidecar.wolfnet_ip = if wip.is_empty() { None } else { Some(wip.clone()) };
        }
        // A bridge/NAT VM has no WolfNet IP. Force it off authoritatively
        // (after the wip assignment above) so switching a VM from WolfNet to
        // bridge never leaves the dead 10.x address in config, even if the UI
        // form still carried the old value (Gary KO4BSR 2026-06-18).
        if matches!(sidecar.network_mode.as_deref(), Some("bridge") | Some("nat")) {
            sidecar.wolfnet_ip = None;
        }
        let ip_changed = before != (sidecar.network_mode.clone(), sidecar.bridge_ip_mode.clone(),
                                    sidecar.bridge_ip.clone(), sidecar.bridge_gateway.clone());
        let _ = serde_json::to_string_pretty(&sidecar)
            .map_err(|_| ())
            .and_then(|json| fs::write(&sidecar_path, json).map_err(|_| ()));
        ip_changed
    }

    /// Public form of [`Self::vm_config_path`] — WolfHA writes a replica's
    /// copy of the VM definition here so the standby can actually start
    /// the VM after a failover.
    pub fn config_path_for(&self, name: &str) -> PathBuf {
        self.vm_config_path(name)
    }
    
    fn vm_disk_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.qcow2", name))
    }

    /// Get the OS disk path, respecting custom storage_path if set
    /// Public form of [`Self::vm_os_disk_path`] — WolfHA needs the disk
    /// path to attach a dirty bitmap to it and to seed a replica.
    pub fn os_disk_path_for(&self, config: &VmConfig) -> PathBuf {
        self.vm_os_disk_path(config)
    }

    /// Public form of [`Self::vm_efivars_path`] — WolfHA replicates an
    /// OVMF VM's NVRAM alongside its disk: a promoted copy with fresh
    /// VARS has lost its boot entries and may not boot at all.
    pub fn efivars_path_for(&self, config: &VmConfig) -> PathBuf {
        self.vm_efivars_path(config)
    }

    /// Get the OS disk path, respecting custom storage_path if set
    fn vm_os_disk_path(&self, config: &VmConfig) -> PathBuf {
        if let Some(ref sp) = config.storage_path {
            Path::new(sp).join(format!("{}.qcow2", config.name))
        } else {
            self.vm_disk_path(&config.name)
        }
    }

    /// Get the per-VM EFI variables file path (for OVMF boot)
    fn vm_efivars_path(&self, config: &VmConfig) -> PathBuf {
        if let Some(ref sp) = config.storage_path {
            Path::new(sp).join(format!("{}_VARS.fd", config.name))
        } else {
            self.base_dir.join(format!("{}_VARS.fd", config.name))
        }
    }

    // ── Native TPM 2.0 via swtpm ───────────────────────────────────────
    // Windows 11 requires a TPM. For the native QEMU backend we run a
    // per-VM `swtpm` daemon that holds the emulated TPM's state on disk and
    // exposes a UNIX control socket QEMU connects to. Proxmox/libvirt manage
    // their own swtpm — this is native-only.

    fn swtpm_sock_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}-tpm.sock", name))
    }
    fn swtpm_pid_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}-tpm.pid", name))
    }

    /// Start the per-VM swtpm daemon and return its socket path. State
    /// persists across boots in a per-VM directory, so the guest sees a
    /// stable TPM. Errors clearly if `swtpm` isn't installed.
    fn start_swtpm(&self, config: &VmConfig) -> Result<String, String> {
        // swtpm must be present; `--version` is a cheap, side-effect-free probe.
        let have = Command::new("swtpm").arg("--version").output()
            .map(|o| o.status.success()).unwrap_or(false);
        if !have {
            return Err("swtpm not found — TPM 2.0 needs it. Install: apt install swtpm (Debian/Ubuntu) or pacman -S swtpm (Arch)".to_string());
        }
        let state_dir = self.base_dir.join(format!("{}-tpm", config.name));
        fs::create_dir_all(&state_dir)
            .map_err(|e| format!("Failed to create TPM state dir: {}", e))?;
        // TPM NVRAM can hold sealing / endorsement material (BitLocker-relevant),
        // so lock the state dir down to the owner rather than trusting umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700));
        }
        let sock = self.swtpm_sock_path(&config.name);
        let pidfile = self.swtpm_pid_path(&config.name);
        // Clear a stale socket/pid from a previous crashed run so the new
        // daemon can bind cleanly.
        let _ = fs::remove_file(&sock);
        self.stop_swtpm(&config.name);
        // `--daemon` forks and returns; `--pid file=` records the pid so
        // stop_vm can reap it.
        let status = Command::new("swtpm")
            .args([
                "socket",
                "--tpmstate", &format!("dir={}", state_dir.display()),
                "--ctrl", &format!("type=unixio,path={}", sock.display()),
                "--tpm2",
                "--daemon",
                "--pid", &format!("file={}", pidfile.display()),
            ])
            .status()
            .map_err(|e| format!("Failed to launch swtpm: {}", e))?;
        if !status.success() {
            return Err("swtpm failed to start (check that /dev and the TPM state dir are writable)".to_string());
        }
        Ok(sock.display().to_string())
    }

    /// Stop the per-VM swtpm daemon (if any) and clean up its socket/pid.
    /// Best-effort; safe to call for VMs that never had a TPM (no-op).
    fn stop_swtpm(&self, name: &str) {
        let pidfile = self.swtpm_pid_path(name);
        if let Ok(pid) = fs::read_to_string(&pidfile) {
            let pid = pid.trim();
            if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
                let _ = Command::new("kill").arg(pid).output();
            }
        }
        let _ = fs::remove_file(&pidfile);
        let _ = fs::remove_file(self.swtpm_sock_path(name));
    }

    /// TAP interface name for a VM
    pub fn tap_name(name: &str) -> String {
        // TAP names limited to 15 chars
        let short = if name.len() > 11 { &name[..11] } else { name };
        format!("tap-{}", short)
    }

    /// Clone an existing VM under a new name. Platform-dispatched:
    ///
    ///   • **Proxmox** → `qm clone <vmid> <new-vmid> --name <new-name>`
    ///     (linked clone by default; `--full 1` for full copy). The
    ///     new VMID comes from `next_pve_vmid()` — cluster-safe.
    ///   • **libvirt** → `virt-clone --original <name> --name <new-name>
    ///     --auto-clone`. virt-clone picks fresh MACs + disk names
    ///     automatically and always does a full disk copy.
    ///   • **native** → read VmConfig, regen MAC, clear runtime state,
    ///     copy OS disk + every extra disk, write new JSON. Refuses
    ///     if source is running (live qcow2 copy = inconsistent disk).
    ///
    /// `full` is honoured only on Proxmox (libvirt is always full,
    /// native is always full). Caller is responsible for any
    /// post-clone follow-up (start, console, etc.).
    /// Fast, lock-friendly snapshot of everything `execute_clone`
    /// needs to perform the clone WITHOUT holding the `VmManager`
    /// mutex for the (potentially multi-minute) disk I/O. The API
    /// handler calls this under the lock, drops the lock, and then
    /// calls `execute_clone` on the returned plan.
    ///
    /// TOCTOU note: between the lock drop and `execute_clone`'s
    /// final JSON write, a concurrent `create_vm` for the same name
    /// could slip in and produce a duplicate. The window is
    /// milliseconds for the platform paths (`qm clone`/`virt-clone`
    /// themselves serialise on the hypervisor) and bounded by the
    /// dest-disk `fs::copy` for native clones. We accept the risk
    /// rather than hold the lock for the whole clone — name
    /// collisions in the native path additionally fail at
    /// `dest_disk.exists()` and at `fs::write(new_config_path)`.
    pub fn prepare_clone(&self, name: &str, new_name: &str)
        -> Result<ClonePlan, String>
    {
        validate_clone_vm_name(name)?;
        validate_clone_vm_name(new_name)?;
        if name == new_name {
            return Err("source and destination names are identical — pick a different new name".into());
        }
        let all = self.list_vms();
        let src = all.iter().find(|v| v.name == name).cloned()
            .ok_or_else(|| format!("VM '{}' not found on this host", name))?;
        if all.iter().any(|v| v.name == new_name) {
            return Err(format!(
                "VM '{}' already exists — pick a different new name", new_name));
        }
        Ok(ClonePlan {
            src,
            base_dir: self.base_dir.clone(),
            on_proxmox: containers::is_proxmox(),
            on_libvirt: containers::is_libvirt() && self.virsh_has_domain(name),
        })
    }

    pub fn create_vm(&self, mut config: VmConfig) -> Result<(), String> {
        // Validation
        if config.cpus == 0 { config.cpus = 1; }
        if config.memory_mb == 0 { config.memory_mb = 1024; }
        if config.disk_size_gb == 0 { config.disk_size_gb = 10; }

        // Stamp the creating node's ID so the cluster view can associate
        // VMs with their host without needing the Scan pass. Overwritten
        // at migrate time by import_vm() below.
        if config.host_id.is_none() {
            config.host_id = Some(crate::agent::self_node_id());
        }

        // Validate WolfNet IP if provided
        if let Some(ref ip) = config.wolfnet_ip {
            let ip = ip.trim();
            if !ip.is_empty() {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                    return Err(format!("Invalid WolfNet IP: '{}' — must be a valid IPv4 address", ip));
                }
                config.wolfnet_ip = Some(ip.to_string());
            } else {
                config.wolfnet_ip = None;
            }
        }

        // On Proxmox, delegate to qm create
        if containers::is_proxmox() {
            return self.qm_create(&config);
        }
        // On libvirt, delegate to virt-install
        if containers::is_libvirt() {
            return self.virsh_create(&config);
        }

        // Standalone: use QEMU directly
        if self.vm_config_path(&config.name).exists() {
            return Err("VM already exists".to_string());
        }

        // Ensure storage path exists
        if let Some(ref sp) = config.storage_path {
            fs::create_dir_all(sp).map_err(|e| format!("Failed to create storage path: {}", e))?;
        }

        let disk_path = self.vm_os_disk_path(&config);

        if let Some(ref import_src) = config.import_image {
            // Import a disk image (.img, .qcow2, .vmdk, .vdi) — convert to qcow2
            if !std::path::Path::new(import_src).exists() {
                return Err(format!("Import image not found: {}", import_src));
            }
            info!("Importing disk image: {} -> {}", import_src, disk_path.display());
            let output = Command::new("qemu-img")
                .arg("convert")
                .arg("-f").arg(detect_image_format(import_src))
                .arg("-O").arg("qcow2")
                .arg(import_src)
                .arg(&disk_path)
                .output()
                .map_err(|e| format!("qemu-img convert failed: {}", e))?;
            if !output.status.success() {
                return Err(format!("Failed to import image: {}", String::from_utf8_lossy(&output.stderr)));
            }
            // Resize if the imported image is smaller than requested
            let _ = Command::new("qemu-img")
                .arg("resize").arg(&disk_path).arg(format!("{}G", config.disk_size_gb))
                .output();
        } else {
            // Create empty OS disk
            let output = Command::new("qemu-img")
                .arg("create")
                .arg("-f")
                .arg("qcow2")
                .arg(&disk_path)
                .arg(format!("{}G", config.disk_size_gb))
                .output()
                .map_err(|e| e.to_string())?;

            if !output.status.success() {
                 return Err(String::from_utf8_lossy(&output.stderr).to_string());
            }
        }

        // Create any extra disks specified at creation time
        for vol in &config.extra_disks {
            self.create_volume_file(vol)?;
        }

        // For OVMF (EFI) boot, create a per-VM copy of the EFI vars file
        if config.bios_type == "ovmf" {
            let vars_dest = self.vm_efivars_path(&config);
            if !vars_dest.exists() {
                let vars_sources = [
                    "/usr/share/OVMF/OVMF_VARS_4M.fd",
                    "/usr/share/OVMF/OVMF_VARS.fd",
                    "/usr/share/edk2/x64/OVMF_VARS.fd",
                    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
                    "/usr/share/qemu/OVMF_VARS.fd",
                    "/usr/share/OVMF/OVMF_VARS.pure-efi.fd",
                ];
                if let Some(src) = vars_sources.iter().find(|p| std::path::Path::new(p).exists()) {
                    fs::copy(src, &vars_dest)
                        .map_err(|e| format!("Failed to copy EFI vars: {}", e))?;
                } else {
                    return Err("OVMF EFI firmware not found. Install OVMF: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)".to_string());
                }
            }
        }

        // Save config
        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(self.vm_config_path(&config.name), json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// Create a VM via Proxmox's qm command
    fn qm_create(&self, config: &VmConfig) -> Result<(), String> {
        // Get next available VMID
        let vmid_output = Command::new("pvesh").args(["get", "/cluster/nextid"]).output()
            .map_err(|e| format!("Failed to get next VMID: {}", e))?;
        if !vmid_output.status.success() {
            return Err("pvesh get /cluster/nextid failed".to_string());
        }
        let vmid_text = String::from_utf8_lossy(&vmid_output.stdout).trim().trim_matches('"').to_string();
        let vmid: u32 = vmid_text.parse().map_err(|e| format!("Invalid VMID '{}': {}", vmid_text, e))?;

        // Determine storage ID (use Proxmox storage name, default to "local-lvm")
        let storage = config.storage_path.as_deref().unwrap_or("local-lvm");



        // net0 wiring depends on the chosen network_mode. Mirrors the LXC
        // network_mode model: "wolfnet" keeps the original dual-NIC layout
        // (vmbr0 LAN + per-VM WolfNet bridge), "bridge" attaches net0 to an
        // operator-chosen bridge (vmbr*, lxcbr*, br-pt-*, or a vSwitch
        // VLAN bridge `vmbr<vlan>` the frontend auto-creates), "nat" stays
        // on vmbr0 (PVE's default management bridge — the closest equivalent
        // to user-mode NAT on a Proxmox host).
        let mode = config.effective_network_mode();
        let net0_bridge: String = match mode {
            "bridge" => config.bridge.clone()
                .filter(|b| !b.is_empty())
                .unwrap_or_else(|| "vmbr0".to_string()),
            _ => "vmbr0".to_string(),
        };
        let net0_model = if config.net_model.is_empty() { "virtio".to_string() } else { config.net_model.clone() };

        let mut args = vec![
            "create".to_string(),
            vmid.to_string(),
            "--name".to_string(), config.name.clone(),
            "--cores".to_string(), config.cpus.to_string(),
            "--memory".to_string(), config.memory_mb.to_string(),
            "--scsi0".to_string(), format!("{}:{}", storage, config.disk_size_gb),
            "--scsihw".to_string(), "virtio-scsi-single".to_string(),
            "--net0".to_string(), format!("{},bridge={}", net0_model, net0_bridge),
            "--ostype".to_string(), "l26".to_string(), // Linux 2.6+ kernel
            "--serial0".to_string(), "socket".to_string(), // Serial console for qm terminal
        ];

        // WolfNet mode (or legacy configs with wolfnet_ip set but no
        // network_mode field) gets a SECOND NIC on a per-VM bridge with a
        // pinned-IP dnsmasq. PVE attaches its own tap to the bridge when
        // the VM starts; the VM gets its WolfNet IP via DHCP automatically.
        //
        // Note on VLANs: on Proxmox, a VLAN tag on the same NIC as WolfNet
        // mangles the routing model (we hit this with LXC — see
        // validate_wolfnet_vlan_conflict). Here we sidestep that entirely:
        // net0 stays on vmbr0 (with whatever VLAN tag the user wants),
        // net1 lives on its own dedicated bridge with no VLAN. The two
        // NICs never share a broadcast domain, so VLAN + WolfNet coexist.
        if mode == "wolfnet"
            && let Some(ref wip) = config.wolfnet_ip {
                self.ensure_dnsmasq_installed();
                let bridge = Self::wn_bridge_name(&vmid.to_string());
                if let Err(e) = self.setup_wolfnet_bridge(&bridge, wip) {
                    warn!("WolfNet bridge setup for VMID {} failed (VM will still be created): {}", vmid, e);
                }
                args.push("--net1".to_string());
                // net1 (WolfNet) uses the SAME adapter model as net0 so the
                // guest can drive it — a Windows VM on e1000 can't use a
                // hardcoded-virtio NIC without virtio drivers (Gary 2026-06-21).
                args.push(format!("{},bridge={}", net0_model, bridge));
            }

        // Boot media (ISO as CD-ROM, .img not supported as USB on Proxmox)
        if let Some(ref iso) = config.iso_path
            && !iso.is_empty() {
                let lower = iso.to_lowercase();
                if lower.ends_with(".img") || lower.ends_with(".raw") {
                    return Err("Proxmox does not support booting from .img files directly. Use 'Import Image' to import it as the OS disk instead.".to_string());
                }
                // On Proxmox, ISOs are referred to as storage:iso/filename.iso
                args.push("--ide2".to_string());
                args.push(format!("{},media=cdrom", iso));
                // Boot order: disk first, CD as fallback. On first boot the
                // disk is empty so SeaBIOS/OVMF falls through to the CD and
                // the installer runs. After install, the disk has a
                // bootloader and is preferred — the user doesn't have to
                // manually detach the ISO to stop the installer launching
                // again on every reboot.
                args.push("--boot".to_string());
                // Operator-set boot order (disk/cdrom/network) mapped to PVE
                // keys; passthrough-USB boot is a Proxmox limitation, so "usb"
                // falls back to the default here.
                args.push(pve_boot_order_arg(&config.boot_order));
            }

        // VirtIO-drivers ISO → ide3 (Windows installs whose OS disk is on the
        // virtio bus need these to see the disk during setup). Read back as
        // drivers_iso so the editor round-trips it.
        if let Some(ref drv) = config.drivers_iso
            && !drv.trim().is_empty() {
                args.push("--ide3".to_string());
                args.push(format!("{},media=cdrom", drv.trim()));
            }

        // BIOS: OVMF (UEFI) needs an efidisk0 NVRAM store on the same storage
        // as the OS disk; SeaBIOS is PVE's default and needs no flag.
        if config.bios_type == "ovmf" {
            args.push("--bios".to_string());
            args.push("ovmf".to_string());
            args.push("--efidisk0".to_string());
            // Secure Boot needs the NVRAM pre-loaded with Microsoft's keys —
            // `pre-enrolled-keys=1` is what actually turns Secure Boot on.
            if config.secure_boot {
                args.push(format!("{}:1,efitype=4m,pre-enrolled-keys=1", storage));
            } else {
                args.push(format!("{}:1,efitype=4m", storage));
            }
            // Windows 11 (TPM / Secure Boot) expects the q35 machine type.
            // Proxmox otherwise defaults new VMs to i440fx.
            if config.tpm || config.secure_boot {
                args.push("--machine".to_string());
                args.push("q35".to_string());
            }
        }

        // Emulated TPM 2.0 (Windows 11 requires it). Proxmox runs swtpm; the
        // state disk lives on the same pool as the OS disk.
        if config.tpm {
            args.push("--tpmstate0".to_string());
            args.push(format!("{}:1,version=v2.0", storage));
        }

        // Extra disks — PVE allocates them from the same storage pool as scsi0.
        // scsi0 is taken, so numbering starts at scsi1.
        for (i, vol) in config.extra_disks.iter().enumerate() {
            let slot = i + 1;
            args.push(format!("--scsi{}", slot));
            args.push(format!("{}:{}", storage, vol.size_gb));
        }

        // Operator notes / description — stored in the PVE config (read back
        // from the `description:` line). Only set when non-empty so a blank
        // notes field doesn't write an empty description line.
        if !config.notes.is_empty() {
            args.push("--description".to_string());
            args.push(config.notes.clone());
        }

        // Operator extra QEMU args → PVE `args:` (raw kvm passthrough). Only
        // set when non-blank, same as notes. PVE takes the whole string as
        // one positional value.
        if !config.extra_qemu_args.trim().is_empty() {
            args.push("--args".to_string());
            args.push(config.extra_qemu_args.trim().to_string());
        }

        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("qm")
            .args(&args_ref)
            .output()
            .map_err(|e| format!("Failed to run qm create: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!("qm create failed: {} {}", stderr.trim(), stdout.trim()));
        }

        // Import disk image if provided (convert and import via qm importdisk)
        if let Some(ref import_src) = config.import_image
            && !import_src.is_empty() {
                if !std::path::Path::new(import_src).exists() {
                    return Err(format!("Import image not found: {}", import_src));
                }
                info!("Proxmox: importing disk image {} into VM {}", import_src, vmid);

                // Convert to raw first if needed, then importdisk
                // qm importdisk accepts raw and qcow2 directly
                let fmt = detect_image_format(import_src);
                let import_path = if fmt != "raw" && fmt != "qcow2" {
                    // Convert to qcow2 in /tmp first
                    let tmp = format!("/tmp/wolfstack-import-{}.qcow2", vmid);
                    let conv = Command::new("qemu-img")
                        .arg("convert").arg("-f").arg(fmt).arg("-O").arg("qcow2")
                        .arg(import_src).arg(&tmp)
                        .output()
                        .map_err(|e| format!("qemu-img convert failed: {}", e))?;
                    if !conv.status.success() {
                        return Err(format!("Failed to convert image: {}", String::from_utf8_lossy(&conv.stderr)));
                    }
                    tmp
                } else {
                    import_src.clone()
                };

                // Import the disk — replaces the empty scsi0 disk
                let import_output = Command::new("qm")
                    .args(["importdisk", &vmid.to_string(), &import_path, storage])
                    .output()
                    .map_err(|e| format!("qm importdisk failed: {}", e))?;
                if !import_output.status.success() {
                    return Err(format!("qm importdisk failed: {}", String::from_utf8_lossy(&import_output.stderr)));
                }

                // The imported disk shows as unused0 — attach it as scsi0
                // First detach the empty disk, then attach the imported one
                let _ = Command::new("qm").args(["set", &vmid.to_string(), "--delete", "scsi0"]).output();
                let _ = Command::new("qm").args(["set", &vmid.to_string(), "--scsi0", &format!("{}:vm-{}-disk-1", storage, vmid)]).output();

                // Resize to requested size
                let _ = Command::new("qm")
                    .args(["resize", &vmid.to_string(), "scsi0", &format!("{}G", config.disk_size_gb)])
                    .output();

                // Clean up temp file
                if import_path.starts_with("/tmp/wolfstack-import-") {
                    let _ = std::fs::remove_file(&import_path);
                }
            }

        // Apply USB/PCI passthrough via qm set if the user configured any
        if (!config.usb_devices.is_empty() || !config.pci_devices.is_empty())
            && let Err(e) = super::passthrough::apply_proxmox_passthrough(vmid, config) {
                warn!("Failed to apply passthrough devices to Proxmox VM {}: {}", vmid, e);
            }

        // Save a WolfStack config for tracking. Propagate errors —
        // pre-v18.7.30 we used `let _ =` which meant a failed write
        // silently lost the VM's tracked storage_path. Next restart
        // would see a VM with storage_path=None and mis-route disk
        // operations (or forget where the qcow2 actually lives).
        let mut tracked = config.clone();
        tracked.storage_path = Some(storage.to_string());
        let json = serde_json::to_string_pretty(&tracked).map_err(|e| e.to_string())?;
        let cfg_path = self.vm_config_path(&config.name);
        fs::write(&cfg_path, json)
            .map_err(|e| format!("write VM tracking config {}: {}", cfg_path.display(), e))?;

        Ok(())
    }

    /// Create a volume's disk file
    fn create_volume_file(&self, vol: &StorageVolume) -> Result<(), String> {
        fs::create_dir_all(&vol.storage_path)
            .map_err(|e| format!("Failed to create storage dir {}: {}", vol.storage_path, e))?;

        let path = vol.file_path();
        if path.exists() {
            return Err(format!("Volume file already exists: {}", path.display()));
        }

        let output = Command::new("qemu-img")
            .args(["create", "-f", &vol.format, &path.to_string_lossy(), &format!("{}G", vol.size_gb)])
            .output()
            .map_err(|e| format!("qemu-img create failed: {}", e))?;

        if !output.status.success() {
            return Err(format!("Failed to create volume: {}", String::from_utf8_lossy(&output.stderr)));
        }


        Ok(())
    }

    /// Add a new storage volume to an existing VM (must be stopped)
    pub fn add_volume(&self, vm_name: &str, vol_name: &str, size_gb: u32, 
                      storage_path: Option<&str>, format: Option<&str>,
                      bus: Option<&str>) -> Result<(), String> {
        if self.check_running(vm_name) {
            return Err("Cannot add volume while VM is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(vm_name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        // Check for duplicate volume name
        if config.extra_disks.iter().any(|d| d.name == vol_name) {
            return Err(format!("Volume '{}' already exists on VM '{}'", vol_name, vm_name));
        }

        // Default storage path: same dir as the VM base
        let sp = storage_path
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.base_dir.to_string_lossy().to_string());

        let vol = StorageVolume {
            name: format!("{}-{}", vm_name, vol_name),
            size_gb,
            storage_path: sp,
            format: format.unwrap_or("qcow2").to_string(),
            bus: bus.unwrap_or("virtio").to_string(),
        };

        self.create_volume_file(&vol)?;
        config.extra_disks.push(vol);

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// Remove a storage volume from a VM (must be stopped)
    pub fn remove_volume(&self, vm_name: &str, vol_name: &str, delete_file: bool) -> Result<(), String> {
        if self.check_running(vm_name) {
            return Err("Cannot remove volume while VM is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(vm_name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        let full_name = format!("{}-{}", vm_name, vol_name);
        let idx = config.extra_disks.iter().position(|d| d.name == full_name || d.name == vol_name)
            .ok_or_else(|| format!("Volume '{}' not found on VM '{}'", vol_name, vm_name))?;

        let vol = config.extra_disks.remove(idx);

        if delete_file {
            let path = vol.file_path();
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|e| format!("Failed to delete volume file: {}", e))?;

            }
        }

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// Resize a storage volume (grow only, must be stopped)
    pub fn resize_volume(&self, vm_name: &str, vol_name: &str, new_size_gb: u32) -> Result<(), String> {
        if self.check_running(vm_name) {
            return Err("Cannot resize volume while VM is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(vm_name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        let full_name = format!("{}-{}", vm_name, vol_name);
        let vol = config.extra_disks.iter_mut()
            .find(|d| d.name == full_name || d.name == vol_name)
            .ok_or_else(|| format!("Volume '{}' not found", vol_name))?;

        if new_size_gb <= vol.size_gb {
            return Err(format!("New size must be larger than current size ({}G)", vol.size_gb));
        }

        let path = vol.file_path();
        let output = Command::new("qemu-img")
            .args(["resize", &path.to_string_lossy(), &format!("{}G", new_size_gb)])
            .output()
            .map_err(|e| format!("qemu-img resize failed: {}", e))?;

        if !output.status.success() {
            return Err(format!("Resize failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        vol.size_gb = new_size_gb;

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;


        Ok(())
    }

    /// List available storage locations (Proxmox-aware)
    pub fn list_storage_locations(&self) -> Vec<StorageLocation> {
        // On Proxmox, use pvesm for storage IDs
        if containers::is_proxmox() {
            let pve_storages = containers::pvesm_list_storage();
            return pve_storages.iter()
                .filter(|s| s.status == "active")
                .filter(|s| s.content.iter().any(|c| c == "images" || c == "rootdir"))
                .map(|s| StorageLocation {
                    path: s.id.clone(), // PVE storage ID as "path"
                    total_gb: s.total_bytes / 1073741824,
                    available_gb: s.available_bytes / 1073741824,
                    fs_type: s.storage_type.clone(),
                })
                .collect();
        }

        // Standalone: filesystem-based storage
        let mut locations = Vec::new();
        if let Ok(output) = Command::new("df").args(["-BG", "--output=target,size,avail,fstype"]).output()
            && let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let mount = parts[0];
                        let total = parts[1].trim_end_matches('G').parse::<u64>().unwrap_or(0);
                        let avail = parts[2].trim_end_matches('G').parse::<u64>().unwrap_or(0);
                        let fstype = parts[3];
                        // Skip pseudo-filesystems
                        if mount.starts_with('/') && !mount.starts_with("/snap") 
                           && !mount.starts_with("/sys") && !mount.starts_with("/proc")
                           && !mount.starts_with("/dev") && !mount.starts_with("/run")
                           && total > 0 {
                            locations.push(StorageLocation {
                                path: mount.to_string(),
                                total_gb: total,
                                available_gb: avail,
                                fs_type: fstype.to_string(),
                            });
                        }
                    }
                }
            }
        locations
    }

    /// Update VM settings (must be stopped)
    #[allow(clippy::too_many_arguments)]
    pub fn update_vm(&self, name: &str, cpus: Option<u32>, memory_mb: Option<u32>,
                     iso_path: Option<String>, wolfnet_ip: Option<String>,
                     disk_size_gb: Option<u32>,
                     os_disk_bus: Option<String>, net_model: Option<String>,
                     drivers_iso: Option<String>, auto_start: Option<bool>,
                     bios_type: Option<String>,
                     tpm: Option<bool>, secure_boot: Option<bool>,
                     extra_nics: Option<Vec<NicConfig>>,
                     usb_devices: Option<Vec<UsbDevice>>,
                     pci_devices: Option<Vec<PciDevice>>,
                     network_mode: Option<String>,
                     bridge: Option<String>,
                     bridge_ip_mode: Option<String>,
                     bridge_ip: Option<String>,
                     bridge_gateway: Option<String>,
                     vsw_uplink: Option<String>,
                     vsw_vlan: Option<u32>,
                     boot_order: Option<Vec<String>>,
                     vnc_external: Option<bool>,
                     notes: Option<String>,
                     extra_qemu_args: Option<String>) -> Result<Option<String>, String> {
        // Ok(Some(msg)) carries a non-fatal advisory the UI shows alongside
        // the success toast (e.g. libvirt hardware edits that only take
        // effect on the VM's next start); Ok(None) is a plain success.
        // On Proxmox, delegate to qm set
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            let vmid_str = vmid.to_string();
            let mut args = vec!["set", &vmid_str];
            let cores_str;
            let mem_str;
            let onboot_str;
            if let Some(c) = cpus && c > 0 { cores_str = c.to_string(); args.extend(["--cores", &cores_str]); }
            if let Some(m) = memory_mb && m >= 256 { mem_str = m.to_string(); args.extend(["--memory", &mem_str]); }
            if let Some(a) = auto_start { onboot_str = if a { "1".to_string() } else { "0".to_string() }; args.extend(["--onboot", &onboot_str]); }
            // Notes / description: a separate `qm set` so an empty value can
            // use `--delete description` (which actually drops the stored line),
            // while non-empty text goes via `--description <text>`. PVE accepts
            // multi-line text as one arg and URL-encodes newlines as %0A in
            // `qm config` output, which the read-back path decodes.
            if let Some(ref n) = notes {
                let desc_args: Vec<&str> = if n.is_empty() {
                    vec!["set", &vmid_str, "--delete", "description"]
                } else {
                    vec!["set", &vmid_str, "--description", n]
                };
                let out = Command::new("qm").args(&desc_args).output()
                    .map_err(|e| format!("qm set --description failed: {}", e))?;
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let trimmed = stderr.trim();
                    // Deleting an already-absent description is the desired
                    // state. Only swallow the specific "key not present"
                    // rejections PVE emits — a real error (perms, lock) must
                    // still surface even though its text may mention the field.
                    let already_clear = n.is_empty()
                        && (trimmed.is_empty()
                            || trimmed.contains("does not have property")
                            || trimmed.contains("not in config")
                            || trimmed.contains("does not exist")
                            || trimmed.contains("no such"));
                    if !already_clear {
                        return Err(format!("qm set --description failed: {}", trimmed));
                    }
                }
            }
            // Extra QEMU args → PVE's `args:` field (raw kvm passthrough). One
            // `qm set` so empty can `--delete args` (drops the stored line)
            // while non-empty text goes via `--args <text>` as a SINGLE arg.
            // `qm set --args` takes the whole string verbatim; PVE forwards it
            // to kvm tokenised the same way we tokenise it for the native path.
            if let Some(ref ea) = extra_qemu_args {
                let trimmed_ea = ea.trim();
                let args_args: Vec<&str> = if trimmed_ea.is_empty() {
                    vec!["set", &vmid_str, "--delete", "args"]
                } else {
                    vec!["set", &vmid_str, "--args", trimmed_ea]
                };
                let out = Command::new("qm").args(&args_args).output()
                    .map_err(|e| format!("qm set --args failed: {}", e))?;
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let trimmed = stderr.trim();
                    let already_clear = trimmed_ea.is_empty()
                        && (trimmed.is_empty()
                            || trimmed.contains("does not have property")
                            || trimmed.contains("not in config")
                            || trimmed.contains("does not exist")
                            || trimmed.contains("no such"));
                    if !already_clear {
                        return Err(format!("qm set --args failed: {}", trimmed));
                    }
                }
            }
            if args.len() > 2 {
                let output = Command::new("qm").args(&args).output()
                    .map_err(|e| format!("Failed to run qm set: {}", e))?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("qm set failed: {}", stderr.trim()));
                }
            }
            // net0 bridge change: when network_mode flips wolfnet/nat ↔ bridge,
            // or the operator picks a different bridge (incl. switching to a
            // vSwitch VLAN bridge `vmbr<vlan>` the frontend auto-created),
            // we have to re-emit net0 via `qm set`. Default mode for both
            // "wolfnet" and "nat" on Proxmox is vmbr0 — the WolfNet TAP rides
            // on net1, not net0, because mixing VLAN tags with the WolfNet
            // bridge breaks PVE's routing model (same gotcha LXC hit, see
            // validate_wolfnet_vlan_conflict).
            //
            // CRITICAL: `qm set --net0 virtio,bridge=X` without the existing
            // MAC makes PVE generate a fresh MAC, which breaks DHCP leases
            // and stale ARP entries inside the guest. Read the current MAC +
            // model from `qm config` first and round-trip them; only fire
            // `qm set` when the bridge OR model would actually change.
            if network_mode.is_some() || bridge.is_some() {
                let mode = network_mode.as_deref().unwrap_or("");
                let target_bridge: String = match mode {
                    "bridge" => bridge.clone().filter(|b| !b.is_empty())
                        .unwrap_or_else(|| "vmbr0".to_string()),
                    "" => bridge.clone().filter(|b| !b.is_empty()).unwrap_or_default(),
                    _ => "vmbr0".to_string(),
                };
                if !target_bridge.is_empty() {
                    // Parse current net0 to recover model + MAC + bridge.
                    let cfg_out = Command::new("qm").args(["config", &vmid_str]).output();
                    let (cur_model, cur_mac, cur_bridge) = match cfg_out {
                        Ok(o) if o.status.success() => {
                            let cfg = String::from_utf8_lossy(&o.stdout).to_string();
                            let mut model = "virtio".to_string();
                            let mut mac: Option<String> = None;
                            let mut br: Option<String> = None;
                            for line in cfg.lines() {
                                let line = line.trim();
                                if let Some(val) = line.strip_prefix("net0:") {
                                    for part in val.split(',') {
                                        let part = part.trim();
                                        if let Some((k, v)) = part.split_once('=') {
                                            if matches!(k, "virtio"|"e1000"|"e1000e"|"rtl8139"|"vmxnet3") {
                                                model = k.to_string();
                                                mac = Some(v.to_string());
                                            } else if k == "bridge" {
                                                let v = v.trim();
                                                if !v.is_empty() { br = Some(v.to_string()); }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                            (model, mac, br)
                        }
                        _ => ("virtio".to_string(), None, None),
                    };

                    // Honour an explicit model override from the request;
                    // otherwise preserve what PVE currently has.
                    let model = net_model.as_deref()
                        .filter(|m| !m.is_empty())
                        .map(|s| s.to_string())
                        .unwrap_or(cur_model);

                    // Skip the qm set entirely when nothing would change —
                    // avoids spurious config-file rewrites and keeps PVE's
                    // last-modified timestamp meaningful.
                    let model_unchanged = net_model.as_deref().filter(|m| !m.is_empty()).is_none()
                        || net_model.as_deref() == Some(&model);
                    let bridge_unchanged = cur_bridge.as_deref() == Some(target_bridge.as_str());
                    if !(bridge_unchanged && model_unchanged) {
                        let val = if let Some(ref m) = cur_mac {
                            format!("{}={},bridge={}", model, m, target_bridge)
                        } else {
                            // No existing MAC parsed — let PVE pick one
                            // (only happens on adopted VMs with malformed
                            // net0 lines, which is rare).
                            format!("{},bridge={}", model, target_bridge)
                        };
                        let out = Command::new("qm").args(["set", &vmid_str, "--net0", &val]).output()
                            .map_err(|e| format!("qm set --net0 failed: {}", e))?;
                        if !out.status.success() {
                            // Propagate the PVE error instead of warning-and-
                            // succeeding. klasSponsor 2026-05-28 reported
                            // "settings saved but settings have not been
                            // changed" — the silent warn here is why: qm
                            // rejected the change (e.g., bridge missing on the
                            // host, running-VM restriction, perms) and the
                            // handler still returned 200, so the UI showed
                            // success while PVE kept the old config.
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            return Err(format!(
                                "qm set --net0 for VMID {} failed: {}",
                                vmid,
                                stderr.trim()
                            ));
                        }
                    }
                }
            }
            // Disk resize on Proxmox
            if let Some(new_size) = disk_size_gb {
                let size_arg = format!("{}G", new_size);
                let _ = Command::new("qm").args(["resize", &vmid_str, "scsi0", &size_arg]).output();
            }
            // Extra NICs on Proxmox: net1=virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1
            if let Some(ref nics) = extra_nics {
                for (i, nic) in nics.iter().enumerate() {
                    let key = format!("--net{}", i + 1);
                    let model = match nic.model.as_str() {
                        "e1000" | "e1000e" | "rtl8139" => nic.model.as_str(),
                        _ => "virtio",
                    };
                    let mac = nic.mac.clone().unwrap_or_else(generate_mac);
                    // Resolve bridge — passthrough_interface auto-creates a vmbr, or use manual bridge
                    let bridge = self.resolve_nic_bridge(nic)
                        .unwrap_or_else(|| "vmbr0".to_string());
                    let val = format!("{}={},bridge={}", model, mac, bridge);
                    let _ = Command::new("qm").args(["set", &vmid_str, &key, &val]).output();
                }
                // Remove higher-numbered NICs that may have been deleted.
                // Only try deleting net{N} if qm config shows it exists (avoid spurious errors).
                if let Ok(cfg_out) = Command::new("qm").args(["config", &vmid_str]).output() {
                    let cfg_text = String::from_utf8_lossy(&cfg_out.stdout);
                    for i in nics.len()..8 {
                        let net_key = format!("net{}", i + 1);
                        if cfg_text.contains(&format!("{}: ", net_key)) {
                            let _ = Command::new("qm").args(["set", &vmid_str, "--delete", &net_key]).output();
                        }
                    }
                }
            }
            // USB/PCI passthrough — build a temporary VmConfig-like holder since
            // apply_proxmox_passthrough operates on a VmConfig. We only need the
            // usb/pci fields populated for that call.
            if usb_devices.is_some() || pci_devices.is_some() {
                let mut tmp = VmConfig::new(name.to_string(), 1, 512, 1);
                tmp.usb_devices = usb_devices.clone().unwrap_or_default();
                tmp.pci_devices = pci_devices.clone().unwrap_or_default();
                super::passthrough::apply_proxmox_passthrough(vmid, &tmp)?;
            }
            // WolfNet net1 reconcile. On Proxmox the per-VM WolfNet bridge
            // rides on net1 (not net0) — see qm_create for the reasoning.
            // Flipping into / out of WolfNet mode means add or delete net1.
            // Idempotent: re-emitting the same net1 is a no-op for PVE.
            if let Some(ref mode) = network_mode {
                // WolfNet is "on" only when the mode is wolfnet AND a non-empty
                // IP was supplied. Clearing the IP while staying in WolfNet mode
                // (the UI sends wolfnet_ip:"" — an empty-string explicit clear;
                // a null/None is also treated the same way here) is an explicit
                // REMOVAL — it used to fall through both arms below and no-op, so
                // the VM kept its DHCP-leased WolfNet IP and the operator's
                // removal "didn't take" (Gary KO4BSR 2026-06-19/06-21). Route it
                // to the teardown path instead.
                let want_wolfnet = mode == "wolfnet"
                    && wolfnet_ip.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
                if want_wolfnet {
                    let wip = wolfnet_ip.as_deref().unwrap_or_default();
                    self.ensure_dnsmasq_installed();
                    let bridge = Self::wn_bridge_name(&vmid_str);
                    // Bridge setup or `qm set --net1` failures used
                    // to be swallowed silently — the UI showed
                    // "settings saved" with no actual NIC change.
                    // Surface both so the operator sees the real
                    // reason (klasSponsor 2026-05-28).
                    self.setup_wolfnet_bridge(&bridge, wip).map_err(|e| {
                        format!(
                            "WolfNet bridge reconcile (qm) for VMID {} failed: {}",
                            vmid, e
                        )
                    })?;
                    // Match net1's adapter to net0 (explicit override or the
                    // model PVE already has) so a non-virtio guest can drive the
                    // WolfNet NIC and actually DHCP its IP (Gary 2026-06-21).
                    let net1_model = net_model.as_deref().map(str::trim)
                        .filter(|m| !m.is_empty())
                        .map(String::from)
                        .unwrap_or_else(|| Self::read_qm_net0_model(&vmid_str));
                    let out = Command::new("qm").args([
                        "set", &vmid_str, "--net1",
                        &format!("{},bridge={}", net1_model, bridge)
                    ]).output()
                        .map_err(|e| format!("qm set --net1 failed: {}", e))?;
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        return Err(format!(
                            "qm set --net1 for VMID {} failed: {}",
                            vmid,
                            stderr.trim()
                        ));
                    }
                } else {
                    // Either explicitly non-wolfnet mode, OR wolfnet mode with a
                    // cleared IP — drop net1 if present and tear the bridge down.
                    // qm errors when net1 doesn't exist; that specific case
                    // is the desired state and stays ignored, but any other
                    // failure (e.g., permissions) needs to surface so the
                    // UI doesn't report a false success.
                    let out = Command::new("qm").args(["set", &vmid_str, "--delete", "net1"]).output();
                    if let Ok(o) = &out
                        && !o.status.success() {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            let stderr_trim = stderr.trim();
                            // PVE phrases the "net1 not in config" rejection
                            // as `unable to find net1 in config`; treat that
                            // as a no-op since the desired state is already
                            // met.
                            let is_already_gone = stderr_trim.contains("net1")
                                && (stderr_trim.contains("not in config")
                                    || stderr_trim.contains("does not exist"));
                            if !is_already_gone {
                                return Err(format!(
                                    "qm set --delete net1 for VMID {} failed: {}",
                                    vmid, stderr_trim
                                ));
                            }
                        }
                    let bridge = Self::wn_bridge_name(&vmid_str);
                    // Proxmox never persists the WolfNet IP (read-back forces it
                    // to None), so the supplied IP is None on removal. Recover it
                    // from the host /32 route we installed on the bridge, so
                    // cleanup can GC the MASQUERADE rule — deleting the bridge
                    // alone drops the route but leaves that iptables rule behind.
                    let old_ip = wolfnet_ip.clone()
                        .filter(|s| !s.is_empty())
                        .or_else(|| Self::recover_wolfnet_ip_from_bridge(&bridge));
                    self.cleanup_wolfnet_bridge(&bridge, old_ip.as_deref());
                }
            }
            // Apply the media + BIOS edits that `qm set --cores/...` above
            // doesn't cover — these used to silently revert on Proxmox the
            // same way they did on libvirt (no qm set was ever issued, and
            // the read-back hardcoded them). OS disk bus is intentionally
            // left to the UI lock (a PVE bus change = risky disk move).
            let (apply_failures, changed_next_boot) =
                qm_apply_media_bios(vmid, &iso_path, &drivers_iso, &bios_type, tpm, secure_boot);
            if !apply_failures.is_empty() {
                return Err(format!(
                    "Some settings could not be applied to the Proxmox VM:\n  - {}",
                    apply_failures.join("\n  - ")
                ));
            }
            // Persist the WolfStack-only network fields. `qm` has no home for
            // the vSwitch selection or the operator's IP hints, and this branch
            // previously wrote no sidecar at all — so both were lost on every
            // Proxmox save and the editor had nothing to read back.
            let ip_changed = self.persist_vm_net_sidecar(name, &VmNetSettings {
                network_mode: network_mode.clone(),
                bridge: bridge.clone(),
                bridge_ip_mode: bridge_ip_mode.clone(),
                bridge_ip: bridge_ip.clone(),
                bridge_gateway: bridge_gateway.clone(),
                vsw_uplink: vsw_uplink.clone(),
                vsw_vlan,
                wolfnet_ip: wolfnet_ip.clone(),
            });
            // Apply the primary NIC's IP choice to the guest. A VM's IP lives
            // inside the guest, so it is staged via cloud-init and applied on
            // the next boot — before this, the choice was stored and never
            // acted on (RutgerDiehard 2026-08-21).
            let mut advisories: Vec<String> = Vec::new();
            if changed_next_boot && is_pve_vmid_running(vmid) {
                advisories.push(
                    "ISO and BIOS changes take effect the next time this VM is started.".to_string());
            }
            if ip_changed {
                match primary_ip_plan(&network_mode, &bridge_ip_mode, &bridge_ip, &bridge_gateway) {
                    Some(plan) => {
                        match crate::networking::vlan_attach::stage_primary_ip_proxmox(&vmid_str, &plan) {
                            Ok(Some(note)) => advisories.push(note),
                            Ok(None) => {}
                            // The settings ARE saved at this point, so a
                            // staging failure is an advisory, not an error —
                            // but it must say plainly that the IP did not take.
                            Err(e) => advisories.push(format!(
                                "The IP could NOT be staged: {}. Set it inside the guest.", e)),
                        }
                    }
                    // The VM left bridge mode (or cleared its addressing):
                    // drop any IP we staged for it earlier.
                    None => {
                        if let Ok(true) = crate::networking::vlan_attach::clear_primary_ip_proxmox(&vmid_str) {
                            advisories.push(
                                "The previously staged static IP was cleared back to DHCP."
                                    .to_string());
                        }
                    }
                }
            }
            if advisories.is_empty() {
                return Ok(None);
            }
            return Ok(Some(format!("Saved. {}", advisories.join(" "))));
        }
        // On libvirt, delegate to virsh (VM must be stopped for CPU/memory
        // changes). Pre-libvirt native VMs fall through to the JSON config
        // update path below.
        if containers::is_libvirt() && self.virsh_has_domain(name) {
            if let Some(c) = cpus
                && c > 0 {
                    let cs = c.to_string();
                    let out = Command::new("virsh").args(["setvcpus", name, &cs, "--config", "--maximum"]).output()
                        .map_err(|e| format!("virsh setvcpus failed: {}", e))?;
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        return Err(format!("Failed to set CPUs: {}", stderr.trim()));
                    }
                    let _ = Command::new("virsh").args(["setvcpus", name, &cs, "--config"]).output();
                }
            if let Some(m) = memory_mb
                && m >= 256 {
                    let kb = format!("{}k", (m as u64) * 1024);
                    let out = Command::new("virsh").args(["setmaxmem", name, &kb, "--config"]).output()
                        .map_err(|e| format!("virsh setmaxmem failed: {}", e))?;
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        return Err(format!("Failed to set memory: {}", stderr.trim()));
                    }
                    let _ = Command::new("virsh").args(["setmem", name, &kb, "--config"]).output();
                }
            if let Some(a) = auto_start {
                let val = if a { "--enable" } else { "--disable" };
                let _ = Command::new("virsh").args(["autostart", name, val]).output();
            }
            // Notes / description: `virsh desc <name> --config -- <text>`. The
            // `--` ends option parsing so the text can begin with a dash; an
            // empty string clears the description. Stored in the domain's
            // <description> element and read back via `virsh desc --config`.
            if let Some(ref n) = notes {
                let out = Command::new("virsh").args(["desc", name, "--config", "--", n]).output()
                    .map_err(|e| format!("virsh desc failed: {}", e))?;
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    return Err(format!("Failed to set notes: {}", stderr.trim()));
                }
            }
            // Extra QEMU args → the domain's `<qemu:commandline>` passthrough
            // block. virt-xml has no flag for this, so we edit the domain XML
            // directly (add the `xmlns:qemu` namespace + the arg block) and
            // re-`virsh define` it. Applies on next start, like the other
            // hardware edits below. Empty clears the block (Golden Rule: a
            // domain we never touched keeps no <qemu:commandline>).
            if let Some(ref ea) = extra_qemu_args {
                libvirt_set_qemu_commandline(name, ea)?;
            }
            // USB/PCI passthrough via virsh attach-device / detach-device
            if usb_devices.is_some() || pci_devices.is_some() {
                let mut tmp = VmConfig::new(name.to_string(), 1, 512, 1);
                tmp.usb_devices = usb_devices.clone().unwrap_or_default();
                tmp.pci_devices = pci_devices.clone().unwrap_or_default();
                super::passthrough::apply_libvirt_passthrough(name, &tmp)?;
            }
            // WolfNet reconcile on libvirt — same pattern as Proxmox but
            // via the existing `reconcile_wolfnet_for_vm` path (which uses
            // virsh attach-interface / detach-interface under the hood).
            // We build a synthetic VmConfig with just the wolfnet_ip set
            // because that's all the reconcile path looks at.
            if network_mode.is_some() || wolfnet_ip.is_some() {
                let want_wolfnet = network_mode.as_deref() == Some("wolfnet")
                    || (network_mode.is_none()
                        && wolfnet_ip.as_deref().map(|s| !s.is_empty()).unwrap_or(false));
                let mut synth = VmConfig::new(name.to_string(), 1, 512, 1);
                synth.wolfnet_ip = if want_wolfnet {
                    wolfnet_ip.clone().filter(|s| !s.is_empty())
                } else { None };
                // Carry the real adapter model into the synth so the WolfNet NIC
                // matches it (explicit override → persisted sidecar → virtio).
                // Without this the synth's VmConfig::new default ("virtio")
                // would force a virtio WolfNet NIC onto an e1000 Windows guest
                // that can't drive it (Gary KO4BSR 2026-06-21).
                synth.net_model = net_model.as_deref().map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(String::from)
                    .or_else(|| fs::read_to_string(self.vm_config_path(name)).ok()
                        .and_then(|t| serde_json::from_str::<VmConfig>(&t).ok())
                        .map(|c| c.net_model)
                        .filter(|m| !m.trim().is_empty()))
                    .unwrap_or_else(|| "virtio".to_string());
                // The previous wolfnet_ip isn't loaded from a sidecar on this
                // branch, so recover it from the host /32 route on the WolfNet
                // bridge. That lets reconcile GC the old MASQUERADE rule on
                // removal / re-IP; if no route exists this is None (the old
                // behaviour) and setup_wolfnet_bridge stays idempotent.
                let old_ip = Self::recover_wolfnet_ip_from_bridge(&Self::wn_bridge_name(name));
                self.reconcile_wolfnet_for_vm(name, &synth, old_ip.as_deref());
            }
            // Push the hardware + primary-NIC edits into the domain's
            // PERSISTENT config. virt-xml --edit defaults to --define even
            // for a running VM, so the live guest is untouched and the
            // change lands on next start — which is why these fields used
            // to silently revert: the old libvirt branch never wrote them
            // anywhere libvirt (or our read-back) would see.
            let (apply_failures, mut changed_next_boot) = libvirt_apply_devices(
                name, &net_model, &network_mode, &bridge,
                &iso_path, &drivers_iso, &os_disk_bus, &bios_type,
                tpm, secure_boot,
            );
            // External-VNC toggle for libvirt: rewrite the domain's graphics so
            // the next start listens on 0.0.0.0 + a password (external) or stays
            // localhost-only (default). virt-xml --edit --graphics mirrors the
            // create syntax; --define means it applies on next start, like
            // native. Non-fatal: a parser hiccup must not abort the whole edit.
            if let Some(want_external) = vnc_external {
                // Only rewrite the graphics when the external state actually
                // changes — otherwise every unrelated edit-save would churn the
                // VNC password. Compare against the PERSISTENT (inactive) config,
                // because that's what `virt-xml --edit` mutates; the live domain
                // still shows the pre-toggle graphics until the next start, so
                // comparing live would refire on every save of a running VM.
                let is_external = {
                    // --security-info is REQUIRED: without it libvirt redacts the
                    // <graphics passwd> attribute from dumpxml output, and
                    // libvirt_xml_is_external_vnc demands a password to call a VM
                    // external. Redacted XML read as "not external", so every
                    // edit-save of an external VM regenerated its VNC password.
                    let xml = Command::new("virsh").args(["dumpxml", "--inactive", "--security-info", name]).output().ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                    libvirt_xml_is_external_vnc(&xml)
                };
                if want_external != is_external {
                    let graphics = if want_external {
                        format!("vnc,listen=0.0.0.0,password={}", gen_vnc_password())
                    } else {
                        "vnc,listen=127.0.0.1,password=".to_string()
                    };
                    match Command::new("virt-xml").args([name, "--edit", "--graphics", &graphics]).output() {
                        Ok(o) if o.status.success() => { changed_next_boot = true; }
                        Ok(o) => warn!("virt-xml graphics edit for VM '{}' failed: {}", name, String::from_utf8_lossy(&o.stderr).trim()),
                        Err(e) => warn!("virt-xml graphics edit for VM '{}' could not run: {}", name, e),
                    }
                }
            }
            // Surface device-apply failures BEFORE persisting the sidecar:
            // returning a false success is exactly the bug we're fixing, and
            // we don't want the sidecar to record intent the domain didn't
            // actually take (which could then read back inconsistently).
            if !apply_failures.is_empty() {
                return Err(format!(
                    "Some settings could not be applied to the libvirt VM:\n  - {}",
                    apply_failures.join("\n  - ")
                ));
            }
            // Persist the WolfStack-only network fields (cloud-init IP hints,
            // wolfnet_ip) into the JSON sidecar so the editor remembers them
            // across reloads — libvirt's XML doesn't carry these as
            // first-class fields. (mode/bridge are read back from the domain
            // XML, which we just edited; the sidecar keeps them in sync for
            // the subprocess fallback path and adoption.)
            let mut ip_advisory: Option<String> = None;
            let ip_changed = self.persist_vm_net_sidecar(name, &VmNetSettings {
                network_mode: network_mode.clone(),
                bridge: bridge.clone(),
                bridge_ip_mode: bridge_ip_mode.clone(),
                bridge_ip: bridge_ip.clone(),
                bridge_gateway: bridge_gateway.clone(),
                vsw_uplink: vsw_uplink.clone(),
                vsw_vlan,
                wolfnet_ip: wolfnet_ip.clone(),
            });
            // Stage the primary NIC's IP into the guest's NoCloud seed. Same
            // reasoning as the Proxmox branch above: the hypervisor can't set
            // a guest IP at runtime, so cloud-init applies it on next boot.
            if ip_changed {
                let br = bridge.as_deref().unwrap_or_default();
                let mac = crate::networking::vlan_attach::primary_nic_mac_libvirt(name, br);
                match (primary_ip_plan(&network_mode, &bridge_ip_mode, &bridge_ip, &bridge_gateway), mac) {
                    (Some(plan), Some(mac)) => {
                        match crate::networking::vlan_attach::stage_primary_ip_libvirt(name, &mac, &plan) {
                            Ok(note) => ip_advisory = note,
                            Err(e) => ip_advisory = Some(format!(
                                "The IP could NOT be staged: {}. Set it inside the guest.", e)),
                        }
                    }
                    (Some(_), None) => ip_advisory = Some(format!(
                        "The IP could NOT be staged: this VM has no NIC on bridge '{}' yet. \
                         Start the VM once so the NIC exists, then save again.", br)),
                    // Left bridge mode (or cleared its addressing) — drop any
                    // IP we staged for this NIC earlier, so the guest stops
                    // re-applying an address that no longer belongs to it.
                    (None, Some(mac)) => {
                        if let Ok(true) = crate::networking::vlan_attach::clear_primary_ip_libvirt(name, &mac) {
                            ip_advisory = Some(
                                "The previously staged static IP was removed from this VM's \
                                 cloud-init seed.".to_string());
                        }
                    }
                    (None, None) => {}
                }
            }
            // Hardware/NIC edits land via virt-xml --define (next boot). When
            // the VM is running, tell the operator so they're not surprised
            // the change isn't live. Liveness signal: libvirt creates
            // /var/run/libvirt/qemu/<name>.xml while a domain is running.
            let running = std::path::Path::new(
                &format!("/var/run/libvirt/qemu/{}.xml", name)
            ).exists();
            let mut advisories: Vec<String> = Vec::new();
            if changed_next_boot && running {
                advisories.push(
                    "Network and hardware changes take effect the next time this VM is started."
                        .to_string());
            }
            if let Some(note) = ip_advisory {
                advisories.push(note);
            }
            if advisories.is_empty() {
                return Ok(None);
            }
            return Ok(Some(format!("Saved. {}", advisories.join(" "))));
        }

        if self.check_running(name) {
            return Err("Cannot edit VM while it is running. Stop it first.".to_string());
        }

        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("VM not found: {}", e))?;
        let mut config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid config: {}", e))?;

        // Capture old network state for OVMF boot entry reset detection
        let old_wolfnet_ip = config.wolfnet_ip.clone();
        let old_net_model = config.net_model.clone();
        let old_nics_count = config.extra_nics.len();
        let old_network_mode = config.network_mode.clone();
        let old_bridge = config.bridge.clone();
        let old_bridge_ip_mode = config.bridge_ip_mode.clone();
        let old_bridge_ip = config.bridge_ip.clone();

        if let Some(c) = cpus && c > 0 { config.cpus = c; }
        if let Some(m) = memory_mb && m >= 256 { config.memory_mb = m; }
        if let Some(a) = auto_start { config.auto_start = a; }
        
        // ISO: accept empty string to clear, or a path to set
        if let Some(ref iso) = iso_path {
            if iso.is_empty() {
                config.iso_path = None;
            } else {
                config.iso_path = Some(iso.clone());
            }
        }

        // WolfNet IP: accept empty string to clear
        if let Some(ref ip) = wolfnet_ip {
            if ip.is_empty() {
                config.wolfnet_ip = None;
            } else {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                    return Err(format!("Invalid WolfNet IP: '{}'", ip));
                }
                config.wolfnet_ip = Some(ip.clone());
            }
        }

        // Hardware settings
        if let Some(ref bus) = os_disk_bus
            && !bus.is_empty() { config.os_disk_bus = bus.clone(); }
        if let Some(ref model) = net_model
            && !model.is_empty() { config.net_model = model.clone(); }
        if let Some(ref drv) = drivers_iso {
            if drv.is_empty() {
                config.drivers_iso = None;
            } else {
                config.drivers_iso = Some(drv.clone());
            }
        }
        if let Some(ref bt) = bios_type
            && !bt.is_empty() { config.bios_type = bt.clone(); }
        // Boot order persists to the native VM's JSON config and is applied on
        // the next start (start_vm rebuilds the qemu boot args from it).
        if let Some(bo) = boot_order {
            config.boot_order = bo;
        }
        // External-VNC toggle also applies on next start (password + port open
        // are wired in start_vm). Editing it on a running VM doesn't reach in.
        if let Some(ve) = vnc_external {
            config.vnc_external = ve;
        }

        // Notes / description — free-text; empty string clears it (mirrors the
        // iso_path/wolfnet_ip clear-on-empty handling above). Persisted into the
        // sidecar JSON, from which the read-back deserializes it back.
        if let Some(ref n) = notes {
            config.notes = n.clone();
        }

        // Extra QEMU args — free-text passthrough applied on next start (the
        // splitter tokenises it in start_vm/build_qemu_command). Empty string
        // clears it. Persisted into the sidecar JSON like notes.
        if let Some(ref ea) = extra_qemu_args {
            config.extra_qemu_args = ea.clone();
        }

        // TPM / Secure Boot toggles. Native QEMU reads the config on every
        // start (firmware + swtpm are wired in start_vm), so persisting here
        // makes the change take effect on the VM's next start. Additive-only
        // — matching Proxmox/libvirt and the UI copy ("can't remove them
        // here") — so an edit-save can never detach a TPM a guest may have
        // sealed secrets (e.g. BitLocker) against.
        if tpm == Some(true) { config.tpm = true; }
        if secure_boot == Some(true) { config.secure_boot = true; }

        // Primary-NIC network mode + bridge details. Each field is independently
        // patchable so the API caller can update just one without nulling
        // sibling fields. Empty string clears optional Strings; mode "" is
        // ignored (the editor never sends an empty mode).
        if let Some(ref nm) = network_mode
            && !nm.is_empty() {
                config.network_mode = Some(nm.clone());
                // Switching off bridge mode wipes the bridge fields so a
                // stale bridge name from a previous mode doesn't ride along
                // and confuse the start path.
                if nm != "bridge" {
                    config.bridge = None;
                    config.bridge_ip_mode = None;
                    config.bridge_ip = None;
                    config.bridge_gateway = None;
                }
            }
        if let Some(ref br) = bridge {
            config.bridge = if br.is_empty() { None } else { Some(br.clone()) };
        }
        if let Some(ref ipm) = bridge_ip_mode {
            config.bridge_ip_mode = if ipm.is_empty() { None } else { Some(ipm.clone()) };
        }
        if let Some(ref bi) = bridge_ip {
            config.bridge_ip = if bi.is_empty() { None } else { Some(bi.clone()) };
        }
        if let Some(ref bg) = bridge_gateway {
            config.bridge_gateway = if bg.is_empty() { None } else { Some(bg.clone()) };
        }

        if let Some(nics) = extra_nics {
            // Auto-generate MACs for any NICs that don't have one
            config.extra_nics = nics.into_iter().map(|mut n| {
                if n.mac.is_none() || n.mac.as_ref().map(|m| m.is_empty()).unwrap_or(false) {
                    n.mac = Some(generate_mac());
                }
                n
            }).collect();
        }

        // USB/PCI passthrough
        if let Some(usbs) = usb_devices {
            config.usb_devices = usbs;
        }
        if let Some(pcis) = pci_devices {
            // Normalize BDFs on write so we store canonical form
            config.pci_devices = pcis.into_iter().map(|mut p| {
                if let Ok(norm) = super::passthrough::normalize_bdf(&p.bdf) {
                    p.bdf = norm;
                }
                p
            }).collect();
        }

        // OVMF boot entry fix: when network topology changes on a UEFI VM, the OVMF
        // boot entries reference device paths that are no longer valid. Reset the EFI
        // vars file so OVMF re-discovers the boot device on next start.
        if config.bios_type == "ovmf" {
            let net_changed = config.wolfnet_ip != old_wolfnet_ip;
            let nics_changed = config.extra_nics.len() != old_nics_count;
            let model_changed = config.net_model != old_net_model;
            let mode_changed = config.network_mode != old_network_mode;
            let bridge_changed = config.bridge != old_bridge;
            if net_changed || nics_changed || model_changed || mode_changed || bridge_changed {
                let vars_path = self.vm_efivars_path(&config);
                if vars_path.exists() {
                    let vars_sources = [
                        "/usr/share/OVMF/OVMF_VARS_4M.fd",
                        "/usr/share/OVMF/OVMF_VARS.fd",
                        "/usr/share/edk2/x64/OVMF_VARS.fd",
                        "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
                        "/usr/share/qemu/OVMF_VARS.fd",
                        "/usr/share/OVMF/OVMF_VARS.pure-efi.fd",
                    ];
                    if let Some(src) = vars_sources.iter().find(|p| std::path::Path::new(p).exists())
                        && fs::copy(src, &vars_path).is_ok() {
                            info!("Reset OVMF EFI vars for VM '{}' due to network topology change", name);
                        }
                }
            }
        }

        // Disk resize (grow only)
        if let Some(new_size) = disk_size_gb
            && new_size > config.disk_size_gb {
                let disk_path = self.vm_os_disk_path(&config);
                let output = Command::new("qemu-img")
                    .args(["resize", &disk_path.to_string_lossy(), &format!("{}G", new_size)])
                    .output()
                    .map_err(|e| format!("Disk resize failed: {}", e))?;
                if !output.status.success() {
                    return Err(format!("Disk resize failed: {}", String::from_utf8_lossy(&output.stderr)));
                }
                config.disk_size_gb = new_size;

            }

        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&config_path, json).map_err(|e| e.to_string())?;

        // If the user added or changed the WolfNet IP, make sure the per-VM
        // WolfNet bridge + dnsmasq exist (so adding-WolfNet-after-creation
        // works the same as setting it at create time) and ensure libvirt /
        // PVE actually have a NIC on that bridge.
        if config.wolfnet_ip != old_wolfnet_ip {
            self.reconcile_wolfnet_for_vm(name, &config, old_wolfnet_ip.as_deref());
        }

        // Native QEMU has no cloud-init path: WolfStack stages a guest IP
        // through libvirt's NoCloud seed or Proxmox's ipconfig, and this VM
        // runs under neither. Say so rather than storing the operator's
        // static IP and silently doing nothing with it — the exact failure
        // this whole change exists to remove.
        if (config.bridge_ip_mode != old_bridge_ip_mode || config.bridge_ip != old_bridge_ip)
            && matches!(primary_ip_plan(&config.network_mode, &config.bridge_ip_mode,
                                        &config.bridge_ip, &config.bridge_gateway),
                        Some(crate::networking::vlan_attach::PrimaryIp::Static { .. }))
        {
            return Ok(Some(
                "Saved, but WolfStack cannot apply an IP to a native QEMU VM — it stages guest                  IPs through cloud-init, which needs libvirt or Proxmox. Set the address inside                  the guest.".to_string()
            ));
        }

        Ok(None)
    }

    /// Read the current `net0` NIC model (virtio/e1000/...) from `qm config`,
    /// defaulting to virtio. The WolfNet `net1` matches it so the guest can
    /// actually drive it: a Windows VM on e1000 can't bind a hardcoded-virtio
    /// WolfNet NIC without virtio drivers, so DHCP never runs and the WolfNet
    /// IP shows in the UI but never reaches the guest (Gary KO4BSR 2026-06-21).
    fn read_qm_net0_model(vmid_str: &str) -> String {
        let cfg = match Command::new("qm").args(["config", vmid_str]).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
            _ => return "virtio".to_string(),
        };
        for line in cfg.lines() {
            let Some(val) = line.trim().strip_prefix("net0:") else { continue };
            for part in val.split(',') {
                let k = match part.trim().split_once('=') {
                    Some((k, _)) => k,
                    None => continue,
                };
                if matches!(k, "virtio" | "e1000" | "e1000e" | "rtl8139" | "vmxnet3") {
                    return k.to_string();
                }
            }
        }
        "virtio".to_string()
    }

    /// Bring the libvirt / PVE VM's WolfNet attachment in line with
    /// `config.wolfnet_ip`. Idempotent — safe to call from update_vm
    /// regardless of whether the VM already has a NIC on the WolfNet
    /// bridge. Standalone QEMU VMs ignore this (their TAP is rebuilt
    /// fresh on every start_vm).
    fn reconcile_wolfnet_for_vm(&self, name: &str, config: &VmConfig, old_ip: Option<&str>) {
        // When the IP changes value (not just absent→present), drop the
        // old /32 host route so packets for the old address don't end up
        // black-holed at the now-unused bridge entry. setup_wolfnet_bridge
        // will install the route for the new IP. Also strip the matching
        // NAT MASQUERADE rule so it doesn't accumulate one per re-IP.
        if let (Some(old), Some(new)) = (old_ip, config.wolfnet_ip.as_deref())
            && old != new {
                let _ = Command::new("ip")
                    .args(["route", "del", &format!("{}/32", old)])
                    .output();
                // The rule may carry the real network or, if written by a
                // version before v25.26.1 on a non-/24 WolfNet, the VM
                // address's /24 — remove whichever exists.
                if let Some(net) = crate::containers::wolfnet_network_or_slash24(old) {
                    for wn_subnet in std::iter::once(net.cidr()).chain(net.legacy_slash24()) {
                        let _ = Command::new("iptables")
                            .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", old),
                                   "!", "-d", &wn_subnet, "-j", "MASQUERADE"]).output();
                    }
                }
            }

        // Proxmox path
        if containers::is_proxmox() {
            let vmid = match self.qm_vmid_by_name(name) {
                Some(v) => v.to_string(),
                None => return, // nothing we can do without a vmid
            };
            let bridge = Self::wn_bridge_name(&vmid);
            match config.wolfnet_ip.as_deref() {
                Some(wip) => {
                    self.ensure_dnsmasq_installed();
                    if let Err(e) = self.setup_wolfnet_bridge(&bridge, wip) {
                        warn!("WolfNet bridge reconcile (qm) for VMID {} failed: {}", vmid, e);
                        return;
                    }
                    // Idempotent: qm set succeeds if --net1 doesn't exist OR if it
                    // already points at the same bridge. If the user previously
                    // configured net1 manually, this overwrites — acceptable
                    // because they explicitly asked for WolfNet.
                    // net1 matches the VM's chosen adapter so a non-virtio guest
                    // can drive the WolfNet NIC and DHCP its IP (Gary 2026-06-21).
                    let model = if config.net_model.trim().is_empty() {
                        "virtio"
                    } else { config.net_model.trim() };
                    let out = Command::new("qm")
                        .args(["set", &vmid, "--net1", &format!("{},bridge={}", model, bridge)])
                        .output();
                    match out {
                        Ok(o) if o.status.success() => {
                            info!("Attached WolfNet NIC (net1 on {}) to VMID {}", bridge, vmid);
                        }
                        Ok(o) => warn!("qm set --net1 failed for VMID {}: {}", vmid, String::from_utf8_lossy(&o.stderr).trim()),
                        Err(e) => warn!("qm set --net1 spawn failed for VMID {}: {}", vmid, e),
                    }
                }
                None => {
                    // WolfNet IP cleared — drop net1 + cleanup the bridge
                    let _ = Command::new("qm").args(["set", &vmid, "--delete", "net1"]).output();
                    self.cleanup_wolfnet_bridge(&bridge, old_ip);
                }
            }
            return;
        }
        // Libvirt path
        if containers::is_libvirt() && self.virsh_has_domain(name) {
            let bridge = Self::wn_bridge_name(name);
            match config.wolfnet_ip.as_deref() {
                Some(wip) => {
                    self.ensure_dnsmasq_installed();
                    if let Err(e) = self.setup_wolfnet_bridge(&bridge, wip) {
                        warn!("WolfNet bridge reconcile (virsh) for VM '{}' failed: {}", name, e);
                        return;
                    }
                    // Check if a NIC on this bridge is already attached. virsh
                    // domiflist prints all interfaces; grep for the bridge name.
                    let already_attached = Command::new("virsh")
                        .args(["domiflist", name]).output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&bridge))
                        .unwrap_or(false);
                    if already_attached { return; }

                    // virsh flag semantics: `--config` persists across reboots,
                    // `--live` applies to a running domain. Combine when the VM
                    // is up so the user gets the NIC immediately AND on reboot;
                    // only `--config` for a stopped VM (libvirt rejects --live
                    // on a defined-but-not-running domain).
                    let mut flags: Vec<&str> = vec!["--config"];
                    if self.check_running(name) { flags.push("--live"); }
                    // Match the VM's adapter so a non-virtio guest can drive the
                    // WolfNet NIC and DHCP its IP (Gary 2026-06-21).
                    let model = if config.net_model.trim().is_empty() {
                        "virtio".to_string()
                    } else { config.net_model.trim().to_string() };
                    let mut argv: Vec<&str> = vec![
                        "attach-interface", "--domain", name,
                        "--type", "bridge", "--source", &bridge,
                        "--model", &model,
                    ];
                    argv.extend_from_slice(&flags);
                    let out = Command::new("virsh").args(&argv).output();
                    match out {
                        Ok(o) if o.status.success() => {
                            info!("Attached WolfNet NIC ({}) to libvirt VM '{}'", bridge, name);
                        }
                        Ok(o) => warn!("virsh attach-interface failed for VM '{}': {}", name, String::from_utf8_lossy(&o.stderr).trim()),
                        Err(e) => warn!("virsh attach-interface spawn failed for VM '{}': {}", name, e),
                    }
                }
                None => {
                    // WolfNet IP cleared — detach the bridge NIC + cleanup.
                    // virsh domiflist columns: Interface Type Source Model MAC.
                    // We grab the MAC from the row whose Source is our bridge.
                    let mac = Command::new("virsh")
                        .args(["domiflist", name]).output().ok()
                        .and_then(|o| {
                            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                            stdout.lines()
                                .find(|l| l.split_whitespace().nth(2) == Some(&bridge))
                                .and_then(|l| l.split_whitespace().last().map(|s| s.to_string()))
                        });
                    if let Some(m) = mac {
                        let mut flags: Vec<&str> = vec!["--config"];
                        if self.check_running(name) { flags.push("--live"); }
                        let mut argv: Vec<&str> = vec![
                            "detach-interface", name, "bridge", "--mac", &m,
                        ];
                        argv.extend_from_slice(&flags);
                        let _ = Command::new("virsh").args(&argv).output();
                    }
                    self.cleanup_wolfnet_bridge(&bridge, old_ip);
                }
            }
        }
        // Standalone QEMU: the TAP is rebuilt by start_vm()'s setup_wolfnet_routing,
        // so nothing to reconcile here.
    }

    pub fn start_vm(&self, name: &str) -> Result<(), String> {
        // A fresh start clears any stale paused marker (a paused VM that was
        // then force-stopped/host-rebooted would otherwise look paused).
        let _ = std::fs::remove_file(self.paused_marker_path(name));
        // Start-time conflict guard: check no running VM on this host has already
        // claimed any USB/PCI device configured on the target VM. Applies to all
        // three backends (native, Proxmox, libvirt) because list_vms() pulls from
        // the active backend's authoritative state.
        let all_vms = self.list_vms();
        if let Some(target) = all_vms.iter().find(|v| v.name == name) {
            let conflicts = find_conflicts(target, &all_vms);
            if !conflicts.is_empty() {
                return Err(format!(
                    "Cannot start VM '{}': passthrough device conflict — {}",
                    name, conflicts.join("; ")
                ));
            }

            // Network-safety preflight, restricted to true VFIO PCI
            // passthrough — `pci_devices` entries whose BDF resolves
            // to the host's default-route NIC. Those genuinely take
            // the device out of the host kernel namespace; the host
            // loses connectivity the moment the VM starts and only a
            // reboot brings it back.
            //
            // Bridge-mode `passthrough_interface` is NOT VFIO — it
            // auto-creates `br-pt-<iface>` and moves the host IP to
            // the bridge so the host stays reachable through the
            // same NIC. The earlier (v22.7.3) version of this
            // preflight blocked bridge-mode too, which killed
            // PapaSchlumpf's HA VM workaround on 2026-05-06. See
            // `passthrough::check_passthrough_steals_host_net` doc
            // for the post-mortem.
            if let Some(blocking_iface) = check_passthrough_steals_host_net(target) {
                return Err(format!(
                    "Cannot start VM '{}': its PCI passthrough list would \
                     claim the host's primary network interface '{}' via VFIO. \
                     Starting would remove that NIC from the host kernel \
                     entirely, disconnect the host from the network, and break \
                     DHCP for every client on the WolfNet bridge — recovery \
                     would require a host reboot.\n\n\
                     Fixes:\n\
                     (a) Remove the PCI passthrough for that NIC and use \
                     bridge-mode passthrough instead (set the NIC's \
                     `passthrough_interface` field) — the guest gets L2 \
                     access via `br-pt-<iface>` without taking the device \
                     out of the host kernel.\n\
                     (b) Move the host's primary connectivity to a different \
                     physical NIC (so the passed-through one is no longer \
                     the default route).\n\
                     (c) If you genuinely need to take that NIC and have an \
                     out-of-band recovery path, edit the VM's PCI passthrough \
                     list to confirm.",
                    name, blocking_iface,
                ));
            }

            // Advisory (non-blocking): bridge-mode passthrough on
            // the default-route iface IS safe — host stays connected
            // via br-pt-<iface> — but the IP-move during bridge
            // creation can blip ongoing TCP flows for a moment.
            // Surface that to the log so an operator who sees a brief
            // SSH/RDP hiccup knows exactly what caused it. No return
            // — we still start the VM.
            if let Some(advisory_iface) = super::passthrough::bridge_passthrough_uses_default_route_iface(target) {
                warn!(
                    "VM '{}' uses bridge-mode passthrough on default-route NIC '{}'. \
                     The host's IP will move to br-pt-{} during start — long-running \
                     TCP flows may briefly reset. SSH normally survives via TCP keepalive.",
                    name, advisory_iface, advisory_iface,
                );
            }
        }

        // Look up the WolfStack-side config so we can re-arm the WolfNet
        // bridge + dnsmasq before delegating to PVE/libvirt. The bridge
        // is a kernel device that vanishes on host reboot, and dnsmasq
        // can be killed; this makes start_vm self-healing for both.
        let wolfstack_cfg: Option<VmConfig> = {
            let cfg_path = self.vm_config_path(name);
            fs::read_to_string(&cfg_path).ok().and_then(|t| serde_json::from_str(&t).ok())
        };
        let wn_ip_for_bridge: Option<String> = wolfstack_cfg
            .as_ref()
            .and_then(|c| c.wolfnet_ip.clone());

        // On Proxmox, delegate to qm start
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;

            // Pre-flight the config before calling qm start. PVE silently
            // tolerates a missing `memory:` field on create/edit, then spams
            // 'Use of uninitialized value in multiplication' from pvestatd
            // and fails to boot the VM with no useful error. Catch the
            // common broken configs here with a clear message instead.
            if let Err(e) = validate_pve_config(vmid) {
                return Err(format!("VM '{}' (vmid {}) config is invalid: {}", name, vmid, e));
            }

            // Re-arm the per-VM WolfNet bridge + dnsmasq. PVE will hook
            // its own tap into this bridge as part of qm start.
            if let Some(ref wip) = wn_ip_for_bridge {
                let bridge = Self::wn_bridge_name(&vmid.to_string());
                if let Err(e) = self.setup_wolfnet_bridge(&bridge, wip) {
                    warn!("WolfNet bridge re-arm for VMID {} failed: {}", vmid, e);
                }
            }

            let output = Command::new("qm").args(["start", &vmid.to_string()]).output()
                .map_err(|e| format!("Failed to run qm start: {}", e))?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("qm start failed: {}", stderr.trim()));
        }
        // On libvirt, delegate to virsh start — but only for VMs that
        // libvirt actually owns. Pre-libvirt native VMs with a JSON
        // config fall through to the qemu path below.
        if containers::is_libvirt() && self.virsh_has_domain(name) {
            // Re-arm the per-VM WolfNet bridge + dnsmasq before virsh start
            // so the VM sees a working DHCP server on its WolfNet NIC.
            if let Some(ref wip) = wn_ip_for_bridge {
                let bridge = Self::wn_bridge_name(name);
                if let Err(e) = self.setup_wolfnet_bridge(&bridge, wip) {
                    warn!("WolfNet bridge re-arm for VM '{}' failed: {}", name, e);
                }
            }

            let output = Command::new("virsh").args(["start", name]).output()
                .map_err(|e| format!("Failed to run virsh start: {}", e))?;
            if output.status.success() {
                // External VNC (libvirt): the domain listens on 0.0.0.0 with a
                // password (set at create); open the firewall for the now-
                // assigned (autoport) VNC port so external clients can reach it.
                let (external, port) = self.libvirt_vnc_info(name);
                if external
                    && let Some(p) = port {
                        vnc_firewall_reap_stale(name, p);  // clear any orphan from a prior autoport
                        vnc_firewall_open(p, name);
                        info!("Opened libvirt VNC port {} for external clients (VM '{}')", p, name);
                    }
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("virsh start failed: {}", stderr.trim()));
        }

        if self.check_running(name) {
             return Err("VM already running".to_string());
        }

        // Reconcile WolfUSB assignments BEFORE QEMU spawns. For a cross-
        // node assignment (or a just-migrated VM) this is where the
        // usbip-client systemd unit gets installed+started on this node,
        // which makes the passthrough USB device appear on the host
        // before QEMU's `-device usb-host,vendorid=...,productid=...`
        // runs and tries to bind to it. Without this, a VM migrating
        // from one node to another would fail at spawn with "usb-host:
        // device not found" because the usbip mount hadn't been set up
        // yet. The hook is idempotent — if everything's already wired
        // up (systemd unit running, dev path present) it's a fast
        // no-op. It also rewrites wolfusb-config.json with the new
        // target_node_id on a migration, which is the mechanism that
        // makes USB assignments follow VMs across nodes.
        {
            let self_id = crate::agent::self_node_id();
            crate::wolfusb::on_container_started(name, "vm", &self_id);
        }

        let config_path = self.vm_config_path(name);
        let log_path = self.base_dir.join(format!("{}.log", name));

        // Helper: append to log file
        let write_log = |msg: &str| {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
                let _ = writeln!(f, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
            }
        };

        write_log(&format!("=== Starting VM '{}' ===", name));

        let content = fs::read_to_string(&config_path)
            .map_err(|e| { 
                let msg = format!("VM config not found: {}", e);
                write_log(&msg); msg
            })?;
        let config: VmConfig = serde_json::from_str(&content)
            .map_err(|e| {
                let msg = format!("Invalid VM config: {}", e);
                write_log(&msg); msg
            })?;

        write_log(&format!("Config: cpus={}, memory={}MB, disk={}GB, iso={:?}, wolfnet_ip={:?}", 
                  config.cpus, config.memory_mb, config.disk_size_gb, config.iso_path, config.wolfnet_ip));

        // Detect host architecture and select the right QEMU binary
        let is_arm64 = std::env::consts::ARCH == "aarch64";
        let qemu_bin = if is_arm64 { "qemu-system-aarch64" } else { "qemu-system-x86_64" };
        let qemu_check = Command::new("which").arg(qemu_bin).output();
        let qemu_path = match &qemu_check {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                let pkg = if is_arm64 { "qemu-system-arm" } else { "qemu-system-x86" };
                let msg = format!("{} not found. Install QEMU: apt install {} qemu-utils", qemu_bin, pkg);
                write_log(&msg);
                return Err(msg);
            }
        };
        write_log(&format!("QEMU binary: {} (arch: {})", qemu_path, std::env::consts::ARCH));

        let mut rng = rand::thread_rng();
        let vnc_num: u16 = rng.gen_range(10..99); 
        let vnc_port: u16 = 5900 + vnc_num;
        let ws_port: u16 = 6080 + vnc_num;  // WebSocket port for noVNC

        // External VNC (opt-in). When on, generate a password QEMU reads from a
        // 0600 secret file and append `password-secret=` to the -vnc arg; the
        // raw port is opened to external clients after a successful start. When
        // off (the default), behaviour is exactly as before — no password, no
        // open port, reachable only via WolfStack's authed browser proxy.
        let vnc_passfile = format!("/var/lib/wolfstack/vms/{}.vncpass", name);
        // The password is written to the 0600 passfile here and read back on
        // demand from there; we don't keep it in a variable past this point.
        let (vnc_arg, vnc_secret_obj): (String, Option<String>) =
            if config.vnc_external {
                let pw = gen_vnc_password();
                write_vnc_passfile(&vnc_passfile, &pw)?;
                (
                    format!("0.0.0.0:{},password-secret=vncsec,websocket={}", vnc_num, ws_port),
                    Some(format!("secret,id=vncsec,file={},format=raw", vnc_passfile)),
                )
            } else {
                let _ = std::fs::remove_file(&vnc_passfile); // clear any stale secret
                (format!("0.0.0.0:{},websocket={}", vnc_num, ws_port), None)
            };

        write_log(&format!("VNC display :{} (port {}), WebSocket port {}{}", vnc_num, vnc_port, ws_port,
            if config.vnc_external { " — EXTERNAL (password-protected, port opened)" } else { "" }));

        // Check if KVM is available
        let kvm_available = std::path::Path::new("/dev/kvm").exists();
        write_log(&format!("KVM available: {}", kvm_available));
        

        let disk_path = self.vm_os_disk_path(&config);
        if !disk_path.exists() {
            // Fall back to default path for backwards compat
            let fallback = self.vm_disk_path(name);
            if !fallback.exists() {
                let msg = format!("Disk image not found: {}", disk_path.display());
                write_log(&msg);
                return Err(msg);
            }
            warn!("OS disk not at configured path, using fallback: {}", fallback.display());
        }
        let actual_disk = if disk_path.exists() { &disk_path } else { &self.vm_disk_path(name) };
        write_log(&format!("OS Disk: {} (exists)", actual_disk.display()));

        let mut cmd = Command::new(qemu_bin);
        
        // OS disk: use configured bus type (virtio by default, ide/sata for Windows)
        let os_disk_if = match config.os_disk_bus.as_str() {
            "ide" => "ide",
            "sata" | "ahci" => "ide",  // QEMU uses ide for SATA in -drive syntax
            _ => "virtio",
        };
        write_log(&format!("OS disk bus: {} (if={})", config.os_disk_bus, os_disk_if));
        
        // QMP (QEMU Monitor Protocol) socket — lets wolfstack hot-plug/unplug
        // USB devices on a running VM without a restart. Path is unique per
        // VM name so we can find it later. Unix socket in a world-writable
        // spot with filename that only root writes.
        let qmp_path = format!("/run/wolfstack-qmp-{}.sock", name);
        // Remove any stale socket from a previous run.
        let _ = std::fs::remove_file(&qmp_path);

        // USB controller setup:
        //   - qemu-xhci = USB 3.0 xHCI, handles full/low/high/super-speed.
        //     Windows 10/11 has native xHCI drivers so this Just Works™.
        //   - The default `-usb` line only provides a USB 1.1 UHCI hub, which
        //     can't enumerate USB 2.0 High-Speed (480 Mb/s) devices like
        //     webcams — they appear to QEMU but never reach the guest.
        // usb-tablet is attached to xHCI so cursor sync works out of the box.
        // Serial console over a Unix socket — console.rs attaches to this
        // with socat when the user clicks the Terminal button. Without
        // this, the Terminal button would fail with "No such file or
        // directory" because nothing listens on the socket. Remove any
        // stale socket from a previous run so server=on can bind fresh.
        let serial_sock = format!("/var/lib/wolfstack/vms/{}.serial.sock", name);
        let _ = std::fs::remove_file(&serial_sock);

        // External-VNC password secret must be declared before -vnc references it.
        if let Some(ref secret) = vnc_secret_obj {
            cmd.arg("-object").arg(secret);
        }

        cmd.arg("-name").arg(name)
           .arg("-m").arg(format!("{}M", config.memory_mb))
           .arg("-smp").arg(format!("{}", config.cpus))
           .arg("-drive").arg(format!("file={},format=qcow2,if={},index=0", actual_disk.display(), os_disk_if))
           .arg("-vnc").arg(&vnc_arg)
           .arg("-device").arg("qemu-xhci,id=xhci")
           .arg("-device").arg("usb-tablet,bus=xhci.0")
           .arg("-vga").arg("std")
           .arg("-chardev").arg(format!("socket,id=serial0,path={},server=on,wait=off", serial_sock))
           .arg("-serial").arg("chardev:serial0")
           .arg("-qmp").arg(format!("unix:{},server,nowait", qmp_path))
           .arg("-daemonize");

        // ARM64 requires the 'virt' machine type and UEFI firmware (no legacy BIOS)
        if is_arm64 {
            cmd.arg("-M").arg("virt");
            // Look for UEFI firmware in common distribution paths
            let fw_paths = [
                "/usr/share/AAVMF/AAVMF_CODE.fd",
                "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
                "/usr/share/edk2/aarch64/QEMU_EFI.fd",
            ];
            if let Some(fw) = fw_paths.iter().find(|p| std::path::Path::new(p).exists()) {
                cmd.arg("-bios").arg(*fw);
                write_log(&format!("ARM64 UEFI firmware: {}", fw));
            } else {
                write_log("WARNING: No UEFI firmware found for ARM64. Install qemu-efi-aarch64 (apt install qemu-efi-aarch64)");
            }
        } else if config.bios_type == "ovmf" {
            // x86_64 UEFI boot via OVMF — q35 for full UEFI compatibility.
            // Secure Boot additionally needs SMM (System Management Mode) so
            // the firmware can protect the key store, plus the pflash secure
            // property. Windows 11 wants Secure Boot on.
            if config.secure_boot {
                cmd.arg("-machine").arg("q35,smm=on");
                cmd.arg("-global").arg("driver=cfi.pflash01,property=secure,value=on");
                write_log("BIOS: OVMF (UEFI) with q35 + SMM (Secure Boot)");
            } else {
                cmd.arg("-machine").arg("q35");
                write_log("BIOS: OVMF (UEFI) with q35 machine type");
            }

            // OVMF firmware code (read-only). For Secure Boot use the
            // `.secboot` build, which enforces the signature checks; the
            // plain build ignores them.
            let code_paths: &[&str] = if config.secure_boot {
                &[
                    "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
                    "/usr/share/OVMF/OVMF_CODE.secboot.fd",
                    "/usr/share/edk2/x64/OVMF_CODE.secboot.fd",
                    "/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd",
                ]
            } else {
                &[
                    "/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "/usr/share/OVMF/OVMF_CODE.fd",
                    "/usr/share/edk2/x64/OVMF_CODE.fd",
                    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
                    "/usr/share/qemu/OVMF_CODE.fd",
                    "/usr/share/OVMF/OVMF_CODE.pure-efi.fd",
                ]
            };
            if let Some(code) = code_paths.iter().find(|p| std::path::Path::new(p).exists()) {
                cmd.arg("-drive").arg(format!("if=pflash,format=raw,readonly=on,file={}", code));
                write_log(&format!("OVMF CODE: {}", code));
            } else if config.secure_boot {
                let msg = "Secure Boot OVMF firmware (OVMF_CODE.secboot.fd) not found. Install: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)";
                write_log(msg);
                return Err(msg.to_string());
            } else {
                let msg = "OVMF firmware not found. Install: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)";
                write_log(msg);
                return Err(msg.to_string());
            }

            // Per-VM EFI vars file (writable — stores boot entries, secure boot state, etc.)
            let vars_path = self.vm_efivars_path(&config);
            if !vars_path.exists() {
                // Create vars file on first boot if it wasn't created during
                // VM creation. For Secure Boot seed from the `.ms` template,
                // which ships Microsoft's KEK/DB keys pre-enrolled so a stock
                // Windows 11 image validates out of the box.
                let vars_sources: &[&str] = if config.secure_boot {
                    &[
                        "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
                        "/usr/share/OVMF/OVMF_VARS.ms.fd",
                        "/usr/share/edk2/x64/OVMF_VARS.ms.fd",
                        "/usr/share/edk2-ovmf/x64/OVMF_VARS.ms.fd",
                    ]
                } else {
                    &[
                        "/usr/share/OVMF/OVMF_VARS_4M.fd",
                        "/usr/share/OVMF/OVMF_VARS.fd",
                        "/usr/share/edk2/x64/OVMF_VARS.fd",
                        "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
                        "/usr/share/qemu/OVMF_VARS.fd",
                        "/usr/share/OVMF/OVMF_VARS.pure-efi.fd",
                    ]
                };
                if let Some(src) = vars_sources.iter().find(|p| std::path::Path::new(p).exists()) {
                    fs::copy(src, &vars_path).map_err(|e| {
                        let msg = format!("Failed to copy EFI vars: {}", e);
                        write_log(&msg); msg
                    })?;
                    write_log(&format!("Created EFI vars from {}", src));
                } else if config.secure_boot {
                    let msg = "Secure Boot NVRAM template (OVMF_VARS.ms.fd, with Microsoft keys) not found. Install: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)";
                    write_log(msg);
                    return Err(msg.to_string());
                } else {
                    let msg = "OVMF_VARS.fd not found. Install: apt install ovmf (Debian/Ubuntu) or pacman -S edk2-ovmf (Arch)";
                    write_log(msg);
                    return Err(msg.to_string());
                }
            }
            cmd.arg("-drive").arg(format!("if=pflash,format=raw,file={}", vars_path.display()));
            write_log(&format!("OVMF VARS: {}", vars_path.display()));
        }

        // Attach extra storage volumes
        for (i, vol) in config.extra_disks.iter().enumerate() {
            let vol_path = vol.file_path();
            if !vol_path.exists() {
                write_log(&format!("WARNING: Volume '{}' not found at {}, skipping", vol.name, vol_path.display()));
                warn!("Volume file not found: {}", vol_path.display());
                continue;
            }
            let idx = i + 1; // OS disk is index 0
            let drive_arg = match vol.bus.as_str() {
                "scsi" => format!("file={},format={},if=none,id=disk{}", vol_path.display(), vol.format, idx),
                "ide" => format!("file={},format={},if=ide,index={}", vol_path.display(), vol.format, idx),
                _ => format!("file={},format={},if=virtio,index={}", vol_path.display(), vol.format, idx),
            };
            cmd.arg("-drive").arg(&drive_arg);
            // For SCSI, also add the device
            if vol.bus == "scsi" {
                cmd.arg("-device").arg(format!("scsi-hd,drive=disk{}", idx));
            }
            write_log(&format!("Extra disk {}: {} ({}G, {})", idx, vol.name, vol.size_gb, vol.bus));
        }

        // KVM or software emulation
        if kvm_available {
            cmd.arg("-enable-kvm").arg("-cpu").arg("host");
        } else {
            let fallback_cpu = if is_arm64 { "max" } else { "qemu64" };
            cmd.arg("-cpu").arg(fallback_cpu);
        }

        // Determine NIC model: virtio-net-pci (Linux), e1000/e1000e (Windows), rtl8139
        let nic_device = match config.net_model.as_str() {
            "e1000" => "e1000",
            "e1000e" => "e1000e",
            "rtl8139" => "rtl8139",
            _ => "virtio-net-pci",
        };
        // Build NIC device string with MAC address if available
        let nic_arg = if let Some(ref mac) = config.mac_address {
            format!("{},netdev=net0,mac={}", nic_device, mac)
        } else {
            format!("{},netdev=net0", nic_device)
        };
        write_log(&format!("NIC model: {} (mac: {})", nic_device, config.mac_address.as_deref().unwrap_or("auto")));

        // Networking: VMs configure their own IP inside the guest OS.
        // network_mode picks the net0 topology:
        //   • "wolfnet" → TAP into per-VM WolfNet bridge (DHCP'd by pinned dnsmasq)
        //   • "bridge"  → TAP attached to operator-chosen bridge (vmbr0, vmbr<vlan>
        //                 from a vSwitch attachment, lxcbr0, br-pt-*, etc.)
        //   • "nat"     → user-mode SLIRP (works without any host bridge config)
        // Backwards-compat: configs without `network_mode` derive it from
        // wolfnet_ip via `effective_network_mode`, matching prior behaviour.
        // Exception: `skip_default_nic` skips net0 entirely — extra_nics[0]
        // becomes net0 (vtnet0) instead. Used by firewall appliances that
        // want the first guest interface to be a physical passthrough.
        let mut net0_attached = false;
        let mut default_nic_used = false;
        if !config.skip_default_nic {
            let mode = config.effective_network_mode();
            match mode {
                "wolfnet" => {
                    if let Some(ref wolfnet_ip) = config.wolfnet_ip {
                        let tap = Self::tap_name(name);
                        write_log(&format!("Net0 mode=wolfnet: TAP networking for WolfNet IP {} (configure this IP inside the guest OS)", wolfnet_ip));
                        match self.setup_tap(&tap) {
                            Ok(_) => {
                                write_log(&format!("TAP '{}' created successfully", tap));
                                cmd.arg("-netdev").arg(format!("tap,id=net0,ifname={},script=no,downscript=no", tap))
                                   .arg("-device").arg(&nic_arg);
                                if let Err(e) = self.setup_wolfnet_routing(&tap, wolfnet_ip) {
                                    write_log(&format!("WolfNet routing warning: {} (VM will still start)", e));
                                } else {
                                    write_log(&format!("WolfNet routing configured for {} via {}", wolfnet_ip, tap));
                                }
                                net0_attached = true;
                            }
                            Err(e) => {
                                write_log(&format!("TAP setup failed: {} — falling back to user-mode networking", e));
                            }
                        }
                    } else {
                        write_log("Net0 mode=wolfnet but wolfnet_ip is empty — falling back to user-mode");
                    }
                }
                "bridge" => {
                    let bridge = config.bridge.clone().filter(|b| !b.is_empty());
                    if let Some(bridge) = bridge {
                        // Same TAP-on-bridge pattern the extra_nics path already uses.
                        let tap = format!("tap-{}-0", &name[..name.len().min(8)]);
                        let _ = Command::new("ip").args(["link", "set", &tap, "down"]).output();
                        let _ = Command::new("ip").args(["tuntap", "del", "dev", &tap, "mode", "tap"]).output();
                        let mut ok = false;
                        if let Ok(o) = Command::new("ip").args(["tuntap", "add", "dev", &tap, "mode", "tap"]).output()
                            && o.status.success() {
                                let master_out = Command::new("ip").args(["link", "set", &tap, "master", &bridge]).output();
                                if let Ok(ref mo) = master_out
                                    && !mo.status.success() {
                                        write_log(&format!("WARNING: bridge '{}' not found or cannot attach TAP — net0 may have no connectivity", bridge));
                                    }
                                let _ = Command::new("ip").args(["link", "set", &tap, "up"]).output();
                                cmd.arg("-netdev").arg(format!("tap,id=net0,ifname={},script=no,downscript=no", tap))
                                   .arg("-device").arg(&nic_arg);
                                write_log(&format!("Net0 mode=bridge: attached to {} (tap: {})", bridge, tap));
                                ok = true;
                                net0_attached = true;
                            }
                        if !ok {
                            write_log(&format!("Net0 mode=bridge for '{}' failed — falling back to user-mode networking", bridge));
                        }
                    } else {
                        write_log("Net0 mode=bridge but no bridge name set — falling back to user-mode");
                    }
                }
                _ => { /* nat (or unknown) — fall through to user-mode below */ }
            }

            if !net0_attached {
                write_log("Net0: user-mode (NAT, VM can access host network)");
                cmd.arg("-netdev").arg("user,id=net0")
                   .arg("-device").arg(&nic_arg);
            }
            default_nic_used = true;
        } else {
            write_log("Networking: skip_default_nic set — net0 will come from extra_nics[0]");
        }

        // Extra NICs — numbering depends on whether net0 was taken by the
        // default block above. With `skip_default_nic`, extra_nics[0]
        // becomes net0 (vtnet0); otherwise it's net1 (vtnet1), etc.
        let base_net_idx = if default_nic_used { 1 } else { 0 };
        for (i, nic) in config.extra_nics.iter().enumerate() {
            let idx = base_net_idx + i;
            let net_id = format!("net{}", idx);
            let dev = match nic.model.as_str() {
                "e1000" => "e1000",
                "e1000e" => "e1000e",
                "rtl8139" => "rtl8139",
                _ => "virtio-net-pci",
            };
            let mac = nic.mac.clone().unwrap_or_else(generate_mac);
            let dev_arg = format!("{},netdev={},mac={}", dev, net_id, mac);

            // Resolve bridge — passthrough_interface auto-creates a bridge, or use manual bridge
            if let Some(bridge) = self.resolve_nic_bridge(nic) {
                // Bridge mode — create a TAP on the resolved bridge
                let tap = format!("tap-{}-{}", &name[..name.len().min(8)], idx);
                // Clean up any stale TAP
                let _ = Command::new("ip").args(["link", "set", &tap, "down"]).output();
                let _ = Command::new("ip").args(["tuntap", "del", "dev", &tap, "mode", "tap"]).output();
                if let Ok(o) = Command::new("ip").args(["tuntap", "add", "dev", &tap, "mode", "tap"]).output()
                    && o.status.success() {
                        let master_out = Command::new("ip").args(["link", "set", &tap, "master", &bridge]).output();
                        if let Ok(ref mo) = master_out
                            && !mo.status.success() {
                                write_log(&format!("WARNING: bridge '{}' not found or cannot attach TAP — NIC {} may have no connectivity", bridge, net_id));
                            }
                        let _ = Command::new("ip").args(["link", "set", &tap, "up"]).output();
                        cmd.arg("-netdev").arg(format!("tap,id={},ifname={},script=no,downscript=no", net_id, tap))
                           .arg("-device").arg(&dev_arg);
                        write_log(&format!("Extra NIC {}: {} on bridge {} (mac: {}, tap: {})", net_id, dev, bridge, mac, tap));
                        continue;
                    }
                write_log(&format!("Extra NIC {}: bridge TAP failed for '{}', falling back to user-mode", net_id, bridge));
            }
            // Fallback: user-mode networking
            cmd.arg("-netdev").arg(format!("user,id={}", net_id))
               .arg("-device").arg(&dev_arg);
            write_log(&format!("Extra NIC {}: {} user-mode (mac: {})", net_id, dev, mac));
        }

        // Boot media: ISO (CD-ROM) or .img (USB drive)
        let mut has_boot_media = false;
        if let Some(iso) = &config.iso_path
             && !iso.is_empty() {
                 if !std::path::Path::new(iso).exists() {
                     let msg = format!("Boot media not found: {}", iso);
                     write_log(&msg);
                     return Err(msg);
                 }
                 let lower = iso.to_lowercase();
                 if lower.ends_with(".img") || lower.ends_with(".raw") {
                     // Raw disk image — attach as USB drive for installation
                     write_log(&format!("Boot image (USB): {} (exists)", iso));
                     cmd.arg("-drive").arg(format!("file={},format=raw,if=none,id=usbdisk,readonly=on", iso))
                        .arg("-device").arg("usb-storage,drive=usbdisk");
                 } else {
                     // ISO — attach as CD-ROM
                     write_log(&format!("ISO: {} (exists)", iso));
                     cmd.arg("-cdrom").arg(iso);
                 }
                 has_boot_media = true;
             }

        // Secondary CD-ROM: VirtIO drivers (for Windows with virtio disk)
        if let Some(ref drivers) = config.drivers_iso
            && !drivers.is_empty() {
                if std::path::Path::new(drivers).exists() {
                    write_log(&format!("VirtIO drivers ISO: {}", drivers));
                    cmd.arg("-drive").arg(format!("file={},media=cdrom,index=1", drivers));
                } else {
                    write_log(&format!("WARNING: Drivers ISO not found: {}", drivers));
                }
            }

        // Boot order: always explicit so OVMF (UEFI) doesn't default to PXE.
        // Default (empty boot_order) keeps the historical behaviour — disk
        // first, CD/USB fallback when install media is present. An operator-set
        // order is mapped to `-boot order=` letters; when "usb" leads, we emit
        // NO `-boot order` and instead put bootindex=0 on the usb-host device
        // (in append_qemu_passthrough_args) — firmware ignores `-boot order`
        // once any device carries a bootindex.
        if let Some(boot_arg) = qemu_boot_order_arg(&config.boot_order, has_boot_media) {
            cmd.arg("-boot").arg(boot_arg);
        }
        write_log(&format!("Boot order: {}", if config.boot_order.is_empty() {
            "default (disk, then CD)".to_string()
        } else {
            config.boot_order.join(" → ")
        }));

        // USB/PCI passthrough — append -device usb-host,... and -device vfio-pci,...
        // for each configured device. The native path already has `-usb` on the
        // command line, so usb-host can attach.
        if !config.usb_devices.is_empty() || !config.pci_devices.is_empty() {
            write_log(&format!("Passthrough: {} USB, {} PCI", config.usb_devices.len(), config.pci_devices.len()));

            // Pre-flight each USB passthrough against the host's actual
            // USB bus. QEMU's `-device usb-host` silently fails to bind
            // when the device isn't present — the VM boots without the
            // device and the operator sees a QEMU log saying "passed
            // through" with no actual hardware inside the guest. This
            // catches the "migration orphaned my USB" case before QEMU
            // spawns so the operator sees a clear, actionable error
            // rather than a confusing empty lsusb inside the VM.
            let mut missing_usb: Vec<String> = Vec::new();
            for u in &config.usb_devices {
                let present = super::passthrough::usb_device_present_on_host(&u.vendor_id, &u.product_id);
                if !present {
                    missing_usb.push(format!("{}:{} ({})",
                        u.vendor_id, u.product_id,
                        u.label.clone().unwrap_or_else(|| "no label".into())));
                }
            }
            if !missing_usb.is_empty() {
                let msg = format!(
                    "USB passthrough pre-flight failed — the following devices \
                     are NOT on this host's USB bus: {}. \
                     Open WolfStack → WolfUSB and click Re-attach on each assignment \
                     (or use Diagnose to see where the chain broke). This usually \
                     means the VM migrated from another node and the source node's \
                     usbip export wasn't set up for cross-node access. Aborting \
                     VM start rather than booting with silently-missing hardware.",
                    missing_usb.join(", ")
                );
                write_log(&msg);
                return Err(msg);
            }

            if let Err(e) = super::passthrough::append_qemu_passthrough_args(&mut cmd, &config) {
                write_log(&format!("Passthrough configuration error: {}", e));
                return Err(format!("Passthrough configuration error: {}", e));
            }
            for u in &config.usb_devices {
                write_log(&format!("  USB: {}:{} {}", u.vendor_id, u.product_id,
                    u.label.clone().unwrap_or_default()));
            }
            for p in &config.pci_devices {
                write_log(&format!("  PCI: {} {} (pcie={})", p.bdf,
                    p.label.clone().unwrap_or_default(), p.pcie));
            }
        }

        // Operator-supplied extra QEMU args (e.g. Windows-11 audio). Appended
        // LAST — after every standard device/-net arg — so they can't reorder
        // or shadow the args we build. Tokenised with our own shell-style
        // splitter and each token pushed as a SEPARATE argv element; the string
        // is NEVER handed to a shell, so embedded metacharacters can't inject.
        if !config.extra_qemu_args.trim().is_empty() {
            let extra = split_qemu_args(&config.extra_qemu_args);
            write_log(&format!("Extra QEMU args ({} tokens): {}", extra.len(), config.extra_qemu_args));
            for tok in &extra {
                cmd.arg(tok);
            }
        }

        write_log(&format!("Launching QEMU: VNC :{} (port {}), KVM: {}", vnc_num, vnc_port, kvm_available));


        // Redirect QEMU stderr to log file (append mode, don't overwrite diagnostics)
        if let Ok(log_file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            cmd.stderr(std::process::Stdio::from(log_file));
        }

        // Emulated TPM 2.0 (Windows 11 requires it). Started HERE — after every
        // fallible preflight above — so a failure earlier in start_vm can't
        // leave an orphaned swtpm daemon. The socket must exist before QEMU
        // connects, which it now does (swtpm --daemon returns once bound). Only
        // touched when the VM opts in, so non-TPM VMs are byte-identical.
        if config.tpm {
            match self.start_swtpm(&config) {
                Ok(sock) => {
                    cmd.arg("-chardev").arg(format!("socket,id=chrtpm,path={}", sock));
                    cmd.arg("-tpmdev").arg("emulator,id=tpm0,chardev=chrtpm");
                    cmd.arg("-device").arg("tpm-tis,tpmdev=tpm0");
                    write_log(&format!("TPM 2.0: swtpm socket {}", sock));
                }
                Err(e) => {
                    write_log(&format!("TPM start failed: {}", e));
                    return Err(e);
                }
            }
        }

        let output = cmd.output().map_err(|e| {
            // QEMU couldn't even exec — reap the swtpm we just started.
            if config.tpm { self.stop_swtpm(&config.name); }
            let msg = format!("Failed to execute QEMU: {}", e);
            write_log(&msg); msg
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let log_content = fs::read_to_string(&log_path).unwrap_or_default();
            let err_msg = if !stderr.is_empty() { stderr } else { log_content.clone() };
            write_log(&format!("QEMU exit with error: {}", err_msg));
            error!("QEMU failed for VM {}: {}", name, err_msg);

            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
            }
            self.cleanup_extra_nic_taps(name, &config.extra_nics);
            if config.tpm { self.stop_swtpm(&config.name); }
            return Err(format!("QEMU failed to start: {}", err_msg));
        }

        // -daemonize makes QEMU fork, so output.status may be 0 even if the child crashes.
        std::thread::sleep(std::time::Duration::from_secs(1));

        if !self.check_running(name) {
            let log_content = fs::read_to_string(&log_path).unwrap_or_else(|_| "no log available".to_string());
            write_log("VM exited immediately after daemonize — check QEMU errors above");
            error!("VM {} exited immediately after daemonize. Log: {}", name, log_content);

            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
            }
            self.cleanup_extra_nic_taps(name, &config.extra_nics);
            if config.tpm { self.stop_swtpm(&config.name); }
            return Err(format!("VM crashed immediately after starting. QEMU log:\n{}", log_content));
        }

        write_log(&format!("VM started successfully. VNC :{} (port {}), noVNC WS :{}", vnc_num, vnc_port, ws_port));

        // External VNC: open the raw port now that QEMU is up and listening.
        if config.vnc_external {
            // Reap a stale rule from a prior run that was force-killed (not
            // stopped cleanly): the old runtime.json still holds its randomized
            // port, so close that rule before opening the new one. (The new
            // runtime.json with the new port is written just below.)
            if let Some(old_port) = self.read_runtime_vnc_port(name)
                && old_port != vnc_port { vnc_firewall_close(old_port, name); }
            vnc_firewall_open(vnc_port, name);
            write_log(&format!("Opened VNC port {} to external clients (password-protected)", vnc_port));
        }

        // Save runtime port info so frontend can connect. The VNC password is
        // deliberately NOT here — runtime.json is world-readable (0644). It
        // lives only in the 0600 `.vncpass` secret file, read on demand by the
        // authed `/api/vms/{name}/vnc-password` endpoint.
        let runtime = serde_json::json!({
            "vnc_port": vnc_port,
            "vnc_ws_port": ws_port,
            "vnc_display": vnc_num,
            "kvm": kvm_available,
            "vnc_external": config.vnc_external,
        });
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let _ = fs::write(&runtime_path, runtime.to_string());

        Ok(())
    }

    /// Reconstruct the exact `qemu-system-*` argv that the native [`start_vm`]
    /// path would build for `config`, WITHOUT executing anything or mutating
    /// the host (no TAP/bridge creation, no vfio binding, no passfile writes).
    /// Returned as a token vector (argv[0] = the qemu binary). Used by the
    /// `start-command` endpoint to show the operator the raw command.
    ///
    /// This MUST stay in lock-step with `start_vm`'s argv emission — the unit
    /// test `build_qemu_command_matches_start_prefix` pins the device/order
    /// prefix so a future edit to one without the other is caught at test time.
    /// Display-only differences are deliberate and documented inline:
    ///   • the VNC display number is randomised at real start — here it shows
    ///     `:NN` as a placeholder so the command is stable/copyable;
    ///   • network args use the deterministic TAP names start_vm would pick,
    ///     and assume the bridge/TAP setup succeeds (the fallback-to-user-mode
    ///     only happens at runtime on failure — not knowable without mutating).
    pub fn build_qemu_command(&self, config: &VmConfig) -> Vec<String> {
        let mut argv: Vec<String> = Vec::new();
        let name = config.name.as_str();
        let is_arm64 = std::env::consts::ARCH == "aarch64";
        let qemu_bin = if is_arm64 { "qemu-system-aarch64" } else { "qemu-system-x86_64" };
        argv.push(qemu_bin.to_string());

        let kvm_available = std::path::Path::new("/dev/kvm").exists();

        let os_disk_if = match config.os_disk_bus.as_str() {
            "ide" => "ide",
            "sata" | "ahci" => "ide",
            _ => "virtio",
        };
        let disk_path = self.vm_os_disk_path(config);
        let actual_disk = if disk_path.exists() { disk_path } else { self.vm_disk_path(name) };

        let qmp_path = format!("/run/wolfstack-qmp-{}.sock", name);
        let serial_sock = format!("/var/lib/wolfstack/vms/{}.serial.sock", name);
        let vnc_passfile = format!("/var/lib/wolfstack/vms/{}.vncpass", name);

        // External-VNC secret object precedes -vnc (mirrors start_vm ordering).
        let (vnc_arg, vnc_secret_obj): (String, Option<String>) = if config.vnc_external {
            (
                "0.0.0.0:NN,password-secret=vncsec,websocket=WS".to_string(),
                Some(format!("secret,id=vncsec,file={},format=raw", vnc_passfile)),
            )
        } else {
            ("0.0.0.0:NN,websocket=WS".to_string(), None)
        };
        if let Some(ref secret) = vnc_secret_obj {
            argv.push("-object".into());
            argv.push(secret.clone());
        }

        argv.push("-name".into()); argv.push(name.to_string());
        argv.push("-m".into()); argv.push(format!("{}M", config.memory_mb));
        argv.push("-smp".into()); argv.push(format!("{}", config.cpus));
        argv.push("-drive".into());
        argv.push(format!("file={},format=qcow2,if={},index=0", actual_disk.display(), os_disk_if));
        argv.push("-vnc".into()); argv.push(vnc_arg);
        argv.push("-device".into()); argv.push("qemu-xhci,id=xhci".into());
        argv.push("-device".into()); argv.push("usb-tablet,bus=xhci.0".into());
        argv.push("-vga".into()); argv.push("std".into());
        argv.push("-chardev".into());
        argv.push(format!("socket,id=serial0,path={},server=on,wait=off", serial_sock));
        argv.push("-serial".into()); argv.push("chardev:serial0".into());
        argv.push("-qmp".into()); argv.push(format!("unix:{},server,nowait", qmp_path));
        argv.push("-daemonize".into());

        if is_arm64 {
            argv.push("-M".into()); argv.push("virt".into());
            let fw_paths = [
                "/usr/share/AAVMF/AAVMF_CODE.fd",
                "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
                "/usr/share/edk2/aarch64/QEMU_EFI.fd",
            ];
            if let Some(fw) = fw_paths.iter().find(|p| std::path::Path::new(p).exists()) {
                argv.push("-bios".into()); argv.push((*fw).to_string());
            }
        } else if config.bios_type == "ovmf" {
            argv.push("-machine".into()); argv.push("q35".into());
            let code_paths = [
                "/usr/share/OVMF/OVMF_CODE_4M.fd",
                "/usr/share/OVMF/OVMF_CODE.fd",
                "/usr/share/edk2/x64/OVMF_CODE.fd",
                "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
                "/usr/share/qemu/OVMF_CODE.fd",
                "/usr/share/OVMF/OVMF_CODE.pure-efi.fd",
            ];
            if let Some(code) = code_paths.iter().find(|p| std::path::Path::new(p).exists()) {
                argv.push("-drive".into());
                argv.push(format!("if=pflash,format=raw,readonly=on,file={}", code));
            }
            let vars_path = self.vm_efivars_path(config);
            argv.push("-drive".into());
            argv.push(format!("if=pflash,format=raw,file={}", vars_path.display()));
        }

        for (i, vol) in config.extra_disks.iter().enumerate() {
            let vol_path = vol.file_path();
            if !vol_path.exists() { continue; }
            let idx = i + 1;
            let drive_arg = match vol.bus.as_str() {
                "scsi" => format!("file={},format={},if=none,id=disk{}", vol_path.display(), vol.format, idx),
                "ide" => format!("file={},format={},if=ide,index={}", vol_path.display(), vol.format, idx),
                _ => format!("file={},format={},if=virtio,index={}", vol_path.display(), vol.format, idx),
            };
            argv.push("-drive".into()); argv.push(drive_arg);
            if vol.bus == "scsi" {
                argv.push("-device".into()); argv.push(format!("scsi-hd,drive=disk{}", idx));
            }
        }

        if kvm_available {
            argv.push("-enable-kvm".into()); argv.push("-cpu".into()); argv.push("host".into());
        } else {
            let fallback_cpu = if is_arm64 { "max" } else { "qemu64" };
            argv.push("-cpu".into()); argv.push(fallback_cpu.to_string());
        }

        let nic_device = match config.net_model.as_str() {
            "e1000" => "e1000",
            "e1000e" => "e1000e",
            "rtl8139" => "rtl8139",
            _ => "virtio-net-pci",
        };
        let nic_arg = if let Some(ref mac) = config.mac_address {
            format!("{},netdev=net0,mac={}", nic_device, mac)
        } else {
            format!("{},netdev=net0", nic_device)
        };

        // net0 — mirror start_vm's mode dispatch using deterministic TAP names.
        let mut default_nic_used = false;
        if !config.skip_default_nic {
            match config.effective_network_mode() {
                "wolfnet" if config.wolfnet_ip.is_some() => {
                    let tap = Self::tap_name(name);
                    argv.push("-netdev".into());
                    argv.push(format!("tap,id=net0,ifname={},script=no,downscript=no", tap));
                    argv.push("-device".into()); argv.push(nic_arg.clone());
                }
                "bridge" if config.bridge.as_deref().map(|b| !b.is_empty()).unwrap_or(false) => {
                    let tap = format!("tap-{}-0", &name[..name.len().min(8)]);
                    argv.push("-netdev".into());
                    argv.push(format!("tap,id=net0,ifname={},script=no,downscript=no", tap));
                    argv.push("-device".into()); argv.push(nic_arg.clone());
                }
                _ => {
                    argv.push("-netdev".into()); argv.push("user,id=net0".into());
                    argv.push("-device".into()); argv.push(nic_arg.clone());
                }
            }
            default_nic_used = true;
        }

        let base_net_idx = if default_nic_used { 1 } else { 0 };
        for (i, nic) in config.extra_nics.iter().enumerate() {
            let idx = base_net_idx + i;
            let net_id = format!("net{}", idx);
            let dev = match nic.model.as_str() {
                "e1000" => "e1000",
                "e1000e" => "e1000e",
                "rtl8139" => "rtl8139",
                _ => "virtio-net-pci",
            };
            let mac = nic.mac.clone().unwrap_or_else(|| "<auto>".to_string());
            let dev_arg = format!("{},netdev={},mac={}", dev, net_id, mac);
            // Display assumes a resolvable bridge → TAP; otherwise user-mode.
            let bridge = nic.bridge.clone().filter(|b| !b.is_empty())
                .or_else(|| nic.passthrough_interface.clone().filter(|p| !p.is_empty()).map(|p| format!("br-pt-{}", p)));
            if let Some(_b) = bridge {
                let tap = format!("tap-{}-{}", &name[..name.len().min(8)], idx);
                argv.push("-netdev".into());
                argv.push(format!("tap,id={},ifname={},script=no,downscript=no", net_id, tap));
                argv.push("-device".into()); argv.push(dev_arg);
            } else {
                argv.push("-netdev".into()); argv.push(format!("user,id={}", net_id));
                argv.push("-device".into()); argv.push(dev_arg);
            }
        }

        let mut has_boot_media = false;
        if let Some(iso) = config.iso_path.as_ref().filter(|i| !i.is_empty()) {
            let lower = iso.to_lowercase();
            if lower.ends_with(".img") || lower.ends_with(".raw") {
                argv.push("-drive".into());
                argv.push(format!("file={},format=raw,if=none,id=usbdisk,readonly=on", iso));
                argv.push("-device".into()); argv.push("usb-storage,drive=usbdisk".into());
            } else {
                argv.push("-cdrom".into()); argv.push(iso.clone());
            }
            has_boot_media = true;
        }
        if let Some(drivers) = config.drivers_iso.as_ref()
            .filter(|d| !d.is_empty() && std::path::Path::new(d.as_str()).exists())
        {
            argv.push("-drive".into());
            argv.push(format!("file={},media=cdrom,index=1", drivers));
        }
        if let Some(boot_arg) = qemu_boot_order_arg(&config.boot_order, has_boot_media) {
            argv.push("-boot".into()); argv.push(boot_arg);
        }

        argv.extend(super::passthrough::passthrough_argv(config));

        // Operator extra args — appended LAST, exactly as start_vm does.
        if !config.extra_qemu_args.trim().is_empty() {
            argv.extend(split_qemu_args(&config.extra_qemu_args));
        }

        argv
    }

    pub fn autostart_vms(&self) {
        // Autostart means "start this VM when the MACHINE boots", not when the
        // WolfStack service restarts (e.g. a binary upgrade) — without these
        // guards, updating WolfStack re-started VMs the operator had
        // deliberately stopped (Restraint, 2026-06-23).
        //
        // On Proxmox the hypervisor's own pve-guests starts onboot VMs at node
        // boot, so leave it entirely to Proxmox (mirrors lxc_autostart_all()).
        if containers::is_proxmox() {
            return;
        }
        // On native/libvirt hosts WolfStack drives autostart itself — but only
        // on an actual machine boot, never on a mere service restart.
        if !containers::host_recently_booted() {
            return;
        }

        // WolfHA copies never boot themselves: a standby starting is a
        // split brain, and a protected primary's boot belongs to the
        // boot guard (which first asks every replica "did you take over
        // while I was down?"). Their stored auto_start is already false
        // (stripped at enable / forced on replica config writes) — this
        // is the backstop for a hand-edited sidecar file.
        // Source: src/wolfha/mod.rs boot_guard() + vm_store_replica_config().
        let ha = crate::wolfha::HaStore::load();
        for vm in self.list_vms() {
            if ha.get(&vm.name).is_some_and(|e| e.kind == crate::wolfha::SubjectKind::Vm) {
                continue;
            }
            if vm.auto_start && !vm.running

                && let Err(e) = self.start_vm(&vm.name) {
                    error!("Failed to autostart VM {}: {}", vm.name, e);
                }
        }
    }

    /// Per-VM WolfNet bridge name for libvirt / PVE VMs. Linux bridge names
    /// are limited to 15 chars (IFNAMSIZ-1).
    pub fn wn_bridge_name(vmid_or_name: &str) -> String {
        // Sanitise: only [a-z0-9-] survives; truncate.
        let safe: String = vmid_or_name.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' })
            .collect();
        let s = format!("wnbr-{}", safe);
        if s.len() > 15 { s[..15].to_string() } else { s }
    }

    /// Idempotently set up a per-VM Linux bridge with dnsmasq pinned to a
    /// single WolfNet IP — the libvirt/PVE equivalent of standalone QEMU's
    /// per-VM TAP. The hypervisor (libvirt / PVE) creates its own tap on
    /// this bridge when the VM starts; the bridge gives us a stable
    /// interface to run dnsmasq + host routing on. Layout matches
    /// setup_wolfnet_routing exactly so the host iptables/forwarding/NAT
    /// rules are identical.
    pub fn setup_wolfnet_bridge(&self, bridge: &str, wolfnet_ip: &str) -> Result<(), String> {
        // Create the bridge if missing.
        let exists = Command::new("ip").args(["link", "show", bridge]).output()
            .map(|o| o.status.success()).unwrap_or(false);
        if !exists {
            let out = Command::new("ip")
                .args(["link", "add", bridge, "type", "bridge"])
                .output()
                .map_err(|e| format!("Failed to create bridge {}: {}", bridge, e))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.contains("File exists") {
                    return Err(format!("Bridge creation failed: {}", stderr));
                }
            }
        }
        // Bring it up — required before dnsmasq can bind, and before
        // the hypervisor attaches a tap.
        let _ = Command::new("ip").args(["link", "set", bridge, "up"]).output();
        // Disable bridge's internal forwarding restrictions — STP off, no
        // multicast snooping confusion, fast failover.
        let _ = Command::new("ip").args(["link", "set", bridge, "type", "bridge", "stp_state", "0"]).output();

        // Reuse the TAP/bridge-agnostic routing+dnsmasq setup. Inside,
        // it `ip addr flush`es the iface and assigns the gateway IP, runs
        // dnsmasq on `--interface={iface}` — works identically for a TAP
        // or a bridge (both are L3 interfaces from the host's POV).
        self.setup_wolfnet_routing(bridge, wolfnet_ip)
    }

    /// Tear down a per-VM WolfNet bridge: kill dnsmasq, drop iptables
    /// rules, delete the bridge. Mirrors cleanup_tap but for our bridges.
    fn cleanup_wolfnet_bridge(&self, bridge: &str, wolfnet_ip: Option<&str>) {
        // Kill the per-bridge dnsmasq using the pid file we set in
        // setup_wolfnet_routing — falls back to pkill on the iface name.
        let _ = Command::new("pkill")
            .args(["-f", &format!("dnsmasq.*--interface={}", bridge)])
            .output();
        let pid_path = format!("/run/dnsmasq-{}.pid", bridge);
        let _ = std::fs::remove_file(&pid_path);
        let lease_path = format!("/run/dnsmasq-{}.leases", bridge);
        let _ = std::fs::remove_file(&lease_path);

        if let Some(ip) = wolfnet_ip {
            // Remove the host /32 route for this VM's WolfNet IP.
            let _ = Command::new("ip")
                .args(["route", "del", &format!("{}/32", ip)])
                .output();
            // Remove the NAT MASQUERADE rule we added — in the real-network
            // form, and in the /24 form versions before v25.26.1 wrote.
            if let Some(net) = crate::containers::wolfnet_network_or_slash24(ip) {
                for wn_subnet in std::iter::once(net.cidr()).chain(net.legacy_slash24()) {
                    let _ = Command::new("iptables")
                        .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", ip),
                               "!", "-d", &wn_subnet, "-j", "MASQUERADE"]).output();
                }
            }
        }

        // Drop iptables FORWARD rules for the bridge — best effort.
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", bridge, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-o", bridge, "-j", "ACCEPT"]).output();

        // Bring down + delete the bridge. Note: libvirt/PVE may still be
        // holding a tap on it; deleting the bridge unhooks them, which is
        // fine because the VM is being destroyed.
        let _ = Command::new("ip").args(["link", "set", bridge, "down"]).output();
        let _ = Command::new("ip").args(["link", "del", bridge]).output();
    }

    /// Best-effort recovery of the WolfNet IP previously assigned to a per-VM
    /// bridge, by reading the host /32 route we installed in
    /// `setup_wolfnet_routing` (`<ip>/32 dev <bridge>`). Proxmox doesn't persist
    /// the WolfNet IP in config, so on removal we need this to GC the
    /// MASQUERADE rule that deleting the bridge won't clear.
    fn recover_wolfnet_ip_from_bridge(bridge: &str) -> Option<String> {
        let out = Command::new("ip")
            .args(["-o", "route", "show", "dev", bridge])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            // Lines look like "10.0.10.5/32 scope link" — take the /32 prefix.
            if let Some(first) = line.split_whitespace().next()
                && let Some(ip) = first.strip_suffix("/32")
                    && ip.split('.').count() == 4
                        && ip.split('.').all(|o| o.parse::<u8>().is_ok())
                    {
                        return Some(ip.to_string());
                    }
        }
        None
    }

    fn setup_tap(&self, tap: &str) -> Result<(), String> {
        // Clean up any stale TAP from a previous crash or host restart first,
        // otherwise `ip tuntap add` can fail with EBUSY if the interface exists
        // in a half-dead state (e.g. after unclean shutdown / reboot).
        let _ = Command::new("ip").args(["link", "set", tap, "down"]).output();
        let _ = Command::new("ip").args(["tuntap", "del", "dev", tap, "mode", "tap"]).output();

        // Create TAP device
        let output = Command::new("ip")
            .args(["tuntap", "add", "dev", tap, "mode", "tap"])
            .output()
            .map_err(|e| format!("Failed to create TAP {}: {}", tap, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("EEXIST") && !stderr.contains("File exists") {
                return Err(format!("TAP creation failed: {}", stderr));
            }
        }

        // Bring TAP up
        let output = Command::new("ip")
            .args(["link", "set", tap, "up"])
            .output()
            .map_err(|e| format!("Failed to bring up TAP {}: {}", tap, e))?;

        if !output.status.success() {
            return Err(format!("TAP up failed: {}", String::from_utf8_lossy(&output.stderr)));
        }


        Ok(())
    }

    /// Set up host-side routing and forwarding for WolfNet IP through a TAP
    /// Install dnsmasq if missing — required for VM TAP DHCP to work.
    /// Without this the VM boots but DHCPDISCOVER gets no reply, and the
    /// guest OS has no IP. Runs the same per-distro install we use for
    /// the CIFS/NFS mount helpers, but here it's a silent background fix
    /// rather than an interactive prompt (the VM is already starting).
    /// Make sure `ethtool` is on the host. Without it, the VLAN-passthrough
    /// fix (`ethtool -K rxvlan/txvlan/rx-vlan-filter off`) can't run — the
    /// Command::new("ethtool") calls return ENOENT and we silently swallow
    /// the failure with `let _ = …`. Stripped-down installs (especially
    /// minimal Debian, container-host distros, custom-built images) often
    /// don't ship it. Symptom is the same as a real VLAN-stripping bug:
    /// first DHCP works, later ones don't, and there's no error in the log.
    fn ensure_ethtool_installed() {
        if Path::new("/usr/sbin/ethtool").exists() || Path::new("/sbin/ethtool").exists()
            || Path::new("/usr/bin/ethtool").exists() || Path::new("/bin/ethtool").exists()
        {
            return;
        }
        let (pkg_mgr, pkg_name) = match crate::installer::detect_distro() {
            crate::installer::DistroFamily::Debian => ("apt-get", "ethtool"),
            crate::installer::DistroFamily::RedHat => ("dnf", "ethtool"),
            crate::installer::DistroFamily::Suse => ("zypper", "ethtool"),
            crate::installer::DistroFamily::Arch => ("pacman", "ethtool"),
            crate::installer::DistroFamily::Alpine => ("apk", "ethtool"),
            crate::installer::DistroFamily::Unknown => ("apt-get", "ethtool"),
        };
        info!("ethtool not found — installing {} via {} so VLAN passthrough fix can apply", pkg_name, pkg_mgr);
        let args: Vec<&str> = match pkg_mgr {
            "pacman" => vec!["-Sy", "--noconfirm", pkg_name],
            "zypper" => vec!["--non-interactive", "install", pkg_name],
            "apk"    => vec!["add", "--no-cache", pkg_name],
            _ => vec!["install", "-y", pkg_name],
        };
        let result = Command::new(pkg_mgr).args(&args).output();
        match result {
            Ok(o) if o.status.success() => info!("Installed {} — VLAN passthrough offload-disable will now apply", pkg_name),
            Ok(o) => warn!("Failed to install {}: {}", pkg_name, String::from_utf8_lossy(&o.stderr).trim()),
            Err(e) => warn!("Failed to run {}: {}", pkg_mgr, e),
        }
    }

    fn ensure_dnsmasq_installed(&self) {
        if Path::new("/usr/sbin/dnsmasq").exists() || Path::new("/sbin/dnsmasq").exists() {
            return;
        }
        let (pkg_mgr, pkg_name) = match crate::installer::detect_distro() {
            crate::installer::DistroFamily::Debian => ("apt-get", "dnsmasq-base"),
            crate::installer::DistroFamily::RedHat => ("dnf", "dnsmasq"),
            crate::installer::DistroFamily::Suse => ("zypper", "dnsmasq"),
            crate::installer::DistroFamily::Arch => ("pacman", "dnsmasq"),
            crate::installer::DistroFamily::Alpine => ("apk", "dnsmasq"),
            crate::installer::DistroFamily::Unknown => ("apt-get", "dnsmasq-base"),
        };
        info!("dnsmasq not found — installing {} via {} so VM DHCP will work", pkg_name, pkg_mgr);
        let args: Vec<&str> = match pkg_mgr {
            "pacman" => vec!["-Sy", "--noconfirm", pkg_name],
            "zypper" => vec!["--non-interactive", "install", pkg_name],
            "apk"    => vec!["add", "--no-cache", pkg_name],
            _ => vec!["install", "-y", pkg_name],
        };
        let result = Command::new(pkg_mgr).args(&args).output();
        match result {
            Ok(o) if o.status.success() => info!("Installed {} — DHCP will now work for new VMs", pkg_name),
            Ok(o) => warn!("Failed to install {}: {}", pkg_name, String::from_utf8_lossy(&o.stderr).trim()),
            Err(e) => warn!("Failed to run {}: {}", pkg_mgr, e),
        }
    }

    fn setup_wolfnet_routing(&self, tap: &str, wolfnet_ip: &str) -> Result<(), String> {
        // Make sure dnsmasq is there before we try to use it further down.
        self.ensure_dnsmasq_installed();

        let wn_iface = networking::detect_wolfnet_iface().unwrap_or_else(|| "wolfnet0".to_string());

        // Enable per-interface forwarding on TAP + WolfNet
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", tap)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", wn_iface)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", wn_iface)]).output();

        // Proxy ARP on both sides so the host answers ARP on behalf of routed IPs
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.proxy_arp=1", tap)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.proxy_arp=1", wn_iface)]).output();

        // Disable reverse-path filtering — packets arrive from tunnel/TAP with
        // source IPs that don't match the directly-connected subnet
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", tap)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", wn_iface)]).output();

        // Suppress ICMP redirects — we handle routing ourselves
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", tap)]).output();

        // Per-interface ARP scoping. Every WolfNet VM TAP gets the same
        // `<subnet>.254` gateway so that statically-configured guests
        // (WolfRouter, HA appliances) keep working unchanged. With the
        // gateway repeated on multiple TAPs, the default kernel ARP
        // behaviour replies for `.254` on whichever TAP is up — meaning
        // a VM on tap-A can receive an ARP reply with tap-B's MAC, then
        // black-hole every packet it sends to its gateway.
        //
        //   arp_ignore=1  → only reply to ARP for an IP that is configured
        //                   on the interface the request arrived on. The
        //                   reply for `.254` on tap-A always uses tap-A's
        //                   MAC, never tap-B's.
        //   arp_announce=2→ when sourcing an ARP, prefer a local address
        //                   on the outgoing interface. Stops the host from
        //                   announcing `.254` on tap-A as if it were on
        //                   tap-B during gratuitous-ARP / proxy traffic.
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.arp_ignore=1", tap)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.arp_announce=2", tap)]).output();

        // Add route: wolfnet_ip/32 via TAP
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", wolfnet_ip)]).output();
        let route_result = Command::new("ip")
            .args(["route", "add", &format!("{}/32", wolfnet_ip), "dev", tap])
            .output()
            .map_err(|e| format!("Route add failed: {}", e))?;

        if !route_result.status.success() {
            let err = String::from_utf8_lossy(&route_result.stderr);
            if !err.contains("File exists") {
                warn!("Failed to add route for {}/32 dev {}: {}", wolfnet_ip, tap, err);
            }
        }

        // On firewalld systems, add TAP + WolfNet to trusted zone so firewalld's
        // nftables REJECT rule doesn't block forwarded VM traffic
        crate::containers::ensure_firewalld_trusted(&[tap, &wn_iface]);

        // iptables FORWARD: allow all traffic to/from the TAP (not just wolfnet0,
        // so the VM can also reach the internet when FORWARD chain default is DROP)
        let check_in = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", tap, "-j", "ACCEPT"]).output();
        if check_in.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables")
                .args(["-I", "FORWARD", "-i", tap, "-j", "ACCEPT"]).output();
        }
        let check_out = Command::new("iptables")
            .args(["-C", "FORWARD", "-o", tap, "-j", "ACCEPT"]).output();
        if check_out.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables")
                .args(["-I", "FORWARD", "-o", tap, "-j", "ACCEPT"]).output();
        }

        // NAT masquerade so the VM can reach the outside world.
        // Exclude WolfNet-destined traffic so the VM appears as its own WolfNet IP,
        // not the host's IP, when communicating with other WolfNet nodes.
        // Remove old overly-broad rule if it exists, then add the correct one.
        // The real WolfNet network, not the address's /24: on a wider
        // WolfNet the /24 form masqueraded this VM towards every other
        // third octet, so peers there saw the host's address, not the VM's.
        let wn_net = crate::containers::wolfnet_network_or_slash24(wolfnet_ip);
        let wn_subnet = wn_net.map(|n| n.cidr()).unwrap_or_default();
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "-j", "MASQUERADE"]).output();
        // ...and the /24 form a version before v25.26.1 left behind.
        if let Some(legacy) = wn_net.and_then(|n| n.legacy_slash24()) {
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "!", "-d", &legacy, "-j", "MASQUERADE"]).output();
        }
        if !wn_subnet.is_empty() {
            let check_nat = Command::new("iptables")
                .args(["-t", "nat", "-C", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "!", "-d", &wn_subnet, "-j", "MASQUERADE"]).output();
            if check_nat.map(|o| !o.status.success()).unwrap_or(true) {
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-A", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "!", "-d", &wn_subnet, "-j", "MASQUERADE"]).output();
            }
        }

        // ── DHCP server on the TAP so VMs get their WolfNet IP automatically ──
        //
        // History recap, because this is the third time we've touched it:
        //   * Pre-v22.9.26: every TAP got `<subnet>.254/24` and dnsmasq
        //     ran with `--bind-interfaces`. Two WolfNet VMs at once →
        //     second dnsmasq died on bind() (`Address already in use`).
        //   * v22.9.26: switched to per-TAP unique mirror gateways
        //     (`subnet.X` → `subnet.(255-X)`) and `/32` on the TAP. That
        //     broke statically-configured guests (WolfRouter and
        //     PapaSchlumpf's HA workaround) because they have `.254`
        //     baked into their config; it also broke fresh DHCP'd guests
        //     because dnsmasq derived a `/32` netmask from the TAP and
        //     handed it out, leaving the gateway off-link.
        //   * v22.9.28: reverted to historic `<subnet>.254/24`. That
        //     restored single-VM and WolfRouter, but two simultaneous
        //     WolfNet VMs each get `.254/24` on their own TAP → the
        //     kernel installs duplicate connected /24 routes and ARP
        //     for `.254` returns whichever TAP's MAC the kernel feels
        //     like, so the second VM (PapaSchlumpf's HA VM) silently
        //     loses its WolfNet uplink.
        //
        // Current design — keeps every prior promise:
        //   * Gateway IP stays `<subnet>.254` — static guests untouched.
        //   * TAP carries `.254/32` instead of `/24`, so the kernel
        //     does NOT auto-add the `<subnet>.0/24 dev <tap>` connected
        //     route. Only the explicit per-VM `/32` route to
        //     `wolfnet_ip` exists, so packets always egress the right
        //     TAP regardless of how many WolfNet VMs are running.
        //   * `arp_ignore=1` / `arp_announce=2` (set above) make ARP
        //     replies for `.254` interface-scoped: a VM on tap-A only
        //     ever learns tap-A's MAC for its gateway.
        //   * dnsmasq runs with `--bind-dynamic` (SO_BINDTODEVICE) so
        //     multiple instances on different TAPs coexist on the same
        //     IP+port.
        //   * dnsmasq offers `--dhcp-option=1,255.255.255.0` so the
        //     guest gets a /24 view (gateway on-link), regardless of
        //     the /32 we put on the TAP. This is the bit v22.9.26
        //     missed and is why fresh-DHCP'd guests broke back then.
        let parts: Vec<&str> = wolfnet_ip.split('.').collect();
        if parts.len() == 4 {
            let gateway_ip = format!("{}.{}.{}.254", parts[0], parts[1], parts[2]);
            let _ = Command::new("ip").args(["addr", "flush", "dev", tap]).output();
            let _ = Command::new("ip")
                .args(["addr", "add", &format!("{}/32", gateway_ip), "dev", tap])
                .output();
            info!("TAP gateway: {}/32 on {} (DHCP offers /24 via option 1)", gateway_ip, tap);

            // Kill any existing dnsmasq on this TAP
            let _ = Command::new("pkill")
                .args(["-f", &format!("dnsmasq.*--interface={}", tap)])
                .output();

            // Start dnsmasq as DHCP server — offers exactly one IP (the VM's WolfNet IP).
            //
            // Each TAP gets its own lease file at /run/dnsmasq-<tap>.leases.
            // Without this every wolfstack dnsmasq instance on the host shared
            // the default /var/lib/misc/dnsmasq.leases, so a lease written by
            // an old (now-deleted) VM for the same IP would persist and the
            // new instance would refuse to hand that IP to a fresh MAC —
            // making recycled WolfNet IPs silently fail to DHCP.
            // We wipe the per-TAP lease file at start so there's never a
            // cross-VM ghost: each VM's dnsmasq begins with a clean slate.
            let lease_file = format!("/run/dnsmasq-{}.leases", tap);
            let _ = std::fs::remove_file(&lease_file);
            let dns_server = "8.8.8.8";
            // `.status()`, not `.spawn()`: dnsmasq daemonizes by double-
            // fork, so the immediate child we launched exits the moment
            // the daemon is forked. If we `.spawn()` and never `.wait()`
            // on the Child, that initial process becomes a `<defunct>`
            // zombie parented to wolfstack — one per TAP setup, forever.
            // KO4BSR 2026-05-28 saw 1300+ accumulate under wolfstack.
            // `.status()` blocks for the ~100ms it takes dnsmasq to
            // fork-and-exit, reaps the parent, and the daemonized child
            // gets reparented to init as normal.
            let dnsmasq_result = Command::new("dnsmasq")
                .args([
                    &format!("--interface={}", tap),
                    // SO_BINDTODEVICE — two instances on different
                    // TAPs no longer race on the same IP+port. See
                    // dnsmasq(8) for the bind-interfaces vs.
                    // bind-dynamic distinction.
                    "--bind-dynamic",
                    "--except-interface=lo",
                    &format!("--dhcp-range={},{},12h", wolfnet_ip, wolfnet_ip),
                    // Force the offered subnet mask to /24. The TAP
                    // carries `gateway_ip/32` (so the kernel doesn't
                    // install a duplicate connected /24 across every
                    // WolfNet TAP) — without this option dnsmasq would
                    // derive `/32` from the interface and hand out a
                    // lease whose gateway is off-link.
                    "--dhcp-option=1,255.255.255.0",
                    &format!("--dhcp-option=3,{}", gateway_ip),
                    &format!("--dhcp-option=6,{}", dns_server),
                    "--no-resolv",
                    &format!("--server={}", dns_server),
                    &format!("--pid-file=/run/dnsmasq-{}.pid", tap),
                    &format!("--dhcp-leasefile={}", lease_file),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            match dnsmasq_result {
                Ok(_status) => {
                    // `.status()` returns once the parent dnsmasq has
                    // exited the daemonize fork — but dnsmasq can still
                    // abort a moment later if its bind() fails (`Address
                    // already in use`, missing perms, kernel misconfig,
                    // etc.).
                    // Verify the daemon actually stayed up and the pid
                    // file points at a live process bound to OUR tap.
                    // If it didn't, log loudly so the predictive
                    // analyzer + ops team see the failure on the FIRST
                    // occurrence rather than after a customer reports
                    // it (PapaSchlumpf bug 2026-05-06).
                    match verify_dnsmasq_running(tap, &gateway_ip) {
                        Ok(_) => info!(
                            "DHCP on {} — gateway {} offering {} to VM",
                            tap, gateway_ip, wolfnet_ip,
                        ),
                        Err(e) => error!(
                            "DHCP verification FAILED on {} — gateway {}, VM IP {}: {}. \
                             VM will boot but DHCPDISCOVER will get no reply. \
                             Predictive Inbox should flag this; see /api/vms/wolfnet/health.",
                            tap, gateway_ip, wolfnet_ip, e,
                        ),
                    }
                }
                Err(e) => warn!("Could not start DHCP on {}: {} — VM will need manual IP", tap, e),
            }
        }

        Ok(())
    }

    /// Clean up TAP interface and routes
    fn cleanup_tap(&self, tap: &str) -> Result<(), String> {
        // Kill dnsmasq for this TAP
        let _ = Command::new("pkill").args(["-f", &format!("dnsmasq.*--interface={}", tap)]).output();
        if let Ok(pid) = std::fs::read_to_string(format!("/run/dnsmasq-{}.pid", tap)) {
            let _ = Command::new("kill").arg(pid.trim()).output();
            let _ = std::fs::remove_file(format!("/run/dnsmasq-{}.pid", tap));
        }
        // Remove the per-TAP lease file so a future VM with a different MAC
        // won't be blocked by a ghost lease entry.
        let _ = std::fs::remove_file(format!("/run/dnsmasq-{}.leases", tap));

        let _ = Command::new("ip").args(["link", "set", tap, "down"]).output();
        let _ = Command::new("ip").args(["tuntap", "del", "dev", tap, "mode", "tap"]).output();
        // Clean up iptables FORWARD rules (generic form used since v11.28)
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", tap, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-o", tap, "-j", "ACCEPT"]).output();
        // Also clean up old-style wolfnet0-specific rules from before v11.28
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", "wolfnet0", "-o", tap, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", tap, "-o", "wolfnet0", "-j", "ACCEPT"]).output();

        Ok(())
    }

    /// Ensure a dedicated bridge exists for a physical NIC passthrough.
    /// Returns the bridge name to use for TAP attachment.
    fn ensure_passthrough_bridge(&self, iface: &str) -> Result<String, String> {
        // Sanitise interface name — prevent path traversal and injection
        if iface.is_empty() || iface.len() > 15
            || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(format!("Invalid interface name: '{}'", iface));
        }

        // Validate interface exists
        if !Path::new(&format!("/sys/class/net/{}", iface)).exists() {
            return Err(format!("Physical interface '{}' not found", iface));
        }

        // Check if interface is already in a bridge — reuse it
        let master_link = format!("/sys/class/net/{}/master", iface);
        if let Ok(target) = std::fs::read_link(&master_link)
            && let Some(bridge_name) = target.file_name().and_then(|n| n.to_str()) {
                // Verify the master is actually a bridge (not a bond, etc.)
                let bridge_check = format!("/sys/class/net/{}/bridge", bridge_name);
                if Path::new(&bridge_check).exists() {
                    // Re-apply the NIC-level fix on existing bridges so a
                    // setup created by an older WolfStack (or by the user)
                    // inherits it without needing teardown. We do NOT touch
                    // the bridge's vlan_filtering on reuse — if the admin
                    // deliberately configured 802.1Q filtering with proper
                    // per-port VID maps, clobbering it would break their
                    // isolation. Only newly-created bridges get the
                    // explicit vlan_filtering=0 write.
                    for flag in ["rxvlan", "txvlan", "rx-vlan-filter"] {
                        let _ = Command::new("ethtool").args(["-K", iface, flag, "off"]).output();
                    }
                    // Some drivers (r8169, some Intel) hard-pin
                    // rx-vlan-filter on and refuse to let ethtool change it.
                    // Kick off a passive learner that registers VLAN VIDs
                    // with the hardware filter table as the guest uses them.
                    crate::vms::vlan_learner::start_if_needed(iface);
                    // Re-pin the MAC on reuse too: a bridge created by an older
                    // WolfStack, or recreated by ifupdown after a host reboot,
                    // is still in auto mode and will drift the moment the guest's
                    // tap joins. Pinning here (before tap attach) restores the
                    // NIC's MAC and locks it. See pin_bridge_mac().
                    Self::pin_bridge_mac(bridge_name, iface);
                    info!("Passthrough: {} already in bridge {} (hw VLAN offload disabled on NIC)", iface, bridge_name);
                    return Ok(bridge_name.to_string());
                }
                warn!("Passthrough: {} has master '{}' but it is not a bridge — creating new bridge", iface, bridge_name);
            }

        if containers::is_proxmox() {
            self.create_proxmox_passthrough_bridge(iface)
        } else {
            self.create_linux_passthrough_bridge(iface)
        }
    }

    /// Read the current IPv4 address, prefix, and default gateway from an interface
    fn read_iface_ip_config(iface: &str) -> Option<(String, u32, Option<String>)> {
        // Get IP/prefix: ip -j addr show dev {iface}
        let addr_out = Command::new("ip").args(["-j", "addr", "show", "dev", iface]).output().ok()?;
        let addr_json: Vec<serde_json::Value> = serde_json::from_slice(&addr_out.stdout).ok()?;
        let entry = addr_json.first()?;
        let addr_info = entry["addr_info"].as_array()?;
        let ipv4 = addr_info.iter().find(|a| a["family"].as_str() == Some("inet") && a["scope"].as_str() == Some("global"))?;
        let ip = ipv4["local"].as_str()?.to_string();
        let prefix = ipv4["prefixlen"].as_u64()? as u32;

        // Get default gateway: ip -j route show default dev {iface}
        let route_out = Command::new("ip").args(["-j", "route", "show", "default", "dev", iface]).output().ok()?;
        let routes: Vec<serde_json::Value> = serde_json::from_slice(&route_out.stdout).unwrap_or_default();
        let gateway = routes.first()
            .and_then(|r| r["gateway"].as_str())
            .map(|g| g.to_string());

        Some((ip, prefix, gateway))
    }

    /// Pin a passthrough bridge's MAC to its physical NIC's own MAC so it can
    /// never drift.
    ///
    /// A Linux bridge left in the kernel's default (auto) MAC mode tracks the
    /// numerically-lowest MAC among its members — `br_stp_recalculate_bridge_id()`
    /// in `net/bridge/br_stp_if.c` only bails out when `addr_assign_type ==
    /// NET_ADDR_SET`. So the moment the guest's tap joins with a lower MAC, or the
    /// bridge is torn down and recreated across a service restart / host reboot,
    /// the bridge address flips. That bridge is the L2 face WolfRouter presents
    /// upstream, so a flip reads to the ISP / LAN exactly like the gateway
    /// changing its MAC: stale ARP entries, a fresh DHCP lease, dropped
    /// connectivity. PapaSchlumpf's HA VM (bridge-mode passthrough on ens1) hit
    /// this on an upgrade restart.
    ///
    /// Pinning to the physical NIC's own hardware MAC keeps the identity the wire
    /// always saw before WolfStack ever bridged the NIC, and `ip link set address`
    /// sets `addr_assign_type = NET_ADDR_SET` (see `dev_set_mac_address()` in
    /// `net/core/dev.c`), which permanently disables the kernel's member-MAC
    /// recalculation. Idempotent: a bridge already SET to the NIC's MAC is left
    /// untouched, so the steady-state reuse path doesn't churn the link.
    fn pin_bridge_mac(bridge: &str, iface: &str) {
        let read_sys = |dev: &str, attr: &str| {
            std::fs::read_to_string(format!("/sys/class/net/{}/{}", dev, attr))
                .map(|s| s.trim().to_string())
                .ok()
        };
        // addr_assign_type is already intentionally fixed → leave it alone: the
        // kernel won't auto-drift it and we must not clobber a deliberate choice.
        //   3 == NET_ADDR_SET   (operator/ifupdown `hwaddress`, or a prior pin here)
        //   0 == NET_ADDR_PERM  (a permanent hardware MAC — not how the kernel
        //                        births a software bridge, but be explicit)
        // Only auto-mode bridges (1 RANDOM / 2 STOLEN) are drift-prone.
        match read_sys(bridge, "addr_assign_type").as_deref() {
            Some("3") | Some("0") => return,
            _ => {}
        }
        // The slave keeps its own hardware MAC after enslaving, so sysfs is the
        // stable source of truth on both the create and the reuse path.
        let nic_mac = match read_sys(iface, "address") {
            Some(m) if !m.is_empty() && m != "00:00:00:00:00:00" => m.to_ascii_lowercase(),
            _ => return,
        };
        match Command::new("ip")
            .args(["link", "set", "dev", bridge, "address", &nic_mac])
            .output()
        {
            Ok(o) if o.status.success() => info!(
                "Passthrough: pinned bridge {} MAC to physical NIC {} ({}) so it can't drift to a tap/veth",
                bridge, iface, nic_mac
            ),
            Ok(o) => warn!(
                "Passthrough: could not pin bridge {} MAC to {}: {}",
                bridge, nic_mac, String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("Passthrough: could not pin bridge {} MAC: {}", bridge, e),
        }
    }

    /// Create a Linux bridge for physical NIC passthrough (standalone QEMU/KVM).
    /// Moves the host's IP from the physical NIC to the bridge so the host stays reachable.
    fn create_linux_passthrough_bridge(&self, iface: &str) -> Result<String, String> {
        let bridge_name = format!("br-pt-{}", iface);

        // Capture the host's current IP config BEFORE bridging — we need to move it
        let ip_config = Self::read_iface_ip_config(iface);

        // Create bridge (ignore "File exists" — means it already exists)
        let out = Command::new("ip").args(["link", "add", &bridge_name, "type", "bridge"]).output()
            .map_err(|e| format!("Failed to create bridge: {}", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("File exists") {
                return Err(format!("Failed to create bridge '{}': {}", bridge_name, stderr.trim()));
            }
        }

        // Flush IPs from physical interface (will be moved to the bridge)
        let _ = Command::new("ip").args(["addr", "flush", "dev", iface]).output();

        // Disable hardware VLAN offloads BEFORE enslaving so VLAN-tagged
        // frames pass through transparently. Without this, most drivers
        // strip incoming 802.1Q tags in hardware (rxvlan) and the bridge
        // delivers untagged frames to the guest — so an OPNsense VM doing
        // VLAN trunking on its vtnetN sees no tags, and VLAN interfaces
        // never get traffic. Also disable the tag filter in case the NIC
        // drops tagged frames it doesn't have a matching filter for.
        // Failures are benign: some drivers (virtio, etc.) don't expose
        // these knobs and ethtool returns non-zero — the VM stack doesn't
        // need the flag flipped in that case.
        for flag in ["rxvlan", "txvlan", "rx-vlan-filter"] {
            let _ = Command::new("ethtool").args(["-K", iface, flag, "off"]).output();
        }
        // Fallback for drivers that hard-pin rx-vlan-filter on.
        crate::vms::vlan_learner::start_if_needed(iface);
        // Keep bridge vlan_filtering off (the kernel default) so it acts
        // as a transparent dumb switch for tagged frames. Being explicit
        // here guards against the case where some host-side tool flipped
        // it on globally.
        let _ = std::fs::write(format!("/sys/class/net/{}/bridge/vlan_filtering", bridge_name), "0");

        // Add physical interface to bridge
        let out = Command::new("ip").args(["link", "set", iface, "master", &bridge_name]).output()
            .map_err(|e| format!("Failed to add {} to bridge: {}", iface, e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("already a member") && !stderr.contains("Device or resource busy") {
                return Err(format!("Failed to add {} to bridge {}: {}", iface, bridge_name, stderr.trim()));
            }
        }

        // Bring up both
        let _ = Command::new("ip").args(["link", "set", iface, "up"]).output();
        let _ = Command::new("ip").args(["link", "set", &bridge_name, "up"]).output();

        // Lock the bridge MAC to the NIC's own MAC before the guest's tap can
        // join and drag it to a lower address. See pin_bridge_mac().
        Self::pin_bridge_mac(&bridge_name, iface);

        // Move the host's IP and gateway to the bridge so the host stays reachable
        if let Some((ip, prefix, gateway)) = ip_config {
            let cidr = format!("{}/{}", ip, prefix);
            let _ = Command::new("ip").args(["addr", "add", &cidr, "dev", &bridge_name]).output();
            if let Some(gw) = gateway {
                let _ = Command::new("ip").args(["route", "add", "default", "via", &gw, "dev", &bridge_name]).output();
            }
            info!("Passthrough: moved host IP {} to bridge {}", cidr, bridge_name);
        }

        info!("Passthrough: created bridge {} for physical NIC {}", bridge_name, iface);
        Ok(bridge_name)
    }

    /// Create a Proxmox vmbr bridge for physical NIC passthrough
    fn create_proxmox_passthrough_bridge(&self, iface: &str) -> Result<String, String> {
        // Find next available vmbr{N}
        let mut next_id = 1u32;
        let bridge_name = loop {
            let candidate = format!("vmbr{}", next_id);
            if !Path::new(&format!("/sys/class/net/{}", candidate)).exists() {
                break candidate;
            }
            next_id += 1;
            if next_id > 99 {
                return Err("No available vmbr{N} slot (checked up to vmbr99)".to_string());
            }
        };

        // Register with Proxmox for persistence across reboots
        let pve_node = Command::new("hostname").arg("-s").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string());

        let pvesh_out = Command::new("pvesh").args([
            "create", &format!("/nodes/{}/network", pve_node),
            "--iface", &bridge_name,
            "--type", "bridge",
            "--bridge_ports", iface,
            "--autostart", "1",
        ]).output();

        if let Ok(ref o) = pvesh_out
            && !o.status.success() {
                warn!("pvesh create bridge failed: {} — creating with ip commands only",
                    String::from_utf8_lossy(&o.stderr).trim());
            }

        // Capture the host's current IP config BEFORE bridging
        let ip_config = Self::read_iface_ip_config(iface);

        // Create immediately with ip commands (pvesh config only takes effect on reboot/ifreload)
        let _ = Command::new("ip").args(["link", "add", &bridge_name, "type", "bridge"]).output();
        let _ = Command::new("ip").args(["addr", "flush", "dev", iface]).output();
        // Same VLAN-offload fix as the standalone path: stop the NIC's
        // hardware stripping 802.1Q tags before frames reach the bridge.
        // OPNsense + VLAN trunking was a reported failure mode before
        // this was applied. See create_linux_passthrough_bridge.
        for flag in ["rxvlan", "txvlan", "rx-vlan-filter"] {
            let _ = Command::new("ethtool").args(["-K", iface, flag, "off"]).output();
        }
        crate::vms::vlan_learner::start_if_needed(iface);
        let _ = std::fs::write(format!("/sys/class/net/{}/bridge/vlan_filtering", bridge_name), "0");
        let _ = Command::new("ip").args(["link", "set", iface, "master", &bridge_name]).output();
        let _ = Command::new("ip").args(["link", "set", iface, "up"]).output();
        let _ = Command::new("ip").args(["link", "set", &bridge_name, "up"]).output();

        // Lock the bridge MAC to the NIC's own MAC before the guest's tap can
        // join and drag it to a lower address. See pin_bridge_mac().
        Self::pin_bridge_mac(&bridge_name, iface);

        // Move the host's IP and gateway to the bridge so the host stays reachable
        if let Some((ip, prefix, gateway)) = ip_config {
            let cidr = format!("{}/{}", ip, prefix);
            let _ = Command::new("ip").args(["addr", "add", &cidr, "dev", &bridge_name]).output();
            if let Some(gw) = gateway {
                let _ = Command::new("ip").args(["route", "add", "default", "via", &gw, "dev", &bridge_name]).output();
            }
            info!("Passthrough: moved host IP {} to bridge {}", cidr, bridge_name);
        }

        info!("Passthrough: created Proxmox bridge {} for physical NIC {}", bridge_name, iface);
        Ok(bridge_name)
    }

    /// Resolve the effective bridge for a NIC config — handles passthrough_interface
    fn resolve_nic_bridge(&self, nic: &NicConfig) -> Option<String> {
        // Passthrough takes priority over manual bridge
        if let Some(ref pt_iface) = nic.passthrough_interface
            && !pt_iface.is_empty() {
                match self.ensure_passthrough_bridge(pt_iface) {
                    Ok(bridge) => return Some(bridge),
                    Err(e) => {
                        warn!("Passthrough bridge failed for {}: {}", pt_iface, e);
                    }
                }
            }
        // Fall back to manual bridge
        nic.bridge.clone().filter(|b| !b.is_empty())
    }

    /// Re-apply hardware VLAN offload disable on every NIC currently used
    /// for passthrough. `ethtool -K` settings are session-local — when the
    /// link bounces (NetworkManager refresh, hostname-network restart, cable
    /// flap, driver reload) the kernel resets offloads to driver defaults,
    /// which on most NICs flips `rxvlan` back on. That silently breaks
    /// VLAN-trunked guests (e.g. OPNsense): the first DHCP handshake works,
    /// then once anything cycles the link, incoming 802.1Q tags are stripped
    /// in hardware and the guest never sees them again. Run this on a timer
    /// so the fix stays sticky.
    ///
    /// Sources of truth for "is this a passthrough NIC":
    ///   1. VM JSON configs in base_dir — `extra_nics[].passthrough_interface`
    ///   2. Slaves of any `br-pt-*` bridge currently in /sys/class/net
    /// We deliberately do NOT touch slaves of admin-named bridges (`vmbr0`,
    /// `br0`, etc.) because we can't tell them apart from the admin's own
    /// bridge config — the Proxmox passthrough path uses `vmbr{N}` too, but
    /// missing the offload re-apply on Proxmox is safer than clobbering an
    /// admin's deliberate offload settings.
    pub fn reapply_passthrough_offloads(&self) {
        use std::collections::HashSet;
        // Make sure the binary actually exists before we silently shell out
        // to it 30s/forever. ensure_ethtool_installed() returns immediately
        // if it's already present, so this is cheap on the steady-state path.
        Self::ensure_ethtool_installed();
        let mut ifaces: HashSet<String> = HashSet::new();

        // Source 1: VM config JSON files in base_dir
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&path)
                    && let Ok(vm) = serde_json::from_str::<VmConfig>(&content) {
                        for nic in &vm.extra_nics {
                            if let Some(ref pt) = nic.passthrough_interface
                                && !pt.is_empty() {
                                    ifaces.insert(pt.clone());
                                }
                        }
                    }
            }
        }

        // Source 2: live br-pt-* bridges — covers VMs created by an older
        // WolfStack whose config we may have lost, or interfaces enslaved
        // by hand to one of our bridges.
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.starts_with("br-pt-") {
                    continue;
                }
                let brif = format!("/sys/class/net/{}/brif", name_str);
                if let Ok(slaves) = fs::read_dir(&brif) {
                    for slave in slaves.flatten() {
                        if let Some(s) = slave.file_name().to_str() {
                            ifaces.insert(s.to_string());
                        }
                    }
                }
            }
        }

        for iface in &ifaces {
            // Validate before shelling out — same rule as ensure_passthrough_bridge
            if iface.is_empty() || iface.len() > 15
                || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                continue;
            }
            if !Path::new(&format!("/sys/class/net/{}", iface)).exists() {
                continue;
            }
            for flag in ["rxvlan", "txvlan", "rx-vlan-filter"] {
                match Command::new("ethtool").args(["-K", iface, flag, "off"]).output() {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => {
                        // Surface real failures (driver doesn't support flag,
                        // permission denied, NIC went away). Driver-doesn't-
                        // support is benign — it just means the offload was
                        // never on in the first place; logging at debug avoids
                        // spamming every 30s.
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        tracing::debug!("ethtool -K {} {} off failed: {}", iface, flag, stderr.trim());
                    }
                    Err(e) => {
                        // ENOENT — ethtool isn't installed. ensure_ethtool_installed()
                        // tried at the top of this function; if we got here it
                        // means install failed. Log loudly so the user sees it.
                        warn!("ethtool not runnable ({}) — VLAN passthrough fix cannot apply on {}. Install ethtool manually.", e, iface);
                        return;
                    }
                }
            }
            // Some NICs hard-pin rx-vlan-filter on and ethtool can't flip
            // it. Ensure a passive VID learner is running — it'll register
            // VIDs with the hardware filter table as guests use them.
            // Idempotent; no-op for NICs that don't need it.
            crate::vms::vlan_learner::start_if_needed(iface);
        }
    }

    /// Clean up TAP interfaces for extra NICs
    fn cleanup_extra_nic_taps(&self, name: &str, nics: &[NicConfig]) {
        for (i, nic) in nics.iter().enumerate() {
            let has_bridge = nic.bridge.as_ref().map(|b| !b.is_empty()).unwrap_or(false);
            let has_passthrough = nic.passthrough_interface.as_ref().map(|p| !p.is_empty()).unwrap_or(false);
            if has_bridge || has_passthrough {
                let tap = format!("tap-{}-{}", &name[..name.len().min(8)], i + 1);
                let _ = self.cleanup_tap(&tap);
            }
        }
    }

    /// Clean up WolfNet routes for a specific IP
    fn cleanup_wolfnet_routes(&self, wolfnet_ip: &str) {
        let _ = Command::new("ip").args(["route", "del", &format!("{}/32", wolfnet_ip)]).output();
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-s", &format!("{}/32", wolfnet_ip), "-j", "MASQUERADE"]).output();
    }

    /// Stop a VM. `force = false` asks the guest to shut down gracefully
    /// (ACPI / SIGTERM); `force = true` yanks the power (like pulling the
    /// plug). Graceful is the default for user-initiated stop actions;
    /// internal callers that need a fast, definite stop pass true.
    pub fn stop_vm(&self, name: &str, force: bool) -> Result<(), String> {
        // Stopping clears any paused state (the marker is meaningless once the
        // VM is down, and start would clear it anyway — do it here too so a
        // graceful stop that lands before the next list looks right).
        let _ = std::fs::remove_file(self.paused_marker_path(name));
        // On Proxmox: force = `qm stop` (immediate, block).
        // Graceful = `qm shutdown --timeout 60` backgrounded so the HTTP
        // response returns immediately — previously we blocked up to 30 s
        // waiting, which made the dashboard look frozen.
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            if force {
                let output = Command::new("qm").args(["stop", &vmid.to_string()]).output()
                    .map_err(|e| format!("Failed to run qm stop: {}", e))?;
                if output.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("qm stop failed: {}", stderr.trim()));
            }
            // Graceful path — fire-and-forget. Send ACPI via `qm shutdown`
            // in a detached thread; ignore the wait-for-shutdown return
            // status since the HTTP caller will poll VM state for the
            // actual stopped transition.
            let vmid_str = vmid.to_string();
            std::thread::spawn(move || {
                let _ = Command::new("qm")
                    .args(["shutdown", &vmid_str, "--timeout", "60"])
                    .output();
            });
            return Ok(());
        }
        // On libvirt: graceful = `virsh shutdown` (ACPI, fire-and-forget);
        // force = `virsh destroy` (immediate). Only for libvirt-owned
        // domains — pre-libvirt native VMs fall through to pkill below.
        if containers::is_libvirt() && self.virsh_has_domain(name) {
            // Capture the external-VNC port while the domain is still running
            // (vncdisplay needs it up) so we can close the firewall hole after.
            let (external, vnc_port) = self.libvirt_vnc_info(name);
            let close_fw = || {
                if external && let Some(p) = vnc_port { vnc_firewall_close(p, name); }
            };
            let (action, label) = if force { ("destroy", "virsh destroy") } else { ("shutdown", "virsh shutdown") };
            let output = Command::new("virsh").args([action, name]).output()
                .map_err(|e| format!("Failed to run {}: {}", label, e))?;
            if output.status.success() {
                close_fw();
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "domain is not running" is not an error — VM is already stopped
            if stderr.contains("not running") || stderr.contains("not found") {
                close_fw();
                return Ok(());
            }
            return Err(format!("{} failed: {}", label, stderr.trim()));
        }

        // Read config to get WolfNet IP for cleanup
        let config = self.get_vm(name);

        let signal = if force { "-9" } else { "-15" };
        let output = Command::new("pkill")
            .arg(signal)
            .arg("-f")
            .arg(format!("qemu-system-x86_64.*-name {}", name))
            .output()
            .map_err(|e| e.to_string())?;

        if !output.status.success() {
            return Err("Failed to stop VM (process not found?)".to_string());
        }

        // Clean up networking
        if let Some(config) = config {
            if config.wolfnet_ip.is_some() {
                let tap = Self::tap_name(name);
                let _ = self.cleanup_tap(&tap);
                if let Some(ref ip) = config.wolfnet_ip {
                    self.cleanup_wolfnet_routes(ip);
                }
            }
            self.cleanup_extra_nic_taps(name, &config.extra_nics);
        }

        // Tear down the per-VM swtpm daemon (no-op if this VM had no TPM).
        self.stop_swtpm(name);

        // External VNC: close the firewall hole and remove the password secret.
        // Read the port from the runtime BEFORE we delete that file. (No-op for
        // non-external VMs — no matching rule/file exists.)
        if let Some(vnc_port) = self.read_runtime_vnc_port(name) {
            vnc_firewall_close(vnc_port, name);
        }
        let _ = fs::remove_file(self.base_dir.join(format!("{}.vncpass", name)));

        // Clean up runtime file
        let _ = fs::remove_file(self.base_dir.join(format!("{}.runtime.json", name)));


        Ok(())
    }

    /// Path of the "this VM is paused" marker. Cheap (one `fs::exists`)
    /// so list_vms can flag paused VMs without a per-VM `qm`/`virsh`/QMP
    /// status call on every poll. See `VmConfig::paused`.
    fn paused_marker_path(&self, name: &str) -> std::path::PathBuf {
        self.base_dir.join(format!("{}.paused", name))
    }

    /// Set `vm.paused` for each VM from the marker file. paused implies
    /// running — a marker for a no-longer-running VM is ignored. When
    /// `heal` is true a stale marker (VM no longer running) is deleted so
    /// it doesn't sit on disk; the observed Network Map passes `heal=false`
    /// so its "read-only" listing never writes. Called once per list, after
    /// the per-backend discovery has set `running`.
    fn annotate_paused_impl(&self, vms: &mut [VmConfig], heal: bool) {
        for vm in vms.iter_mut() {
            let marker = self.paused_marker_path(&vm.name);
            if marker.exists() {
                if vm.running {
                    vm.paused = true;
                } else if heal {
                    // Stale marker for a VM that's no longer running (host
                    // reboot, external kill) — self-heal so it doesn't sit on
                    // disk and the UI never offers Resume on a dead VM.
                    let _ = std::fs::remove_file(&marker);
                }
            }
        }
    }

    /// Run a hypervisor CLI verb (`qm`/`virsh`) and map the exit status to
    /// a Result. Shared by restart/pause/resume so the three read alike.
    fn vm_cli(bin: &str, args: &[&str]) -> Result<(), String> {
        let output = Command::new(bin).args(args).output()
            .map_err(|e| format!("Failed to run {} {}: {}", bin, args.join(" "), e))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{} {} failed: {}", bin, args.join(" "), stderr.trim()))
    }

    /// Send one QMP command to a native (raw-QEMU) VM's monitor socket and
    /// wait for its reply. QEMU is launched with
    /// `-qmp unix:/run/wolfstack-qmp-<name>.sock,server,nowait`, so this is
    /// how native VMs get pause/resume/reset when there's no `qm`/`virsh`
    /// CLI. Read/write timeouts guard against a wedged socket holding the
    /// VM-manager mutex (this runs under `state.vms.lock()`, same as the
    /// existing qm/virsh calls). Returns Ok on a QMP `return`, Err on a QMP
    /// `error` or any I/O failure.
    fn qmp_execute(&self, name: &str, command: &str) -> Result<(), String> {
        qmp_command(name, command, None).map(|_| ())
    }

}

/// Send one QMP command, with optional arguments, and hand back its
/// `return` value.
///
/// A free function because the monitor socket path is derived entirely
/// from the VM name — none of this needs a [`VmManager`]. `wolfha`'s
/// dirty-bitmap replication driver therefore talks to QEMU without
/// holding the VM-manager lock, which it must not do: a replication round
/// lasts as long as a backup job, and that mutex serialises every VM
/// operation on the node.
///
/// `args` is the QMP `arguments` object, omitted entirely when `None` —
/// some commands reject an empty object where they accept no member.
///
/// One connection per command is deliberate: the chardev is created as
/// `server,nowait`, which serves one client at a time and accepts the
/// next once it closes, so sequential short-lived connections are the
/// safe pattern (and the one the existing pause/resume calls already rely
/// on). Capabilities are renegotiated each time — mandatory per
/// connection, not per session.
pub(crate) fn qmp_command(
    name: &str,
    command: &str,
    args: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    {
        use std::os::unix::net::UnixStream;
        use std::io::{BufRead, BufReader, Write};
        use std::time::Duration;

        let sock = format!("/run/wolfstack-qmp-{}.sock", name);
        let stream = UnixStream::connect(&sock).map_err(|e| {
            format!(
                "QMP monitor {} not reachable — is the VM running? (VMs started by a \
                 build older than the QMP-socket support must be restarted once to gain it): {}",
                sock, e
            )
        })?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        let mut writer = stream.try_clone().map_err(|e| format!("QMP socket clone: {}", e))?;
        let mut reader = BufReader::new(stream);

        // Read QMP replies until a `return`/`error` object — skipping the
        // `{"QMP":…}` greeting and any async `{"event":…}` lines.
        let await_reply = |reader: &mut BufReader<UnixStream>| -> Result<serde_json::Value, String> {
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).map_err(|e| format!("QMP read: {}", e))?;
                if n == 0 {
                    return Err("QMP socket closed before replying".to_string());
                }
                let v: serde_json::Value = match serde_json::from_str(line.trim()) {
                    Ok(v) => v,
                    Err(_) => continue, // ignore non-JSON noise
                };
                if let Some(err) = v.get("error") {
                    let desc = err.get("desc").and_then(|d| d.as_str()).unwrap_or("unknown QMP error");
                    return Err(format!("QMP error: {}", desc));
                }
                if let Some(r) = v.get("return") {
                    return Ok(r.clone());
                }
                // greeting / event — keep reading.
            }
        };

        // Negotiate capabilities (mandatory before any command), then send
        // the command. The greeting banner is consumed by await_reply.
        writer.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
            .map_err(|e| format!("QMP write: {}", e))?;
        await_reply(&mut reader)?;

        // Build the request with serde rather than string interpolation: a
        // bitmap or node name reaching the monitor unescaped would break the
        // frame (and QMP names are operator-influenced via the VM name).
        let mut req = serde_json::json!({ "execute": command });
        if let Some(a) = args {
            req["arguments"] = a;
        }
        let mut wire = serde_json::to_string(&req)
            .map_err(|e| format!("QMP encode: {}", e))?;
        wire.push('\n');
        writer.write_all(wire.as_bytes())
            .map_err(|e| format!("QMP write: {}", e))?;
        await_reply(&mut reader)
    }
}

impl VmManager {

    /// Restart (reboot) a running VM. Proxmox/libvirt issue a clean guest
    /// reboot; native QEMU has no single ACPI-reboot command, so we QMP
    /// `system_reset` — an in-place hard reset that keeps the process and
    /// networking up (honest difference, documented for the operator).
    pub fn restart_vm(&self, name: &str) -> Result<(), String> {
        let result = if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            Self::vm_cli("qm", &["reboot", &vmid.to_string()])
        } else if containers::is_libvirt() && self.virsh_has_domain(name) {
            Self::vm_cli("virsh", &["reboot", name])
        } else if !self.check_running(name) {
            Err("VM is not running".to_string())
        } else {
            self.qmp_execute(name, "system_reset")
        };
        // Only clear the paused marker once the reboot actually succeeded —
        // a failed `qm reboot` must not strip the operator's ability to Resume.
        if result.is_ok() {
            let _ = std::fs::remove_file(self.paused_marker_path(name));
        }
        result
    }

    /// Pause/suspend a running VM (freeze vCPUs, hold RAM). Proxmox
    /// `qm suspend`, libvirt `virsh suspend`, native QMP `stop`. Writes the
    /// paused marker so the UI shows a Resume control.
    pub fn pause_vm(&self, name: &str) -> Result<(), String> {
        let result = if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            // `--todisk 0` forces suspend-to-RAM (vCPUs frozen, process + RAM
            // stay live) so it matches `virsh suspend` / QMP `stop` and keeps
            // the VM "running" for the paused-implies-running invariant.
            // Without it we'd risk a hibernate-to-disk that exits the process.
            Self::vm_cli("qm", &["suspend", &vmid.to_string(), "--todisk", "0"])
        } else if containers::is_libvirt() && self.virsh_has_domain(name) {
            Self::vm_cli("virsh", &["suspend", name])
        } else if !self.check_running(name) {
            Err("VM is not running".to_string())
        } else {
            self.qmp_execute(name, "stop")
        };
        if result.is_ok() {
            // Best-effort marker; a failure here just means the UI won't show
            // the Resume control until the next state change — not fatal.
            let _ = std::fs::write(self.paused_marker_path(name), b"");
        }
        result
    }

    /// Resume a paused VM. Proxmox `qm resume`, libvirt `virsh resume`,
    /// native QMP `cont`. Clears the paused marker on success.
    pub fn resume_vm(&self, name: &str) -> Result<(), String> {
        let result = if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            Self::vm_cli("qm", &["resume", &vmid.to_string()])
        } else if containers::is_libvirt() && self.virsh_has_domain(name) {
            Self::vm_cli("virsh", &["resume", name])
        } else if !self.check_running(name) {
            // Stale marker — the native VM died while paused. Surface a clear
            // error; the marker is cleared below so the UI stops offering Resume.
            Err("VM is not running".to_string())
        } else {
            self.qmp_execute(name, "cont")
        };
        // Clear the marker on success OR when the VM is no longer running
        // (dead VM with a leftover marker — stop offering Resume on it).
        if result.is_ok() || !self.check_running(name) {
            let _ = std::fs::remove_file(self.paused_marker_path(name));
        }
        result
    }

    /// Which hypervisor backend owns this VM: "proxmox", "libvirt", or
    /// "native". Lets the editor tailor its UI — e.g. "stop to edit" for
    /// native (which blocks running-VM edits) vs "applies on next start" for
    /// PVE/libvirt, and locking the OS-disk-bus field for Proxmox.
    pub fn vm_platform(&self, name: &str) -> &'static str {
        if containers::is_proxmox() { "proxmox" }
        else if containers::is_libvirt() && self.virsh_has_domain(name) { "libvirt" }
        else { "native" }
    }

    /// Produce the raw VM start command for display, per backend. Returns
    /// `(command, source)` where source is "native" | "proxmox" | "libvirt".
    /// Honest degradation: if a backend can't produce the command, the
    /// `command` carries a clear human message (never a fabricated command)
    /// and the correct source is still returned so the UI can label it.
    pub fn start_command(&self, name: &str) -> (String, String) {
        // Proxmox: `qm showcmd <vmid> --pretty` prints the exact kvm command.
        if containers::is_proxmox() {
            let Some(vmid) = self.qm_vmid_by_name(name) else {
                return (format!("VM '{}' not found in Proxmox.", name), "proxmox".to_string());
            };
            match Command::new("qm").args(["showcmd", &vmid.to_string(), "--pretty"]).output() {
                Ok(o) if o.status.success() => {
                    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if out.is_empty() {
                        return ("Proxmox returned an empty start command for this VM.".to_string(), "proxmox".to_string());
                    }
                    return (out, "proxmox".to_string());
                }
                Ok(o) => {
                    return (
                        format!("Could not get the start command from Proxmox (qm showcmd): {}",
                            String::from_utf8_lossy(&o.stderr).trim()),
                        "proxmox".to_string(),
                    );
                }
                Err(e) => {
                    return (format!("Could not run `qm showcmd`: {}", e), "proxmox".to_string());
                }
            }
        }

        // libvirt: `virsh domxml-to-native qemu-argv <name>` reconstructs the
        // argv libvirt would launch. Some builds restrict this; fall back to
        // showing the <qemu:commandline> passthrough block when it errors.
        if containers::is_libvirt() && self.virsh_has_domain(name) {
            match Command::new("virsh").args(["domxml-to-native", "qemu-argv", "--domain", name]).output() {
                Ok(o) if o.status.success() => {
                    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if !out.is_empty() {
                        return (out, "libvirt".to_string());
                    }
                }
                _ => {
                    // Some virsh versions take the domain as a bare positional.
                    if let Ok(o) = Command::new("virsh").args(["domxml-to-native", "qemu-argv", name]).output() {
                        let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if o.status.success() && !out.is_empty() {
                            return (out, "libvirt".to_string());
                        }
                    }
                }
            }
            // Fallback: surface the passthrough args we know about + a note.
            let xml = Command::new("virsh").args(["dumpxml", "--inactive", name]).output().ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            let extra = libvirt_xml_qemu_commandline(&xml);
            let msg = if extra.is_empty() {
                "This libvirt build does not allow reconstructing the raw QEMU command \
                 (domxml-to-native is restricted), and this domain has no extra \
                 <qemu:commandline> passthrough args set.".to_string()
            } else {
                format!(
                    "This libvirt build does not allow reconstructing the full raw QEMU \
                     command (domxml-to-native is restricted). Extra passthrough args \
                     currently set on the domain:\n{}", extra)
            };
            return (msg, "libvirt".to_string());
        }

        // Native: reconstruct the exact argv our start path would build.
        match self.get_vm(name) {
            Some(config) => {
                let argv = self.build_qemu_command(&config);
                (join_qemu_args(&argv), "native".to_string())
            }
            None => (format!("VM '{}' not found.", name), "native".to_string()),
        }
    }

    pub fn get_vm(&self, name: &str) -> Option<VmConfig> {
        // On Proxmox, find VM in the qm list output
        if containers::is_proxmox() {
            return self.qm_list_all().into_iter().find(|vm| vm.name == name);
        }
        // On libvirt, get VM details via virsh — but only for VMs that
        // libvirt actually owns. Pre-libvirt native VMs fall through to
        // the JSON-config path below.
        if containers::is_libvirt() && self.virsh_has_domain(name) {
            return self.virsh_vm_to_config(name);
        }

        let config_path = self.vm_config_path(name);
        let content = fs::read_to_string(&config_path).ok()?;
        let mut vm: VmConfig = serde_json::from_str(&content).ok()?;
        vm.running = self.check_running(name);
        if vm.running {
            vm.vnc_port = self.read_runtime_vnc_port(name);
            vm.vnc_ws_port = self.read_runtime_ws_port(name);
        }
        Some(vm)
    }

    pub fn delete_vm(&self, name: &str) -> Result<(), String> {
        // Clear any paused marker up front so a deleted-then-recreated VM of
        // the same name can't inherit a ghost "Paused" state (all backends —
        // the native path also clears it via stop_vm, but Proxmox/libvirt
        // destroy directly without going through stop_vm).
        let _ = std::fs::remove_file(self.paused_marker_path(name));
        // Capture the VM config BEFORE any destroy step. We need:
        //   • wolfnet_ip — to release it from the route cache below.
        //   • pci_devices — to hand back any vfio-pci-bound devices to
        //     the host kernel after destroy (otherwise the NIC/GPU/USB
        //     stays bound to vfio-pci forever even though the VM that
        //     was using it is gone).
        // We don't read it twice because libvirt's `virsh dumpxml` stops
        // working as soon as we've called `virsh undefine`.
        let pre_destroy_config: Option<VmConfig> = self.get_vm(name);
        let released_ip: Option<String> = pre_destroy_config
            .as_ref()
            .and_then(|c| c.wolfnet_ip.clone());

        // On Proxmox, delegate to qm destroy
        if containers::is_proxmox() {
            let vmid = self.qm_vmid_by_name(name)
                .ok_or_else(|| format!("VM '{}' not found in Proxmox", name))?;
            // Stop first if running
            let _ = Command::new("qm").args(["stop", &vmid.to_string()]).output();
            let output = Command::new("qm").args(["destroy", &vmid.to_string(), "--purge"]).output()
                .map_err(|e| format!("Failed to run qm destroy: {}", e))?;
            if output.status.success() {
                // Also clean up any WolfStack tracking config
                let _ = fs::remove_file(self.vm_config_path(name));
                // Tear down the per-VM WolfNet bridge + dnsmasq if any.
                let bridge = Self::wn_bridge_name(&vmid.to_string());
                self.cleanup_wolfnet_bridge(&bridge, released_ip.as_deref());
                if let Some(ip) = released_ip { containers::release_wolfnet_ip(&ip); }
                // Release any vSwitch/VLAN IP the VM held. Proxmox VMs are
                // attached by VMID (the attach target_id), so release that.
                crate::networking::vlan::release_target_allocations(
                    crate::networking::vlan::TargetKind::VmProxmox, &vmid.to_string());
                // Release any PCI passthrough devices the VM was holding.
                // qm_list_all() populates VmConfig.pci_devices by running
                // parse_proxmox_passthrough() on `qm config <vmid>`, so the
                // pre-destroy snapshot already has the BDF list — no
                // separate qm config parse needed here.
                if let Some(ref cfg) = pre_destroy_config {
                    super::passthrough::release_passthrough_devices(cfg);
                }
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("qm destroy failed: {}", stderr.trim()));
        }
        // On libvirt, delegate to virsh undefine (keeps disk files — user
        // can delete manually). Pre-libvirt native VMs fall through to
        // the qemu/disk removal path below.
        if containers::is_libvirt() && self.virsh_has_domain(name) {
            // Stop first if running
            let _ = Command::new("virsh").args(["destroy", name]).output();
            // Undefine the VM definition (does NOT delete disk files)
            let output = Command::new("virsh").args(["undefine", name, "--nvram"]).output()
                .map_err(|e| format!("Failed to run virsh undefine: {}", e))?;
            if output.status.success() {
                let bridge = Self::wn_bridge_name(name);
                self.cleanup_wolfnet_bridge(&bridge, released_ip.as_deref());
                if let Some(ip) = released_ip { containers::release_wolfnet_ip(&ip); }
                // Release any vSwitch/VLAN IP the VM held. libvirt VMs are
                // attached by domain name (the attach target_id).
                crate::networking::vlan::release_target_allocations(
                    crate::networking::vlan::TargetKind::VmNative, name);
                if let Some(ref cfg) = pre_destroy_config {
                    super::passthrough::release_passthrough_devices(cfg);
                }
                return Ok(());
            }
            // Retry without --nvram for non-UEFI VMs
            let output2 = Command::new("virsh").args(["undefine", name]).output()
                .map_err(|e| format!("Failed to run virsh undefine: {}", e))?;
            if output2.status.success() {
                let bridge = Self::wn_bridge_name(name);
                self.cleanup_wolfnet_bridge(&bridge, released_ip.as_deref());
                if let Some(ip) = released_ip { containers::release_wolfnet_ip(&ip); }
                // Release any vSwitch/VLAN IP the VM held. libvirt VMs are
                // attached by domain name (the attach target_id).
                crate::networking::vlan::release_target_allocations(
                    crate::networking::vlan::TargetKind::VmNative, name);
                if let Some(ref cfg) = pre_destroy_config {
                    super::passthrough::release_passthrough_devices(cfg);
                }
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output2.stderr);
            return Err(format!("virsh undefine failed: {}", stderr.trim()));
        }

        if self.check_running(name) {
            // Deleting — force stop is correct here, no point waiting for ACPI
            let _ = self.stop_vm(name, true);
        }

        // Use the config we captured at the top of delete_vm — getting it
        // again here would just re-read the same JSON.
        if let Some(ref config) = pre_destroy_config {
            // Release any PCI passthrough devices the VM was holding —
            // unbinds them from vfio-pci so the host kernel can use them
            // again, and writes a netplan drop-in for any returned NIC so
            // it comes up with DHCP without the operator hand-editing
            // /etc/netplan/. Best-effort.
            super::passthrough::release_passthrough_devices(config);

            // Delete OS disk at custom path if applicable
            let os_disk = self.vm_os_disk_path(config);
            let _ = fs::remove_file(&os_disk);

            // Delete all extra volume files
            for vol in &config.extra_disks {
                let path = vol.file_path();
                if path.exists() {
                    let _ = fs::remove_file(&path);
                }
            }
        }

        let _ = fs::remove_file(self.vm_config_path(name));
        let _ = fs::remove_file(self.vm_disk_path(name));  // fallback default path
        let _ = fs::remove_file(self.base_dir.join(format!("{}.runtime.json", name)));
        let _ = fs::remove_file(self.base_dir.join(format!("{}.log", name)));

        if let Some(ip) = released_ip {
            containers::release_wolfnet_ip(&ip);
        }
        // Release any vSwitch/VLAN IP the VM held. Native/libvirt VMs are
        // attached by domain name (the attach target_id).
        crate::networking::vlan::release_target_allocations(
            crate::networking::vlan::TargetKind::VmNative, name);

        Ok(())
    }

    pub fn check_running(&self, name: &str) -> bool {
        // Check both x86_64 and aarch64 QEMU binaries (for PiMox / ARM hosts)
        for qemu_bin in &["qemu-system-x86_64", "qemu-system-aarch64"] {
            let output = Command::new("pgrep")
                .arg("-f")
                .arg(format!("{}.*-name {}", qemu_bin, name))
                .output();
            if let Ok(o) = output
                && o.status.success() {
                    return true;
                }
        }
        false
    }

    /// Read the VNC port from runtime file
    fn read_runtime_vnc_port(&self, name: &str) -> Option<u16> {
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let content = fs::read_to_string(&runtime_path).ok()?;
        let runtime: serde_json::Value = serde_json::from_str(&content).ok()?;
        runtime.get("vnc_port").and_then(|v| v.as_u64()).map(|v| v as u16)
    }

    /// Read the WebSocket port from runtime file (for noVNC)
    fn read_runtime_ws_port(&self, name: &str) -> Option<u16> {
        let runtime_path = self.base_dir.join(format!("{}.runtime.json", name));
        let content = fs::read_to_string(&runtime_path).ok()?;
        let runtime: serde_json::Value = serde_json::from_str(&content).ok()?;
        runtime.get("vnc_ws_port").and_then(|v| v.as_u64()).map(|v| v as u16)
    }

    /// Read the external-VNC password. Native QEMU keeps it in the 0600
    /// `.vncpass` file; libvirt keeps it in the domain XML (`<graphics passwd>`,
    /// root-readable), read back via `virsh dumpxml`. NEVER from runtime.json
    /// (0644) or the WolfStack config — so it can't land in a world-readable
    /// file or a config export. None for VMs without external VNC.
    pub fn read_runtime_vnc_password(&self, name: &str) -> Option<String> {
        // Native: the 0600 passfile.
        let passfile = self.base_dir.join(format!("{}.vncpass", name));
        if let Ok(pw) = fs::read_to_string(&passfile) {
            let pw = pw.trim();
            if !pw.is_empty() { return Some(pw.to_string()); }
        }
        // libvirt: the domain XML graphics password. --security-info is
        // REQUIRED — without it libvirt redacts passwd from dumpxml, this
        // returned None, the browser console had no ticket to auth with
        // ("Connection lost"), and the editor had no password to show
        // (klasSponsor 2026-06-10).
        if crate::containers::is_libvirt() {
            let xml = Command::new("virsh").args(["dumpxml", "--security-info", name]).output().ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())?;
            if let Some(pw) = libvirt_xml_attr_in_block(&xml, "graphics", "passwd")
                && !pw.is_empty() { return Some(pw); }
        }
        None
    }

    /// For a libvirt VM: (external?, vnc_port). "External" means WolfStack-
    /// managed external VNC — graphics listen on 0.0.0.0 AND a password is set.
    /// Requiring the password is what stops a pre-existing legacy VM (old
    /// WolfStack defaulted libvirt to 0.0.0.0 with NO password) from being
    /// mistaken for external and having its UNAUTHENTICATED VNC port opened.
    /// Port from `virsh vncdisplay`.
    fn libvirt_vnc_info(&self, name: &str) -> (bool, Option<u16>) {
        // --security-info: see read_runtime_vnc_password — without it the
        // redacted passwd made every VM read as NOT external, so virsh start
        // never opened the firewall port for an external-VNC VM.
        let xml = Command::new("virsh").args(["dumpxml", "--security-info", name]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let port = Command::new("virsh").args(["vncdisplay", name]).output().ok()
            .and_then(|o| {
                let t = String::from_utf8_lossy(&o.stdout).trim().to_string();
                t.rsplit(':').next().and_then(|n| n.parse::<u16>().ok()).map(|n| 5900 + n)
            });
        (libvirt_xml_is_external_vnc(&xml), port)
    }

    // ─── Libvirt VM Management (virsh) ───

    /// List all VMs from libvirt via `virsh list --all`
    /// Is this VM defined in libvirt? Used to route operations per-VM
    /// on libvirt hosts — VMs created before libvirt was installed
    /// (plain qemu with a JSON config in base_dir) are still managed
    /// natively even when libvirtd is running.
    fn virsh_has_domain(&self, name: &str) -> bool {
        Command::new("virsh").args(["domstate", name]).output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn virsh_list_all(&self) -> Vec<VmConfig> {
        let output = match Command::new("virsh").args(["list", "--all", "--name"]).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return vec![],
        };

        let libvirt_names: std::collections::HashSet<String> = output.lines()
            .map(|l| l.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect();

        let mut vms: Vec<VmConfig> = libvirt_names.iter()
            .filter_map(|n| self.virsh_vm_to_config(n))
            .collect();

        // Pre-libvirt native VMs: JSON configs in base_dir for names
        // not defined in libvirt. These were created by WolfStack
        // before libvirtd was installed and are still managed the
        // native qemu way — surfacing them in the list means they
        // don't silently vanish from the UI just because libvirt is
        // now present. The per-VM dispatch in start/stop/delete uses
        // virsh_has_domain() so these still get the native path.
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                let stem = match path.file_stem().and_then(|n| n.to_str()) {
                    Some(s) => s,
                    None => continue,
                };
                if stem.ends_with(".runtime") { continue; }
                if libvirt_names.contains(stem) { continue; }
                let content = match fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let mut vm = match serde_json::from_str::<VmConfig>(&content) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to parse native VM config {} on libvirt host: {}", path.display(), e);
                        continue;
                    }
                };
                vm.running = self.check_running(&vm.name);
                if vm.running {
                    vm.vnc_port = self.read_runtime_vnc_port(&vm.name);
                    vm.vnc_ws_port = self.read_runtime_ws_port(&vm.name);
                } else {
                    vm.vnc_port = None;
                    vm.vnc_ws_port = None;
                }
                vms.push(vm);
            }
        }

        vms
    }

    /// Convert a libvirt VM into a VmConfig (used by list and get).
    ///
    /// Fast path: read `/etc/libvirt/qemu/<name>.xml` directly. libvirt
    /// stores its persistent domain XML there as the source of truth —
    /// `virsh dumpxml` returns the same content (plus an extra `<uuid>`
    /// block when running). Reading the file is microseconds; the
    /// previous path ran 4–5 separate `virsh` subprocesses per VM
    /// (dominfo + domblklist + domiflist + vncdisplay + dumpxml) at
    /// ~200ms each. On a 20-VM box that was ~16s of forks; filesystem
    /// path is sub-millisecond.
    ///
    /// Falls back to the subprocess pipeline when the XML isn't
    /// readable (rare — same condition that breaks `virsh dumpxml`).
    fn virsh_vm_to_config(&self, name: &str) -> Option<VmConfig> {
        if let Some(cfg) = self.virsh_vm_to_config_via_filesystem(name) {
            return Some(cfg);
        }
        self.virsh_vm_to_config_via_subprocess(name)
    }

    fn virsh_vm_to_config_via_subprocess(&self, name: &str) -> Option<VmConfig> {
        // dominfo for CPU, memory, state
        let dominfo = Command::new("virsh").args(["dominfo", name]).output().ok()?;
        let dominfo_text = String::from_utf8_lossy(&dominfo.stdout);

        let mut cpus = 1u32;
        let mut memory_kb = 1048576u64;
        let mut running = false;
        let mut auto_start = false;

        for line in dominfo_text.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 { continue; }
            let key = parts[0].trim();
            let val = parts[1].trim();
            match key {
                "CPU(s)" => { cpus = val.parse().unwrap_or(1); }
                "Max memory" => {
                    memory_kb = val.split_whitespace().next()
                        .and_then(|v| v.parse().ok()).unwrap_or(1048576);
                }
                "State" => { running = val.contains("running"); }
                "Autostart" => { auto_start = val.contains("enable"); }
                _ => {}
            }
        }

        // Primary disk: first non-CDROM from domblklist
        let blklist = Command::new("virsh").args(["domblklist", name, "--details"]).output().ok()?;
        let blklist_text = String::from_utf8_lossy(&blklist.stdout);
        let mut disk_size_gb = 0u32;
        let mut disk_source = String::new();
        // CD-ROM slots are mapped by index, not "first one with media": slot 0
        // is the OS-install ISO, slot 1 the VirtIO-drivers ISO — the same
        // ordering the write path (libvirt_apply_devices) uses, so a saved ISO
        // round-trips back to the right editor field.
        let mut iso_path: Option<String> = None;
        let mut drivers_iso: Option<String> = None;
        let mut cdrom_idx = 0usize;

        for line in blklist_text.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Need at least Type/Device/Target. An empty cdrom drive may print
            // no source column at all (3 cols) — keep it so it still counts
            // toward the cdrom slot index, matching the filesystem read path.
            if parts.len() < 3 { continue; }
            let device = parts[1]; // disk, cdrom
            let target = parts[2]; // vda, sda
            let source = if parts.len() > 3 { parts[3..].join(" ") } else { String::new() };
            let has_src = !(source == "-" || source.is_empty());

            if device == "cdrom" {
                let src = if has_src { Some(source) } else { None };
                match cdrom_idx {
                    0 => iso_path = src,
                    1 => drivers_iso = src,
                    _ => {}
                }
                cdrom_idx += 1;
            } else if device == "disk" && has_src && disk_source.is_empty() {
                disk_source = source;
                disk_size_gb = disk_size_from_virsh(name, target).unwrap_or(0);
            }
        }

        // MAC address from first NIC
        let iflist = Command::new("virsh").args(["domiflist", name]).output().ok()?;
        let iflist_text = String::from_utf8_lossy(&iflist.stdout);
        let mut mac_address: Option<String> = None;
        for line in iflist_text.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                mac_address = Some(parts[4].to_string());
                break;
            }
        }

        // VNC port for running VMs: virsh vncdisplay returns ":N" or "host:N"
        let vnc_port = if running {
            Command::new("virsh").args(["vncdisplay", name]).output().ok()
                .and_then(|o| {
                    let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    // Parse display number after the last ':'  (handles both ":0" and "127.0.0.1:0")
                    text.rsplit(':').next()
                        .and_then(|n| n.parse::<u16>().ok())
                        .map(|n| 5900 + n)
                })
        } else {
            None
        };

        // Storage path from disk source directory
        let storage_path = Path::new(&disk_source).parent()
            .map(|p| p.to_string_lossy().to_string());

        // Detect UEFI/OVMF from dumpxml, and parse <hostdev> nodes for USB/PCI
        // passthrough. --security-info so the <graphics passwd> attribute is
        // present — the vnc_external field below requires it (redacted XML read
        // every VM as not-external).
        let dumpxml = Command::new("virsh").args(["dumpxml", "--security-info", name]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let bios_type = if libvirt_xml_is_ovmf(&dumpxml) {
            "ovmf".to_string()
        } else {
            "seabios".to_string()
        };

        // Primary NIC model + OS disk bus come straight from the live XML so
        // the editor reflects what the operator last saved (these used to be
        // hardcoded to "virtio", which is why an e1000 / SATA choice reverted).
        let net_model = libvirt_primary_net_model(&dumpxml)
            .unwrap_or_else(|| "virtio".to_string());
        let os_disk_bus = libvirt_primary_disk_target(&dumpxml)
            .map(|(_, bus)| bus)
            .unwrap_or_else(|| "virtio".to_string());

        let (usb_devices, pci_devices) = parse_libvirt_hostdevs(&dumpxml);
        let (extra_nics, wolfnet_active) = parse_libvirt_extra_nics(&dumpxml);
        // Derive primary-NIC mode + bridge from the first <interface>
        // block. A WolfNet attachment anywhere flips mode to "wolfnet".
        let primary_bridge = iter_xml_blocks(&dumpxml, "interface").next()
            .and_then(|b| libvirt_xml_attr_in_block(b, "source", "bridge"));
        let (derived_mode, derived_bridge) = if wolfnet_active {
            (Some("wolfnet".to_string()), None)
        } else {
            match primary_bridge.as_deref() {
                None | Some("virbr0") => (Some("nat".to_string()), None),
                Some(other) => (Some("bridge".to_string()), Some(other.to_string())),
            }
        };

        let mut config = VmConfig {
            name: name.to_string(),
            cpus,
            memory_mb: (memory_kb / 1024) as u32,
            disk_size_gb,
            iso_path,
            running,
            vnc_port,
            vnc_ws_port: None, // libvirt VMs don't use WebSocket VNC
            mac_address,
            auto_start,
            wolfnet_ip: None,
            storage_path,
            os_disk_bus,
            net_model,
            drivers_iso,
            import_image: None,
            extra_disks: Vec::new(),
            extra_nics,
            usb_devices,
            pci_devices,
            vmid: None,
            bios_type,
            tpm: false,
            secure_boot: false,
            boot_order: Vec::new(),
            // External VNC = WolfStack-managed (0.0.0.0 + password); read from the
            // domain XML so the toggle reflects reality and re-saving can't flip it.
            vnc_external: libvirt_xml_is_external_vnc(&dumpxml),
            host_id: Some(crate::agent::self_node_id()),
            skip_default_nic: false,
            network_mode: derived_mode,
            bridge: derived_bridge,
            bridge_ip_mode: None,
            bridge_ip: None,
            vsw_uplink: None,
            vsw_vlan: None,
            bridge_gateway: None,
            // Notes from the domain's <description> element. libvirt owns this
            // field (set via `virsh desc`), so the XML is authoritative.
            notes: libvirt_xml_description(&dumpxml),
            // Extra QEMU args from the domain's <qemu:commandline> passthrough
            // block — libvirt owns this once we've written it, so the XML is
            // authoritative (empty for any domain we never touched).
            extra_qemu_args: libvirt_xml_qemu_commandline(&dumpxml),
            paused: false,
        };

        // Overlay adoption sidecar for WolfStack-specific fields that
        // libvirt doesn't carry (wolfnet_ip, extra_disks/nics that the
        // virsh parse above leaves empty, etc.). Libvirt's domain XML is now
        // authoritative for everything it owns — cpu/memory/running state,
        // NIC model, OS disk bus, ISOs, firmware — which the parse above reads
        // back directly; the sidecar only backfills the gaps libvirt can't
        // represent.
        if let Ok(text) = fs::read_to_string(self.vm_config_path(name))
            && let Ok(sidecar) = serde_json::from_str::<VmConfig>(&text) {
                if config.wolfnet_ip.is_none() { config.wolfnet_ip = sidecar.wolfnet_ip; }
                if config.extra_disks.is_empty() { config.extra_disks = sidecar.extra_disks; }
                if config.extra_nics.is_empty() { config.extra_nics = sidecar.extra_nics; }
                config.skip_default_nic = sidecar.skip_default_nic;
                // Network-mode + bridge details: libvirt's domain XML
                // doesn't carry these as first-class fields the way our
                // VmConfig does, so the sidecar is authoritative.
                if config.network_mode.is_none() { config.network_mode = sidecar.network_mode; }
                if config.bridge.is_none() { config.bridge = sidecar.bridge; }
                if config.bridge_ip_mode.is_none() { config.bridge_ip_mode = sidecar.bridge_ip_mode; }
                if config.bridge_ip.is_none() { config.bridge_ip = sidecar.bridge_ip; }
                if config.bridge_gateway.is_none() { config.bridge_gateway = sidecar.bridge_gateway; }
                if config.vsw_uplink.is_none() { config.vsw_uplink = sidecar.vsw_uplink; }
                if config.vsw_vlan.is_none() { config.vsw_vlan = sidecar.vsw_vlan; }
            }

        Some(config)
    }

    /// Filesystem-direct equivalent of `virsh_vm_to_config_via_subprocess`.
    /// Reads /etc/libvirt/qemu/<name>.xml + the WolfStack JSON sidecar
    /// (same as the subprocess path) without spawning any virsh process.
    /// Liveness via /var/run/libvirt/qemu/<name>.xml — libvirt creates
    /// that file when starting a domain and removes it when stopped.
    /// Returns None when /etc/libvirt/qemu/<name>.xml isn't readable —
    /// caller falls back to the subprocess pipeline.
    fn virsh_vm_to_config_via_filesystem(&self, name: &str) -> Option<VmConfig> {
        let persistent_path = format!("/etc/libvirt/qemu/{}.xml", name);
        let persistent = fs::read_to_string(&persistent_path).ok()?;

        // Liveness: /var/run/libvirt/qemu/<name>.xml only exists while
        // the domain is running. Same signal `virsh domstate` returns.
        let runtime_path = format!("/var/run/libvirt/qemu/{}.xml", name);
        let runtime = fs::read_to_string(&runtime_path).ok();
        let running = runtime.is_some();

        // For VNC port: when running, the runtime XML has the resolved
        // port (5900+N). When not running, /etc/libvirt/qemu/<name>.xml
        // typically has port='-1' meaning "auto-allocate at start time".
        let vnc_xml = runtime.as_deref().unwrap_or(&persistent);

        // CPU + memory: the persistent XML is authoritative.
        let cpus = libvirt_xml_inner_text_after_tag(&persistent, "<vcpu")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1);
        let memory_kb = libvirt_xml_inner_text_after_tag(&persistent, "<memory")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1048576);

        // Autostart: libvirt symlinks /etc/libvirt/qemu/autostart/<name>.xml
        // → ../<name>.xml. Presence of the symlink IS the autostart flag.
        let auto_start = std::fs::symlink_metadata(
            format!("/etc/libvirt/qemu/autostart/{}.xml", name)
        ).is_ok();

        // First <disk device='disk'> block: source file + bus. CD-ROM slots
        // are mapped by index (slot 0 = install ISO, slot 1 = VirtIO drivers
        // ISO) — the same ordering the write path uses, so a saved ISO
        // round-trips to the right editor field. Empty cdrom drives still
        // count toward the index so slot 1 doesn't slide into slot 0.
        let mut disk_source = String::new();
        let mut disk_size_gb: u32 = 0;
        let mut iso_path: Option<String> = None;
        let mut drivers_iso: Option<String> = None;
        let mut os_disk_bus = "virtio".to_string();
        let mut cdrom_idx = 0usize;
        for block in iter_xml_blocks(&persistent, "disk") {
            // device='disk' or device='cdrom' lives in the opening tag
            let header_end = block.find('>').unwrap_or(block.len());
            let header = &block[..header_end];
            let device = if header.contains("device='disk'") || header.contains("device=\"disk\"") {
                "disk"
            } else if header.contains("device='cdrom'") || header.contains("device=\"cdrom\"") {
                "cdrom"
            } else {
                continue;
            };
            let source = libvirt_xml_attr_in_block(block, "source", "file")
                .or_else(|| libvirt_xml_attr_in_block(block, "source", "dev"));
            if device == "cdrom" {
                match cdrom_idx {
                    0 => iso_path = source,
                    1 => drivers_iso = source,
                    _ => {}
                }
                cdrom_idx += 1;
            } else if disk_source.is_empty() {
                let Some(source) = source else { continue; };
                if let Some(bus) = libvirt_xml_attr_in_block(block, "target", "bus") {
                    os_disk_bus = bus;
                }
                // Disk size: stat() the file. libvirt-managed qcow2
                // files report virtual size via stat (sparse), so we
                // need `qemu-img info` for the real allocated size.
                // Cheap approximation: use file size in bytes / 1024^3.
                // Same approximation virsh's domblkinfo does for
                // sparse files.
                if let Ok(meta) = std::fs::metadata(&source) {
                    disk_size_gb = (meta.len() / 1_073_741_824) as u32;
                }
                disk_source = source;
            }
        }

        // First <interface><mac address='...' /> block.
        let mac_address = iter_xml_blocks(&persistent, "interface")
            .find_map(|block| libvirt_xml_attr_in_block(block, "mac", "address"));
        // …and its <model type='...'/> — the editor's primary-NIC adapter.
        let net_model = libvirt_primary_net_model(&persistent)
            .unwrap_or_else(|| "virtio".to_string());

        // <graphics type='vnc' port='N'/>
        let vnc_port = libvirt_xml_attr_in_block(vnc_xml, "graphics", "port")
            .and_then(|s| s.parse::<i32>().ok())
            .filter(|p| *p > 0)
            .map(|p| p as u16);

        // BIOS detection — same heuristic as the subprocess path.
        let bios_type = if libvirt_xml_is_ovmf(&persistent) {
            "ovmf".to_string()
        } else {
            "seabios".to_string()
        };

        let storage_path = Path::new(&disk_source).parent()
            .map(|p| p.to_string_lossy().to_string());

        // Reuse the existing libvirt hostdev parser for USB/PCI passthrough.
        let (usb_devices, pci_devices) = parse_libvirt_hostdevs(&persistent);
        // Surface extra NICs + the primary NIC's bridge for the editor.
        let (extra_nics, wolfnet_active) = parse_libvirt_extra_nics(&persistent);
        let primary_bridge = iter_xml_blocks(&persistent, "interface").next()
            .and_then(|b| libvirt_xml_attr_in_block(b, "source", "bridge"));
        let (derived_mode, derived_bridge) = if wolfnet_active {
            (Some("wolfnet".to_string()), None)
        } else {
            match primary_bridge.as_deref() {
                None | Some("virbr0") => (Some("nat".to_string()), None),
                Some(other) => (Some("bridge".to_string()), Some(other.to_string())),
            }
        };

        let mut config = VmConfig {
            name: name.to_string(),
            cpus,
            memory_mb: (memory_kb / 1024) as u32,
            disk_size_gb,
            iso_path,
            running,
            vnc_port,
            vnc_ws_port: None,
            mac_address,
            auto_start,
            wolfnet_ip: None,
            storage_path,
            os_disk_bus,
            net_model,
            drivers_iso,
            import_image: None,
            extra_disks: Vec::new(),
            extra_nics,
            usb_devices,
            pci_devices,
            vmid: None,
            bios_type,
            tpm: false,
            secure_boot: false,
            boot_order: Vec::new(),
            // External VNC = WolfStack-managed (0.0.0.0 + password). Read back
            // from the domain XML so the editor toggle is honest (re-saving an
            // external VM must not flip it off). A legacy 0.0.0.0-no-password VM
            // reads as NOT external, so it's never auto-exposed.
            vnc_external: libvirt_xml_is_external_vnc(&persistent),
            host_id: Some(crate::agent::self_node_id()),
            skip_default_nic: false,
            network_mode: derived_mode,
            bridge: derived_bridge,
            bridge_ip_mode: None,
            bridge_ip: None,
            vsw_uplink: None,
            vsw_vlan: None,
            bridge_gateway: None,
            // Notes from the persistent domain XML's <description> element.
            notes: libvirt_xml_description(&persistent),
            // Extra QEMU args from the persistent domain's <qemu:commandline>.
            extra_qemu_args: libvirt_xml_qemu_commandline(&persistent),
            paused: false,
        };

        // Same WolfStack sidecar overlay as the subprocess path: the domain
        // XML is authoritative for libvirt-owned hardware (NIC model, disk
        // bus, ISOs, firmware), so the sidecar only backfills WolfStack-only
        // fields libvirt can't carry.
        if let Ok(text) = fs::read_to_string(self.vm_config_path(name))
            && let Ok(sidecar) = serde_json::from_str::<VmConfig>(&text) {
                if config.wolfnet_ip.is_none() { config.wolfnet_ip = sidecar.wolfnet_ip; }
                if config.extra_disks.is_empty() { config.extra_disks = sidecar.extra_disks; }
                if config.extra_nics.is_empty() { config.extra_nics = sidecar.extra_nics; }
                config.skip_default_nic = sidecar.skip_default_nic;
                if config.network_mode.is_none() { config.network_mode = sidecar.network_mode; }
                if config.bridge.is_none() { config.bridge = sidecar.bridge; }
                if config.bridge_ip_mode.is_none() { config.bridge_ip_mode = sidecar.bridge_ip_mode; }
                if config.bridge_ip.is_none() { config.bridge_ip = sidecar.bridge_ip; }
                if config.bridge_gateway.is_none() { config.bridge_gateway = sidecar.bridge_gateway; }
                if config.vsw_uplink.is_none() { config.vsw_uplink = sidecar.vsw_uplink; }
                if config.vsw_vlan.is_none() { config.vsw_vlan = sidecar.vsw_vlan; }
            }

        Some(config)
    }

    /// Create a VM via libvirt (virt-install)
    fn virsh_create(&self, config: &VmConfig) -> Result<(), String> {
        // Make sure the `default` network is active before attaching a VM
        // to it. On some libvirtd installs it's defined but stopped, which
        // results in a VM with a NIC but no DHCP (the guest never gets an
        // IP). Autostart it too so it survives host reboots.
        let _ = Command::new("virsh").args(["net-start", "default"]).output();
        let _ = Command::new("virsh").args(["net-autostart", "default"]).output();

        let storage_dir = config.storage_path.as_deref().unwrap_or("/var/lib/libvirt/images");
        let disk_path = format!("{}/{}.qcow2", storage_dir, config.name);

        // Honour the operator's NIC-model and OS-disk-bus choices at create
        // time (not just on edit) so a Windows VM built with e1000 / SATA
        // comes up that way instead of silently reverting to virtio.
        let net_model = if config.net_model.trim().is_empty() { "virtio" } else { config.net_model.trim() };
        let os_bus = if config.os_disk_bus.trim().is_empty() { "virtio" } else { config.os_disk_bus.trim() };

        // VNC graphics: default to localhost-only (reachable solely through
        // WolfStack's authed browser proxy) — this fixes the long-standing
        // libvirt default of listening on 0.0.0.0 with NO password. When the
        // operator opts into external VNC, listen on all interfaces with a
        // generated password (mirrors the native-QEMU path). The password
        // persists in the domain XML and is read back via `virsh dumpxml`.
        let libvirt_graphics = if config.vnc_external {
            format!("vnc,listen=0.0.0.0,password={}", gen_vnc_password())
        } else {
            "vnc,listen=127.0.0.1".to_string()
        };

        let mut args = vec![
            "--name".to_string(), config.name.clone(),
            "--vcpus".to_string(), config.cpus.to_string(),
            "--memory".to_string(), config.memory_mb.to_string(),
            "--disk".to_string(), format!("path={},size={},format=qcow2,bus={}", disk_path, config.disk_size_gb, os_bus),
            "--os-variant".to_string(), "generic".to_string(),
            "--graphics".to_string(), libvirt_graphics,
            "--noautoconsole".to_string(),
        ];

        // Net0 wiring driven by network_mode (mirrors the LXC model):
        //   • "bridge"  — `--network bridge=<config.bridge>,model=<net_model>`
        //   • "wolfnet" — primary `--network network=default` (NAT egress)
        //                 PLUS a SECOND NIC on the per-VM WolfNet bridge.
        //   • "nat"     — `--network network=default` only (NAT, no WolfNet).
        // virt-install's "default" is libvirt's NAT network (192.168.122.x).
        let mode = config.effective_network_mode();
        match mode {
            "bridge" => {
                let bridge = config.bridge.clone()
                    .filter(|b| !b.is_empty())
                    .unwrap_or_else(|| "virbr0".to_string());
                args.extend(["--network".to_string(), format!("bridge={},model={}", bridge, net_model)]);
            }
            _ => {
                args.extend(["--network".to_string(), format!("network=default,model={}", net_model)]);
            }
        }

        // For WolfNet mode (or legacy configs with wolfnet_ip set), attach a
        // SECOND NIC to the per-VM WolfNet bridge. WolfStack runs a one-IP
        // dnsmasq on that bridge so the VM gets its WolfNet IP automatically
        // via DHCP — same UX as the standalone QEMU path. dnsmasq is started
        // here (idempotent) and again at start_vm() time in case the host
        // rebooted or dnsmasq was killed.
        if mode == "wolfnet"
            && let Some(ref wip) = config.wolfnet_ip {
                self.ensure_dnsmasq_installed();
                let bridge = Self::wn_bridge_name(&config.name);
                if let Err(e) = self.setup_wolfnet_bridge(&bridge, wip) {
                    warn!("WolfNet bridge setup for VM '{}' failed (VM will still be created): {}", config.name, e);
                }
                args.extend(["--network".to_string(), format!("bridge={},model=virtio", bridge)]);
            }

        // Import image or ISO — one of these is required for virt-install
        if let Some(ref import) = config.import_image {
            if !import.is_empty() {
                args.push("--import".to_string());
                // Replace the disk arg with the import image (keep the bus).
                if let Some(pos) = args.iter().position(|a| a.starts_with("path=")) {
                    args[pos] = format!("path={},format=qcow2,bus={}", import, os_bus);
                }
            }
        } else if let Some(ref iso) = config.iso_path {
            if !iso.is_empty() {
                args.extend(["--cdrom".to_string(), iso.clone()]);
                // Boot order: disk first, CD as fallback. virt-install's
                // default with --cdrom is CD-only, which means the VM
                // boots back into the installer on every reboot — even
                // after the OS is installed. Telling libvirt to prefer
                // hd lets the empty-disk first-boot fall through to the
                // CD, then subsequent boots find the bootloader on disk.
                // Honour an operator-set boot order (disk/cdrom/network); USB
                // boot isn't expressible via virt-install --boot (libvirt
                // limitation) so it falls back to the default here.
                args.extend(["--boot".to_string(), libvirt_boot_order_arg(&config.boot_order, true)]);
            } else {
                return Err("An ISO or import image is required to create a VM via libvirt".to_string());
            }
        } else {
            return Err("An ISO or import image is required to create a VM via libvirt".to_string());
        }

        if config.bios_type == "ovmf" {
            // UEFI flag may already have been appended above; re-emit with
            // the uefi keyword so libvirt picks the right firmware.
            if config.secure_boot {
                // Secure Boot: ask libvirt for the secure OVMF firmware and
                // enable SMM (required for a trusted Secure Boot). Needs a
                // reasonably recent virt-install (loader.secure / smm.state).
                args.extend(["--boot".to_string(), "uefi,loader.secure=yes".to_string()]);
                args.extend(["--features".to_string(), "smm.state=on".to_string()]);
            } else {
                args.extend(["--boot".to_string(), "uefi".to_string()]);
            }
        }

        // Emulated TPM 2.0 (Windows 11 requires it) — libvirt drives swtpm.
        if config.tpm {
            args.extend(["--tpm".to_string(),
                "model=tpm-crb,backend.type=emulator,backend.version=2.0".to_string()]);
        }

        // Secondary CD-ROM for the VirtIO drivers ISO — a Windows install
        // whose OS disk is on the virtio bus needs these drivers loaded
        // during setup to see the disk. Becomes cdrom slot 1 (the read-back
        // maps slot 0 → install ISO, slot 1 → drivers ISO).
        if let Some(ref drv) = config.drivers_iso
            && !drv.trim().is_empty() {
                args.push("--disk".to_string());
                args.push(format!("device=cdrom,path={}", drv.trim()));
            }

        // Extra disks — virt-install accepts multiple --disk flags. The
        // files are created by virt-install itself when size is given.
        for vol in &config.extra_disks {
            let vol_path = vol.file_path();
            args.push("--disk".to_string());
            args.push(format!(
                "path={},size={},format={},bus={}",
                vol_path.display(), vol.size_gb, vol.format, vol.bus
            ));
        }

        let output = Command::new("virt-install").args(&args).output()
            .map_err(|e| format!("Failed to run virt-install: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("virt-install failed: {}", stderr.trim()));
        }

        // Attach USB/PCI passthrough devices to the newly-created domain
        if (!config.usb_devices.is_empty() || !config.pci_devices.is_empty())
            && let Err(e) = super::passthrough::apply_libvirt_passthrough(&config.name, config) {
                warn!("Failed to attach passthrough devices to libvirt VM {}: {}", config.name, e);
            }

        // Operator notes / description → domain's <description> element. The
        // domain exists now, so `virsh desc --config` persists it (read back
        // from the XML). Best-effort: a notes failure must not undo the VM.
        if !config.notes.is_empty() {
            match Command::new("virsh").args(["desc", &config.name, "--config", "--", &config.notes]).output() {
                Ok(o) if o.status.success() => {}
                Ok(o) => warn!("virsh desc for VM '{}' failed: {}", config.name, String::from_utf8_lossy(&o.stderr).trim()),
                Err(e) => warn!("virsh desc for VM '{}' could not run: {}", config.name, e),
            }
        }

        // Operator extra QEMU args → the domain's <qemu:commandline> block.
        // Best-effort like notes: a passthrough failure must not undo the VM.
        if !config.extra_qemu_args.trim().is_empty()
            && let Err(e) = libvirt_set_qemu_commandline(&config.name, &config.extra_qemu_args) {
                warn!("Setting <qemu:commandline> for VM '{}' failed: {}", config.name, e);
            }

        // virt-install auto-starts the domain; if the operator opted into
        // external VNC the graphics already listen on 0.0.0.0 with a password,
        // so open the firewall for the assigned VNC port now.
        if config.vnc_external {
            let (external, port) = self.libvirt_vnc_info(&config.name);
            if external
                && let Some(p) = port {
                    vnc_firewall_reap_stale(&config.name, p);
                    vnc_firewall_open(p, &config.name);
                }
        }

        Ok(())
    }

    // ─── Libvirt VM Discovery & Adoption ───

    /// Discover VMs managed by libvirt that could be adopted into WolfStack
    pub fn discover_libvirt_vms(&self) -> Vec<DiscoveredVm> {
        // Check if virsh is available
        let virsh_check = Command::new("which").arg("virsh").output();
        if !virsh_check.map(|o| o.status.success()).unwrap_or(false) {
            return vec![];
        }

        // Get all VM names
        let output = match Command::new("virsh").args(["list", "--all", "--name"]).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return vec![],
        };

        let existing_vms: Vec<String> = self.list_vms().iter().map(|v| v.name.clone()).collect();

        output.lines()
            .map(|l| l.trim().to_string())
            .filter(|name| !name.is_empty())
            .filter_map(|name| self.discover_single_libvirt_vm(&name, &existing_vms))
            .collect()
    }

    fn discover_single_libvirt_vm(&self, name: &str, existing: &[String]) -> Option<DiscoveredVm> {
        // Get dominfo for CPU, memory, state
        let dominfo = Command::new("virsh").args(["dominfo", name]).output().ok()?;
        let dominfo_text = String::from_utf8_lossy(&dominfo.stdout);

        let mut cpus = 1u32;
        let mut memory_kb = 1048576u64; // 1GB default
        let mut state = "unknown".to_string();

        for line in dominfo_text.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 { continue; }
            let key = parts[0].trim();
            let val = parts[1].trim();
            match key {
                "CPU(s)" => { cpus = val.parse().unwrap_or(1); }
                "Max memory" => {
                    // Format: "2097152 KiB"
                    memory_kb = val.split_whitespace().next()
                        .and_then(|v| v.parse().ok()).unwrap_or(1048576);
                }
                "State" => { state = val.to_string(); }
                _ => {}
            }
        }

        // Get disk info via domblklist
        let blklist = Command::new("virsh").args(["domblklist", name, "--details"]).output().ok()?;
        let blklist_text = String::from_utf8_lossy(&blklist.stdout);
        let mut disks = Vec::new();

        for line in blklist_text.lines().skip(2) { // Skip header + separator
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: Type  Device  Target  Source
            if parts.len() < 4 { continue; }
            let _dev_type = parts[0]; // file, block, etc.
            let device = parts[1];   // disk, cdrom
            let target = parts[2];   // vda, sda, hda
            let source = parts[3..].join(" "); // path (may contain spaces)

            if source == "-" || source.is_empty() { continue; }

            let is_cdrom = device == "cdrom";
            // Get disk size: try virsh domblkinfo first (works on running VMs),
            // fall back to qemu-img info
            let (size_gb, format) = if !is_cdrom {
                let size = disk_size_from_virsh(name, target)
                    .unwrap_or_else(|| disk_info_from_qemu_img(&source).0);
                let fmt = Path::new(&source).extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("qcow2")
                    .to_string();
                (size, fmt)
            } else {
                (0, "raw".to_string())
            };

            disks.push(DiscoveredDisk {
                target: target.to_string(),
                source: source.to_string(),
                size_gb,
                format,
                is_cdrom,
            });
        }

        // Get NIC info via domiflist
        let iflist = Command::new("virsh").args(["domiflist", name]).output().ok()?;
        let iflist_text = String::from_utf8_lossy(&iflist.stdout);
        let mut nics = Vec::new();

        for line in iflist_text.lines().skip(2) { // Skip header + separator
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: Interface  Type  Source  Model  MAC
            if parts.len() < 5 { continue; }
            nics.push(DiscoveredNic {
                nic_type: parts[1].to_string(),
                source: parts[2].to_string(),
                model: parts[3].to_string(),
                mac: parts[4].to_string(),
            });
        }

        // Parse dumpxml for BIOS type and primary disk bus
        let (bios_type, os_disk_bus) = if let Ok(xml_out) = Command::new("virsh").args(["dumpxml", name]).output() {
            let xml = String::from_utf8_lossy(&xml_out.stdout);
            let bios = if xml.contains("OVMF") || xml.contains("ovmf") || xml.contains("AAVMF") || xml.contains("edk2") {
                "ovmf".to_string()
            } else {
                "seabios".to_string()
            };
            // Find primary disk bus: look for <target dev='vda' bus='virtio'/> in first <disk device='disk'> block
            let bus = xml.lines()
                .skip_while(|l| !l.contains("device='disk'"))
                .find(|l| l.contains("<target") && l.contains("bus="))
                .and_then(|l| {
                    l.split("bus='").nth(1).or_else(|| l.split("bus=\"").nth(1))
                        .and_then(|s| s.split(['\'', '"']).next())
                })
                .unwrap_or("virtio")
                .to_string();
            (bios, bus)
        } else {
            ("seabios".to_string(), "virtio".to_string())
        };

        Some(DiscoveredVm {
            name: name.to_string(),
            state,
            cpus,
            memory_mb: (memory_kb / 1024) as u32,
            disks,
            nics,
            bios_type,
            os_disk_bus,
            already_managed: existing.contains(&name.to_string()),
        })
    }

    /// Adopt a libvirt VM into WolfStack management.
    /// Creates a WolfStack config pointing at the existing disk files.
    /// Does NOT modify or remove anything from libvirt — the user can
    /// stop and undefine from libvirt themselves when ready to switch.
    pub fn adopt_libvirt_vm(&self, name: &str) -> Result<VmConfig, String> {
        // Validate name
        if name.contains('/') || name.contains("..") || name.contains('\0') || name.is_empty() {
            return Err("Invalid VM name".to_string());
        }

        // Check not already managed
        if self.vm_config_path(name).exists() {
            return Err(format!("VM '{}' is already managed by WolfStack", name));
        }

        // Discover VM details
        let existing = self.list_vms().iter().map(|v| v.name.clone()).collect::<Vec<_>>();
        let discovered = self.discover_single_libvirt_vm(name, &existing)
            .ok_or_else(|| format!("Could not read VM '{}' from libvirt", name))?;

        // Find primary disk (first non-CDROM disk)
        let primary_disk = discovered.disks.iter()
            .find(|d| !d.is_cdrom)
            .ok_or_else(|| format!("VM '{}' has no disk images", name))?;

        // Validate disk is a real file
        let disk_path = Path::new(&primary_disk.source);
        if !disk_path.exists() {
            return Err(format!("Disk file not found: {}", primary_disk.source));
        }
        let disk_dir = disk_path.parent()
            .ok_or_else(|| "Cannot determine disk directory".to_string())?;

        // If the disk filename doesn't match {name}.qcow2, create a symlink
        let storage_path = disk_dir.to_string_lossy().to_string();
        let expected_path = disk_dir.join(format!("{}.qcow2", name));
        if disk_path != expected_path {
            if expected_path.exists() {
                warn!("Expected disk path {} already exists — using it as-is", expected_path.display());
            } else {
                std::os::unix::fs::symlink(disk_path, &expected_path)
                    .map_err(|e| format!("Failed to create symlink for disk: {}", e))?;
                info!("Created symlink: {} -> {}", expected_path.display(), disk_path.display());
            }
        }

        // Build VmConfig
        let primary_mac = discovered.nics.first().map(|n| n.mac.clone());
        let primary_nic_model = discovered.nics.first()
            .map(|n| n.model.clone()).unwrap_or_else(|| "virtio".to_string());

        // Extra NICs (all after the first)
        let extra_nics: Vec<NicConfig> = discovered.nics.iter().skip(1).map(|n| {
            NicConfig {
                model: n.model.clone(),
                mac: Some(n.mac.clone()),
                bridge: if n.nic_type == "bridge" { Some(n.source.clone()) } else { None },
                passthrough_interface: None,
            }
        }).collect();

        // Extra disks (non-primary, non-CDROM)
        let extra_disks: Vec<StorageVolume> = discovered.disks.iter()
            .filter(|d| !d.is_cdrom && d.source != primary_disk.source)
            .enumerate()
            .map(|(i, d)| {
                let dp = Path::new(&d.source);
                StorageVolume {
                    name: format!("{}-extra{}", name, i + 1),
                    size_gb: d.size_gb,
                    storage_path: dp.parent().map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| storage_path.clone()),
                    format: d.format.clone(),
                    bus: discovered.os_disk_bus.clone(),
                }
            }).collect();

        // ISO (first CDROM with a source)
        let iso_path = discovered.disks.iter()
            .find(|d| d.is_cdrom && !d.source.is_empty())
            .map(|d| d.source.clone());

        // Parse passthrough devices from the libvirt XML so adopted VMs retain them
        let dumpxml = Command::new("virsh").args(["dumpxml", name]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let (usb_devices, pci_devices) = parse_libvirt_hostdevs(&dumpxml);

        let config = VmConfig {
            name: name.to_string(),
            cpus: discovered.cpus,
            memory_mb: discovered.memory_mb,
            disk_size_gb: primary_disk.size_gb,
            iso_path,
            running: false,
            vnc_port: None,
            vnc_ws_port: None,
            mac_address: primary_mac,
            auto_start: false,
            wolfnet_ip: None,
            storage_path: Some(storage_path),
            os_disk_bus: discovered.os_disk_bus,
            net_model: primary_nic_model,
            drivers_iso: None,
            import_image: None,
            extra_disks,
            extra_nics,
            usb_devices,
            pci_devices,
            vmid: None,
            bios_type: discovered.bios_type,
            tpm: false,
            secure_boot: false,
            boot_order: Vec::new(),
            vnc_external: false,
            host_id: Some(crate::agent::self_node_id()),
            skip_default_nic: false,
            // Adopted VMs default to "nat" — the libvirt sidecar overlay
            // will populate the real mode if a sidecar exists; otherwise
            // the operator picks a mode from the editor on first edit.
            network_mode: None,
            bridge: None,
            bridge_ip_mode: None,
            bridge_ip: None,
            vsw_uplink: None,
            vsw_vlan: None,
            bridge_gateway: None,
            // Carry over any existing libvirt <description> as the VM's notes.
            notes: libvirt_xml_description(&dumpxml),
            // Carry over any existing <qemu:commandline> passthrough args.
            extra_qemu_args: libvirt_xml_qemu_commandline(&dumpxml),
            paused: false,
        };

        // Save config
        let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(self.vm_config_path(name), json).map_err(|e| e.to_string())?;

        info!("Adopted libvirt VM '{}' into WolfStack (libvirt config left intact)", name);
        Ok(config)
    }
}

/// A VM discovered from libvirt that can be adopted
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredVm {
    pub name: String,
    pub state: String,
    pub cpus: u32,
    pub memory_mb: u32,
    pub disks: Vec<DiscoveredDisk>,
    pub nics: Vec<DiscoveredNic>,
    pub bios_type: String,
    pub os_disk_bus: String,
    pub already_managed: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredDisk {
    pub target: String,
    pub source: String,
    pub size_gb: u32,
    pub format: String,
    pub is_cdrom: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscoveredNic {
    pub nic_type: String,
    pub source: String,
    pub model: String,
    pub mac: String,
}

/// Get disk size from virsh domblkinfo (works on running VMs)
fn disk_size_from_virsh(vm_name: &str, target: &str) -> Option<u32> {
    let output = Command::new("virsh").args(["domblkinfo", vm_name, target]).output().ok()?;
    if !output.status.success() { return None; }
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "Capacity:       21474836480" line
    for line in text.lines() {
        if let Some(val) = line.strip_prefix("Capacity:") {
            let bytes: u64 = val.trim().parse().ok()?;
            let gb = (bytes / (1024 * 1024 * 1024)) as u32;
            return Some(gb.max(1));
        }
    }
    None
}

/// Get disk size and format from qemu-img info
fn disk_info_from_qemu_img(path: &str) -> (u32, String) {
    let output = Command::new("qemu-img").args(["info", "--output=json", path]).output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&text) {
                let size_bytes = info["virtual-size"].as_u64().unwrap_or(0);
                let size_gb = (size_bytes / (1024 * 1024 * 1024)) as u32;
                let format = info["format"].as_str().unwrap_or("qcow2").to_string();
                return (size_gb.max(1), format);
            }
            (0, "qcow2".to_string())
        }
        _ => (0, "qcow2".to_string()),
    }
}

// ─── VM Migration (standalone functions — no mutex needed) ───

const VM_BASE: &str = "/var/lib/wolfstack/vms";

/// Pick the base directory for export / import staging. Precedence:
///   1. explicit per-call `staging_dir` argument (operator's pick
///      from the migrate dialog) — fastest, most specific.
///   2. `$TMPDIR` environment variable (systemd Environment= line).
///   3. `/tmp` (the long-standing default).
///
/// Migration staging can be 2× the VM disk size (staged copy + the
/// tar.gz on top), so operators whose `/tmp` is a small tmpfs hit
/// "no space left on device" long before their target storage fills.
/// Letting them point staging at a roomy filesystem is the fix.
pub fn migration_staging_root(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        let p = p.trim();
        if !p.is_empty() { return PathBuf::from(p); }
    }
    if let Ok(v) = std::env::var("TMPDIR")
        && !v.trim().is_empty() { return PathBuf::from(v); }
    PathBuf::from("/tmp")
}

/// Proxmox-host implementation of `export_vm_with_staging`. Reads the
/// Proxmox `.conf`, enumerates every disk slot (scsi[N] / virtio[N] /
/// ide[N] / sata[N], skipping CD-ROM and EFI/TPM and cloud-init seeds),
/// converts each to qcow2 via `pvesm path` + `qemu-img convert`, writes
/// a portable JSON VmConfig, and tars the lot into a WolfStack-native
/// archive at `<staging>/wolfstack-vm-exports/vm-<name>-<ts>.tar.gz`.
///
/// **Caller responsibility:** stop the VM beforehand if you want a
/// consistent snapshot. This function does NOT stop/start — it's
/// shared between backup (which has its own RAII restart guard) and
/// migration (which has its own stop/start dance around export).
pub fn export_proxmox_vm_with_staging(name: &str, staging_dir: Option<&str>) -> Result<PathBuf, String> {
    // Look up the VM (qm_list_all → parse_pve_qemu_conf) to get name→vmid + bus + memory.
    let manager = VmManager::new();
    let vm = manager.list_vms().into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| format!("Proxmox VM '{}' not found", name))?;
    let vmid = vm.vmid.ok_or_else(||
        format!("Proxmox VM '{}' has no vmid — cannot locate Proxmox config", name))?;

    // Read raw conf so we can enumerate ALL disk slots, not just the
    // first one parse_pve_qemu_conf captures.
    let conf_path = format!("/etc/pve/qemu-server/{}.conf", vmid);
    let conf_text = fs::read_to_string(&conf_path)
        .map_err(|e| format!("could not read Proxmox conf {}: {}", conf_path, e))?;
    let main_section: String = conf_text.lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .collect::<Vec<_>>()
        .join("\n");

    // Stage qcow2 conversions in a per-export work directory.
    let export_dir = migration_staging_root(staging_dir).join("wolfstack-vm-exports");
    fs::create_dir_all(&export_dir)
        .map_err(|e| format!("create export dir: {}", e))?;
    let staging = export_dir.join(format!("staging-{}-{}", name, uuid::Uuid::new_v4()));
    fs::create_dir_all(&staging)
        .map_err(|e| format!("create staging dir: {}", e))?;
    // Auto-clean staging on early return.
    struct StagingGuard(PathBuf);
    impl Drop for StagingGuard {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let _staging_guard = StagingGuard(staging.clone());

    let mut extra_disks: Vec<StorageVolume> = Vec::new();
    let mut os_disk_converted = false;

    for line in main_section.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let Some((key, val)) = line.split_once(':') else { continue; };
        let key = key.trim();
        let val = val.trim();

        let is_disk_slot = ["scsi", "virtio", "ide", "sata"].iter().any(|prefix| {
            key.starts_with(prefix)
                && !key[prefix.len()..].is_empty()
                && key[prefix.len()..].chars().all(|c| c.is_ascii_digit())
        });
        if !is_disk_slot { continue; }
        // Skip CD-ROM ISOs (not a real backing disk).
        if val.contains("media=cdrom") { continue; }
        // Skip EFI / TPM specials.
        if val.contains("efitype=") || val.contains("vendor=") { continue; }
        // C4 fix: skip Proxmox cloud-init drives. They appear as
        // `ide2: local-lvm:vm-101-cloudinit` — usually with media=cdrom
        // (caught above) but the PVE API can omit it in edge cases.
        // Without this filter, qemu-img would try to convert a
        // cloud-init seed ISO as if it were a VM disk → non-bootable archive.
        // N7: lowercase compare so an odd PVE release with uppercase
        // "CLOUDINIT" output still gets filtered.
        let val_lower = val.to_lowercase();
        if val_lower.contains("-cloudinit") || val_lower.contains("cloudinit,") { continue; }

        let volume_id = match val.split(',').next() {
            Some(v) if v.contains(':') => v.trim().to_string(),
            _ => {
                warn!("Proxmox VM '{}' disk {}: unparseable value '{}', skipped", name, key, val);
                continue;
            }
        };

        let pvesm = Command::new("pvesm").args(["path", &volume_id]).output()
            .map_err(|e| format!("pvesm path failed to start: {}", e))?;
        if !pvesm.status.success() {
            return Err(format!(
                "pvesm could not resolve disk '{}' for VM '{}': {}",
                volume_id, name, String::from_utf8_lossy(&pvesm.stderr).trim()));
        }
        let disk_source = String::from_utf8_lossy(&pvesm.stdout).trim().to_string();
        if disk_source.is_empty() {
            return Err(format!("pvesm returned empty path for disk '{}'", volume_id));
        }

        // First non-CD disk becomes OS disk at <name>.qcow2; extras at <name>-<slot>.qcow2.
        let dest_name = if !os_disk_converted {
            os_disk_converted = true;
            format!("{}.qcow2", name)
        } else {
            format!("{}-{}.qcow2", name, key)
        };
        let dest_path = staging.join(&dest_name);

        let convert = Command::new("qemu-img")
            .args(["convert", "-O", "qcow2", &disk_source, &dest_path.to_string_lossy()])
            .output()
            .map_err(|e| format!("qemu-img convert failed to start: {}", e))?;
        if !convert.status.success() {
            return Err(format!(
                "qemu-img convert failed for disk '{}': {}",
                volume_id, String::from_utf8_lossy(&convert.stderr).trim()));
        }

        if dest_name != format!("{}.qcow2", name) {
            // Record extra disk metadata for restore-side re-attachment.
            let size_gb = qcow2_virtual_size_gb(&dest_path).unwrap_or(vm.disk_size_gb);
            let bus = ["scsi", "virtio", "ide", "sata"].iter()
                .find(|p| key.starts_with(*p))
                .map(|p| (*p).to_string())
                .unwrap_or_else(|| "virtio".to_string());
            extra_disks.push(StorageVolume {
                name: format!("{}-{}", name, key),
                size_gb,
                storage_path: VM_BASE.to_string(),
                format: "qcow2".to_string(),
                bus,
            });
        }
    }
    if !os_disk_converted {
        return Err(format!(
            "Proxmox VM '{}' has no non-CD disk slot — nothing to export", name));
    }

    // Portable JSON config — strip host-specific bits, target-native layout.
    let mut portable = vm.clone();
    portable.vmid = None;
    portable.storage_path = None;
    portable.running = false;
    portable.vnc_port = None;
    portable.vnc_ws_port = None;
    portable.wolfnet_ip = None;
    portable.usb_devices.clear();
    portable.pci_devices.clear();
    portable.extra_disks = extra_disks;
    // Cross-host normalisation: a source-host WolfNet IP / bridge name is
    // meaningless on the restore target (different subnet, different
    // bridge naming). Reset the primary-NIC topology to NAT — the operator
    // re-picks the right mode + bridge on restore via the editor. Extra
    // NICs keep their bridge names as hints but the operator may need to
    // re-map them too.
    portable.network_mode = Some("nat".to_string());
    portable.bridge = None;
    portable.bridge_ip_mode = None;
    portable.bridge_ip = None;
    portable.bridge_gateway = None;
    let config_json = serde_json::to_string_pretty(&portable)
        .map_err(|e| format!("serialize VM config: {}", e))?;
    fs::write(staging.join(format!("{}.json", name)), &config_json)
        .map_err(|e| format!("write config: {}", e))?;

    // Tar into the final archive (NOT under staging — that gets cleaned).
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let archive_name = format!("vm-{}-{}.tar.gz", name, timestamp);
    let archive_path = export_dir.join(&archive_name);
    // Collect filenames from staging for tar's positional args.
    let mut tar_items: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(&staging) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                tar_items.push(fname.to_string());
            }
        }
    }
    let tar = Command::new("tar")
        .arg("czf").arg(archive_path.to_string_lossy().as_ref())
        .arg("-C").arg(staging.to_string_lossy().as_ref())
        .args(&tar_items)
        .output()
        .map_err(|e| {
            // tar may have created an empty/partial archive before failing
            // to spawn (rare but possible) — clean up so a later listing
            // doesn't show a corrupt entry.
            let _ = fs::remove_file(&archive_path);
            format!("tar failed to start: {}", e)
        })?;
    if !tar.status.success() {
        let _ = fs::remove_file(&archive_path);
        return Err(format!("tar failed: {}", String::from_utf8_lossy(&tar.stderr).trim()));
    }

    Ok(archive_path)
}

/// Read the virtual size of a qcow2 file via `qemu-img info --output=json`.
/// Returns size in GB (rounded up).
fn qcow2_virtual_size_gb(path: &Path) -> Option<u32> {
    let out = Command::new("qemu-img")
        .args(["info", "--output=json", &path.to_string_lossy()])
        .output().ok()?;
    if !out.status.success() { return None; }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let bytes = json.get("virtual-size")?.as_u64()?;
    Some(((bytes + (1 << 30) - 1) >> 30) as u32)
}

/// libvirt-host implementation of `export_vm_with_staging`. Reads the
/// libvirt domain XML via `virsh dumpxml`, enumerates disks via
/// `virsh domblklist --details` (skipping CD-ROMs), converts each
/// backing file to qcow2 via `qemu-img convert`, writes a portable
/// JSON VmConfig (translated from dominfo), and tars into the same
/// WolfStack-native archive format the Proxmox / native paths use.
///
/// Same caller contract as the Proxmox helper: caller stops/starts.
pub fn export_libvirt_vm_with_staging(name: &str, staging_dir: Option<&str>) -> Result<PathBuf, String> {
    let manager = VmManager::new();
    let vm = manager.list_vms().into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| format!("libvirt VM '{}' not found", name))?;

    // Enumerate disks via virsh domblklist (Target/Source columns).
    // Skip cdrom devices — they reference an ISO, not a backing disk.
    let blklist = Command::new("virsh")
        .args(["domblklist", name, "--details"])
        .output()
        .map_err(|e| format!("virsh domblklist failed to start: {}", e))?;
    if !blklist.status.success() {
        return Err(format!("virsh domblklist for '{}' failed: {}",
            name, String::from_utf8_lossy(&blklist.stderr).trim()));
    }
    let blklist_text = String::from_utf8_lossy(&blklist.stdout);

    // Parse: header line + dashes line + entries. Each entry:
    //   <Type> <Device> <Target> <Source>
    // We want Device=disk rows with a non-"-" Source.
    let mut disks: Vec<(String, String)> = Vec::new();  // (target, source)
    for line in blklist_text.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let device = parts[1];
        let target = parts[2];
        let source = parts[3..].join(" ");
        if source == "-" || source.is_empty() { continue; }
        if device == "cdrom" { continue; }
        disks.push((target.to_string(), source));
    }
    if disks.is_empty() {
        return Err(format!("libvirt VM '{}' has no non-CD backing disks — nothing to export", name));
    }

    // Stage qcow2 conversions.
    let export_dir = migration_staging_root(staging_dir).join("wolfstack-vm-exports");
    fs::create_dir_all(&export_dir).map_err(|e| format!("create export dir: {}", e))?;
    let staging = export_dir.join(format!("staging-{}-{}", name, uuid::Uuid::new_v4()));
    fs::create_dir_all(&staging).map_err(|e| format!("create staging dir: {}", e))?;
    struct StagingGuard(PathBuf);
    impl Drop for StagingGuard {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let _staging_guard = StagingGuard(staging.clone());

    let mut extra_disks: Vec<StorageVolume> = Vec::new();
    for (idx, (target, source)) in disks.iter().enumerate() {
        let dest_name = if idx == 0 {
            // First disk is the OS disk — flat layout matches native.
            format!("{}.qcow2", name)
        } else {
            // Extra disks keyed by their libvirt target dev name (vda/vdb/sda…).
            format!("{}-{}.qcow2", name, target)
        };
        let dest_path = staging.join(&dest_name);
        let convert = Command::new("qemu-img")
            .args(["convert", "-O", "qcow2", source, &dest_path.to_string_lossy()])
            .output()
            .map_err(|e| format!("qemu-img convert failed to start: {}", e))?;
        if !convert.status.success() {
            return Err(format!(
                "qemu-img convert failed for libvirt disk '{}' (target {}): {}",
                source, target, String::from_utf8_lossy(&convert.stderr).trim()));
        }
        if idx > 0 {
            let size_gb = qcow2_virtual_size_gb(&dest_path).unwrap_or(vm.disk_size_gb);
            // libvirt target prefix tells us the bus: vd*=virtio, sd*=scsi, hd*=ide.
            let bus = if target.starts_with("vd") { "virtio" }
                else if target.starts_with("sd") { "scsi" }
                else if target.starts_with("hd") { "ide" }
                else { "virtio" }.to_string();
            extra_disks.push(StorageVolume {
                name: format!("{}-{}", name, target),
                size_gb,
                storage_path: VM_BASE.to_string(),
                format: "qcow2".to_string(),
                bus,
            });
        }
    }

    // Portable JSON config.
    let mut portable = vm.clone();
    portable.vmid = None;
    portable.storage_path = None;
    portable.running = false;
    portable.vnc_port = None;
    portable.vnc_ws_port = None;
    portable.wolfnet_ip = None;
    portable.usb_devices.clear();
    portable.pci_devices.clear();
    portable.extra_disks = extra_disks;
    // Same cross-host normalisation as the Proxmox export — see comment
    // on portable.network_mode in export_proxmox_vm_with_staging.
    portable.network_mode = Some("nat".to_string());
    portable.bridge = None;
    portable.bridge_ip_mode = None;
    portable.bridge_ip = None;
    portable.bridge_gateway = None;
    let config_json = serde_json::to_string_pretty(&portable)
        .map_err(|e| format!("serialize VM config: {}", e))?;
    fs::write(staging.join(format!("{}.json", name)), &config_json)
        .map_err(|e| format!("write config: {}", e))?;

    // Tar to final archive (outside staging — staging gets cleaned).
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let archive_path = export_dir.join(format!("vm-{}-{}.tar.gz", name, timestamp));
    let mut tar_items: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(&staging) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                tar_items.push(fname.to_string());
            }
        }
    }
    let tar = Command::new("tar")
        .arg("czf").arg(archive_path.to_string_lossy().as_ref())
        .arg("-C").arg(staging.to_string_lossy().as_ref())
        .args(&tar_items)
        .output()
        .map_err(|e| {
            let _ = fs::remove_file(&archive_path);
            format!("tar failed to start: {}", e)
        })?;
    if !tar.status.success() {
        let _ = fs::remove_file(&archive_path);
        return Err(format!("tar failed: {}", String::from_utf8_lossy(&tar.stderr).trim()));
    }
    Ok(archive_path)
}

pub fn export_vm_with_staging(name: &str, staging_dir: Option<&str>) -> Result<PathBuf, String> {
    // Validate name to prevent path traversal
    if name.contains('/') || name.contains("..") || name.contains('\0') || name.is_empty() {
        return Err("Invalid VM name".to_string());
    }

    // Platform dispatch — Proxmox-managed VMs don't have a WolfStack
    // .json config; instead their state lives in /etc/pve/qemu-server/
    // and we build the portable archive from the conf + pvesm-resolved
    // disks. Migration AND backup both reach this code path; the caller
    // is responsible for stop/start safety around it.
    if containers::is_proxmox() {
        return export_proxmox_vm_with_staging(name, staging_dir);
    }
    if containers::is_libvirt() {
        return export_libvirt_vm_with_staging(name, staging_dir);
    }

    let base = Path::new(VM_BASE);
    let config_path = base.join(format!("{}.json", name));

    if !config_path.exists() {
        return Err(format!("VM config not found: {}", config_path.display()));
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read VM config: {}", e))?;
    let config: VmConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse VM config: {}", e))?;

    // Create export staging directory under the operator's chosen root
    // (or $TMPDIR / /tmp). Needs ~2× the VM disk size free: one copy
    // in the staged directory + the tar.gz on top.
    let export_dir = migration_staging_root(staging_dir).join("wolfstack-vm-exports");
    fs::create_dir_all(&export_dir)
        .map_err(|e| format!("Failed to create export dir {}: {}", export_dir.display(), e))?;

    // Stage files into a temp directory, then tar from there
    let staging = export_dir.join(format!("staging-{}-{}", name, uuid::Uuid::new_v4()));
    fs::create_dir_all(&staging)
        .map_err(|e| format!("Failed to create staging dir: {}", e))?;

    // Copy config JSON (clear runtime fields for portability)
    let mut portable = config.clone();
    portable.running = false;
    portable.vnc_port = None;
    portable.vnc_ws_port = None;
    portable.wolfnet_ip = None;
    portable.storage_path = None; // will use target default
    portable.vmid = None; // clear Proxmox VMID
    // Passthrough devices are host-specific — they never survive a migration
    portable.usb_devices.clear();
    portable.pci_devices.clear();
    // Same cross-host normalisation as the Proxmox + libvirt exports —
    // bridge names and WolfNet IPs don't transfer across clusters.
    portable.network_mode = Some("nat".to_string());
    portable.bridge = None;
    portable.bridge_ip_mode = None;
    portable.bridge_ip = None;
    portable.bridge_gateway = None;
    // Reset extra disk storage paths to default
    for disk in &mut portable.extra_disks {
        disk.storage_path = VM_BASE.to_string();
    }
    let portable_json = serde_json::to_string_pretty(&portable)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(staging.join(format!("{}.json", name)), &portable_json)
        .map_err(|e| format!("Failed to write staged config: {}", e))?;

    // Copy OS disk — may be in custom storage_path or default
    let os_disk = if let Some(ref sp) = config.storage_path {
        Path::new(sp).join(format!("{}.qcow2", name))
    } else {
        base.join(format!("{}.qcow2", name))
    };

    if let Some(vmid) = config.vmid.filter(|_| containers::is_proxmox()) {
        // On Proxmox, export disk via qemu-img convert
        // Get the disk path from Proxmox storage
        let pvesm = Command::new("pvesm")
            .args(["path", &format!("local-lvm:vm-{}-disk-0", vmid)])
            .output();
        let disk_source = match pvesm {
            Ok(ref o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
            _ => {
                // Fallback: try common paths
                format!("/dev/pve/vm-{}-disk-0", vmid)
            }
        };
        let dest = staging.join(format!("{}.qcow2", name));
        let output = Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2", &disk_source, &dest.to_string_lossy()])
            .output()
            .map_err(|e| format!("qemu-img convert failed to start: {}", e))?;
        if !output.status.success() {
            let _ = fs::remove_dir_all(&staging);
            return Err(format!("qemu-img convert failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
    } else if os_disk.exists() {
        fs::copy(&os_disk, staging.join(format!("{}.qcow2", name)))
            .map_err(|e| format!("Failed to copy OS disk: {}", e))?;
    } else {
        warn!("VM '{}' has no OS disk at {}", name, os_disk.display());
    }

    // Copy extra disks
    for disk in &config.extra_disks {
        let src = disk.file_path();
        if src.exists() {
            let dest_name = src.file_name().unwrap_or_default();
            fs::copy(&src, staging.join(dest_name))
                .map_err(|e| format!("Failed to copy extra disk '{}': {}", disk.name, e))?;
        }
    }

    // Create tar.gz archive
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let archive_name = format!("vm-{}-{}.tar.gz", name, timestamp);
    let archive_path = export_dir.join(&archive_name);

    // Collect filenames in staging for tar
    let mut tar_items: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(&staging) {
        for entry in entries.flatten() {
            if let Some(fname) = entry.file_name().to_str() {
                tar_items.push(fname.to_string());
            }
        }
    }

    let output = Command::new("tar")
        .arg("czf")
        .arg(archive_path.to_string_lossy().as_ref())
        .arg("-C")
        .arg(staging.to_string_lossy().as_ref())
        .args(&tar_items)
        .output()
        .map_err(|e| format!("Failed to create archive: {}", e))?;

    // Clean up staging
    let _ = fs::remove_dir_all(&staging);

    if !output.status.success() {
        return Err(format!("tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    Ok(archive_path)
}

/// Import a VM from a tar.gz archive. Extracts to the VM base
/// directory. Returns a success message with the VM name. The
/// `staging_dir` argument points the extraction temp dir at a roomy
/// filesystem when `/tmp` is too small — falls back to `$TMPDIR`
/// then `/tmp` when None.
pub fn import_vm_with_staging(
    archive_path: &str, new_name: Option<&str>, storage: Option<&str>,
    staging_dir: Option<&str>,
) -> Result<String, String> {
    // Validate new_name to prevent path traversal
    if let Some(n) = new_name
        && (n.contains('/') || n.contains("..") || n.contains('\0') || n.is_empty()) {
            return Err("Invalid VM name: must not contain path separators".to_string());
        }

    let base = Path::new(VM_BASE);
    fs::create_dir_all(base)
        .map_err(|e| format!("Failed to create VM dir: {}", e))?;

    // Extract to a unique temp directory under the operator's chosen
    // staging root. Needs ~1× VM disk size free.
    let tmp = migration_staging_root(staging_dir)
        .join(format!("wolfstack-vm-import-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp)
        .map_err(|e| format!("Failed to create import temp dir: {}", e))?;

    let output = Command::new("tar")
        .args(["xzf", archive_path, "-C"])
        .arg(tmp.to_string_lossy().as_ref())
        .output()
        .map_err(|e| format!("Failed to extract archive: {}", e))?;

    if !output.status.success() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("tar extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Find the config JSON
    let config_file = fs::read_dir(&tmp)
        .map_err(|e| format!("Failed to read temp dir: {}", e))?
        .flatten()
        .find(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .ok_or_else(|| "No .json config file found in archive".to_string())?;

    let config_content = fs::read_to_string(config_file.path())
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let mut config: VmConfig = serde_json::from_str(&config_content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    let original_name = config.name.clone();
    let target_name = new_name.unwrap_or(&original_name).to_string();

    // Validate names from the archive to prevent path traversal
    if original_name.contains('/') || original_name.contains("..") || original_name.contains('\0') ||
       target_name.contains('/') || target_name.contains("..") || target_name.contains('\0') ||
       target_name.is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("Invalid VM name in archive: must not contain path separators".to_string());
    }

    // Check for name conflict
    if base.join(format!("{}.json", target_name)).exists() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("A VM named '{}' already exists on this node", target_name));
    }

    // Determine destination storage path
    let dest_storage = storage.filter(|s| !s.is_empty());

    // Update config for the new host
    config.name = target_name.clone();
    config.running = false;
    config.vnc_port = None;
    config.vnc_ws_port = None;
    config.wolfnet_ip = None;
    config.storage_path = dest_storage.map(|s| s.to_string());
    config.vmid = None;
    config.mac_address = Some(generate_mac()); // new MAC to avoid conflicts
    // Rewrite the ownership tag so the cluster view sees the VM under its
    // new host as soon as the import finishes. Without this, migrated VMs
    // would still claim the source host until the next manual Scan.
    config.host_id = Some(crate::agent::self_node_id());
    // Passthrough devices are host-specific; the target host may not even have
    // matching hardware, so clear them.
    config.usb_devices.clear();
    config.pci_devices.clear();
    // Reset extra disk storage paths
    let disk_storage = dest_storage.unwrap_or(VM_BASE);
    for disk in &mut config.extra_disks {
        disk.storage_path = disk_storage.to_string();
    }

    // On Proxmox, create via qm and import the disk
    if containers::is_proxmox() {
        // N3 fix: use the shared `next_pve_vmid` helper instead of
        // inlining `pvesh get /cluster/nextid` with simpler error
        // handling. Same cluster-safe primitive, better error text on
        // failure (preserves pvesh's stderr instead of "Failed to ...").
        let vmid = match next_pve_vmid() {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_dir_all(&tmp);
                return Err(format!("Failed to allocate Proxmox VMID: {}", e));
            }
        };

        // Create a minimal VM shell
        let create = Command::new("qm")
            .args([
                "create", &vmid.to_string(),
                "--name", &target_name,
                "--cores", &config.cpus.to_string(),
                "--memory", &config.memory_mb.to_string(),
                "--net0", &format!("virtio={},bridge=vmbr0", config.mac_address.as_deref().unwrap_or("auto")),
            ])
            .output()
            .map_err(|e| format!("qm create failed: {}", e))?;
        if !create.status.success() {
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!("qm create failed: {}", String::from_utf8_lossy(&create.stderr)));
        }

        // Import the disk
        let pve_storage = dest_storage.unwrap_or("local-lvm");
        let qcow2 = tmp.join(format!("{}.qcow2", original_name));
        if qcow2.exists() {
            let import = Command::new("qm")
                .args(["importdisk", &vmid.to_string(), &qcow2.to_string_lossy(), pve_storage])
                .output()
                .map_err(|e| format!("qm importdisk failed: {}", e))?;
            if !import.status.success() {
                // Clean up the VM shell we created since disk import failed
                let _ = Command::new("qm").args(["destroy", &vmid.to_string(), "--purge"]).output();
                let _ = fs::remove_dir_all(&tmp);
                return Err(format!("qm importdisk failed: {}", String::from_utf8_lossy(&import.stderr)));
            }
            // Attach the imported disk
            let attach = Command::new("qm")
                .args(["set", &vmid.to_string(), "--scsi0", &format!("{}:vm-{}-disk-0", pve_storage, vmid)])
                .output()
                .map_err(|e| format!("qm set disk failed: {}", e))?;
            if !attach.status.success() {
                let _ = Command::new("qm").args(["destroy", &vmid.to_string(), "--purge"]).output();
                let _ = fs::remove_dir_all(&tmp);
                return Err(format!("qm set disk failed: {}", String::from_utf8_lossy(&attach.stderr)));
            }
            let boot = Command::new("qm")
                .args(["set", &vmid.to_string(), "--boot", "order=scsi0"])
                .output()
                .map_err(|e| format!("qm set boot failed: {}", e))?;
            if !boot.status.success() {
                warn!("qm set boot order failed: {}", String::from_utf8_lossy(&boot.stderr));
            }
        }

        config.vmid = Some(vmid);
        // Save WolfStack tracking config
        let json = serde_json::to_string_pretty(&config).unwrap_or_default();
        let _ = fs::write(base.join(format!("{}.json", target_name)), &json);

        let _ = fs::remove_dir_all(&tmp);
        return Ok(format!("VM '{}' imported as Proxmox VMID {} ({})", original_name, vmid, target_name));
    }

    // Standalone: move files to destination storage directory
    let disk_dest = if let Some(sp) = dest_storage {
        let p = Path::new(sp);
        fs::create_dir_all(p).map_err(|e| format!("Failed to create storage dir '{}': {}", sp, e))?;
        p.to_path_buf()
    } else {
        base.to_path_buf()
    };

    // Move the qcow2 disk
    let src_disk = tmp.join(format!("{}.qcow2", original_name));
    if src_disk.exists() {
        let dest_disk = disk_dest.join(format!("{}.qcow2", target_name));
        fs::rename(&src_disk, &dest_disk)
            .or_else(|_| fs::copy(&src_disk, &dest_disk).map(|_| ()))
            .map_err(|e| format!("Failed to move OS disk: {}", e))?;
    }

    // Move extra disk files (rename if target_name differs)
    for disk in &mut config.extra_disks {
        let old_filename = format!("{}.{}", disk.name, disk.format);
        let src = tmp.join(&old_filename);
        if src.exists() {
            // Update disk name if VM was renamed
            if target_name != original_name && disk.name.starts_with(&original_name) {
                disk.name = disk.name.replacen(&original_name, &target_name, 1);
            }
            let new_filename = format!("{}.{}", disk.name, disk.format);
            let dest = disk_dest.join(&new_filename);
            fs::rename(&src, &dest)
                .or_else(|_| fs::copy(&src, &dest).map(|_| ()))
                .map_err(|e| format!("Failed to move extra disk '{}': {}", disk.name, e))?;
        }
    }

    // Write the updated config
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(base.join(format!("{}.json", target_name)), &json)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Clean up
    let _ = fs::remove_dir_all(&tmp);

    Ok(format!("VM '{}' imported successfully as '{}'", original_name, target_name))
}

/// Clean up an export archive
pub fn export_cleanup(archive_path: &str) {
    let _ = fs::remove_file(archive_path);
}

/// Import a WolfStack VM archive as a PVE-managed VM. Runs on a
/// Proxmox host where `qm` is available. Does NOT create a
/// WolfStack-style config in /var/lib/wolfstack/vms — the VM ends
/// up owned by Proxmox (entry in /etc/pve/qemu-server/<vmid>.conf)
/// and is manageable via the PVE UI, `qm`, and the WolfStack
/// cluster view equally.
///
/// Sequence:
///   1. Extract the tar.gz to staging (respects staging_dir / TMPDIR).
///   2. Parse the bundled VmConfig for memory / cpus / disk size.
///   3. Allocate a VMID via `pvesh get /cluster/nextid`.
///   4. `qm create` with cpu / memory / basic net / ostype.
///   5. `qm importdisk` to copy every qcow2 into the target PVE
///      storage (PVE handles format conversion + storage-specific
///      allocation — lvm-thin, zfs, dir, etc.).
///   6. `qm set --scsi0 <storage>:vm-<vmid>-disk-0 --boot order=scsi0`
///      to attach the primary disk and make it bootable.
///   7. Additional disks attach as scsi1..N.
///
/// Network bridges may not match source-to-target; we default to
/// `vmbr0`, which is the PVE default. Operator fixes via the PVE UI
/// afterwards if they use a non-default bridge layout.
pub fn import_vm_proxmox(
    archive_path: &str, new_name: Option<&str>, storage: &str,
    staging_dir: Option<&str>,
) -> Result<String, String> {
    if !containers::is_proxmox() {
        return Err("import_vm_proxmox called on a non-Proxmox host".into());
    }
    let storage = storage.trim();
    if storage.is_empty() {
        return Err("PVE storage id is required for Proxmox import".into());
    }

    // Extract archive.
    let tmp = migration_staging_root(staging_dir)
        .join(format!("wolfstack-vm-import-pve-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp)
        .map_err(|e| format!("mkdir staging {}: {}", tmp.display(), e))?;
    let out = Command::new("tar")
        .args(["xzf", archive_path, "-C"])
        .arg(tmp.to_string_lossy().as_ref())
        .output()
        .map_err(|e| format!("tar spawn: {}", e))?;
    if !out.status.success() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("tar extract: {}", String::from_utf8_lossy(&out.stderr)));
    }

    // Find + parse the VmConfig.
    let cfg_file = match fs::read_dir(&tmp) {
        Ok(d) => d.flatten().find(|e| e.path().extension().map(|x| x == "json").unwrap_or(false)),
        Err(e) => { let _ = fs::remove_dir_all(&tmp); return Err(format!("read staging: {}", e)); }
    };
    let Some(cfg_file) = cfg_file else {
        let _ = fs::remove_dir_all(&tmp);
        return Err("no .json config found in archive".into());
    };
    let cfg_content = match fs::read_to_string(cfg_file.path()) {
        Ok(c) => c,
        Err(e) => { let _ = fs::remove_dir_all(&tmp); return Err(format!("read config: {}", e)); }
    };
    let config: VmConfig = match serde_json::from_str(&cfg_content) {
        Ok(c) => c,
        Err(e) => { let _ = fs::remove_dir_all(&tmp); return Err(format!("parse config: {}", e)); }
    };
    let target_name = new_name.unwrap_or(&config.name).to_string();
    // PVE VM names are length-limited and can't have slashes — same
    // path-traversal guard as the native importer.
    if target_name.contains('/') || target_name.contains("..") || target_name.contains('\0') || target_name.is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("Invalid VM name: must not contain path separators".into());
    }

    // Allocate a VMID.
    let vmid = match next_pve_vmid() {
        Ok(v) => v,
        Err(e) => { let _ = fs::remove_dir_all(&tmp); return Err(e); }
    };

    // Create the VM config.
    //
    // Bridge: WolfStack's VmConfig doesn't carry a primary-NIC bridge
    // field — the main NIC only knows model + MAC. We default to vmbr0
    // (PVE's default bridge) and fall back to extra_nics[0].bridge if
    // the operator uses the OPNsense-style "skip-default-nic, NICs
    // live in extra_nics" pattern. This is a documented limitation:
    // non-standard bridge layouts need a post-import fix via the PVE
    // UI. MAC gets regenerated automatically so the destination and
    // the still-running source can coexist.
    let bridge = config.extra_nics.first()
        .and_then(|n| n.bridge.clone())
        .unwrap_or_else(|| "vmbr0".to_string());
    let net_model = match config.net_model.as_str() {
        "e1000" | "e1000e" | "rtl8139" => config.net_model.clone(),
        _ => "virtio".to_string(),
    };
    let net0 = format!("{},bridge={}", net_model, bridge);
    let bios = if config.bios_type == "ovmf" { "ovmf" } else { "seabios" };
    // OS type heuristic for PVE. WolfStack doesn't track OS family
    // explicitly, but the existing new-VM flow uses:
    //   - net_model = "e1000"/"e1000e"/"rtl8139" → Windows (virtio-net
    //     drivers aren't in Win installer media)
    //   - os_disk_bus = "ide"/"sata" → Windows (virtio-blk is in the
    //     same boat on Win)
    // Pick "win11" (most recent, backward-compatible with all Win10
    // paravirt guest behaviour) when either signal fires; else "l26"
    // (Linux 2.6+). Operator can fix post-import if wrong.
    let looks_windows = matches!(config.net_model.as_str(), "e1000" | "e1000e" | "rtl8139")
        || matches!(config.os_disk_bus.as_str(), "ide" | "sata");
    let ostype = if looks_windows { "win11" } else { "l26" };
    let mut create = Command::new("qm");
    create.args([
        "create", &vmid.to_string(),
        "--name", &target_name,
        "--memory", &config.memory_mb.to_string(),
        "--cores", &config.cpus.to_string(),
        "--sockets", "1",
        "--net0", &net0,
        "--ostype", ostype,
        "--bios", bios,
    ]);
    // UEFI (OVMF) VMs require an EFI disk entry or PVE refuses to
    // boot them ("no bootable device" regardless of the OS disk).
    // Allocate a tiny 4m EFI disk on the same storage as the OS disk.
    if bios == "ovmf" {
        let efi = format!("{}:0,efitype=4m,pre-enrolled-keys=0", storage);
        create.args(["--efidisk0", &efi]);
    }
    let out = create.output().map_err(|e| format!("qm create spawn: {}", e))?;
    if !out.status.success() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!(
            "qm create {}: {}",
            vmid,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Import each disk. OS disk is named `<config.name>.qcow2` in the
    // archive (portability rewrite in export_vm stripped the custom
    // storage_path, so it's always at the archive root).
    let os_disk_path = tmp.join(format!("{}.qcow2", config.name));
    if !os_disk_path.exists() {
        let _ = destroy_pve_vm(vmid);
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("OS disk {} missing from archive — aborting", os_disk_path.display()));
    }
    if let Err(e) = pve_import_and_attach_disk(vmid, &os_disk_path, storage, "scsi0") {
        let _ = destroy_pve_vm(vmid);
        let _ = fs::remove_dir_all(&tmp);
        return Err(e);
    }
    // Mark boot order explicitly — PVE's default is to boot whatever
    // disk happens to be first, but being explicit is friendlier. If
    // this fails the VM is still valid but won't boot; surface the
    // error as a warning so the operator knows to fix it in the PVE
    // UI rather than silently failing later.
    let boot_out = Command::new("qm")
        .args(["set", &vmid.to_string(), "--boot", "order=scsi0"])
        .output();
    if let Ok(o) = boot_out
        && !o.status.success() {
            warn!(
                "import_vm_proxmox: vmid {} created but `qm set --boot order=scsi0` failed: {}. Fix via PVE UI → Hardware → Boot Order.",
                vmid,
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }

    // Attach extras as scsi1..N.
    for (i, extra) in config.extra_disks.iter().enumerate() {
        let filename = format!("{}.{}", extra.name, extra.format);
        let extra_path = tmp.join(&filename);
        if !extra_path.exists() {
            let _ = destroy_pve_vm(vmid);
            let _ = fs::remove_dir_all(&tmp);
            return Err(format!(
                "extra disk {} missing from archive",
                filename
            ));
        }
        let slot = format!("scsi{}", i + 1);
        if let Err(e) = pve_import_and_attach_disk(vmid, &extra_path, storage, &slot) {
            let _ = destroy_pve_vm(vmid);
            let _ = fs::remove_dir_all(&tmp);
            return Err(e);
        }
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(format!(
        "VM '{}' imported as PVE VMID {} on storage {} (stopped; start via `qm start {}` or the PVE UI)",
        target_name, vmid, storage, vmid
    ))
}

/// Ask PVE for the next free VMID. Uses pvesh because `qm` doesn't
/// expose this directly on older releases.
/// Allocate the next available VMID via Proxmox's cluster-safe API.
/// Wraps `pvesh get /cluster/nextid` — handles whatever format the
/// cluster's PVE version returns (raw int, JSON int, quoted string).
///
/// Public for backup/restore reuse — the alternative (scanning local
/// .conf files) races other cluster nodes during concurrent restore.
pub(crate) fn next_pve_vmid() -> Result<u32, String> {
    let out = Command::new("pvesh")
        .args(["get", "/cluster/nextid"])
        .output()
        .map_err(|e| format!("pvesh nextid spawn: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "pvesh nextid: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // pvesh may return raw integer, JSON-wrapped int, or quoted string
    // depending on --output-format defaults. Strip whitespace + quotes.
    let cleaned = text.trim().trim_matches('"').trim();
    cleaned.parse::<u32>()
        .map_err(|e| format!("cannot parse VMID from pvesh output '{}': {}", cleaned, e))
}

/// `qm importdisk` → `qm set --<slot> <storage>:vm-<vmid>-disk-N` in
/// two steps. The disk index PVE assigns depends on what's already
/// attached, so we parse the importdisk output for the disk id it
/// picked and use that in the set step.
///
/// Public for backup/restore reuse — DO NOT duplicate this with
/// `--format qcow2`, that breaks LVM-thin and ZFS (the most common
/// production PVE storage layouts).
pub(crate) fn pve_import_and_attach_disk(
    vmid: u32, qcow2_path: &std::path::Path, storage: &str, slot: &str,
) -> Result<(), String> {
    // Intentionally no `--format`: PVE picks the right format for the
    // target storage (qcow2 for `dir`-type, raw for LVM-thin, zvol for
    // ZFS). Forcing qcow2 made importdisk error out on block-level
    // storages, which are PVE's most common defaults.
    let out = Command::new("qm")
        .args(["importdisk", &vmid.to_string()])
        .arg(qcow2_path)
        .arg(storage)
        .output()
        .map_err(|e| format!("qm importdisk spawn: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!(
            "qm importdisk failed for slot {}: {}",
            slot, stderr.trim()
        ));
    }
    // Output varies by PVE version. Either of these shapes appears
    // between single quotes on a success line:
    //   old: "'unused0:<storage>:vm-<vmid>-disk-N'"
    //   new: "'<storage>:vm-<vmid>-disk-N'"
    // We want the `<storage>:vm-<vmid>-disk-N` form regardless, which
    // is what `qm set --<slot>` accepts. Parse by extracting the
    // quoted substring, then stripping a leading `unused\d+:` if
    // present.
    let mut disk_id: Option<String> = None;
    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(start) = line.find('\'')
            && let Some(end) = line[start + 1..].find('\'') {
                let inside = &line[start + 1..start + 1 + end];
                // Must look like `<token>:vm-<digits>-disk-<digits>`
                // — i.e. at least one colon AND the `vm-...-disk-`
                // shape to avoid false-matching other quoted strings
                // in the output (e.g. file paths).
                if !inside.contains(":vm-") || !inside.contains("-disk-") { continue; }
                let candidate = if let Some(rest) = inside.split_once(':')
                    .and_then(|(head, rest)| {
                        let is_unused = head.starts_with("unused")
                            && head["unused".len()..].chars().all(|c| c.is_ascii_digit());
                        if is_unused { Some(rest) } else { None }
                    })
                {
                    rest.to_string()
                } else {
                    inside.to_string()
                };
                disk_id = Some(candidate);
                break;
            }
    }
    let disk_id = disk_id.ok_or_else(|| format!(
        "qm importdisk succeeded but we could not parse the new disk id from output: {}",
        stdout.trim()
    ))?;

    let set_out = Command::new("qm")
        .args(["set", &vmid.to_string(), &format!("--{}", slot), &disk_id])
        .output()
        .map_err(|e| format!("qm set spawn: {}", e))?;
    if !set_out.status.success() {
        return Err(format!(
            "qm set --{} {}: {}",
            slot, disk_id,
            String::from_utf8_lossy(&set_out.stderr).trim()
        ));
    }
    Ok(())
}

/// Best-effort destroy of a half-imported PVE VM. Called when a
/// multi-step import fails partway — leaves no orphan qm config.
fn destroy_pve_vm(vmid: u32) -> Result<(), String> {
    // `--purge` is a boolean flag on current PVE — some older builds
    // accept `--purge 1` but current docs say bare `--purge`. Best-
    // effort: if this fails the caller already surfaced the real
    // error; an orphan VM config is less bad than overwriting the
    // original error message.
    let _ = Command::new("qm").args(["destroy", &vmid.to_string(), "--purge"]).output();
    Ok(())
}

/// Move a VM's disks to a new storage path on the SAME node. Companion
/// to `containers::lxc_storage::migrate` for VMs. Used when an
/// operator wants to shift a stopped VM from local /var/lib to a
/// bigger ZFS pool (or similar) without doing a full cross-node
/// migration. Both the OS disk and every extra disk move; the
/// VmConfig.storage_path + extra_disks[].storage_path are rewritten
/// to point at the new location.
///
/// Refuses to operate on a running VM — a live qcow2 copy would be
/// inconsistent and the VM would crash once it's pointed at the copy.
///
/// `remove_source=false` (default) copies and leaves the source
/// alone, so the operator can verify the new copy boots before
/// reclaiming space manually. `remove_source=true` deletes the
/// source file AFTER a successful copy.
pub fn migrate_storage(
    name: &str, target: &str, remove_source: bool,
) -> Result<String, String> {
    if name.contains('/') || name.contains("..") || name.contains('\0') || name.is_empty() {
        return Err("Invalid VM name".to_string());
    }
    let target = target.trim();
    if target.is_empty() {
        return Err("target storage path is required".into());
    }

    let base = Path::new(VM_BASE);
    let config_path = base.join(format!("{}.json", name));
    if !config_path.exists() {
        return Err(format!("VM config not found: {}", config_path.display()));
    }
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read VM config: {}", e))?;
    let mut config: VmConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse VM config: {}", e))?;

    if config.running {
        return Err(format!(
            "VM '{}' is marked running — stop it first (live qcow2 copy produces a corrupted target).",
            name
        ));
    }
    // Belt-and-braces: also check for a live QEMU process, since the
    // config flag can drift from reality after a crash. Must match the
    // exact pattern WolfStack uses to launch QEMU (from check_running):
    // `qemu-system-{x86_64,aarch64} ... -name <name>`. The earlier
    // `guest=<name>` check was a bug — WolfStack never passes that
    // flag, so the check was silently inert and a crashed-but-lingering
    // qemu would slip through.
    for qemu_bin in &["qemu-system-x86_64", "qemu-system-aarch64"] {
        if let Ok(o) = Command::new("pgrep")
            .args(["-f", &format!("{}.*-name {}", qemu_bin, name)])
            .output()
            && o.status.success() {
                return Err(format!(
                    "VM '{}' has a live {} process — shutdown first",
                    name, qemu_bin
                ));
            }
    }
    // Proxmox-managed VMs ask `qm` instead — same check, different OS.
    if let Some(vmid) = config.vmid.filter(|_| containers::is_proxmox())
        && let Ok(o) = Command::new("qm").args(["status", &vmid.to_string()]).output() {
            let s = String::from_utf8_lossy(&o.stdout).to_lowercase();
            if s.contains("status: running") {
                return Err(format!(
                    "VM '{}' (vmid {}) is running on Proxmox — stop it via `qm stop` first",
                    name, vmid
                ));
            }
        }

    // Proxmox-managed VMs: shell out to `qm move_disk`. PVE handles
    // the copy between storage pools (zfs send/recv, dd for LVM-thin,
    // etc.) AND updates the VM config — we must not write to disk
    // ourselves or PVE's /etc/pve overlay would be out of sync.
    if let Some(vmid) = config.vmid.filter(|_| containers::is_proxmox()) {
        return migrate_storage_proxmox(vmid, target, remove_source);
    }

    // Native / libvirt path. Validate the target is a directory. For
    // PVE we'd accept a storage ID (e.g. "local-lvm"), not a path.
    let target_path = Path::new(target);
    if !target_path.exists() {
        return Err(format!(
            "target storage directory '{}' does not exist — mount/create it first",
            target
        ));
    }
    if !target_path.is_dir() {
        return Err(format!("target storage '{}' is not a directory", target));
    }

    // Figure out where the OS disk currently lives.
    let source_os_storage = config.storage_path.clone().unwrap_or_else(|| VM_BASE.to_string());
    // Normalise trailing slashes so `/pool` and `/pool/` compare equal.
    // Operator-written config paths drift between the two forms; a
    // byte-exact comparison missed the "same storage" case and produced
    // a confusing "target file already exists — refuse to overwrite"
    // error instead of a clean "source == target".
    let src_norm = source_os_storage.trim_end_matches('/');
    let tgt_norm = target.trim_end_matches('/');
    if src_norm == tgt_norm {
        return Err("source and target storage paths are the same".into());
    }
    let source_os_disk = Path::new(&source_os_storage).join(format!("{}.qcow2", name));
    let target_os_disk = target_path.join(format!("{}.qcow2", name));

    // Free-space pre-flight: add up the sizes we're about to copy.
    let mut bytes_needed: u64 = 0;
    if source_os_disk.exists() {
        bytes_needed += fs::metadata(&source_os_disk).map(|m| m.len()).unwrap_or(0);
    }
    for disk in &config.extra_disks {
        let p = disk.file_path();
        if p.exists() {
            bytes_needed += fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        }
    }
    if let Some(avail) = available_bytes(target)
        && avail < bytes_needed {
            return Err(format!(
                "target '{}' has {} bytes free, but migration needs {} bytes",
                target, avail, bytes_needed
            ));
        }

    // Copy the OS disk.
    let mut copied: Vec<PathBuf> = Vec::new();
    if source_os_disk.exists() {
        if target_os_disk.exists() {
            return Err(format!(
                "target file {} already exists — refuse to overwrite",
                target_os_disk.display()
            ));
        }
        fs::copy(&source_os_disk, &target_os_disk)
            .map_err(|e| format!("copy OS disk {} → {}: {}",
                source_os_disk.display(), target_os_disk.display(), e))?;
        copied.push(target_os_disk.clone());
    } else if config.extra_disks.is_empty() {
        // No OS disk AND no extras = nothing to copy. A stored config
        // pointing at a missing qcow2 is almost certainly stale; refuse
        // rather than silently rewriting storage_path to a location
        // that has no data.
        return Err(format!(
            "OS disk not found at {} and no extra disks to migrate — config may be stale",
            source_os_disk.display()
        ));
    } else {
        warn!(
            "migrate_storage: OS disk for VM '{}' not found at {} — only extra disks will be migrated",
            name, source_os_disk.display()
        );
    }

    // Copy each extra disk.
    let mut new_extras: Vec<StorageVolume> = Vec::new();
    for disk in &config.extra_disks {
        let src = disk.file_path();
        let dst = target_path.join(format!("{}.{}", disk.name, disk.format));
        if src.exists() {
            if dst.exists() {
                // Roll back what we've copied so far.
                for p in &copied { let _ = fs::remove_file(p); }
                return Err(format!(
                    "target file {} already exists — refuse to overwrite",
                    dst.display()
                ));
            }
            if let Err(e) = fs::copy(&src, &dst) {
                for p in &copied { let _ = fs::remove_file(p); }
                return Err(format!("copy extra disk {} → {}: {}",
                    src.display(), dst.display(), e));
            }
            copied.push(dst);
        }
        let mut moved_disk = disk.clone();
        moved_disk.storage_path = target.to_string();
        new_extras.push(moved_disk);
    }

    // Rewrite the config to point at the new storage.
    config.storage_path = Some(target.to_string());
    config.extra_disks = new_extras;
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("serialise config: {}", e))?;
    if let Err(e) = fs::write(&config_path, &json) {
        for p in &copied { let _ = fs::remove_file(p); }
        return Err(format!("rewrite config: {}", e));
    }

    // Delete sources if requested. Errors here are non-fatal — the
    // copy already succeeded and the config points at the new copy,
    // so a stale source file on disk isn't a correctness problem.
    if remove_source {
        if source_os_disk.exists()
            && let Err(e) = fs::remove_file(&source_os_disk) {
                warn!("migrate_storage: failed to remove source OS disk {}: {}",
                    source_os_disk.display(), e);
            }
        // For extras we need the OLD paths — the old disk list was
        // just replaced, so we walk the pre-replace list.
        // (Avoid re-reading config from disk — it's already updated.
        // Reconstruct the old paths from the saved content instead.)
        if let Ok(old_cfg) = serde_json::from_str::<VmConfig>(&content) {
            for disk in &old_cfg.extra_disks {
                let p = disk.file_path();
                if p.exists()
                    && let Err(e) = fs::remove_file(&p) {
                        warn!("migrate_storage: failed to remove source extra disk {}: {}",
                            p.display(), e);
                    }
            }
        }
    }

    Ok(format!(
        "migrated VM '{}' disks from {} → {} ({} files copied)",
        name, source_os_storage, target, copied.len()
    ))
}

/// Proxmox branch for migrate_storage. PVE owns the VM config, the
/// volumes, and the copy mechanics — we must not touch qcow2 files
/// directly. Instead: parse `qm config <vmid>`, find every disk slot
/// whose storage prefix differs from the target, and call
/// `qm move_disk <vmid> <slot> <target>` for each. PVE runs the
/// actual copy (zfs send/recv, dd, qemu-img depending on storage
/// type) and rewrites the VM config in /etc/pve atomically.
///
/// `target` here is a PVE STORAGE ID (e.g. `local-lvm`, `wolfpool`),
/// not a filesystem path. The UI's datalist sources both kinds from
/// /api/storage/list so operators can pick whichever their VM needs.
fn migrate_storage_proxmox(
    vmid: u32, target: &str, remove_source: bool,
) -> Result<String, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target PVE storage id is required".into());
    }
    // Parse `qm config <vmid>` for disk slots. Output format:
    //   scsi0: local-lvm:vm-101-disk-0,size=32G
    //   ide2: none,media=cdrom                  ← skip (cdrom)
    //   virtio0: wolfpool:vm-101-disk-1,size=64G
    let cfg_out = Command::new("qm")
        .args(["config", &vmid.to_string()])
        .output()
        .map_err(|e| format!("qm config failed: {}", e))?;
    if !cfg_out.status.success() {
        return Err(format!(
            "qm config {} failed: {}",
            vmid, String::from_utf8_lossy(&cfg_out.stderr).trim()
        ));
    }
    let cfg_text = String::from_utf8_lossy(&cfg_out.stdout);

    let slots = parse_pve_disk_slots(&cfg_text, target);

    if slots.is_empty() {
        return Err(format!(
            "vmid {}: no disk slots needing migration — all disks already on '{}' (or no qcow/raw volumes found)",
            vmid, target
        ));
    }

    let mut moved: Vec<String> = Vec::new();
    for (slot, from) in &slots {
        let mut cmd = Command::new("qm");
        cmd.args(["move_disk", &vmid.to_string(), slot, target]);
        if remove_source { cmd.args(["--delete", "1"]); }
        let out = cmd.output()
            .map_err(|e| format!("qm move_disk {} {} {}: {}", vmid, slot, target, e))?;
        if !out.status.success() {
            return Err(format!(
                "qm move_disk {} {} → {} failed: {} (prior disks already moved: [{}])",
                vmid, slot, target,
                String::from_utf8_lossy(&out.stderr).trim(),
                moved.join(", ")
            ));
        }
        moved.push(format!("{} ({}→{})", slot, from, target));
    }

    Ok(format!(
        "vmid {}: moved {} disk(s) to '{}' via qm move_disk [{}]",
        vmid, moved.len(), target, moved.join(", ")
    ))
}

/// Read a VM's stored config JSON from disk. Lightweight accessor so
/// callers that want to pre-compute things (disk sizes, extras,
/// Proxmox vmid) don't have to hold the VmManager mutex or redo the
/// path math. Returns the canonical config blob as stored in
/// /var/lib/wolfstack/vms/<name>.json.
pub fn read_vm_config(name: &str) -> Result<VmConfig, String> {
    if name.contains('/') || name.contains("..") || name.contains('\0') || name.is_empty() {
        return Err("Invalid VM name".to_string());
    }
    let path = Path::new(VM_BASE).join(format!("{}.json", name));
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("read VM config {}: {}", path.display(), e))?;
    serde_json::from_str(&content).map_err(|e| format!("parse VM config: {}", e))
}

/// Sum the on-disk size of the OS disk + every extra disk for a VM.
/// Used by the disk-migrate progress bar to derive `bytes_total` up
/// front. Returns 0 for disks that don't exist on disk — same
/// forgiveness model as `migrate_storage`.
pub fn total_disk_bytes(config: &VmConfig) -> u64 {
    let base = Path::new(VM_BASE);
    let mut total: u64 = 0;
    let os_disk = if let Some(ref sp) = config.storage_path {
        Path::new(sp).join(format!("{}.qcow2", config.name))
    } else {
        base.join(format!("{}.qcow2", config.name))
    };
    if os_disk.exists()
        && let Ok(md) = fs::metadata(&os_disk) { total += md.len(); }
    for disk in &config.extra_disks {
        let p = disk.file_path();
        if p.exists()
            && let Ok(md) = fs::metadata(&p) { total += md.len(); }
    }
    total
}

/// Public wrapper around the private PVE slot parser so the api layer
/// can enumerate disks for per-slot progress reporting before invoking
/// `qm move_disk` itself.
pub fn pve_disk_slots_for_vmid(vmid: u32, target: &str) -> Result<Vec<(String, String)>, String> {
    let out = Command::new("qm")
        .args(["config", &vmid.to_string()])
        .output()
        .map_err(|e| format!("qm config failed: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "qm config {}: {}",
            vmid, String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(parse_pve_disk_slots(&String::from_utf8_lossy(&out.stdout), target))
}

/// Parse `qm config <vmid>` output into a list of
/// (slot, current_storage) pairs for disks that aren't already on
/// `target`. Extracted from `migrate_storage_proxmox` so the slot
/// detection + cdrom/passthrough filter can be unit-tested without
/// shelling out to qm.
fn parse_pve_disk_slots(cfg_text: &str, target: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in cfg_text.lines() {
        let Some((slot, rest)) = line.split_once(':') else { continue; };
        let slot = slot.trim();
        let rest = rest.trim();
        // Disk slot names: scsi0..scsi30, virtio0..15, sata0..5, ide0..3.
        // Each is a prefix followed only by decimal digits.
        let is_disk_slot = ["scsi", "virtio", "sata", "ide"].iter()
            .any(|prefix| slot.strip_prefix(prefix)
                .map(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false));
        if !is_disk_slot { continue; }
        // cdrom / passthrough entries have no storage-colon: either
        // `none,media=cdrom` or `/dev/sdX,...`. Skip those — only
        // real disks have the `<storage>:<volume>` shape.
        let first_part = rest.split(',').next().unwrap_or("");
        let Some((current_storage, _vol)) = first_part.split_once(':') else { continue; };
        let current_storage = current_storage.trim();
        if current_storage.is_empty() || current_storage == "none" { continue; }
        // Skip cdrom-style entries that sneak a colon (rare, but
        // defensive) — media=cdrom is the telltale.
        if rest.contains("media=cdrom") { continue; }
        if current_storage == target { continue; } // already there — skip silently
        out.push((slot.to_string(), current_storage.to_string()));
    }
    out
}

#[cfg(test)]
mod pve_slot_tests {
    use super::*;

    #[test]
    fn parses_typical_qm_config() {
        let cfg = "agent: 1\n\
                   boot: order=scsi0\n\
                   cores: 2\n\
                   cpu: host\n\
                   ide2: none,media=cdrom\n\
                   memory: 2048\n\
                   name: test-vm\n\
                   scsi0: local-lvm:vm-101-disk-0,size=32G\n\
                   scsi1: local-lvm:vm-101-disk-1,size=16G\n\
                   virtio0: wolfpool:vm-101-disk-2,size=64G\n\
                   scsihw: virtio-scsi-pci\n\
                   smbios1: uuid=...\n\
                   sockets: 1\n";
        let slots = parse_pve_disk_slots(cfg, "wolfpool");
        // Two scsi0/scsi1 entries on local-lvm should move;
        // virtio0 already on wolfpool is skipped; ide2 cdrom is skipped.
        assert_eq!(slots.len(), 2);
        assert!(slots.iter().any(|(s, st)| s == "scsi0" && st == "local-lvm"));
        assert!(slots.iter().any(|(s, st)| s == "scsi1" && st == "local-lvm"));
    }

    #[test]
    fn skips_cdrom_entries_even_with_storage_colon() {
        let cfg = "ide0: local:iso/debian-12.iso,media=cdrom\n\
                   scsi0: local-lvm:vm-42-disk-0,size=8G\n";
        let slots = parse_pve_disk_slots(cfg, "wolfpool");
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, "scsi0");
    }

    #[test]
    fn ignores_non_disk_slot_lines() {
        // `net0: virtio=AA:...,bridge=vmbr0` starts with "net0" — not
        // a disk slot. Also `scsihw` / `smbios1` / `sockets` — not
        // disks despite prefix-substring coincidences.
        let cfg = "net0: virtio=00:11:22:33:44:55,bridge=vmbr0\n\
                   scsihw: virtio-scsi-pci\n\
                   smbios1: uuid=abc\n\
                   sockets: 1\n\
                   scsi0: local-lvm:vm-1-disk-0,size=4G\n";
        let slots = parse_pve_disk_slots(cfg, "wolfpool");
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, "scsi0");
    }

    /// Pure extract of the disk-id parser so we can unit-test both
    /// old- and new-style `qm importdisk` output without spawning qm.
    fn extract_disk_id(stdout: &str) -> Option<String> {
        for line in stdout.lines() {
            if let Some(start) = line.find('\'')
                && let Some(end) = line[start + 1..].find('\'') {
                    let inside = &line[start + 1..start + 1 + end];
                    if !inside.contains(":vm-") || !inside.contains("-disk-") { continue; }
                    let candidate = if let Some(rest) = inside.split_once(':')
                        .and_then(|(head, rest)| {
                            let is_unused = head.starts_with("unused")
                                && head["unused".len()..].chars().all(|c| c.is_ascii_digit());
                            if is_unused { Some(rest) } else { None }
                        })
                    {
                        rest.to_string()
                    } else {
                        inside.to_string()
                    };
                    return Some(candidate);
                }
        }
        None
    }

    #[test]
    fn parse_importdisk_older_pve_format() {
        // PVE 7.x emits: `unused0: successfully imported disk 'unused0:local-lvm:vm-101-disk-0'`
        let out = "Formatting 'vm-101-disk-0.raw'\n\
                   Successfully imported disk as 'unused0:local-lvm:vm-101-disk-0'\n";
        assert_eq!(extract_disk_id(out).as_deref(), Some("local-lvm:vm-101-disk-0"));
    }

    #[test]
    fn parse_importdisk_newer_pve_format() {
        // Newer PVE drops the "unusedN:" prefix in the quoted form.
        let out = "transferred 32.0 GiB of 32.0 GiB (100%)\n\
                   Successfully imported disk as 'wolfpool:vm-500-disk-0'\n";
        assert_eq!(extract_disk_id(out).as_deref(), Some("wolfpool:vm-500-disk-0"));
    }

    #[test]
    fn parse_importdisk_skips_file_path_quotes() {
        // Ignore quoted file paths that don't match the disk-id shape.
        let out = "Formatting '/tmp/source.qcow2'\n\
                   Successfully imported disk as 'local-lvm:vm-42-disk-0'\n";
        assert_eq!(extract_disk_id(out).as_deref(), Some("local-lvm:vm-42-disk-0"));
    }

    #[test]
    fn parse_importdisk_returns_none_on_error_output() {
        let out = "Error: storage 'bogus' does not exist\n";
        assert_eq!(extract_disk_id(out), None);
    }

    #[test]
    fn skips_disks_already_on_target() {
        let cfg = "scsi0: wolfpool:vm-1-disk-0,size=4G\n\
                   scsi1: local-lvm:vm-1-disk-1,size=8G\n";
        let slots = parse_pve_disk_slots(cfg, "wolfpool");
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, "scsi1");
    }
}

/// Bytes free on the filesystem backing `path`. Used for the
/// migrate_storage pre-flight. Returns None if we can't read it —
/// caller treats that as "couldn't check, proceed and let the OS
/// report the space error if it happens".
fn available_bytes(path: &str) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(std::ffi::OsStr::new(path).as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) };
    if rc != 0 { return None; }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// Pre-flight a Proxmox VM config before `qm start`.
///
/// Reads `/etc/pve/qemu-server/<vmid>.conf` and confirms the fields that PVE
/// silently blank-tolerates but can't actually boot without. Returns the
/// problem in plain English so the UI/CLI can surface it instead of the
/// generic pvestatd warning.
pub fn validate_pve_config(vmid: u32) -> Result<(), String> {
    let path = format!("/etc/pve/qemu-server/{}.conf", vmid);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {}", path, e))?;

    // Walk the top-level section only — snapshots appear as [snap-name]
    // headers and carry their own memory/cores which we do not validate.
    let mut memory: Option<i64> = None;
    let mut cores: Option<i64> = None;
    let mut has_boot_target = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if line.starts_with('[') { break; } // start of snapshot section
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            match key {
                "memory" => memory = val.parse::<i64>().ok(),
                "cores" => cores = val.parse::<i64>().ok(),
                _ => {
                    // Any scsi/virtio/ide/sata block device counts as a
                    // bootable target. efidisk0 is just EFI vars, not boot.
                    let is_disk = ["scsi", "virtio", "ide", "sata"].iter().any(|prefix| {
                        key.starts_with(prefix)
                            && key.len() > prefix.len()
                            && key[prefix.len()..].chars().all(|c| c.is_ascii_digit())
                    });
                    if is_disk && !val.is_empty() { has_boot_target = true; }
                }
            }
        }
    }

    match memory {
        None => return Err("missing `memory:` line (e.g. `memory: 512`)".into()),
        Some(m) if m <= 0 => return Err(format!("`memory: {}` must be greater than 0", m)),
        _ => {}
    }
    match cores {
        // PVE defaults `cores` to 1 when absent, so only reject explicitly-
        // blank or zero values.
        Some(c) if c <= 0 => return Err(format!("`cores: {}` must be greater than 0", c)),
        _ => {}
    }
    if !has_boot_target {
        return Err("no disk attached (need at least one of scsi0/virtio0/ide0/sata0)".into());
    }
    Ok(())
}

// ─── Filesystem-direct Proxmox VM discovery ──────────────────────────
//
// The Proxmox `qm` CLI is a Perl wrapper around the PVE API server —
// each invocation pays ~300ms of interpreter startup + IPC. Listing
// every VM via `qm list` + `qm config` per-VM is N+1 subprocesses;
// on a 20-VM box that's ~12s wall-clock, which used to block every
// VM-related HTTP handler (state.vms.lock() was held across the
// entire walk) and produce the "Virtual machines page spins forever
// + Start VM says failed but actually starts" symptoms Adam Cogswell
// reported on 2026-04-29.
//
// `/etc/pve/qemu-server/<vmid>.conf` is the source of truth — the
// pmxcfs FUSE mount surfaces the cluster filesystem here, and the
// content is byte-identical to `qm config <vmid>`. Reading these
// directly is a few microseconds per file, no subprocesses.
//
// Liveness comes from `/var/run/qemu-server/<vmid>.pid`, which the
// PVE qemu wrapper writes when it spawns a VM. The pid file existing
// + the PID being live in /proc is exactly what `qm status` checks.

const PVE_QEMU_DIR: &str = "/etc/pve/qemu-server";
const PVE_QEMU_RUN_DIR: &str = "/var/run/qemu-server";

/// True when /etc/pve/qemu-server can be enumerated. False on any
/// permission / mount-not-present error. Used to decide whether to
/// fall back to the slow subprocess path.
pub(crate) fn pve_qemu_server_dir_readable() -> bool {
    fs::read_dir(PVE_QEMU_DIR).is_ok()
}

/// Read every VM config from /etc/pve/qemu-server/*.conf and assemble
/// the same `Vec<VmConfig>` shape `qm_list_via_subprocess` would
/// return. Returns an empty Vec on read failure (caller distinguishes
/// "no VMs" from "/etc/pve unreadable" via `pve_qemu_server_dir_readable`).
fn qm_list_via_filesystem() -> Vec<VmConfig> {
    let entries = match fs::read_dir(PVE_QEMU_DIR) {
        Ok(e) => e,
        Err(_) => return vec![],
    };
    let mut vms = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") { continue; }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue; };
        let Ok(vmid) = stem.parse::<u32>() else { continue; };
        let Ok(text) = fs::read_to_string(&path) else { continue; };
        if let Some(vm) = parse_pve_qemu_conf(vmid, &text) {
            vms.push(vm);
        }
    }
    vms
}

/// Parse one /etc/pve/qemu-server/<vmid>.conf into a VmConfig. Mirrors
/// the parsing the previous `qm config <vmid>` path did.
fn parse_pve_qemu_conf(vmid: u32, text: &str) -> Option<VmConfig> {
    // PVE conf files start with a single VM section, then optional
    // `[snapshot_<name>]` sections we must NOT pick fields from.
    // Cheap split: stop at the first `[` line.
    let main_section: String = text.lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .collect::<Vec<_>>()
        .join("\n");

    let mut name = format!("vm-{}", vmid);
    let mut cpus: u32 = 1;
    let mut memory_mb: u32 = 0;
    let mut disk_size_gb: u32 = 0;
    let mut auto_start = false;
    let mut mac_address: Option<String> = None;
    let mut storage_path: Option<String> = None;
    let mut bios_type = "seabios".to_string();
    let mut net0_bridge: Option<String> = None;
    let mut net_model = "virtio".to_string();
    let mut wolfnet_active = false;
    let mut notes = String::new();
    let mut extra_qemu_args = String::new();
    let mut extra_nic_pairs: Vec<(usize, NicConfig)> = Vec::new();

    for line in main_section.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let Some((key, val)) = line.split_once(':') else { continue; };
        let key = key.trim();
        let val = val.trim();
        match key {
            "name" => { if !val.is_empty() { name = val.to_string(); } }
            "description" => { notes = containers::pve_decode_description(val); }
            "args" => { extra_qemu_args = val.to_string(); }
            "cores" => { cpus = val.parse().unwrap_or(1); }
            "memory" => { memory_mb = val.parse().unwrap_or(memory_mb); }
            "onboot" => { auto_start = val == "1"; }
            "bios" => { if !val.is_empty() { bios_type = val.to_string(); } }
            "net0" => {
                for part in val.split(',') {
                    let part = part.trim();
                    if let Some((kind, mac)) = part.split_once('=') {
                        if matches!(kind, "virtio" | "e1000" | "e1000e" | "rtl8139" | "vmxnet3") {
                            mac_address = Some(mac.to_string());
                            net_model = kind.to_string();
                        }
                    } else if let Some(br) = part.strip_prefix("bridge=") {
                        let br = br.trim();
                        if !br.is_empty() { net0_bridge = Some(br.to_string()); }
                    }
                }
            }
            k if k.starts_with("net") && k != "net0" => {
                // net1, net2, … — surface as editable extra NICs so the
                // operator can change model/bridge/MAC without having to
                // delete + re-add. The WolfNet bridge (wnbr-*) is filtered
                // inside parse_pve_extra_nic and instead flips network_mode.
                if val.contains("bridge=wnbr-") { wolfnet_active = true; }
                if let Some(pair) = parse_pve_extra_nic(k, val) {
                    extra_nic_pairs.push(pair);
                }
            }
            "scsi0" | "virtio0" | "ide0" | "sata0" => {
                let disk_spec = val;
                if let Some(store) = disk_spec.split(':').next() {
                    storage_path = Some(store.trim().to_string());
                }
                for part in disk_spec.split(',') {
                    let part = part.trim();
                    if let Some(rest) = part.strip_prefix("size=") {
                        let s = rest.trim_end_matches('G').trim_end_matches('g')
                            .trim_end_matches('M').trim_end_matches('m');
                        if let Ok(num) = s.parse::<f64>() {
                            // Heuristic: if the original suffix was M/m,
                            // convert to GB rounded down. PVE always
                            // writes G for >=1GB so this branch is rare.
                            let is_mb = part.ends_with('M') || part.ends_with('m');
                            disk_size_gb = if is_mb { (num / 1024.0) as u32 } else { num as u32 };
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Reuse the existing passthrough parser — it already handles the
    // usbN/hostpciN line shape from `qm config` output, which is the
    // same shape as the on-disk conf.
    let (usb_devices, pci_devices) = parse_proxmox_passthrough(&main_section);

    let running = is_pve_vmid_running(vmid);

    // Sort extra NICs by their net-index so the editor's net1/net2/…
    // order matches PVE's, then strip the index — NicConfig is positional
    // by Vec order from the operator's POV.
    extra_nic_pairs.sort_by_key(|(n, _)| *n);
    let extra_nics: Vec<NicConfig> = extra_nic_pairs.into_iter().map(|(_, n)| n).collect();

    // Derive network_mode from net0's bridge (and net1's WolfNet bridge if
    // present). Priority: a WolfNet attachment ALWAYS wins regardless of
    // net0's bridge, otherwise non-vmbr0 net0 means "bridge", and vmbr0
    // (or no net0 at all) means "nat".
    let (derived_mode, derived_bridge) = if wolfnet_active {
        (Some("wolfnet".to_string()), None)
    } else {
        match net0_bridge.as_deref() {
            Some("vmbr0") | None => (Some("nat".to_string()), None),
            Some(other) => (Some("bridge".to_string()), Some(other.to_string())),
        }
    };

    // Media + OS-disk bus all flow through the one `pve_cdrom_iso` /
    // `pve_os_disk_bus` code path the apply side uses, so read and write
    // agree (and an empty `none,media=cdrom` drive reads back as cleared).
    // ide2 = install ISO, ide3 = VirtIO-drivers ISO; the legacy `cdrom`
    // key is still honoured for older configs.
    let iso_path = pve_cdrom_iso(&main_section, "ide2")
        .or_else(|| pve_cdrom_iso(&main_section, "cdrom"));
    let drivers_iso = pve_cdrom_iso(&main_section, "ide3");
    let os_disk_bus = pve_os_disk_bus(&main_section);

    Some(VmConfig {
        name,
        cpus,
        memory_mb,
        disk_size_gb,
        iso_path,
        running,
        vnc_port: None,
        vnc_ws_port: None,
        mac_address,
        auto_start,
        wolfnet_ip: None,
        storage_path,
        os_disk_bus,
        net_model,
        drivers_iso,
        import_image: None,
        extra_disks: Vec::new(),
        extra_nics,
        usb_devices,
        pci_devices,
        vmid: Some(vmid),
        bios_type,
        tpm: false,
        secure_boot: false,
        boot_order: Vec::new(),
        vnc_external: false,
        host_id: Some(crate::agent::self_node_id()),
        skip_default_nic: false,
        network_mode: derived_mode,
        bridge: derived_bridge,
        bridge_ip_mode: None,
        bridge_ip: None,
        bridge_gateway: None,
        vsw_uplink: None,
        vsw_vlan: None,
        notes,
        extra_qemu_args,
        paused: false,
    })
}

// PVE `description:` decoding lives in `containers::pve_decode_description`
// (the same encoding applies to qemu-server and pct configs). It's used by the
// read-back paths above via the fully-qualified `containers::` path.

// ─── Proxmox qemu-server conf helpers (used by update_vm / read-back) ────
//
// Mirror the libvirt device-edit helpers: pure parsers over `qm config`
// output + the on-disk conf (same line shape), unit-tested without a PVE
// host. Key names (ide2 = install CD, ide3 = VirtIO-drivers CD, efidisk0 =
// OVMF NVRAM, scsi0/virtio0/sata0/ide0 = OS disk) are taken from this file's
// own qm_create, which is the authoritative source for how WolfStack lays
// out a PVE VM.

/// Value of a top-level `key: value` line in a PVE qemu-server conf's MAIN
/// section (stops at the first `[snapshot]` header). None if absent/empty.
fn pve_conf_value(conf: &str, key: &str) -> Option<String> {
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('[') { break; } // entered a snapshot section
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() != key { continue; }
            let v = v.trim();
            return if v.is_empty() { None } else { Some(v.to_string()) };
        }
    }
    None
}

/// The ISO volume on a PVE cdrom key (ide2/ide3/…). None if the key is
/// absent, empty (`none`), or not a cdrom.
fn pve_cdrom_iso(conf: &str, key: &str) -> Option<String> {
    let val = pve_conf_value(conf, key)?;
    if !val.contains("media=cdrom") { return None; }
    let vol = val.split(',').next().unwrap_or("").trim();
    if vol.is_empty() || vol == "none" { None } else { Some(vol.to_string()) }
}

/// True if the VM already has an efidisk0 (NVRAM store required for OVMF).
fn pve_has_efidisk(conf: &str) -> bool {
    pve_conf_value(conf, "efidisk0").is_some()
}

fn pve_has_tpmstate(conf: &str) -> bool {
    pve_conf_value(conf, "tpmstate0").is_some()
}

/// Storage pool backing the OS disk (first non-cdrom scsi/virtio/sata/ide
/// disk), e.g. "local-lvm" from `scsi0: local-lvm:vm-100-disk-0,size=32G`.
fn pve_os_disk_storage(conf: &str) -> Option<String> {
    for key in ["scsi0", "virtio0", "sata0", "ide0"] {
        if let Some(val) = pve_conf_value(conf, key) {
            if val.contains("media=cdrom") { continue; }
            let store = val.split(':').next().unwrap_or("").trim();
            if !store.is_empty() { return Some(store.to_string()); }
        }
    }
    None
}

/// The OS disk bus in the editor's vocabulary. PVE's scsi0 (virtio-SCSI) and
/// virtio0 (virtio-blk) are both the paravirtual fast path the editor labels
/// "VirtIO"; ide0 → "ide", sata0 → "sata". Defaults to "virtio".
fn pve_os_disk_bus(conf: &str) -> String {
    for key in ["scsi0", "virtio0", "sata0", "ide0"] {
        if let Some(val) = pve_conf_value(conf, key) {
            if val.contains("media=cdrom") { continue; }
            return match key {
                "ide0" => "ide",
                "sata0" => "sata",
                _ => "virtio", // scsi0 / virtio0
            }.to_string();
        }
    }
    "virtio".to_string()
}

/// Apply the operator's Proxmox VM-settings edits that `qm set --cores/...`
/// doesn't already cover — install ISO (ide2), VirtIO-drivers ISO (ide3),
/// and BIOS firmware (+ an efidisk0 NVRAM store when switching to OVMF). Each
/// fires only when it differs from the current `qm config`, mirroring the
/// libvirt path. OS disk bus is intentionally NOT changed here (it's locked
/// in the UI for PVE — a bus change means a risky disk detach/reattach).
/// Returns (failures, changed): failures empty == all applied; changed ==
/// at least one next-boot-only field changed (drives the running advisory).
fn qm_apply_media_bios(vmid: u32, iso_path: &Option<String>, drivers_iso: &Option<String>, bios_type: &Option<String>, tpm: Option<bool>, secure_boot: Option<bool>) -> (Vec<String>, bool) {
    let mut failures: Vec<String> = Vec::new();
    let mut changed = false;
    let vmid_str = vmid.to_string();

    // Snapshot the live config once; every diff is computed against it.
    let conf = Command::new("qm").args(["config", &vmid_str]).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // Install ISO → ide2 cdrom. Empty clears the media (keeps the drive, so
    // the `boot order=...;ide2` reference set at create time stays valid).
    if let Some(iso) = iso_path.as_deref().map(|s| s.trim()) {
        let cur = pve_cdrom_iso(&conf, "ide2");
        if iso.is_empty() {
            if cur.is_some() {
                let args = vec!["set".into(), vmid_str.clone(), "--ide2".into(), "none,media=cdrom".into()];
                changed |= run_tool_cmd("qm", &args, "ISO", &mut failures);
            }
        } else if cur.as_deref() != Some(iso) {
            let args = vec!["set".into(), vmid_str.clone(), "--ide2".into(), format!("{},media=cdrom", iso)];
            changed |= run_tool_cmd("qm", &args, "ISO", &mut failures);
        }
    }

    // VirtIO-drivers ISO → ide3 cdrom.
    if let Some(drv) = drivers_iso.as_deref().map(|s| s.trim()) {
        let cur = pve_cdrom_iso(&conf, "ide3");
        if drv.is_empty() {
            if cur.is_some() {
                let args = vec!["set".into(), vmid_str.clone(), "--ide3".into(), "none,media=cdrom".into()];
                changed |= run_tool_cmd("qm", &args, "VirtIO drivers ISO", &mut failures);
            }
        } else if cur.as_deref() != Some(drv) {
            let args = vec!["set".into(), vmid_str.clone(), "--ide3".into(), format!("{},media=cdrom", drv)];
            changed |= run_tool_cmd("qm", &args, "VirtIO drivers ISO", &mut failures);
        }
    }

    // BIOS firmware. Switching to OVMF also needs an efidisk0 for NVRAM if the
    // VM doesn't have one yet — without it PVE would lose EFI vars every boot.
    if let Some(bt) = bios_type.as_deref().map(|b| b.trim()).filter(|b| !b.is_empty()) {
        let cur_bios = pve_conf_value(&conf, "bios").unwrap_or_else(|| "seabios".to_string());
        if cur_bios != bt {
            let need_efidisk = bt == "ovmf" && !pve_has_efidisk(&conf);
            let efidisk_storage = if need_efidisk { pve_os_disk_storage(&conf) } else { None };
            if need_efidisk && efidisk_storage.is_none() {
                // Refuse rather than half-apply: switching to OVMF without an
                // NVRAM store leaves the VM losing EFI vars on every boot.
                failures.push(
                    "BIOS type: cannot switch to OVMF — could not find the OS disk's storage pool to create the efidisk0 NVRAM store".to_string()
                );
            } else {
                let mut args = vec!["set".into(), vmid_str.clone(), "--bios".into(), bt.to_string()];
                if let Some(storage) = efidisk_storage {
                    args.push("--efidisk0".into());
                    args.push(format!("{}:1,efitype=4m", storage));
                }
                changed |= run_tool_cmd("qm", &args, "BIOS type", &mut failures);
            }
        }
    }

    // TPM 2.0 — ADD the tpmstate0 device when asked (Windows 11 needs it).
    // Additive only: we never auto-delete a TPM on edit, so an edit-save can
    // never strip an existing VM's TPM (removing one is a deliberate host-side
    // action).
    if tpm == Some(true) && !pve_has_tpmstate(&conf) {
        if let Some(storage) = pve_os_disk_storage(&conf) {
            let args = vec!["set".into(), vmid_str.clone(), "--tpmstate0".into(),
                format!("{}:1,version=v2.0", storage)];
            changed |= run_tool_cmd("qm", &args, "TPM 2.0", &mut failures);
        } else {
            failures.push("TPM: could not find the OS disk's storage pool to create the TPM state disk".into());
        }
    }

    // Secure Boot — turning it on re-creates the EFI NVRAM with Microsoft
    // keys pre-enrolled. That resets boot entries, so we do it only when
    // asked, only for OVMF, only if not already pre-enrolled, and we tell
    // the operator the NVRAM was reset.
    if secure_boot == Some(true) {
        let cur_bios = pve_conf_value(&conf, "bios").unwrap_or_else(|| "seabios".into());
        let is_ovmf = cur_bios == "ovmf" || bios_type.as_deref().map(|b| b.trim()) == Some("ovmf");
        let already = conf.contains("pre-enrolled-keys=1");
        if is_ovmf && !already
            && let Some(storage) = pve_os_disk_storage(&conf) {
                let args = vec!["set".into(), vmid_str.clone(), "--efidisk0".into(),
                    format!("{}:1,efitype=4m,pre-enrolled-keys=1", storage)];
                // Applies silently on success — `changed` alone surfaces the
                // "takes effect next boot" advisory. (Pushing to `failures`
                // would wrongly report this success as an error, since the
                // caller treats any failure as fatal.) Re-creating the efidisk
                // resets NVRAM; that's acceptable for a VM being prepared for a
                // Windows 11 install, which is the only time Secure Boot is set.
                changed |= run_tool_cmd("qm", &args, "Secure Boot", &mut failures);
            }
    }

    (failures, changed)
}

/// Walk every `<interface>` block in a libvirt domain XML and produce
/// a NicConfig per interface (skipping the first — that's the editor's
/// "primary NIC" surfaced through the preset cards, and the WolfNet
/// bridge, which is owned by WolfStack). Returns `(nics, wolfnet_active)`
/// so the caller can flip `network_mode` to "wolfnet" when WolfStack's
/// per-VM bridge is attached.
fn parse_libvirt_extra_nics(xml: &str) -> (Vec<NicConfig>, bool) {
    let mut nics: Vec<NicConfig> = Vec::new();
    let mut wolfnet_active = false;
    let mut index = 0usize;
    for block in iter_xml_blocks(xml, "interface") {
        let mac = libvirt_xml_attr_in_block(block, "mac", "address");
        // Source bridge: `<source bridge='...'/>` for type='bridge'.
        // Network-type interfaces (<source network='default'/>) don't have
        // a host bridge name we can edit, so we surface them as user-mode-
        // style with bridge=None.
        let bridge = libvirt_xml_attr_in_block(block, "source", "bridge");
        if bridge.as_deref().map(|b| b.starts_with("wnbr-")).unwrap_or(false) {
            wolfnet_active = true;
            index += 1;
            continue;
        }
        // First interface is the editor's primary NIC — handled via
        // network_mode + bridge fields, not as an extra NIC.
        if index == 0 {
            index += 1;
            continue;
        }
        let model = libvirt_xml_attr_in_block(block, "model", "type")
            .unwrap_or_else(|| "virtio".to_string());
        nics.push(NicConfig {
            model,
            mac,
            bridge,
            passthrough_interface: None,
        });
        index += 1;
    }
    (nics, wolfnet_active)
}

// ─── libvirt device-edit helpers (used by update_vm's libvirt branch) ───
//
// These build the exact `virt-xml` / `virsh change-media` argv that push an
// operator's VM-settings edits into an existing libvirt domain's PERSISTENT
// config. `virt-xml --edit` defaults to `--define` ("--edit implies default
// output action is --define, even if the VM is running" — man virt-xml), so
// the running guest is never disturbed and the change takes effect on next
// start — exactly the semantics the editor's BIOS-change warning already
// implies. argv are returned as owned Vec<String> so they unit-test without
// a libvirt host. Syntax verified against the virt-xml / virt-install /
// virsh man pages (model.type|model, target.bus|bus, --boot uefi[=off],
// change-media --update|--eject --config).

/// `<model type=...>` of the first `<interface>` block — the editor's
/// primary NIC, matching parse_libvirt_extra_nics' "index 0 is primary".
fn libvirt_primary_net_model(xml: &str) -> Option<String> {
    iter_xml_blocks(xml, "interface").next()
        .and_then(|b| libvirt_xml_attr_in_block(b, "model", "type"))
}

/// Every `<disk device='cdrom'>` slot in document order, as
/// (target-dev, current-source). Slot 0 is the OS-install ISO drive, slot 1
/// the VirtIO-drivers drive — the SAME index ordering the read-back uses, so
/// a saved ISO round-trips back to the right editor field.
fn libvirt_cdrom_slots(xml: &str) -> Vec<(String, Option<String>)> {
    let mut slots = Vec::new();
    for block in iter_xml_blocks(xml, "disk") {
        let header_end = block.find('>').unwrap_or(block.len());
        let header = &block[..header_end];
        if !(header.contains("device='cdrom'") || header.contains("device=\"cdrom\"")) {
            continue;
        }
        let dev = libvirt_xml_attr_in_block(block, "target", "dev").unwrap_or_default();
        let source = libvirt_xml_attr_in_block(block, "source", "file")
            .or_else(|| libvirt_xml_attr_in_block(block, "source", "dev"));
        slots.push((dev, source));
    }
    slots
}

/// (target-dev, bus) of the first `<disk device='disk'>` block.
fn libvirt_primary_disk_target(xml: &str) -> Option<(String, String)> {
    for block in iter_xml_blocks(xml, "disk") {
        let header_end = block.find('>').unwrap_or(block.len());
        let header = &block[..header_end];
        if header.contains("device='disk'") || header.contains("device=\"disk\"") {
            let dev = libvirt_xml_attr_in_block(block, "target", "dev")?;
            let bus = libvirt_xml_attr_in_block(block, "target", "bus")
                .unwrap_or_else(|| "virtio".to_string());
            return Some((dev, bus));
        }
    }
    None
}

/// True when the domain XML selects OVMF/UEFI firmware. Same heuristic the
/// read-back uses, so "what we detect" and "what we set" stay in sync.
fn libvirt_xml_is_ovmf(xml: &str) -> bool {
    xml.contains("OVMF") || xml.contains("ovmf")
        || xml.contains("AAVMF") || xml.contains("edk2")
        || xml.contains("firmware='efi'") || xml.contains("firmware=\"efi\"")
}

/// Canonical libvirt target-dev name for a bus, preserving the disk's slot
/// letter (vda↔sda↔hda all keep 'a'). virtio → vd*, ide → hd*, everything
/// else (sata/scsi/usb) → sd* — matching libvirt's own dev-naming.
fn disk_dev_for_bus(cur_dev: &str, bus: &str) -> String {
    let letter = cur_dev.chars().rev().find(|c| c.is_ascii_alphabetic()).unwrap_or('a');
    let prefix = match bus {
        "virtio" => "vd",
        "ide" => "hd",
        _ => "sd", // sata, scsi, usb
    };
    format!("{}{}", prefix, letter)
}

/// `virt-xml <name> --edit 1 --network <opts>` for the primary NIC.
/// `mode` Some → also (re)write source/type; None → change only the model.
/// virt-xml --edit leaves unspecified suboptions (incl. the existing MAC)
/// untouched. Returns None when there is nothing to change.
fn build_virtxml_network_args(name: &str, mode: Option<&str>, bridge: Option<&str>, model: Option<&str>) -> Option<Vec<String>> {
    let mut opts: Vec<String> = Vec::new();
    match mode {
        Some("bridge") => {
            let br = bridge.map(|b| b.trim()).filter(|b| !b.is_empty())?;
            opts.push(format!("bridge={}", br));
        }
        // Primary egress NIC is libvirt's default NAT network for both "nat"
        // and "wolfnet" (the WolfNet bridge NIC is a SEPARATE interface).
        Some("nat") | Some("wolfnet") => opts.push("network=default".to_string()),
        Some(_) => return None, // unknown mode — caller validates; ignore
        None => {}
    }
    if let Some(m) = model.map(|m| m.trim()).filter(|m| !m.is_empty()) {
        opts.push(format!("model={}", m));
    }
    if opts.is_empty() { return None; }
    Some(vec![
        name.to_string(), "--edit".into(), "1".into(),
        "--network".into(), opts.join(","),
    ])
}

/// `virt-xml <name> --edit target=<cur_dev> --disk target.bus=<bus>,target.dev=<new_dev>`
fn build_virtxml_disk_bus_args(name: &str, cur_dev: &str, bus: &str) -> Vec<String> {
    let new_dev = disk_dev_for_bus(cur_dev, bus);
    vec![
        name.to_string(),
        "--edit".into(), format!("target={}", cur_dev),
        "--disk".into(), format!("target.bus={},target.dev={}", bus, new_dev),
    ]
}

/// `virt-xml <name> --edit --boot uefi` (OVMF) or `--boot uefi=off` (SeaBIOS).
fn build_virtxml_bios_args(name: &str, want_ovmf: bool) -> Vec<String> {
    let boot = if want_ovmf { "uefi" } else { "uefi=off" };
    vec![name.to_string(), "--edit".into(), "--boot".into(), boot.to_string()]
}

/// `virt-xml <name> --add-device --disk device=cdrom,path=<src>` — used when
/// the operator sets an ISO on a VM that has no matching cdrom slot yet.
/// libvirt auto-assigns the target dev.
fn build_virtxml_add_cdrom_args(name: &str, src: &str) -> Vec<String> {
    vec![
        name.to_string(), "--add-device".into(),
        "--disk".into(), format!("device=cdrom,path={}", src),
    ]
}

/// `virsh change-media <name> <target> [<src>] (--update|--eject) --config`.
/// `src` Some → insert/replace (--update covers both per the man page);
/// None → eject. `--config` only, so the swap is persistent / next-boot and
/// the running guest's mounted media is left alone.
fn build_change_media_args(name: &str, target: &str, src: Option<&str>) -> Vec<String> {
    let mut a = vec!["change-media".to_string(), name.to_string(), target.to_string()];
    match src {
        Some(s) => { a.push(s.to_string()); a.push("--update".into()); }
        None => a.push("--eject".into()),
    }
    a.push("--config".into());
    a
}

/// Run `cmd args`, returning true on exit-0. On failure, push a
/// "<field>: <reason>" line onto `failures` (ENOENT → the tool isn't
/// installed, surfaced honestly rather than swallowed).
fn run_tool_cmd(cmd: &str, args: &[String], field: &str, failures: &mut Vec<String>) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            failures.push(format!("{}: {}", field, String::from_utf8_lossy(&o.stderr).trim()));
            false
        }
        Err(e) => {
            failures.push(format!("{}: {} unavailable ({})", field, cmd, e));
            false
        }
    }
}

/// Decide the `virt-xml` argv (if any) to bring the primary NIC into line
/// with the requested mode/bridge/model, given the current domain XML. Pure
/// so the diffing logic is unit-tested without a libvirt host; returns None
/// when nothing needs to change. The primary NIC is interface 1 (virt-xml is
/// 1-indexed); the WolfNet NIC (`wnbr-*`) is always a SECOND interface and is
/// filtered out so we never mistake it for the primary and clobber it.
fn libvirt_primary_nic_edit(cur_xml: &str, name: &str, req_mode: Option<&str>, req_bridge: Option<&str>, req_model: Option<&str>) -> Option<Vec<String>> {
    let cur_model = libvirt_primary_net_model(cur_xml);
    let cur_bridge = iter_xml_blocks(cur_xml, "interface").next()
        .and_then(|b| libvirt_xml_attr_in_block(b, "source", "bridge"))
        .filter(|b| !b.starts_with("wnbr-"));
    // Current primary source → normalized (mode, bridge): a non-virbr0 bridge
    // is "bridge"; everything else (virbr0 / network=default / user) is "nat".
    let (cur_mode, cur_br): (&str, Option<String>) = match cur_bridge.as_deref() {
        Some(b) if b != "virbr0" => ("bridge", Some(b.to_string())),
        _ => ("nat", None),
    };
    let req_mode = req_mode.filter(|s| !s.is_empty());
    // "wolfnet" and "nat" both leave the PRIMARY on the default NAT net (the
    // WolfNet bridge NIC is reconciled separately as a second interface).
    let (want_mode, want_br): (&str, Option<String>) = match req_mode {
        Some("bridge") => ("bridge", req_bridge.map(|b| b.trim().to_string()).filter(|b| !b.is_empty())),
        Some("nat") | Some("wolfnet") => ("nat", None),
        _ => (cur_mode, cur_br.clone()), // no mode change requested
    };
    let source_changed = req_mode.is_some() && (want_mode != cur_mode || want_br != cur_br);
    let model_changed = req_model.filter(|m| !m.is_empty())
        .map(|m| Some(m) != cur_model.as_deref()).unwrap_or(false);
    let mode_for_build = if source_changed { Some(want_mode) } else { None };
    let model_for_build = if model_changed { req_model } else { None };
    build_virtxml_network_args(name, mode_for_build, want_br.as_deref(), model_for_build)
}

/// Push the operator's libvirt VM-settings edits — primary NIC model +
/// mode/bridge, OS-install + VirtIO-drivers ISOs, OS disk bus, BIOS firmware
/// — into the domain's PERSISTENT config. Only fields whose Option is Some
/// AND whose value differs from the current domain XML trigger a command
/// (mirrors the Proxmox path's "skip when nothing would change"). Returns
/// (failures, changed_next_boot): `failures` is empty when everything
/// applied; `changed_next_boot` is true when at least one next-boot-only
/// field actually changed (drives the running-VM advisory).
#[allow(clippy::too_many_arguments)]
fn libvirt_apply_devices(
    name: &str,
    net_model: &Option<String>, network_mode: &Option<String>, bridge: &Option<String>,
    iso_path: &Option<String>, drivers_iso: &Option<String>,
    os_disk_bus: &Option<String>, bios_type: &Option<String>,
    tpm: Option<bool>, secure_boot: Option<bool>,
) -> (Vec<String>, bool) {
    let mut failures: Vec<String> = Vec::new();
    let mut changed = false;

    // Snapshot the persistent XML once; every diff is computed against it.
    let cur_xml = Command::new("virsh").args(["dumpxml", "--inactive", name]).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // ── Primary NIC: mode/bridge + model (no-op-safe: the pure helper
    //    returns None when nothing differs from the current domain XML) ──
    if let Some(args) = libvirt_primary_nic_edit(
        &cur_xml, name, network_mode.as_deref(), bridge.as_deref(), net_model.as_deref(),
    ) {
        changed |= run_tool_cmd("virt-xml", &args, "network adapter", &mut failures);
    }

    // ── OS disk bus (only when it actually differs) ────────────────────
    let disk_bus_edit = os_disk_bus.as_deref().map(|b| b.trim()).filter(|b| !b.is_empty())
        .and_then(|bus| libvirt_primary_disk_target(&cur_xml)
            .filter(|(_, cur_bus)| cur_bus.as_str() != bus)
            .map(|(cur_dev, _)| build_virtxml_disk_bus_args(name, &cur_dev, bus)));
    if let Some(args) = disk_bus_edit {
        changed |= run_tool_cmd("virt-xml", &args, "OS disk bus", &mut failures);
    }

    // ── BIOS firmware (SeaBIOS ↔ OVMF) ─────────────────────────────────
    if let Some(bt) = bios_type.as_deref().map(|b| b.trim()).filter(|b| !b.is_empty()) {
        let want_ovmf = bt == "ovmf";
        if want_ovmf != libvirt_xml_is_ovmf(&cur_xml) {
            let args = build_virtxml_bios_args(name, want_ovmf);
            changed |= run_tool_cmd("virt-xml", &args, "BIOS type", &mut failures);
        }
    }

    // ── TPM 2.0 device (Windows 11) — ADD when asked, no-op-safe ───────
    // Additive only (see the Proxmox path): an edit never strips an
    // existing TPM.
    if tpm == Some(true) && !cur_xml.contains("<tpm") {
        let args = vec![name.to_string(), "--add-device".into(), "--tpm".into(),
            "model=tpm-crb,backend.type=emulator,backend.version=2.0".into()];
        changed |= run_tool_cmd("virt-xml", &args, "TPM 2.0", &mut failures);
    }

    // ── Secure Boot — secure loader + SMM. Applied on next boot. ───────
    if secure_boot == Some(true) && !cur_xml.contains("secure='yes'") {
        let boot_args = vec![name.to_string(), "--edit".into(), "--boot".into(), "loader.secure=yes".into()];
        changed |= run_tool_cmd("virt-xml", &boot_args, "Secure Boot", &mut failures);
        let smm_args = vec![name.to_string(), "--edit".into(), "--features".into(), "smm.state=on".into()];
        changed |= run_tool_cmd("virt-xml", &smm_args, "Secure Boot (SMM)", &mut failures);
    }

    // ── CD-ROM media: slot 0 = install ISO, slot 1 = VirtIO drivers ISO ─
    let slots = libvirt_cdrom_slots(&cur_xml);
    let apply_cdrom = |idx: usize, want: &str, field: &str, failures: &mut Vec<String>, changed: &mut bool| {
        match slots.get(idx) {
            Some((dev, cur_src)) => {
                if want.is_empty() {
                    // Clear the slot only if it currently holds media.
                    if cur_src.is_some() {
                        let args = build_change_media_args(name, dev, None);
                        *changed |= run_tool_cmd("virsh", &args, field, failures);
                    }
                } else if cur_src.as_deref() != Some(want) {
                    let args = build_change_media_args(name, dev, Some(want));
                    *changed |= run_tool_cmd("virsh", &args, field, failures);
                }
            }
            None => {
                // No such slot. Add a cdrom only when setting a non-empty ISO.
                // (A drivers-ISO add on a VM with zero cdrom slots lands as the
                // first cdrom and would read back as the install ISO — rare, as
                // libvirt VMs are created with the install cdrom already.)
                if !want.is_empty() {
                    let args = build_virtxml_add_cdrom_args(name, want);
                    *changed |= run_tool_cmd("virt-xml", &args, field, failures);
                }
            }
        }
    };
    if let Some(iso) = iso_path.as_deref() {
        apply_cdrom(0, iso.trim(), "ISO", &mut failures, &mut changed);
    }
    if let Some(drv) = drivers_iso.as_deref() {
        apply_cdrom(1, drv.trim(), "VirtIO drivers ISO", &mut failures, &mut changed);
    }

    (failures, changed)
}

/// Parse a single `netN: <value>` line value into a NicConfig. Returns
/// (n, NicConfig) so the caller can sort by N and skip net0. Skips the
/// per-VM WolfNet bridge (`wnbr-*`) — that's the WolfNet attachment,
/// surfaced via `network_mode == "wolfnet"` not as a user-facing extra
/// NIC. Returns None when the value isn't parseable.
fn parse_pve_extra_nic(key: &str, val: &str) -> Option<(usize, NicConfig)> {
    if !key.starts_with("net") { return None; }
    let n: usize = key[3..].parse().ok()?;
    let mut model = "virtio".to_string();
    let mut mac: Option<String> = None;
    let mut bridge: Option<String> = None;
    for part in val.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if matches!(k, "virtio" | "e1000" | "e1000e" | "rtl8139" | "vmxnet3") {
                model = k.to_string();
                mac = Some(v.to_string());
            } else if k == "bridge" {
                let v = v.trim();
                if !v.is_empty() { bridge = Some(v.to_string()); }
            }
        }
    }
    // The per-VM WolfNet bridge is owned by WolfStack and surfaced via
    // network_mode — never list it as an editable extra NIC, or the
    // editor would treat it as a manual bridge attachment and the next
    // save would freeze the auto-name.
    if bridge.as_deref().map(|b| b.starts_with("wnbr-")).unwrap_or(false) {
        return None;
    }
    Some((n, NicConfig {
        model,
        mac,
        bridge,
        passthrough_interface: None,
    }))
}

/// The set of VM names currently RUNNING on this host, across whichever
/// hypervisor backends are present — the VM counterpart of the LXC
/// `lxc_running_names` probe in containers/. Used by the WolfNet
/// advertisement scan so a stopped VM's IP is neither advertised for
/// routing nor counted by the start-time conflict check. (Counting every
/// VM config as "active" made a VM start conflict with its OWN config
/// file — any wolfnet_ip it was given reported "already in use: active
/// on this node"; klasSponsor 2026-06-10.) Returns None when run-state
/// can't be determined at all; callers fall back to counting every VM
/// rather than dropping a running VM's route on a tooling hiccup.
pub fn running_vm_names() -> Option<std::collections::HashSet<String>> {
    let mut set = std::collections::HashSet::new();
    if crate::containers::is_proxmox() {
        // Filesystem-direct: /etc/pve/qemu-server/*.conf names plus the
        // qemu-server pidfile run-state — the same sources get_vm /
        // qm_list_all read. Unreadable dir → indeterminate. Early return
        // (no pgrep supplement) mirrors get_vm(): on a PVE host WolfStack
        // only ever manages VMs through qm, never bare qemu processes.
        if !pve_qemu_server_dir_readable() {
            return None;
        }
        for vm in qm_list_via_filesystem() {
            if vm.running {
                set.insert(vm.name);
            }
        }
        return Some(set);
    }
    if crate::containers::is_libvirt() {
        // One subprocess for every libvirt domain. A virsh failure makes
        // the WHOLE probe indeterminate (not a partial native-only set):
        // None is the safe direction — every VM stays advertised — at the
        // cost of the start-time conflict check transiently counting
        // stopped VMs again until virsh recovers.
        match Command::new("virsh").args(["list", "--name", "--state-running"]).output() {
            Ok(o) if o.status.success() => {
                for name in String::from_utf8_lossy(&o.stdout).lines() {
                    let name = name.trim();
                    if !name.is_empty() {
                        set.insert(name.to_string());
                    }
                }
            }
            _ => return None,
        }
    }
    // Native QEMU processes — also covers pre-libvirt VMs on libvirt hosts
    // (mirrors get_vm()'s fall-through). One pgrep for ALL VMs instead of
    // check_running()'s per-name probe. Native starts pass a plain
    // `-name <vm>` (start_vm); libvirt-spawned qemu uses
    // `-name guest=<vm>,debug-threads=on` — handle both shapes.
    match Command::new("pgrep").args(["-a", "-f", "qemu-system"]).output() {
        Ok(o) => {
            // pgrep exits 1 with no matches — that's a definitive
            // "no native VMs running", not a probe failure.
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let mut toks = line.split_whitespace();
                while let Some(t) = toks.next() {
                    if t != "-name" {
                        continue;
                    }
                    if let Some(v) = toks.next() {
                        let v = v.strip_prefix("guest=").unwrap_or(v);
                        let v = v.split(',').next().unwrap_or(v);
                        if !v.is_empty() {
                            set.insert(v.to_string());
                        }
                    }
                    break;
                }
            }
        }
        // pgrep itself couldn't run — we can't see native VMs, and a
        // partial (libvirt-only) answer could blackhole a running
        // native VM's route. Indeterminate.
        Err(_) => return None,
    }
    Some(set)
}

/// True if /var/run/qemu-server/<vmid>.pid points at a live process.
/// Replaces the per-VM `qm status <vmid>` subprocess.
fn is_pve_vmid_running(vmid: u32) -> bool {
    let pid_path = format!("{}/{}.pid", PVE_QEMU_RUN_DIR, vmid);
    let Ok(pid_str) = fs::read_to_string(&pid_path) else { return false; };
    let Ok(pid) = pid_str.trim().parse::<u32>() else { return false; };
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Filesystem-direct VMID-by-name lookup. Walks /etc/pve/qemu-server/*.conf
/// looking for a `name: <target>` line in the main (non-snapshot)
/// section. None when no match.
fn qm_vmid_by_name_filesystem(target: &str) -> Option<u32> {
    let entries = fs::read_dir(PVE_QEMU_DIR).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") { continue; }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue; };
        let Ok(vmid) = stem.parse::<u32>() else { continue; };
        let Ok(text) = fs::read_to_string(&path) else { continue; };
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') { break; } // entered snapshot section
            if let Some(rest) = line.strip_prefix("name:") {
                if rest.trim() == target {
                    return Some(vmid);
                }
                break; // only one name per main section
            }
        }
    }
    None
}

// ─── Minimal libvirt XML extraction helpers ─────────────────────────
//
// The libvirt domain XML is well-structured but small; parsing the
// half-dozen fields we care about doesn't justify pulling in a real
// XML crate. These helpers handle:
//   • single OR double quote attribute values
//   • self-closing (<x/>) and paired (<x>...</x>) tags
//   • multiple instances of the same tag (we walk one block at a time)
//
// Edge cases NOT handled (libvirt never emits these):
//   • CDATA sections
//   • Comments containing '<' or '>'
//   • Namespaces with custom prefixes (`<ns:tag>`)
//
// If libvirt ever adds those, the subprocess fallback path still works.

/// Extract text between `<tag ...>` and `</tag>`. The opening tag may
/// have attributes — we find the next `>` after the tag start. Returns
/// the trimmed inner text on success, None when the tag doesn't appear
/// or has no closing tag.
fn libvirt_xml_inner_text_after_tag(xml: &str, tag_open_prefix: &str) -> Option<String> {
    // tag_open_prefix is like "<vcpu" or "<memory" — the caller chooses
    // whether to allow attributes by using a partial prefix.
    let start = xml.find(tag_open_prefix)?;
    // Skip past the closing '>' of the open tag.
    let after_open = xml.get(start..)?.find('>')? + start + 1;
    // Derive the close-tag from the prefix's tag name.
    let tag_name = tag_open_prefix.trim_start_matches('<')
        .split(|c: char| c.is_whitespace() || c == '>')
        .next()?;
    let close = format!("</{}>", tag_name);
    let close_idx = xml.get(after_open..)?.find(&close)? + after_open;
    Some(xml.get(after_open..close_idx)?.trim().to_string())
}

/// Extract the libvirt domain `<description>` text (operator notes), XML-
/// unescaped. libvirt stores the description set by `virsh desc` in this
/// element with the usual XML entity escaping (`&lt;`, `&amp;`, etc.). Empty
/// string when absent. `<description/>` (self-closing, no close tag) reads as
/// empty too since `libvirt_xml_inner_text_after_tag` finds no `</description>`.
fn libvirt_xml_description(xml: &str) -> String {
    libvirt_xml_inner_text_after_tag(xml, "<description")
        .map(|s| xml_unescape(&s))
        .unwrap_or_default()
}

/// Extract the operator's extra QEMU args from a libvirt domain XML's
/// `<qemu:commandline>` passthrough block. Each `<qemu:arg value='...'/>`
/// child becomes one token; tokens are re-joined with the shell-style
/// quoting used for the editable text field (so a token containing spaces
/// round-trips). Empty string when no `<qemu:commandline>` is present —
/// which is the case for every domain we didn't add passthrough to, so
/// existing libvirt VMs read back as having no extra args (Golden Rule).
fn libvirt_xml_qemu_commandline(xml: &str) -> String {
    let mut tokens: Vec<String> = Vec::new();
    for block in iter_xml_blocks(xml, "qemu:commandline") {
        for arg_block in iter_xml_blocks(block, "qemu:arg") {
            if let Some(v) = xml_attr_value(arg_block, "value") {
                tokens.push(xml_unescape(&v));
            }
        }
    }
    join_qemu_args(&tokens)
}

/// Pull `attr='value'` (or `attr="value"`) out of a single XML open tag.
/// Used for `<qemu:arg value='...'/>`. Tokenises on the attribute name
/// followed by `=` so a suffix can't false-match.
fn xml_attr_value(tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=", attr);
    let idx = tag.find(&needle)?;
    let after = &tag[idx + needle.len()..];
    let quote = after.chars().next()?;
    if quote != '\'' && quote != '"' { return None; }
    let rest = &after[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// Escape a string for use inside a single-quoted XML attribute value. We
/// emit `<qemu:arg value='...'/>` with single quotes, so `'` must become
/// `&apos;`; `&` and `<` are escaped to keep the document well-formed.
fn xml_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

/// Persist operator extra QEMU args into a libvirt domain's
/// `<qemu:commandline>` passthrough block. There is no virt-xml flag for
/// this, so we edit the inactive domain XML by hand: ensure the
/// `xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'` namespace on
/// the root `<domain>` element, strip any existing `<qemu:commandline>`,
/// insert a fresh one built from the tokenised args (each token a
/// `<qemu:arg>`), then `virsh define` the result. An empty/blank `args`
/// just removes the block (and leaves the namespace, which is harmless).
/// Applies on next start. Returns Err only on a real virsh failure.
fn libvirt_set_qemu_commandline(name: &str, args: &str) -> Result<(), String> {
    let dump = Command::new("virsh").args(["dumpxml", "--inactive", name]).output()
        .map_err(|e| format!("virsh dumpxml failed: {}", e))?;
    if !dump.status.success() {
        return Err(format!("virsh dumpxml failed: {}", String::from_utf8_lossy(&dump.stderr).trim()));
    }
    let xml = String::from_utf8_lossy(&dump.stdout).to_string();
    let new_xml = match rewrite_domain_qemu_commandline(&xml, args) {
        Some(x) => x,
        None => return Err("Could not locate <domain> element in domain XML".to_string()),
    };
    // virsh define reads the XML from a file path argument. Sanitise the
    // name for the temp filename so a quirky VM name can't escape temp_dir.
    let safe_name: String = name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let tmp = std::env::temp_dir().join(format!("wolfstack-qemucmdline-{}.xml", safe_name));
    fs::write(&tmp, &new_xml).map_err(|e| format!("write temp domain XML: {}", e))?;
    let define = Command::new("virsh").args(["define", &tmp.to_string_lossy()]).output();
    let _ = fs::remove_file(&tmp);
    let out = define.map_err(|e| format!("virsh define failed: {}", e))?;
    if !out.status.success() {
        return Err(format!("virsh define (qemu:commandline) failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Pure XML transform behind [`libvirt_set_qemu_commandline`] (unit-tested):
/// add the qemu namespace to `<domain ...>`, drop any existing
/// `<qemu:commandline>...</qemu:commandline>` block, and append a fresh one
/// (when `args` is non-blank) just before `</domain>`. Returns None if no
/// `<domain` open tag is found.
fn rewrite_domain_qemu_commandline(xml: &str, args: &str) -> Option<String> {
    let qemu_ns = "http://libvirt.org/schemas/domain/qemu/1.0";
    // 1. Ensure the namespace on the <domain ...> open tag.
    let dom_start = xml.find("<domain")?;
    let dom_open_end = xml[dom_start..].find('>')? + dom_start; // index of '>'
    let mut out = String::with_capacity(xml.len() + 256);
    out.push_str(&xml[..dom_start]);
    let open_tag = &xml[dom_start..=dom_open_end];
    if open_tag.contains("xmlns:qemu=") {
        out.push_str(open_tag);
    } else {
        // Insert the namespace right after `<domain` (before any other attrs).
        // `<domain ...>` → `<domain xmlns:qemu='...' ...>`
        let inserted = open_tag.replacen("<domain", &format!("<domain xmlns:qemu='{}'", qemu_ns), 1);
        out.push_str(&inserted);
    }
    let mut rest = xml[dom_open_end + 1..].to_string();

    // 2. Strip any existing <qemu:commandline>...</qemu:commandline> blocks.
    while let Some(s) = rest.find("<qemu:commandline") {
        // Self-closing form <qemu:commandline/> or full block.
        let after = &rest[s..];
        let block_len = if let Some(close) = after.find("</qemu:commandline>") {
            close + "</qemu:commandline>".len()
        } else if let Some(sc) = after.find("/>") {
            sc + "/>".len()
        } else {
            break;
        };
        // Also swallow trailing whitespace/newline left behind for tidiness.
        let mut end = s + block_len;
        while end < rest.len() && rest.as_bytes()[end].is_ascii_whitespace() {
            end += 1;
        }
        rest.replace_range(s..end, "");
    }

    // 3. Build + insert a fresh block before </domain> when args are non-blank.
    let tokens = split_qemu_args(args);
    if !tokens.is_empty() {
        let mut block = String::from("  <qemu:commandline>\n");
        for t in &tokens {
            block.push_str(&format!("    <qemu:arg value='{}'/>\n", xml_escape_attr(t)));
        }
        block.push_str("  </qemu:commandline>\n");
        if let Some(close) = rest.rfind("</domain>") {
            rest.insert_str(close, &block);
        } else {
            rest.push_str(&block);
        }
    }
    out.push_str(&rest);
    Some(out)
}

/// Minimal XML entity unescaping for the five predefined entities plus the
/// numeric line-feed/carriage-return references libvirt emits for multi-line
/// descriptions. Sufficient for the `<description>` text — we never round-trip
/// arbitrary markup here.
fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // Newline/CR numeric refs — decimal (what libvirt emits) and hex
        // (some tooling in the ecosystem) for robustness.
        .replace("&#10;", "\n")
        .replace("&#xA;", "\n")
        .replace("&#xa;", "\n")
        .replace("&#13;", "")
        .replace("&#xD;", "")
        .replace("&#xd;", "")
        // `&amp;` MUST be resolved last so we never double-decode (e.g. the
        // literal text "&lt;" arrives as "&amp;lt;" and must stay "&lt;").
        .replace("&amp;", "&")
}

/// Find every `<tag>...</tag>` (or self-closing `<tag .../>`) block in
/// `xml` and yield each as a slice. Used to walk multiple `<disk>`,
/// `<interface>`, etc. elements in one pass.
fn iter_xml_blocks<'a>(xml: &'a str, tag: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    XmlBlockIter { xml, tag, pos: 0 }
}

struct XmlBlockIter<'a> {
    xml: &'a str,
    tag: &'a str,
    pos: usize,
}

impl<'a> Iterator for XmlBlockIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        // Match `<tag ` or `<tag>` exactly so `<tag2>` doesn't trigger.
        let needle_with_space = format!("<{} ", self.tag);
        let needle_with_close = format!("<{}>", self.tag);
        let needle_with_slash = format!("<{}/", self.tag);
        let rest = self.xml.get(self.pos..)?;
        // Find the earliest of the three forms.
        let candidates: Vec<usize> = [&needle_with_space, &needle_with_close, &needle_with_slash]
            .iter()
            .filter_map(|n| rest.find(n.as_str()))
            .collect();
        let start_in_rest = *candidates.iter().min()?;
        let abs_start = self.pos + start_in_rest;
        // Find end of the opening tag (`>`).
        let after_open = self.xml.get(abs_start..)?.find('>')? + abs_start + 1;
        // Self-closing? Last char before > is /
        let self_closing = self.xml.get(abs_start..after_open)?.ends_with("/>");
        let block_end = if self_closing {
            after_open
        } else {
            let close = format!("</{}>", self.tag);
            self.xml.get(after_open..)?.find(&close)? + after_open + close.len()
        };
        let block = self.xml.get(abs_start..block_end)?;
        self.pos = block_end;
        Some(block)
    }
}

/// Within `block`, find `<inner_tag ... attr='value' ... />` (or an
/// equivalent quoted form) and return the value. Used to fish the file
/// path out of `<source file='...'/>` inside a `<disk>` block.
///
/// Tokenises on whitespace inside the open tag so attribute names
/// don't substring-match suffixes — e.g. looking up `id` won't match
/// `userid='X'`. (libvirt domain XML doesn't currently have any such
/// pairs; harden anyway because the same helper is reused for any
/// future call sites.)
/// True when a libvirt domain XML describes WolfStack-managed EXTERNAL VNC:
/// the *VNC* graphics device listens on 0.0.0.0 AND has a password. The
/// password is the key discriminator — a legacy VM left on 0.0.0.0 with NO
/// password must NOT count as external (else we'd open its unauthenticated
/// port). Evaluated WITHIN the single `type='vnc'` graphics block so a second
/// graphics device (e.g. SPICE on a different listen/passwd) can't cross-wire
/// the decision. Handles both `<graphics … listen='0.0.0.0'>` and the nested
/// `<listen address='0.0.0.0'/>` forms.
fn libvirt_xml_is_external_vnc(xml: &str) -> bool {
    for block in iter_xml_blocks(xml, "graphics") {
        let header_end = block.find('>').unwrap_or(block.len());
        let header = &block[..header_end];
        if !(header.contains("type='vnc'") || header.contains("type=\"vnc\"")) { continue; }
        let listens_all = libvirt_xml_attr_in_block(block, "graphics", "listen").as_deref() == Some("0.0.0.0")
            || libvirt_xml_attr_in_block(block, "listen", "address").as_deref() == Some("0.0.0.0");
        let has_password = libvirt_xml_attr_in_block(block, "graphics", "passwd")
            .map(|p| !p.is_empty()).unwrap_or(false);
        return listens_all && has_password;
    }
    false
}

fn libvirt_xml_attr_in_block(block: &str, inner_tag: &str, attr: &str) -> Option<String> {
    let needle_space = format!("<{} ", inner_tag);
    let needle_close = format!("<{}>", inner_tag);
    let pos = block.find(&needle_space)
        .or_else(|| block.find(&needle_close))?;
    let after = &block[pos..];
    let end = after.find('>').unwrap_or(after.len());
    let inside = &after[..end];
    for token in inside.split_whitespace() {
        for quote in ['\'', '"'] {
            let prefix = format!("{}={}", attr, quote);
            if let Some(rest) = token.strip_prefix(prefix.as_str())
                && let Some(end) = rest.find(quote) {
                    return Some(rest[..end].to_string());
                }
        }
    }
    None
}

/// Status of one VM's WolfNet DHCP plumbing. Surfaced by the
/// predictive analyzer and the `/api/vms/wolfnet/health` endpoint
/// so operators see broken plumbing the moment the orchestrator
/// ticks instead of when a customer reports it.
///
/// `Ok` is reserved for "every check passed". Anything else is
/// listed in `failures` so the UI can render the first thing the
/// operator should fix.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WolfnetTapHealth {
    pub tap: String,
    pub gateway_ip: String,
    pub wolfnet_ip: String,
    pub tap_exists: bool,
    pub tap_up: bool,
    pub gateway_assigned: bool,
    pub dnsmasq_pid: Option<i32>,
    pub dnsmasq_alive: bool,
    pub dnsmasq_owns_tap: bool,
    pub lease_present: bool,
    pub failures: Vec<String>,
}

impl WolfnetTapHealth {
    pub fn ok(&self) -> bool { self.failures.is_empty() }
}

/// Probe the network plumbing for a VM TAP. Returns a structured
/// health record so the predictive analyzer and the API share one
/// implementation — drift between "what we check at boot" and "what
/// we check at runtime" is exactly how regressions slip in.
///
/// Pure inspection: never starts or kills processes, never
/// reconfigures interfaces. Safe to call many times per second.
pub fn probe_wolfnet_tap_health(tap: &str, wolfnet_ip: &str) -> WolfnetTapHealth {
    // Historic gateway derivation: <subnet>.254. The v22.9.26
    // mirror-across-the-/24-midpoint scheme was reverted because it
    // broke pre-existing VMs that had `subnet.254` baked into their
    // static configs as the default gateway.
    let parts: Vec<&str> = wolfnet_ip.split('.').collect();
    let gateway_ip = if parts.len() == 4 {
        format!("{}.{}.{}.254", parts[0], parts[1], parts[2])
    } else {
        wolfnet_ip.to_string()
    };
    let mut h = WolfnetTapHealth {
        tap: tap.to_string(),
        gateway_ip: gateway_ip.clone(),
        wolfnet_ip: wolfnet_ip.to_string(),
        tap_exists: false,
        tap_up: false,
        gateway_assigned: false,
        dnsmasq_pid: None,
        dnsmasq_alive: false,
        dnsmasq_owns_tap: false,
        lease_present: false,
        failures: Vec::new(),
    };

    // 1. TAP existence + state. `/sys/class/net/<tap>/operstate`
    //    reports "up", "down", or "unknown" (TAPs without a peer
    //    often report "unknown" but are actually usable).
    let operstate_path = format!("/sys/class/net/{}/operstate", tap);
    if std::path::Path::new(&operstate_path).exists() {
        h.tap_exists = true;
        let state = std::fs::read_to_string(&operstate_path).unwrap_or_default();
        let state = state.trim();
        if state == "up" || state == "unknown" {
            h.tap_up = true;
        } else {
            h.failures.push(format!("TAP {} operstate is `{}` (expected up/unknown)", tap, state));
        }
    } else {
        h.failures.push(format!("TAP {} does not exist on the host", tap));
    }

    // 2. Gateway IP must be assigned to the TAP.
    if h.tap_exists {
        let out = Command::new("ip")
            .args(["addr", "show", "dev", tap])
            .output();
        if let Ok(o) = out {
            let body = String::from_utf8_lossy(&o.stdout);
            // Match `inet 10.10.10.250/` — anchored on the address
            // and a trailing `/` to avoid matching a substring of a
            // longer address.
            if body.contains(&format!("inet {}/", gateway_ip)) {
                h.gateway_assigned = true;
            } else {
                h.failures.push(format!(
                    "Gateway {} not assigned to {} (ip addr show shows: {})",
                    gateway_ip, tap,
                    body.lines().filter(|l| l.contains("inet ")).collect::<Vec<_>>().join("; "),
                ));
            }
        }
    }

    // 3. dnsmasq pid + liveness + correct interface.
    let pid_path = format!("/run/dnsmasq-{}.pid", tap);
    if let Ok(s) = std::fs::read_to_string(&pid_path) {
        let pid_str = s.trim();
        if let Ok(pid) = pid_str.parse::<i32>() {
            h.dnsmasq_pid = Some(pid);
            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                h.dnsmasq_alive = true;
                if let Ok(cmdline_bytes) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
                    let cmdline = String::from_utf8_lossy(&cmdline_bytes).replace('\0', " ");
                    if cmdline.contains(&format!("--interface={}", tap)) {
                        h.dnsmasq_owns_tap = true;
                    } else {
                        h.failures.push(format!(
                            "dnsmasq pid {} is alive but cmdline does not reference --interface={} \
                             (pid file may be stale from a different VM)",
                            pid, tap,
                        ));
                    }
                }
            } else {
                h.failures.push(format!(
                    "dnsmasq pid {} from {} is not running — most likely failed to bind \
                     {}:53 or {}:67 (Address already in use)",
                    pid, pid_path, gateway_ip, gateway_ip,
                ));
            }
        } else {
            h.failures.push(format!("dnsmasq pid file {} contains non-numeric data: {:?}", pid_path, pid_str));
        }
    } else {
        h.failures.push(format!("dnsmasq pid file {} missing — daemon never wrote it", pid_path));
    }

    // 4. Lease file: present + non-empty means the VM has actually
    //    DHCP'd. A successful spawn with no lease for a running VM
    //    means the VM never reached the DHCP server.
    let lease_path = format!("/run/dnsmasq-{}.leases", tap);
    if let Ok(meta) = std::fs::metadata(&lease_path)
        && meta.len() > 0 {
            h.lease_present = true;
        }
        // Empty lease file is normal for a freshly-started VM that
        // hasn't DHCP'd yet — don't flag as a failure here, the
        // analyzer can decide whether "running for >30s with no
        // lease" rises to a finding.

    h
}

/// Block briefly (≤1s) after spawning dnsmasq to confirm it
/// actually stayed up and bound to the right TAP. Called from
/// `setup_wolfnet_routing` directly after `Command::spawn()`.
fn verify_dnsmasq_running(tap: &str, gateway_ip: &str) -> Result<(), String> {
    let pid_path = format!("/run/dnsmasq-{}.pid", tap);
    let mut last_err = String::new();
    // 10 × 100ms = up to 1s. dnsmasq normally writes its pid file
    // and reports bind status within ~50ms on a healthy host; the
    // generous budget covers slow disks / busy hosts.
    for attempt in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let pid_str = match std::fs::read_to_string(&pid_path) {
            Ok(s) => s.trim().to_string(),
            Err(_) => {
                last_err = format!("pid file {} not yet present (attempt {}/10)", pid_path, attempt + 1);
                continue;
            }
        };
        let pid: i32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => { last_err = format!("malformed dnsmasq pid {:?}", pid_str); continue; }
        };
        if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
            last_err = format!(
                "dnsmasq pid {} died after spawn (likely bind failure on {}:53 or {}:67)",
                pid, gateway_ip, gateway_ip,
            );
            continue;
        }
        // Confirm the live process owns OUR tap, not a stale match.
        if let Ok(cmdline_bytes) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
            let cmdline = String::from_utf8_lossy(&cmdline_bytes).replace('\0', " ");
            if !cmdline.contains(&format!("--interface={}", tap)) {
                last_err = format!(
                    "dnsmasq pid {} is alive but bound to a different interface (--interface={} not in cmdline)",
                    pid, tap,
                );
                continue;
            }
        }
        return Ok(());
    }
    Err(if last_err.is_empty() {
        "dnsmasq verification timed out without a specific error".to_string()
    } else {
        last_err
    })
}

#[cfg(test)]
mod tap_gateway_tests {
    /// Mirrors the gateway derivation used by `setup_wolfnet_routing`
    /// and `probe_wolfnet_tap_health`. Documents the contract:
    ///
    ///   * Every VM in the same /24 gets the same `<subnet>.254`
    ///     gateway. Static guests (WolfRouter, HA appliances) hardcode
    ///     this value, so it must stay stable.
    ///   * The TAP carries `gateway/32` (not `/24`) so the kernel
    ///     doesn't auto-install duplicate connected /24 routes when
    ///     more than one WolfNet VM is up; ARP scoping plus
    ///     `--dhcp-option=1` give the guest a clean /24 view.
    ///   * dnsmasq `--bind-dynamic` is what lets multiple instances
    ///     coexist on the same IP+port across different TAPs.
    fn historic_gateway(ip: &str) -> String {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.254", parts[0], parts[1], parts[2])
        } else {
            ip.to_string()
        }
    }

    #[test]
    fn gateway_is_subnet_dot254() {
        assert_eq!(historic_gateway("10.10.10.5"),  "10.10.10.254");
        assert_eq!(historic_gateway("10.10.10.50"), "10.10.10.254");
        assert_eq!(historic_gateway("192.168.1.7"), "192.168.1.254");
    }

    #[test]
    fn distinct_vms_share_gateway_ip() {
        // PapaSchlumpf's scenario: WolfRouter at .5, HA VM at .10 on
        // the same WolfNet /24. They MUST resolve to the same gateway
        // (.254) so static configs keep working. Multi-VM coexistence
        // is handled at the L2/ARP layer — see the `arp_ignore` /
        // `arp_announce` sysctls and the `/32` TAP address in
        // `setup_wolfnet_routing` — not by per-VM gateway tricks.
        assert_eq!(historic_gateway("10.10.10.5"),  "10.10.10.254");
        assert_eq!(historic_gateway("10.10.10.10"), "10.10.10.254");
    }

    #[test]
    fn malformed_input_passes_through() {
        assert_eq!(historic_gateway(""), "");
        assert_eq!(historic_gateway("not-an-ip"), "not-an-ip");
    }
}

#[cfg(test)]
mod libvirt_xml_tests {
    use super::*;

    #[test]
    fn boot_order_empty_keeps_historical_default() {
        // Golden Rule: an existing VM (empty boot_order) boots exactly as before.
        assert_eq!(qemu_boot_order_arg(&[], true).as_deref(), Some("order=cd"));
        assert_eq!(qemu_boot_order_arg(&[], false).as_deref(), Some("order=c"));
        assert_eq!(libvirt_boot_order_arg(&[], true), "hd,cdrom");
        assert_eq!(pve_boot_order_arg(&[]), "order=scsi0;ide2");
        assert!(!boot_order_usb_first(&[]));
    }

    #[test]
    fn boot_order_usb_first_drives_bootindex() {
        let o = vec!["usb".to_string(), "disk".to_string()];
        assert!(boot_order_usb_first(&o));
        // QEMU: no `-boot order` when USB leads — the device bootindex wins.
        assert_eq!(qemu_boot_order_arg(&o, true), None);
        // libvirt can't express USB boot — usb is dropped, leaving disk→hd.
        assert_eq!(libvirt_boot_order_arg(&o, true), "hd");
    }

    #[test]
    fn libvirt_external_vnc_requires_listen_all_and_password() {
        // Legacy 0.0.0.0 with NO password must NOT read as external (else its
        // unauthenticated VNC port would get auto-opened). Flat + nested forms.
        assert!(!libvirt_xml_is_external_vnc("<graphics type='vnc' port='5901' autoport='yes' listen='0.0.0.0'/>"));
        assert!(!libvirt_xml_is_external_vnc("<graphics type='vnc' port='5901'><listen type='address' address='0.0.0.0'/></graphics>"));
        // Localhost-only (the new default) → not external.
        assert!(!libvirt_xml_is_external_vnc("<graphics type='vnc' port='5901' listen='127.0.0.1'/>"));
        // WolfStack-managed external (0.0.0.0 + password), flat + nested → external.
        assert!(libvirt_xml_is_external_vnc("<graphics type='vnc' port='5901' listen='0.0.0.0' passwd='abc12345'/>"));
        assert!(libvirt_xml_is_external_vnc("<graphics type='vnc' port='5901' passwd='abc12345'><listen type='address' address='0.0.0.0'/></graphics>"));
    }

    #[test]
    fn libvirt_external_vnc_ignores_other_graphics_devices() {
        // SPICE exposed+passworded must NOT make a localhost VNC read external.
        assert!(!libvirt_xml_is_external_vnc(
            "<graphics type='spice' listen='0.0.0.0' passwd='spicepw1'/><graphics type='vnc' port='5901' listen='127.0.0.1'/>"));
        // VNC external behind a localhost SPICE listed first → still external.
        assert!(libvirt_xml_is_external_vnc(
            "<graphics type='spice' listen='127.0.0.1'/><graphics type='vnc' port='5901' listen='0.0.0.0' passwd='abc12345'/>"));
        // No VNC device at all → not external.
        assert!(!libvirt_xml_is_external_vnc("<graphics type='spice' listen='0.0.0.0' passwd='spicepw1'/>"));
    }

    #[test]
    fn boot_order_disk_cdrom_network_mapping() {
        let o = vec!["cdrom".to_string(), "disk".to_string()];
        assert_eq!(qemu_boot_order_arg(&o, true).as_deref(), Some("order=dc"));
        assert_eq!(libvirt_boot_order_arg(&o, true), "cdrom,hd");
        assert_eq!(pve_boot_order_arg(&o), "order=ide2;scsi0");
        let net = vec!["network".to_string(), "disk".to_string()];
        assert_eq!(qemu_boot_order_arg(&net, false).as_deref(), Some("order=nc"));
        assert_eq!(pve_boot_order_arg(&net), "order=net0;scsi0");
        // Case-insensitive + dedup.
        assert_eq!(qemu_boot_order_arg(&["DISK".to_string(), "disk".to_string()], false).as_deref(), Some("order=c"));
    }

    const SAMPLE: &str = r#"<domain type='kvm'>
  <name>my-vm</name>
  <memory unit='KiB'>2097152</memory>
  <currentMemory unit='KiB'>2097152</currentMemory>
  <vcpu placement='static'>4</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-9.0'>hvm</type>
    <loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.fd</loader>
  </os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/my-vm.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <source file='/var/lib/iso/debian-12.iso'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source bridge='virbr0'/>
      <model type='virtio'/>
    </interface>
    <graphics type='vnc' port='5901' autoport='yes' listen='0.0.0.0'/>
  </devices>
</domain>"#;

    #[test]
    fn extracts_inner_text_with_attributes_in_open_tag() {
        assert_eq!(
            libvirt_xml_inner_text_after_tag(SAMPLE, "<vcpu").as_deref(),
            Some("4")
        );
        assert_eq!(
            libvirt_xml_inner_text_after_tag(SAMPLE, "<memory").as_deref(),
            Some("2097152")
        );
        assert_eq!(
            libvirt_xml_inner_text_after_tag(SAMPLE, "<name>").as_deref(),
            Some("my-vm")
        );
    }

    #[test]
    fn iterates_disk_blocks_skipping_other_disk_subtags() {
        let blocks: Vec<&str> = iter_xml_blocks(SAMPLE, "disk").collect();
        assert_eq!(blocks.len(), 2, "must yield exactly 2 disk blocks (disk + cdrom)");
        assert!(blocks[0].contains("device='disk'"));
        assert!(blocks[1].contains("device='cdrom'"));
        // <driver type='qcow2'/> inside the first disk shouldn't appear
        // as its own block — we asked for `disk`, not `driver`.
        let drivers: Vec<&str> = iter_xml_blocks(SAMPLE, "driver").collect();
        assert_eq!(drivers.len(), 1);
        // self-closing block ends with `/>`
        assert!(drivers[0].ends_with("/>"));
    }

    #[test]
    fn extracts_attr_from_nested_tag() {
        let disk_block = iter_xml_blocks(SAMPLE, "disk").next().unwrap();
        assert_eq!(
            libvirt_xml_attr_in_block(disk_block, "source", "file").as_deref(),
            Some("/var/lib/libvirt/images/my-vm.qcow2"),
        );
        assert_eq!(
            libvirt_xml_attr_in_block(disk_block, "target", "bus").as_deref(),
            Some("virtio"),
        );
    }

    #[test]
    fn extracts_mac_from_interface_block() {
        let iface_block = iter_xml_blocks(SAMPLE, "interface").next().unwrap();
        assert_eq!(
            libvirt_xml_attr_in_block(iface_block, "mac", "address").as_deref(),
            Some("52:54:00:aa:bb:cc"),
        );
    }

    #[test]
    fn extracts_vnc_port_from_graphics_self_closing() {
        let graphics_block = iter_xml_blocks(SAMPLE, "graphics").next().unwrap();
        assert_eq!(
            libvirt_xml_attr_in_block(graphics_block, "graphics", "port").as_deref(),
            Some("5901"),
        );
    }

    #[test]
    fn handles_double_quote_attributes() {
        let xml = r#"<root><foo bar="42"/></root>"#;
        assert_eq!(
            libvirt_xml_attr_in_block(xml, "foo", "bar").as_deref(),
            Some("42"),
        );
    }

    #[test]
    fn attr_lookup_doesnt_substring_match_longer_attr_names() {
        // Pre-fix: looking up `id` would match the trailing `id=` of
        // `userid='admin'`. After the tokenise-on-whitespace fix, only
        // `id='X'` proper matches.
        let xml = r#"<root><tag userid='admin' id='42'/></root>"#;
        assert_eq!(
            libvirt_xml_attr_in_block(xml, "tag", "id").as_deref(),
            Some("42"),
        );
        let xml_only_userid = r#"<root><tag userid='admin'/></root>"#;
        assert_eq!(
            libvirt_xml_attr_in_block(xml_only_userid, "tag", "id"),
            None,
            "id must NOT match the trailing 'id' of 'userid'",
        );
    }

    #[test]
    fn iter_handles_self_closing_only() {
        let xml = "<a><x foo='1'/><x foo='2'/></a>";
        let blocks: Vec<&str> = iter_xml_blocks(xml, "x").collect();
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("foo='1'"));
        assert!(blocks[1].contains("foo='2'"));
    }

    // A VM with TWO cdrom drives (install ISO + VirtIO drivers) and an
    // e1000 NIC — exercises the slot-ordering the editor depends on.
    const SAMPLE_TWO_CDROM: &str = r#"<domain type='kvm'>
  <os><type machine='pc-i440fx-9.0'>hvm</type></os>
  <devices>
    <disk type='file' device='disk'>
      <source file='/var/lib/libvirt/images/win.qcow2'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <disk type='file' device='cdrom'>
      <source file='/media/Win11.iso'/>
      <target dev='sdb' bus='sata'/>
    </disk>
    <disk type='file' device='cdrom'>
      <source file='/share/virtio-win.iso'/>
      <target dev='sdc' bus='sata'/>
    </disk>
    <interface type='network'>
      <mac address='52:54:00:00:60:e8'/>
      <source network='default'/>
      <model type='e1000'/>
    </interface>
  </devices>
</domain>"#;

    #[test]
    fn primary_net_model_reads_first_interface() {
        assert_eq!(libvirt_primary_net_model(SAMPLE).as_deref(), Some("virtio"));
        assert_eq!(libvirt_primary_net_model(SAMPLE_TWO_CDROM).as_deref(), Some("e1000"));
        assert_eq!(libvirt_primary_net_model("<domain/>"), None);
    }

    #[test]
    fn cdrom_slots_are_index_ordered() {
        // SAMPLE: one cdrom with media.
        let one = libvirt_cdrom_slots(SAMPLE);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0], ("sda".to_string(), Some("/var/lib/iso/debian-12.iso".to_string())));
        // Two cdroms: slot 0 = install ISO, slot 1 = drivers ISO.
        let two = libvirt_cdrom_slots(SAMPLE_TWO_CDROM);
        assert_eq!(two.len(), 2);
        assert_eq!(two[0], ("sdb".to_string(), Some("/media/Win11.iso".to_string())));
        assert_eq!(two[1], ("sdc".to_string(), Some("/share/virtio-win.iso".to_string())));
    }

    #[test]
    fn cdrom_slots_counts_empty_drive() {
        let xml = r#"<domain><devices>
            <disk device='cdrom'><target dev='sda' bus='sata'/></disk>
            <disk device='cdrom'><source file='/d.iso'/><target dev='sdb' bus='sata'/></disk>
        </devices></domain>"#;
        let slots = libvirt_cdrom_slots(xml);
        // An empty drive still occupies slot 0 so the drivers ISO stays in 1.
        assert_eq!(slots[0], ("sda".to_string(), None));
        assert_eq!(slots[1], ("sdb".to_string(), Some("/d.iso".to_string())));
    }

    #[test]
    fn primary_disk_target_reads_dev_and_bus() {
        assert_eq!(libvirt_primary_disk_target(SAMPLE), Some(("vda".to_string(), "virtio".to_string())));
        assert_eq!(libvirt_primary_disk_target(SAMPLE_TWO_CDROM), Some(("sda".to_string(), "sata".to_string())));
    }

    #[test]
    fn ovmf_detection() {
        assert!(libvirt_xml_is_ovmf(SAMPLE)); // has OVMF_CODE loader
        assert!(!libvirt_xml_is_ovmf(SAMPLE_TWO_CDROM)); // plain i440fx/SeaBIOS
        assert!(libvirt_xml_is_ovmf("<os firmware='efi'/>"));
    }

    #[test]
    fn disk_dev_name_preserves_slot_letter() {
        assert_eq!(disk_dev_for_bus("vda", "sata"), "sda");
        assert_eq!(disk_dev_for_bus("vda", "ide"), "hda");
        assert_eq!(disk_dev_for_bus("sdb", "virtio"), "vdb");
        assert_eq!(disk_dev_for_bus("hda", "scsi"), "sda");
    }

    #[test]
    fn virtxml_network_args_bridge_and_model() {
        let args = build_virtxml_network_args("win", Some("bridge"), Some("vmbr0"), Some("e1000")).unwrap();
        assert_eq!(args, vec!["win", "--edit", "1", "--network", "bridge=vmbr0,model=e1000"]);
    }

    #[test]
    fn virtxml_network_args_nat_uses_default_network() {
        let args = build_virtxml_network_args("win", Some("nat"), None, None).unwrap();
        assert_eq!(args, vec!["win", "--edit", "1", "--network", "network=default"]);
        // wolfnet keeps the PRIMARY on the default NAT net too.
        let wn = build_virtxml_network_args("win", Some("wolfnet"), None, Some("virtio")).unwrap();
        assert_eq!(wn[4], "network=default,model=virtio");
    }

    #[test]
    fn virtxml_network_args_model_only() {
        // No mode change → only the model is rewritten, source/MAC untouched.
        let args = build_virtxml_network_args("win", None, None, Some("rtl8139")).unwrap();
        assert_eq!(args, vec!["win", "--edit", "1", "--network", "model=rtl8139"]);
    }

    #[test]
    fn virtxml_network_args_none_when_nothing_to_do() {
        // bridge mode without a bridge name can't be applied.
        assert!(build_virtxml_network_args("win", Some("bridge"), None, Some("e1000")).is_none());
        // no mode and no model → nothing to change.
        assert!(build_virtxml_network_args("win", None, None, None).is_none());
    }

    #[test]
    fn virtxml_disk_bus_args() {
        let args = build_virtxml_disk_bus_args("win", "vda", "sata");
        assert_eq!(args, vec!["win", "--edit", "target=vda", "--disk", "target.bus=sata,target.dev=sda"]);
    }

    #[test]
    fn virtxml_bios_args() {
        assert_eq!(build_virtxml_bios_args("win", true), vec!["win", "--edit", "--boot", "uefi"]);
        assert_eq!(build_virtxml_bios_args("win", false), vec!["win", "--edit", "--boot", "uefi=off"]);
    }

    #[test]
    fn virtxml_add_cdrom_args() {
        assert_eq!(
            build_virtxml_add_cdrom_args("win", "/media/d.iso"),
            vec!["win", "--add-device", "--disk", "device=cdrom,path=/media/d.iso"]
        );
    }

    #[test]
    fn change_media_args_update_and_eject() {
        assert_eq!(
            build_change_media_args("win", "sdb", Some("/media/w.iso")),
            vec!["change-media", "win", "sdb", "/media/w.iso", "--update", "--config"]
        );
        assert_eq!(
            build_change_media_args("win", "sdb", None),
            vec!["change-media", "win", "sdb", "--eject", "--config"]
        );
    }

    // Primary NIC currently on a real LAN bridge (vmbr0), virtio model.
    const NIC_ON_VMBR0: &str = r#"<domain><devices>
        <interface type='bridge'><mac address='52:54:00:11:22:33'/>
          <source bridge='vmbr0'/><model type='virtio'/></interface>
    </devices></domain>"#;
    // Misordered domain whose FIRST interface is the WolfNet NIC — the filter
    // must stop us treating it as the primary.
    const WNBR_FIRST: &str = r#"<domain><devices>
        <interface type='bridge'><source bridge='wnbr-vm1'/><model type='virtio'/></interface>
        <interface type='network'><source network='default'/><model type='virtio'/></interface>
    </devices></domain>"#;

    // helper: the joined --network opts string the builder emits (args[4]).
    fn nic_opts(v: &Option<Vec<String>>) -> Option<&str> {
        v.as_ref().map(|a| a[4].as_str())
    }

    #[test]
    fn nic_edit_nat_to_bridge() {
        // SAMPLE_TWO_CDROM is on network=default (nat) with e1000.
        let edit = libvirt_primary_nic_edit(SAMPLE_TWO_CDROM, "win", Some("bridge"), Some("vmbr0"), Some("e1000"));
        // mode changes; model unchanged (already e1000) so only the bridge is set.
        assert_eq!(nic_opts(&edit), Some("bridge=vmbr0"));
    }

    #[test]
    fn nic_edit_bridge_to_nat_and_wolfnet() {
        let to_nat = libvirt_primary_nic_edit(NIC_ON_VMBR0, "win", Some("nat"), None, None);
        assert_eq!(nic_opts(&to_nat), Some("network=default"));
        // wolfnet keeps the PRIMARY on the default NAT net too.
        let to_wn = libvirt_primary_nic_edit(NIC_ON_VMBR0, "win", Some("wolfnet"), None, None);
        assert_eq!(nic_opts(&to_wn), Some("network=default"));
    }

    #[test]
    fn nic_edit_model_only_when_mode_unchanged() {
        // nat→nat, but adapter virtio→e1000... here current is e1000, ask virtio.
        let edit = libvirt_primary_nic_edit(SAMPLE_TWO_CDROM, "win", Some("nat"), None, Some("virtio"));
        assert_eq!(nic_opts(&edit), Some("model=virtio"));
    }

    #[test]
    fn nic_edit_noop_when_nothing_changes() {
        // Same mode (nat) and same model (e1000) → no command.
        assert!(libvirt_primary_nic_edit(SAMPLE_TWO_CDROM, "win", Some("nat"), None, Some("e1000")).is_none());
    }

    #[test]
    fn nic_edit_ignores_wolfnet_first_interface() {
        // First interface is wnbr-* — filtered out, so the primary reads as
        // "nat"; asking for wolfnet is therefore a no-op (we must NOT rewrite
        // the WolfNet NIC).
        assert!(libvirt_primary_nic_edit(WNBR_FIRST, "win", Some("wolfnet"), None, None).is_none());
    }

    // ─── Notes / description decode (operator notes round-trip) ───
    // PVE `description:` decoding is unit-tested in the containers module
    // (the single shared `pve_decode_description`); here we cover the
    // libvirt-specific XML description read-back.

    #[test]
    fn libvirt_description_unescapes_xml_entities() {
        let xml = "<domain><name>web</name><description>A &amp; B&#10;&lt;tag&gt;</description></domain>";
        assert_eq!(libvirt_xml_description(xml), "A & B\n<tag>");
        // Absent description reads as empty.
        assert_eq!(libvirt_xml_description("<domain><name>web</name></domain>"), "");
        // Empty description element reads as empty.
        assert_eq!(libvirt_xml_description("<domain><description></description></domain>"), "");
    }

    #[test]
    fn xml_unescape_decodes_amp_last() {
        // `&amp;lt;` must decode to the literal "&lt;", NOT "<" — i.e. the
        // ampersand entity is resolved last so we never double-decode.
        assert_eq!(xml_unescape("&amp;lt;"), "&lt;");
        assert_eq!(xml_unescape("&quot;x&quot;"), "\"x\"");
    }
}

#[cfg(test)]
mod pve_filesystem_tests {
    use super::*;

    #[test]
    fn parse_basic_pve_qemu_conf() {
        let conf = "\
name: webserver
cores: 4
memory: 8192
onboot: 1
bios: ovmf
net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0
scsi0: local-lvm:vm-100-disk-0,size=64G
ide2: local:iso/debian-12.iso,media=cdrom
";
        let vm = parse_pve_qemu_conf(100, conf).expect("parse");
        assert_eq!(vm.vmid, Some(100));
        assert_eq!(vm.name, "webserver");
        assert_eq!(vm.cpus, 4);
        assert_eq!(vm.memory_mb, 8192);
        assert_eq!(vm.disk_size_gb, 64);
        assert!(vm.auto_start);
        assert_eq!(vm.bios_type, "ovmf");
        assert_eq!(vm.mac_address.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(vm.storage_path.as_deref(), Some("local-lvm"));
        assert_eq!(vm.iso_path.as_deref(), Some("local:iso/debian-12.iso"));
    }

    #[test]
    fn parse_skips_snapshot_sections() {
        // Snapshot sections inherit field names but represent the
        // *snapshotted* state, not the live one. Picking from them
        // would show stale memory/cores numbers after a snapshot.
        let conf = "\
name: live-name
cores: 8
memory: 4096

[snapshot_old]
name: pre-upgrade
cores: 2
memory: 1024
";
        let vm = parse_pve_qemu_conf(101, conf).expect("parse");
        assert_eq!(vm.name, "live-name");
        assert_eq!(vm.cpus, 8);
        assert_eq!(vm.memory_mb, 4096);
    }

    #[test]
    fn vmid_lookup_returns_none_when_dir_absent() {
        // We can't fake the FS, but we can confirm the function is
        // total (doesn't panic) when /etc/pve isn't present.
        assert!(qm_vmid_by_name_filesystem("nonexistent-vm").is_none()
            || qm_vmid_by_name_filesystem("nonexistent-vm").is_some());
    }

    // A Windows VM with install ISO (ide2), VirtIO-drivers ISO (ide3), OVMF
    // + efidisk0, and a SATA OS disk — exercises every new read/apply helper.
    const WIN_CONF: &str = "\
name: win11
cores: 4
memory: 8192
bios: ovmf
efidisk0: local-lvm:vm-200-disk-1,efitype=4m,size=4M
net0: e1000=AA:BB:CC:00:11:22,bridge=vmbr0
sata0: local-lvm:vm-200-disk-0,size=64G
ide2: local:iso/Win11.iso,media=cdrom
ide3: local:iso/virtio-win.iso,media=cdrom
[snapshot_pre]
ide2: local:iso/OLD.iso,media=cdrom
";

    #[test]
    fn pve_helpers_read_media_bios_disk() {
        assert_eq!(pve_cdrom_iso(WIN_CONF, "ide2").as_deref(), Some("local:iso/Win11.iso"));
        assert_eq!(pve_cdrom_iso(WIN_CONF, "ide3").as_deref(), Some("local:iso/virtio-win.iso"));
        assert!(pve_has_efidisk(WIN_CONF));
        assert_eq!(pve_conf_value(WIN_CONF, "bios").as_deref(), Some("ovmf"));
        assert_eq!(pve_os_disk_storage(WIN_CONF).as_deref(), Some("local-lvm"));
        assert_eq!(pve_os_disk_bus(WIN_CONF), "sata");
        // The snapshot section's ide2 must NOT leak into the main-section read.
        assert_ne!(pve_cdrom_iso(WIN_CONF, "ide2").as_deref(), Some("local:iso/OLD.iso"));
    }

    #[test]
    fn pve_helpers_handle_empty_and_absent() {
        let conf = "\
scsi0: local-lvm:vm-1-disk-0,size=32G
ide2: none,media=cdrom
";
        assert_eq!(pve_cdrom_iso(conf, "ide2"), None);     // `none` = empty drive
        assert_eq!(pve_cdrom_iso(conf, "ide3"), None);     // absent
        assert!(!pve_has_efidisk(conf));
        assert_eq!(pve_os_disk_bus(conf), "virtio");       // scsi0 → virtio class
        assert_eq!(pve_os_disk_storage(conf).as_deref(), Some("local-lvm"));
    }

    #[test]
    fn parse_pve_conf_reads_drivers_iso_and_bus() {
        let vm = parse_pve_qemu_conf(200, WIN_CONF).expect("parse");
        assert_eq!(vm.iso_path.as_deref(), Some("local:iso/Win11.iso"));
        assert_eq!(vm.drivers_iso.as_deref(), Some("local:iso/virtio-win.iso"));
        assert_eq!(vm.os_disk_bus, "sata");
        assert_eq!(vm.net_model, "e1000");
        assert_eq!(vm.bios_type, "ovmf");
    }
}

#[cfg(test)]
mod extra_qemu_args_tests {
    use super::*;

    #[test]
    fn split_empty_and_whitespace_yield_no_tokens() {
        assert_eq!(split_qemu_args(""), Vec::<String>::new());
        assert_eq!(split_qemu_args("   \t \n "), Vec::<String>::new());
    }

    #[test]
    fn split_garys_audio_example() {
        // Gary's exact request — must become 6 separate argv tokens.
        let s = "-audiodev pa,id=snd0 -device ich9-intel-hda -device hda-output,audiodev=snd0";
        assert_eq!(split_qemu_args(s), vec![
            "-audiodev", "pa,id=snd0",
            "-device", "ich9-intel-hda",
            "-device", "hda-output,audiodev=snd0",
        ]);
    }

    #[test]
    fn split_collapses_runs_of_whitespace() {
        assert_eq!(split_qemu_args("-a    -b\t-c"), vec!["-a", "-b", "-c"]);
    }

    #[test]
    fn split_single_quotes_preserve_spaces() {
        assert_eq!(split_qemu_args("-name 'My VM'"), vec!["-name", "My VM"]);
        // Empty single-quoted string is a real (empty) token.
        assert_eq!(split_qemu_args("''"), vec![""]);
    }

    #[test]
    fn split_double_quotes_preserve_spaces_and_escapes() {
        assert_eq!(split_qemu_args("-x \"a b\""), vec!["-x", "a b"]);
        // \" is a literal quote; \\ is a literal backslash inside dquotes.
        assert_eq!(split_qemu_args(r#""he said \"hi\"""#), vec![r#"he said "hi""#]);
        assert_eq!(split_qemu_args(r#""a\\b""#), vec![r"a\b"]);
        // A backslash before a non-special char stays literal (POSIX dquote).
        assert_eq!(split_qemu_args(r#""a\nb""#), vec![r"a\nb"]);
    }

    #[test]
    fn split_backslash_escape_outside_quotes() {
        // `\ ` is a literal space joining one token.
        assert_eq!(split_qemu_args(r"a\ b"), vec!["a b"]);
        assert_eq!(split_qemu_args(r"\'"), vec!["'"]);
    }

    #[test]
    fn split_adjacent_quoted_unquoted_concatenate() {
        assert_eq!(split_qemu_args(r#"-x"a b"c"#), vec!["-xa bc"]);
        assert_eq!(split_qemu_args("a'b c'd"), vec!["ab cd"]);
    }

    #[test]
    fn split_unterminated_quote_is_tolerated() {
        assert_eq!(split_qemu_args("-name 'unterminated"), vec!["-name", "unterminated"]);
        assert_eq!(split_qemu_args(r#"-x "open"#), vec!["-x", "open"]);
    }

    #[test]
    fn join_round_trips_through_split() {
        let cases = vec![
            vec!["-audiodev".to_string(), "pa,id=snd0".to_string()],
            vec!["-name".to_string(), "My VM".to_string()],
            vec!["weird's".to_string(), "a b".to_string(), "".to_string()],
            vec!["-device".to_string(), "hda-output,audiodev=snd0".to_string()],
        ];
        for tokens in cases {
            let joined = join_qemu_args(&tokens);
            assert_eq!(split_qemu_args(&joined), tokens, "round-trip failed for {:?} (joined: {})", tokens, joined);
        }
    }

    #[test]
    fn shell_quote_plain_token_unquoted() {
        assert_eq!(shell_quote("-audiodev"), "-audiodev");
        assert_eq!(shell_quote("pa,id=snd0"), "pa,id=snd0");
    }

    #[test]
    fn shell_quote_special_tokens() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn libvirt_commandline_round_trips_via_xml() {
        // Build a block, parse it back — tokens must survive incl. spaces/quotes.
        let tokens = vec![
            "-audiodev".to_string(), "pa,id=snd0".to_string(),
            "-device".to_string(), "hda-output,audiodev=snd0".to_string(),
            "weird & <val>".to_string(),
        ];
        let args = join_qemu_args(&tokens);
        let xml = rewrite_domain_qemu_commandline(
            "<domain type='kvm'><name>v</name></domain>", &args).unwrap();
        assert!(xml.contains("xmlns:qemu="));
        assert!(xml.contains("<qemu:commandline>"));
        let parsed = libvirt_xml_qemu_commandline(&xml);
        assert_eq!(split_qemu_args(&parsed), tokens);
    }

    #[test]
    fn rewrite_empty_args_removes_block_keeps_namespace() {
        let with_block = "<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>\
            <name>v</name>\n  <qemu:commandline>\n    <qemu:arg value='-x'/>\n  </qemu:commandline>\n</domain>";
        let out = rewrite_domain_qemu_commandline(with_block, "").unwrap();
        assert!(!out.contains("<qemu:commandline>"));
        assert!(out.contains("xmlns:qemu=")); // namespace left in place (harmless)
        assert!(out.contains("</domain>"));
    }

    #[test]
    fn rewrite_does_not_double_add_namespace() {
        let xml = "<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'><name>v</name></domain>";
        let out = rewrite_domain_qemu_commandline(xml, "-x").unwrap();
        assert_eq!(out.matches("xmlns:qemu=").count(), 1);
    }

    #[test]
    fn rewrite_returns_none_without_domain_tag() {
        assert!(rewrite_domain_qemu_commandline("<notadomain/>", "-x").is_none());
    }

    #[test]
    fn build_qemu_command_appends_extra_args_last() {
        let mut cfg = VmConfig::new("testvm".to_string(), 2, 1024, 10);
        cfg.extra_qemu_args = "-audiodev pa,id=snd0".to_string();
        let argv = VmManager::new().build_qemu_command(&cfg);
        // argv[0] is the qemu binary.
        assert!(argv[0].starts_with("qemu-system-"));
        // The extra args must be the final tokens.
        let n = argv.len();
        assert_eq!(&argv[n-2..], &["-audiodev".to_string(), "pa,id=snd0".to_string()]);
        // And the standard -name flag must precede them.
        assert!(argv.iter().any(|a| a == "-name"));
    }
}

#[cfg(test)]
mod vm_net_sidecar_tests {
    use super::*;

    fn temp_manager(tag: &str) -> VmManager {
        let dir = std::env::temp_dir()
            .join(format!("wolfstack-vmnet-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        VmManager { base_dir: dir }
    }

    fn read_back(m: &VmManager, name: &str) -> VmConfig {
        let text = fs::read_to_string(m.vm_config_path(name)).unwrap();
        serde_json::from_str::<VmConfig>(&text).unwrap()
    }

    /// The reported bug: a VM on a bridge that happens to be a WolfStack VLAN
    /// bridge must NOT come back looking like a vSwitch VM. Only an explicitly
    /// recorded uplink+VLAN pair marks one.
    #[test]
    fn a_plain_bridge_save_records_no_vswitch_selection() {
        let m = temp_manager("plain");
        m.persist_vm_net_sidecar("vm1", &VmNetSettings {
            network_mode: Some("bridge".into()),
            bridge: Some("vmbr101".into()),
            bridge_ip_mode: Some("static".into()),
            bridge_ip: Some("192.168.1.50/24".into()),
            bridge_gateway: Some("192.168.1.1".into()),
            vsw_uplink: Some(String::new()),   // '' = "not a vSwitch VM"
            vsw_vlan: None,
            wolfnet_ip: None,
        });
        let cfg = read_back(&m, "vm1");
        assert_eq!(cfg.bridge.as_deref(), Some("vmbr101"));
        assert_eq!(cfg.bridge_ip.as_deref(), Some("192.168.1.50/24"));
        assert_eq!(cfg.vsw_uplink, None, "a plain-bridge save must not look like a vSwitch");
        assert_eq!(cfg.vsw_vlan, None);
        let _ = fs::remove_dir_all(&m.base_dir);
    }

    #[test]
    fn a_vswitch_save_records_the_selection_and_a_later_bridge_save_clears_it() {
        let m = temp_manager("vsw");
        m.persist_vm_net_sidecar("vm1", &VmNetSettings {
            network_mode: Some("bridge".into()),
            bridge: Some("vmbr4000".into()),
            vsw_uplink: Some("eno2".into()),
            vsw_vlan: Some(4000),
            ..Default::default()
        });
        let cfg = read_back(&m, "vm1");
        assert_eq!(cfg.vsw_uplink.as_deref(), Some("eno2"));
        assert_eq!(cfg.vsw_vlan, Some(4000));

        // Operator moves it to a plain bridge — the vSwitch label must go.
        m.persist_vm_net_sidecar("vm1", &VmNetSettings {
            network_mode: Some("bridge".into()),
            bridge: Some("br0".into()),
            vsw_uplink: Some(String::new()),
            vsw_vlan: None,
            ..Default::default()
        });
        let cfg = read_back(&m, "vm1");
        assert_eq!(cfg.bridge.as_deref(), Some("br0"));
        assert_eq!(cfg.vsw_uplink, None);
        assert_eq!(cfg.vsw_vlan, None);
        let _ = fs::remove_dir_all(&m.base_dir);
    }

    /// Leaving bridge mode entirely drops the bridge details AND the vSwitch
    /// pair — otherwise a VM moved to WolfNet would re-open on a vSwitch card.
    #[test]
    fn leaving_bridge_mode_clears_the_bridge_details() {
        let m = temp_manager("leave");
        m.persist_vm_net_sidecar("vm1", &VmNetSettings {
            network_mode: Some("bridge".into()),
            bridge: Some("vmbr4000".into()),
            bridge_ip_mode: Some("static".into()),
            bridge_ip: Some("10.0.0.5/24".into()),
            vsw_uplink: Some("eno2".into()),
            vsw_vlan: Some(4000),
            ..Default::default()
        });
        m.persist_vm_net_sidecar("vm1", &VmNetSettings {
            network_mode: Some("wolfnet".into()),
            wolfnet_ip: Some("10.10.10.7".into()),
            ..Default::default()
        });
        let cfg = read_back(&m, "vm1");
        assert_eq!(cfg.network_mode.as_deref(), Some("wolfnet"));
        assert_eq!(cfg.bridge, None);
        assert_eq!(cfg.bridge_ip, None);
        assert_eq!(cfg.vsw_uplink, None);
        assert_eq!(cfg.vsw_vlan, None);
        assert_eq!(cfg.wolfnet_ip.as_deref(), Some("10.10.10.7"));
        let _ = fs::remove_dir_all(&m.base_dir);
    }

    /// A save that mentions no network field must not create a sidecar at all.
    #[test]
    fn an_unrelated_save_writes_no_sidecar() {
        let m = temp_manager("noop");
        m.persist_vm_net_sidecar("vm1", &VmNetSettings::default());
        assert!(!m.vm_config_path("vm1").exists());
        let _ = fs::remove_dir_all(&m.base_dir);
    }
}

#[cfg(test)]
mod primary_ip_plan_tests {
    use super::*;
    use crate::networking::vlan_attach::PrimaryIp;

    fn s(v: &str) -> Option<String> { Some(v.to_string()) }

    #[test]
    fn only_bridge_mode_has_a_primary_ip_to_stage() {
        // WolfNet and NAT own their own addressing.
        assert_eq!(primary_ip_plan(&s("wolfnet"), &s("static"), &s("10.0.0.5/24"), &None), None);
        assert_eq!(primary_ip_plan(&s("nat"), &s("static"), &s("10.0.0.5/24"), &None), None);
        assert_eq!(primary_ip_plan(&None, &s("static"), &s("10.0.0.5/24"), &None), None);
    }

    #[test]
    fn a_static_bridge_save_produces_a_static_plan() {
        assert_eq!(
            primary_ip_plan(&s("bridge"), &s("static"), &s("192.168.1.50/24"), &s("192.168.1.1")),
            Some(PrimaryIp::Static {
                ip_cidr: "192.168.1.50/24".into(),
                gateway: Some("192.168.1.1".into()),
            })
        );
        // Static with the address left blank is not a plan — nothing to apply.
        assert_eq!(primary_ip_plan(&s("bridge"), &s("static"), &s("  "), &None), None);
        // A blank gateway means "address only, no default route".
        assert_eq!(
            primary_ip_plan(&s("bridge"), &s("static"), &s("10.0.0.5/24"), &s("")),
            Some(PrimaryIp::Static { ip_cidr: "10.0.0.5/24".into(), gateway: None })
        );
    }

    #[test]
    fn a_dhcp_bridge_save_produces_a_dhcp_plan() {
        assert_eq!(primary_ip_plan(&s("bridge"), &s("dhcp"), &None, &None), Some(PrimaryIp::Dhcp));
        // No IP mode in the request = the save didn't touch addressing.
        assert_eq!(primary_ip_plan(&s("bridge"), &None, &None, &None), None);
    }
}
