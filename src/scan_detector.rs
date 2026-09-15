// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Outbound scan detection — catches a host being used to scan others
//! before the provider's abuse desk does.
//!
//! ## Two detection paths (they cover different scanners)
//!
//! **1. SYN_SENT cardinality (connect()-based scanners).**
//! Every sample we read `/proc/net/tcp` and `/proc/net/tcp6` for sockets
//! in SYN_SENT state. Each row gives a (local_pid via `inode→pid`,
//! remote_addr) pair. We count distinct remote addresses per process
//! across a rolling window; above `threshold_destinations` = suspect.
//! This catches scanners that use the *kernel TCP stack*: `nmap -sT`,
//! Python-`socket.connect()` scanners, most application-level fan-out.
//!
//! **2. Raw / packet socket holders (stateless scanners).**
//! `zmap`, `masscan`, and `nmap -sS` (as root) do NOT use the kernel TCP
//! stack — they craft raw SYN packets and send them via an `AF_PACKET`
//! or `SOCK_RAW` socket, reading replies with libpcap. They therefore
//! create **zero SYN_SENT entries**, and path #1 is structurally blind
//! to them. (This is the real reason the July 2026 `mouse` zmap run was
//! never caught in-flight — the detector as originally written could not
//! see it, despite a comment here once claiming it would.) Path #2 closes
//! that gap: we enumerate processes holding an `AF_PACKET`/`SOCK_RAW`
//! socket (`/proc/net/packet`, `/proc/net/raw[6]`, joined via the same
//! `inode→pid` map), and flag any that is not allowlisted and persists
//! for `raw_socket_min_samples` consecutive samples. The persistence gate
//! + allowlist (dhclient, tcpdump, ping, keepalived, …) keep brief/benign
//!   raw-socket users from being actioned.
//!
//! ## Why /proc not eBPF
//!
//! eBPF would be more accurate but requires kernel headers/BCC that
//! minimal installs may lack. Everything here reads `/proc/net/*`, which
//! exists on every Linux kernel since 2.0 — including the AF_PACKET and
//! raw-socket tables path #2 relies on.
//!
//! ## What we do on detection
//!
//! 1. Log a CRITICAL audit entry with the offending PID + comm
//! 2. SIGTERM (then SIGKILL after 5s) the process
//! 3. Add an iptables OUTPUT rule for that PID's UID (kernel-level
//!    block of all further outbound from the same user)
//! 4. Push an alert into the WolfStack alert log
//! 5. Surface in the Fleet Security UI
//!
//! ## False-positive mitigation
//!
//! Many legitimate processes make many outbound connections (apt
//! during a big upgrade, docker pulling layers, ceph-osd peering,
//! WolfStack itself polling 14 peers). Allowlist by comm name:
//! apt, dpkg, docker*, ceph-*, wolfstack, sshd, etc.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanDetectorConfig {
    /// Enable the detector. Default true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// How many distinct destinations within the window flag a process.
    #[serde(default = "default_threshold")]
    pub threshold_destinations: usize,
    /// Window in seconds for counting destinations.
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    /// Sample interval. Smaller = faster detection, more CPU.
    #[serde(default = "default_sample")]
    pub sample_interval_seconds: u64,
    /// Comm names that bypass detection. Pre-populated with known
    /// legitimate fan-out processes.
    #[serde(default = "default_allowlist")]
    pub allowlist_comms: Vec<String>,
    /// Numeric UIDs that bypass detection entirely. Use this for
    /// dedicated service accounts running legitimate high-fanout
    /// software (data-analysis pipelines, multi-API integrations).
    /// Safer than comm-name allowlisting when the process runs under
    /// a generic interpreter like `python` or `node` — operator can
    /// allowlist just the analytics user without exempting EVERY
    /// python process on the box.
    ///
    /// Find a user's UID: `id -u <username>` or
    /// `getent passwd <username> | cut -d: -f3`.
    #[serde(default)]
    pub allowlist_uids: Vec<u32>,
    /// What to do on detection. "alert_only" | "kill_and_block" (default).
    #[serde(default = "default_action")]
    pub action: String,
    /// Also detect raw / AF_PACKET socket holders (zmap, masscan,
    /// `nmap -sS`) that path #1's SYN_SENT sampling is structurally blind
    /// to. Default on — it is the whole reason the `mouse` zmap run went
    /// undetected. Legit raw-socket users are covered by the allowlist +
    /// the persistence gate below.
    #[serde(default = "default_detect_raw")]
    pub detect_raw_sockets: bool,
    /// A non-allowlisted process must hold a raw/packet socket for this
    /// many CONSECUTIVE samples before it is actioned. Guards against
    /// killing a brief legitimate raw-socket user (a one-off `ping`, a
    /// short `tcpdump`). Default 2 = the socket must persist across two
    /// samples (~one sample interval of dwell).
    #[serde(default = "default_raw_min_samples")]
    pub raw_socket_min_samples: usize,
}

// v23.12.3: default OFF. v23.10.0–v23.12.2 shipped this enabled-by-
// default with action=kill_and_block, which on Proxmox hosts could
// SIGKILL pmxcfs (cluster-fs replication burst during a backup run),
// taking /etc/pve / pveproxy / pvedaemon down with it. Reddit report
// 2026-05-17 — exact "comes online for a few then stops working"
// pattern.
//
// Operators who want outbound-scan detection back can flip it on in
// Fleet Security → Scan Detector. The ESSENTIAL_SAFETY_COMMS list
// (defined below) still protects the OS / cluster / DB / virt critical
// services even if the operator enables it AND mis-allowlists.
// Existing installs whose config file already says `enabled: true`
// keep their setting — this default only applies to fresh installs.
fn default_enabled() -> bool { false }
fn default_threshold() -> usize { 50 }
fn default_window() -> u64 { 60 }
fn default_sample() -> u64 { 15 }
fn default_action() -> String { "kill_and_block".into() }
fn default_detect_raw() -> bool { true }
fn default_raw_min_samples() -> usize { 2 }
fn default_allowlist() -> Vec<String> {
    let mut v: Vec<String> = vec![
        "apt".into(), "apt-get".into(), "dpkg".into(), "unattended-upgr".into(),
        "dockerd".into(), "containerd".into(), "docker".into(),
        "ceph-osd".into(), "ceph-mon".into(), "ceph-mgr".into(), "ceph-mds".into(),
        "wolfstack".into(), "wolfagent".into(), "wolfram".into(), "wolfusb".into(),
        "sshd".into(), "sshd-session".into(),
        "pveproxy".into(), "pvedaemon".into(), "pvestatd".into(), "pveupload".into(),
        "rsyncd".into(), "rsync".into(),
        "chronyd".into(), "systemd-resolve".into(), "systemd-network".into(),
        "tailscaled".into(), "tailscale".into(), "wg-quick".into(),
        "node_exporter".into(), "prometheus".into(),
        // Legit AF_PACKET / SOCK_RAW holders — these hold raw sockets by
        // design and must not trip the raw-socket path (#2). Diagnostics
        // (tcpdump/ping/mtr) are usually brief and would clear the
        // persistence gate anyway, but allowlisting them removes any doubt.
        "tcpdump".into(), "tshark".into(), "dumpcap".into(), "wireshark".into(),
        "ping".into(), "ping6".into(), "fping".into(), "arping".into(),
        "mtr".into(), "mtr-packet".into(), "traceroute".into(),
        "avahi-daemon".into(),
    ];
    // Also surface the essential-safety set in the editable allowlist
    // so operators see (and can audit) what's protected. The
    // ESSENTIAL_SAFETY_COMMS list below remains the hard guarantee —
    // even if the operator removes one of these entries from the UI
    // allowlist, `tick()` still skips it. (v23.12.3.)
    for comm in ESSENTIAL_SAFETY_COMMS {
        v.push((*comm).into());
    }
    v
}

/// Hard-coded "do not kill under any circumstances" list. Checked
/// BEFORE the operator-configurable `allowlist_comms`, so removing
/// these from the UI allowlist still doesn't expose them.
///
/// Added in v23.12.3 after a Proxmox host on Reddit was bricked: the
/// detector hit pmxcfs (cluster-fs replication burst during a backup
/// cycle), SIGKILL'd it, /etc/pve FUSE mount dropped, pveproxy /
/// pvedaemon / qm / pct all failed, host appeared dead on every
/// reboot.
///
/// Membership criterion: "killing this process takes the host down,
/// makes it unreachable, or causes data loss". Inconvenience alone
/// (nginx, mariadb, etc.) doesn't qualify — those belong in the
/// editable `default_allowlist` so operators can prune them.
///
/// When deciding whether to add something here, ask:
///   - Does killing it lose data mid-write?  (DBs, backup writers, mail queues)
///   - Does killing it break cluster quorum or membership?  (corosync, etcd, consul)
///   - Does killing it take down a FUSE/kernel mount?  (pmxcfs, lxcfs, fuse-*)
///   - Does killing it brick the OS networking stack?  (NetworkManager, systemd-networkd)
///   - Does killing it kill running guests (data loss for VM tenants)?  (libvirtd, qemu-kvm)
///     If yes to any, it goes here.
pub const ESSENTIAL_SAFETY_COMMS: &[&str] = &[
    // ── Proxmox VE cluster filesystem + services ─────────────────
    // pmxcfs → /etc/pve. corosync → quorum. HA stack → fence-on-kill.
    "pmxcfs", "corosync", "pve-firewall", "pve-ha-crm", "pve-ha-lrm",
    "pve-cluster", "spiceproxy", "pvescheduler", "pvefw-logger",
    // Proxmox Backup Server / client + vzdump — backup runs are the
    // single most common false-positive trigger (many storage targets).
    "proxmox-backup", "proxmox-backup-proxy", "proxmox-backup-client",
    "vzdump",

    // ── Container runtimes (data loss on kill) ───────────────────
    "lxc-start", "lxc-monitord", "lxc-attach", "lxcfs",
    "runc", "crun", "containerd-shim", "containerd-shim-runc-v2",
    "kata-runtime", "kata-agent",

    // ── Virtualization (kill = guest data loss) ──────────────────
    "qemu-kvm", "qemu-system-x86_64", "qemu-system-aarch64",
    "libvirtd", "virtqemud", "virtlogd", "virtlockd",

    // ── Cluster coordination (kill = split brain / fence) ────────
    "etcd", "consul", "pacemaker", "pacemakerd", "pacemaker-attrd",
    "pacemaker-execd", "pacemaker-fenced", "pacemaker-schedulerd",
    "crm_mon", "crmd",
    // Kubernetes control plane + node agents
    "kube-apiserver", "kube-controller", "kube-scheduler",
    "kubelet", "kube-proxy", "k3s", "k3s-agent", "k3s-server",

    // ── Distributed storage (kill mid-IO = corruption risk) ──────
    "glusterd", "glusterfsd", "ganesha.nfsd",
    "ceph-osd", "ceph-mon", "ceph-mgr", "ceph-mds", "ceph-fuse",
    "moosefs-master", "mfsmaster",

    // ── Local storage daemons ────────────────────────────────────
    "zed", "zfs", "zpool",
    "mdadm", "multipathd",
    "iscsid", "iscsiadm",
    // NFS server stack — killing nfsd while clients are mounted
    // hangs every client.
    "nfsd", "rpc.mountd", "rpc.statd", "rpcbind",
    // SMB server stack
    "smbd", "nmbd", "winbindd",

    // ── Databases (kill mid-write = corruption / journal recovery) ─
    "mariadbd", "mysqld", "mysqld_safe",
    "postgres", "postmaster",
    "mongod", "mongos",
    "redis-server", "redis-sentinel",
    "cassandra", "scylla",
    "influxd", "clickhouse-server",
    // Galera cluster sync needs all peers alive
    "garbd", "wsrep_sst_rsync", "wsrep_sst_xtrabackup",

    // ── Mail (kill queue runner = message loss) ──────────────────
    "postfix", "smtpd", "qmgr", "pickup", "exim4", "sendmail",
    "dovecot", "opensmtpd",

    // ── Routing daemons (kill = traffic blackhole) ───────────────
    "frr", "bgpd", "ospfd", "ospf6d", "zebra", "ripd", "isisd",
    "bird", "bird6",
    // VPN tunnels
    "openvpn", "strongswan", "charon", "pluto", "wg-quick",
    // VRRP / HA — holds a raw socket for VRRP advertisements; killing it
    // triggers a VIP failover (or split-brain) across the cluster.
    "keepalived", "vrrpd",

    // ── Core OS daemons (kill = host unreachable / unbootable) ───
    "systemd",   // PID 1 is already protected, but defence in depth
    "init",
    "NetworkManager", "nm-applet",
    "systemd-networkd", "systemd-resolved", "systemd-udevd",
    "systemd-logind", "systemd-journald",
    "dbus-daemon", "dbus-broker",
    "polkitd", "accountsservice",
    "rsyslogd", "syslog-ng",
    "udevadm",

    // ── DNS / DHCP (kill = network goes dark) ────────────────────
    // DHCP clients hold an AF_PACKET socket for the lease handshake —
    // essential-safety (not just allowlist) so the raw-socket path can
    // never kill one and strand the host at lease-renewal time.
    "dnsmasq", "named", "unbound", "bind9", "kresd", "knot",
    "dhclient", "dhcpcd", "dhcpd", "dhcrelay",

    // ── Time sync (kill = clock drift breaks auth, TLS, kerberos) ─
    "chronyd", "ntpd",
];

/// True if `comm` (as read from `/proc/<pid>/comm`, which the kernel
/// truncates to 15 bytes / TASK_COMM_LEN-1) names a process on the
/// essential-safety list — one that must NEVER be killed by an automated
/// heuristic. Handles the 15-byte truncation so long names like
/// `qemu-system-x86_64` / `systemd-networkd` are matched by the truncated
/// form the kernel actually reports. Shared single source of truth for the
/// scan detector and the antivirus auto-kill path.
pub fn is_essential_safety_comm(comm: &str) -> bool {
    ESSENTIAL_SAFETY_COMMS
        .iter()
        .any(|&s| s == comm || s.get(..15) == Some(comm))
}

impl Default for ScanDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            threshold_destinations: default_threshold(),
            window_seconds: default_window(),
            sample_interval_seconds: default_sample(),
            allowlist_comms: default_allowlist(),
            allowlist_uids: Vec::new(),
            action: default_action(),
            detect_raw_sockets: default_detect_raw(),
            raw_socket_min_samples: default_raw_min_samples(),
        }
    }
}

impl ScanDetectorConfig {
    fn config_path() -> String {
        format!("{}/scan-detector.json", crate::paths::get().config_dir)
    }
    pub fn load() -> Self {
        std::fs::read_to_string(Self::config_path()).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("save scan detector config: {}", e))
    }
}

/// One detection event, kept in a bounded ring for the UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectionEvent {
    pub timestamp: u64,
    pub pid: i32,
    pub comm: String,
    pub uid: u32,
    pub distinct_destinations: usize,
    pub window_seconds: u64,
    pub sample_destinations: Vec<String>,
    pub action_taken: String,
    /// Which detection path fired: "syn_sent" (path #1, connect()-based
    /// scanners) or "raw_packet_socket" (path #2, zmap/masscan/nmap -sS).
    /// The event ring is serialise-only (out to the UI), never read back,
    /// so no serde default is needed.
    pub reason: String,
}

const EVENTS_MAX: usize = 200;

#[derive(Default)]
struct Inner {
    /// Per-PID: rolling list of (timestamp, dest_ip).
    samples: HashMap<i32, Vec<(Instant, String)>>,
    /// PIDs we've already actioned (don't repeat-action).
    actioned: HashMap<i32, Instant>,
    /// Path #2: per-PID count of CONSECUTIVE samples the process has held
    /// a raw/packet socket. Reset to 0 the moment it no longer holds one,
    /// so a brief holder never accumulates toward the threshold.
    raw_holders: HashMap<i32, usize>,
    events: std::collections::VecDeque<DetectionEvent>,
}

/// (title, body) callback fired when a scanner is detected. main.rs
/// wires this to alerting::send_node_alert so the operator gets a
/// Discord / Slack / Telegram / email with the cluster + hostname
/// included.
pub type ScanAlertHook = Arc<dyn Fn(String, String) + Send + Sync>;

pub struct ScanDetector {
    inner: Mutex<Inner>,
    config: std::sync::RwLock<ScanDetectorConfig>,
    alert_hook: std::sync::RwLock<Option<ScanAlertHook>>,
}

impl ScanDetector {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            config: std::sync::RwLock::new(ScanDetectorConfig::load()),
            alert_hook: std::sync::RwLock::new(None),
        }
    }

    pub fn install_alert_hook(&self, hook: ScanAlertHook) {
        *self.alert_hook.write().unwrap() = Some(hook);
    }

    pub fn config(&self) -> ScanDetectorConfig {
        self.config.read().unwrap().clone()
    }

    pub fn set_config(&self, new: ScanDetectorConfig) -> Result<ScanDetectorConfig, String> {
        new.save()?;
        *self.config.write().unwrap() = new.clone();
        Ok(new)
    }

    pub fn events(&self) -> Vec<DetectionEvent> {
        let inner = self.inner.lock().unwrap();
        inner.events.iter().rev().cloned().collect()
    }

    /// Start the periodic sampler thread. Idempotent — calling twice
    /// just spawns two samplers (which is harmless but wasteful), so
    /// the caller (main.rs) calls once at startup.
    pub fn start(self: Arc<Self>) {
        std::thread::Builder::new()
            .name("wolfstack-scandetect".into())
            .spawn(move || self.run_loop())
            .ok();
    }

    fn run_loop(self: Arc<Self>) {
        loop {
            let cfg = self.config.read().unwrap().clone();
            if cfg.enabled {
                self.tick(&cfg);
            }
            std::thread::sleep(Duration::from_secs(cfg.sample_interval_seconds));
        }
    }

    fn tick(&self, cfg: &ScanDetectorConfig) {
        // Build inode→PID map ONCE per tick (it's the expensive part).
        let inode_to_pid = build_inode_pid_map();
        // Sample SYN_SENT sockets across v4 + v6.
        let mut samples: Vec<(i32, String)> = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            samples.extend(parse_syn_sent(path, &inode_to_pid));
        }
        // Insert into rolling window.
        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_seconds);
        let mut inner = self.inner.lock().unwrap();
        for (pid, dest) in samples {
            let entry = inner.samples.entry(pid).or_default();
            entry.push((now, dest));
        }
        // Prune old samples + check thresholds. Snapshot `actioned`
        // ahead of the iter_mut so we don't hold conflicting borrows
        // on `inner` simultaneously.
        let allowlist: HashSet<&str> = cfg.allowlist_comms.iter().map(|s| s.as_str()).collect();
        // /proc/<pid>/comm is truncated by the kernel to 15 bytes
        // (TASK_COMM_LEN-1), so a daemon whose real name is longer —
        // qemu-system-x86_64, systemd-networkd, proxmox-backup-proxy,
        // containerd-shim-runc-v2, pacemaker-schedulerd — appears as just
        // its 15-char prefix. Register BOTH the full name and its 15-byte
        // truncation so the exact-match guard below still protects it.
        // Without this the guard silently skipped every critical daemon
        // with a >15-char name (it could never match the truncated comm).
        let essential: HashSet<&str> = ESSENTIAL_SAFETY_COMMS
            .iter()
            .flat_map(|&s| match s.get(..15) {
                Some(trunc) if trunc.len() < s.len() => vec![s, trunc],
                _ => vec![s],
            })
            .collect();
        let recently_actioned: HashMap<i32, Instant> = inner.actioned.clone();
        let mut to_action: Vec<(i32, String, u32, HashSet<String>)> = Vec::new();
        for (pid, entries) in inner.samples.iter_mut() {
            entries.retain(|(t, _)| now.duration_since(*t) < window);
            let distinct: HashSet<String> = entries.iter().map(|(_, d)| d.clone()).collect();
            if distinct.len() < cfg.threshold_destinations { continue; }
            // Already actioned recently? Skip.
            if recently_actioned.get(pid)
                .is_some_and(|when| now.duration_since(*when) < Duration::from_secs(300))
            {
                continue;
            }
            let comm = read_comm(*pid).unwrap_or_else(|| "?".into());
            // Essential-safety list checked BEFORE the operator allowlist.
            // Even if an operator removes pmxcfs from their visible
            // allowlist, we never kill it. Logged at debug rather than
            // ignored silently so an operator hunting through journals
            // can see what fired.
            if essential.contains(comm.as_str()) {
                tracing::debug!(
                    "scan-detect: PID {} ({}) crossed threshold but is on the essential-safety list — skipping",
                    pid, comm
                );
                continue;
            }
            if allowlist.contains(comm.as_str()) { continue; }
            let uid = read_uid(*pid).unwrap_or(0);
            // UID allowlist — dedicated service accounts for legit
            // high-fanout software bypass detection entirely.
            if cfg.allowlist_uids.contains(&uid) { continue; }
            to_action.push((*pid, comm, uid, distinct.clone()));
        }
        for (pid, comm, uid, dests) in to_action {
            let sample_dests: Vec<String> = dests.iter().take(20).cloned().collect();
            let detail = format!(
                "{} distinct outbound destinations in {}s",
                dests.len(), cfg.window_seconds
            );
            self.emit_detection(
                &mut inner, now, cfg, pid, &comm, uid,
                "syn_sent", &detail, dests.len(), sample_dests,
            );
        }

        // ── Path #2: raw / AF_PACKET socket holders (zmap/masscan/nmap -sS) ──
        // These never appear in the SYN_SENT table above. A non-allowlisted
        // process holding such a socket across `raw_socket_min_samples`
        // consecutive samples is actioned. The consecutive-count lives in
        // `inner.raw_holders` and is reset the moment the socket goes away.
        if cfg.detect_raw_sockets {
            let raw_pids = sample_raw_socket_pids(&inode_to_pid);
            // Bump counts for current holders; anyone not currently holding
            // a raw socket drops out (map rebuilt from current holders only).
            inner.raw_holders = update_raw_holder_counts(&inner.raw_holders, &raw_pids);
            let min_samples = cfg.raw_socket_min_samples.max(1);
            let raw_to_action: Vec<(i32, usize)> = inner.raw_holders.iter()
                .filter(|(_, c)| **c >= min_samples)
                .map(|(p, c)| (*p, *c))
                .collect();
            for (pid, count) in raw_to_action {
                // Skip if actioned recently — checked against the LIVE
                // `actioned` map, not the pre-tick snapshot, so a PID that
                // path #1 already killed/alerted THIS tick isn't actioned a
                // second time here (which would double-kill, insert a
                // duplicate iptables rule, and log a duplicate event).
                if inner.actioned.get(&pid)
                    .is_some_and(|when| now.duration_since(*when) < Duration::from_secs(300))
                {
                    continue;
                }
                let comm = read_comm(pid).unwrap_or_else(|| "?".into());
                if essential.contains(comm.as_str()) {
                    tracing::debug!(
                        "scan-detect: PID {} ({}) holds a raw socket but is on the essential-safety list — skipping",
                        pid, comm
                    );
                    continue;
                }
                if allowlist.contains(comm.as_str()) { continue; }
                let uid = read_uid(pid).unwrap_or(0);
                if cfg.allowlist_uids.contains(&uid) { continue; }
                let detail = format!(
                    "held an AF_PACKET/SOCK_RAW socket for {} consecutive samples \
                     (raw-packet scanner class — zmap / masscan / nmap -sS)",
                    count
                );
                self.emit_detection(
                    &mut inner, now, cfg, pid, &comm, uid,
                    "raw_packet_socket", &detail, 0, Vec::new(),
                );
            }
        } else {
            // Raw path disabled — drop any stale per-PID counters so a
            // re-enable starts from a clean slate.
            inner.raw_holders.clear();
        }

        // Garbage-collect actioned entries older than 1h.
        inner.actioned.retain(|_, t| now.duration_since(*t) < Duration::from_secs(3600));
        inner.samples.retain(|_, entries| !entries.is_empty());
    }

    /// Record a detection: take the configured action, append a bounded
    /// event, log, and fire the operator alert. Shared by both detection
    /// paths so the SYN_SENT and raw-socket branches stay consistent.
    /// `detail` is a human phrase describing why it fired; `reason` is the
    /// machine tag ("syn_sent" | "raw_packet_socket").
    #[allow(clippy::too_many_arguments)]
    fn emit_detection(
        &self, inner: &mut Inner, now: Instant, cfg: &ScanDetectorConfig,
        pid: i32, comm: &str, uid: u32, reason: &str, detail: &str,
        distinct_destinations: usize, sample_destinations: Vec<String>,
    ) {
        let action_taken = self.take_action(pid, comm, uid, cfg);
        let event = DetectionEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            pid,
            comm: comm.to_string(),
            uid,
            distinct_destinations,
            window_seconds: cfg.window_seconds,
            sample_destinations: sample_destinations.into_iter().take(20).collect(),
            action_taken: action_taken.clone(),
            reason: reason.to_string(),
        };
        inner.actioned.insert(pid, now);
        if inner.events.len() >= EVENTS_MAX { inner.events.pop_front(); }
        let sample_preview = event.sample_destinations.iter()
            .take(15).cloned().collect::<Vec<_>>().join(", ");
        inner.events.push_back(event);
        tracing::error!(
            "scan-detect [{}]: PID {} ({}, uid {}) — {} — action: {}",
            reason, pid, comm, uid, detail, action_taken
        );
        // Operator alert out-of-band. Cluster + hostname stamped by the hook.
        let hook = self.alert_hook.read().unwrap().clone();
        if let Some(h) = hook {
            let title = format!("🚨 Outbound scan detected ({}): PID {} ({})", reason, pid, comm);
            let dests_line = if sample_preview.is_empty() {
                "Sample destinations: (none — raw-socket senders bypass per-connection tracking)".to_string()
            } else {
                format!("Sample destinations: {}", sample_preview)
            };
            let body = format!(
                "A process on this host tripped the outbound-scan detector.\n\n\
                 PID:       {}\n\
                 comm:      {}\n\
                 UID:       {}\n\
                 Detection: {}\n\
                 Detail:    {}\n\
                 Action taken: {}\n\n\
                 {}\n\n\
                 If this process is legitimate, add its comm name to the \
                 scan-detector allowlist on the Fleet Security page.",
                pid, comm, uid, reason, detail, action_taken, dests_line,
            );
            h(title, body);
        }
    }

    /// Apply the configured action. Returns a human-readable description.
    fn take_action(&self, pid: i32, comm: &str, uid: u32, cfg: &ScanDetectorConfig) -> String {
        // Hard safety guard: NEVER kill PID 1 (init) or our own
        // process, no matter what the operator did to the allowlist.
        // Killing PID 1 = reboot loop. Killing ourselves = silent
        // brick of WolfStack. Both are unrecoverable without console.
        let our_pid = std::process::id() as i32;
        if pid == 1 || pid == our_pid {
            tracing::error!(
                "scan-detect: REFUSING to kill PID {} ({}) — protected (init or WolfStack itself)",
                pid, comm
            );
            return format!("REFUSED to kill PID {} (protected — init or WolfStack)", pid);
        }
        match cfg.action.as_str() {
            "alert_only" => {
                "alert only (no kill / no block)".into()
            }
            _ => {
                // SIGTERM, then SIGKILL after 2s if still alive.
                let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).output();
                std::thread::sleep(Duration::from_secs(2));
                let _ = Command::new("kill").args(["-KILL", &pid.to_string()]).output();
                // Block all further outbound from that UID. This catches
                // re-spawns from cron or systemd that would otherwise
                // immediately resume scanning.
                if uid != 0 {
                    // Don't iptables-block UID 0 — would break too much.
                    let _ = Command::new("iptables").args([
                        "-I", "OUTPUT", "1",
                        "-m", "owner", "--uid-owner", &uid.to_string(),
                        "-p", "tcp", "--syn",
                        "-j", "REJECT",
                    ]).output();
                    format!("killed PID {} ({}); blocked outbound TCP SYN for UID {}", pid, comm, uid)
                } else {
                    format!("killed PID {} ({}); UID 0 not auto-blocked (would break too much) — investigate manually", pid, comm)
                }
            }
        }
    }
}

/// Walk /proc to build inode→pid map. Used to translate /proc/net/tcp
/// inode column back to a PID. Reasonably fast on a typical host
/// (under 100ms for ~2000 processes).
fn build_inode_pid_map() -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    let proc = match std::fs::read_dir("/proc") { Ok(r) => r, Err(_) => return map };
    for entry in proc.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: i32 = match name_str.parse() { Ok(p) => p, Err(_) => continue };
        let fd_dir = format!("/proc/{}/fd", pid);
        let fds = match std::fs::read_dir(&fd_dir) { Ok(r) => r, Err(_) => continue };
        for fd in fds.flatten() {
            let target = match std::fs::read_link(fd.path()) { Ok(t) => t, Err(_) => continue };
            let s = target.to_string_lossy();
            if let Some(rest) = s.strip_prefix("socket:[")
                && let Some(end) = rest.find(']')
                    && let Ok(inode) = rest[..end].parse::<u64>() {
                        map.insert(inode, pid);
                    }
        }
    }
    map
}

/// Enumerate PIDs holding an `AF_PACKET` or `SOCK_RAW` socket, via
/// `/proc/net/packet`, `/proc/net/raw` and `/proc/net/raw6`, joined
/// through the inode→pid map. These are the socket types zmap / masscan /
/// `nmap -sS` use to send hand-crafted probes outside the kernel TCP
/// stack — which is exactly why they never show up in the SYN_SENT table
/// that `parse_syn_sent` reads.
/// Advance the raw-socket persistence counters by one sample. Each PID
/// currently holding a raw/packet socket has its consecutive-sample count
/// incremented; a PID that dropped its socket is absent from `current` and
/// therefore vanishes from the returned map — i.e. its count resets to 0.
/// Pure (no I/O) so the gate transition logic is unit-testable without
/// touching /proc. Returned map is rebuilt from `current` only, so it is
/// bounded by the number of live raw-socket holders.
fn update_raw_holder_counts(
    prev: &HashMap<i32, usize>,
    current: &HashSet<i32>,
) -> HashMap<i32, usize> {
    let mut next = HashMap::with_capacity(current.len());
    for pid in current {
        next.insert(*pid, prev.get(pid).copied().unwrap_or(0) + 1);
    }
    next
}

fn sample_raw_socket_pids(inode_to_pid: &HashMap<u64, i32>) -> HashSet<i32> {
    let mut pids = HashSet::new();
    // /proc/net/packet — AF_PACKET sockets. Columns:
    //   sk RefCnt Type Proto Iface R Rmem User Inode
    // Inode is the LAST whitespace-separated column.
    if let Ok(content) = std::fs::read_to_string("/proc/net/packet") {
        for (i, line) in content.lines().enumerate() {
            if i == 0 { continue; } // header
            if let Some(inode_str) = line.split_whitespace().last()
                && let Ok(inode) = inode_str.parse::<u64>()
                    && let Some(&pid) = inode_to_pid.get(&inode) { pids.insert(pid); }
        }
    }
    // /proc/net/raw[6] — SOCK_RAW IP sockets. Same column layout as
    // /proc/net/tcp: inode is column index 9.
    for path in ["/proc/net/raw", "/proc/net/raw6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for (i, line) in content.lines().enumerate() {
                if i == 0 { continue; }
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 10 { continue; }
                if let Ok(inode) = cols[9].parse::<u64>()
                    && let Some(&pid) = inode_to_pid.get(&inode) { pids.insert(pid); }
            }
        }
    }
    pids
}

/// Parse /proc/net/tcp[6] for SYN_SENT (state=02) sockets. Returns
/// (pid, remote_ip) pairs, joined via the inode→pid map.
fn parse_syn_sent(path: &str, inode_to_pid: &HashMap<u64, i32>) -> Vec<(i32, String)> {
    let content = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return Vec::new() };
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if i == 0 { continue; } // header
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 { continue; }
        // cols[3] = "ST" (state, hex). 02 = SYN_SENT.
        if cols[3] != "02" { continue; }
        // cols[2] = remote address "HEX:PORT"
        let rem = cols[2];
        let ip = match rem.rsplit_once(':') {
            Some((hex_ip, _)) => hex_to_ip(hex_ip),
            None => continue,
        };
        // cols[9] = inode
        let inode: u64 = match cols[9].parse() { Ok(i) => i, Err(_) => continue };
        if let Some(&pid) = inode_to_pid.get(&inode) {
            out.push((pid, ip));
        }
    }
    out
}

/// Convert /proc/net/tcp's hex-encoded IP to a printable string.
/// Format is little-endian per-byte: e.g. "0100007F" → "127.0.0.1",
/// or for v6 a 32-char string of 4 little-endian dwords.
fn hex_to_ip(hex: &str) -> String {
    if hex.len() == 8 {
        // v4
        let mut bytes = [0u8; 4];
        for i in 0..4 {
            bytes[3 - i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else if hex.len() == 32 {
        // v6 — 4 dwords, each little-endian
        let mut groups: Vec<String> = Vec::new();
        for dw in 0..4 {
            for word in 0..2 {
                let i = dw * 8 + (1 - word) * 4;
                let chunk = &hex[i..i + 4];
                // Each "word" needs byte-swap within the 16-bit chunk.
                let hi = u8::from_str_radix(&chunk[0..2], 16).unwrap_or(0);
                let lo = u8::from_str_radix(&chunk[2..4], 16).unwrap_or(0);
                let val = ((lo as u16) << 8) | (hi as u16);
                groups.push(format!("{:x}", val));
            }
        }
        groups.join(":")
    } else {
        hex.to_string()
    }
}

fn read_comm(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_ipv4_localhost() {
        // 127.0.0.1 little-endian = 0100007F
        assert_eq!(hex_to_ip("0100007F"), "127.0.0.1");
    }

    #[test]
    fn hex_to_ipv4_external() {
        // 8.8.8.8 little-endian = 08080808
        assert_eq!(hex_to_ip("08080808"), "8.8.8.8");
    }

    #[test]
    fn config_default_includes_known_safe_processes() {
        let cfg = ScanDetectorConfig::default();
        assert!(cfg.allowlist_comms.contains(&"apt".to_string()));
        assert!(cfg.allowlist_comms.contains(&"docker".to_string()));
        assert!(cfg.allowlist_comms.contains(&"wolfstack".to_string()));
        assert!(cfg.allowlist_comms.contains(&"ceph-osd".to_string()));
        assert!(cfg.threshold_destinations >= 10, "default threshold should be permissive enough not to false-positive");
    }

    /// v23.12.3 flipped the default to OFF after a Reddit user lost a
    /// Proxmox host. Pin this so a future refactor can't silently
    /// re-enable detection-by-default.
    #[test]
    fn config_default_is_disabled() {
        let cfg = ScanDetectorConfig::default();
        assert!(!cfg.enabled, "detector must default to disabled — re-enabling by default is what bricked the Reddit reporter's PVE host");
    }

    /// The essential-safety list is the hard guarantee — if any of
    /// these get dropped from the const, hosts running Proxmox /
    /// libvirt / mariadb / NetworkManager / etc. can lose them to
    /// SIGKILL even if the operator hasn't customised their allowlist.
    /// Pin the critical entries explicitly so the next refactor surfaces
    /// the intent.
    #[test]
    fn essential_safety_protects_the_critical_set() {
        let essential: HashSet<&str> = ESSENTIAL_SAFETY_COMMS.iter().copied().collect();
        // Proxmox VE cluster fs / quorum / HA — the bug that motivated v23.12.3
        for must in &["pmxcfs", "corosync", "pve-cluster", "pve-ha-crm", "pve-ha-lrm",
                      "vzdump", "proxmox-backup-client", "lxcfs", "lxc-start"] {
            assert!(essential.contains(must), "essential-safety list must contain {must}");
        }
        // Virtualization / container runtimes — kill = guest data loss
        for must in &["qemu-kvm", "libvirtd", "runc", "containerd-shim"] {
            assert!(essential.contains(must), "essential-safety list must contain {must}");
        }
        // Cluster coordination — kill = split brain
        for must in &["etcd", "consul", "pacemaker", "kubelet"] {
            assert!(essential.contains(must), "essential-safety list must contain {must}");
        }
        // Databases — kill mid-write = corruption
        for must in &["mariadbd", "mysqld", "postgres", "mongod", "redis-server"] {
            assert!(essential.contains(must), "essential-safety list must contain {must}");
        }
        // Core OS / networking — kill = host unreachable
        for must in &["systemd", "NetworkManager", "systemd-networkd",
                      "dnsmasq", "named", "chronyd"] {
            assert!(essential.contains(must), "essential-safety list must contain {must}");
        }
    }

    /// /proc/<pid>/comm is truncated to 15 bytes, so the runtime guard
    /// must also protect the truncated form of long critical names —
    /// otherwise it silently skipped qemu-system-x86_64, systemd-networkd,
    /// proxmox-backup-proxy, containerd-shim-runc-v2, pacemaker-schedulerd
    /// (their full names can never equal the 15-char comm the kernel reports).
    #[test]
    fn essential_safety_handles_comm_truncation() {
        // Mirror the truncation-aware construction used in ScanDetector::tick().
        let essential: HashSet<&str> = ESSENTIAL_SAFETY_COMMS
            .iter()
            .flat_map(|&s| match s.get(..15) {
                Some(trunc) if trunc.len() < s.len() => vec![s, trunc],
                _ => vec![s],
            })
            .collect();
        // The exact 15-byte comm values the kernel reports for these
        // long-named critical daemons — each MUST be protected.
        for must in &[
            "qemu-system-x86", // qemu-system-x86_64
            "systemd-network", // systemd-networkd
            "systemd-resolve", // systemd-resolved
            "pacemaker-sched", // pacemaker-schedulerd
            "proxmox-backup-", // proxmox-backup-proxy / -client
        ] {
            assert!(
                essential.contains(must),
                "truncated comm {must:?} must be protected (kernel truncates comm to 15 bytes)"
            );
        }
    }

    #[test]
    fn take_action_refuses_to_kill_pid_1() {
        let det = ScanDetector::new();
        let cfg = ScanDetectorConfig {
            action: "kill_and_block".into(),
            ..Default::default()
        };
        let result = det.take_action(1, "systemd", 0, &cfg);
        assert!(result.contains("REFUSED"), "must refuse PID 1, got: {}", result);
    }

    #[test]
    fn take_action_refuses_to_kill_self() {
        let det = ScanDetector::new();
        let cfg = ScanDetectorConfig {
            action: "kill_and_block".into(),
            ..Default::default()
        };
        let our_pid = std::process::id() as i32;
        let result = det.take_action(our_pid, "wolfstack", 0, &cfg);
        assert!(result.contains("REFUSED"), "must refuse own PID, got: {}", result);
    }

    #[test]
    fn config_round_trip() {
        let cfg = ScanDetectorConfig {
            threshold_destinations: 75,
            action: "alert_only".into(),
            allowlist_uids: vec![1000, 1001],
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ScanDetectorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.threshold_destinations, 75);
        assert_eq!(back.action, "alert_only");
        assert_eq!(back.allowlist_uids, vec![1000, 1001]);
    }

    #[test]
    fn uid_allowlist_default_is_empty() {
        let cfg = ScanDetectorConfig::default();
        assert!(cfg.allowlist_uids.is_empty(),
            "default config must NOT auto-allowlist any UIDs — operator opts in explicitly");
    }

    #[test]
    fn deserialise_without_allowlist_uids_field_defaults_to_empty() {
        // Backwards-compat: existing config files written by v23.10.0
        // (no allowlist_uids field) must still load without error.
        let old_json = r#"{
            "enabled": true,
            "threshold_destinations": 50,
            "window_seconds": 60,
            "sample_interval_seconds": 15,
            "allowlist_comms": ["apt"],
            "action": "kill_and_block"
        }"#;
        let cfg: ScanDetectorConfig = serde_json::from_str(old_json).unwrap();
        assert!(cfg.allowlist_uids.is_empty(),
            "missing allowlist_uids field must default to empty Vec");
        assert_eq!(cfg.threshold_destinations, 50);
        // Configs predating the raw-socket path must still enable it by
        // default on load — otherwise an upgrade silently leaves the
        // zmap/masscan blind spot open on every existing install.
        assert!(cfg.detect_raw_sockets,
            "missing detect_raw_sockets must default to true (closes the raw-scanner blind spot on upgrade)");
        assert_eq!(cfg.raw_socket_min_samples, 2,
            "missing raw_socket_min_samples must default to 2");
    }

    #[test]
    fn raw_socket_detection_defaults_on() {
        let cfg = ScanDetectorConfig::default();
        assert!(cfg.detect_raw_sockets, "raw-socket detection must be on by default");
        assert!(cfg.raw_socket_min_samples >= 1, "min samples must be at least 1");
    }

    /// The raw-socket path must honour the same essential-safety guarantee
    /// as the SYN_SENT path — keepalived (VRRP) holds a raw socket by
    /// design and killing it fails a cluster VIP over.
    #[test]
    fn essential_safety_covers_raw_socket_holders() {
        let essential: HashSet<&str> = ESSENTIAL_SAFETY_COMMS.iter().copied().collect();
        assert!(essential.contains("keepalived"),
            "keepalived holds a raw VRRP socket — must be essential-safety protected");
        // DHCP clients (AF_PACKET for the lease handshake) — both dhclient
        // and dhcpcd must be essential-safety, not merely allowlisted.
        assert!(essential.contains("dhclient"),
            "dhclient holds an AF_PACKET socket — must be essential-safety protected");
        assert!(essential.contains("dhcpcd"),
            "dhcpcd holds an AF_PACKET socket — must be essential-safety protected");
    }

    #[test]
    fn raw_holder_counts_increment_and_reset() {
        let prev = HashMap::new();
        // Two holders appear → each at count 1.
        let s1: HashSet<i32> = [10, 20].into_iter().collect();
        let c1 = update_raw_holder_counts(&prev, &s1);
        assert_eq!(c1.get(&10), Some(&1));
        assert_eq!(c1.get(&20), Some(&1));
        // 10 persists (→2), 20 drops its socket (absent → reset).
        let s2: HashSet<i32> = [10].into_iter().collect();
        let c2 = update_raw_holder_counts(&c1, &s2);
        assert_eq!(c2.get(&10), Some(&2), "persistent holder must accumulate");
        assert!(!c2.contains_key(&20), "a holder that dropped its socket must reset (absent)");
        // 10 keeps holding → 3; a fresh PID 30 starts at 1.
        let s3: HashSet<i32> = [10, 30].into_iter().collect();
        let c3 = update_raw_holder_counts(&c2, &s3);
        assert_eq!(c3.get(&10), Some(&3));
        assert_eq!(c3.get(&30), Some(&1), "new holder starts at 1");
        // Everyone drops → empty map (bounded, no leak).
        let empty: HashSet<i32> = HashSet::new();
        assert!(update_raw_holder_counts(&c3, &empty).is_empty());
    }

    #[test]
    fn allowlist_covers_common_raw_socket_tools() {
        let cfg = ScanDetectorConfig::default();
        for tool in &["tcpdump", "ping", "mtr", "traceroute"] {
            assert!(cfg.allowlist_comms.contains(&tool.to_string()),
                "{tool} is a legitimate raw-socket user and must be allowlisted");
        }
    }

    #[test]
    fn sample_raw_socket_pids_reads_live_proc() {
        // Smoke test against the real /proc — must not panic and returns a
        // set (typically non-empty on a real host: dhclient / systemd-*).
        let inode_to_pid = build_inode_pid_map();
        let _pids = sample_raw_socket_pids(&inode_to_pid);
        // No assertion on contents (host-dependent) — the contract under
        // test is "parses live /proc without panicking".
    }

    #[test]
    fn detection_event_reason_serialises() {
        let ev = DetectionEvent {
            timestamp: 0, pid: 42, comm: "zmap".into(), uid: 0,
            distinct_destinations: 0, window_seconds: 60,
            sample_destinations: vec![], action_taken: "alert only".into(),
            reason: "raw_packet_socket".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("raw_packet_socket"), "reason must serialise into the event");
    }
}
