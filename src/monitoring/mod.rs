// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! System monitoring — collects CPU, RAM, disk, and network stats

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;
use sysinfo::{System, Disks, Networks, MINIMUM_CPU_UPDATE_INTERVAL};


/// Snapshot of system metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub hostname: String,
    pub uptime_secs: u64,
    pub cpu_usage_percent: f32,
    pub cpu_count: usize,
    pub cpu_model: String,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_percent: f32,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disks: Vec<DiskMetrics>,
    pub network: Vec<NetworkMetrics>,
    pub load_avg: LoadAverage,
    pub processes: usize,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    /// Hardware classification: "low", "mid", or "high"
    #[serde(default)]
    pub hardware_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub name: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

/// System monitor that maintains state between polls
pub struct SystemMonitor {
    sys: System,
    disks: Disks,
    networks: Networks,
    /// Counter for slow-path refreshes (processes, disks) — every Nth collect
    tick: u32,
    /// When the CPU counters were last sampled. sysinfo derives CPU% from the
    /// delta between two refreshes, so the gap between them IS the measurement
    /// window — see the guard in `collect()`.
    last_cpu_sample: Instant,
}

/// How often to do the expensive refresh (disk list).
/// At 2s polling interval, 15 ticks = every 30 seconds.
const SLOW_REFRESH_TICKS: u32 = 15;

/// How long a top-processes scan stays good for.
///
/// The dashboard polls every 15s per viewer; without this the cost scaled
/// with the number of open browser tabs. 30s keeps a top-10 table honest to
/// anyone reading it while capping the scan rate no matter how many clients
/// ask.
const TOP_PROC_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Last top-processes scan: when it was taken, top-by-CPU, top-by-memory.
/// Process-wide, so every viewer and every node-proxied request shares one
/// scan rather than each triggering their own.
type ProcessSnapshot = (Instant, Vec<ProcessInfo>, Vec<ProcessInfo>);

static TOP_PROC_CACHE: Mutex<Option<ProcessSnapshot>> =
    Mutex::new(None);

/// Number of running processes, counted straight from /proc.
///
/// A `read_dir` and a digit check per entry — no per-process `open()`, so it
/// costs nothing and, critically, leaves no descriptors behind. This replaces
/// asking sysinfo, which only knows the count as a side effect of caching an
/// open `/proc/<pid>/stat` handle for every process on the box.
///
/// Counts thread-group leaders (the numeric directories directly under /proc),
/// which is what an operator means by "processes" — the previous number
/// included every thread, so a node running a few hundred processes with heavy
/// threading reported tens of thousands.
fn count_processes() -> usize {
    match std::fs::read_dir("/proc") {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let bytes = name.as_encoded_bytes();
                !bytes.is_empty() && bytes.iter().all(|b| b.is_ascii_digit())
            })
            .count(),
        Err(_) => 0,
    }
}

impl SystemMonitor {
    pub fn new() -> Self {
        // Deliberately NOT `System::new_all()` / `refresh_all()`.
        //
        // Both mean `RefreshKind::everything()`, which includes a full process
        // refresh — the exact thing collect() no longer does. sysinfo keeps an
        // open `/proc/<pid>/stat` handle per process and grants itself HALF of
        // RLIMIT_NOFILE for the cache, so a single construction claimed ~32,768
        // descriptors on a busy host before a single metric was read. Removing
        // the refresh from collect() alone was not enough: regions1-host still
        // showed 33,178 fds twenty seconds after start (2026-08-05).
        //
        // Refresh only what SystemMetrics actually reads: CPU and memory.
        // Disks and networks are separate objects handled below, and the
        // process COUNT comes from `count_processes()` reading /proc directly.
        // `top_processes()` still refreshes processes on demand for
        // GET /api/metrics/processes — the one caller that wants the list.
        let mut sys = System::new();
        sys.refresh_cpu_all();
        sys.refresh_memory();
        // Disks deliberately NOT refreshed at construction: sysinfo's disk
        // refresh statvfs()'s every mount, and a dead/starting FUSE mount
        // (/etc/pve while pve-cluster is still coming up, a stale sshfs, …)
        // blocks statvfs UNINTERRUPTIBLY. Constructing the monitor on the
        // startup path then wedges the whole process before the dashboard
        // ever binds (masterpier's athena: 26h dark, 2026-07-03). Start
        // empty and pre-arm `tick` so the FIRST collect() runs the slow-path
        // list refresh — callers on the startup path wrap that collect in a
        // timeout guard, and the polling loop repeats it every ~30s.
        let disks = Disks::new();
        let networks = Networks::new_with_refreshed_list();

        Self {
            sys,
            disks,
            networks,
            tick: SLOW_REFRESH_TICKS,
            // refresh_all() above took the first CPU sample; collect() measures
            // against this instant.
            last_cpu_sample: Instant::now(),
        }
    }

    /// Collect current system metrics
    pub fn collect(&mut self) -> SystemMetrics {
        // sysinfo computes CPU% from the delta between two refreshes, so the
        // elapsed time between them IS the measurement window. Refresh again
        // too soon and the busy-time delta is divided by a near-zero window,
        // which pegs the result at ~100% no matter how idle the box is.
        //
        // The 2s polling loop is never anywhere near that limit, but every
        // one-shot `SystemMonitor::new()` + `collect()` caller landed squarely
        // inside it — the startup collection in main.rs, the MCP metrics tool
        // and the WolfAgents node query. The startup one is the damaging case:
        // its bogus reading is what the node publishes via `cluster.update_self`,
        // so a freshly started or freshly restarted node advertised itself to
        // the whole fleet at ~100% CPU while sitting idle (RutgerDiehard,
        // 2026-08-05: six hosts all reporting 96-100% with `top` showing 76%
        // idle). Restarting the service "fixed" it only until the next startup
        // sample replaced it with another bogus 100%.
        //
        // Wait out the remainder of the interval so the window is real. Every
        // one-shot caller is already on a dedicated thread or spawn_blocking,
        // so this never parks an async worker, and the steady-state pollers
        // never sleep at all.
        let since_last = self.last_cpu_sample.elapsed();
        if since_last < MINIMUM_CPU_UPDATE_INTERVAL {
            std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL - since_last);
        }

        // Fast path (every tick): CPU + memory + network only
        self.sys.refresh_cpu_all();
        self.last_cpu_sample = Instant::now();
        self.sys.refresh_memory();
        self.networks.refresh();

        // Slow path (every ~30s): disk list only.
        //
        // The full `refresh_processes(All, true)` that used to live here has
        // been removed, and it was the single most expensive thing WolfStack
        // did on a busy host. Two costs, both severe:
        //
        //   1. sysinfo walks and parses every entry under /proc. On a node
        //      running ~190 OpenSim regions that is 50,766 threads, every 30
        //      seconds, which alone put wolfstack at 390% CPU (production
        //      fleet, 2026-08-05).
        //   2. sysinfo's Linux backend keeps an open `/proc/<pid>/stat` handle
        //      per process as a cache (`stat_file: Option<FileCounter>`), and
        //      budgets itself HALF of RLIMIT_NOFILE to do it — it even raises
        //      our soft limit to the hard limit first. With LimitNOFILE=65535
        //      that is 32,767 descriptors held open for ever, which is what
        //      exhausted the fd table and drove system CPU to 60-80%.
        //
        // Nothing in collect() needed it. The only consumer was the
        // `processes` count below, and `top_processes()` — the one caller that
        // actually wants the process LIST, behind GET /api/metrics/processes —
        // already refreshes for itself on demand. So this was paying to scan
        // every thread on the box every 30s to produce a single integer.
        self.tick += 1;
        if self.tick >= SLOW_REFRESH_TICKS {
            self.tick = 0;
            self.disks.refresh_list();
        }

        let cpu_model = self.sys.cpus().first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let cpu_usage: f32 = self.sys.cpus().iter()
            .map(|c| c.cpu_usage())
            .sum::<f32>() / self.sys.cpus().len().max(1) as f32;

        let disks: Vec<DiskMetrics> = self.disks.iter()
            .filter(|d| {
                let mount = d.mount_point().to_string_lossy();
                !mount.starts_with("/snap") && !mount.starts_with("/boot/efi")
                    && d.total_space() > 0
            })
            .map(|d| {
                let total = d.total_space();
                let available = d.available_space();
                let used = total.saturating_sub(available);
                DiskMetrics {
                    name: d.name().to_string_lossy().to_string(),
                    mount_point: d.mount_point().to_string_lossy().to_string(),
                    fs_type: d.file_system().to_string_lossy().to_string(),
                    total_bytes: total,
                    used_bytes: used,
                    available_bytes: available,
                    usage_percent: if total > 0 { (used as f32 / total as f32) * 100.0 } else { 0.0 },
                }
            })
            .collect();

        let network: Vec<NetworkMetrics> = self.networks.iter()
            .filter(|(name, _)| *name != "lo")
            .map(|(name, data)| NetworkMetrics {
                interface: name.clone(),
                rx_bytes: data.total_received(),
                tx_bytes: data.total_transmitted(),
                rx_packets: data.total_packets_received(),
                tx_packets: data.total_packets_transmitted(),
            })
            .collect();

        let load = System::load_average();

        let cpu_count = self.sys.cpus().len();
        let total_memory = self.sys.total_memory();
        let hardware_tier = classify_hardware(cpu_count, total_memory);

        SystemMetrics {
            hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
            uptime_secs: System::uptime(),
            cpu_usage_percent: cpu_usage,
            cpu_count,
            cpu_model,
            memory_total_bytes: total_memory,
            memory_used_bytes: self.sys.used_memory(),
            memory_percent: if total_memory > 0 {
                (self.sys.used_memory() as f32 / total_memory as f32) * 100.0
            } else { 0.0 },
            swap_total_bytes: self.sys.total_swap(),
            swap_used_bytes: self.sys.used_swap(),
            disks,
            network,
            load_avg: LoadAverage {
                one: load.one,
                five: load.five,
                fifteen: load.fifteen,
            },
            processes: count_processes(),
            os_name: System::name(),
            os_version: System::os_version(),
            kernel_version: System::kernel_version(),
            hardware_tier,
        }
    }
}

/// A single process entry for top-N display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub memory_percent: f32,
}

impl SystemMonitor {
    /// Get top processes by CPU and memory usage.
    ///
    /// Rate-limited to one real scan per `TOP_PROC_TTL` regardless of how many
    /// clients ask, and scanned on a throwaway `System` so the descriptors it
    /// needs are released immediately. Blocks for `MINIMUM_CPU_UPDATE_INTERVAL`
    /// on a cache miss — callers must be on a blocking thread.
    pub fn top_processes(&mut self, count: usize) -> (Vec<ProcessInfo>, Vec<ProcessInfo>) {
        // Serve from cache if a recent scan exists.
        //
        // "On demand" turned out to be a lie: the dashboard polls
        // /api/metrics/processes every 15 SECONDS while the Top Processes
        // panel is on screen (startProcessPolling in app.js). That is a
        // faster timer than the 30s metrics loop this refresh was moved out
        // of in v25.10.4, so anyone sitting on the dashboard reinstated the
        // whole problem — full /proc walk plus sysinfo's descriptor claim,
        // four times a minute (reported by JJ, 2026-08-06, nodes at 100%
        // CPU on v25.10.4).
        //
        // The panel does not need second-by-second truth; a 30s cache is
        // indistinguishable to a human reading a top-10 table, and it makes
        // the cost independent of how hard any client polls.
        {
            let cache = TOP_PROC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((taken, cpu, mem)) = cache.as_ref()
                && taken.elapsed() < TOP_PROC_TTL {
                    return (
                        cpu.iter().take(count).cloned().collect(),
                        mem.iter().take(count).cloned().collect(),
                    );
                }
        }

        // Scan on a THROWAWAY System, never `self.sys`.
        //
        // sysinfo keeps an open /proc/<pid>/stat handle per process and
        // budgets itself HALF of RLIMIT_NOFILE for that cache. Held on the
        // long-lived monitor those descriptors are permanent — 32,767 on a
        // busy host. Scoped to a temporary System they are released the
        // moment it drops, so the claim is transient instead of forever, and
        // `self.sys` (the one the 2s metrics loop uses) never holds any.
        //
        // The scan must be TWO refreshes with a gap. sysinfo derives process
        // CPU from the delta between consecutive samples, and on a System that
        // has never seen a process before it bails out and leaves the figure
        // at zero (`compute_cpu_usage`, linux/process.rs:289 — "First time
        // updating the values without reference, wait for a second cycle").
        // A single refresh here would return a Top-CPU table of all-zeros in
        // arbitrary order. The gap must be at least MINIMUM_CPU_UPDATE_INTERVAL
        // or the CPU times behind the delta are not re-read either
        // (`CpusWrapper::refresh`, linux/cpu.rs:56).
        //
        // 200ms of blocking is affordable because this runs at most once per
        // TOP_PROC_TTL and the endpoint is already on `spawn_blocking`.
        let mut scan = System::new();
        scan.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
        scan.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        // Total RAM and core count come from `self.sys`, which the metrics
        // loop keeps refreshed. The throwaway System has only ever been asked
        // for processes, so its memory and CPU tables are still zeroed — using
        // them would report every process as 0% of RAM.
        let total_mem = self.sys.total_memory();
        let cpu_count = self.sys.cpus().len().max(1) as f32;

        let mut procs: Vec<ProcessInfo> = scan.processes().values()
            .filter(|p| p.cpu_usage() > 0.0 || p.memory() > 0)
            .map(|p| {
                let mem = p.memory();
                // sysinfo reports per-core CPU (e.g. 400% on 4 cores) — normalise to 0-100%
                let cpu_normalized = p.cpu_usage() / cpu_count;
                ProcessInfo {
                    pid: p.pid().as_u32(),
                    name: p.name().to_string_lossy().to_string(),
                    cpu_percent: cpu_normalized,
                    memory_bytes: mem,
                    memory_percent: if total_mem > 0 { (mem as f32 / total_mem as f32) * 100.0 } else { 0.0 },
                }
            })
            .collect();

        // Cache deeper than the caller asked for, so a later request for a
        // longer list is still served from cache instead of forcing a fresh
        // /proc walk. Ranked lists are built from the FULL set before any
        // truncation — caching an already-trimmed list would silently pin the
        // cache depth to whatever the first caller happened to ask for.
        const CACHE_DEPTH: usize = 50;
        let depth = count.max(CACHE_DEPTH);

        // Top CPU
        procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
        let cached_cpu: Vec<ProcessInfo> = procs.iter().take(depth).cloned().collect();
        let top_cpu: Vec<ProcessInfo> = cached_cpu.iter().take(count).cloned().collect();

        // Top Memory
        procs.sort_by_key(|p| std::cmp::Reverse(p.memory_bytes));
        let cached_mem: Vec<ProcessInfo> = procs.iter().take(depth).cloned().collect();
        let top_mem: Vec<ProcessInfo> = cached_mem.iter().take(count).cloned().collect();

        // Drop the scan explicitly so its /proc handles are released before
        // we take the cache lock — makes the transient claim as short as
        // possible rather than relying on end-of-scope.
        drop(scan);

        let mut cache = TOP_PROC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        *cache = Some((Instant::now(), cached_cpu, cached_mem));

        (top_cpu, top_mem)
    }
}

/// Classify hardware as "low", "mid", or "high" based on CPU cores and RAM
pub fn classify_hardware(cpu_count: usize, total_memory_bytes: u64) -> String {
    let ram_gb = total_memory_bytes / (1024 * 1024 * 1024);
    if cpu_count <= 2 || ram_gb <= 4 {
        "low".into()
    } else if cpu_count <= 4 || ram_gb <= 8 {
        "mid".into()
    } else {
        "high".into()
    }
}

// ─── Historical Metrics ───

/// Maximum number of historical snapshots to keep (300 × 2s = ~10 min)
pub const HISTORY_MAX_SNAPSHOTS: usize = 300;

/// A single disk's usage at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSnapshot {
    pub mount_point: String,
    pub usage_percent: f32,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

/// A point-in-time snapshot of key metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disks: Vec<DiskSnapshot>,
    #[serde(default)]
    pub network_rx_bytes: u64,
    #[serde(default)]
    pub network_tx_bytes: u64,
}

/// Ring buffer of historical metric snapshots
pub struct MetricsHistory {
    snapshots: VecDeque<MetricsSnapshot>,
    max_size: usize,
}

impl MetricsHistory {
    pub fn new() -> Self {
        Self {
            snapshots: VecDeque::with_capacity(HISTORY_MAX_SNAPSHOTS),
            max_size: HISTORY_MAX_SNAPSHOTS,
        }
    }

    /// Record a snapshot from current SystemMetrics
    pub fn push(&mut self, metrics: &SystemMetrics) {
        let (rx_total, tx_total) = metrics.network.iter().fold((0u64, 0u64), |(rx, tx), n| {
            (rx + n.rx_bytes, tx + n.tx_bytes)
        });
        let snap = MetricsSnapshot {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            cpu_percent: metrics.cpu_usage_percent,
            memory_percent: metrics.memory_percent,
            memory_used_bytes: metrics.memory_used_bytes,
            memory_total_bytes: metrics.memory_total_bytes,
            disks: metrics.disks.iter().map(|d| DiskSnapshot {
                mount_point: d.mount_point.clone(),
                usage_percent: d.usage_percent,
                used_bytes: d.used_bytes,
                total_bytes: d.total_bytes,
            }).collect(),
            network_rx_bytes: rx_total,
            network_tx_bytes: tx_total,
        };

        if self.snapshots.len() >= self.max_size {
            self.snapshots.pop_front();
        }
        self.snapshots.push_back(snap);
    }

    /// Get all snapshots
    pub fn get_all(&self) -> Vec<MetricsSnapshot> {
        self.snapshots.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;



    /// Construction must not claim sysinfo's descriptor budget either.
    ///
    /// `System::new_all()` means `RefreshKind::everything()`, which includes a
    /// full process refresh — and sysinfo caches an open `/proc/<pid>/stat`
    /// handle per process, budgeting itself HALF of RLIMIT_NOFILE. Fixing
    /// collect() alone left this path claiming ~32,768 descriptors at startup
    /// on a busy host.
    #[test]
    fn construction_does_not_claim_a_descriptor_per_process() {
        fn open_fds() -> usize {
            std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
        }
        // Three attempts, pass on any: parallel test threads open and
        // close their own descriptors between the two counts, which
        // occasionally inflated `after` past the margin (two spurious
        // release-gate failures on 2026-08-11 alone). The regression
        // this guards — sysinfo caching a /proc/<pid>/stat handle per
        // process — HOLDS its descriptors, so it fails every attempt.
        let procs = count_processes();
        let mut last = (0usize, 0usize);
        for _ in 0..3 {
            let before = open_fds();
            let mon = SystemMonitor::new();
            let after = open_fds();
            drop(mon);
            if after < before + procs.max(64) {
                return;
            }
            last = (before, after);
        }
        panic!(
            "SystemMonitor::new() opened {} descriptors with {} processes on the \
             box (3/3 attempts) — it is refreshing processes and caching a stat \
             handle each.",
            last.1.saturating_sub(last.0), procs,
        );
    }

    /// The periodic collect() must NOT hold /proc file handles open. sysinfo
    /// caches a `/proc/<pid>/stat` handle per process and grants itself half
    /// of RLIMIT_NOFILE to do it; on the production fleet that was 32,767
    /// descriptors per node and 60-80% system CPU. collect() no longer
    /// refreshes processes at all, so repeated collects must not grow our fd
    /// table.
    #[test]
    fn repeated_collect_does_not_accumulate_descriptors() {
        fn open_fds() -> usize {
            std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
        }
        let mut mon = SystemMonitor::new();
        let _ = mon.collect();
        let baseline = open_fds();
        // Enough iterations to cross SLOW_REFRESH_TICKS several times.
        for _ in 0..(SLOW_REFRESH_TICKS * 3) {
            let _ = mon.collect();
        }
        let after = open_fds();
        assert!(
            after <= baseline + 16,
            "collect() leaked descriptors: {} -> {} over {} calls. sysinfo's \
             per-process stat-handle cache is back in the hot path.",
            baseline, after, SLOW_REFRESH_TICKS * 3,
        );
    }

    /// The top-processes scan must be capped by the clock, not by how hard
    /// clients poll — and it must still leave no descriptors behind.
    ///
    /// The dashboard polls /api/metrics/processes every 15s PER VIEWER
    /// (`startProcessPolling`, web/js/app.js). v25.10.4 took the process
    /// refresh off the metrics loop and left this endpoint to do it on demand,
    /// which meant anyone parked on the dashboard reinstated the full /proc
    /// walk four times a minute — faster than the loop that was removed.
    ///
    /// Two things are asserted here, both by observable behaviour rather than
    /// by inspecting internals: a burst of calls costs one scan, and it costs
    /// no descriptors.
    #[test]
    fn top_processes_scan_is_rate_limited_and_leaks_nothing() {
        fn open_fds() -> usize {
            std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
        }
        let mut mon = SystemMonitor::new();

        // First call pays for a scan; it must be a REAL one, so at least the
        // two-sample CPU window.
        let start = Instant::now();
        let (cpu, mem) = mon.top_processes(10);
        let first = start.elapsed();
        assert!(!cpu.is_empty() && !mem.is_empty(), "scan returned no processes");
        assert!(
            first >= MINIMUM_CPU_UPDATE_INTERVAL,
            "scan took {:?} — shorter than the CPU sampling window, so every \
             process CPU figure is zero (sysinfo needs two samples)",
            first,
        );
        assert!(
            cpu.iter().any(|p| p.cpu_percent > 0.0),
            "every process reported 0% CPU — the scan is sampling only once",
        );
        assert!(
            mem.iter().any(|p| p.memory_percent > 0.0),
            "every process reported 0% of RAM — total memory was read from a \
             System that never refreshed memory",
        );

        // A burst must be served from cache: 20 calls in well under the cost
        // of a second scan, and no growth in our fd table.
        let baseline = open_fds();
        let burst = Instant::now();
        for _ in 0..20 {
            let _ = mon.top_processes(10);
        }
        let burst = burst.elapsed();
        assert!(
            burst < MINIMUM_CPU_UPDATE_INTERVAL,
            "20 polls took {:?} — at least one re-scanned, so the cache is not \
             bounding the rate and every dashboard viewer costs a /proc walk",
            burst,
        );
        let after = open_fds();
        assert!(
            after <= baseline + 16,
            "top_processes leaked descriptors: {} -> {}. The scan must run on \
             a throwaway System that drops its /proc handles.",
            baseline, after,
        );
    }

    /// The count must still be sane after dropping sysinfo's process refresh.
    #[test]
    fn process_count_is_plausible() {
        let n = count_processes();
        assert!(n > 0, "counted 0 processes — /proc parsing is broken");
        assert!(n < 500_000, "counted {} processes, implausible", n);
    }

    /// A one-shot `new()` + `collect()` must still produce a real CPU
    /// measurement.
    ///
    /// sysinfo derives CPU% from the gap between two refreshes. Before the
    /// guard in `collect()`, the one-shot callers (startup metrics, the MCP
    /// metrics tool, WolfAgents) refreshed microseconds after construction and
    /// got ~100% on a completely idle machine — and the startup one is
    /// published to the whole cluster via `update_self`, so every node
    /// advertised itself as pegged right after boot.
    ///
    /// Asserting the elapsed window rather than the returned percentage keeps
    /// this deterministic: a CI box under real load can legitimately report
    /// any value, but the measurement window is ours to guarantee.
    #[test]
    fn one_shot_collect_waits_for_a_real_cpu_window() {
        let start = Instant::now();
        let mut mon = SystemMonitor::new();
        let m = mon.collect();
        println!(
            "one-shot collect: cpu={:.1}% over {:?} ({} cores, load1={:.2})",
            m.cpu_usage_percent, start.elapsed(), m.cpu_count, m.load_avg.one,
        );
        assert!(
            (0.0..=100.0).contains(&m.cpu_usage_percent),
            "cpu_usage_percent {:.1} is outside 0-100 — the averaging or the \
             sampling window is wrong", m.cpu_usage_percent,
        );
        assert!(
            start.elapsed() >= MINIMUM_CPU_UPDATE_INTERVAL,
            "collect() returned after {:?}, which is less than sysinfo's \
             MINIMUM_CPU_UPDATE_INTERVAL ({:?}) — the CPU delta was measured \
             over a near-zero window and the percentage is meaningless",
            start.elapsed(), MINIMUM_CPU_UPDATE_INTERVAL,
        );
    }

    /// The steady-state poller must NOT pay the wait. Callers refreshing on a
    /// 2s loop are already far past the minimum interval, and adding a sleep
    /// to the hot path would slow every node's metrics tick.
    #[test]
    fn steady_state_collect_does_not_sleep() {
        let mut mon = SystemMonitor::new();
        let _ = mon.collect(); // first one may wait — that's the point above
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);

        let start = Instant::now();
        let _ = mon.collect();
        assert!(
            start.elapsed() < MINIMUM_CPU_UPDATE_INTERVAL,
            "collect() slept for {:?} despite the previous sample being older \
             than the minimum interval — the guard should be a no-op here",
            start.elapsed(),
        );
    }
}
