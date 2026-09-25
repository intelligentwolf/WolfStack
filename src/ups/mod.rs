// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! UPS power management (NUT integration + staged shutdown).
//!
//! Operators run Network UPS Tools (upsd/upsmon/drivers) as "basic Linux
//! stuff" — WolfStack deliberately does NOT write or manage any NUT
//! config file ("never break existing installs"). What NUT alone can't
//! express is the thing operators actually want on battery power: a
//! staged, workload-aware wind-down. This module layers exactly that on
//! top of any working NUT setup, needing nothing but read access via
//! `upsc`:
//!
//!   at ≤ 60% battery → gracefully stop VMs and containers
//!   at ≤ 40% battery → stop file-sharing services
//!   at ≤ 20% battery → shut the host down
//!
//! Each stage fires once per outage (latched) and everything is written
//! to a persisted action log — the host may be about to power off, so
//! the post-mortem must survive the shutdown we cause. Stage thresholds,
//! actions and the polled UPS target are all operator-configured in
//! `/etc/wolfstack/ups.json`; nothing fires unless the engine is enabled
//! AND live `upsc` data shows the UPS on battery (stale or unreadable
//! data never triggers actions).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::VecDeque;
use std::process::Command;
use std::sync::RwLock;
use tracing::{info, warn};

fn config_file() -> String {
    format!("{}/ups.json", crate::paths::get().config_dir)
}
/// Survives the host shutdown this engine can cause — /var/lib, not tmpfs.
const LOG_FILE: &str = "/var/lib/wolfstack/ups-log.json";
const LOG_KEEP: usize = 200;

// ═══════════════════════════════════════════════
// ─── Config ───
// ═══════════════════════════════════════════════

/// One action inside a stage. Executed in the order declared here —
/// workloads before the services they depend on, host last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpsAction {
    /// Gracefully stop VMs: every WolfStack-managed VM via the manager
    /// (which dispatches qm / virsh / native per platform), then a CLI
    /// sweep for any still-running unmanaged qm / libvirt guests.
    StopVms,
    /// Stop all running Docker containers, Proxmox `pct` containers and
    /// classic `lxc-*` containers.
    StopContainers,
    /// Stop file-sharing services (samba + NFS server, both unit-name
    /// spellings). Network filesystems this host merely MOUNTS are left
    /// alone.
    StopShares,
    /// `systemctl poweroff` (fallback `shutdown -h now`). The final
    /// stage — the log is flushed before this runs.
    ShutdownHost,
}

impl UpsAction {
    pub fn label(&self) -> &'static str {
        match self {
            UpsAction::StopVms => "stop VMs",
            UpsAction::StopContainers => "stop containers",
            UpsAction::StopShares => "stop shares",
            UpsAction::ShutdownHost => "shut down host",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsStage {
    /// Fires when the UPS is on battery AND battery.charge <= this.
    pub battery_percent: u8,
    pub actions: Vec<UpsAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `upsc` target: "myups" for a local upsd, "myups@host" for a
    /// remote one. Empty = engine idle even when enabled.
    #[serde(default)]
    pub ups: String,
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    #[serde(default)]
    pub stages: Vec<UpsStage>,
}

fn default_poll_secs() -> u64 { 15 }

impl Default for UpsConfig {
    fn default() -> Self {
        Self { enabled: false, ups: String::new(), poll_secs: default_poll_secs(), stages: Vec::new() }
    }
}

impl UpsConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(config_file()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize ups config: {}", e))?;
        std::fs::write(config_file(), json)
            .map_err(|e| format!("write {}: {}", config_file(), e))
    }

    /// Clamp operator input into sane ranges (mirrors what the API
    /// handler enforces so a hand-edited file can't misbehave either).
    pub fn sanitize(&mut self) {
        self.poll_secs = self.poll_secs.clamp(5, 300);
        for s in &mut self.stages {
            s.battery_percent = s.battery_percent.min(100);
            s.actions.dedup();
        }
        self.stages.retain(|s| !s.actions.is_empty());
        // Highest threshold first = the order stages will fire while
        // the battery drains; also the order the UI shows them.
        self.stages.sort_by_key(|s| std::cmp::Reverse(s.battery_percent));
    }
}

// ═══════════════════════════════════════════════
// ─── Live status (upsc) ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct UpsLiveStatus {
    /// Raw ups.status token string, e.g. "OL", "OB DISCHRG", "OB LB".
    pub status: String,
    pub on_battery: bool,
    pub low_battery: bool,
    /// battery.charge %, when the driver reports it.
    pub charge: Option<u8>,
    /// battery.runtime seconds remaining, when reported.
    pub runtime_secs: Option<u64>,
    /// ups.load %, when reported.
    pub load: Option<u8>,
    /// The UPS says its battery is worn out: the `RB` status token
    /// ("The battery needs to be replaced", NUT docs/new-drivers.txt
    /// "Status data" — the flag upsmon turns into its REPLBATT notice,
    /// clients/upsmon.c upsreplbatt()), battery.packs.bad > 0, OR
    /// [`test_failed`](Self::test_failed).
    pub replace_battery: bool,
    /// The last battery self-test failed, per [`self_test_failed`]. Kept
    /// separate from RB because on most drivers the two are independent:
    /// usbhid-ups only raises RB from the UPS's own NeedReplacement bit
    /// (drivers/usbhid-ups.c ups_status_set), so a failed test with the
    /// bit unset reads "OL" plus "Done and error" and nothing else.
    pub test_failed: bool,
    /// battery.packs.bad ("Number of bad battery packs", nut-names.txt),
    /// when the driver reports it.
    pub battery_packs_bad: Option<u32>,
    /// ups.test.result — opaque per nut-names.txt, and every driver words
    /// it differently, so it is always shown verbatim; only the exact
    /// strings in [`self_test_failed`] are read as a verdict.
    pub test_result: Option<String>,
    /// ups.alarm — opaque, possibly several sentences (nut-names.txt).
    pub alarm: Option<String>,
    /// battery.date — installation / last-change date, opaque string.
    pub battery_date: Option<String>,
    pub model: String,
    /// Unix time of this reading.
    pub read_at: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `upsc <target>` → parsed status. Err carries upsc's own message so
/// the UI can show WHY the UPS is unreachable (bad name, upsd down…).
pub fn query_ups(target: &str) -> Result<UpsLiveStatus, String> {
    let out = Command::new("upsc")
        .arg(target)
        .output()
        .map_err(|e| format!("upsc not runnable: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // upsc prints informational TLS chatter to stderr ("Init SSL…",
        // "SSL handshake done…") before the real failure, which it
        // formats as "Error: <reason>" (nut clients/upsc.c fatalx
        // paths). Surface just the reason, not the noise wall.
        let err = stderr.lines().rev()
            .find_map(|l| l.trim().strip_prefix("Error: "))
            .map(str::to_string)
            .unwrap_or_else(|| stderr.trim().to_string());
        if err.is_empty() {
            return Err("upsc failed".to_string());
        }
        // A bare "Unknown error" is upsc's translation of an ERR reply
        // token it doesn't recognise (nut clients/upsclient.c
        // upscli_errcheck) — in practice a NUT server whose UPS name or
        // hostname configuration doesn't match what we asked for.
        return Err(if err == "Unknown error" {
            "the NUT server replied with an error upsc does not recognise (\"Unknown error\") — \
             check that the target is name@host with the exact UPS name, and that the \
             hostname configured on the NUT server itself matches".to_string()
        } else {
            err
        });
    }
    Ok(parse_upsc(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `upsc <target>` stdout ("key: value" per line). Split out of
/// [`query_ups`] so the status-token handling is unit-testable.
fn parse_upsc(text: &str) -> UpsLiveStatus {
    let get = |key: &str| -> Option<String> {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{}: ", key)))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    // ups.status is a space-separated token list (NUT docs/new-drivers.txt
    // "Status data"): OL = on line, OB = on battery, LB = low battery,
    // RB = the battery needs to be replaced. upsmon matches the tokens
    // case-insensitively (clients/upsmon.c parse_status, strcasecmp), so
    // do the same.
    let status = get("ups.status").unwrap_or_default();
    let has = |tok: &str| status.split_whitespace().any(|t| t.eq_ignore_ascii_case(tok));
    let battery_packs_bad = get("battery.packs.bad").and_then(|v| v.parse::<f64>().ok()).map(|v| v as u32);
    let test_result = get("ups.test.result");
    let test_failed = test_result.as_deref().is_some_and(self_test_failed);
    UpsLiveStatus {
        on_battery: has("OB"),
        low_battery: has("LB"),
        replace_battery: has("RB") || battery_packs_bad.is_some_and(|n| n > 0) || test_failed,
        test_failed,
        battery_packs_bad,
        test_result,
        alarm: get("ups.alarm"),
        battery_date: get("battery.date"),
        charge: get("battery.charge").and_then(|v| v.parse::<f64>().ok()).map(|v| v.round() as u8),
        runtime_secs: get("battery.runtime").and_then(|v| v.parse::<f64>().ok()).map(|v| v as u64),
        load: get("ups.load").and_then(|v| v.parse::<f64>().ok()).map(|v| v.round() as u8),
        model: get("device.model").or_else(|| get("ups.model")).unwrap_or_default(),
        status,
        read_at: now_secs(),
    }
}

/// ups.test.result values that mean the battery self-test FAILED. Only
/// strings a NUT driver is known to emit for that outcome are listed —
/// ups.test.result is otherwise free text, and matching loosely (say, any
/// "fail" substring) would also catch "Bad Inverter"-style results that
/// are not about the battery. Anything not listed stays display-only.
///
/// Exact values:
///   "Done and error"        usbhid-ups test_read_info[] value 3 — used by
///                           the apc, cps (CyberPower), mge (Eaton), tripplite,
///                           liebert, delta_ups, powercom and salicru HID
///                           subdrivers (drivers/usbhid-ups.c)
///   "Battery Bad (Replace)" tripplite.c (serial Tripp Lite), which never
///                           sets RB
///   "10s test failed", "deep test failed"
///                           belkin.c (serial Belkin), which never sets RB
///   "Failed"                apc-mib.c apcc_testdiag_results and
///                           cyberpower-mib.c cyberpower_testdiag_results
///                           (SNMP network cards)
/// Plus the first ", "-separated field being "Failed": apc_modbus.c joins
/// result, source and modifier with ", " ("Failed, Source: Internal")
/// in every release that reports the test (2.8.2 onward;
/// _apc_modbus_string_join / apc_common.c apc_format_test_status_value).
pub fn self_test_failed(result: &str) -> bool {
    const EXACT: [&str; 5] = [
        "Done and error",
        "Battery Bad (Replace)",
        "10s test failed",
        "deep test failed",
        "Failed",
    ];
    let r = result.trim();
    EXACT.contains(&r) || r.split(", ").next() == Some("Failed")
}

/// Why the UPS wants a new battery, in operator words — shared by the
/// Issues scan, the predictive finding and the UPS action log so all
/// three say the same thing. None when the battery is not flagged.
pub fn battery_fault_summary(live: &UpsLiveStatus) -> Option<String> {
    if !live.replace_battery {
        return None;
    }
    let mut parts = Vec::new();
    if live.status.split_whitespace().any(|t| t.eq_ignore_ascii_case("RB")) {
        parts.push(format!("the UPS reports \"replace battery\" (status {})", live.status));
    }
    if let Some(n) = live.battery_packs_bad.filter(|n| *n > 0) {
        parts.push(format!("{} bad battery pack(s)", n));
    }
    if let Some(t) = &live.test_result {
        if live.test_failed {
            parts.push(format!("the last battery self-test failed (\"{}\")", t));
        } else {
            parts.push(format!("last self-test: {}", t));
        }
    }
    Some(parts.join("; "))
}

/// `upsc -l` — names of UPSes served by the local upsd. Empty when
/// there's no local upsd (a client-only box monitors a remote target).
pub fn list_local_upses() -> Vec<String> {
    Command::new("upsc").arg("-l").output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout)
            .lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

pub fn upsc_installed() -> bool {
    crate::mail_relay::which("upsc").is_some()
}

// ═══════════════════════════════════════════════
// ─── Runtime state + action log ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsLogEntry {
    pub timestamp: u64,
    /// "on_battery" | "online" | "stage" | "action" | "error" | "battery"
    pub kind: String,
    pub message: String,
}

#[derive(Default)]
pub struct UpsRuntime {
    /// Unix time the current outage started; None = on mains.
    pub on_battery_since: Option<u64>,
    /// battery_percent thresholds already fired this outage. Keyed by
    /// threshold (not index) so a config edit mid-outage can't re-fire
    /// a stage that already ran.
    pub fired: HashSet<u8>,
    pub last_status: Option<UpsLiveStatus>,
    pub last_error: Option<String>,
    /// Whether the last good reading flagged the battery for
    /// replacement — edge-detects the fault so the action log gets one
    /// entry when it appears and one when it clears, not one per poll.
    pub battery_fault: bool,
    pub log: VecDeque<UpsLogEntry>,
}

pub struct UpsState {
    pub runtime: RwLock<UpsRuntime>,
}

impl UpsState {
    pub fn new() -> Self {
        let mut rt = UpsRuntime::default();
        // Reload the persisted log so the post-outage UI shows what the
        // engine did before a shutdown/restart.
        if let Ok(s) = std::fs::read_to_string(LOG_FILE)
            && let Ok(entries) = serde_json::from_str::<Vec<UpsLogEntry>>(&s)
        {
            rt.log = entries.into_iter().collect();
        }
        Self { runtime: RwLock::new(rt) }
    }
}

impl Default for UpsState {
    fn default() -> Self { Self::new() }
}

/// Append to the in-memory log AND persist immediately — a stage may be
/// the last thing this host does before losing power.
fn log_event(state: &UpsState, kind: &str, message: String) {
    info!("UPS: {}", message);
    let snapshot: Vec<UpsLogEntry> = {
        let mut rt = state.runtime.write().unwrap();
        rt.log.push_back(UpsLogEntry { timestamp: now_secs(), kind: kind.to_string(), message });
        while rt.log.len() > LOG_KEEP {
            rt.log.pop_front();
        }
        rt.log.iter().cloned().collect()
    };
    let _ = std::fs::create_dir_all("/var/lib/wolfstack");
    if let Ok(json) = serde_json::to_string_pretty(&snapshot)
        && let Err(e) = std::fs::write(LOG_FILE, json)
    {
        warn!("UPS: failed to persist action log: {}", e);
    }
}

// ═══════════════════════════════════════════════
// ─── Engine ───
// ═══════════════════════════════════════════════

/// One poll cycle. Called from the background loop in main.rs; all
/// blocking work (upsc, stop commands) runs inside spawn_blocking.
///
/// Monitoring (live reading, comms errors, battery health) runs whenever
/// a UPS target is set. `enabled` arms only the power-event side: the
/// on-battery / restored alerts and the shutdown stages. A saved but
/// disarmed target used to go unpolled, so a failed battery on it
/// was never shown (RutgerDiehard, 2026-09-25).
pub async fn engine_tick(state: &std::sync::Arc<UpsState>, app: &std::sync::Arc<crate::api::AppState>) {
    let config = UpsConfig::load();
    if config.ups.trim().is_empty() {
        return;
    }

    let target = config.ups.trim().to_string();
    let status = tokio::task::spawn_blocking(move || query_ups(&target)).await;
    let status = match status {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            // Unreadable UPS data must never fire actions — record the
            // error for the UI and wait for the next poll.
            let mut rt = state.runtime.write().unwrap();
            rt.last_error = Some(e);
            return;
        }
        Err(e) => {
            warn!("UPS: status poll task failed: {}", e);
            return;
        }
    };

    // Battery-health edge, logged whether or not the stages are armed.
    // Notification is the predictive `ups_battery_replace` finding's job
    // (High → first-appearance dispatch), so this only writes the log.
    let fault_changed = {
        let mut rt = state.runtime.write().unwrap();
        rt.last_error = None;
        let changed = rt.battery_fault != status.replace_battery;
        rt.battery_fault = status.replace_battery;
        rt.last_status = Some(status.clone());
        changed
    };
    if fault_changed {
        match battery_fault_summary(&status) {
            Some(why) => log_event(state, "battery",
                format!("UPS '{}' battery needs replacing: {}", config.ups, why)),
            None => log_event(state, "battery",
                format!("UPS '{}' no longer reports a battery fault", config.ups)),
        }
    }
    if !config.enabled {
        return;
    }

    // Transition detection under one short lock, actions after.
    let (went_on_battery, recovered, outage_secs) = {
        let mut rt = state.runtime.write().unwrap();
        let went_on = status.on_battery && rt.on_battery_since.is_none();
        let recovered = !status.on_battery && rt.on_battery_since.is_some();
        let outage_secs = rt.on_battery_since.map(|t| now_secs().saturating_sub(t)).unwrap_or(0);
        if went_on {
            rt.on_battery_since = Some(now_secs());
        }
        if recovered {
            rt.on_battery_since = None;
            rt.fired.clear();
        }
        (went_on, recovered, outage_secs)
    };

    if went_on_battery {
        let msg = format!(
            "UPS '{}' on battery ({}% charge, {} min runtime reported)",
            config.ups,
            status.charge.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
            status.runtime_secs.map(|r| (r / 60).to_string()).unwrap_or_else(|| "?".into()),
        );
        log_event(state, "on_battery", msg.clone());
        crate::alerting::send_local_alert(
            crate::alerting::AlertCategory::Lifecycle,
            "UPS on battery", &msg,
        ).await;
        crate::wolffunctions::fire_event_global(
            crate::wolffunctions::TriggerEvent::UpsOnBattery,
            serde_json::json!({ "ups": config.ups, "charge": status.charge, "runtime_secs": status.runtime_secs, "status": status.status }),
            true,
        );
    }
    if recovered {
        let msg = format!(
            "UPS '{}' back on mains after {} min ({}% charge)",
            config.ups, outage_secs / 60,
            status.charge.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
        );
        log_event(state, "online", msg.clone());
        crate::alerting::send_local_alert(
            crate::alerting::AlertCategory::Lifecycle,
            "UPS power restored", &msg,
        ).await;
        crate::wolffunctions::fire_event_global(
            crate::wolffunctions::TriggerEvent::UpsOnline,
            serde_json::json!({ "ups": config.ups, "charge": status.charge, "outage_secs": outage_secs }),
            true,
        );
    }

    if !status.on_battery {
        return;
    }
    let Some(charge) = status.charge else {
        // Driver reports no battery.charge — stages are %-keyed, so they
        // can't fire. Surface that once per outage so it isn't silent.
        if went_on_battery {
            log_event(state, "error",
                "UPS reports no battery.charge — staged shutdown cannot trigger on this driver".to_string());
        }
        return;
    };

    // Due = configured threshold reached and not fired this outage.
    // Sorted highest-first so a fast drain past two thresholds still
    // runs the gentler stage (VMs) before the harsher one (host off).
    let due: Vec<UpsStage> = {
        let rt = state.runtime.read().unwrap();
        let mut d: Vec<UpsStage> = config.stages.iter()
            .filter(|s| charge <= s.battery_percent && !rt.fired.contains(&s.battery_percent))
            .cloned()
            .collect();
        d.sort_by_key(|s| std::cmp::Reverse(s.battery_percent));
        d
    };

    for stage in due {
        {
            let mut rt = state.runtime.write().unwrap();
            rt.fired.insert(stage.battery_percent);
        }
        let actions_label: Vec<&str> = stage.actions.iter().map(|a| a.label()).collect();
        let msg = format!(
            "battery at {}% (≤{}% stage): {}",
            charge, stage.battery_percent, actions_label.join(", "),
        );
        log_event(state, "stage", msg.clone());
        crate::alerting::send_local_alert(
            crate::alerting::AlertCategory::Threshold,
            "UPS shutdown stage triggered", &msg,
        ).await;
        crate::wolffunctions::fire_event_global(
            crate::wolffunctions::TriggerEvent::UpsStageFired,
            serde_json::json!({ "ups": config.ups, "charge": charge, "stage_percent": stage.battery_percent, "actions": stage.actions }),
            true,
        );
        for action in &stage.actions {
            run_action(state, app, *action).await;
        }
    }
}

/// Execute one action, logging every command outcome. Failures are
/// logged and skipped — on battery, doing the REST of the wind-down
/// beats aborting because one VM refused to stop.
async fn run_action(state: &std::sync::Arc<UpsState>, app: &std::sync::Arc<crate::api::AppState>, action: UpsAction) {
    let state_c = state.clone();
    let app_c = app.clone();
    let result = tokio::task::spawn_blocking(move || {
        match action {
            UpsAction::StopVms => stop_all_vms(&state_c, &app_c),
            UpsAction::StopContainers => stop_all_containers(&state_c),
            UpsAction::StopShares => stop_share_services(&state_c),
            UpsAction::ShutdownHost => shutdown_host(&state_c),
        }
    }).await;
    if let Err(e) = result {
        log_event(state, "error", format!("{} task failed: {}", action.label(), e));
    }
}

fn run_logged(state: &UpsState, desc: &str, cmd: &str, args: &[&str]) {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => log_event(state, "action", format!("{}: ok", desc)),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            log_event(state, "error", format!("{}: {}", desc, if err.is_empty() { "failed".into() } else { err }));
        }
        Err(e) => log_event(state, "error", format!("{}: {}", desc, e)),
    }
}

fn stop_all_vms(state: &UpsState, app: &crate::api::AppState) {
    // 1. WolfStack-managed VMs — the manager dispatches per platform
    // (qm graceful / virsh shutdown / native), same path as the UI's
    // stop button.
    let managed: Vec<String> = {
        let mgr = app.vms.lock().unwrap();
        mgr.list_vms().iter()
            .map(|v| v.name.clone())
            .filter(|n| mgr.check_running(n))
            .collect()
    };
    for name in &managed {
        let res = { app.vms.lock().unwrap().stop_vm(name, false) };
        match res {
            Ok(_) => log_event(state, "action", format!("stop VM '{}': requested", name)),
            Err(e) => log_event(state, "error", format!("stop VM '{}': {}", name, e)),
        }
    }
    // 2. Sweep unmanaged guests the tools know about. Overlap with the
    // managed set is harmless — a second shutdown of a stopping guest
    // just logs an error.
    if crate::mail_relay::which("qm").is_some() {
        // `qm list` columns: VMID NAME STATUS … — take running VMIDs.
        if let Ok(o) = Command::new("qm").arg("list").output() {
            for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 3 && cols[2] == "running" {
                    run_logged(state, &format!("qm shutdown {}", cols[0]),
                        "qm", &["shutdown", cols[0], "--timeout", "60"]);
                }
            }
        }
    }
    if crate::mail_relay::which("virsh").is_some()
        && let Ok(o) = Command::new("virsh").args(["list", "--name"]).output()
    {
        for dom in String::from_utf8_lossy(&o.stdout).lines().map(str::trim).filter(|l| !l.is_empty()) {
            run_logged(state, &format!("virsh shutdown {}", dom), "virsh", &["shutdown", dom]);
        }
    }
    if managed.is_empty() {
        log_event(state, "action", "stop VMs: no managed VMs running".to_string());
    }
}

fn stop_all_containers(state: &UpsState) {
    if crate::mail_relay::which("docker").is_none()
        && crate::mail_relay::which("pct").is_none()
        && crate::mail_relay::which("lxc-ls").is_none()
    {
        log_event(state, "action", "stop containers: no container runtime on this host".to_string());
        return;
    }
    if crate::mail_relay::which("docker").is_some() {
        let ids: Vec<String> = Command::new("docker").args(["ps", "-q"]).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout)
                .lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        if ids.is_empty() {
            log_event(state, "action", "stop containers: no docker containers running".to_string());
        } else {
            let mut args: Vec<&str> = vec!["stop"];
            args.extend(ids.iter().map(String::as_str));
            run_logged(state, &format!("docker stop ({} containers)", ids.len()), "docker", &args);
        }
    }
    if crate::mail_relay::which("pct").is_some() {
        // `pct list` columns: VMID STATUS … NAME — stop running CTs.
        if let Ok(o) = Command::new("pct").arg("list").output() {
            for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 2 && cols[1] == "running" {
                    run_logged(state, &format!("pct shutdown {}", cols[0]),
                        "pct", &["shutdown", cols[0], "--timeout", "60"]);
                }
            }
        }
    } else if crate::mail_relay::which("lxc-ls").is_some()
        && let Ok(o) = Command::new("lxc-ls").arg("--running").output()
    {
        for ct in String::from_utf8_lossy(&o.stdout).split_whitespace().filter(|l| !l.is_empty()) {
            run_logged(state, &format!("lxc-stop {}", ct), "lxc-stop", &["-n", ct]);
        }
    }
}

fn stop_share_services(state: &UpsState) {
    // Both unit-name spellings across distros: Debian smbd/nmbd,
    // RHEL/Arch/SUSE smb/nmb; nfs-server is the systemd unit everywhere.
    // Stopping a unit that doesn't exist just logs and moves on.
    let mut any = false;
    for unit in ["smbd", "nmbd", "smb", "nmb", "nfs-server"] {
        let active = Command::new("systemctl").args(["is-active", "--quiet", unit])
            .status().map(|s| s.success()).unwrap_or(false);
        if active {
            any = true;
            run_logged(state, &format!("systemctl stop {}", unit), "systemctl", &["stop", unit]);
        }
    }
    if !any {
        log_event(state, "action", "stop shares: no share services active".to_string());
    }
}

fn shutdown_host(state: &UpsState) {
    log_event(state, "action", "shutting down host".to_string());
    // log_event persisted above — safe to go.
    let ok = Command::new("systemctl").arg("poweroff").status()
        .map(|s| s.success()).unwrap_or(false);
    if !ok {
        run_logged(state, "shutdown -h now", "shutdown", &["-h", "now"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_online_ups_has_no_battery_fault() {
        let s = parse_upsc("battery.charge: 100\nups.status: OL CHRG\nups.test.result: Done and passed\n");
        assert!(!s.on_battery && !s.replace_battery);
        assert_eq!(battery_fault_summary(&s), None);
        assert_eq!(s.test_result.as_deref(), Some("Done and passed"));
    }

    #[test]
    fn rb_token_flags_battery_replacement() {
        let s = parse_upsc("ups.status: OL RB\nups.test.result: Battery Bad (Replace)\n");
        assert!(s.replace_battery);
        assert!(!s.on_battery);
        let why = battery_fault_summary(&s).unwrap();
        assert!(why.contains("OL RB") && why.contains("Battery Bad (Replace)"), "{why}");
    }

    #[test]
    fn status_tokens_match_case_insensitively_like_upsmon() {
        let s = parse_upsc("ups.status: ob lb rb\n");
        assert!(s.on_battery && s.low_battery && s.replace_battery);
    }

    #[test]
    fn rb_is_a_whole_token_not_a_substring() {
        // A token that merely contains the letters must not trip it.
        let s = parse_upsc("ups.status: OL ALARM\n");
        assert!(!s.replace_battery);
    }

    #[test]
    fn bad_battery_packs_flag_replacement_without_rb() {
        let s = parse_upsc("ups.status: OL\nbattery.packs.bad: 1\n");
        assert!(s.replace_battery);
        assert_eq!(s.battery_packs_bad, Some(1));
        assert!(battery_fault_summary(&s).unwrap().contains("1 bad battery pack"));
        let ok = parse_upsc("ups.status: OL\nbattery.packs.bad: 0\n");
        assert!(!ok.replace_battery);
    }

    #[test]
    fn usbhid_failed_self_test_without_rb_is_caught() {
        // usbhid-ups with the UPS's NeedReplacement bit unset: no RB,
        // only the test result says the battery failed.
        let s = parse_upsc("ups.status: OL\nups.test.result: Done and error\n");
        assert!(s.test_failed && s.replace_battery);
        assert!(battery_fault_summary(&s).unwrap().contains("self-test failed"));
    }

    #[test]
    fn self_test_verdicts_come_only_from_known_driver_strings() {
        for failed in ["Done and error", "Battery Bad (Replace)", "10s test failed",
                       "deep test failed", "Failed", "Failed, Source: Internal"] {
            assert!(self_test_failed(failed), "{failed}");
        }
        for fine in ["Done and passed", "Done and warning", "Passed", "OK", "Ok",
                     "No test initiated", "Aborted", "In progress", "Bad Inverter",
                     "Passed, Source: Protocol", "Refused, Modifier: InvalidState"] {
            assert!(!self_test_failed(fine), "{fine}");
        }
    }

    #[test]
    fn empty_values_are_absent() {
        let s = parse_upsc("ups.status: OL\nups.alarm: \n");
        assert_eq!(s.alarm, None);
    }
}
