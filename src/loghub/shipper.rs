// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Fleet Logs shipper: the per-node collector. Runs on every enabled node,
//! tails its log sources, redacts secrets at source (before anything leaves the
//! box), and forwards batches to the cluster's hub — or writes locally when
//! this node *is* the hub.
//!
//! Sources, all using mechanisms the rest of WolfStack already relies on:
//!   - **journald (host)** — `journalctl -o json` with a persistent cursor
//!     (`--after-cursor`), a direct generalisation of [`crate::auth::log_monitor`].
//!   - **Docker** — `docker logs --since <ts> --timestamps` per running
//!     container (same CLI as [`crate::containers::docker_logs`]).
//!   - **LXC** — `lxc-attach … journalctl -o json` per running container (same
//!     entry point as [`crate::containers::lxc_logs`]), with its own cursor.
//!
//! Cursors live in memory: on disable or restart we re-baseline at the newest
//! journal entry (`-n 1`, not forwarded) so we never replay a huge backlog, and on any journalctl
//! failure (e.g. a vacuumed/rotated cursor) we reset rather than wedge.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::agent::ClusterState;

use super::{now_millis, LogEvent, LogHubConfig, LogHubState, LogLevel, LogSource, Redactor};
use crate::node_identity::PeerAuth;

/// How often the shipper collects + forwards.
const SHIP_INTERVAL_SECS: u64 = 10;
/// Cap on entries pulled from one journalctl invocation per round (protects
/// against a flood after the cursor falls behind).
const MAX_LINES_PER_ROUND: usize = 50_000;
/// Cap on events held in the local spool while the hub is unreachable. Oldest
/// are dropped (and counted) beyond this so a down hub can never OOM a node.
const SPOOL_MAX: usize = 100_000;
/// Max events per POST to the hub. Bounds each request body so a large spool
/// flush can't exceed the hub's ingest size limit (and can't get wedged).
const SEND_CHUNK: usize = 10_000;
/// Truncate any single log line longer than this (keeps the store + request
/// bodies sane; a multi-megabyte line is almost always a dump we don't want
/// verbatim). The marker makes the truncation visible.
const MAX_MSG_LEN: usize = 16 * 1024;

/// Truncate a message at a UTF-8 char boundary if it exceeds `MAX_MSG_LEN`.
fn cap_msg(mut s: String) -> String {
    if s.len() > MAX_MSG_LEN {
        let mut end = MAX_MSG_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("…[truncated]");
    }
    s
}

/// Shipper thread entry point. Idles (cheaply) while Fleet Logs is disabled.
pub fn ship_loop(loghub: Arc<LogHubState>, cluster: Arc<ClusterState>, secret: String) {
    let node_id = loghub.node_id.clone();
    let mut journ_cursor: Option<String> = None;
    // Docker cursor is tracked in NANOSECONDS (docker --timestamps emits
    // nanosecond precision) so a sub-millisecond burst can't collide on the
    // dedup boundary and stall a container's shipping.
    let mut docker_ns: HashMap<String, i64> = HashMap::new();
    let mut lxc_cursor: HashMap<String, String> = HashMap::new();
    let mut spool: VecDeque<LogEvent> = VecDeque::new();

    loop {
        let cfg = { loghub.config.read().unwrap().clone() };

        if !cfg.enabled {
            // Reset all cursors/spool so re-enabling re-baselines at the newest entry
            // instead of replaying whatever accumulated while we were off.
            journ_cursor = None;
            docker_ns.clear();
            lxc_cursor.clear();
            spool.clear();
            std::thread::sleep(Duration::from_secs(SHIP_INTERVAL_SECS));
            continue;
        }

        let redactor = Redactor::new(&cfg);
        let mut batch: Vec<LogEvent> = Vec::new();

        if cfg.ship_journald {
            batch.extend(collect_journald(&mut journ_cursor, &node_id, &cfg, &redactor));
        }
        if cfg.ship_docker {
            batch.extend(collect_docker(&mut docker_ns, &node_id, &cfg, &redactor));
        }
        if cfg.ship_lxc {
            batch.extend(collect_lxc(&mut lxc_cursor, &node_id, &cfg, &redactor));
        }

        deliver(batch, &mut spool, &loghub, &cluster, &secret);

        std::thread::sleep(Duration::from_secs(SHIP_INTERVAL_SECS));
    }
}

// ── Collection ────────────────────────────────────────────────────────────

fn denylisted(unit: &str, cfg: &LogHubConfig) -> bool {
    cfg.unit_denylist.iter().any(|d| !d.is_empty() && unit.contains(d.as_str()))
}

/// Run a journalctl invocation in JSON mode and return parsed entries plus the
/// new cursor. `program`/`pre_args` let the same code drive the host journal
/// (`journalctl …`) and a container's journal (`lxc-attach … -- journalctl …`).
/// On any failure the cursor resets to `None` (re-baseline at the newest entry) rather
/// than wedging on a stale cursor.
fn journalctl_json(
    program: &str,
    pre_args: &[String],
    cursor: &Option<String>,
) -> (Vec<serde_json::Value>, Option<String>) {
    let mut args: Vec<String> = pre_args.to_vec();
    args.push("-o".into());
    args.push("json".into());
    args.push("--no-pager".into());
    // Baseline: with no cursor, read only the newest entry to learn its cursor.
    // `--since now` cannot baseline — "now" is evaluated per call, so it matches
    // nothing even on a busy journal, no cursor is ever recorded, and every
    // later round repeats the same empty query, so nothing ever ships.
    match cursor {
        Some(c) => args.push(format!("--after-cursor={c}")),
        None => {
            args.push("-n".into());
            args.push("1".into());
        }
    }

    let output = Command::new(program).args(&args).stderr(Stdio::null()).output();
    let o = match output {
        Ok(o) => o,
        Err(_) => return (Vec::new(), None), // tool missing / cannot spawn → re-baseline
    };
    if !o.status.success() {
        // Bad/rotated cursor or transient failure — reset to re-baseline.
        return (Vec::new(), None);
    }

    let text = String::from_utf8_lossy(&o.stdout);
    let mut vals = Vec::new();
    let mut newcur = cursor.clone();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(c) = v.get("__CURSOR").and_then(|x| x.as_str()) {
                newcur = Some(c.to_string());
            }
            vals.push(v);
            if vals.len() >= MAX_LINES_PER_ROUND {
                break;
            }
        }
    }
    if cursor.is_none() {
        // A baseline round only establishes the cursor. The entry it read was
        // written before shipping started, so it is not forwarded — the same
        // "start from now, never replay a backlog" rule the module states.
        return (Vec::new(), newcur);
    }
    (vals, newcur)
}

fn extract_message(v: &serde_json::Value) -> Option<String> {
    match v.get("MESSAGE") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        // journald emits non-UTF8 messages as a byte array.
        Some(serde_json::Value::Array(a)) => {
            let bytes: Vec<u8> = a.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

fn extract_ts(v: &serde_json::Value) -> i64 {
    v.get("__REALTIME_TIMESTAMP")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .map(|micros| micros / 1000)
        .unwrap_or_else(now_millis)
}

fn extract_unit(v: &serde_json::Value) -> String {
    for k in ["_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_COMM"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str())
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    "unknown".to_string()
}

/// Convert a journald JSON entry to a `LogEvent`, applying denylist + redaction.
fn value_to_event(
    v: &serde_json::Value,
    node: &str,
    source: LogSource,
    unit_override: Option<&str>,
    cfg: &LogHubConfig,
    redactor: &Redactor,
) -> Option<LogEvent> {
    let msg_raw = extract_message(v)?;
    let unit = match unit_override {
        Some(u) => u.to_string(),
        None => extract_unit(v),
    };
    if denylisted(&unit, cfg) {
        return None;
    }
    let level = v
        .get("PRIORITY")
        .and_then(|x| x.as_str())
        .map(LogLevel::from_priority)
        .unwrap_or(LogLevel::Unknown);
    Some(LogEvent {
        ts: extract_ts(v),
        node: node.to_string(),
        source,
        unit,
        level,
        msg: cap_msg(redactor.apply(&msg_raw)),
        fields: BTreeMap::new(),
    })
}

fn collect_journald(
    cursor: &mut Option<String>,
    node_id: &str,
    cfg: &LogHubConfig,
    redactor: &Redactor,
) -> Vec<LogEvent> {
    let (vals, newcur) = journalctl_json("journalctl", &[], cursor);
    *cursor = newcur;
    vals.iter()
        .filter_map(|v| value_to_event(v, node_id, LogSource::Journald, None, cfg, redactor))
        .collect()
}

fn collect_lxc(
    cursors: &mut HashMap<String, String>,
    node_id: &str,
    cfg: &LogHubConfig,
    redactor: &Redactor,
) -> Vec<LogEvent> {
    let mut out = Vec::new();
    for c in crate::containers::lxc_list_all() {
        if !c.state.eq_ignore_ascii_case("running") || c.name.is_empty() {
            continue;
        }
        if denylisted(&c.name, cfg) {
            continue;
        }
        let base = crate::containers::lxc_base_dir(&c.name);
        let mut pre: Vec<String> = Vec::new();
        if base != crate::containers::LXC_DEFAULT_PATH {
            pre.push("-P".into());
            pre.push(base);
        }
        pre.push("-n".into());
        pre.push(c.name.clone());
        pre.push("--".into());
        pre.push("journalctl".into());

        let cur = cursors.get(&c.name).cloned();
        let (vals, newcur) = journalctl_json("lxc-attach", &pre, &cur);
        match newcur {
            Some(nc) => {
                cursors.insert(c.name.clone(), nc);
            }
            None => {
                cursors.remove(&c.name);
            }
        }
        for v in &vals {
            // Tag the line with the container name as its unit so operators can
            // filter "which container"; the in-container service stays in msg.
            if let Some(ev) = value_to_event(v, node_id, LogSource::Lxc, Some(&c.name), cfg, redactor) {
                out.push(ev);
            }
        }
    }
    out
}

fn collect_docker(
    last_ns: &mut HashMap<String, i64>,
    node_id: &str,
    cfg: &LogHubConfig,
    redactor: &Redactor,
) -> Vec<LogEvent> {
    let mut out = Vec::new();
    let now_ns = now_millis().saturating_mul(1_000_000);
    for c in crate::containers::docker_list_running() {
        if c.name.is_empty() {
            continue;
        }
        if denylisted(&c.name, cfg) {
            continue;
        }
        // First sight of a container: baseline at "now" so we don't ship its
        // entire backlog. Thereafter, only lines strictly newer than the last
        // shipped timestamp — nanosecond precision so a sub-millisecond burst
        // on the boundary can't stall the container forever.
        let since_ns = *last_ns.get(&c.name).unwrap_or(&now_ns);
        let since_arg = rfc3339_from_ns(since_ns);
        let output = Command::new("docker")
            .args(["logs", "--since", &since_arg, "--timestamps", &c.id])
            .output();
        let o = match output {
            Ok(o) => o,
            Err(_) => continue,
        };
        let mut max_ns = since_ns;
        for stream in [&o.stdout, &o.stderr] {
            let text = String::from_utf8_lossy(stream);
            for line in text.lines() {
                // "<rfc3339-nano> <message...>"
                let (ts_str, msg) = match line.split_once(' ') {
                    Some(p) => p,
                    None => continue,
                };
                let ns = match parse_rfc3339_ns(ts_str) {
                    Some(t) => t,
                    None => continue,
                };
                if ns <= since_ns {
                    continue; // dedup across the inclusive --since boundary
                }
                max_ns = max_ns.max(ns);
                let msg = cap_msg(redactor.apply(msg));
                out.push(LogEvent {
                    ts: ns / 1_000_000,
                    node: node_id.to_string(),
                    source: LogSource::Docker,
                    unit: c.name.clone(),
                    level: LogLevel::sniff(&msg),
                    msg,
                    fields: BTreeMap::new(),
                });
            }
        }
        last_ns.insert(c.name.clone(), max_ns);
    }
    out
}

fn rfc3339_from_ns(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339()
}

fn parse_rfc3339_ns(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .and_then(|dt| dt.timestamp_nanos_opt())
}

// ── Delivery ──────────────────────────────────────────────────────────────

enum HubTarget {
    SelfLocal,
    Remote { address: String, port: u16 },
    None,
}

fn resolve_hub(loghub: &Arc<LogHubState>, cluster: &Arc<ClusterState>) -> HubTarget {
    let hub_id = {
        let cfg = loghub.config.read().unwrap();
        match &cfg.hub_node_id {
            Some(h) => h.clone(),
            None => return HubTarget::None,
        }
    };
    if hub_id == loghub.node_id {
        return HubTarget::SelfLocal;
    }
    // Cluster.nodes is keyed by a locally-assigned `node-{uuid}`, so the same
    // hub has a different key on every peer; `hub_node_id` is the hub's own
    // self_id. `get_node` matches the local key first, then falls back to the
    // peer's self_id — a key-only match never found the hub from any other node.
    match cluster.get_node(&hub_id) {
        Some(n) if n.is_self => HubTarget::SelfLocal,
        Some(n) => HubTarget::Remote { address: n.address, port: n.port },
        None => HubTarget::None,
    }
}

fn requeue(spool: &mut VecDeque<LogEvent>, events: Vec<LogEvent>, loghub: &Arc<LogHubState>) {
    for ev in events {
        spool.push_back(ev);
    }
    while spool.len() > SPOOL_MAX {
        spool.pop_front();
        loghub.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn deliver(
    mut batch: Vec<LogEvent>,
    spool: &mut VecDeque<LogEvent>,
    loghub: &Arc<LogHubState>,
    cluster: &Arc<ClusterState>,
    secret: &str,
) {
    if batch.is_empty() && spool.is_empty() {
        return;
    }
    // Spooled (older) events first, then this round's batch.
    let mut to_send: Vec<LogEvent> = Vec::with_capacity(spool.len() + batch.len());
    to_send.extend(spool.drain(..));
    to_send.append(&mut batch);

    match resolve_hub(loghub, cluster) {
        HubTarget::SelfLocal => {
            if loghub.ingest_blocked.load(Ordering::SeqCst) {
                requeue(spool, to_send, loghub);
                return;
            }
            let root = loghub.store_root();
            match super::store::append_events(&root, &to_send) {
                Ok(n) => {
                    loghub.ingested.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(_) => requeue(spool, to_send, loghub),
            }
        }
        HubTarget::Remote { address, port } => {
            // Send in bounded chunks so a large spool flush never exceeds the
            // hub's ingest size limit (and can't wedge a too-big request). On
            // the first failed chunk, requeue everything from there onward.
            let mut idx = 0;
            while idx < to_send.len() {
                let end = (idx + SEND_CHUNK).min(to_send.len());
                if post_to_hub(&address, port, secret, &to_send[idx..end]) {
                    idx = end;
                } else {
                    let remainder = to_send.split_off(idx);
                    requeue(spool, remainder, loghub);
                    return;
                }
            }
        }
        HubTarget::None => requeue(spool, to_send, loghub),
    }
}

/// POST a batch to the hub's ingest endpoint. Inter-node trust is the shared
/// cluster secret (header), not TLS cert validation — WolfStack nodes present
/// self-signed certs, so we accept them here exactly as every other inter-node
/// call does. Returns true only on a 2xx.
fn post_to_hub(address: &str, port: u16, secret: &str, events: &[LogEvent]) -> bool {
    let client = match reqwest::blocking::Client::builder()
        // Bound the CONNECT, not just the request: a SYN to an
        // unroutable host holds a descriptor for the kernel's full
        // retry window (~130s). Enforced by tests/resource_safety.rs
        // after the 2026-08-05 fd-exhaustion outage.
        .connect_timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    for url in crate::api::build_node_urls(address, port, "/api/logs/ingest") {
        match client.post(&url).peer_auth(secret).json(events).send() {
            Ok(r) if r.status().is_success() => return true,
            // 507 = hub disk full; it wants us to keep spooling. Stop trying
            // other URLs for this round.
            Ok(r) if r.status().as_u16() == 507 => return false,
            _ => continue,
        }
    }
    false
}
