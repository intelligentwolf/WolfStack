// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Node outage history — WHEN a peer went offline, as seen by this node.
//!
//! klas 2026-11-05: "Can you put in banner when a node goes offline so you
//! can see exactly when it went offline? One of my servers crashed last night
//! 4.48 am." Before this, the only record of a peer dropping off was the
//! node-offline alert, and that is only evaluated on the primary alerter and
//! only when email alerting is configured. The UI could say "Offline" but
//! never "offline since 04:48".
//!
//! What this records, per peer, from THIS node's point of view:
//! - `offline_since` — the last time a poll of the peer actually succeeded
//!   (fed by [`note_contact`] from the poll's success path). That is the
//!   closest thing to "when it died" an observer can know. It is NOT the
//!   peer's `last_seen`: the poller bumps `last_seen` on the first failed
//!   poll to ride out a single blip, so `last_seen` is one poll late.
//! - `detected_at` — when this node concluded the peer was offline.
//! - `restored_at` — when it answered again, and `rebooted_at` (from the
//!   peer's own reported uptime) when the peer had restarted in between,
//!   which is what tells a crash/reboot apart from a network outage.
//!
//! Persistence: `<config_dir>/node-outages.json`, written immediately on
//! every open/close and at most once a minute for the last-contact map (so
//! an observer restart during a peer's outage still knows when it last heard
//! from it). History is bounded per node and in total.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

/// Closed outages kept per node — enough for a few weeks of a flaky box
/// without the file growing without bound.
const MAX_HISTORY_PER_NODE: usize = 50;
/// Hard ceiling across all nodes (large clusters, long-gone node ids).
const MAX_HISTORY_TOTAL: usize = 1000;
/// Minimum seconds between writes caused only by last-contact updates.
const CONTACT_PERSIST_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutageRecord {
    pub node_id: String,
    #[serde(default)]
    pub hostname: String,
    /// Unix secs of the last successful poll before the outage. `None` when
    /// this node never heard from the peer (e.g. the peer was already down
    /// when this node's WolfStack started and no earlier contact was saved).
    #[serde(default)]
    pub offline_since: Option<u64>,
    /// Unix secs when this node decided the peer was offline.
    pub detected_at: u64,
    /// Unix secs when the peer answered again; `None` while still offline.
    #[serde(default)]
    pub restored_at: Option<u64>,
    /// Unix secs the peer booted, when its reported uptime shows it
    /// restarted during the outage. `None` = no reboot seen (network/service
    /// outage) or not known.
    #[serde(default)]
    pub rebooted_at: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    open: HashMap<String, OutageRecord>,
    #[serde(default)]
    history: Vec<OutageRecord>,
    #[serde(default)]
    last_contact: HashMap<String, u64>,
}

struct Tracker {
    store: Store,
    loaded: bool,
    /// Process-local "first observed" instant, so peers whose state is not
    /// yet settled after startup are not recorded as outages.
    started: Option<Instant>,
    last_contact_persist: u64,
    contact_dirty: bool,
    /// Monotonic generation of the serialized snapshot, so a slow blocking
    /// write never overwrites a newer one.
    generation: u64,
}

static TRACKER: LazyLock<Mutex<Tracker>> = LazyLock::new(|| Mutex::new(Tracker {
    store: Store::default(),
    loaded: false,
    started: None,
    last_contact_persist: 0,
    contact_dirty: false,
    generation: 0,
}));

/// Last generation actually written to disk.
static WRITTEN_GENERATION: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

fn store_file() -> String {
    format!("{}/node-outages.json", crate::paths::get().config_dir)
}

fn ensure_loaded(t: &mut Tracker) {
    if t.loaded { return; }
    t.loaded = true;
    if let Ok(data) = std::fs::read_to_string(store_file())
        && let Ok(store) = serde_json::from_str::<Store>(&data) {
            t.store = store;
        }
}

/// One peer's state for this poll cycle, as computed by the poller.
pub struct PeerObservation<'a> {
    pub node_id: &'a str,
    pub hostname: &'a str,
    pub online: bool,
    /// The peer's reported uptime from its latest successful report.
    pub uptime_secs: Option<u64>,
    /// Seconds after this node starts observing before an "offline" reading
    /// of this peer can be trusted: its online window plus one poll interval.
    /// Before that, the stale `last_seen` loaded from nodes.json makes every
    /// peer read offline until its first poll lands.
    pub settle_secs: u64,
}

/// Record a successful poll of `node_id` at `now`. Called from the poll
/// loop's success path.
pub fn note_contact(node_id: &str, now: u64) {
    let mut t = TRACKER.lock().unwrap_or_else(|e| e.into_inner());
    ensure_loaded(&mut t);
    t.store.last_contact.insert(node_id.to_string(), now);
    t.contact_dirty = true;
}

/// Pure transition step, separated from I/O for testing. Returns true when
/// an outage was opened or closed (i.e. the store must be written now).
fn apply_observations(store: &mut Store, observed: &[PeerObservation<'_>], now: u64, uptime_secs: u64) -> bool {
    let mut changed = false;
    for o in observed {
        let open = store.open.contains_key(o.node_id);
        if !o.online && !open && uptime_secs >= o.settle_secs {
            store.open.insert(o.node_id.to_string(), OutageRecord {
                node_id: o.node_id.to_string(),
                hostname: o.hostname.to_string(),
                offline_since: store.last_contact.get(o.node_id).copied(),
                detected_at: now,
                restored_at: None,
                rebooted_at: None,
            });
            changed = true;
        } else if o.online && open
            && let Some(mut rec) = store.open.remove(o.node_id) {
                rec.restored_at = Some(now);
                if !o.hostname.is_empty() { rec.hostname = o.hostname.to_string(); }
                // A boot time after the last contact means the peer
                // restarted during the outage (crash, power loss, reboot).
                if let Some(up) = o.uptime_secs {
                    let booted = now.saturating_sub(up);
                    let floor = rec.offline_since.unwrap_or(rec.detected_at);
                    if booted >= floor { rec.rebooted_at = Some(booted); }
                }
                store.history.push(rec);
                changed = true;
            }
    }
    // Drop open outages and contacts for nodes no longer in the cluster, so
    // a removed node never keeps a banner. History is kept (bounded below).
    let present: std::collections::HashSet<&str> = observed.iter().map(|o| o.node_id).collect();
    let before = store.open.len();
    store.open.retain(|id, _| present.contains(id.as_str()));
    if store.open.len() != before { changed = true; }
    store.last_contact.retain(|id, _| present.contains(id.as_str()));
    if changed { trim_history(&mut store.history); }
    changed
}

fn trim_history(history: &mut Vec<OutageRecord>) {
    // Newest last; keep the newest MAX_HISTORY_PER_NODE per node.
    let mut per_node: HashMap<String, usize> = HashMap::new();
    let mut keep = vec![false; history.len()];
    for (i, rec) in history.iter().enumerate().rev() {
        let c = per_node.entry(rec.node_id.clone()).or_insert(0);
        if *c < MAX_HISTORY_PER_NODE { keep[i] = true; *c += 1; }
    }
    let mut i = 0;
    history.retain(|_| { let k = keep[i]; i += 1; k });
    if history.len() > MAX_HISTORY_TOTAL {
        let excess = history.len() - MAX_HISTORY_TOTAL;
        history.drain(0..excess);
    }
}

/// Feed this cycle's peer states (every non-self WolfStack peer the cluster
/// knows). Opens/closes outages and persists when needed. The disk write
/// runs on the blocking pool.
pub fn observe(observed: &[PeerObservation<'_>], now: u64) {
    let snapshot = {
        let mut t = TRACKER.lock().unwrap_or_else(|e| e.into_inner());
        ensure_loaded(&mut t);
        let started = *t.started.get_or_insert_with(Instant::now);
        let uptime = started.elapsed().as_secs();
        let changed = apply_observations(&mut t.store, observed, now, uptime);
        let contact_due = t.contact_dirty
            && now.saturating_sub(t.last_contact_persist) >= CONTACT_PERSIST_INTERVAL_SECS;
        if !(changed || contact_due) { return; }
        t.contact_dirty = false;
        t.last_contact_persist = now;
        t.generation += 1;
        match serde_json::to_string(&t.store) {
            Ok(json) => (t.generation, json),
            Err(e) => {
                tracing::warn!("node-outages: serialize failed: {}", e);
                return;
            }
        }
    };
    let (generation, json) = snapshot;
    tokio::task::spawn_blocking(move || {
        let mut written = WRITTEN_GENERATION.lock().unwrap_or_else(|e| e.into_inner());
        if *written >= generation { return; }
        match crate::paths::write_secure(&store_file(), json) {
            Ok(()) => *written = generation,
            Err(e) => tracing::warn!("node-outages: write {} failed: {}", store_file(), e),
        }
    });
}

/// Current open outage per node id (for the /api/nodes banner data).
pub fn open_outages() -> HashMap<String, OutageRecord> {
    let mut t = TRACKER.lock().unwrap_or_else(|e| e.into_inner());
    ensure_loaded(&mut t);
    t.store.open.clone()
}

/// Most recent closed outage per node id.
pub fn last_closed_outages() -> HashMap<String, OutageRecord> {
    let mut t = TRACKER.lock().unwrap_or_else(|e| e.into_inner());
    ensure_loaded(&mut t);
    let mut out: HashMap<String, OutageRecord> = HashMap::new();
    for rec in &t.store.history {
        out.insert(rec.node_id.clone(), rec.clone()); // later entries are newer
    }
    out
}

/// Every recorded outage for one node, newest first, open one included.
pub fn history_for(node_id: &str) -> Vec<OutageRecord> {
    let mut t = TRACKER.lock().unwrap_or_else(|e| e.into_inner());
    ensure_loaded(&mut t);
    let mut out: Vec<OutageRecord> = t.store.history.iter()
        .filter(|r| r.node_id == node_id).cloned().collect();
    out.reverse();
    if let Some(open) = t.store.open.get(node_id) { out.insert(0, open.clone()); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs<'a>(id: &'a str, online: bool, uptime: Option<u64>) -> PeerObservation<'a> {
        PeerObservation { node_id: id, hostname: "host", online, uptime_secs: uptime, settle_secs: 60 }
    }

    #[test]
    fn no_outage_before_settle_window() {
        let mut s = Store::default();
        // 10s after start every peer reads offline (stale last_seen) — ignore.
        assert!(!apply_observations(&mut s, &[obs("a", false, None)], 1000, 10));
        assert!(s.open.is_empty());
    }

    #[test]
    fn outage_uses_last_contact_and_detects_reboot() {
        let mut s = Store::default();
        s.last_contact.insert("a".into(), 5000);
        assert!(apply_observations(&mut s, &[obs("a", false, None)], 5100, 600));
        let open = s.open.get("a").unwrap();
        assert_eq!(open.offline_since, Some(5000));
        assert_eq!(open.detected_at, 5100);
        // Back at 9000 with 1000s uptime → booted at 8000, after last contact.
        assert!(apply_observations(&mut s, &[obs("a", true, Some(1000))], 9000, 4000));
        assert!(s.open.is_empty());
        let rec = &s.history[0];
        assert_eq!(rec.restored_at, Some(9000));
        assert_eq!(rec.rebooted_at, Some(8000));
    }

    #[test]
    fn network_outage_has_no_reboot() {
        let mut s = Store::default();
        s.last_contact.insert("a".into(), 5000);
        apply_observations(&mut s, &[obs("a", false, None)], 5100, 600);
        // Uptime 100000s → booted long before the outage: not a reboot.
        apply_observations(&mut s, &[obs("a", true, Some(100_000))], 9000, 4000);
        assert_eq!(s.history[0].rebooted_at, None);
    }

    #[test]
    fn removed_node_outage_is_dropped() {
        let mut s = Store::default();
        apply_observations(&mut s, &[obs("a", false, None)], 5100, 600);
        assert!(s.open.contains_key("a"));
        assert!(apply_observations(&mut s, &[], 5200, 700));
        assert!(s.open.is_empty());
    }

    #[test]
    fn history_is_bounded_per_node() {
        let mut h: Vec<OutageRecord> = (0..(MAX_HISTORY_PER_NODE as u64 + 10)).map(|i| OutageRecord {
            node_id: "a".into(), hostname: String::new(), offline_since: Some(i),
            detected_at: i, restored_at: Some(i + 1), rebooted_at: None,
        }).collect();
        trim_history(&mut h);
        assert_eq!(h.len(), MAX_HISTORY_PER_NODE);
        assert_eq!(h[0].detected_at, 10); // oldest 10 dropped
    }
}
