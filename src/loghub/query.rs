// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Fleet Logs search: prune segments by time window (via the `.idx` sidecars
//! and date-directory names), stream-scan the survivors, filter, and return the
//! newest matches. Brute-force but bounded — correct and cheap to maintain.
//! When the volume of a single query outgrows this, the `.idx` sidecar is where
//! a real inverted index would later live (explicitly future work).

use std::io::BufRead;

use serde::{Deserialize, Serialize};

use super::store::{list_subdirs, open_segment_reader, read_idx, safe_component};
use super::{LogEvent, LogLevel, LogSource};

/// Hard ceiling on lines read per query, regardless of matches. Protects the
/// hub from an unbounded scan. Hitting it sets `truncated`.
const MAX_SCAN_LINES: usize = 300_000;
/// Hard ceiling on matched events held in memory before sort/truncate.
const MAX_MATCHES: usize = 50_000;

fn default_limit() -> usize {
    1000
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct SearchQuery {
    /// Inclusive window start (unix millis). Defaults to the dawn of time.
    pub from: Option<i64>,
    /// Inclusive window end (unix millis). Defaults to the heat death of it.
    pub to: Option<i64>,
    /// Restrict to a single node id.
    pub node: Option<String>,
    /// Restrict to a single source.
    pub source: Option<LogSource>,
    /// Substring match against the unit/container name.
    pub unit: Option<String>,
    /// Minimum severity — include events at this level **or more serious**.
    /// Omit to include everything (including unlabelled `Unknown` lines).
    pub level: Option<LogLevel>,
    /// Case-insensitive substring match against the message (and unit).
    pub q: Option<String>,
    /// Max events to return (newest first). Clamped to [1, 10000].
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Serialize)]
pub struct SearchResult {
    pub events: Vec<LogEvent>,
    /// Total lines read across all scanned segments.
    pub scanned: usize,
    /// True if a hard cap (scan lines or matches) was hit — results may not be
    /// the global newest set. The UI must surface this; we never silently cap.
    pub truncated: bool,
}

/// UTC `[start, end]` millisecond bounds for a `YYYY-MM-DD` date.
fn day_bounds(date: &str) -> Option<(i64, i64)> {
    let nd = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    let start = nd.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis();
    Some((start, start + 86_400_000 - 1))
}

const ALL_STEMS: [&str; 5] = ["journald", "docker", "lxc", "file", "other"];

/// Search the store under `root`. Blocking + CPU-bound (decompression, JSON
/// parse) — call inside `web::block` from async handlers.
pub fn search(root: &str, q: &SearchQuery) -> SearchResult {
    let limit = q.limit.clamp(1, 10_000);
    let from = q.from.unwrap_or(i64::MIN);
    let to = q.to.unwrap_or(i64::MAX);
    let q_lower = q.q.as_ref().map(|s| s.to_lowercase());

    let nodes = match &q.node {
        Some(n) => vec![safe_component(n)],
        None => list_subdirs(root),
    };

    let mut matched: Vec<LogEvent> = Vec::new();
    let mut scanned = 0usize;
    let mut truncated = false;

    'outer: for node in nodes {
        let node_dir = format!("{root}/{node}");
        let mut dates = list_subdirs(&node_dir);
        dates.reverse(); // newest day first

        for date in dates {
            // Whole-day window prune.
            if let Some((ds, de)) = day_bounds(&date)
                && (de < from || ds > to)
            {
                continue;
            }
            let date_dir = format!("{node_dir}/{date}");

            let stems: Vec<&str> = match q.source {
                Some(s) => vec![s.stem()],
                None => ALL_STEMS.to_vec(),
            };

            for stem in stems {
                // Prune cold segments by their index time window before opening.
                let cold = format!("{date_dir}/{stem}.jsonl.zst");
                if std::path::Path::new(&cold).exists()
                    && let Some(idx) = read_idx(&date_dir, stem)
                    && idx.lines > 0
                    && (idx.max_ts < from || idx.min_ts > to)
                {
                    continue;
                }

                // Stream the segment line-by-line — never loads the whole
                // (possibly multi-GB) segment into memory.
                let reader = match open_segment_reader(&date_dir, stem) {
                    Some(r) => r,
                    None => continue,
                };

                for line in reader.lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    if line.is_empty() {
                        continue;
                    }
                    scanned += 1;
                    if scanned > MAX_SCAN_LINES {
                        truncated = true;
                        break 'outer;
                    }
                    let ev: LogEvent = match serde_json::from_str(&line) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    if ev.ts < from || ev.ts > to {
                        continue;
                    }
                    // Severity floor: enum is ordered severe→least, so a more
                    // serious level has a *smaller* ordinal. Keep `ev <= floor`.
                    if let Some(floor) = q.level
                        && ev.level > floor
                    {
                        continue;
                    }
                    if let Some(unit) = &q.unit
                        && !ev.unit.contains(unit.as_str())
                    {
                        continue;
                    }
                    if let Some(ql) = &q_lower
                        && !ev.msg.to_lowercase().contains(ql)
                        && !ev.unit.to_lowercase().contains(ql)
                    {
                        continue;
                    }
                    matched.push(ev);
                    if matched.len() >= MAX_MATCHES {
                        truncated = true;
                        break 'outer;
                    }
                }
            }
        }
    }

    matched.sort_by_key(|event| std::cmp::Reverse(event.ts));
    if matched.len() > limit {
        matched.truncate(limit);
    }
    SearchResult { events: matched, scanned, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loghub::store::append_events;
    use crate::loghub::{date_str, now_millis};
    use std::collections::BTreeMap;

    fn ev(node: &str, ts: i64, unit: &str, level: LogLevel, msg: &str) -> LogEvent {
        LogEvent {
            ts,
            node: node.into(),
            source: LogSource::Journald,
            unit: unit.into(),
            level,
            msg: msg.into(),
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn search_filters_window_text_and_level() {
        let dir = std::env::temp_dir().join(format!("loghub-q-{}", std::process::id()));
        let root = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_dir_all(&root);

        let now = now_millis();
        let events = vec![
            ev("n1", now, "sshd.service", LogLevel::Error, "Failed password for root"),
            ev("n1", now - 1000, "nginx.service", LogLevel::Info, "GET / 200"),
            ev("n2", now - 2000, "app.service", LogLevel::Warning, "disk getting full"),
        ];
        append_events(&root, &events).unwrap();
        let _ = date_str(now); // ensure same-day pathing

        // Text match
        let r = search(&root, &SearchQuery { q: Some("password".into()), limit: 100, ..Default::default() });
        assert_eq!(r.events.len(), 1);
        assert!(r.events[0].msg.contains("Failed password"));

        // Severity floor = Warning → Error + Warning, not Info
        let r = search(&root, &SearchQuery { level: Some(LogLevel::Warning), limit: 100, ..Default::default() });
        assert_eq!(r.events.len(), 2);
        assert!(r.events.iter().all(|e| e.level <= LogLevel::Warning));

        // Node filter
        let r = search(&root, &SearchQuery { node: Some("n2".into()), limit: 100, ..Default::default() });
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.events[0].node, "n2");

        // Newest-first ordering
        let r = search(&root, &SearchQuery { limit: 100, ..Default::default() });
        assert_eq!(r.events.len(), 3);
        assert!(r.events[0].ts >= r.events[1].ts && r.events[1].ts >= r.events[2].ts);

        let _ = std::fs::remove_dir_all(&root);
    }
}
