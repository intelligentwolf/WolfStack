// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Poll-based event source for the container/VM types that have no event stream.
//!
//! Docker pushes events (`source_docker`). Nothing else here does:
//!
//! | Backend | How state is read | Why polled |
//! |---|---|---|
//! | `lxc` | `containers::lxc_list_all_cached()` | LXC has no event stream |
//! | `libvirt` | `virsh list --all` | `virsh event` exists but needs a persistent connection per URI; polling covers local + is uniform |
//! | `pve` | `qm list` | Proxmox exposes no event feed to a local process |
//!
//! A poll cannot see *why* something stopped — there is no exit code — so a
//! disappearance is reported as [`EventKind::ObjectStopped`], never as a
//! failure. Claiming "failed" from a poll would be a guess, and an operator
//! paged for a clean shutdown stops trusting the channel.
//!
//! ## The seeding rule
//!
//! The first poll establishes a baseline and emits NOTHING. Without that, every
//! restart of the daemon would report every stopped container on the node as a
//! fresh event — hundreds of notifications on a busy host, every deploy.

use std::collections::HashMap;

use super::{EventKind, NotifyEvent};

/// Snapshot of one backend: object name -> state string (`running`, `stopped`…).
pub type StateMap = HashMap<String, String>;

fn is_running(state: &str) -> bool {
    let s = state.trim().to_ascii_lowercase();
    s == "running" || s == "up" || s.starts_with("up ")
}

/// Diff two snapshots into events.
///
/// Pure: no clock, no I/O. `now_ts` is supplied so the caller controls time and
/// this stays testable.
///
/// * running -> not running (or gone)  => `ObjectStopped`
/// * not running (or absent) -> running => `ObjectStarted`
///
/// An object that is absent from BOTH, or unchanged, produces nothing.
pub fn diff_states(
    prev: &StateMap,
    now: &StateMap,
    backend: &str,
    node: &str,
    now_ts: u64,
) -> Vec<NotifyEvent> {
    let mut out = Vec::new();

    let mk = |kind: EventKind, object: &str, msg: String| NotifyEvent {
        kind,
        node: node.to_string(),
        backend: backend.to_string(),
        object: object.to_string(),
        labels: HashMap::new(),
        exit_code: None,
        restart_count: None,
        timestamp: now_ts,
        message: msg,
    };

    // Went away or stopped.
    for (name, prev_state) in prev {
        if !is_running(prev_state) {
            continue;
        }
        match now.get(name) {
            Some(cur) if is_running(cur) => {}
            Some(cur) => out.push(mk(
                EventKind::ObjectStopped,
                name,
                format!("state changed from {} to {}", prev_state, cur),
            )),
            // Deleted while running — still worth reporting; the workload is
            // gone either way, and silence here hides a destructive action.
            None => out.push(mk(
                EventKind::ObjectStopped,
                name,
                "no longer present on this node".to_string(),
            )),
        }
    }

    // Came up.
    for (name, cur_state) in now {
        if !is_running(cur_state) {
            continue;
        }
        let was_running = prev.get(name).map(|s| is_running(s)).unwrap_or(false);
        if !was_running {
            out.push(mk(EventKind::ObjectStarted, name, String::new()));
        }
    }

    out.sort_by(|a, b| a.object.cmp(&b.object));
    out
}

/// Current LXC state on this node, via the shared cached listing so polling
/// adds no extra `lxc-ls` load beyond what the UI already causes.
pub fn snapshot_lxc() -> StateMap {
    crate::containers::lxc_list_all_cached()
        .into_iter()
        .map(|c| (c.name, c.state))
        .collect()
}

/// Current libvirt domain state. Empty when libvirt isn't installed.
pub fn snapshot_libvirt() -> StateMap {
    let out = match std::process::Command::new("virsh")
        .args(["list", "--all"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return StateMap::new(),
    };
    parse_virsh_list(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `virsh list --all`:
/// ```text
///  Id   Name       State
/// ----------------------------
///  1    web        running
///  -    archived   shut off
/// ```
pub fn parse_virsh_list(text: &str) -> StateMap {
    let mut map = StateMap::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("Id") || t.starts_with("---") {
            continue;
        }
        let mut parts = t.split_whitespace();
        let _id = match parts.next() { Some(v) => v, None => continue };
        let name = match parts.next() { Some(v) => v, None => continue };
        // State can be two words ("shut off"), so take the remainder.
        let state: String = parts.collect::<Vec<_>>().join(" ");
        if state.is_empty() { continue; }
        map.insert(name.to_string(), state);
    }
    map
}

/// Current Proxmox VM state. Empty when `qm` isn't installed.
pub fn snapshot_pve() -> StateMap {
    let out = match std::process::Command::new("qm").arg("list").output() {
        Ok(o) if o.status.success() => o,
        _ => return StateMap::new(),
    };
    parse_qm_list(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `qm list`:
/// ```text
///       VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
///        100 web                  running    2048       32.00        1234
/// ```
/// Keyed by NAME, not VMID, so a rule can say `web` rather than `100`.
pub fn parse_qm_list(text: &str) -> StateMap {
    let mut map = StateMap::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("VMID") {
            continue;
        }
        let parts: Vec<&str> = t.split_whitespace().collect();
        if parts.len() < 3 { continue; }
        map.insert(parts[1].to_string(), parts[2].to_string());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, &str)]) -> StateMap {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_running_container_that_stops_is_reported() {
        let ev = diff_states(&m(&[("web", "running")]), &m(&[("web", "stopped")]), "lxc", "n", 10);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::ObjectStopped);
        assert_eq!(ev[0].object, "web");
        assert_eq!(ev[0].backend, "lxc");
    }

    #[test]
    fn a_container_that_vanishes_while_running_is_reported() {
        // Deleted out from under us. Silence would hide a destructive action.
        let ev = diff_states(&m(&[("web", "running")]), &m(&[]), "lxc", "n", 10);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::ObjectStopped);
        assert!(ev[0].message.contains("no longer present"));
    }

    #[test]
    fn coming_back_up_is_a_recovery() {
        let ev = diff_states(&m(&[("web", "stopped")]), &m(&[("web", "running")]), "lxc", "n", 10);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::ObjectStarted);
        assert!(ev[0].kind.is_recovery());
    }

    #[test]
    fn no_change_produces_nothing() {
        assert!(diff_states(&m(&[("web", "running")]), &m(&[("web", "running")]), "lxc", "n", 10).is_empty());
        assert!(diff_states(&m(&[("web", "stopped")]), &m(&[("web", "stopped")]), "lxc", "n", 10).is_empty());
    }

    #[test]
    fn an_always_stopped_container_never_fires() {
        // A node with 200 stopped containers must not emit 200 events, ever.
        let prev = m(&[("a", "stopped"), ("b", "stopped")]);
        let now = m(&[("a", "stopped"), ("b", "stopped")]);
        assert!(diff_states(&prev, &now, "lxc", "n", 10).is_empty());
    }

    #[test]
    fn a_poll_never_claims_failure() {
        // A poll cannot see an exit code, so it must not guess "failed" —
        // paging someone for a clean shutdown loses their trust in the channel.
        let ev = diff_states(&m(&[("web", "running")]), &m(&[("web", "stopped")]), "lxc", "n", 10);
        assert_ne!(ev[0].kind, EventKind::ObjectFailed);
        assert!(ev[0].exit_code.is_none());
    }

    #[test]
    fn virsh_list_parses_including_two_word_states() {
        let text = " Id   Name       State\n\
                    ----------------------------\n\
                     1    web        running\n\
                     -    archived   shut off\n";
        let m = parse_virsh_list(text);
        assert_eq!(m.get("web").map(String::as_str), Some("running"));
        assert_eq!(m.get("archived").map(String::as_str), Some("shut off"));
        assert!(!is_running("shut off"));
        assert!(is_running("running"));
    }

    #[test]
    fn qm_list_parses_and_keys_by_name() {
        let text = "      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n\
                          100 web                  running    2048       32.00        1234\n\
                          101 db                   stopped    4096       64.00        0\n";
        let m = parse_qm_list(text);
        assert_eq!(m.get("web").map(String::as_str), Some("running"));
        assert_eq!(m.get("db").map(String::as_str), Some("stopped"));
        assert!(!m.contains_key("100"), "should key by name, not VMID");
    }

    #[test]
    fn absent_tooling_yields_an_empty_snapshot_not_a_panic() {
        // A host with no libvirt/qm must simply contribute nothing.
        assert!(parse_virsh_list("").is_empty());
        assert!(parse_qm_list("").is_empty());
        assert!(parse_qm_list("VMID NAME STATUS").is_empty());
    }
}
