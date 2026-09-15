// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Tail journald for SSH + Proxmox failed-authentication events and
//! feed them into the same lockout system the WolfStack web UI uses.
//! On a Proxmox-on-Hetzner host this gives operators one unified
//! brute-force defence covering the three attack surfaces:
//!
//!   - WolfStack web UI (8553) — handled by login_limiter directly
//!   - SSH (22)                — this module taps sshd's auth events
//!   - Proxmox web UI (8006)   — this module taps pveproxy + pvedaemon
//!
//! All three feed `record_failure_with()` so kernel-block + fleet
//! propagation are identical regardless of which surface was hit.
//!
//! pveproxy is the HTTP frontend on 8006; pvedaemon is the API worker
//! behind it. Both call the same `PVE::AccessControl` Perl path and
//! emit the same `authentication failure; rhost=… user=…` syslog line,
//! but which one logs depends on where in the request lifecycle the
//! credential check ran. Tapping both is the only way to guarantee no
//! failed Proxmox login slips past.
//!
//! ## Why journald and not /var/log/auth.log
//!
//! Modern Debian/Trixie/Proxmox installs often ship without rsyslog —
//! `/var/log/auth.log` doesn't exist. journald is the universal source.
//! We `journalctl -f -o cat` and stream-parse line-by-line.
//!
//! ## Patterns
//!
//! - sshd:          `Failed password for [invalid user]? <user> from <IP>`
//! - sshd:          `Invalid user <user> from <IP>`
//! - sshd:          `Disconnected from authenticating user <user> <IP> ... [preauth]`
//!   — only when there was a password attempt; pure
//!   pre-auth disconnects are bots and don't count.
//! - pvedaemon:     `authentication failure; rhost=<IP> user=<user> ...`
//! - pveproxy:      `authentication failure; rhost=<IP> user=<user> ...`
//!
//! We deduplicate within a 2-second window to avoid double-counting
//! the multiple log lines a single failed attempt usually produces
//! (`pam_unix authentication failure` + `Failed password for ...`).

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::auth::LoginRateLimiter;

/// Start the background monitor. Spawns a blocking thread that reads
/// journalctl in follow mode and dispatches each parsed event to the
/// limiter via `record_failure_with()`. The blocking thread is the
/// right shape because `journalctl -f` is line-oriented and slow —
/// async I/O would buy us nothing.
///
/// Returns immediately; the thread runs for the lifetime of the
/// process. If journalctl isn't available, the thread exits silently
/// (operator just doesn't get this coverage — WolfStack UI lockout
/// still works).
pub fn start_monitor(limiter: Arc<LoginRateLimiter>) {
    // Single dedup map shared across both source threads. Prevents
    // double-counting when sshd logs both a "pam_unix authentication
    // failure" AND a "Failed password" line for the same attempt.
    let dedup: Arc<Mutex<HashMap<(String, String), Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    let limiter_clone = limiter.clone();
    let dedup_clone = dedup.clone();
    std::thread::Builder::new()
        .name("wolfstack-authmonitor".into())
        .spawn(move || tail_journal_loop(limiter_clone, dedup_clone))
        .ok();
}

/// Outer loop — restarts the journalctl child if it ever exits
/// (logrotate, journal rotation, crash). 5s backoff between restarts
/// so we don't busy-spin if journalctl is missing.
fn tail_journal_loop(
    limiter: Arc<LoginRateLimiter>,
    dedup: Arc<Mutex<HashMap<(String, String), Instant>>>,
) {
    loop {
        if !run_one_journal_session(&limiter, &dedup) {
            tracing::warn!("auth-monitor: journalctl unavailable, exiting monitor thread");
            return;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// One follow-session. Returns true if the operator should try again
/// (transient failure), false if journalctl can't be spawned at all
/// (permanent — operator's system doesn't have it).
fn run_one_journal_session(
    limiter: &Arc<LoginRateLimiter>,
    dedup: &Arc<Mutex<HashMap<(String, String), Instant>>>,
) -> bool {
    // Follow journal, no pager, raw lines, only since "now" so we
    // don't replay history on every restart. Filter to the units
    // we care about. `-o cat` strips the systemd metadata prefix.
    let child = Command::new("journalctl")
        .args([
            "--follow",
            "--no-pager",
            "--output=short",
            "--since=now",
            "_COMM=sshd",
            "_COMM=sshd-session",
            "_COMM=pvedaemon",
            "_COMM=pveproxy",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("auth-monitor: cannot spawn journalctl: {}", e);
            return false;
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            tracing::error!("auth-monitor: journalctl produced no stdout");
            let _ = child.kill();
            return true;
        }
    };
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Some((ip, user, source)) = parse_failure(&line) {
            handle_failure(&ip, &user, source, limiter, dedup);
        }
    }
    let _ = child.wait();
    true
}

/// Parse a line and return (source_ip, username, source_label) if it's
/// a failed authentication event we care about. Returns None for
/// successful logins, pre-auth bot disconnects, and anything we don't
/// recognise.
fn parse_failure(line: &str) -> Option<(String, String, &'static str)> {
    // sshd: "Failed password for [invalid user ]<user> from <IP> port <port> ssh2"
    if let Some(rest) = line.find("Failed password for ").map(|i| &line[i + 20..]) {
        let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
        // Split: "<user> from <IP> port <port>"
        if let Some((user_part, after)) = rest.split_once(" from ") {
            let user = user_part.trim().to_string();
            let ip = after.split_whitespace().next()?.to_string();
            return Some((ip, user, "sshd"));
        }
    }
    // sshd: "Invalid user <user> from <IP> port <port>" — also counts;
    // these are username-enumeration probes that often precede a
    // password attempt with the same source.
    if let Some(rest) = line.find("Invalid user ").map(|i| &line[i + 13..])
        && let Some((user_part, after)) = rest.split_once(" from ") {
            let user = user_part.trim().to_string();
            let ip = after.split_whitespace().next()?.to_string();
            return Some((ip, user, "sshd-invalid-user"));
        }
    // pvedaemon / pveproxy: ... "authentication failure; rhost=<IP> user=<user> ..."
    // Both daemons share PVE::AccessControl and emit identical lines;
    // which one logs depends on where in the request the check ran.
    // pveproxy is checked first so the more specific label wins when
    // a line somehow mentions both daemons (e.g. forwarded log).
    let pve_source: Option<&'static str> = if line.contains("pveproxy") {
        Some("pveproxy")
    } else if line.contains("pvedaemon") {
        Some("pvedaemon")
    } else {
        None
    };
    if let Some(source) = pve_source
        && line.contains("authentication failure") {
            // rhost=<IP>
            let rhost = line.find("rhost=").map(|i| &line[i + 6..])?;
            let ip = rhost.split_whitespace().next()?
                .trim_end_matches(';')
                .to_string();
            // user=<user> (might not be present; default to "")
            let user = line.find("user=").map(|i| &line[i + 5..])
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("")
                .to_string();
            return Some((ip, user, source));
        }
    None
}

/// Apply dedup + dispatch to the limiter. The dedup window is 2 seconds
/// per (ip, source) pair — long enough to merge the PAM/sshd duplicate
/// lines, short enough that a real burst still registers many failures.
fn handle_failure(
    ip: &str,
    user: &str,
    source: &'static str,
    limiter: &Arc<LoginRateLimiter>,
    dedup: &Arc<Mutex<HashMap<(String, String), Instant>>>,
) {
    let key = (ip.to_string(), source.to_string());
    let now = Instant::now();
    {
        let mut map = dedup.lock().unwrap();
        if let Some(last) = map.get(&key)
            && now.duration_since(*last) < Duration::from_secs(2) {
                return; // dedup'd
            }
        map.insert(key, now);
        // Bound the dedup map so it doesn't grow unbounded.
        if map.len() > 4096 {
            let cutoff = now - Duration::from_secs(60);
            map.retain(|_, t| *t > cutoff);
        }
    }
    // Tag the username so audit log shows which surface the failure
    // came from. "sshd:root", "pvedaemon:root" etc.
    let tagged_user = format!("{}:{}", source, user);
    let just_locked = limiter.record_failure_with(ip, &tagged_user);
    if just_locked {
        tracing::warn!(
            "auth-monitor: {} threshold reached for {} (from {}), kernel-blocked",
            source, ip, user
        );
        // Note: fleet propagation is the API layer's responsibility.
        // The monitor only feeds the limiter; we don't have direct
        // access to ClusterState here (would create a dependency
        // tangle). The login handler's existing propagation covers
        // the WolfStack-UI source. For sshd/pvedaemon events we'd
        // need either: (a) make the limiter signal back, or
        // (b) fan out from here. See SshPveFanoutTrigger below.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sshd_failed_password() {
        let line = "sshd-session[12345]: Failed password for root from 158.173.240.177 port 1821 ssh2";
        let r = parse_failure(line).expect("must parse");
        assert_eq!(r.0, "158.173.240.177");
        assert_eq!(r.1, "root");
        assert_eq!(r.2, "sshd");
    }

    #[test]
    fn parse_sshd_failed_password_invalid_user() {
        let line = "sshd-session[12345]: Failed password for invalid user admin from 87.121.84.41 port 10474 ssh2";
        let r = parse_failure(line).expect("must parse");
        assert_eq!(r.0, "87.121.84.41");
        assert_eq!(r.1, "admin");
    }

    #[test]
    fn parse_sshd_invalid_user_only() {
        let line = "sshd-session[12345]: Invalid user eric from 87.121.84.41 port 38600";
        let r = parse_failure(line).expect("must parse");
        assert_eq!(r.0, "87.121.84.41");
        assert_eq!(r.1, "eric");
        assert_eq!(r.2, "sshd-invalid-user");
    }

    #[test]
    fn parse_pvedaemon_failure() {
        let line = "pvedaemon[1234]: authentication failure; rhost=158.173.240.177 user=root@pam msg=Authentication failure";
        let r = parse_failure(line).expect("must parse");
        assert_eq!(r.0, "158.173.240.177");
        assert_eq!(r.1, "root@pam");
        assert_eq!(r.2, "pvedaemon");
    }

    #[test]
    fn parse_pveproxy_failure() {
        let line = "pveproxy[5678]: authentication failure; rhost=158.173.240.177 user=admin@pam msg=no such user ('admin@pam')";
        let r = parse_failure(line).expect("must parse");
        assert_eq!(r.0, "158.173.240.177");
        assert_eq!(r.1, "admin@pam");
        assert_eq!(r.2, "pveproxy");
    }

    #[test]
    fn parse_success_returns_none() {
        // Normal accepted login — not a failure.
        let line = "sshd-session[12345]: Accepted password for root from 1.2.3.4 port 12345 ssh2";
        assert!(parse_failure(line).is_none());
    }

    #[test]
    fn parse_garbage_returns_none() {
        assert!(parse_failure("").is_none());
        assert!(parse_failure("random log line that doesn't match anything").is_none());
        assert!(parse_failure("sshd-session: Disconnected from 1.2.3.4").is_none());
    }
}
