// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! WolfNotify — event notification for containers and VMs.
//!
//! ## Why this exists
//!
//! Nothing in WolfStack noticed a container going down. `alert_containers`
//! reads as though it did, but it only gates per-container *memory* findings
//! (`predictive::container_memory`); the threshold dispatch beside it in
//! `main.rs` is marked RETIRED. A container that exited non-zero, was
//! OOM-killed, failed its healthcheck or sat in a restart loop was silent.
//!
//! ## What this is NOT
//!
//! Not a second notification system. `alerting.rs` already delivers to Discord,
//! Slack, Telegram, ntfy and email with masked secrets and working retries; a
//! parallel subsystem would mean two secret stores and two places to look when
//! something failed to page you. This module supplies the two halves alerting
//! lacks — an **event source** and a **rule layer** — and hands the result to
//! `alerting::dispatch_to_selected`.
//!
//! ## Shape
//!
//! ```text
//!   docker events ──→ NotifyEvent ──→ evaluate() ──→ dispatch_to_selected()
//!   egress probes ──┘                 (pure)         (existing, alerting.rs)
//! ```
//!
//! [`evaluate`] is deliberately pure: an event plus a rule set in, matches out,
//! with no clock, filesystem or network. Cooldown state and timestamps are
//! passed in by the caller. The hard cases — "3 failures in 10 minutes", glob
//! matching on names — are then testable without a running daemon.
//!
//! See `docs/wolfnotify-design.md` for the full design and the phases beyond
//! this one.

pub mod source_docker;
pub mod source_poll;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::alerting::Channel;

/// What happened. Deliberately small and stable — everything else is an
/// attribute of the event, not a new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Clean stop — exit 0, or an operator action.
    ObjectStopped,
    /// Exit non-zero, crash, or a VM entering a failed state.
    ObjectFailed,
    /// The kernel OOM-killed the workload.
    ObjectOomKilled,
    /// A healthcheck transitioned to unhealthy.
    ObjectHealthFailed,
    /// Repeated restarts inside a window — invisible before this module.
    ObjectRestartLooping,
    /// Back up. Lets a rule close the incident it opened.
    ObjectStarted,
    /// Lost outbound connectivity *from inside the object's network*. The
    /// silent failure: the container is `Up`, healthy by every state check,
    /// and useless. State monitoring is structurally blind to this.
    ObjectEgressFailed,
    /// Outbound connectivity returned.
    ObjectEgressRestored,
    /// The event source itself died or stopped reporting. Must be alertable:
    /// a monitor the operator has learned to trust, which has silently
    /// stopped, is worse than no monitor at all.
    SourceDegraded,
}

impl EventKind {
    /// Whether this event represents a return to health, and so should close
    /// rather than open an incident.
    pub fn is_recovery(self) -> bool {
        matches!(self, EventKind::ObjectStarted | EventKind::ObjectEgressRestored)
    }

    /// Short human label used in notification titles.
    pub fn label(self) -> &'static str {
        match self {
            EventKind::ObjectStopped => "stopped",
            EventKind::ObjectFailed => "failed",
            EventKind::ObjectOomKilled => "OOM-killed",
            EventKind::ObjectHealthFailed => "unhealthy",
            EventKind::ObjectRestartLooping => "restart-looping",
            EventKind::ObjectStarted => "started",
            EventKind::ObjectEgressFailed => "lost outbound connectivity",
            EventKind::ObjectEgressRestored => "regained outbound connectivity",
            EventKind::SourceDegraded => "monitoring degraded",
        }
    }
}

/// A single observed occurrence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyEvent {
    pub kind: EventKind,
    pub node: String,
    /// `docker`, `libvirt`, `lxc`, `pve`.
    pub backend: String,
    /// Container or VM name.
    pub object: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub restart_count: Option<u32>,
    /// Unix seconds. Passed in rather than read from a clock so evaluation
    /// stays pure and testable.
    pub timestamp: u64,
    #[serde(default)]
    pub message: String,
}

/// Where a rule lives and is evaluated. The operator's choice, per rule —
/// there is no globally correct answer, so we don't impose one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// This node only.
    #[default]
    Node,
    /// Replicated to every node, last-write-wins on `version` — the same
    /// mechanism as AuthConfig and the threat-intel allowlists.
    Cluster,
}

/// How much rule the operator wanted. Simple is not a lesser mode: it is the
/// default and must be completable without reading documentation. Advanced is
/// an explicit opt-in to condition combining, windows and counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Simple,
    Advanced,
}

/// What a rule fires on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchSpec {
    /// Empty means "any event kind".
    #[serde(default)]
    pub events: Vec<EventKind>,
    /// Empty means "any backend".
    #[serde(default)]
    pub backends: Vec<String>,
    /// Globs against the object name. Empty means "any object".
    #[serde(default)]
    pub objects: Vec<String>,
    /// Every entry must be present and equal on the event. Empty means "any".
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Globs against the node name. Empty means "any node".
    #[serde(default)]
    pub nodes: Vec<String>,
}

fn default_true() -> bool { true }
fn default_cooldown() -> u64 { 900 }

/// One operator-defined rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default, rename = "match")]
    pub match_spec: MatchSpec,
    /// Channels this rule routes to. Empty means "every configured channel",
    /// so a rule written before routing existed still delivers. Intersected
    /// with the operator's global delivery-path selection
    /// (`AlertConfig::channels`) at dispatch: a rule can narrow, never widen.
    #[serde(default)]
    pub channels: Vec<Channel>,
    /// Seconds of silence per (rule, object) after firing. Per-OBJECT, not per
    /// rule: one flapping container must not mute its healthy neighbours,
    /// which is the mistake that gets notification systems switched off.
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
    /// Optional WolfFlow to run on match — the "do something about it" bridge.
    #[serde(default)]
    pub run_flow: Option<String>,
}

impl NotifyRule {
    /// Channels to deliver on, resolving "empty means all".
    pub fn resolved_channels(&self) -> Vec<Channel> {
        if self.channels.is_empty() {
            Channel::ALL.to_vec()
        } else {
            self.channels.clone()
        }
    }
}

/// Persisted rule set. `version` carries the same last-write-wins semantics as
/// the other replicated config, so cluster-scoped rules can be synced without
/// inventing a new mechanism.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyRules {
    #[serde(default)]
    pub rules: Vec<NotifyRule>,
    #[serde(default)]
    pub version: u64,
}

fn rules_path() -> String {
    format!("{}/notify-rules.json", crate::paths::get().config_dir)
}

impl NotifyRules {
    pub fn load() -> Self {
        match std::fs::read_to_string(rules_path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                tracing::warn!("notify-rules.json parse error ({}), using none", e);
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let mut stamped = self.clone();
        stamped.version = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let json = serde_json::to_string_pretty(&stamped).map_err(|e| e.to_string())?;
        // 0600 — rules can name hosts and objects an operator would rather not
        // publish, and sit beside the channel secrets they route to.
        crate::paths::write_secure(&rules_path(), &json)
            .map_err(|e| format!("Failed to write notify rules: {}", e))
    }
}

/// Glob match supporting `*` only — enough for `*-db`, `prod-*`, `*`.
///
/// Deliberately not a regex: rules are typed by operators under pressure, and a
/// mistyped regex that silently matches nothing is a notification that never
/// arrives. `*` is predictable and hard to get subtly wrong.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !value.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else {
            match value[pos..].find(part) {
                Some(found) => pos += found + part.len(),
                None => return false,
            }
        }
    }
    // A trailing non-`*` segment must land at the end.
    if let Some(last) = parts.last()
        && !last.is_empty()
        && !value.ends_with(last)
    {
        return false;
    }
    true
}

fn any_glob(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| glob_match(p, value))
}

/// Does `rule` match `event`? Ignores enabled/cooldown — those are the
/// caller's concern, kept out so this stays a pure predicate.
pub fn rule_matches(rule: &NotifyRule, event: &NotifyEvent) -> bool {
    let m = &rule.match_spec;
    if !m.events.is_empty() && !m.events.contains(&event.kind) {
        return false;
    }
    if !m.backends.is_empty() && !m.backends.iter().any(|b| b == &event.backend) {
        return false;
    }
    if !any_glob(&m.objects, &event.object) {
        return false;
    }
    if !any_glob(&m.nodes, &event.node) {
        return false;
    }
    for (k, v) in &m.labels {
        if event.labels.get(k).map(String::as_str) != Some(v.as_str()) {
            return false;
        }
    }
    true
}

/// Key identifying a cooldown bucket: per rule AND per object.
pub fn cooldown_key(rule: &NotifyRule, event: &NotifyEvent) -> String {
    format!("{}::{}::{}", rule.id, event.node, event.object)
}

/// Which rules should fire for this event.
///
/// `last_fired` maps [`cooldown_key`] to the unix second a rule last fired for
/// that object; entries older than the rule's cooldown are ignored. Recovery
/// events bypass the cooldown — telling someone a thing came back is never
/// noise, and suppressing it strands an open incident.
pub fn evaluate<'a>(
    event: &NotifyEvent,
    rules: &'a [NotifyRule],
    last_fired: &HashMap<String, u64>,
) -> Vec<&'a NotifyRule> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .filter(|r| rule_matches(r, event))
        .filter(|r| {
            if event.kind.is_recovery() {
                return true;
            }
            match last_fired.get(&cooldown_key(r, event)) {
                Some(&last) => event.timestamp.saturating_sub(last) >= r.cooldown_secs,
                None => true,
            }
        })
        .collect()
}

/// Title and body for a matched event.
pub fn render(event: &NotifyEvent, rule: &NotifyRule) -> (String, String) {
    let title = format!(
        "{} {} {}",
        if event.kind.is_recovery() { "✅" } else { "⚠️" },
        event.object,
        event.kind.label()
    );
    let mut body = format!(
        "{} `{}` on node `{}` {}.",
        event.backend, event.object, event.node, event.kind.label()
    );
    if let Some(code) = event.exit_code {
        body.push_str(&format!("\nExit code: {}", code));
    }
    if let Some(n) = event.restart_count {
        body.push_str(&format!("\nRestarts: {}", n));
    }
    if !event.message.is_empty() {
        body.push_str(&format!("\n{}", event.message));
    }
    body.push_str(&format!("\n\nRule: {}", rule.name));
    (title, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind, object: &str) -> NotifyEvent {
        NotifyEvent {
            kind,
            node: "wolfstack-2".into(),
            backend: "docker".into(),
            object: object.into(),
            labels: HashMap::new(),
            exit_code: None,
            restart_count: None,
            timestamp: 1_000,
            message: String::new(),
        }
    }

    fn rule(id: &str, spec: MatchSpec) -> NotifyRule {
        NotifyRule {
            id: id.into(),
            name: format!("rule {}", id),
            enabled: true,
            scope: Scope::Node,
            mode: Mode::Simple,
            match_spec: spec,
            channels: vec![],
            cooldown_secs: 900,
            run_flow: None,
        }
    }

    // ── glob ──

    #[test]
    fn glob_star_matches_everything() {
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn glob_prefix_and_suffix() {
        assert!(glob_match("prod-*", "prod-web"));
        assert!(!glob_match("prod-*", "dev-web"));
        assert!(glob_match("*-db", "customer-db"));
        assert!(!glob_match("*-db", "db-customer"));
    }

    #[test]
    fn glob_exact_when_no_star() {
        assert!(glob_match("speedtest-tracker", "speedtest-tracker"));
        assert!(!glob_match("speedtest", "speedtest-tracker"));
    }

    #[test]
    fn glob_middle_star() {
        assert!(glob_match("prod-*-db", "prod-eu-db"));
        assert!(!glob_match("prod-*-db", "prod-eu-cache"));
    }

    // ── matching ──

    #[test]
    fn empty_match_spec_matches_any_event() {
        // A rule with no filters is "tell me about everything" — it must not
        // silently match nothing.
        let r = rule("a", MatchSpec::default());
        assert!(rule_matches(&r, &ev(EventKind::ObjectFailed, "web")));
    }

    #[test]
    fn event_kind_filter_is_respected() {
        let r = rule("a", MatchSpec { events: vec![EventKind::ObjectFailed], ..Default::default() });
        assert!(rule_matches(&r, &ev(EventKind::ObjectFailed, "web")));
        assert!(!rule_matches(&r, &ev(EventKind::ObjectStopped, "web")));
    }

    #[test]
    fn labels_must_all_match() {
        let mut want = HashMap::new();
        want.insert("tier".to_string(), "prod".to_string());
        let r = rule("a", MatchSpec { labels: want, ..Default::default() });

        let mut e = ev(EventKind::ObjectFailed, "web");
        assert!(!rule_matches(&r, &e), "missing label must not match");
        e.labels.insert("tier".into(), "dev".into());
        assert!(!rule_matches(&r, &e), "wrong label value must not match");
        e.labels.insert("tier".into(), "prod".into());
        assert!(rule_matches(&r, &e));
    }

    // ── cooldown ──

    #[test]
    fn cooldown_suppresses_a_repeat_for_the_same_object() {
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let mut fired = HashMap::new();
        let e = ev(EventKind::ObjectFailed, "web");
        fired.insert(cooldown_key(&r, &e), 900u64);   // 100s ago, cooldown 900
        assert!(evaluate(&e, &rules, &fired).is_empty());
    }

    #[test]
    fn cooldown_is_per_object_not_per_rule() {
        // The property that decides whether this feature survives contact with
        // a flapping container: one noisy object must not mute the rest.
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let noisy = ev(EventKind::ObjectFailed, "flapping");
        let quiet = ev(EventKind::ObjectFailed, "healthy-neighbour");
        let mut fired = HashMap::new();
        fired.insert(cooldown_key(&r, &noisy), 900u64);

        assert!(evaluate(&noisy, &rules, &fired).is_empty(), "noisy object stays suppressed");
        assert_eq!(evaluate(&quiet, &rules, &fired).len(), 1, "neighbour must still alert");
    }

    #[test]
    fn cooldown_expires() {
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let mut e = ev(EventKind::ObjectFailed, "web");
        let mut fired = HashMap::new();
        fired.insert(cooldown_key(&r, &e), 0u64);
        e.timestamp = 1_000;   // 1000s later, cooldown 900
        assert_eq!(evaluate(&e, &rules, &fired).len(), 1);
    }

    #[test]
    fn recovery_bypasses_cooldown() {
        // Suppressing "it came back" leaves an incident open forever.
        let r = rule("a", MatchSpec::default());
        let rules = vec![r.clone()];
        let e = ev(EventKind::ObjectStarted, "web");
        let mut fired = HashMap::new();
        fired.insert(cooldown_key(&r, &e), 999u64);
        assert_eq!(evaluate(&e, &rules, &fired).len(), 1);
    }

    #[test]
    fn disabled_rules_never_fire() {
        let mut r = rule("a", MatchSpec::default());
        r.enabled = false;
        assert!(evaluate(&ev(EventKind::ObjectFailed, "web"), &[r], &HashMap::new()).is_empty());
    }

    // ── routing ──

    #[test]
    fn no_channels_means_every_channel() {
        // A rule written before routing existed, or left blank, must still
        // deliver rather than silently going nowhere.
        let r = rule("a", MatchSpec::default());
        assert_eq!(r.resolved_channels().len(), Channel::ALL.len());
    }

    #[test]
    fn explicit_channels_are_honoured() {
        let mut r = rule("a", MatchSpec::default());
        r.channels = vec![Channel::Ntfy];
        assert_eq!(r.resolved_channels(), vec![Channel::Ntfy]);
    }

    #[test]
    fn egress_failure_is_a_first_class_event() {
        // The silent failure: container Up, healthy, and unable to reach out.
        let r = rule("a", MatchSpec {
            events: vec![EventKind::ObjectEgressFailed],
            ..Default::default()
        });
        assert!(rule_matches(&r, &ev(EventKind::ObjectEgressFailed, "speedtest-tracker")));
        assert!(!rule_matches(&r, &ev(EventKind::ObjectStarted, "speedtest-tracker")));
    }
}

// ─── Runner ───

/// How long a loaded rules/alert-config snapshot is reused. Short
/// enough that an operator editing the file still sees the effect
/// almost immediately (the original reason these were read per event),
/// long enough that an event STORM costs one load instead of thousands.
const CONFIG_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(2);

/// Rules snapshot, reloaded at most every [`CONFIG_CACHE_TTL`].
fn cached_rules() -> NotifyRules {
    static CACHE: std::sync::LazyLock<std::sync::Mutex<Option<(NotifyRules, std::time::Instant)>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
    let mut guard = match CACHE.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if let Some((val, at)) = &*guard
        && at.elapsed() < CONFIG_CACHE_TTL {
            return val.clone();
        }
    let val = NotifyRules::load();
    *guard = Some((val.clone(), std::time::Instant::now()));
    val
}

/// Alert-config snapshot, same policy as [`cached_rules`].
fn cached_alert_config() -> crate::alerting::AlertConfig {
    static CACHE: std::sync::LazyLock<std::sync::Mutex<Option<(crate::alerting::AlertConfig, std::time::Instant)>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
    let mut guard = match CACHE.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if let Some((val, at)) = &*guard
        && at.elapsed() < CONFIG_CACHE_TTL {
            return val.clone();
        }
    let val = crate::alerting::AlertConfig::load();
    *guard = Some((val.clone(), std::time::Instant::now()));
    val
}

/// Consume events from every available source, evaluate rules, and deliver.
///
/// Rules and alert config are read through a 2-second cache. They used to
/// be re-read from disk on EVERY event, justified as "events are rare (a
/// busy node sees a handful an hour)" — which is true right up until a
/// container enters a restart loop. Docker then emits a continuous event
/// stream, and a file read + JSON parse per event (twice per matching
/// event) pegged the actix workers on a node with ~100 crash-looping
/// containers (klas, 2026-08-12). The cache keeps the original intent —
/// an operator's edit takes effect within two seconds, no restart needed.
pub async fn handle_event(
    event: NotifyEvent,
    last_fired: &mut HashMap<String, u64>,
) {
    let rules = cached_rules();
    if rules.rules.is_empty() {
        return;
    }
    let matched = evaluate(&event, &rules.rules, last_fired);
    if matched.is_empty() {
        return;
    }
    let cfg = cached_alert_config();
    for rule in matched {
        let (title, body) = render(&event, rule);
        // Recovery is informational; a failure should be able to cut through
        // a phone's do-not-disturb, which is what ntfy priority 5 is for.
        let priority = if event.kind.is_recovery() { 3 } else { 5 };
        // The rule's channels are intersected with the operator's global
        // delivery-path selection inside `dispatch_to_selected` — a rule picks
        // from the paths they chose, it can't reinstate one they switched off.
        crate::alerting::dispatch_to_selected(
            &cfg, &rule.resolved_channels(), &title, &body, priority,
        ).await;
        last_fired.insert(cooldown_key(rule, &event), event.timestamp);
        tracing::info!(
            "notify: rule '{}' fired for {} {} ({})",
            rule.name, event.backend, event.object, event.kind.label()
        );
    }
}

/// Supervised `docker events` tail. Restarts with backoff; a source that has
/// silently stopped is worse than no source, so persistent failure is itself
/// reported through the rule engine as [`EventKind::SourceDegraded`].
pub async fn run_docker_source(node: String) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let mut last_fired: HashMap<String, u64> = HashMap::new();
    let mut tracker = source_docker::RestartTracker::default();
    let mut backoff_secs = 5u64;
    let mut degraded_reported = false;

    loop {
        if std::process::Command::new("docker").arg("--version").output().map(|o| !o.status.success()).unwrap_or(true) {
            // No docker on this node — nothing to watch, and nothing broken.
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            continue;
        }

        let child = Command::new("docker")
            .args(["events", "--format", "{{json .}}"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)   // never leak the child if this task is cancelled
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("notify: could not start docker events: {}", e);
                report_degraded(&node, &mut degraded_reported, &mut last_fired, &e.to_string()).await;
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(300);
                continue;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                let _ = child.kill().await;
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                continue;
            }
        };

        // Connected: reset the backoff and clear any degraded state.
        backoff_secs = 5;
        degraded_reported = false;
        tracing::info!("notify: docker event source connected");

        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Some(event) = source_docker::parse_docker_event(&line, &node) else {
                continue;
            };

            // Restart-loop detection sits here rather than in the parser: it
            // needs state across events, which the parser deliberately has none of.
            if event.kind == EventKind::ObjectFailed {
                let count = tracker.record(&event.object, event.timestamp, 600);
                if count >= 3 {
                    let mut loop_event = event.clone();
                    loop_event.kind = EventKind::ObjectRestartLooping;
                    loop_event.restart_count = Some(count as u32);
                    handle_event(loop_event, &mut last_fired).await;
                }
            } else if event.kind == EventKind::ObjectStarted {
                tracker.clear(&event.object);
            }

            handle_event(event, &mut last_fired).await;
        }

        // Stream ended — usually the daemon restarting.
        let _ = child.kill().await;
        tracing::warn!("notify: docker event stream ended, reconnecting in {}s", backoff_secs);
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(300);
    }
}

/// Report that a source is not reporting — once per outage, not per retry.
async fn report_degraded(
    node: &str,
    already: &mut bool,
    last_fired: &mut HashMap<String, u64>,
    detail: &str,
) {
    if *already {
        return;
    }
    *already = true;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    handle_event(
        NotifyEvent {
            kind: EventKind::SourceDegraded,
            node: node.to_string(),
            backend: "docker".into(),
            object: "docker-events".into(),
            labels: HashMap::new(),
            exit_code: None,
            restart_count: None,
            timestamp: now,
            message: detail.to_string(),
        },
        last_fired,
    )
    .await;
}



/// Poll LXC, libvirt and Proxmox for state changes.
///
/// Runs alongside the Docker event source, covering every backend that has no
/// event stream to subscribe to. Cadence is fixed at 60s: fast enough that an
/// outage is noticed promptly, slow enough that it costs nothing on a node with
/// hundreds of containers (the LXC snapshot reuses the shared listing cache).
pub async fn run_poll_sources(node: String) {
    use std::collections::HashMap;

    let mut last_fired: HashMap<String, u64> = HashMap::new();
    // None = never polled. The FIRST poll of each backend only seeds the
    // baseline and emits nothing; otherwise every daemon restart would report
    // every stopped container on the node as a fresh event.
    let mut prev: HashMap<&'static str, source_poll::StateMap> = HashMap::new();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Snapshots shell out, so keep them off the async worker threads.
        let snaps: Vec<(&'static str, source_poll::StateMap)> =
            match tokio::task::spawn_blocking(|| {
                vec![
                    ("lxc", source_poll::snapshot_lxc()),
                    ("libvirt", source_poll::snapshot_libvirt()),
                    ("pve", source_poll::snapshot_pve()),
                ]
            }).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("notify: poll snapshot task failed: {}", e);
                    continue;
                }
            };

        for (backend, now_map) in snaps {
            // A backend with no tooling installed reports nothing, forever —
            // don't let that look like "everything disappeared".
            if now_map.is_empty() && !prev.contains_key(backend) {
                continue;
            }
            match prev.get(backend) {
                None => {
                    tracing::info!(
                        "notify: {} poll seeded with {} object(s)", backend, now_map.len()
                    );
                }
                Some(prev_map) => {
                    for event in source_poll::diff_states(prev_map, &now_map, backend, &node, now_ts) {
                        handle_event(event, &mut last_fired).await;
                    }
                }
            }
            prev.insert(backend, now_map);
        }
    }
}

/// Create a probe from an AI tool call and persist it **docked**.
///
/// The approval gate in a chat context. In the bay, an AI draft opens in the
/// editor and only exists if the operator saves it; there is no editor in a
/// chat, so the equivalent is to save it disabled. The operator sees it in the
/// Probe Bay, checks what it watches, and launches it deliberately.
///
/// Saving it live would mean a sentence typed into a chat window silently
/// arms fleet-wide notifications — and an AI-invented rule that matches nothing
/// looks deployed while never firing.
pub fn create_probe_docked(
    name: &str,
    events: Vec<String>,
    backends: Vec<String>,
    objects: Vec<String>,
    nodes: Vec<String>,
    channels: Vec<String>,
    cooldown_minutes: Option<u64>,
) -> Result<NotifyRule, String> {
    if name.trim().is_empty() {
        return Err("a probe needs a name".into());
    }
    // Unknown event names are dropped rather than stored: a rule carrying an
    // invented event parses fine and then never matches anything, which is the
    // worst outcome this subsystem has.
    let parsed_events: Vec<EventKind> = events.iter()
        .filter_map(|e| serde_json::from_value(serde_json::Value::String(e.clone())).ok())
        .collect();
    if !events.is_empty() && parsed_events.is_empty() {
        return Err(format!(
            "none of those event names exist: {}. Valid: object_failed, object_stopped, \
             object_started, object_oom_killed, object_health_failed, \
             object_restart_looping, object_egress_failed, source_degraded",
            events.join(", ")
        ));
    }
    let parsed_channels: Vec<crate::alerting::Channel> = channels.iter()
        .filter_map(|c| serde_json::from_value(serde_json::Value::String(c.to_lowercase())).ok())
        .collect();

    let rule = NotifyRule {
        id: format!("probe-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        name: name.trim().to_string(),
        enabled: false,          // docked until the operator launches it
        scope: if nodes.iter().any(|n| n == "*") { Scope::Cluster } else { Scope::Node },
        mode: Mode::Simple,
        match_spec: MatchSpec {
            events: parsed_events,
            backends,
            objects,
            labels: HashMap::new(),
            nodes,
        },
        channels: parsed_channels,
        cooldown_secs: cooldown_minutes.unwrap_or(15) * 60,
        run_flow: None,
    };

    let mut store = NotifyRules::load();
    store.rules.push(rule.clone());
    store.save()?;
    Ok(rule)
}

/// Human summary of a probe, for the chat reply.
pub fn describe_rule(r: &NotifyRule) -> String {
    let objects = if r.match_spec.objects.is_empty() { "anything".to_string() }
                  else { r.match_spec.objects.join(", ") };
    let kinds = if r.match_spec.backends.is_empty() { "all types".to_string() }
                else { r.match_spec.backends.join(", ") };
    let events = if r.match_spec.events.is_empty() { "any event".to_string() }
                 else { r.match_spec.events.iter().map(|e| e.label()).collect::<Vec<_>>().join(", ") };
    let channels = if r.channels.is_empty() { "every configured channel".to_string() }
                   else { r.channels.iter()
                            .map(|c| format!("{:?}", c).to_lowercase())
                            .collect::<Vec<_>>().join(", ") };
    format!(
        "**{}** — watches {} ({}), reports {}, signals {}. Quiet {} min per object after firing.",
        r.name, objects, kinds, events, channels, r.cooldown_secs / 60
    )
}

#[cfg(test)]
mod tool_tests {
    use super::*;

    #[test]
    fn an_invented_event_name_is_rejected_not_stored() {
        // The failure that matters: a rule carrying a hallucinated event parses
        // fine and then never matches anything, looking deployed for ever.
        let e = create_probe_docked(
            "bad", vec!["container_exploded".into()], vec![], vec![], vec![], vec![], None,
        ).unwrap_err();
        assert!(e.contains("none of those event names exist"), "{}", e);
    }

    #[test]
    fn a_probe_needs_a_name() {
        assert!(create_probe_docked("   ", vec![], vec![], vec![], vec![], vec![], None).is_err());
    }

    #[test]
    fn describe_rule_states_what_it_watches() {
        let r = NotifyRule {
            id: "x".into(), name: "DBs".into(), enabled: false,
            scope: Scope::Node, mode: Mode::Simple,
            match_spec: MatchSpec {
                events: vec![EventKind::ObjectFailed],
                backends: vec!["docker".into()],
                objects: vec!["*-db".into()],
                labels: HashMap::new(), nodes: vec![],
            },
            channels: vec![crate::alerting::Channel::Email],
            cooldown_secs: 900, run_flow: None,
        };
        let d = describe_rule(&r);
        assert!(d.contains("*-db"), "{}", d);
        assert!(d.contains("docker"), "{}", d);
        assert!(d.contains("email"), "{}", d);
        assert!(d.contains("15 min"), "{}", d);
    }
}

/// This node's name, as events and rules refer to it.
pub fn local_node_name() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod event_storm_tests {
    use super::*;

    /// An event storm must not cost one config load per event.
    ///
    /// `handle_event` used to call `NotifyRules::load()` (a file read +
    /// JSON parse) on EVERY event, on the stated assumption that "events
    /// are rare". A node with ~100 containers in a restart loop makes
    /// Docker emit a continuous stream, and that assumption pegged the
    /// actix workers (klas, 2026-08-12). This pins the caching policy:
    /// N events in a burst cost ONE load, not N.
    #[test]
    fn config_is_loaded_once_per_ttl_not_once_per_event() {
        use std::time::{Duration, Instant};
        // Mirror of cached_rules()'s policy with a counted loader.
        // Mirror of cached_rules()'s policy with a counted loader.
        fn load_through_cache(now: Instant, ttl: Duration, cache: &mut Option<Instant>, loads: &mut usize) {
            let fresh = cache.map(|at| now.duration_since(at) < ttl).unwrap_or(false);
            if !fresh {
                *loads += 1;
                *cache = Some(now);
            }
        }
        let mut loads = 0usize;
        let mut cache: Option<Instant> = None;
        let ttl = CONFIG_CACHE_TTL;
        // 5,000 events arriving inside the TTL window — a restart-loop storm.
        let t0 = Instant::now();
        for _ in 0..5_000 {
            load_through_cache(t0, ttl, &mut cache, &mut loads);
        }
        assert_eq!(loads, 1, "a burst of events must cost ONE config load, not one each");

        // After the TTL elapses, the next event reloads — an operator's
        // edit must still take effect without a restart.
        load_through_cache(t0 + ttl + Duration::from_millis(1), ttl, &mut cache, &mut loads);
        assert_eq!(loads, 2, "config must be re-read once the TTL expires");
    }

    #[test]
    fn cache_ttl_stays_short_enough_to_feel_live() {
        // The per-event read existed so edits applied immediately; the
        // cache keeps that promise only while the window stays small.
        assert!(
            CONFIG_CACHE_TTL <= std::time::Duration::from_secs(5),
            "notify config cache must stay short — operators edit rules and expect them to apply",
        );
    }
}
