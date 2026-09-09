// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Proposal data model + ProposalStore.
//!
//! A `Proposal` is the unit of inbox-surfaced advice. Every analyzer
//! emits these; the orchestrator dedups them by (finding_type, scope)
//! so the same recurring issue updates the existing entry instead of
//! piling up. The store is the single source of truth for what's
//! pending the operator's attention.
//!
//! ## Why dedup keys are (finding_type, scope) and not random IDs
//!
//! The disk-fill analyzer reruns every five minutes. If it created a
//! fresh Proposal each cycle, the operator's inbox would gain twelve
//! identical entries an hour for the same disk. Keying by
//! `(finding_type, scope)` means the second-and-onward sightings
//! *update* the original entry — keeping `created_at` fixed (so the
//! age in the UI represents "how long has this been an issue") while
//! refreshing severity, evidence, and `updated_at`.

#[cfg(test)]
use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User-facing severity tier. Drives inbox sort order, badge colour,
/// and (later) which notification channels fire.
///
/// `Info` proposals are emitted but conventionally hidden from the
/// default inbox view — useful for baseline-posture reporting without
/// crying wolf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Warn,
    Info,
}

impl Severity {
    /// Sort key — Critical first, Info last. Used by the inbox.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Warn => 2,
            Severity::Info => 3,
        }
    }
}

/// Where the proposal came from. AI-source proposals carry a visual
/// distinction in the UI and start one severity tier lower than their
/// computed value until the rule's accept-ratio earns parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalSource {
    Rule,
    Ai,
}

/// What the operator should do. v1 emits `Manual` — operator runs the
/// commands themselves. v2 will introduce `OneClick` proposals whose
/// `handler_id` references an existing one-click-fix endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemediationPlan {
    /// Operator executes manually. The UI shows `instructions` as
    /// prose and `commands` as copy-pasteable monospace.
    Manual {
        instructions: String,
        commands: Vec<String>,
    },
    /// Click Approve → dispatch to a pre-allowlisted handler. Not
    /// used by any v1 analyzer — defined now so the data model is
    /// stable when v2 wires the first OneClick analyzer.
    OneClick {
        handler_id: String,
        params: serde_json::Value,
    },
}

/// One supporting fact attached to a proposal. Rendered as a small
/// chip in the inbox card. Always has a label and a value; `detail`
/// is for the "expand" panel.
///
/// `links` carries authoritative external references (e.g. vendor
/// advisories, distro security trackers) and is rendered as small
/// pill links beside the chip. Used by the OSV analyzer to surface
/// mitigation guidance for unpatched CVEs without us synthesising the
/// advice ourselves. Empty for analyzers that don't have references
/// to surface — `skip_serializing_if = "Vec::is_empty"` keeps the
/// JSON wire size unchanged for those callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub label: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<EvidenceLink>,
}

/// One labelled URL attached to an [`Evidence`] entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLink {
    /// Short human label for the chip. The OSV analyzer uses values
    /// like "Advisory", "Fix", "Web", or a derived host name.
    pub label: String,
    pub url: String,
}

/// Where in the cluster the proposal applies. `resource_id` is the
/// finer-grained anchor (mount point, container id, certificate name)
/// that distinguishes one finding from another at the same node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProposalScope {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}

/// Lifecycle of a proposal in the inbox.
///
/// `Pending` is the initial state — visible to the operator, awaiting
/// action. `Snoozed` hides it from the inbox until `until` passes,
/// at which point the next analyzer run that re-detects the issue
/// will flip it back to Pending. `Dismissed` is permanent ("not a
/// real issue, stop showing me"). `Approved` records the outcome of
/// a successful (or failed) one-click apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Snoozed { until: DateTime<Utc> },
    Approved { applied_at: DateTime<Utc>, outcome: ApprovalOutcome },
    Dismissed { reason: String, dismissed_at: DateTime<Utc> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// Operator ran the suggested remediation and confirmed.
    Applied,
    /// Operator clicked apply but the dispatched handler errored
    /// (v2-only — v1 proposals are `Manual`, never one-click).
    Failed { error: String },
    /// Analyzer noticed the condition cleared on its own (e.g. disk
    /// freed, container restart-loop stopped). No operator action.
    /// Distinguished from `Applied` so the audit trail keeps the
    /// closed-loop signal honest.
    ConditionCleared,
    /// The thing the finding was about no longer exists — a WolfNet peer
    /// removed from the config, a container destroyed, a node taken out
    /// of the cluster, a systemd unit `reset-failed`. The condition was
    /// never "fixed"; the resource went away, so nothing can re-evaluate
    /// it. Kept distinct from `ConditionCleared` because the audit trail
    /// must not claim the analyzer watched a problem resolve when what
    /// actually happened is that it lost sight of it.
    ResourceGone { reason: String },
}

/// One inbox entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub finding_type: String,
    pub source: ProposalSource,
    pub severity: Severity,
    pub title: String,
    pub why: String,
    pub evidence: Vec<Evidence>,
    pub remediation: RemediationPlan,
    pub scope: ProposalScope,
    pub status: ProposalStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Last tick an analyzer actually EVALUATED this (finding, scope) — i.e. the
    /// scope was in the orchestrator's `covered` set this run, whether or not the
    /// condition re-fired. Lets the operator (and us) tell "still actively
    /// detected" (advancing, with updated_at) from "no longer being checked"
    /// (stale → the analyzer's data source is unavailable, which is precisely why
    /// it can't auto-resolve). Defaults to None for proposals persisted before
    /// this field existed (KO4BSR/Gary 2026-06-29).
    #[serde(default)]
    pub last_checked_at: Option<DateTime<Utc>>,
}

impl Proposal {
    /// Build a fresh `Pending` proposal. Caller fills in the
    /// finding-specific fields; this fixes id + timestamps + status.
    pub fn new(
        finding_type: impl Into<String>,
        source: ProposalSource,
        severity: Severity,
        title: impl Into<String>,
        why: impl Into<String>,
        evidence: Vec<Evidence>,
        remediation: RemediationPlan,
        scope: ProposalScope,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            finding_type: finding_type.into(),
            source,
            severity,
            title: title.into(),
            why: why.into(),
            evidence,
            remediation,
            scope,
            status: ProposalStatus::Pending,
            created_at: now,
            updated_at: now,
            last_checked_at: Some(now),
        }
    }

    /// Stable identity for dedup. Two proposals collide iff their
    /// finding_type and scope match.
    pub fn dedup_key(&self) -> (String, ProposalScope) {
        (self.finding_type.clone(), self.scope.clone())
    }
}

/// On-disk persistence of the inbox. JSON file under
/// `/etc/wolfstack/predictive_proposals.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProposalStore {
    /// `proposals` is a flat list rather than a HashMap because order
    /// of insertion matters for stable inbox UX and serde-default
    /// HashMap iteration order would shuffle entries on every save.
    #[serde(default)]
    pub proposals: Vec<Proposal>,
}

/// How long a `Pending` finding may go un-evaluated before
/// [`ProposalStore::resolve_orphaned`] resolves it as
/// [`ApprovalOutcome::ResourceGone`].
///
/// Sized against the worst *legitimate* blind spot: a data source an operator
/// leaves down over a long weekend (docker stopped, an unmounted array, a peer
/// powered off for a hardware swap) must not lose its findings. A week covers
/// that with room to spare, and the analyzer re-emits within one tick if the
/// resource comes back — so the cost of being wrong is one re-notification,
/// while the cost of no fuse at all is a permanent inbox entry the operator
/// can only dismiss by hand.
pub const ORPHAN_FUSE_DAYS: i64 = 7;

/// Pending findings whose resource is absent from a *successful* enumeration
/// — i.e. the resource has been removed, so the finding can be retired now
/// rather than waiting out the [`ORPHAN_FUSE_DAYS`] fuse. Feed the result to
/// [`ProposalStore::resolve_vanished`].
///
/// The precondition is the whole point, and it is the caller's to prove:
/// `enumerated` must mean "this analyzer listed every resource of its kind
/// that exists, and the listing succeeded". An analyzer whose sampler returns
/// an empty list on failure cannot claim that — pass `false` and let the fuse
/// handle it. Claiming it falsely resolves live findings.
///
/// `covered` is the set the analyzers built for this tick; anything in it is
/// being evaluated normally (and will re-emit or auto-resolve on its own), so
/// it is left alone. Only pending findings owned by THIS node are considered,
/// for the same reason `resolve_orphaned` treats a foreign scope separately.
pub fn vanished_scopes(
    finding_types: &[&str],
    enumerated: bool,
    covered: &[(String, ProposalScope)],
    store: &ProposalStore,
    node_id: &str,
) -> Vec<(String, ProposalScope)> {
    if !enumerated { return Vec::new(); }
    store.proposals.iter()
        .filter(|p| matches!(p.status, ProposalStatus::Pending))
        .filter(|p| p.scope.node_id == node_id)
        .filter(|p| finding_types.contains(&p.finding_type.as_str()))
        .filter(|p| !covered.iter()
            .any(|(ft, sc)| ft == &p.finding_type && sc == &p.scope))
        .map(|p| (p.finding_type.clone(), p.scope.clone()))
        .collect()
}

/// File location for the proposal store. Top-level fn so tests can
/// inject a temp path via the env var.
pub fn proposals_file() -> PathBuf {
    if let Ok(p) = std::env::var("WOLFSTACK_PROPOSALS_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from("/etc/wolfstack/predictive_proposals.json")
}

impl ProposalStore {
    pub fn load() -> Self {
        let path = proposals_file();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = proposals_file();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write proposals file: {}", e))?;
        Ok(())
    }

    /// Insert or update by dedup key. Returns the canonical id of
    /// the upserted record. If a `Snoozed` or `Dismissed` proposal
    /// exists for the same key, it's preserved unchanged — the
    /// operator's prior decision wins until snooze expires or the
    /// dismissal is explicitly cleared.
    ///
    /// On update of a `Pending` entry: `created_at` is preserved
    /// (so the inbox shows "this has been a problem for N days"),
    /// `updated_at`/`severity`/`evidence`/`why` are refreshed.
    /// True when a proposal with this dedup key already exists (any
    /// status). Lets callers tell a genuinely NEW upsert from a refresh
    /// of a standing one — the orchestrator logs only the former.
    pub fn contains_key(&self, key: &(String, ProposalScope)) -> bool {
        self.proposals.iter().any(|p| p.dedup_key() == *key)
    }

    /// Grace window after an operator marks a finding "applied", during
    /// which the finding is neither re-surfaced (`upsert`) nor rebuilt by
    /// analyzers (`is_suppressed`). Must comfortably exceed the package
    /// index refresh throttle (default ~6h) so the condition can actually
    /// be re-verified before we nag again. See `upsert` for the storm this
    /// prevents.
    const APPLIED_GRACE_HOURS: i64 = 12;

    pub fn upsert(&mut self, incoming: Proposal) -> String {
        let key = incoming.dedup_key();
        if let Some(existing) = self.proposals.iter_mut()
            .find(|p| p.dedup_key() == key)
        {
            // Operator action stands until expiry — never overwrite.
            match &existing.status {
                ProposalStatus::Snoozed { until } if *until > Utc::now() => {
                    return existing.id.clone();
                }
                ProposalStatus::Dismissed { .. } => {
                    return existing.id.clone();
                }
                // A finding the operator just marked "applied" must NOT be
                // resurrected to Pending on every tick. The vuln sampler
                // reads the package manager's *cached* index (refreshed at
                // most ~6h) and kernel updates stay "pending" until a
                // reboot, so the condition reads true long after the apply.
                // Without this grace the proposal ping-pongs Approved↔Pending
                // every 5-min tick which, via the cluster inbox fan-out,
                // pegs CPU fleet-wide. It re-surfaces after the window if
                // the condition is genuinely still true (apply didn't take).
                ProposalStatus::Approved { applied_at, outcome: ApprovalOutcome::Applied }
                    if *applied_at + chrono::Duration::hours(Self::APPLIED_GRACE_HOURS) > Utc::now() =>
                {
                    return existing.id.clone();
                }
                _ => {}
            }
            // Refresh in place — preserve id and created_at.
            existing.severity = incoming.severity;
            existing.title = incoming.title;
            existing.why = incoming.why;
            existing.evidence = incoming.evidence;
            existing.remediation = incoming.remediation;
            existing.source = incoming.source;
            existing.status = ProposalStatus::Pending;
            existing.updated_at = Utc::now();
            existing.id.clone()
        } else {
            let id = incoming.id.clone();
            self.proposals.push(incoming);
            id
        }
    }

    /// Stamp `last_checked_at = now` on every PENDING proposal whose
    /// (finding_type, scope) the analyzers actually evaluated this tick
    /// (`covered`). Drives the inbox's "last checked" indicator so a finding
    /// that won't auto-resolve is visibly either still-being-detected (stamp
    /// advances) or no-longer-evaluated (stamp goes stale — the analyzer's data
    /// source is unavailable, the real reason it can't clear).
    pub fn touch_checked(&mut self, covered: &[(String, ProposalScope)]) {
        let now = Utc::now();
        for p in &mut self.proposals {
            if !matches!(p.status, ProposalStatus::Pending) {
                continue;
            }
            // Compare by reference — never clone `p.finding_type`/`p.scope` into a
            // throwaway tuple just to scan `covered` (this runs every tick over
            // every pending proposal).
            if covered.iter().any(|(ft, sc)| ft == &p.finding_type && sc == &p.scope) {
                p.last_checked_at = Some(now);
            }
        }
    }

    /// Auto-resolve `Pending` proposals whose (finding_type, scope)
    /// pair was *covered* by an analyzer in this tick but not
    /// re-emitted — i.e. the analyzer looked at the resource and
    /// found nothing wrong, so the previously-pending finding has
    /// cleared. Records as `Approved { outcome: ConditionCleared }`
    /// so the audit trail shows the operator didn't apply anything;
    /// the system noticed the issue resolved on its own.
    ///
    /// Without this, a disk that was filling and then got cleaned up
    /// would leave its proposal sitting in the inbox until the
    /// 90-day retention sweep — confusing the operator and erasing
    /// the closed-loop signal that the analyzer is working.
    ///
    /// `covered_scopes` is the set of `(finding_type, scope)` pairs
    /// the analyzer evaluated this tick (regardless of whether it
    /// emitted a proposal for them). The orchestrator builds this
    /// from the analyzer's input list, NOT from its output — that's
    /// what makes the auto-resolve work.
    ///
    /// Returns the number of proposals auto-resolved.
    pub fn auto_resolve_cleared(
        &mut self,
        covered: &[(String, ProposalScope)],
        emitted: &[(String, ProposalScope)],
    ) -> usize {
        let mut count = 0;
        for p in &mut self.proposals {
            if !matches!(p.status, ProposalStatus::Pending) { continue; }
            let key = (p.finding_type.clone(), p.scope.clone());
            // Was this (finding, scope) under the analyzer's eye
            // this tick but NOT re-emitted? If so, the condition has
            // cleared — auto-resolve.
            let was_considered = covered.contains(&key);
            let was_emitted = emitted.contains(&key);
            if was_considered && !was_emitted {
                p.status = ProposalStatus::Approved {
                    applied_at: Utc::now(),
                    outcome: ApprovalOutcome::ConditionCleared,
                };
                p.updated_at = Utc::now();
                count += 1;
            }
        }
        count
    }

    /// Resolve `Pending` findings that nothing is evaluating any more, so a
    /// finding whose *resource* has disappeared can't sit in the inbox for
    /// ever.
    ///
    /// Two independent cases, both of which produced permanent ghost entries
    /// before this existed (klas, 2026-09-09: "Predictive inbox keeps raising
    /// issues with a node that is long gone from the cluster"):
    ///
    /// 1. **Wrong owner.** Every analyzer scopes its findings to
    ///    `ctx.node_id`, which is this node's `/etc/wolfstack/node_id`, so a
    ///    proposal in the LOCAL store carrying a different `node_id` can never
    ///    be re-evaluated by anything. That happens when a node is rebuilt (new
    ///    id) or the file is replaced. Resolved immediately — there is no fuse
    ///    to wait out, because no future tick can ever cover that scope.
    ///
    /// 2. **Vanished resource.** `auto_resolve_cleared` only clears a finding
    ///    whose scope the analyzers *covered* this tick, deliberately: a
    ///    finding that stops being covered usually means the data source went
    ///    away (hung NFS, dead docker socket), and clearing on that would erase
    ///    live problems. But a resource that is genuinely gone — a WolfNet peer
    ///    deleted from the config, a destroyed container, a `reset-failed`
    ///    systemd unit — also stops being covered, and then nothing ever clears
    ///    it. The fuse resolves those, and is deliberately long (see
    ///    [`ORPHAN_FUSE_DAYS`]) so a data source that is merely down for a while
    ///    doesn't lose real findings.
    ///
    /// Self-correcting either way: an orphan that was actually still real
    /// re-emits on the next tick that covers it (`upsert` flips it straight
    /// back to `Pending` — `ResourceGone` carries no suppression grace).
    ///
    /// "Last evidence this finding is alive" is `max(updated_at,
    /// last_checked_at)`: `upsert` re-stamps `updated_at` on every tick a
    /// standing condition re-fires, and `touch_checked` stamps
    /// `last_checked_at` on every tick the scope is merely covered. So a
    /// finding that is either still firing or still being looked at can never
    /// trip the fuse, regardless of which of the two paths is keeping it alive.
    ///
    /// Snoozed and Dismissed entries are left alone — those are operator
    /// decisions, not analyzer state. Returns the number resolved.
    pub fn resolve_orphaned(&mut self, node_id: &str, fuse_days: i64) -> usize {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::days(fuse_days);
        let mut count = 0;
        for p in &mut self.proposals {
            if !matches!(p.status, ProposalStatus::Pending) { continue; }
            // An empty node_id means we failed to establish an identity this
            // start (see main.rs) — every scope would look foreign, so don't
            // use ownership as a signal at all.
            let reason = if !node_id.is_empty() && p.scope.node_id != node_id {
                format!(
                    "finding belongs to node {}, which this node is not — nothing here can re-evaluate it",
                    p.scope.node_id,
                )
            } else {
                let last_alive = p.last_checked_at.unwrap_or(p.updated_at).max(p.updated_at);
                if last_alive >= cutoff { continue; }
                // Worded as the inference it is: the fuse concludes the
                // resource is gone, it doesn't observe it. The immediate path
                // (`resolve_vanished`) is the one with proof.
                format!(
                    "nothing has evaluated this finding since {}, past the {}-day fuse — \
                     treating the resource it refers to as gone",
                    last_alive.format("%Y-%m-%d %H:%M UTC"), fuse_days,
                )
            };
            p.status = ProposalStatus::Approved {
                applied_at: now,
                outcome: ApprovalOutcome::ResourceGone { reason },
            };
            p.updated_at = now;
            count += 1;
        }
        count
    }

    /// Resolve pending findings whose resource an analyzer has positively
    /// established is gone — see [`vanished_scopes`], which computes the list
    /// and owns the "positively" part.
    ///
    /// Separate from `auto_resolve_cleared` because the two say different
    /// things: that one means "the analyzer looked and the problem is no
    /// longer there" (`ConditionCleared`), this one means "there is nothing
    /// left to look at" (`ResourceGone`). Routing these through the covered
    /// set would have recorded the wrong one, and would also have stamped
    /// `last_checked_at` on scopes nothing checked.
    ///
    /// Returns the number resolved.
    pub fn resolve_vanished(&mut self, vanished: &[(String, ProposalScope)]) -> usize {
        if vanished.is_empty() { return 0; }
        let now = Utc::now();
        let mut count = 0;
        for p in &mut self.proposals {
            if !matches!(p.status, ProposalStatus::Pending) { continue; }
            if !vanished.iter().any(|(ft, sc)| ft == &p.finding_type && sc == &p.scope) {
                continue;
            }
            p.status = ProposalStatus::Approved {
                applied_at: now,
                outcome: ApprovalOutcome::ResourceGone {
                    reason: "the resource this finding is about is no longer present \
                             on this node".to_string(),
                },
            };
            p.updated_at = now;
            count += 1;
        }
        count
    }

    /// Returns true if there's an active suppression for this
    /// (finding_type, scope) — either a Snoozed proposal whose snooze
    /// hasn't expired, or a Dismissed proposal. Analyzers query this
    /// to skip building proposals that would be filtered out anyway.
    pub fn is_suppressed(&self, finding_type: &str, scope: &ProposalScope) -> bool {
        let now = Utc::now();
        self.proposals.iter().any(|p| {
            p.finding_type == finding_type
                && p.scope == *scope
                && match &p.status {
                    ProposalStatus::Snoozed { until } => *until > now,
                    ProposalStatus::Dismissed { .. } => true,
                    // Stay suppressed during the post-apply grace window so
                    // analyzers don't rebuild the finding every tick (which
                    // is what feeds the resurrection storm — see `upsert`).
                    ProposalStatus::Approved { applied_at, outcome: ApprovalOutcome::Applied } =>
                        *applied_at + chrono::Duration::hours(Self::APPLIED_GRACE_HOURS) > now,
                    _ => false,
                }
        })
    }

    /// Inbox view: pending + currently-snoozed-but-not-expired,
    /// sorted by (severity rank, then most-recent updated_at first).
    pub fn inbox(&self) -> Vec<&Proposal> {
        let now = Utc::now();
        let mut out: Vec<&Proposal> = self.proposals.iter()
            .filter(|p| match &p.status {
                ProposalStatus::Pending => true,
                ProposalStatus::Snoozed { until } => *until > now,
                _ => false,
            })
            .collect();
        out.sort_by(|a, b| {
            a.severity.rank().cmp(&b.severity.rank())
                .then_with(|| b.updated_at.cmp(&a.updated_at))
        });
        out
    }

    pub fn get(&self, id: &str) -> Option<&Proposal> {
        self.proposals.iter().find(|p| p.id == id)
    }

    pub fn snooze(&mut self, id: &str, until: DateTime<Utc>) -> Result<(), String> {
        let p = self.proposals.iter_mut().find(|p| p.id == id)
            .ok_or_else(|| format!("proposal {} not found", id))?;
        p.status = ProposalStatus::Snoozed { until };
        p.updated_at = Utc::now();
        Ok(())
    }

    pub fn dismiss(&mut self, id: &str, reason: impl Into<String>) -> Result<(), String> {
        let p = self.proposals.iter_mut().find(|p| p.id == id)
            .ok_or_else(|| format!("proposal {} not found", id))?;
        p.status = ProposalStatus::Dismissed {
            reason: reason.into(),
            dismissed_at: Utc::now(),
        };
        p.updated_at = Utc::now();
        Ok(())
    }

    pub fn record_approval(&mut self, id: &str, outcome: ApprovalOutcome) -> Result<(), String> {
        let p = self.proposals.iter_mut().find(|p| p.id == id)
            .ok_or_else(|| format!("proposal {} not found", id))?;
        p.status = ProposalStatus::Approved {
            applied_at: Utc::now(),
            outcome,
        };
        p.updated_at = Utc::now();
        Ok(())
    }

    /// Drop `Approved` and `Dismissed` proposals whose
    /// `updated_at` is older than `days`. Pending and active-Snoozed
    /// entries are never pruned regardless of age — they're still
    /// surfaced in the inbox and dropping them would drop live
    /// state. Returns the number of entries removed.
    ///
    /// Called periodically from the orchestrator so the store
    /// doesn't grow unboundedly across years of operator use.
    pub fn prune_resolved_older_than(&mut self, days: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        let before = self.proposals.len();
        self.proposals.retain(|p| match &p.status {
            ProposalStatus::Approved { .. } | ProposalStatus::Dismissed { .. } => {
                p.updated_at >= cutoff
            }
            _ => true,
        });
        before - self.proposals.len()
    }

    /// Test-only per-rule statistics. Used by the trust-calibration
    /// test cases to assert "rules that get dismissed often should
    /// auto-quiet"; the production auto-quiet path consumes
    /// `proposals` directly so this aggregator isn't on a live
    /// code path.
    #[cfg(test)]
    pub fn stats_by_rule(&self) -> HashMap<String, RuleStats> {
        let mut out: HashMap<String, RuleStats> = HashMap::new();
        for p in &self.proposals {
            let s = out.entry(p.finding_type.clone()).or_default();
            s.fired += 1;
            match &p.status {
                ProposalStatus::Approved { .. } => s.approved += 1,
                ProposalStatus::Snoozed { .. } => s.snoozed += 1,
                ProposalStatus::Dismissed { reason, .. } => {
                    s.dismissed += 1;
                    s.dismiss_reasons.push(reason.clone());
                }
                ProposalStatus::Pending => s.pending += 1,
            }
        }
        out
    }
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    pub fired: u64,
    pub approved: u64,
    pub snoozed: u64,
    pub dismissed: u64,
    pub pending: u64,
    pub dismiss_reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn scope(node: &str, resource: Option<&str>) -> ProposalScope {
        ProposalScope { node_id: node.into(), resource_id: resource.map(|s| s.into()) }
    }

    fn fake_proposal(finding: &str, sev: Severity, sc: ProposalScope) -> Proposal {
        Proposal::new(
            finding,
            ProposalSource::Rule,
            sev,
            "title",
            "why",
            vec![],
            RemediationPlan::Manual { instructions: "do thing".into(), commands: vec![] },
            sc,
        )
    }

    #[test]
    fn upsert_dedups_on_finding_type_and_scope() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));

        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        store.upsert(fake_proposal("disk_fill_eta", Severity::High, s.clone()));

        assert_eq!(store.proposals.len(), 1);
        assert_eq!(store.proposals[0].severity, Severity::High);
    }

    #[test]
    fn upsert_preserves_created_at_on_refresh() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));

        let mut first = fake_proposal("disk_fill_eta", Severity::Warn, s.clone());
        // Pretend this finding has been around for two days.
        first.created_at = Utc::now() - Duration::days(2);
        let original_created = first.created_at;
        store.upsert(first);

        store.upsert(fake_proposal("disk_fill_eta", Severity::High, s.clone()));

        assert_eq!(store.proposals[0].created_at, original_created,
            "created_at should be preserved on refresh so the inbox \
             can show 'this has been a problem for N days'");
    }

    #[test]
    fn upsert_does_not_clobber_dismissed_proposal() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        store.dismiss(&id, "intentionally fills, log rotation handles it").unwrap();

        // Analyzer re-fires next cycle — must NOT resurrect.
        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        assert_eq!(store.proposals.len(), 1);
        assert!(matches!(store.proposals[0].status, ProposalStatus::Dismissed { .. }));
    }

    #[test]
    fn upsert_does_not_clobber_active_snooze() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        store.snooze(&id, Utc::now() + Duration::hours(4)).unwrap();

        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        match &store.proposals[0].status {
            ProposalStatus::Snoozed { .. } => {}
            other => panic!("expected snooze preserved, got {:?}", other),
        }
        // Severity must not have updated either — operator's snooze
        // means "I know, leave me alone".
        assert_eq!(store.proposals[0].severity, Severity::Warn);
    }

    #[test]
    fn expired_snooze_allows_refresh() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        // Snooze in the past — already expired.
        store.snooze(&id, Utc::now() - Duration::minutes(1)).unwrap();

        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
        assert_eq!(store.proposals[0].severity, Severity::Critical);
    }

    #[test]
    fn upsert_does_not_resurrect_recently_applied() {
        // The CPU-storm regression: marking a vuln "applied" then having
        // the analyzer re-fire (cached pkg index still shows it pending)
        // must NOT flip it back to Pending — it stays Approved during grace.
        let mut store = ProposalStore::default();
        let s = scope("node-a", None);
        store.upsert(fake_proposal("host_security_updates_pending", Severity::High, s.clone()));
        let id = store.proposals[0].id.clone();
        store.record_approval(&id, ApprovalOutcome::Applied).unwrap();

        // Analyzer re-fires next tick — condition still reads true.
        store.upsert(fake_proposal("host_security_updates_pending", Severity::High, s.clone()));

        assert_eq!(store.proposals.len(), 1);
        assert!(matches!(store.proposals[0].status,
            ProposalStatus::Approved { outcome: ApprovalOutcome::Applied, .. }),
            "a just-applied finding must not be resurrected to Pending every tick");
        // And the analyzer should skip rebuilding it entirely during grace.
        assert!(store.is_suppressed("host_security_updates_pending", &s));
    }

    #[test]
    fn applied_finding_resurfaces_after_grace_expires() {
        // If the apply genuinely didn't take, the finding must come back
        // after the grace window so the operator isn't left blind.
        let mut store = ProposalStore::default();
        let s = scope("node-a", None);
        store.upsert(fake_proposal("host_security_updates_pending", Severity::High, s.clone()));
        // Simulate an apply that happened longer ago than the grace window.
        store.proposals[0].status = ProposalStatus::Approved {
            applied_at: Utc::now() - Duration::hours(ProposalStore::APPLIED_GRACE_HOURS + 1),
            outcome: ApprovalOutcome::Applied,
        };

        assert!(!store.is_suppressed("host_security_updates_pending", &s));
        store.upsert(fake_proposal("host_security_updates_pending", Severity::Critical, s.clone()));
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending),
            "an applied finding still true after the grace window must re-surface");
    }

    #[test]
    fn is_suppressed_honors_snooze_and_dismissal() {
        let mut store = ProposalStore::default();
        let s = scope("node-a", Some("/var"));

        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();

        assert!(!store.is_suppressed("disk_fill_eta", &s));

        store.snooze(&id, Utc::now() + Duration::hours(2)).unwrap();
        assert!(store.is_suppressed("disk_fill_eta", &s));

        // Different finding_type for same scope — not suppressed.
        assert!(!store.is_suppressed("memory_pressure", &s));
    }

    #[test]
    fn inbox_sorts_critical_first() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("a", Severity::Warn,
            scope("n", Some("/a"))));
        store.upsert(fake_proposal("b", Severity::Critical,
            scope("n", Some("/b"))));
        store.upsert(fake_proposal("c", Severity::Info,
            scope("n", Some("/c"))));

        let inbox = store.inbox();
        assert_eq!(inbox[0].finding_type, "b");
        assert_eq!(inbox[1].finding_type, "a");
        assert_eq!(inbox[2].finding_type, "c");
    }

    #[test]
    fn dismissed_proposals_excluded_from_inbox() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("a", Severity::Warn,
            scope("n", Some("/a"))));
        let id = store.proposals[0].id.clone();
        store.dismiss(&id, "ack").unwrap();

        assert_eq!(store.inbox().len(), 0);
    }

    #[test]
    fn auto_resolve_clears_pending_when_condition_gone() {
        let mut store = ProposalStore::default();
        let s_disk = scope("n", Some("/var"));
        let s_mem = scope("n", Some("postgres"));

        // Two pending findings.
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s_disk.clone()));
        store.upsert(fake_proposal("memory_pressure", Severity::Warn, s_mem.clone()));

        // Analyzer considered both this tick but only re-emitted memory.
        let covered = vec![
            ("disk_fill_eta".to_string(), s_disk.clone()),
            ("memory_pressure".to_string(), s_mem.clone()),
        ];
        let emitted = vec![
            ("memory_pressure".to_string(), s_mem.clone()),
        ];

        let n = store.auto_resolve_cleared(&covered, &emitted);
        assert_eq!(n, 1, "exactly one proposal should auto-resolve");

        // Disk one is now Approved-with-ConditionCleared, memory still Pending.
        let disk = store.proposals.iter()
            .find(|p| p.finding_type == "disk_fill_eta").unwrap();
        match &disk.status {
            ProposalStatus::Approved { outcome, .. } => {
                assert!(matches!(outcome, ApprovalOutcome::ConditionCleared));
            }
            other => panic!("expected Approved/ConditionCleared, got {:?}", other),
        }
        let mem = store.proposals.iter()
            .find(|p| p.finding_type == "memory_pressure").unwrap();
        assert!(matches!(mem.status, ProposalStatus::Pending));
    }

    #[test]
    fn auto_resolve_does_not_touch_uncovered_pending() {
        // Critical safety property: if the analyzer didn't run at
        // all (data source unavailable), it covers NO scopes — and
        // we MUST NOT auto-resolve everything. Pending proposals
        // for scopes the analyzer didn't consider stay Pending.
        let mut store = ProposalStore::default();
        let s = scope("n", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        // Empty covered list (analyzer didn't run / data missing).
        let n = store.auto_resolve_cleared(&[], &[]);
        assert_eq!(n, 0, "an analyzer that ran on nothing must not resolve anything");
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
    }

    #[test]
    fn auto_resolve_skips_snoozed_and_dismissed() {
        let mut store = ProposalStore::default();
        let s = scope("n", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, s.clone()));
        let id = store.proposals[0].id.clone();
        store.snooze(&id, Utc::now() + Duration::hours(4)).unwrap();

        // Analyzer considered the scope but didn't emit (cleared
        // condition). Snoozed proposal must stay Snoozed — operator
        // intent dominates.
        let covered = vec![("disk_fill_eta".to_string(), s.clone())];
        let n = store.auto_resolve_cleared(&covered, &[]);
        assert_eq!(n, 0);
        assert!(matches!(store.proposals[0].status, ProposalStatus::Snoozed { .. }));
    }

    #[test]
    fn prune_drops_old_resolved_keeps_pending() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("a", Severity::Warn, scope("n", Some("/old-dismissed"))));
        store.upsert(fake_proposal("b", Severity::Warn, scope("n", Some("/old-approved"))));
        store.upsert(fake_proposal("c", Severity::Warn, scope("n", Some("/recent-dismissed"))));
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/pending"))));

        let id_a = store.proposals[0].id.clone();
        let id_b = store.proposals[1].id.clone();
        let id_c = store.proposals[2].id.clone();
        store.dismiss(&id_a, "old").unwrap();
        store.record_approval(&id_b, ApprovalOutcome::Applied).unwrap();
        store.dismiss(&id_c, "recent").unwrap();

        // Backdate a and b by 100 days; leave c and d at "now".
        store.proposals[0].updated_at = Utc::now() - Duration::days(100);
        store.proposals[1].updated_at = Utc::now() - Duration::days(100);

        let dropped = store.prune_resolved_older_than(30);
        assert_eq!(dropped, 2, "old resolved entries should be pruned");

        let remaining: Vec<&str> = store.proposals.iter()
            .map(|p| p.scope.resource_id.as_deref().unwrap_or(""))
            .collect();
        assert!(remaining.contains(&"/recent-dismissed"));
        assert!(remaining.contains(&"/pending"),
            "pending entries must NEVER be pruned regardless of age");
    }

    #[test]
    fn stats_classify_each_status() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/a"))));
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/b"))));
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/c"))));

        let id_b = store.proposals[1].id.clone();
        let id_c = store.proposals[2].id.clone();
        store.dismiss(&id_b, "false positive").unwrap();
        store.record_approval(&id_c, ApprovalOutcome::Applied).unwrap();

        let stats = store.stats_by_rule();
        let s = stats.get("d").unwrap();
        assert_eq!(s.fired, 3);
        assert_eq!(s.dismissed, 1);
        assert_eq!(s.approved, 1);
        assert_eq!(s.pending, 1);
        assert_eq!(s.dismiss_reasons, vec!["false positive".to_string()]);
    }
    // ── Orphan sweep (klas 2026-09-09: findings for a node long gone) ──

    /// Backdate a proposal's liveness stamps so the fuse can be exercised
    /// without sleeping the suite.
    fn backdate(store: &mut ProposalStore, idx: usize, days: i64) {
        let then = Utc::now() - Duration::days(days);
        store.proposals[idx].updated_at = then;
        store.proposals[idx].last_checked_at = Some(then);
    }

    #[test]
    fn orphan_sweep_resolves_a_finding_no_analyzer_still_evaluates() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal(
            "wolfnet_peer_unreachable", Severity::High,
            scope("n", Some("wolfnet-peer:10.100.10.30")),
        ));
        backdate(&mut store, 0, ORPHAN_FUSE_DAYS + 1);

        assert_eq!(store.resolve_orphaned("n", ORPHAN_FUSE_DAYS), 1);
        match &store.proposals[0].status {
            ProposalStatus::Approved { outcome: ApprovalOutcome::ResourceGone { reason }, .. } => {
                assert!(reason.contains("fuse"), "reason was: {}", reason);
            }
            other => panic!("expected ResourceGone, got {:?}", other),
        }
        assert!(store.inbox().is_empty(), "a resolved orphan leaves the inbox");
    }

    #[test]
    fn orphan_sweep_spares_a_finding_still_being_checked() {
        // The whole safety property: a data source that is merely quiet still
        // COVERS its scopes, so `touch_checked` keeps the stamp fresh and the
        // fuse must never fire.
        let mut store = ProposalStore::default();
        let s = scope("n", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));
        backdate(&mut store, 0, ORPHAN_FUSE_DAYS + 30);
        store.touch_checked(&[("disk_fill_eta".to_string(), s.clone())]);

        assert_eq!(store.resolve_orphaned("n", ORPHAN_FUSE_DAYS), 0);
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
    }

    #[test]
    fn orphan_sweep_spares_a_still_firing_finding_with_no_check_stamp() {
        // Proposals written before `last_checked_at` existed deserialise with
        // None. A standing condition still re-stamps `updated_at` on every
        // upsert, so that alone must keep it alive.
        let mut store = ProposalStore::default();
        let s = scope("n", Some("/var"));
        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));
        backdate(&mut store, 0, ORPHAN_FUSE_DAYS + 5);
        store.proposals[0].last_checked_at = None;
        store.upsert(fake_proposal("disk_fill_eta", Severity::Critical, s.clone()));

        assert_eq!(store.resolve_orphaned("n", ORPHAN_FUSE_DAYS), 0);
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
    }

    #[test]
    fn orphan_sweep_resolves_a_foreign_scope_immediately() {
        // A rebuilt node gets a new node_id; the findings the old identity
        // left behind can never be covered again, so they don't wait the fuse.
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal(
            "host_cpu_high", Severity::Critical, scope("ws-oldnode", Some("host")),
        ));
        assert_eq!(store.resolve_orphaned("ws-newnode", ORPHAN_FUSE_DAYS), 1);
        match &store.proposals[0].status {
            ProposalStatus::Approved { outcome: ApprovalOutcome::ResourceGone { reason }, .. } => {
                assert!(reason.contains("ws-oldnode"), "reason was: {}", reason);
            }
            other => panic!("expected ResourceGone, got {:?}", other),
        }
    }

    #[test]
    fn orphan_sweep_keeps_foreign_scopes_when_identity_is_unknown() {
        // Empty node_id = we couldn't establish an identity this start. Every
        // scope would look foreign; resolving them all would wipe the inbox.
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal(
            "host_cpu_high", Severity::Critical, scope("ws-real", Some("host")),
        ));
        assert_eq!(store.resolve_orphaned("", ORPHAN_FUSE_DAYS), 0);
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
    }

    #[test]
    fn orphan_sweep_leaves_operator_decisions_alone() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/a"))));
        store.upsert(fake_proposal("d", Severity::Warn, scope("n", Some("/b"))));
        backdate(&mut store, 0, ORPHAN_FUSE_DAYS + 1);
        backdate(&mut store, 1, ORPHAN_FUSE_DAYS + 1);
        let snoozed = store.proposals[0].id.clone();
        let dismissed = store.proposals[1].id.clone();
        store.snooze(&snoozed, Utc::now() + Duration::hours(4)).unwrap();
        store.dismiss(&dismissed, "not a real issue").unwrap();

        assert_eq!(store.resolve_orphaned("n", ORPHAN_FUSE_DAYS), 0);
    }

    #[test]
    fn a_resolved_orphan_re_surfaces_if_the_resource_returns() {
        // Self-correction: being wrong costs one re-notification, not a lost
        // finding. `ResourceGone` must carry no suppression grace.
        let mut store = ProposalStore::default();
        let s = scope("n", Some("wolfnet-peer:10.100.10.30"));
        store.upsert(fake_proposal("wolfnet_peer_unreachable", Severity::High, s.clone()));
        backdate(&mut store, 0, ORPHAN_FUSE_DAYS + 1);
        assert_eq!(store.resolve_orphaned("n", ORPHAN_FUSE_DAYS), 1);

        assert!(!store.is_suppressed("wolfnet_peer_unreachable", &s));
        store.upsert(fake_proposal("wolfnet_peer_unreachable", Severity::High, s.clone()));
        assert!(matches!(store.proposals[0].status, ProposalStatus::Pending));
        assert_eq!(store.proposals.len(), 1, "re-emission must not duplicate the entry");
    }

    #[test]
    fn vanished_resource_is_covered_so_it_resolves_this_tick() {
        // A peer deleted from /etc/wolfnet/config.toml: the enumeration
        // succeeded and no longer lists it, so it clears now rather than
        // waiting out the fuse.
        let mut store = ProposalStore::default();
        let gone = scope("n", Some("wolfnet-peer:10.100.10.30"));
        let live = scope("n", Some("wolfnet-peer:10.100.10.31"));
        store.upsert(fake_proposal("wolfnet_peer_unreachable", Severity::High, gone.clone()));
        store.upsert(fake_proposal("wolfnet_peer_unreachable", Severity::High, live.clone()));

        let covered = vec![("wolfnet_peer_unreachable".to_string(), live.clone())];
        let vanished = vanished_scopes(
            &["wolfnet_peer_unreachable"], true, &covered, &store, "n",
        );
        assert_eq!(vanished, vec![("wolfnet_peer_unreachable".to_string(), gone.clone())]);

        assert_eq!(store.resolve_vanished(&vanished), 1);
        let g = store.proposals.iter().find(|p| p.scope == gone).unwrap();
        match &g.status {
            ProposalStatus::Approved { outcome: ApprovalOutcome::ResourceGone { .. }, .. } => {}
            other => panic!("a vanished resource must not read as condition_cleared: {:?}", other),
        }
        // The peer that IS still configured stays open — it's covered, so the
        // normal auto-resolve path owns it.
        let l = store.proposals.iter().find(|p| p.scope == live).unwrap();
        assert!(matches!(l.status, ProposalStatus::Pending));
    }

    #[test]
    fn a_failed_enumeration_covers_nothing() {
        // `scanned == false` (config unreadable, systemctl absent, docker
        // socket down) must never be treated as "the resource is gone".
        let mut store = ProposalStore::default();
        let s = scope("n", Some("wolfnet-peer:10.100.10.30"));
        store.upsert(fake_proposal("wolfnet_peer_unreachable", Severity::High, s));
        assert!(vanished_scopes(
            &["wolfnet_peer_unreachable"], false, &[], &store, "n",
        ).is_empty());
    }

    #[test]
    fn vanished_coverage_ignores_other_finding_types_and_other_nodes() {
        let mut store = ProposalStore::default();
        store.upsert(fake_proposal("disk_fill_eta", Severity::Warn, scope("n", Some("/var"))));
        store.upsert(fake_proposal(
            "wolfnet_peer_unreachable", Severity::High,
            scope("other-node", Some("wolfnet-peer:10.0.0.9")),
        ));
        assert!(vanished_scopes(
            &["wolfnet_peer_unreachable"], true, &[], &store, "n",
        ).is_empty());
    }
}
