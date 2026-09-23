// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Acknowledgements — operator-declared "yes, this is intentional".
//!
//! An `Ack` is a durable suppression for a (finding_type, scope)
//! pair, with a *reason* and an optional expiry. Acks live in their
//! own store rather than being a special proposal status because
//! they're a different kind of intent: a Dismissal says "this
//! particular sighting wasn't worth showing me", an Ack says "this
//! whole class of finding for this resource is fine, don't ever ring
//! again until expiry".
//!
//! Acks default to a 180-day expiry rather than living forever — a
//! permanent ack rots silently as the surrounding system changes
//! (the LAN that was private becomes a DMZ; the database that didn't
//! hold PII now does). Re-prompting at 6 months is friction by
//! design.

use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::predictive::proposal::ProposalScope;

/// Default lifetime of a new ack. Operators can set custom expiries
/// or pass `None` for "until I revoke", but the default surfaces a
/// re-confirmation prompt at 6 months.
pub const DEFAULT_ACK_LIFETIME_DAYS: i64 = 180;

/// What the ack covers. `Cluster` matches every node and resource;
/// `Node` matches every resource on a single node; `Resource` is the
/// most specific.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// `tag = "kind"` mirrors `ProposalStatus` and `RemediationPlan` —
// using `tag = "scope"` here would produce confusing wire formats
// like `{"scope": {"scope": "node", "node_id": "..."}}` because
// `CreateAckRequest` already has a field literally named `scope`.
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AckScope {
    Cluster,
    Node { node_id: String },
    Resource { node_id: String, resource_id: String },
}

impl AckScope {
    /// Does this ack scope cover the proposal scope? An ack at
    /// `Cluster` covers everything; `Node` covers any proposal on
    /// that node; `Resource` requires both ids to match.
    pub fn covers(&self, proposal: &ProposalScope) -> bool {
        match self {
            AckScope::Cluster => true,
            AckScope::Node { node_id } => *node_id == proposal.node_id,
            AckScope::Resource { node_id, resource_id } => {
                *node_id == proposal.node_id
                    && proposal.resource_id.as_deref() == Some(resource_id)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub id: String,
    pub finding_type: String,
    pub scope: AckScope,
    pub reason: String,
    pub acknowledged_by: String,
    pub created_at: DateTime<Utc>,
    /// `None` means "until revoked" — strongly discouraged, but
    /// supported. The default `expires` is `created_at +
    /// DEFAULT_ACK_LIFETIME_DAYS` so operators get re-prompted.
    pub expires: Option<DateTime<Utc>>,
}

impl Ack {
    pub fn new(
        finding_type: impl Into<String>,
        scope: AckScope,
        reason: impl Into<String>,
        acknowledged_by: impl Into<String>,
        lifetime: Option<Duration>,
    ) -> Self {
        let now = Utc::now();
        let expires = match lifetime {
            Some(d) => Some(now + d),
            None => Some(now + Duration::days(DEFAULT_ACK_LIFETIME_DAYS)),
        };
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            finding_type: finding_type.into(),
            scope,
            reason: reason.into(),
            acknowledged_by: acknowledged_by.into(),
            created_at: now,
            expires,
        }
    }

    /// Test-only constructor for acks-without-expiry. Production
    /// flows always hand the operator a renewal prompt so this
    /// branch never fires in non-test code; kept gated on
    /// `cfg(test)` rather than deleted because the tests cover
    /// the "infinite ack still flagged active after a year"
    /// invariant.
    #[cfg(test)]
    pub fn permanent(
        finding_type: impl Into<String>,
        scope: AckScope,
        reason: impl Into<String>,
        acknowledged_by: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            finding_type: finding_type.into(),
            scope,
            reason: reason.into(),
            acknowledged_by: acknowledged_by.into(),
            created_at: Utc::now(),
            expires: None,
        }
    }

    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expires {
            None => true,
            Some(e) => e > now,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AckStore {
    #[serde(default)]
    pub acks: Vec<Ack>,
}

pub fn acks_file() -> PathBuf {
    if let Ok(p) = std::env::var("WOLFSTACK_PROPOSAL_ACKS_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from("/etc/wolfstack/proposal_acks.json")
}

impl AckStore {
    pub fn load() -> Self {
        let path = acks_file();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = acks_file();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write acks file: {}", e))?;
        Ok(())
    }

    pub fn add(&mut self, ack: Ack) -> String {
        let id = ack.id.clone();
        self.acks.push(ack);
        id
    }

    /// Store a copy of an ack created on another cluster node. Keyed by
    /// id so a repeated push (retry, or the operator acking twice from
    /// two tabs) replaces rather than duplicates.
    pub fn upsert_replica(&mut self, ack: Ack) {
        match self.acks.iter_mut().find(|a| a.id == ack.id) {
            Some(existing) => *existing = ack,
            None => self.acks.push(ack),
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.acks.len();
        self.acks.retain(|a| a.id != id);
        self.acks.len() < before
    }

    /// Returns true if any active ack covers this (finding_type, scope).
    /// Analyzers consult this *before* building proposals to avoid the
    /// false-positive class the user called out (e.g. MariaDB on
    /// 0.0.0.0 over a private LAN).
    pub fn suppresses(&self, finding_type: &str, scope: &ProposalScope) -> bool {
        let now = Utc::now();
        self.acks.iter().any(|a| {
            a.is_active(now)
                && a.finding_type == finding_type
                && a.scope.covers(scope)
        })
    }

    /// Test-only: Acks whose expiry is approaching. Surface tests
    /// rely on this for "review your acknowledgements" coverage,
    /// but production has no consumer yet.
    #[cfg(test)]
    pub fn expiring_within(&self, days: i64) -> Vec<&Ack> {
        let now = Utc::now();
        let horizon = now + Duration::days(days);
        self.acks.iter()
            .filter(|a| matches!(a.expires, Some(e) if e > now && e <= horizon))
            .collect()
    }

    /// Drop entries whose expiry has passed. Called at startup and
    /// periodically; keeps the on-disk file from growing unboundedly
    /// over years of operator use.
    pub fn prune_expired(&mut self) -> usize {
        let now = Utc::now();
        let before = self.acks.len();
        self.acks.retain(|a| a.is_active(now));
        before - self.acks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pscope(node: &str, resource: Option<&str>) -> ProposalScope {
        ProposalScope { node_id: node.into(), resource_id: resource.map(|s| s.into()) }
    }

    // ── AckScope::covers ────────────────────────────────────────────

    #[test]
    fn cluster_scope_covers_everything() {
        let s = AckScope::Cluster;
        assert!(s.covers(&pscope("a", Some("/var"))));
        assert!(s.covers(&pscope("b", None)));
    }

    #[test]
    fn node_scope_only_matches_same_node() {
        let s = AckScope::Node { node_id: "a".into() };
        assert!(s.covers(&pscope("a", Some("/var"))));
        assert!(s.covers(&pscope("a", None)));
        assert!(!s.covers(&pscope("b", Some("/var"))));
    }

    #[test]
    fn resource_scope_requires_both_ids() {
        let s = AckScope::Resource { node_id: "a".into(), resource_id: "/var".into() };
        assert!(s.covers(&pscope("a", Some("/var"))));
        assert!(!s.covers(&pscope("a", Some("/etc"))));
        assert!(!s.covers(&pscope("a", None)));
        assert!(!s.covers(&pscope("b", Some("/var"))));
    }

    // ── Replication ────────────────────────────────────────────────

    #[test]
    fn upsert_replica_is_idempotent_by_id() {
        let mut store = AckStore::default();
        let ack = Ack::new("disk_fill_eta", AckScope::Cluster, "x", "paul", None);
        store.upsert_replica(ack.clone());
        let mut changed = ack.clone();
        changed.reason = "y".into();
        store.upsert_replica(changed);
        assert_eq!(store.acks.len(), 1);
        assert_eq!(store.acks[0].reason, "y");
    }

    // ── Lifecycle ──────────────────────────────────────────────────

    #[test]
    fn default_ack_has_180_day_expiry() {
        let ack = Ack::new(
            "disk_fill_eta",
            AckScope::Cluster,
            "log rotation handles it",
            "paul",
            None,
        );
        let exp = ack.expires.expect("default ack must have expiry");
        let days = (exp - ack.created_at).num_days();
        assert_eq!(days, DEFAULT_ACK_LIFETIME_DAYS);
    }

    #[test]
    fn permanent_ack_has_no_expiry() {
        let ack = Ack::permanent(
            "disk_fill_eta",
            AckScope::Cluster,
            "we know",
            "paul",
        );
        assert!(ack.expires.is_none());
        assert!(ack.is_active(Utc::now() + Duration::days(10000)));
    }

    #[test]
    fn expired_ack_is_inactive() {
        let mut ack = Ack::new(
            "disk_fill_eta",
            AckScope::Cluster,
            "x",
            "paul",
            Some(Duration::days(1)),
        );
        ack.expires = Some(Utc::now() - Duration::hours(1));
        assert!(!ack.is_active(Utc::now()));
    }

    // ── Store suppression ──────────────────────────────────────────

    #[test]
    fn suppresses_when_resource_ack_matches() {
        // The exact false-positive Paul called out: MariaDB bound on
        // 0.0.0.0 on a private LAN. Operator acks the resource;
        // analyzer must skip the finding.
        let mut store = AckStore::default();
        store.add(Ack::new(
            "service_bound_publicly",
            AckScope::Resource { node_id: "node-a".into(), resource_id: "mariadb:3306".into() },
            "private LAN, intentional for analytics tools",
            "paul",
            None,
        ));
        assert!(store.suppresses(
            "service_bound_publicly",
            &pscope("node-a", Some("mariadb:3306")),
        ));
        // A different resource on the same node — NOT suppressed.
        assert!(!store.suppresses(
            "service_bound_publicly",
            &pscope("node-a", Some("postgres:5432")),
        ));
        // A different finding_type — NOT suppressed.
        assert!(!store.suppresses(
            "weak_ssh_auth",
            &pscope("node-a", Some("mariadb:3306")),
        ));
    }

    #[test]
    fn cluster_ack_suppresses_all_nodes() {
        let mut store = AckStore::default();
        store.add(Ack::new(
            "ntp_drift",
            AckScope::Cluster,
            "no NTP available, GPS time source instead",
            "paul",
            None,
        ));
        assert!(store.suppresses("ntp_drift", &pscope("node-a", None)));
        assert!(store.suppresses("ntp_drift", &pscope("node-b", Some("eth0"))));
    }

    #[test]
    fn expired_ack_does_not_suppress() {
        let mut store = AckStore::default();
        let mut a = Ack::new(
            "disk_fill_eta",
            AckScope::Cluster,
            "x", "paul",
            Some(Duration::days(1)),
        );
        a.expires = Some(Utc::now() - Duration::hours(1));
        store.add(a);

        assert!(!store.suppresses("disk_fill_eta", &pscope("node-a", Some("/var"))));
    }

    #[test]
    fn prune_drops_expired_only() {
        let mut store = AckStore::default();
        let mut expired = Ack::new("a", AckScope::Cluster, "r", "p", None);
        expired.expires = Some(Utc::now() - Duration::days(1));
        store.add(expired);
        store.add(Ack::new("b", AckScope::Cluster, "r", "p", None));

        let dropped = store.prune_expired();
        assert_eq!(dropped, 1);
        assert_eq!(store.acks.len(), 1);
        assert_eq!(store.acks[0].finding_type, "b");
    }

    #[test]
    fn expiring_within_window() {
        let mut store = AckStore::default();
        let mut soon = Ack::new("a", AckScope::Cluster, "r", "p", None);
        soon.expires = Some(Utc::now() + Duration::days(5));
        let mut later = Ack::new("b", AckScope::Cluster, "r", "p", None);
        later.expires = Some(Utc::now() + Duration::days(60));
        store.add(soon);
        store.add(later);

        let near = store.expiring_within(10);
        assert_eq!(near.len(), 1);
        assert_eq!(near[0].finding_type, "a");
    }
}
