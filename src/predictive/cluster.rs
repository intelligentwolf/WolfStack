// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Cluster-wide proposal aggregation.
//!
//! Each node's orchestrator produces proposals locally; this module
//! pulls them together so the Inbox UI shows findings from every
//! reachable peer at once. The data flow:
//!
//!   1. The dashboard hits `GET /api/proposals/cluster` on any node.
//!   2. That node consults a 30-second cache. On a miss, it fans out
//!      to every other online cluster peer's `/api/proposals` (using
//!      `X-WolfStack-Secret` for inter-node auth, with a 5 s
//!      per-peer timeout).
//!   3. Local proposals + per-peer results are merged into a single
//!      list, sorted Critical→Info / most-recent first.
//!   4. Per-peer status (responded / failed / unreachable) is
//!      surfaced so the UI can warn the operator if the Inbox is
//!      incomplete instead of silently showing partial data.
//!
//! ## Cache invalidation
//!
//! Every state-changing predictive endpoint (snooze, dismiss,
//! approve, run-now, ack create+delete) clears the cache. Operator
//! actions should produce immediate refreshes, not wait the 30 s
//! TTL.
//!
//! ## Why not push?
//!
//! A push model would have each node POST its proposals to a
//! "leader". That requires leader election and a sync protocol; pull
//! is consistent with the existing 10 s cluster polling pattern and
//! gracefully degrades when a peer is unreachable (just shows a
//! stale-data warning instead of hanging).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::Proposal;

/// How long the aggregated response is cached before another
/// peer-fan-out is performed. Refreshing a dashboard every couple of
/// seconds shouldn't translate into one round-trip per peer per
/// refresh.
pub const CACHE_TTL_SECS: u64 = 30;

/// Per-peer fetch timeout. Long enough to cover slow LANs / loaded
/// peers, short enough that a fully-unreachable peer doesn't keep
/// the rest of the dashboard waiting.
pub const PEER_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterProposalsResponse {
    pub proposals: Vec<Proposal>,
    pub nodes: Vec<NodeAggregateStatus>,
    /// 0 when this response was just built; otherwise the age of
    /// the cached entry in seconds. Lets the UI decide whether to
    /// show a "fresh / stale" indicator.
    pub cached_for_seconds: u64,
}

/// Per-node fetch outcome surfaced to the UI. The only way the
/// operator should see a "Inbox incomplete" warning is via this
/// list — never a silent gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAggregateStatus {
    pub node_id: String,
    pub hostname: String,
    pub is_self: bool,
    pub responded: bool,
    /// `Some` when `responded == false`. Short, operator-readable
    /// reason: "timeout", "auth rejected (HTTP 403)", "connection
    /// refused", etc. Never a stack trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// User-facing cluster grouping — `cluster_name` for
    /// WolfStack-typed nodes, `pve_cluster_name` for Proxmox.
    /// Falls back to `"WolfStack"` for older WolfStack nodes
    /// without a cluster name and `address` for Proxmox without
    /// one. Mirrors the resolution rule in app.js so the Inbox
    /// groups consistently with the rest of the dashboard.
    #[serde(default)]
    pub cluster_name: String,
}

/// Sort proposals as the inbox would: Critical first, then by
/// most-recently updated.
///
/// `Severity::rank()` returns `Critical=0, High=1, Warn=2, Info=3`,
/// so ascending `cmp` puts Critical first. The inner `b.updated_at
/// .cmp(&a.updated_at)` is reversed-arg order to get descending
/// recency within a tier.
pub fn sort_proposals(proposals: &mut [Proposal]) {
    proposals.sort_by(|a, b| {
        a.severity.rank().cmp(&b.severity.rank())
            .then_with(|| b.updated_at.cmp(&a.updated_at))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::proposal::{
        ProposalScope, RemediationPlan, Severity,
    };

    fn p(node: &str, sev: Severity, finding: &str) -> Proposal {
        Proposal::new_rule(
            finding,
            sev,
            "title", "why", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            ProposalScope { node_id: node.into(), resource_id: None },
        )
    }

    #[test]
    fn sort_puts_critical_first_then_recency() {
        let mut all = vec![
            p("a", Severity::Warn, "f1"),
            p("b", Severity::Critical, "f2"),
            p("c", Severity::Info, "f3"),
            p("d", Severity::High, "f4"),
        ];
        sort_proposals(&mut all);
        assert_eq!(all[0].severity, Severity::Critical);
        assert_eq!(all[1].severity, Severity::High);
        assert_eq!(all[2].severity, Severity::Warn);
        assert_eq!(all[3].severity, Severity::Info);
    }

    #[test]
    fn sort_is_stable_within_same_severity() {
        let mut p1 = p("a", Severity::Warn, "f1");
        let mut p2 = p("b", Severity::Warn, "f2");
        // p2 is more-recently updated.
        p1.updated_at = chrono::Utc::now() - chrono::Duration::minutes(5);
        p2.updated_at = chrono::Utc::now();
        let mut all = vec![p1.clone(), p2.clone()];
        sort_proposals(&mut all);
        assert_eq!(all[0].id, p2.id, "more-recent updated_at sorts first within tier");
    }

    #[test]
    fn response_serializes_cached_for_seconds() {
        // Belt-and-braces — the field name shows up in the UI's
        // optimistic cache check, so keep it pinned.
        let resp = ClusterProposalsResponse {
            proposals: vec![],
            nodes: vec![],
            cached_for_seconds: 12,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"cached_for_seconds\":12"));
    }
}
