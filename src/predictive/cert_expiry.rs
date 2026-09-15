// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Certificate expiry — Item 4 of the predictive plan.
//!
//! Surfaces certificates approaching expiry so operators see them
//! before browsers, status-page consumers, or inter-node TLS
//! handshakes start failing. Reads from two sources today:
//!
//! - **Let's Encrypt** — `certbot::list_certs()` already enumerates
//!   `/etc/letsencrypt/live/*` and reports `days_remaining`. We
//!   reuse that primitive verbatim; no new parsing.
//! - **WolfStack-managed TLS** — `/etc/wolfstack/tls/*.pem` (the
//!   dashboard's own cert chain). Parsed once per tick via `openssl
//!   x509 -enddate`.
//!
//! ## Severity tiers
//!
//! | Days remaining     | Severity   |
//! |--------------------|------------|
//! | < 3                | `Critical` |
//! | < 7                | `High`     |
//! | < 14               | `Warn`     |
//! | ≥ 14               | suppressed |
//!
//! Already-expired certs (negative days_remaining) get `Critical`.
//!
//! ## Why these thresholds
//!
//! 14 days is a comfortable lead time — Let's Encrypt's own
//! auto-renewal kicks in at 30 days, so a finding at 14 means
//! renewal has *already failed* twice. 7 days is the "this is
//! actually getting urgent" tier. 3 days is "page someone now".
//!
//! ## What this DOESN'T cover (yet)
//!
//! - **Status Pages monitor SSL** — that's a different concern
//!   (operator-monitored external URLs); separate analyzer.
//! - **Cluster-peer inter-node TLS** — covered by per-node TLS
//!   findings since each peer scans its own files.
//! - **Self-signed cert detection** — orthogonal posture finding,
//!   belongs with the security convergence (item 8).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::predictive::{
    Context,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    ack::AckStore,
};

pub const FINDING_TYPE: &str = "cert_expiry_window";

const CRITICAL_DAYS: i64 = 3;
const HIGH_DAYS: i64 = 7;
const WARN_DAYS: i64 = 14;

/// Where this cert lives — used as the `resource_id` so each cert
/// dedups separately and the operator can ack a specific cert.
#[derive(Debug, Clone, PartialEq)]
pub enum CertSource {
    /// Let's Encrypt cert under `/etc/letsencrypt/live/<name>/`.
    LetsEncrypt { name: String },
    /// File under `/etc/wolfstack/tls/`.
    WolfStackTls { path: PathBuf },
}

impl CertSource {
    pub fn resource_id(&self) -> String {
        match self {
            CertSource::LetsEncrypt { name } => format!("letsencrypt:{}", name),
            CertSource::WolfStackTls { path } => format!("wolfstack-tls:{}", path.display()),
        }
    }
    pub fn human_label(&self) -> String {
        match self {
            CertSource::LetsEncrypt { name } => format!("Let's Encrypt cert '{}'", name),
            CertSource::WolfStackTls { path } => format!("TLS cert at {}", path.display()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertFact {
    pub source: CertSource,
    pub domains: Vec<String>,
    pub days_remaining: i64,
    pub expires_iso: String,
}

/// Sample certs from both sources. Synchronous — both sources do
/// local file reads only (no network).
pub fn sample_certs_now() -> Vec<CertFact> {
    let mut out = Vec::new();

    // Source 1: Let's Encrypt via the existing certbot primitive.
    for s in crate::certbot::list_certs() {
        out.push(CertFact {
            source: CertSource::LetsEncrypt { name: s.name },
            domains: s.domains,
            days_remaining: s.days_remaining,
            expires_iso: s.expires,
        });
    }

    // Source 2: WolfStack-managed TLS in /etc/wolfstack/tls/.
    out.extend(scan_wolfstack_tls_dir(Path::new("/etc/wolfstack/tls")));

    out
}

/// Async timeout-bounded variant for the orchestrator.
pub async fn sample_certs_now_async(timeout: Duration) -> Vec<CertFact> {
    let fut = tokio::task::spawn_blocking(sample_certs_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::warn!("predictive: cert sampling task panicked: {}", e);
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(
                "predictive: cert sampling timed out after {}s — \
                 skipping cert-expiry analysis this tick",
                timeout.as_secs(),
            );
            Vec::new()
        }
    }
}

fn scan_wolfstack_tls_dir(dir: &Path) -> Vec<CertFact> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        // Pem chain conventions vary; accept the common extensions.
        // Ignore CSRs and key files — never useful for expiry.
        if !matches!(ext, "pem" | "crt" | "cer") { continue; }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
        if stem.contains("key") || stem.contains("csr") { continue; }

        if let Some(fact) = parse_cert_file(&path) {
            out.push(fact);
        }
    }
    out
}

/// Parse a PEM cert and return its expiry. Uses `openssl x509
/// -enddate` because adding a Rust x509 parser dependency just for
/// this is overkill and openssl is already required for everything
/// else WolfStack does with TLS.
fn parse_cert_file(path: &Path) -> Option<CertFact> {
    // Get expiry timestamp via `-enddate -noout` → "notAfter=Apr 30 12:34:56 2026 GMT"
    let out = Command::new("openssl")
        .args(["x509", "-noout", "-enddate", "-in"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    let date_str = text.trim().strip_prefix("notAfter=")?;

    // openssl prints in `MMM DD HH:MM:SS YYYY GMT` — chrono can
    // parse this format directly.
    let parsed = chrono::NaiveDateTime::parse_from_str(
        date_str.trim(),
        "%b %e %H:%M:%S %Y GMT",
    ).or_else(|_| chrono::NaiveDateTime::parse_from_str(
        date_str.trim(),
        "%b %d %H:%M:%S %Y GMT",
    )).ok()?;
    let expires_utc = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        parsed, chrono::Utc,
    );

    let days_remaining = (expires_utc - chrono::Utc::now()).num_days();

    // Pull SAN list as the cert's "domains" via `openssl x509
    // -text -noout` then grep. Keep it best-effort — a cert that
    // parses for expiry but not SANs still gets a useful finding.
    let domains = parse_cert_domains(path).unwrap_or_default();

    Some(CertFact {
        source: CertSource::WolfStackTls { path: path.to_path_buf() },
        domains,
        days_remaining,
        expires_iso: expires_utc.to_rfc3339(),
    })
}

fn parse_cert_domains(path: &Path) -> Option<Vec<String>> {
    let out = Command::new("openssl")
        .args(["x509", "-noout", "-text", "-in"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut domains = Vec::new();
    let mut in_san_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("X509v3 Subject Alternative Name") {
            in_san_block = true;
            continue;
        }
        if in_san_block {
            for part in trimmed.split(',') {
                if let Some(d) = part.trim().strip_prefix("DNS:") {
                    domains.push(d.to_string());
                }
            }
            // SAN block is a single line of comma-separated values
            // — exit after one line.
            break;
        }
    }
    if domains.is_empty() { None } else { Some(domains) }
}

/// Run the analyzer.
pub fn analyze(
    ctx: &Context,
    current: &[CertFact],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    for fact in current {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(fact.source.resource_id()),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }

        let Some(severity) = severity_for_days(fact.days_remaining) else { continue; };
        out.push(build_proposal(fact, &scope, severity));
    }
    out
}

/// Maps days-remaining to severity. Returns `None` when the cert is
/// comfortably outside the warning window.
pub fn severity_for_days(days: i64) -> Option<Severity> {
    if days < 0 { return Some(Severity::Critical); }
    if days < CRITICAL_DAYS { Some(Severity::Critical) }
    else if days < HIGH_DAYS { Some(Severity::High) }
    else if days < WARN_DAYS { Some(Severity::Warn) }
    else { None }
}

/// Per-source covered-scope set for auto-resolve. A cert that gets
/// renewed (days_remaining jumps back above 14) clears the previous
/// finding via this list.
pub fn covered_scopes(
    ctx: &Context,
    current: &[CertFact],
) -> Vec<(String, ProposalScope)> {
    current.iter().map(|f| (
        FINDING_TYPE.to_string(),
        ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(f.source.resource_id()),
        },
    )).collect()
}

fn build_proposal(fact: &CertFact, scope: &ProposalScope, severity: Severity) -> Proposal {
    let label = fact.source.human_label();
    let domain_summary = if fact.domains.is_empty() {
        "(no SAN list — check the cert manually)".to_string()
    } else if fact.domains.len() <= 3 {
        fact.domains.join(", ")
    } else {
        format!("{} (+{} more)", fact.domains[..3].join(", "), fact.domains.len() - 3)
    };

    let title = if fact.days_remaining < 0 {
        format!("{} has EXPIRED ({} days ago)", label, -fact.days_remaining)
    } else if fact.days_remaining < 1 {
        format!("{} expires within the day", label)
    } else {
        format!("{} expires in {} day{}", label, fact.days_remaining,
            if fact.days_remaining == 1 { "" } else { "s" })
    };

    let why = if fact.days_remaining < 0 {
        format!(
            "{} has already expired ({} days ago). Browsers, \
             status-page consumers, and any inter-node TLS \
             handshake using this cert will refuse to connect. \
             Renew immediately.",
            label, -fact.days_remaining,
        )
    } else {
        format!(
            "{} expires in {} day{} (covers {}). Let's Encrypt's \
             own auto-renewal kicks in at 30 days, so a finding at \
             14 days means renewal has already failed twice — \
             investigate the renewal pipeline before the cert lapses.",
            label, fact.days_remaining,
            if fact.days_remaining == 1 { "" } else { "s" },
            domain_summary,
        )
    };

    let evidence = vec![
        Evidence {
            label: "Days remaining".into(),
            value: fact.days_remaining.to_string(),
            detail: Some(format!("Expires at {}", fact.expires_iso)),
            links: Vec::new(),
        },
        Evidence {
            label: "Domains".into(),
            value: domain_summary,
            detail: if fact.domains.len() > 3 {
                Some(format!("Full list: {}", fact.domains.join(", ")))
            } else { None },
            links: Vec::new(),
        },
    ];

    let remediation = build_remediation(&fact.source);

    Proposal::new_rule(
        FINDING_TYPE, severity,
        title, why, evidence, remediation, scope.clone(),
    )
}

fn build_remediation(source: &CertSource) -> RemediationPlan {
    match source {
        CertSource::LetsEncrypt { name } => RemediationPlan::Manual {
            instructions: format!(
                "Let's Encrypt cert '{name}' is approaching expiry. \
                 Try a manual renewal first; if it fails, the issue \
                 is usually webroot challenge access (`/.well-known/\
                 acme-challenge/`) or DNS for the domain. Check the \
                 dashboard's Certificates page for renewal logs.",
                name = name,
            ),
            commands: vec![
                format!("sudo certbot renew --cert-name {} --dry-run    # preview", name),
                format!("sudo certbot renew --cert-name {}    # apply", name),
                format!("sudo certbot certificates --cert-name {}", name),
                format!("sudo journalctl -u certbot.timer -n 50 --no-pager"),
            ],
        },
        CertSource::WolfStackTls { path } => RemediationPlan::Manual {
            instructions: format!(
                "WolfStack-managed TLS cert at {} is approaching \
                 expiry. If this is a Let's Encrypt cert symlinked \
                 here, fix the renewal pipeline. If it's an \
                 operator-issued cert, replace via the Certificates \
                 page or by writing a fresh chain to this path.",
                path.display(),
            ),
            commands: vec![
                format!("sudo openssl x509 -noout -dates -in {}", path.display()),
                format!("sudo openssl x509 -noout -text -in {} | head -30", path.display()),
            ],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::NetworkSnapshot;
    use crate::predictive::proposal::ProposalStore;

    fn ctx() -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }

    fn fact_le(name: &str, days: i64) -> CertFact {
        CertFact {
            source: CertSource::LetsEncrypt { name: name.into() },
            domains: vec![format!("{}.example.com", name)],
            days_remaining: days,
            expires_iso: "2026-12-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn severity_thresholds() {
        // Already expired
        assert_eq!(severity_for_days(-5), Some(Severity::Critical));
        // Critical: <3 days
        assert_eq!(severity_for_days(0), Some(Severity::Critical));
        assert_eq!(severity_for_days(2), Some(Severity::Critical));
        // High: <7 days
        assert_eq!(severity_for_days(3), Some(Severity::High));
        assert_eq!(severity_for_days(6), Some(Severity::High));
        // Warn: <14 days
        assert_eq!(severity_for_days(7), Some(Severity::Warn));
        assert_eq!(severity_for_days(13), Some(Severity::Warn));
        // Suppressed: ≥14 days
        assert_eq!(severity_for_days(14), None);
        assert_eq!(severity_for_days(60), None);
    }

    #[test]
    fn analyzer_emits_for_expiring_cert() {
        let facts = vec![fact_le("api", 5)];
        let p = analyze(
            &ctx(), &facts, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::High);
        assert_eq!(p[0].finding_type, FINDING_TYPE);
        assert!(p[0].title.contains("api"));
        // Resource_id is source-prefixed so a Let's Encrypt cert
        // and a WolfStack TLS cert with the same logical name don't
        // collide.
        assert_eq!(p[0].scope.resource_id.as_deref(), Some("letsencrypt:api"));
    }

    #[test]
    fn analyzer_silent_for_fresh_certs() {
        let facts = vec![fact_le("api", 60)];
        let p = analyze(
            &ctx(), &facts, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty());
    }

    #[test]
    fn already_expired_is_critical() {
        let facts = vec![fact_le("dead", -5)];
        let p = analyze(
            &ctx(), &facts, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::Critical);
        assert!(p[0].title.contains("EXPIRED"));
    }

    #[test]
    fn ack_suppresses_finding() {
        let facts = vec![fact_le("api", 5)];
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_TYPE,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "letsencrypt:api".into(),
            },
            "deprecated cert, getting replaced this week",
            "paul", None,
        ));
        let p = analyze(&ctx(), &facts, &acks, &ProposalStore::default());
        assert!(p.is_empty());
    }

    #[test]
    fn resource_ids_distinguish_sources() {
        // Same logical name 'foo' on Let's Encrypt and WolfStack
        // TLS must produce distinct resource_ids so acks/snoozes
        // don't cross-talk.
        let le_id = CertSource::LetsEncrypt { name: "foo".into() }.resource_id();
        let ws_id = CertSource::WolfStackTls {
            path: PathBuf::from("/etc/wolfstack/tls/foo.pem"),
        }.resource_id();
        assert_ne!(le_id, ws_id);
        assert!(le_id.starts_with("letsencrypt:"));
        assert!(ws_id.starts_with("wolfstack-tls:"));
    }

    #[test]
    fn analyzer_can_stay_quiet() {
        let facts = vec![fact_le("ok", 90)];
        let p = analyze(
            &ctx(), &facts, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty());
    }

    #[test]
    fn covered_scopes_includes_every_sampled_cert() {
        let facts = vec![fact_le("a", 5), fact_le("b", 90)];
        let cov = covered_scopes(&ctx(), &facts);
        assert_eq!(cov.len(), 2);
        // Both included even though only one would emit a proposal —
        // that's deliberate: when the about-to-expire cert is
        // renewed, days_remaining jumps to 90 and the absence from
        // the next emit-set is what triggers auto_resolve.
    }
}
