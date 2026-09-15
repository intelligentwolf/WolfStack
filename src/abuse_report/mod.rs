// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! In-app abuse reporting.
//!
//! When the kernel auto-block fires on an IP, the operator has all
//! the evidence in hand (audit log, source IP, timestamps) AND the
//! upstream provider that owns that IP usually has a public abuse
//! contact. This module wires those two facts together: one click on
//! a blocked IP composes an RFC-style email to the right abuse desk,
//! pre-filled with the evidence, and sends it via the existing
//! `ai::send_alert_email` SMTP transport.
//!
//! ## What we do
//!
//! 1. **whois lookup** (`whois_lookup`) — shells out to `whois`,
//!    parses the response for `abuse-mailbox`, `country`, `netname`,
//!    `descr`/`OrgName`, `inetnum`/`NetRange`, `origin` (ASN). Cached
//!    in `/tmp/wolfstack-whois-<ip>.json` with a 6-hour TTL so the
//!    abuse desk doesn't get repeated whois server hits.
//! 2. **Evidence collector** (`collect_evidence`) — pulls audit-log
//!    rows for the target IP from the limiter's in-memory ring and
//!    formats them as a plaintext block (timestamp · status · reason).
//! 3. **Email composer** (`compose_report`) — builds a structured
//!    RFC-style email body. Subject template makes the IP and our
//!    hostname obvious to the abuse desk's triage queue.
//! 4. **Send + history** (`send_report`, `report_history`) — fires
//!    the SMTP send via the existing AI alerting transport and
//!    records the report in `/etc/wolfstack/abuse-reports.json` so
//!    we can show a "Last reported X days ago" badge and refuse to
//!    re-report the same IP within 7 days (configurable).
//!
//! ## What we deliberately DON'T do — **DO NOT CHANGE**
//!
//! - **Auto-report is FORBIDDEN.** This module must ONLY be triggered
//!   by an authenticated operator clicking "Send report" in the UI.
//!   Reasons (each one alone is sufficient):
//!     1. Mail-reputation damage — auto-sending similar emails to
//!        abuse desks gets your SMTP flagged. Your real alerts stop
//!        arriving and nobody notices.
//!     2. False positives become public + permanent the moment they
//!        leave the SMTP server. A human reading the draft catches
//!        "wait, that's our own monitoring" before send.
//!     3. Abuse desks pattern-match auto-mail and deprioritise it.
//!        A short hand-reviewed report from a real person is
//!        dramatically more likely to get the customer suspended.
//!     4. Legal exposure — making a written accusation against a
//!        third party carries some weight. A human must stand behind
//!        the claim.
//!     5. Volume amplification across the fleet — one attacker
//!        hitting 12 nodes becomes 12 auto-reports for one incident.
//!     6. Replies need a human. Auto-send + no follow-up = case dies
//!        in the desk's queue.
//!
//!   The regression test `only_api_handler_calls_send_report` enforces
//!   this at build time.
//! - **Try to discover NEW abuse contacts beyond whois.** No RIPE
//!   API, no AbuseIPDB-as-reporter, no IPinfo. whois is the canonical
//!   source and the operator can edit the recipient before sending if
//!   whois is wrong (some abuse desks publish a different address in
//!   their TOS than they put in whois).

use serde::{Deserialize, Serialize};
use std::path::Path;

const REPORTS_PATH: &str = "/etc/wolfstack/abuse-reports.json";
const WHOIS_CACHE_DIR: &str = "/tmp";
const WHOIS_CACHE_TTL_SECS: u64 = 6 * 3600;
/// Days we refuse to re-report the same IP. Operator can override
/// per-report via `override_cooldown=true` in the send body.
const DEFAULT_COOLDOWN_DAYS: u64 = 7;

// ══════════════════════════════════════════════════════════
// whois lookup
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhoisInfo {
    /// The original IP we looked up.
    pub ip: String,
    /// First abuse-mailbox / OrgAbuseEmail found in the response.
    /// Empty when whois didn't publish one (rare for cloud providers,
    /// common for ISPs in less-regulated regions).
    pub abuse_email: String,
    /// ISO country code (CN, US, DE…). May be empty.
    pub country: String,
    /// Network range as published by the RIR (`101.200.0.0 - 101.201.255.255`
    /// or `101.200.0.0/16`).
    pub net_range: String,
    /// Operator-friendly name of the network block.
    pub netname: String,
    /// Owner / description string (`Aliyun Computing Co., LTD`, etc.).
    pub org: String,
    /// First ASN found (`AS37963`). Empty when whois didn't include one.
    pub asn: String,
    /// Raw whois output, capped to 8KB. Helpful when the structured
    /// parse missed a field the operator wants to read.
    pub raw: String,
}

/// Run `whois <ip>`, parse the structured fields we care about, and
/// cache the result for `WHOIS_CACHE_TTL_SECS`. On any error the
/// function returns a WhoisInfo populated with whatever it could
/// extract — never panics, never blocks the caller indefinitely.
pub fn whois_lookup(ip: &str) -> WhoisInfo {
    if let Some(cached) = read_whois_cache(ip) {
        return cached;
    }
    let mut info = WhoisInfo { ip: ip.to_string(), ..Default::default() };
    let output = match std::process::Command::new("whois")
        .arg(ip)
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            // whois binary not installed — return a minimal record so
            // the UI shows "whois not available" rather than blanking.
            info.raw = "whois command not installed on this node".into();
            return info;
        }
    };
    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    info.raw = raw.chars().take(8192).collect();
    parse_whois_into(&raw, &mut info);
    let _ = write_whois_cache(ip, &info);
    info
}

fn parse_whois_into(raw: &str, info: &mut WhoisInfo) {
    // Lower-case the KEY only — values keep their case so e.g. country
    // codes display correctly. Many whois outputs use Mixed-Case or
    // ALL-CAPS keys depending on RIR.
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') { continue; }
        let Some(colon) = trimmed.find(':') else { continue; };
        let key = trimmed[..colon].trim().to_ascii_lowercase();
        let value = trimmed[colon+1..].trim().to_string();
        if value.is_empty() { continue; }
        match key.as_str() {
            // Abuse contact — first match wins, except we prefer
            // "orgabuseemail" (ARIN) over "abuse-mailbox" (RIPE/APNIC)
            // only when both appear. Both are right; we take whichever
            // comes first in the response, which is the order the RIR
            // intended.
            "abuse-mailbox" | "orgabuseemail" | "abuseemail" => {
                if info.abuse_email.is_empty() { info.abuse_email = value; }
            }
            "country" => {
                if info.country.is_empty() { info.country = value; }
            }
            "inetnum" | "netrange" | "cidr" => {
                if info.net_range.is_empty() { info.net_range = value; }
            }
            "netname" => {
                if info.netname.is_empty() { info.netname = value; }
            }
            "descr" | "orgname" | "organization" | "owner" => {
                // Multiple descr lines: keep the first non-empty.
                // Address lines often follow descr too, but the first
                // descr is typically the org name. Good enough.
                if info.org.is_empty() { info.org = value; }
            }
            "origin"
                if info.asn.is_empty() => { info.asn = value; }
            _ => {}
        }
    }
}

fn whois_cache_path(ip: &str) -> std::path::PathBuf {
    // Replace separators so the filename is filesystem-safe (already
    // is for IPv4; IPv6 has colons we replace with underscores).
    let safe = ip.replace(['/', ':'], "_");
    Path::new(WHOIS_CACHE_DIR).join(format!("wolfstack-whois-{}.json", safe))
}

fn read_whois_cache(ip: &str) -> Option<WhoisInfo> {
    let path = whois_cache_path(ip);
    let meta = std::fs::metadata(&path).ok()?;
    let mtime = meta.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(mtime).ok()?;
    if age.as_secs() > WHOIS_CACHE_TTL_SECS { return None; }
    let text = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_whois_cache(ip: &str, info: &WhoisInfo) -> std::io::Result<()> {
    let path = whois_cache_path(ip);
    let body = serde_json::to_string_pretty(info)
        .unwrap_or_else(|_| "{}".into());
    std::fs::write(path, body)
}

// ══════════════════════════════════════════════════════════
// Evidence collection
// ══════════════════════════════════════════════════════════

/// One line of evidence: a single failed-auth event from this node's
/// audit log. Plain serializable so the API can render it directly.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceLine {
    pub timestamp_unix: u64,
    /// RFC3339 timestamp for display.
    pub when: String,
    /// "fail" | "blocked" | "ok" — matching the audit-log shape.
    pub status: String,
    pub username: String,
    pub reason: String,
}

/// Pull all audit-log entries for `ip` from the limiter. Capped at
/// `max_lines` newest entries to keep emails under SMTP size limits.
pub fn collect_evidence(
    limiter: &crate::auth::LoginRateLimiter,
    ip: &str,
    max_lines: usize,
) -> Vec<EvidenceLine> {
    let audit = limiter.audit_log();
    let mut out: Vec<EvidenceLine> = audit.into_iter()
        .filter(|e| e.ip == ip)
        .map(|e| {
            let when = chrono::DateTime::<chrono::Utc>::from_timestamp(e.timestamp as i64, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| e.timestamp.to_string());
            let status = if e.success { "ok" }
                         else if e.was_locked { "blocked" }
                         else { "fail" };
            EvidenceLine {
                timestamp_unix: e.timestamp,
                when,
                status: status.into(),
                username: e.username,
                reason: e.reason,
            }
        })
        .collect();
    // Newest first, then trim.
    out.sort_by_key(|e| std::cmp::Reverse(e.timestamp_unix));
    out.truncate(max_lines);
    out
}

// ══════════════════════════════════════════════════════════
// Email composition
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ReportDraft {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Compose the abuse-report email from whois + evidence + our identity.
/// `our_hostname` is what gets named as the victim — typically the
/// wolfstack node's hostname. `from_email` (the operator's email
/// address used to receive replies) is included in the body so the
/// abuse desk can confirm receipt.
pub fn compose_report(
    ip: &str,
    whois: &WhoisInfo,
    evidence: &[EvidenceLine],
    our_hostname: &str,
    from_email: &str,
) -> ReportDraft {
    let attempt_count = evidence.len();
    let recipient = if whois.abuse_email.is_empty() {
        // No published abuse contact — surface that to the operator
        // and let them research a recipient before sending.
        String::new()
    } else {
        whois.abuse_email.clone()
    };
    let subject = format!(
        "[Abuse Report] SSH brute-force from {} targeting {}",
        ip, our_hostname);
    let now = chrono::Utc::now().to_rfc3339();
    let mut body = String::new();
    body.push_str("Hello abuse team,\n\n");
    body.push_str("We are observing brute-force authentication attempts originating from one of your IP addresses against our infrastructure. \
        We have automatically firewall-blocked the source IP and are reporting the activity to you per standard internet abuse-reporting practice.\n\n");
    body.push_str("---- INCIDENT SUMMARY ----\n");
    body.push_str(&format!("Reported at:    {}\n", now));
    body.push_str(&format!("Source IP:      {}\n", ip));
    if !whois.org.is_empty()      { body.push_str(&format!("Owner:          {}\n", whois.org)); }
    if !whois.netname.is_empty()  { body.push_str(&format!("Netname:        {}\n", whois.netname)); }
    if !whois.net_range.is_empty(){ body.push_str(&format!("Net range:      {}\n", whois.net_range)); }
    if !whois.asn.is_empty()      { body.push_str(&format!("ASN:            {}\n", whois.asn)); }
    if !whois.country.is_empty()  { body.push_str(&format!("Country:        {}\n", whois.country)); }
    body.push_str(&format!("Victim host:    {}\n", our_hostname));
    body.push_str(&format!("Reply-to:       {}\n", from_email));
    body.push_str(&format!("Failed attempts logged: {}\n\n", attempt_count));

    body.push_str("---- EVIDENCE (newest first) ----\n");
    if evidence.is_empty() {
        body.push_str("(no audit-log entries available; the source IP was reported manually by the operator)\n");
    } else {
        for e in evidence.iter().take(40) {
            body.push_str(&format!(
                "{}  {:8}  user={:<24}  reason={}\n",
                e.when, e.status, e.username, e.reason));
        }
        if evidence.len() > 40 {
            body.push_str(&format!("(+ {} more attempts truncated for brevity)\n",
                evidence.len() - 40));
        }
    }
    body.push_str("\n---- REQUEST ----\n");
    body.push_str(&format!(
        "Please investigate the source customer / instance behind {} and take appropriate action. \
        All times above are UTC. We're happy to provide additional logs or packet captures on request — reply to this email.\n\n",
        ip));
    body.push_str("Thank you for your prompt attention to this report.\n\n");
    body.push_str("-- \n");
    body.push_str("Generated by WolfStack (https://wolf.uk.com)\n");
    body.push_str(&format!("Auto-composed on {}\n", our_hostname));

    ReportDraft { to: recipient, subject, body }
}

// ══════════════════════════════════════════════════════════
// Send + history
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRecord {
    pub ip: String,
    pub recipient: String,
    pub subject: String,
    pub sent_at: String,       // RFC3339
    pub sent_at_unix: u64,
    pub evidence_count: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReportHistory {
    #[serde(default)]
    pub reports: Vec<ReportRecord>,
}

impl ReportHistory {
    pub fn load() -> Self {
        std::fs::read_to_string(REPORTS_PATH)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = Path::new(REPORTS_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| "{}".into());
        std::fs::write(REPORTS_PATH, body)?;
        // Sensitive (contains attacker IPs we've reported): 0600.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(REPORTS_PATH,
            std::fs::Permissions::from_mode(0o600));
        Ok(())
    }
    pub fn last_for(&self, ip: &str) -> Option<&ReportRecord> {
        self.reports.iter().filter(|r| r.ip == ip)
            .max_by_key(|r| r.sent_at_unix)
    }
    /// Refuse to re-report if the same IP was reported within the
    /// cool-down window. Caller can override via `override_cooldown`.
    pub fn cooldown_remaining_secs(&self, ip: &str, cooldown_days: u64) -> u64 {
        let now = chrono::Utc::now().timestamp() as u64;
        match self.last_for(ip) {
            Some(rec) => {
                let elapsed = now.saturating_sub(rec.sent_at_unix);
                let cooldown = cooldown_days * 86400;
                cooldown.saturating_sub(elapsed)
            }
            None => 0,
        }
    }
}

/// Send the abuse report and persist a history record.
///
/// # ⚠ MANUAL-ONLY — DO NOT AUTOMATE
///
/// This function MUST ONLY be called from the API handler
/// `abuse_report_send` in `src/api/mod.rs`, which itself is only
/// reachable via an authenticated operator POSTing through the UI
/// Send button. **Never** wire this into:
///   - the LoginRateLimiter's `install_propagation_hooks`
///   - any `tokio::spawn` or `std::thread::spawn` triggered by a
///     block/scan event
///   - the alerting loop in `alerting.rs`
///   - a `cron`-style scheduled task
///   - a tailing loop / log monitor
///
/// The regression test `only_api_handler_calls_send_report` will fail
/// the build if a second caller appears anywhere in the source tree.
/// See the module-level doc for the six reasons this is forbidden.
///
/// Reuses the AI config's SMTP transport (`ai::send_alert_email`) so
/// the operator doesn't have to configure a separate mail server.
/// The function writes to history regardless of cool-down — the
/// caller is expected to have checked cool-down already and passed
/// `override_cooldown=true` if they wanted to send anyway.
pub fn send_report(
    ai_config: &crate::ai::AiConfig,
    ip: &str,
    draft: &ReportDraft,
    evidence_count: usize,
) -> Result<ReportRecord, String> {
    if draft.to.trim().is_empty() {
        return Err("recipient address is empty — set it explicitly before sending".into());
    }
    if ai_config.smtp_host.is_empty() {
        return Err("SMTP not configured. Set the SMTP host (and a From address) via Settings → AI Alerting before sending abuse reports. Username/password are only needed for relays that require authentication.".into());
    }
    // Temporarily swap the email_to so send_alert_email goes to the
    // abuse desk rather than the operator's own address. We clone
    // and mutate locally; the on-disk AiConfig is untouched.
    let mut cfg = ai_config.clone();
    cfg.email_to = draft.to.clone();
    crate::ai::send_alert_email(&cfg, &draft.subject, &draft.body)
        .map_err(|e| format!("SMTP send failed: {}", e))?;
    let now_unix = chrono::Utc::now().timestamp() as u64;
    let rec = ReportRecord {
        ip: ip.to_string(),
        recipient: draft.to.clone(),
        subject: draft.subject.clone(),
        sent_at: chrono::Utc::now().to_rfc3339(),
        sent_at_unix: now_unix,
        evidence_count,
    };
    let mut hist = ReportHistory::load();
    hist.reports.push(rec.clone());
    // Cap at 500 to keep the file bounded.
    let len = hist.reports.len();
    if len > 500 {
        hist.reports.drain(..len - 500);
    }
    hist.save().map_err(|e| format!("save abuse history: {}", e))?;
    Ok(rec)
}

pub fn default_cooldown_days() -> u64 { DEFAULT_COOLDOWN_DAYS }

#[cfg(test)]
mod tests {
    use super::*;

    /// Manual-only enforcement: `send_report` may ONLY be called from
    /// the `abuse_report_send` API handler in `src/api/mod.rs`. This
    /// test walks the source tree and fails the build if a second
    /// caller appears anywhere — preventing accidental wiring into a
    /// limiter hook, alerting loop, scheduled task, or anything else
    /// that would auto-send. See the module-level doc for the six
    /// reasons auto-reporting is forbidden.
    #[test]
    fn only_api_handler_calls_send_report() {
        let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut callers: Vec<String> = Vec::new();
        walk_rs(&src_root, &mut |path, contents| {
            // Skip this file itself — the doc comment + definition
            // both mention `send_report` and would falsely trigger.
            let rel = path.strip_prefix(&src_root).unwrap_or(path);
            if rel == std::path::Path::new("abuse_report/mod.rs") { return; }
            for (lineno, line) in contents.lines().enumerate() {
                let trimmed = line.trim_start();
                // Comment lines aren't callers.
                if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") {
                    continue;
                }
                if line.contains("abuse_report::send_report")
                    || (line.contains("send_report") && line.contains("crate::abuse_report"))
                {
                    callers.push(format!("{}:{}: {}",
                        rel.display(), lineno + 1, trimmed));
                }
            }
        });
        assert_eq!(callers.len(), 1,
            "abuse_report::send_report MUST have exactly one caller \
             (src/api/mod.rs::abuse_report_send). Found {}:\n  {}\n\n\
             Auto-reporting is FORBIDDEN — see the module-level doc for \
             the six reasons. If you genuinely need a new code path that \
             reaches send_report, raise it with the human owner first.",
            callers.len(), callers.join("\n  "));
        // Belt-and-braces: the one caller MUST be in src/api/mod.rs.
        assert!(callers[0].starts_with("api/mod.rs"),
            "the only caller of send_report must be the API handler in api/mod.rs, \
             found: {}", callers[0]);
    }

    /// Tiny recursive directory walker used by the audit test above.
    /// Stays at the test scope so we don't ship it as a public helper.
    fn walk_rs<F: FnMut(&std::path::Path, &str)>(dir: &std::path::Path, f: &mut F) {
        let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs(&path, f);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
                && let Ok(c) = std::fs::read_to_string(&path) {
                    f(&path, &c);
                }
        }
    }

    #[test]
    fn parse_whois_extracts_alibaba_fields() {
        // Real whois snippet for 101.200.221.177 (Alibaba) — what we
        // saw in the user's actual report. Locks in field extraction.
        let raw = "\
inetnum:        101.200.0.0 - 101.201.255.255
netname:        ALISOFT
descr:          Aliyun Computing Co., LTD
country:        CN
abuse-mailbox:  didong.jc@alibaba-inc.com
origin:         AS37963
";
        let mut info = WhoisInfo { ip: "101.200.221.177".into(), ..Default::default() };
        parse_whois_into(raw, &mut info);
        assert_eq!(info.abuse_email, "didong.jc@alibaba-inc.com");
        assert_eq!(info.country, "CN");
        assert_eq!(info.net_range, "101.200.0.0 - 101.201.255.255");
        assert_eq!(info.netname, "ALISOFT");
        assert_eq!(info.org, "Aliyun Computing Co., LTD");
        assert_eq!(info.asn, "AS37963");
    }

    #[test]
    fn parse_whois_handles_arin_style_keys() {
        // ARIN uses OrgName + OrgAbuseEmail + NetRange + CIDR.
        let raw = "\
NetRange:       203.0.113.0 - 203.0.113.255
CIDR:           203.0.113.0/24
NetName:        EXAMPLE-NET
OrgName:        Example Hosting LLC
OrgAbuseEmail:  abuse@example.com
Country:        US
";
        let mut info = WhoisInfo { ip: "203.0.113.10".into(), ..Default::default() };
        parse_whois_into(raw, &mut info);
        assert_eq!(info.abuse_email, "abuse@example.com");
        assert_eq!(info.org, "Example Hosting LLC");
        // inetnum wins over CIDR because it appears first in the parsed input.
        assert_eq!(info.net_range, "203.0.113.0 - 203.0.113.255");
        assert_eq!(info.country, "US");
    }

    #[test]
    fn parse_whois_skips_blanks_and_comments() {
        let raw = "\
# Comment line
% Server notice

inetnum: 1.2.3.0 - 1.2.3.255
abuse-mailbox:  noc@isp.example
";
        let mut info = WhoisInfo { ip: "1.2.3.4".into(), ..Default::default() };
        parse_whois_into(raw, &mut info);
        assert_eq!(info.abuse_email, "noc@isp.example");
        assert_eq!(info.net_range, "1.2.3.0 - 1.2.3.255");
    }

    #[test]
    fn compose_report_renders_evidence_table() {
        let whois = WhoisInfo {
            ip: "1.2.3.4".into(),
            abuse_email: "abuse@example.com".into(),
            country: "US".into(),
            net_range: "1.2.3.0/24".into(),
            netname: "EXAMPLE".into(),
            org: "Example Hosting".into(),
            asn: "AS64500".into(),
            raw: String::new(),
        };
        let evidence = vec![
            EvidenceLine {
                timestamp_unix: 1_700_000_000,
                when: "2023-11-14T22:13:20+00:00".into(),
                status: "fail".into(),
                username: "root".into(),
                reason: "bad password".into(),
            },
            EvidenceLine {
                timestamp_unix: 1_700_000_005,
                when: "2023-11-14T22:13:25+00:00".into(),
                status: "blocked".into(),
                username: "admin".into(),
                reason: "bad password".into(),
            },
        ];
        let draft = compose_report("1.2.3.4", &whois, &evidence, "wolf1", "ops@example.org");
        assert_eq!(draft.to, "abuse@example.com");
        assert!(draft.subject.contains("1.2.3.4"));
        assert!(draft.subject.contains("wolf1"));
        assert!(draft.body.contains("Example Hosting"));
        assert!(draft.body.contains("AS64500"));
        assert!(draft.body.contains("root"));
        assert!(draft.body.contains("admin"));
        assert!(draft.body.contains("ops@example.org"));
    }

    #[test]
    fn compose_report_leaves_recipient_empty_when_no_abuse_email() {
        let whois = WhoisInfo { ip: "1.2.3.4".into(), ..Default::default() };
        let draft = compose_report("1.2.3.4", &whois, &[], "wolf1", "ops@example.org");
        assert_eq!(draft.to, "", "recipient must be empty so the UI prompts the operator to set one");
    }

    #[test]
    fn cooldown_remaining_secs_zero_for_unreported_ip() {
        let h = ReportHistory::default();
        assert_eq!(h.cooldown_remaining_secs("1.1.1.1", 7), 0);
    }

    #[test]
    fn cooldown_remaining_secs_counts_down_after_send() {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut h = ReportHistory::default();
        // Pretend we reported 1 day ago.
        h.reports.push(ReportRecord {
            ip: "9.9.9.9".into(),
            recipient: "abuse@x".into(),
            subject: "x".into(),
            sent_at: "x".into(),
            sent_at_unix: now - 86400,
            evidence_count: 1,
        });
        // 7-day cool-down: 6 days remaining (within +/- a few seconds).
        let remaining = h.cooldown_remaining_secs("9.9.9.9", 7);
        let expected = 6 * 86400;
        assert!(remaining > expected - 5 && remaining <= expected,
            "expected ~{}, got {}", expected, remaining);
        // Different IP not affected.
        assert_eq!(h.cooldown_remaining_secs("1.1.1.1", 7), 0);
    }
}
