// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! Day-to-day management of a running mail cluster through Stalwart's JMAP
//! API: domains, mailboxes, aliases, credentials, DNS records, health.
//!
//! Configuration is shared through the data store, so any healthy node can
//! serve a change and every node sees it at once — accounts, domains and
//! DKIM keys take effect immediately (docs configuration/index.md "Applying
//! changes"). Calls go to the first node that answers.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

use super::jmap::{self, Auth};
use super::MailCluster;

fn auth(c: &MailCluster) -> Result<Auth, String> {
    let k = super::unseal(&c.api_key_enc);
    if k.is_empty() {
        return Err("This mail cluster has no stored API key (the install did not finish, or the cluster secret was rotated without re-keying). Remove and reinstall it.".into());
    }
    Ok(Auth::Bearer(k))
}

fn bases(c: &MailCluster) -> Vec<String> {
    c.mail_nodes.iter()
        .map(|n| format!("http://{}:{}", n.wolfnet_ip, super::preflight::STALWART_MGMT_PORT))
        .collect()
}

/// Run `f` against the first node that is reachable. Only transport failures
/// move on to the next node; a Stalwart error is returned as-is.
fn with_node<T>(c: &MailCluster, mut f: impl FnMut(&str, &Auth) -> Result<T, String>) -> Result<T, String> {
    let a = auth(c)?;
    let mut last = "the mail cluster has no nodes".to_string();
    for b in bases(c) {
        match f(&b, &a) {
            Err(e) if e.starts_with("could not reach Stalwart") => last = e,
            other => return other,
        }
    }
    Err(format!("No mail node answered. Last error: {}", last))
}

// ── Health ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct NodeHealth {
    pub node_id: String,
    pub label: String,
    pub stalwart_hostname: String,
    /// "ready", "not ready (HTTP 503)", "unreachable: …"
    pub state: String,
    pub ready: bool,
    /// Lease status from `ClusterNode` (active/stale/inactive), if known.
    pub lease: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterHealth {
    pub nodes: Vec<NodeHealth>,
    /// Messages in the outbound queue (capped at the query limit).
    pub queued_messages: Option<usize>,
    pub error: String,
}

pub fn health(c: &MailCluster, rt: &tokio::runtime::Handle) -> ClusterHealth {
    let mut nodes = vec![];
    for n in &c.mail_nodes {
        let url = format!("http://{}:{}/healthz/ready", n.wolfnet_ip, super::preflight::STALWART_MGMT_PORT);
        let (state, ready) = rt.block_on(async {
            match crate::api::API_HTTP_CLIENT.get(&url).timeout(Duration::from_secs(4)).send().await {
                Ok(r) => {
                    let st = r.status();
                    let _ = r.bytes().await; // drain (tests/resource_safety.rs)
                    if st.is_success() { ("ready".to_string(), true) } else { (format!("not ready (HTTP {})", st.as_u16()), false) }
                }
                Err(e) => (format!("unreachable: {}", e), false),
            }
        });
        nodes.push(NodeHealth {
            node_id: n.node_id.clone(), label: n.label.clone(),
            stalwart_hostname: n.stalwart_hostname.clone(), state, ready, lease: String::new(),
        });
    }
    let mut error = String::new();
    let mut queued_messages = None;
    let r = with_node(c, |b, a| {
        let leases = if c.mail_nodes.len() > 1 {
            jmap::query_get(rt, b, a, "ClusterNode", json!({}), None)?
        } else { vec![] };
        let q = jmap::call(rt, b, a, vec![json!(["x:QueuedMessage/query", { "filter": {}, "limit": 1000 }, "q"])])?;
        Ok((leases, q))
    });
    match r {
        Ok((leases, q)) => {
            for l in leases {
                let host = l.get("hostname").and_then(|h| h.as_str()).unwrap_or("");
                let st = l.get("status").and_then(|s| s.as_str()).unwrap_or("");
                if let Some(n) = nodes.iter_mut().find(|n| n.stalwart_hostname == host) {
                    n.lease = st.to_string();
                }
            }
            queued_messages = q.first().and_then(|r| r.get("ids")).and_then(|i| i.as_array()).map(|a| a.len());
        }
        Err(e) => error = e,
    }
    ClusterHealth { nodes, queued_messages, error }
}

// ── Domains ──────────────────────────────────────────────────────────

pub fn list_domains(c: &MailCluster, rt: &tokio::runtime::Handle) -> Result<Vec<Value>, String> {
    with_node(c, |b, a| jmap::get(rt, b, a, "Domain", None,
        Some(&["id", "name", "aliases", "enable", "description", "catchAllAddress", "certificateManagement"]), None))
}

#[derive(Debug, Clone, Deserialize)]
pub struct NewDomain {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Use the cluster's ACME provider for this domain's own names
    /// (mta-sts, autoconfig, …). Every name must resolve here first, or the
    /// whole order fails (docs server/tls/acme/configuration.md).
    #[serde(default)]
    pub request_tls_certificate: bool,
}

pub fn create_domain(c: &MailCluster, rt: &tokio::runtime::Handle, d: &NewDomain) -> Result<Value, String> {
    let name = d.name.trim().to_lowercase();
    if !super::valid_domain(&name) {
        return Err(format!("'{}' is not a valid domain name.", d.name));
    }
    with_node(c, |b, a| {
        // certificateManagement Automatic needs an AcmeProvider id (docs
        // ref/object/domain.md CertificateManagementProperties). The setup
        // step created one when the operator asked for a certificate.
        let cert = if d.request_tls_certificate {
            let providers = jmap::get(rt, b, a, "AcmeProvider", None, Some(&["id"]), None)?;
            let id = providers.first().and_then(|p| p.get("id")).and_then(|i| i.as_str())
                .ok_or("No ACME provider exists — the cluster was installed without a TLS certificate request. Add the domain without one, or configure ACME in Stalwart's admin.")?
                .to_string();
            json!({ "@type": "Automatic", "acmeProviderId": id })
        } else {
            json!({ "@type": "Manual" })
        };
        // Field set from docs ref/object/domain.md create example.
        let mut obj = json!({
            "name": name,
            "aliases": {},
            "certificateManagement": cert,
            "dnsManagement": { "@type": "Manual" },
            "dkimManagement": { "@type": "Automatic" },
            "subAddressing": { "@type": "Enabled" },
        });
        if !d.description.trim().is_empty() {
            obj["description"] = json!(d.description.trim());
        }
        jmap::create(rt, b, a, "Domain", obj, None)
    })
}

pub fn delete_domain(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str) -> Result<(), String> {
    with_node(c, |b, a| jmap::destroy(rt, b, a, "Domain", id, None))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    /// The value as a DNS provider's form wants it (TXT unquoted + joined).
    pub value: String,
}

/// Parse Stalwart's `dnsZoneFile`. Format from dns-update 0.6.2 src/bind.rs
/// `BindSerializer::serialize`: one `{name} IN {TYPE} {content}` line per
/// record; a TXT over 255 bytes is `{name} IN TXT (` then indented quoted
/// 255-byte chunks then `)`. TXT quotes and `\\`/`\"` escapes are removed so
/// the value pastes straight into a provider's form.
pub fn parse_zone(text: &str) -> Vec<DnsRecord> {
    fn unquote(s: &str) -> String {
        let s = s.trim();
        let s = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(s);
        s.replace("\\\"", "\"").replace("\\\\", "\\")
    }
    let mut out = vec![];
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(idx) = line.find(" IN ") else { continue };
        let name = line[..idx].trim().to_string();
        let rest = &line[idx + 4..];
        let (rtype, content) = match rest.split_once(' ') {
            Some((t, c)) => (t.to_string(), c.trim().to_string()),
            None => continue,
        };
        let value = if rtype == "TXT" && content == "(" {
            let mut joined = String::new();
            for l in lines.by_ref() {
                if l.trim() == ")" { break; }
                joined.push_str(&unquote(l));
            }
            joined
        } else if rtype == "TXT" {
            unquote(&content)
        } else {
            content
        };
        out.push(DnsRecord { name, rtype, value });
    }
    out
}

/// The records a domain needs: Stalwart's own set, plus the A/AAAA records
/// for the public hostname, which `dnsZoneFile` leaves out (docs
/// install/platform/docker.md Step 6) — one per mail node's public address.
pub fn domain_dns(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str) -> Result<Value, String> {
    let domain = with_node(c, |b, a| jmap::get(rt, b, a, "Domain", Some(vec![id.to_string()]), Some(&["id", "name", "dnsZoneFile"]), None))?
        .into_iter().next().ok_or("domain not found")?;
    let zone = domain.get("dnsZoneFile").and_then(|z| z.as_str()).unwrap_or("").to_string();
    let mut records = parse_zone(&zone);
    let host = format!("{}.", c.public_hostname.trim_end_matches('.'));
    for n in &c.mail_nodes {
        if n.public_ip.is_empty() { continue; }
        let rtype = if n.public_ip.contains(':') { "AAAA" } else { "A" };
        let r = DnsRecord { name: host.clone(), rtype: rtype.into(), value: n.public_ip.clone() };
        if !records.contains(&r) { records.insert(0, r); }
    }
    Ok(json!({
        "domain": domain.get("name"),
        "records": records,
        "zone_file": zone,
        "missing_public_ip": c.mail_nodes.iter().filter(|n| n.public_ip.is_empty()).map(|n| n.label.clone()).collect::<Vec<_>>(),
    }))
}

// ── Accounts ─────────────────────────────────────────────────────────

/// Accounts (users) of one domain. Filter `domainId` per docs
/// ref/object/account.md `x:Account/query`.
pub fn list_accounts(c: &MailCluster, rt: &tokio::runtime::Handle, domain_id: &str) -> Result<Vec<Value>, String> {
    let accounts = with_node(c, |b, a| jmap::query_get(rt, b, a, "Account", json!({ "domainId": domain_id }),
        Some(&["id", "@type", "name", "domainId", "emailAddress", "description", "aliases", "quotas", "usedDiskQuota", "permissions", "roles", "credentials"])))?;
    // Never send credential secrets to the browser — only whether the
    // password has two-factor enrolled and how many app passwords exist.
    Ok(accounts.into_iter().map(|mut acc| {
        let creds = acc.get("credentials").cloned().unwrap_or(Value::Null);
        let mut totp = false;
        let mut app_passwords = 0usize;
        if let Some(map) = creds.as_object() {
            for (_, cr) in map {
                match cr.get("@type").and_then(|t| t.as_str()) {
                    Some("Password") => totp = cr.get("otpUrl").map(|o| !o.is_null()).unwrap_or(false),
                    Some("AppPassword") => app_passwords += 1,
                    _ => {}
                }
            }
        }
        if let Some(o) = acc.as_object_mut() {
            o.remove("credentials");
            o.insert("two_factor".into(), json!(totp));
            o.insert("app_password_count".into(), json!(app_passwords));
            let suspended = o.get("permissions")
                .and_then(|p| p.get("disabledPermissions"))
                .and_then(|d| d.get("authenticate"))
                .and_then(|v| v.as_bool()).unwrap_or(false);
            o.insert("suspended".into(), json!(suspended));
        }
        acc
    }).collect())
}

fn valid_local_part(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c))
        && !s.starts_with('.') && !s.ends_with('.')
}

#[derive(Debug, Clone, Deserialize)]
pub struct NewAccount {
    pub name: String,
    pub domain_id: String,
    pub password: String,
    #[serde(default)]
    pub description: String,
    /// Mailbox quota in bytes; 0 = unlimited.
    #[serde(default)]
    pub quota_bytes: u64,
    #[serde(default)]
    pub admin: bool,
}

/// Minimum password length enforced here (Stalwart applies its own policy
/// too — docs auth/authentication/password.md).
pub const MIN_PASSWORD: usize = 12;

pub fn create_account(c: &MailCluster, rt: &tokio::runtime::Handle, n: &NewAccount) -> Result<Value, String> {
    let name = n.name.trim().to_lowercase();
    if !valid_local_part(&name) {
        return Err("The mailbox name may use letters, digits and . _ - + (it becomes name@domain).".into());
    }
    if n.password.chars().count() < MIN_PASSWORD {
        return Err(format!("Use a password of at least {} characters.", MIN_PASSWORD));
    }
    // Create body per docs auth/accounts/manage.md "Create a user".
    let mut obj = json!({
        "@type": "User",
        "name": name,
        "domainId": n.domain_id,
        "credentials": { "0": { "@type": "Password", "secret": n.password } },
        "roles": { "@type": if n.admin { "Admin" } else { "User" } },
        "permissions": { "@type": "Inherit" },
    });
    if !n.description.trim().is_empty() { obj["description"] = json!(n.description.trim()); }
    if n.quota_bytes > 0 { obj["quotas"] = json!({ "maxDiskQuota": n.quota_bytes }); }
    with_node(c, |b, a| jmap::create(rt, b, a, "Account", obj.clone(), None))
}

pub fn delete_account(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str) -> Result<(), String> {
    with_node(c, |b, a| jmap::destroy(rt, b, a, "Account", id, None))
}

/// Set a new password: patch `credentials/0/secret` (docs auth/accounts/
/// manage.md "Reset a password" — the Password is the
/// account's first credential for every account this module creates). Signs the account out of every OAuth app.
pub fn set_password(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str, password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(format!("Use a password of at least {} characters.", MIN_PASSWORD));
    }
    with_node(c, |b, a| jmap::update(rt, b, a, "Account", id, json!({ "credentials/0/secret": password }), None)).map(|_| ())
}

/// Remove two-factor: `credentials/0/otpUrl` → null (docs auth/
/// authentication/2fa.md "admin recovery").
pub fn reset_two_factor(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str) -> Result<(), String> {
    with_node(c, |b, a| jmap::update(rt, b, a, "Account", id, json!({ "credentials/0/otpUrl": null }), None)).map(|_| ())
}

/// Suspend = `permissions` Merge with authenticate/emailReceive/emailSend
/// disabled; resume = back to Inherit (docs auth/accounts/manage.md
/// "Suspend an account": there is no enabled flag).
pub fn set_suspended(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str, suspended: bool) -> Result<(), String> {
    let perms = if suspended {
        json!({ "@type": "Merge", "enabledPermissions": {}, "disabledPermissions": { "authenticate": true, "emailReceive": true, "emailSend": true } })
    } else {
        json!({ "@type": "Inherit" })
    };
    with_node(c, |b, a| jmap::update(rt, b, a, "Account", id, json!({ "permissions": perms }), None)).map(|_| ())
}

/// Set the quota (bytes; 0 removes it).
pub fn set_quota(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str, bytes: u64) -> Result<(), String> {
    let patch = if bytes == 0 { json!({ "quotas/maxDiskQuota": null }) } else { json!({ "quotas/maxDiskQuota": bytes }) };
    with_node(c, |b, a| jmap::update(rt, b, a, "Account", id, patch.clone(), None)).map(|_| ())
}

/// Replace the account's alias list. `aliases` is a list encoded as an
/// object keyed "0","1",… (docs auth/accounts/manage.md — lists are objects).
pub fn set_aliases(c: &MailCluster, rt: &tokio::runtime::Handle, id: &str, aliases: &[(String, String)]) -> Result<(), String> {
    let mut map = serde_json::Map::new();
    for (i, (local, domain_id)) in aliases.iter().enumerate() {
        let l = local.trim().to_lowercase();
        if !valid_local_part(&l) {
            return Err(format!("'{}' is not a valid alias name.", local));
        }
        map.insert(i.to_string(), json!({ "name": l, "domainId": domain_id }));
    }
    with_node(c, |b, a| jmap::update(rt, b, a, "Account", id, json!({ "aliases": Value::Object(map.clone()) }), None)).map(|_| ())
}

/// Create an app password for an account and return its secret (shown once).
/// An administrator acts for another account with the request-level
/// `accountId` (docs auth/accounts/manage.md "Add an app password or API
/// key"); the secret is returned in `created.<id>.secret` (stalwart
/// registry/mapping/account.rs:458-472).
pub fn create_app_password(c: &MailCluster, rt: &tokio::runtime::Handle, account_id: &str, description: &str) -> Result<String, String> {
    let desc = if description.trim().is_empty() { "Mail app" } else { description.trim() };
    let created = with_node(c, |b, a| jmap::create(rt, b, a, "AppPassword", json!({ "description": desc, "permissions": { "@type": "Inherit" }, "allowedIps": {} }), Some(account_id)))?;
    created.get("secret").and_then(|s| s.as_str()).map(|s| s.to_string())
        .ok_or_else(|| "Stalwart created the app password but did not return it.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bind_lines_and_long_txt() {
        let zone = "example.com. IN MX 10 mx.example.com.\n\
                    example.com. IN TXT \"v=spf1 mx -all\"\n\
                    202611e._domainkey.example.com. IN TXT (\n    \"v=DKIM1; k=rsa; p=AAAA\"\n    \"BBBB\"\n)\n\
                    _dmarc.example.com. IN TXT \"v=DMARC1; p=reject; rua=mailto:\\\"x\\\"\"\n\
                    _imaps._tcp.example.com. IN SRV 0 1 993 mx.example.com.\n";
        let r = parse_zone(zone);
        assert_eq!(r.len(), 5);
        assert_eq!(r[0], DnsRecord { name: "example.com.".into(), rtype: "MX".into(), value: "10 mx.example.com.".into() });
        assert_eq!(r[1].value, "v=spf1 mx -all");
        assert_eq!(r[2].value, "v=DKIM1; k=rsa; p=AAAABBBB");
        assert_eq!(r[3].value, "v=DMARC1; p=reject; rua=mailto:\"x\"");
        assert_eq!(r[4].rtype, "SRV");
    }

    #[test]
    fn local_parts() {
        assert!(valid_local_part("jane.doe"));
        assert!(valid_local_part("info+news"));
        assert!(!valid_local_part(".jane"));
        assert!(!valid_local_part("ja ne"));
        assert!(!valid_local_part("jane@x"));
    }
}
