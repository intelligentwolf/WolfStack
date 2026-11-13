// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! Minimal client for Stalwart's JMAP management API.
//!
//! Source: docs configuration/index.md "Configuration objects" — every
//! management object is reached with `POST /jmap/` using
//! `["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]` and methods
//! `x:<Type>/get|set|query`. Lists and sets are JSON objects, never arrays
//! (docs auth/accounts/manage.md: "Sending an array is rejected with an
//! `invalidPatch` error"). Registry objects default `accountId` to the
//! caller's own account (stalwart crates/jmap/src/api/request.rs:824-850).

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum Auth {
    Basic { user: String, password: String },
    /// API key `API_…` (docs auth/authentication/api-key.md: "in an
    /// `Authorization: Bearer API_...` header, for the management API").
    Bearer(String),
}

const USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];

/// One JMAP request with `calls` (each `[method, args, callId]`). Returns the
/// method responses in order. A method-level `error` response is turned into
/// Err with Stalwart's description.
pub fn call(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, calls: Vec<Value>) -> Result<Vec<Value>, String> {
    let url = format!("{}/jmap/", base.trim_end_matches('/'));
    let body = json!({ "using": USING, "methodCalls": calls });
    let auth = auth.clone();
    rt.block_on(async move {
        let mut req = crate::api::API_HTTP_CLIENT.post(&url)
            .timeout(Duration::from_secs(60))
            .json(&body);
        req = match &auth {
            Auth::Basic { user, password } => req.basic_auth(user, Some(password)),
            Auth::Bearer(t) => req.bearer_auth(t),
        };
        let resp = req.send().await.map_err(|e| format!("could not reach Stalwart at {}: {}", url, e))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // RFC 9457 problem+json (docs http/api.md): prefer `detail`/`title`.
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let msg = v.get("detail").or_else(|| v.get("title")).and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| text.chars().take(300).collect());
            return Err(format!("Stalwart returned HTTP {}: {}", status.as_u16(), msg));
        }
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("Stalwart sent an unreadable reply: {}", e))?;
        let responses = v.get("methodResponses").and_then(|r| r.as_array()).cloned()
            .ok_or("Stalwart reply had no methodResponses")?;
        let mut out = Vec::with_capacity(responses.len());
        for r in responses {
            let name = r.get(0).and_then(|n| n.as_str()).unwrap_or("");
            let args = r.get(1).cloned().unwrap_or(Value::Null);
            if name == "error" {
                let t = args.get("type").and_then(|t| t.as_str()).unwrap_or("error");
                let d = args.get("description").and_then(|t| t.as_str()).unwrap_or("");
                return Err(if d.is_empty() { t.to_string() } else { format!("{}: {}", t, d) });
            }
            out.push(args);
        }
        Ok(out)
    })
}

/// Turn a JMAP SetError object into a readable line.
pub fn set_error_text(e: &Value) -> String {
    let t = e.get("type").and_then(|t| t.as_str()).unwrap_or("error");
    let d = e.get("description").and_then(|t| t.as_str()).unwrap_or("");
    let props = e.get("properties").and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    // validationFailed carries per-field errors (bootstrap.rs:126-131).
    let ve = e.get("validationErrors").map(|v| v.to_string()).unwrap_or_default();
    let mut s = t.to_string();
    if !d.is_empty() { s.push_str(": "); s.push_str(d); }
    if !props.is_empty() { s.push_str(&format!(" (field: {})", props)); }
    if !ve.is_empty() && ve != "null" { s.push_str(&format!(" {}", ve)); }
    s
}

fn single(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, method: &str, args: Value) -> Result<Value, String> {
    call(rt, base, auth, vec![json!([method, args, "c1"])])?
        .into_iter().next().ok_or_else(|| format!("{}: empty reply", method))
}

/// `x:<Type>/set` create of one object. Returns the server's `created` entry
/// (carries `id`, and `secret` for credentials — stalwart crates/jmap/src/
/// registry/mapping/account.rs:458-530).
pub fn create(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, ty: &str, obj: Value, account_id: Option<&str>) -> Result<Value, String> {
    let mut args = json!({ "create": { "n1": obj } });
    if let Some(a) = account_id { args["accountId"] = json!(a); }
    let r = single(rt, base, auth, &format!("x:{}/set", ty), args)?;
    if let Some(e) = r.get("notCreated").and_then(|n| n.get("n1")) {
        return Err(set_error_text(e));
    }
    r.get("created").and_then(|c| c.get("n1")).cloned()
        .ok_or_else(|| format!("x:{}/set: Stalwart did not confirm the create", ty))
}

/// `x:<Type>/set` update (JSON-pointer patch keys allowed). `id` is
/// `singleton` for singleton objects (docs ref/object/bootstrap.md).
pub fn update(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, ty: &str, id: &str, patch: Value, account_id: Option<&str>) -> Result<Value, String> {
    let mut args = json!({ "update": { id: patch } });
    if let Some(a) = account_id { args["accountId"] = json!(a); }
    let r = single(rt, base, auth, &format!("x:{}/set", ty), args)?;
    if let Some(e) = r.get("notUpdated").and_then(|n| n.get(id)) {
        return Err(set_error_text(e));
    }
    Ok(r.get("updated").and_then(|u| u.get(id)).cloned().unwrap_or(Value::Null))
}

pub fn destroy(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, ty: &str, id: &str, account_id: Option<&str>) -> Result<(), String> {
    let mut args = json!({ "destroy": [id] });
    if let Some(a) = account_id { args["accountId"] = json!(a); }
    let r = single(rt, base, auth, &format!("x:{}/set", ty), args)?;
    if let Some(e) = r.get("notDestroyed").and_then(|n| n.get(id)) {
        return Err(set_error_text(e));
    }
    Ok(())
}

/// `x:<Type>/get`. `ids: None` returns every object (RFC 8620 §5.1).
pub fn get(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, ty: &str, ids: Option<Vec<String>>, properties: Option<&[&str]>, account_id: Option<&str>) -> Result<Vec<Value>, String> {
    let mut args = json!({ "ids": ids });
    if let Some(p) = properties { args["properties"] = json!(p); }
    if let Some(a) = account_id { args["accountId"] = json!(a); }
    let r = single(rt, base, auth, &format!("x:{}/get", ty), args)?;
    Ok(r.get("list").and_then(|l| l.as_array()).cloned().unwrap_or_default())
}

/// `x:<Type>/query` then `/get` of the matches. Two requests rather than one
/// with a result reference: plain query + get is what Stalwart's docs show for
/// registry objects, so nothing here depends on back-reference support.
pub fn query_get(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, ty: &str, filter: Value, properties: Option<&[&str]>) -> Result<Vec<Value>, String> {
    let r = single(rt, base, auth, &format!("x:{}/query", ty), json!({ "filter": filter, "limit": 1000 }))?;
    let ids: Vec<String> = r.get("ids").and_then(|i| i.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return Ok(vec![]);
    }
    get(rt, base, auth, ty, Some(ids), properties, None)
}

/// Apply the `Bootstrap` singleton in bootstrap mode. Returns the generated
/// admin account `(username, password)`.
///
/// Source: stalwart crates/jmap/src/registry/mapping/bootstrap.rs:82-560 —
/// only `update` of id `singleton` is accepted; on success
/// `updated.singleton` carries `{"username": "admin@<domain>", "secret": …}`
/// when the internal directory is used (bootstrap.rs:515-540).
pub fn apply_bootstrap(rt: &tokio::runtime::Handle, base: &str, auth: &Auth, fields: &Value) -> Result<(String, String), String> {
    let updated = update(rt, base, auth, "Bootstrap", "singleton", fields.clone(), None)
        .map_err(|e| format!("Stalwart rejected the setup: {}", e))?;
    let user = updated.get("username").and_then(|u| u.as_str()).unwrap_or("").to_string();
    let secret = updated.get("secret").and_then(|u| u.as_str()).unwrap_or("").to_string();
    if user.is_empty() || secret.is_empty() {
        return Err("Stalwart completed setup but returned no administrator credentials".into());
    }
    Ok((user, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_error_formatting() {
        let e = json!({"type": "invalidProperties", "description": "Invalid default domain", "properties": ["defaultDomain"]});
        assert_eq!(set_error_text(&e), "invalidProperties: Invalid default domain (field: defaultDomain)");
        assert_eq!(set_error_text(&json!({"type": "notFound"})), "notFound");
    }
}
