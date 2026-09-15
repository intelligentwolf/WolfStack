// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Cloud-init payload generator for WolfStack Pools.
//!
//! Produces a `#cloud-config` YAML that:
//!
//!   1. Writes the shared cluster secret + per-VM join-token under
//!      /etc/wolfstack/ via the `write_files` directive — runs
//!      BEFORE `runcmd`, so setup.sh sees them as existing config.
//!      (setup.sh:260: "treating this as an upgrade...preserving
//!      existing config, cluster secret, and join token".)
//!   2. On the leader VM only, also writes the federation token to
//!      /etc/wolfstack/federation_tokens.json so the SP's poll of
//!      `/api/federation/status` (auth via Bearer <federation_token>)
//!      starts succeeding the moment the daemon is up.
//!   3. Sets the hostname.
//!   4. Pulls setup.sh from the SP install proxy
//!      (`/api/install/setup.sh`, see api/mod.rs:24722) with a
//!      GitHub fallback. Runs it.
//!   5. Per role:
//!        * leader   → POST `/api/tenants/self-register` to the SP
//!          with the bootstrap token + leader URL. SP
//!          validates the token against a pending pool.
//!        * follower → POST `/api/cluster/bootstrap-add` to the
//!          leader's URL with X-WolfStack-Secret =
//!          pool_secret + own join_token + own address.
//!          Leader joins this VM into its cluster.
//!
//! Both callbacks run inside a small bash retry loop because the
//! daemon may take 30-60 s to come up after setup.sh, and the
//! follower must wait for the leader to be reachable too.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Leader,
    Follower,
}

#[derive(Debug, Clone)]
pub struct Bootstrap {
    pub role: Role,
    /// Hostname to set on the VM.
    pub hostname: String,
    /// SP's WolfStack URL (the leader posts back here on
    /// self-register; both leader and followers fetch setup.sh
    /// from `<sp_url>/api/install/setup.sh`).
    pub sp_url: String,
    /// Shared cluster secret, used as X-WolfStack-Secret across
    /// the pool's VMs and by the follower→leader bootstrap-add call.
    pub cluster_secret: String,
    /// Per-VM join-token planted in /etc/wolfstack/join-token.
    /// On a follower, the leader's bootstrap-add endpoint will
    /// verify this against `/api/cluster/verify-token` on the
    /// follower's own daemon — same flow as the existing add_node
    /// path (api/mod.rs:2339).
    pub join_token: String,
    /// Leader-only: the federation token the SP will use to poll
    /// /api/federation/status. Empty on followers.
    pub federation_token: String,
    /// Leader-only: bootstrap_token that authenticates the
    /// self-register callback. Empty on followers.
    pub bootstrap_token: String,
    /// Leader-only: tenant display name to send to self-register.
    pub tenant_name: String,
    /// Follower-only: leader's https URL the follower posts to.
    /// Empty on the leader. Filled in by the orchestrator once
    /// leader self-register has succeeded — followers' cloud-init
    /// can't include this at provision time because the leader's
    /// IP isn't known yet.
    pub leader_url: String,
}

/// Sanitise a hostname to RFC 1123 (alphanumeric + hyphen, 1-63).
/// Defence in depth — callers should already validate.
fn safe_hostname(s: &str) -> String {
    let cleaned: String = s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(63)
        .collect();
    if cleaned.is_empty() { "wolfstack-vm".into() } else { cleaned }
}

/// Quote a value for embedding inside a single-quoted bash string.
/// Used in runcmd lines so a stray apostrophe in user input can't
/// break out of the surrounding quotes.
fn shell_quote(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Render the cloud-config YAML for one VM.
pub fn build(b: &Bootstrap) -> String {
    let hostname = safe_hostname(&b.hostname);
    let github_url = "https://raw.githubusercontent.com/intelligentwolf/WolfStack/master/setup.sh";

    // ── write_files: pre-create /etc/wolfstack/* before setup.sh ──
    //
    // setup.sh treats existing /etc/wolfstack as an upgrade (line 260)
    // and preserves cluster-secret + join-token + nodes.json. By
    // pre-writing the secret + join-token, the new VM joins the pool
    // with the SP-chosen secret instead of generating its own.
    //
    // Permissions match what setup.sh sets at line 847-848:
    // /etc/wolfstack/custom-cluster-secret = 0600 root:root.
    let mut write_files = String::new();
    write_files.push_str(&format!(
        "  - path: /etc/wolfstack/custom-cluster-secret\n\
         \x20   permissions: '0600'\n\
         \x20   owner: root:root\n\
         \x20   content: '{}'\n",
        shell_quote(&b.cluster_secret),
    ));
    write_files.push_str(&format!(
        "  - path: /etc/wolfstack/join-token\n\
         \x20   permissions: '0600'\n\
         \x20   owner: root:root\n\
         \x20   content: '{}'\n",
        shell_quote(&b.join_token),
    ));
    if b.role == Role::Leader && !b.federation_token.is_empty() {
        // federation_tokens.json is a JSON array of bearer strings;
        // see api/mod.rs:24628 (load_federation_tokens parses it
        // with serde_json::from_str::<Vec<String>>). Render exactly
        // that shape so the daemon picks it up at first start.
        let token_json = serde_json::to_string(&vec![b.federation_token.clone()])
            .unwrap_or_else(|_| "[]".into());
        write_files.push_str(&format!(
            "  - path: /etc/wolfstack/federation_tokens.json\n\
             \x20   permissions: '0600'\n\
             \x20   owner: root:root\n\
             \x20   content: |\n\
             \x20     {}\n",
            token_json,
        ));
    }
    // /etc/wolfstack must exist before write_files lands — cloud-init
    // creates parent dirs automatically, but setup.sh's chmod 0700
    // on the dir will run later, so we explicitly chmod here too.
    let chmod_dir = "chmod 0700 /etc/wolfstack || true";

    // ── runcmd: install + start daemon + role-specific callback ──
    let mut runcmds: Vec<String> = vec![
        format!("hostnamectl set-hostname '{}'", shell_quote(&hostname)),
        chmod_dir.to_string(),
    ];

    // Pull setup.sh: prefer SP install proxy (cached, version-pinned),
    // fall back to GitHub. Same pattern as xo/mod.rs:651-681 — kept
    // structurally identical so behaviour is consistent across
    // existing XO Provision and the new Pools wizard.
    let sp_setup = if !b.sp_url.is_empty() {
        format!("{}/api/install/setup.sh", b.sp_url.trim_end_matches('/'))
    } else { String::new() };

    // cloud-init `runcmd` already executes as root, and not every base
    // image ships sudo (e.g. some Proxmox-derived templates strip it).
    // Drop sudo to keep this working across all minimal images.
    let install_cmd = if !sp_setup.is_empty() {
        format!(
            "rm -f /tmp/wolfstack-setup.sh && \
             (curl -fsSL --max-time 30 '{}' -o /tmp/wolfstack-setup.sh \
              || curl -fsSL --max-time 60 '{}' -o /tmp/wolfstack-setup.sh) && \
             [ -s /tmp/wolfstack-setup.sh ] && \
             bash /tmp/wolfstack-setup.sh --yes",
            shell_quote(&sp_setup), shell_quote(github_url),
        )
    } else {
        format!(
            "rm -f /tmp/wolfstack-setup.sh && \
             curl -fsSL --max-time 60 '{}' -o /tmp/wolfstack-setup.sh && \
             [ -s /tmp/wolfstack-setup.sh ] && \
             bash /tmp/wolfstack-setup.sh --yes",
            shell_quote(github_url),
        )
    };
    runcmds.push(install_cmd);

    // Wait for own daemon to answer /api/health on 127.0.0.1:8553.
    // 60 retries × 2 s = 2 min ceiling. Past that, role callbacks
    // will fail and the pool ends up in `failed` — visible in the UI.
    let wait_self = "for i in $(seq 1 60); do \
        curl -fks --max-time 3 https://127.0.0.1:8553/api/health > /dev/null && break; \
        sleep 2; \
    done".to_string();
    runcmds.push(wait_self);

    match b.role {
        Role::Leader => {
            // Self-register with the SP. POST JSON to
            // /api/tenants/self-register with the bootstrap token,
            // tenant name, leader URL, federation token. The SP
            // validates bootstrap_token against pending pools and
            // creates a Tenant row.
            //
            // `leader_url` for the SP record uses the VM's own
            // primary IPv4 with port 8553. We probe `hostname -I`
            // and pick the first non-loopback address — same logic
            // setup.sh uses. WolfNet IPs (10.42.x.x) won't be
            // reachable from the SP, so we filter them out.
            let sp_url = b.sp_url.trim_end_matches('/').to_string();
            // Build the JSON body via serde so any double-quote /
            // backslash in user input is escaped correctly.
            // `__IP__` is a placeholder we substitute server-side
            // (in the bash runcmd) once we know the VM's primary
            // IPv4. Using a sentinel keeps the JSON valid through
            // the cloud-init → bash → curl chain.
            let body_template = serde_json::json!({
                "bootstrap_token": b.bootstrap_token,
                "name": b.tenant_name,
                "url": "https://__IP__:8553",
                "federation_token": b.federation_token,
            }).to_string();
            // The body lives inside a bash single-quoted echo. Any
            // single quote in the JSON body would terminate the
            // single-quoted string — a tenant name with `'` would
            // break it. serde_json never emits a bare single quote
            // in JSON output, so this is safe today, but defence in
            // depth: assert the body contains no apostrophe before
            // we embed it.
            //
            // (We can't run shell_quote on the body itself because
            // it gets sent to the SP via curl, not parsed by bash;
            // the body must be byte-identical JSON.)
            //
            // `assert!` (not debug_assert!) because release builds
            // strip debug_assert; if a future contract change ever
            // produces an apostrophe-bearing token we want to fail
            // fast, not silently emit a broken cloud-init.
            assert!(!body_template.contains('\''),
                "JSON body must not contain raw apostrophes — \
                 token generator violated alphabet contract");
            let callback = format!(
                "IP=$(hostname -I | tr ' ' '\\n' | grep -v '^10\\.42\\.' | grep -v '^127\\.' | grep -v '^$' | head -n1); \
                 [ -z \"$IP\" ] && IP=$(hostname -I | awk '{{print $1}}'); \
                 BODY=$(echo '{body}' | sed \"s|__IP__|$IP|g\"); \
                 for i in $(seq 1 30); do \
                    curl -fks --max-time 10 -X POST \
                        -H 'Content-Type: application/json' \
                        -d \"$BODY\" \
                        '{sp}/api/tenants/self-register' && break; \
                    sleep 4; \
                 done",
                body = body_template, sp = shell_quote(&sp_url),
            );
            runcmds.push(callback);
        }
        Role::Follower => {
            // Followers do NOTHING role-specific in cloud-init —
            // they just bring the daemon up with the shared
            // cluster_secret + their own per-VM join-token already
            // pre-written by `write_files` above.
            //
            // The SP-side orchestrator (src/pools/orchestrator.rs)
            // polls the backend for follower IPs, and once it sees
            // both the leader and a follower are reachable, calls
            // the LEADER's /api/cluster/bootstrap-add to add the
            // follower (auth: X-WolfStack-Secret = pool_secret;
            // verifies the follower's join_token via the follower's
            // /api/cluster/verify-token — same path as add_node at
            // api/mod.rs:2339).
            //
            // We therefore deliberately ignore `leader_url` on the
            // follower side; the SP knows the leader URL after
            // self-register and drives the join from there.
            let _ = b.leader_url;
        }
    }

    // YAML assembly — single-quoted strings everywhere. Hostname
    // comes through `safe_hostname` so it can't include YAML
    // metacharacters; tokens are random alphanumeric and don't need
    // escaping; cluster_secret is also alphanumeric.
    let runcmd_yaml = runcmds.iter()
        .map(|c| format!("  - bash -lc '{}'", shell_quote(c)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "#cloud-config\n\
         # WolfStack Pool bootstrap — generated by SP for tenant cluster.\n\
         # Pre-writes /etc/wolfstack/{{custom-cluster-secret,join-token{}}} so setup.sh\n\
         # picks them up as existing config (setup.sh treats existing /etc/wolfstack\n\
         # as an upgrade and preserves these files).\n\
         hostname: \"{hostname}\"\n\
         package_update: false\n\
         package_upgrade: false\n\
         write_files:\n\
         {wf}\
         runcmd:\n\
         {rc}\n\
         final_message: \"WolfStack Pool VM first-boot finished.\"\n",
        if b.role == Role::Leader { ",federation_tokens.json" } else { "" },
        hostname = hostname,
        wf = write_files,
        rc = runcmd_yaml,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(role: Role) -> Bootstrap {
        Bootstrap {
            role,
            hostname: "alpha-1".into(),
            sp_url: "https://sp.example.com:8553".into(),
            cluster_secret: "abc123".into(),
            join_token: "join-tok".into(),
            federation_token: "fed-tok".into(),
            bootstrap_token: "boot-tok".into(),
            tenant_name: "Customer A".into(),
            leader_url: String::new(),
        }
    }

    #[test]
    fn leader_yaml_contains_self_register() {
        let yaml = build(&sample(Role::Leader));
        assert!(yaml.contains("/api/tenants/self-register"), "leader must self-register");
        assert!(yaml.contains("federation_tokens.json"), "leader writes federation token");
        assert!(yaml.contains("custom-cluster-secret"), "shared cluster secret pre-written");
        assert!(yaml.contains("join-token"), "join-token pre-written");
        assert!(yaml.contains("hostname: \"alpha-1\""), "hostname set");
        assert!(yaml.contains("/api/install/setup.sh"), "setup.sh pulled from SP proxy");
        assert!(yaml.contains("raw.githubusercontent.com"), "GitHub fallback present");
    }

    #[test]
    fn follower_yaml_no_federation_token() {
        let yaml = build(&sample(Role::Follower));
        // Follower must not get a federation token planted; only
        // the leader receives polls from the SP.
        assert!(!yaml.contains("federation_tokens.json"));
        // Follower also doesn't self-register.
        assert!(!yaml.contains("/api/tenants/self-register"));
        // But still gets cluster-secret + join-token.
        assert!(yaml.contains("custom-cluster-secret"));
        assert!(yaml.contains("join-token"));
    }

    #[test]
    fn hostname_sanitised() {
        let mut b = sample(Role::Leader);
        b.hostname = "evil:host;\nname".into();
        let yaml = build(&b);
        assert!(yaml.contains("hostname: \"evilhostname\""), "metachars stripped");
        assert!(!yaml.contains("\nname"), "newline removed");
    }

    #[test]
    fn empty_hostname_falls_back() {
        let mut b = sample(Role::Leader);
        b.hostname = "".into();
        let yaml = build(&b);
        assert!(yaml.contains("hostname: \"wolfstack-vm\""));
    }

    #[test]
    fn shell_quote_handles_apostrophe() {
        assert_eq!(shell_quote("it's"), "it'\\''s");
    }

    /// Simulate what bash does when it parses `bash -lc '<arg>'`
    /// with embedded `'\''` escapes. Returns the unescaped string
    /// the inner shell would see.
    fn unescape_bash_arg(quoted_yaml_line: &str) -> String {
        // Strip leading `  - bash -lc '` and trailing `'`.
        let start = quoted_yaml_line.find("bash -lc '")
            .expect("missing bash -lc") + "bash -lc '".len();
        let inner = &quoted_yaml_line[start..];
        let inner = inner.trim_end().trim_end_matches('\'');
        // Bash unescapes `'\''` → literal `'` (a single-quote
        // closure followed by escaped quote followed by re-entry).
        inner.replace("'\\''", "'")
    }

    /// Pull the leader's runcmd line that contains BODY= and
    /// return the JSON literal bash would echo after parsing.
    fn extract_self_register_json(yaml: &str) -> String {
        let line = yaml.lines().find(|l| l.contains("BODY=$(echo"))
            .expect("BODY=$(echo... line not in YAML");
        let unescaped = unescape_bash_arg(line);
        // Now find the inner single-quoted JSON: `echo '...'`.
        let start = unescaped.find("BODY=$(echo '")
            .expect("BODY= prefix missing after unescape") + "BODY=$(echo '".len();
        let rest = &unescaped[start..];
        let end = rest.find("' | sed").expect("' | sed marker missing");
        rest[..end].replace("__IP__", "192.0.2.1")
    }

    /// Ensures the leader's self-register JSON body is valid JSON
    /// after Rust → cloud-init → bash → curl. Catches escape /
    /// closure bugs that would otherwise ship non-parseable JSON
    /// to the SP.
    #[test]
    fn leader_self_register_body_is_valid_json() {
        let yaml = build(&sample(Role::Leader));
        let json = extract_self_register_json(&yaml);
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("body not valid JSON: {} — body={}", e, json));
        assert_eq!(parsed["bootstrap_token"], "boot-tok");
        assert_eq!(parsed["name"], "Customer A");
        assert_eq!(parsed["federation_token"], "fed-tok");
        assert_eq!(parsed["url"], "https://192.0.2.1:8553");
    }

    /// Tenant names with quotes / backslashes must still produce
    /// parseable JSON. serde_json::to_string escapes them.
    /// (Apostrophe is rejected upstream by the debug_assert because
    /// it would break the bash single-quoted echo. Test the JSON
    /// special chars here.)
    #[test]
    fn json_body_handles_special_chars_in_tenant_name() {
        let mut b = sample(Role::Leader);
        b.tenant_name = r#"Customer "Acme" \ Co"#.into();
        let yaml = build(&b);
        let json = extract_self_register_json(&yaml);
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("body not valid JSON: {} — body={}", e, json));
        assert_eq!(parsed["name"], r#"Customer "Acme" \ Co"#);
    }
}
