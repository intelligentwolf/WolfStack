// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! Node-local container deploys for a Stalwart mail cluster: Stalwart Keep,
//! Valkey + Sentinel, and Stalwart itself. Every function here acts on THIS
//! host only; the install job in `install` calls them locally or through the
//! node-local API routes on peers.
//!
//! Layout on each host, all under `/var/lib/wolfstack/stalwart/<cluster id>/`:
//!   etc/       → Stalwart `/etc/stalwart` (config.json, secrets/, keep/)
//!   data/      → Stalwart `/var/lib/stalwart`
//!   keep/      → Keep `/etc/keep` (read-only)
//!   valkey/    → Valkey `/data` (config is rewritten at runtime → a dir)
//!   sentinel/  → Sentinel `/data`

use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::preflight::{KEEP_CLIENT_PORT, KEEP_PEER_PORT, SENTINEL_PORT, STALWART_MGMT_PORT, STALWART_PUBLIC_PORTS, VALKEY_PORT};

/// Source: docs install/platform/docker.md "Choosing a tag" + install/
/// upgrade.md — follow the major tag `v1`, avoid `latest`.
pub const STALWART_IMAGE: &str = "stalwartlabs/stalwart:v1";
/// Source: keep .github/workflows/ci.yml:121-122 (semver `v{{major}}` tags)
/// and README "Binaries and Docker" (`stalwartlabs/keep`).
pub const KEEP_IMAGE: &str = "stalwartlabs/keep:v1";
/// Source: valkey-container generate-stackbrew-library.sh + versions.json —
/// 9.1.3 is the latest stable (2026-10-26). Pinned exactly so every member of
/// a Sentinel set runs the same server.
pub const VALKEY_IMAGE: &str = "valkey/valkey:9.1.3";

/// Container users. Sources: stalwart Dockerfile:32-33 and keep Dockerfile
/// (`useradd -r -u 2000 -g 2000`); valkey-container Dockerfile.template:168
/// (`useradd -r -g valkey -u 999 valkey`).
const STALWART_UID: u32 = 2000;
const KEEP_UID: u32 = 2000;
const VALKEY_UID: u32 = 999;

/// Sentinel's name for the monitored primary; Stalwart's `serviceName`.
pub const SENTINEL_SERVICE: &str = "stalwart";

pub fn base_dir(cluster_id: &str) -> PathBuf {
    PathBuf::from(format!("/var/lib/wolfstack/stalwart/{}", cluster_id))
}

fn run(args: &[&str]) -> Result<String, String> {
    let out = Command::new("docker").args(args).output()
        .map_err(|e| format!("could not run docker: {}", e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!("docker {}: {}", args.first().unwrap_or(&""), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Pull `image` unless it's already present.
fn ensure_image(image: &str) -> Result<(), String> {
    if run(&["image", "inspect", "--format", "{{.Id}}", image]).is_ok() {
        return Ok(());
    }
    run(&["pull", image]).map(|_| ())
}

/// Remove a container if it exists (no error when it doesn't).
fn remove_container(name: &str) {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
}

fn mkdir(path: &Path, uid: u32, mode: u32) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("create {}: {}", path.display(), e))?;
    std::os::unix::fs::chown(path, Some(uid), Some(uid)).map_err(|e| format!("chown {}: {}", path.display(), e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {}: {}", path.display(), e))
}

/// Write `contents` to `path`, owned by `uid`, with `mode` set before any
/// bytes land (created through write_secure at 0600, then widened/narrowed).
fn write_owned(path: &Path, contents: &[u8], uid: u32, mode: u32) -> Result<(), String> {
    let p = path.to_string_lossy().to_string();
    crate::paths::write_secure(&p, contents).map_err(|e| format!("write {}: {}", p, e))?;
    std::os::unix::fs::chown(path, Some(uid), Some(uid)).map_err(|e| format!("chown {}: {}", p, e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {}: {}", p, e))
}

/// `net.ipv4.tcp_rto_min_us=5000` on the host, persisted. Needed on Keep
/// servers below kernel 6.15. Source: keep docs/DEPLOYMENT.md §3 ("Minimum RTO
/// 5 ms … set `net.ipv4.tcp_rto_min_us=5000` (6.11 and later) … on Keep
/// servers and on client nodes").
fn ensure_host_rto_sysctl() -> Result<(), String> {
    const CONF: &str = "/etc/sysctl.d/90-wolfstack-stalwart-keep.conf";
    std::fs::write(CONF, "# Written by WolfStack for Stalwart Keep (keep docs/DEPLOYMENT.md section 3)\nnet.ipv4.tcp_rto_min_us = 5000\n")
        .map_err(|e| format!("write {}: {}", CONF, e))?;
    let out = Command::new("sysctl").args(["-w", "net.ipv4.tcp_rto_min_us=5000"]).output()
        .map_err(|e| format!("sysctl: {}", e))?;
    if !out.status.success() {
        return Err(format!("sysctl net.ipv4.tcp_rto_min_us: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Docker DNS flags, so Stalwart resolves MX/SPF/DNSBL lookups even on
/// systemd-resolved hosts (same handling as every WolfStack docker create).
fn dns_args() -> Vec<String> {
    crate::containers::docker_dns::get_docker_dns_servers().into_iter()
        .flat_map(|d| ["--dns".to_string(), d])
        .collect()
}

// ── Stalwart Keep ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeepMemberSpec {
    pub member_id: u32,
    pub wolfnet_ip: String,
    pub shards: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeepDeploy {
    pub cluster_id: String,
    /// This server's `--node` id.
    pub member_id: u32,
    pub members: Vec<KeepMemberSpec>,
    pub cluster_secret: String,
    pub peer_secret: String,
    /// This server's Ed25519 private key, PKCS#8 PEM.
    pub server_key_pem: String,
    /// Every member's public key (PEM `PUBLIC KEY` blocks).
    pub servers_pem: String,
    /// Every Stalwart node's client public key.
    pub clients_pem: String,
    pub needs_rto_sysctl: bool,
}

/// A Keep member string. Source: keep crates/keep-server/src/cli.rs:208 —
/// "node@client_ip:port/peer_ip:port/shards". The peer address is given in
/// full (not just the port) so every member dials the WolfNet address.
pub fn keep_member_entry(m: &KeepMemberSpec) -> String {
    format!("{}@{}:{}/{}:{}/{}", m.member_id, m.wolfnet_ip, KEEP_CLIENT_PORT, m.wolfnet_ip, KEEP_PEER_PORT, m.shards)
}

/// keep.toml. Keys are the flag names without dashes (keep docs/DEPLOYMENT.md
/// §2.2). Both listeners are pinned to the WolfNet address so neither port is
/// ever reachable from the internet: DEPLOYMENT §1 requires the peer port be
/// reachable only from members ("about 5 datagrams a second keep a cluster
/// down"). `peer-listen` is separate from `listen` and defaults to the
/// UNSPECIFIED address (cli.rs:211-215, DEPLOYMENT §2 `--peer-listen`) — found
/// live 2026-11-13 bound to 0.0.0.0:7100 before this was set.
pub fn keep_toml(d: &KeepDeploy) -> Result<String, String> {
    let me = d.members.iter().find(|m| m.member_id == d.member_id)
        .ok_or_else(|| format!("member {} is not in the member list", d.member_id))?;
    let members: Vec<String> = d.members.iter().map(|m| format!("  \"{}\",", keep_member_entry(m))).collect();
    Ok(format!(
        "# Written by WolfStack (Stalwart Mail Manager). Do not edit: WolfStack rewrites it.\n\
         listen = \"{ip}:{port}\"\n\
         peer-listen = \"{ip}:{pport}\"\n\
         members = [\n{members}\n]\n\
         secret-file = \"/etc/keep/cluster.secret\"\n\
         peer-secret-file = \"/etc/keep/peer.secret\"\n\
         tls-key = \"/etc/keep/keep.key\"\n\
         tls-clients = \"/etc/keep/clients.pem\"\n\
         tls-servers = \"/etc/keep/servers.pem\"\n\
         ready-file = \"/run/keep/settled\"\n",
        ip = me.wolfnet_ip, port = KEEP_CLIENT_PORT, pport = KEEP_PEER_PORT, members = members.join("\n"),
    ))
}

pub fn deploy_keep(d: &KeepDeploy) -> Result<(), String> {
    if !super::valid_cluster_id(&d.cluster_id) {
        return Err("invalid cluster id".into());
    }
    let me = d.members.iter().find(|m| m.member_id == d.member_id)
        .ok_or_else(|| format!("member {} is not in the member list", d.member_id))?.clone();
    if d.needs_rto_sysctl {
        ensure_host_rto_sysctl()?;
    }
    ensure_image(KEEP_IMAGE)?;

    let dir = base_dir(&d.cluster_id).join("keep");
    mkdir(&base_dir(&d.cluster_id), 0, 0o755)?;
    mkdir(&dir, KEEP_UID, 0o500)?;
    write_owned(&dir.join("keep.toml"), keep_toml(d)?.as_bytes(), KEEP_UID, 0o400)?;
    write_owned(&dir.join("cluster.secret"), d.cluster_secret.as_bytes(), KEEP_UID, 0o400)?;
    write_owned(&dir.join("peer.secret"), d.peer_secret.as_bytes(), KEEP_UID, 0o400)?;
    write_owned(&dir.join("keep.key"), d.server_key_pem.as_bytes(), KEEP_UID, 0o400)?;
    write_owned(&dir.join("servers.pem"), d.servers_pem.as_bytes(), KEEP_UID, 0o400)?;
    write_owned(&dir.join("clients.pem"), d.clients_pem.as_bytes(), KEEP_UID, 0o400)?;

    let name = super::keep_container(&d.cluster_id);
    remove_container(&name);
    let vol = format!("{}:/etc/keep:ro", dir.display());
    let cpus = me.shards.to_string();
    let node = d.member_id.to_string();
    // Source: keep README "Binaries and Docker" — `--network host` (members
    // address each other by IP) and `--stop-timeout 16` (a leaving member
    // hands its keys over for up to 16 s; Docker's 10 s default kills it
    // mid-handoff). `--cpus` sets cgroup cpu.max, which is where Keep takes
    // its shard budget from, so it matches the `/shards` in the member entry
    // (DEPLOYMENT §4: "each member's shard count in `--members` is
    // authoritative"). No `--start bootstrap`: DEPLOYMENT §2 forbids it in
    // restart-on-failure units, and `--restart unless-stopped` is one — the
    // default `rejoin` quarantines locks for ~10.5 minutes after a cold
    // start, which the install log tells the operator about.
    run(&[
        "run", "-d", "--name", &name, "--network", "host",
        "--restart", "unless-stopped", "--stop-timeout", "16",
        "--cpus", &cpus, "--memory", "512m",
        "--label", "wolfstack.mail.cluster", "--label", "wolfstack.mail.role=keep",
        "-v", &vol, KEEP_IMAGE, "--node", &node,
    ])?;
    Ok(())
}

/// True once this member reports `settled` — the ready file Keep keeps
/// present while settled (DEPLOYMENT §2 `--ready-file`).
pub fn keep_settled(cluster_id: &str) -> bool {
    run(&["exec", &super::keep_container(cluster_id), "test", "-e", "/run/keep/settled"]).is_ok()
}

// ── Valkey + Sentinel (fallback coordinator) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValkeyDeploy {
    pub cluster_id: String,
    pub wolfnet_ip: String,
    /// WolfNet address of the initial primary (first member).
    pub primary_ip: String,
    pub password: String,
    pub sentinel_password: String,
    /// Sentinel quorum (2 for three members).
    pub quorum: u32,
}

/// valkey.conf. Directive names from valkey 9.1.3 valkey.conf (lines 88, 112,
/// 139, 657, 680, 687, 1019, 1237, 1317, 1346). `primaryauth` is set on every
/// node because roles swap on failover (valkey-doc sentinel.md "Valkey
/// password-only authentication"). `protected-mode yes` is explicit because
/// the official image patches its default to off (valkey-container
/// description-template.md:21). maxmemory + volatile-lru: Stalwart docs
/// storage/backends/redis.md "Memory limit and eviction policy".
pub fn valkey_conf(d: &ValkeyDeploy) -> String {
    let mut s = format!(
        "# Written by WolfStack (Stalwart Mail Manager)\n\
         bind {ip}\nprotected-mode yes\nport {port}\ndir /data\n\
         requirepass \"{pw}\"\nprimaryauth \"{pw}\"\n\
         replica-announce-ip {ip}\n\
         maxmemory 256mb\nmaxmemory-policy volatile-lru\nappendonly no\n",
        ip = d.wolfnet_ip, port = VALKEY_PORT, pw = d.password,
    );
    if d.wolfnet_ip != d.primary_ip {
        s.push_str(&format!("replicaof {} {}\n", d.primary_ip, VALKEY_PORT));
    }
    s
}

/// sentinel.conf. Directives from valkey 9.1.3 sentinel.conf (lines 10, 46,
/// 73, 75, 94, 128, 171, 202, 210, 345). `sentinel monitor` must precede the
/// per-primary directives (src/sentinel.c:1850-1887).
pub fn sentinel_conf(d: &ValkeyDeploy) -> String {
    format!(
        "# Written by WolfStack (Stalwart Mail Manager). Sentinel rewrites this file.\n\
         bind {ip}\nport {sport}\ndir /tmp\n\
         sentinel announce-ip {ip}\n\
         requirepass \"{spw}\"\n\
         sentinel monitor {svc} {primary} {vport} {quorum}\n\
         sentinel auth-pass {svc} {pw}\n\
         sentinel down-after-milliseconds {svc} 5000\n\
         sentinel failover-timeout {svc} 60000\n\
         sentinel parallel-syncs {svc} 1\n\
         sentinel resolve-hostnames no\n",
        ip = d.wolfnet_ip, sport = SENTINEL_PORT, spw = d.sentinel_password,
        svc = SENTINEL_SERVICE, primary = d.primary_ip, vport = VALKEY_PORT,
        quorum = d.quorum, pw = d.password,
    )
}

pub fn deploy_valkey(d: &ValkeyDeploy) -> Result<(), String> {
    if !super::valid_cluster_id(&d.cluster_id) {
        return Err("invalid cluster id".into());
    }
    ensure_image(VALKEY_IMAGE)?;
    mkdir(&base_dir(&d.cluster_id), 0, 0o755)?;
    let vdir = base_dir(&d.cluster_id).join("valkey");
    let sdir = base_dir(&d.cluster_id).join("sentinel");
    // Directories, not single files: both processes rewrite their config by
    // rename() (valkey src/config.c:1712-1756), which a file bind mount breaks.
    mkdir(&vdir, VALKEY_UID, 0o700)?;
    mkdir(&sdir, VALKEY_UID, 0o700)?;
    write_owned(&vdir.join("valkey.conf"), valkey_conf(d).as_bytes(), VALKEY_UID, 0o600)?;
    write_owned(&sdir.join("sentinel.conf"), sentinel_conf(d).as_bytes(), VALKEY_UID, 0o600)?;

    for (name, dir, args) in [
        (super::valkey_container(&d.cluster_id), &vdir, vec!["valkey-server", "/data/valkey.conf"]),
        // `valkey-server … --sentinel`, NOT `valkey-sentinel`: the entrypoint
        // only drops root and chowns /data when argv[1] is valkey-server
        // (valkey-container docker-entrypoint.sh).
        (super::sentinel_container(&d.cluster_id), &sdir, vec!["valkey-server", "/data/sentinel.conf", "--sentinel"]),
    ] {
        remove_container(&name);
        let vol = format!("{}:/data", dir.display());
        let mut a: Vec<&str> = vec![
            "run", "-d", "--name", &name, "--network", "host",
            "--restart", "unless-stopped", "--memory", "512m",
            "--label", "wolfstack.mail.cluster", "--label", "wolfstack.mail.role=coordinator",
            "-v", &vol, VALKEY_IMAGE,
        ];
        a.extend(args.iter());
        run(&a)?;
    }
    Ok(())
}

/// Ask this host's Sentinel whether it can authorise a failover
/// (`SENTINEL CKQUORUM`, valkey-doc sentinel.md:597). Ok(message) when it can.
pub fn sentinel_ckquorum(cluster_id: &str, wolfnet_ip: &str, sentinel_password: &str) -> Result<String, String> {
    let env = format!("VALKEYCLI_AUTH={}", sentinel_password); // valkey-cli.c:92 CLI_AUTH_ENV
    let port = SENTINEL_PORT.to_string();
    let out = run(&[
        "exec", "-e", &env, &super::sentinel_container(cluster_id),
        "valkey-cli", "-h", wolfnet_ip, "-p", &port, "SENTINEL", "CKQUORUM", SENTINEL_SERVICE,
    ])?;
    if out.starts_with("OK") { Ok(out) } else { Err(out) }
}

// ── Stalwart ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StalwartMode {
    /// First node: no config.json yet → Stalwart's bootstrap mode, then the
    /// `Bootstrap` object is applied and the container is removed.
    Bootstrap,
    /// Normal operation with the shared config.json.
    Normal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalwartDeploy {
    pub cluster_id: String,
    pub mode: StalwartMode,
    pub stalwart_hostname: String,
    pub wolfnet_ip: String,
    /// config.json contents (Normal mode).
    #[serde(default)]
    pub config_json: String,
    /// The `Bootstrap` object fields (Bootstrap mode).
    #[serde(default)]
    pub bootstrap: Option<serde_json::Value>,
    /// Secret files under /etc/stalwart/secrets/, name → contents.
    pub secrets: Vec<(String, String)>,
    /// Keep client key + server keys (empty when not using Keep).
    #[serde(default)]
    pub keep_client_key_pem: String,
    #[serde(default)]
    pub keep_servers_pem: String,
    pub needs_rto_sysctl: bool,
}

/// What a Bootstrap-mode deploy returns: the generated admin account and the
/// config.json Stalwart wrote, which every other node must share.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapResult {
    pub admin_user: String,
    pub admin_password: String,
    pub config_json: String,
}

/// Paths inside the Stalwart container that the shared config refers to.
/// Every node mounts its own copy at the same path.
pub const SECRET_DIR_IN_CONTAINER: &str = "/etc/stalwart/secrets";
pub const KEEP_KEY_IN_CONTAINER: &str = "/etc/stalwart/keep/client.key";
pub const KEEP_SERVERS_IN_CONTAINER: &str = "/etc/stalwart/keep/servers.pem";

fn valid_secret_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 40 && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A free loopback TCP port for the bootstrap listener.
fn free_loopback_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("pick a port: {}", e))?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

fn prepare_stalwart_dirs(d: &StalwartDeploy) -> Result<(PathBuf, PathBuf), String> {
    let base = base_dir(&d.cluster_id);
    mkdir(&base, 0, 0o755)?;
    let etc = base.join("etc");
    let data = base.join("data");
    mkdir(&etc, STALWART_UID, 0o700)?;
    mkdir(&data, STALWART_UID, 0o700)?;
    let sdir = etc.join("secrets");
    mkdir(&sdir, STALWART_UID, 0o500)?;
    for (name, value) in &d.secrets {
        if !valid_secret_name(name) {
            return Err(format!("invalid secret name '{}'", name));
        }
        write_owned(&sdir.join(name), value.as_bytes(), STALWART_UID, 0o400)?;
    }
    if !d.keep_client_key_pem.is_empty() {
        let kdir = etc.join("keep");
        mkdir(&kdir, STALWART_UID, 0o500)?;
        write_owned(&kdir.join("client.key"), d.keep_client_key_pem.as_bytes(), STALWART_UID, 0o400)?;
        write_owned(&kdir.join("servers.pem"), d.keep_servers_pem.as_bytes(), STALWART_UID, 0o400)?;
    }
    Ok((etc, data))
}

/// Wait until `url` answers HTTP at all (any status). Bootstrap mode has no
/// documented health semantics, so "the listener is up" is the signal.
fn wait_http_up(rt: &tokio::runtime::Handle, url: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    loop {
        let ok = rt.block_on(async {
            crate::api::API_HTTP_CLIENT.get(url).timeout(Duration::from_secs(3)).send().await.is_ok()
        });
        if ok { return Ok(()); }
        if start.elapsed() > timeout {
            return Err(format!("Stalwart did not start listening on {} within {}s", url, timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Wait for `/healthz/ready` → 200. Source: docs cluster/configuration/
/// load-balancing.md — "`/healthz/ready` (returns 503 when the data store is
/// unavailable)".
pub fn wait_ready(rt: &tokio::runtime::Handle, wolfnet_ip: &str, timeout: Duration) -> Result<(), String> {
    let url = format!("http://{}:{}/healthz/ready", wolfnet_ip, STALWART_MGMT_PORT);
    let start = Instant::now();
    loop {
        let r = rt.block_on(async {
            match crate::api::API_HTTP_CLIENT.get(&url).timeout(Duration::from_secs(3)).send().await {
                Ok(resp) => {
                    let st = resp.status();
                    let _ = resp.bytes().await; // drain (tests/resource_safety.rs)
                    Ok(st)
                }
                Err(e) => Err(e.to_string()),
            }
        });
        let last = match r {
            Ok(st) if st.is_success() => return Ok(()),
            Ok(st) => format!("HTTP {}", st.as_u16()),
            Err(e) => e,
        };
        if start.elapsed() > timeout {
            return Err(format!("Stalwart on {} was not ready after {}s (last: {})", wolfnet_ip, timeout.as_secs(), last));
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn container_logs_tail(name: &str) -> String {
    Command::new("docker").args(["logs", "--tail", "25", name]).output().ok()
        .map(|o| {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            strip_ansi(&s)
        })
        .unwrap_or_default()
}

/// Remove ANSI escape sequences (Stalwart colours its console log before its
/// own Tracer settings load), so the log reads cleanly in the browser.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // CSI: parameters until a final byte in 0x40..=0x7e.
                for n in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&n) { break; }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

pub fn deploy_stalwart(d: &StalwartDeploy, rt: &tokio::runtime::Handle) -> Result<Option<BootstrapResult>, String> {
    if !super::valid_cluster_id(&d.cluster_id) {
        return Err("invalid cluster id".into());
    }
    if d.stalwart_hostname.is_empty() || d.stalwart_hostname.len() > 253
        || !d.stalwart_hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return Err("invalid Stalwart hostname".into());
    }
    ensure_image(STALWART_IMAGE)?;
    let (etc, data) = prepare_stalwart_dirs(d)?;
    let name = super::stalwart_container(&d.cluster_id);
    remove_container(&name);

    let etc_vol = format!("{}:/etc/stalwart", etc.display());
    let data_vol = format!("{}:/var/lib/stalwart", data.display());
    // STALWART_HOSTNAME: unique per node — node ids are leased by hostname
    // (docs cluster/configuration/node-id.md).
    let host_env = format!("STALWART_HOSTNAME={}", d.stalwart_hostname);
    let rto = "net.ipv4.tcp_rto_min_us=5000";
    let dns = dns_args();

    match d.mode {
        StalwartMode::Bootstrap => {
            let bootstrap = d.bootstrap.clone().ok_or("bootstrap fields missing")?;
            // A config.json from an earlier attempt would skip bootstrap mode
            // (docs configuration/bootstrap-mode.md: the mode is entered
            // whenever the file does not exist).
            let _ = std::fs::remove_file(etc.join("config.json"));
            let port = free_loopback_port()?;
            let admin_pw = super::random_secret(32);
            // STALWART_RECOVERY_ADMIN replaces the random temporary password
            // in bootstrap mode (bootstrap-mode.md "Temporary administrator").
            // It is only ever set on this short-lived container, never on the
            // long-running one: while set it is a full-access credential
            // (configuration/recovery-mode.md).
            let admin_env = format!("STALWART_RECOVERY_ADMIN=admin:{}", admin_pw);
            // The bootstrap listener has no brute-force protection
            // (bootstrap-mode.md), so it is published on loopback only.
            let publish = format!("127.0.0.1:{}:{}", port, STALWART_MGMT_PORT);
            let mut a: Vec<String> = vec![
                "run".into(), "-d".into(), "--name".into(), name.clone(), "--init".into(),
                "--restart".into(), "no".into(),
                "-e".into(), host_env.clone(), "-e".into(), admin_env,
                "-v".into(), etc_vol.clone(), "-v".into(), data_vol.clone(),
                "-p".into(), publish,
            ];
            a.extend(dns.iter().cloned());
            a.push(STALWART_IMAGE.into());
            let refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
            run(&refs)?;

            let base = format!("http://127.0.0.1:{}", port);
            let result = (|| -> Result<BootstrapResult, String> {
                wait_http_up(rt, &format!("{}/healthz/live", base), Duration::from_secs(120))?;
                let auth = super::jmap::Auth::Basic { user: "admin".into(), password: admin_pw.clone() };
                let (admin_user, admin_password) = super::jmap::apply_bootstrap(rt, &base, &auth, &bootstrap)?;
                // bootstrap_set writes config.json through write_data_store
                // (stalwart crates/jmap/src/registry/mapping/bootstrap.rs:308).
                let config_json = std::fs::read_to_string(etc.join("config.json"))
                    .map_err(|e| format!("Stalwart accepted the setup but config.json was not written: {}", e))?;
                Ok(BootstrapResult { admin_user, admin_password, config_json })
            })();
            let logs = if result.is_err() { container_logs_tail(&name) } else { String::new() };
            // The server keeps running in bootstrap mode until restarted
            // (bootstrap-mode.md "Completing the setup"); the next deploy
            // starts it normally.
            remove_container(&name);
            result.map(Some).map_err(|e| if logs.is_empty() { e } else { format!("{}\n--- Stalwart log ---\n{}", e, logs) })
        }
        StalwartMode::Normal => {
            if d.config_json.trim().is_empty() {
                return Err("config.json contents missing".into());
            }
            write_owned(&etc.join("config.json"), d.config_json.as_bytes(), STALWART_UID, 0o600)?;
            let mut a: Vec<String> = vec![
                "run".into(), "-d".into(), "--name".into(), name.clone(), "--init".into(),
                "--restart".into(), "unless-stopped".into(),
                "--label".into(), "wolfstack.mail.cluster".into(),
                "--label".into(), "wolfstack.mail.role=stalwart".into(),
                "-e".into(), host_env,
                "-v".into(), etc_vol, "-v".into(), data_vol,
            ];
            // Default listener ports on every interface; the plain-HTTP
            // management listener on the WolfNet address only (docs
            // install/platform/docker.md publishes it on loopback for the
            // same reason; WolfNet lets the owner node reach it).
            for p in STALWART_PUBLIC_PORTS {
                a.push("-p".into());
                a.push(format!("{}:{}", p, p));
            }
            a.push("-p".into());
            a.push(format!("{}:{}:{}", d.wolfnet_ip, STALWART_MGMT_PORT, STALWART_MGMT_PORT));
            if d.needs_rto_sysctl {
                // Per network namespace, so it must be set on the container,
                // not only the host (verified: docker --sysctl applies it).
                a.push("--sysctl".into());
                a.push(rto.into());
            }
            a.extend(dns.iter().cloned());
            a.push(STALWART_IMAGE.into());
            let mut ports: Vec<String> = STALWART_PUBLIC_PORTS.iter().map(|p| format!("{}:{}", p, p)).collect();
            ports.push(format!("{}:{}:{}", d.wolfnet_ip, STALWART_MGMT_PORT, STALWART_MGMT_PORT));
            crate::containers::validate_host_ports_free(&ports, &name)?;
            let refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
            run(&refs)?;
            if let Err(e) = wait_ready(rt, &d.wolfnet_ip, Duration::from_secs(180)) {
                return Err(format!("{}\n--- Stalwart log ---\n{}", e, container_logs_tail(&name)));
            }
            Ok(None)
        }
    }
}

/// Restart this node's Stalwart container (picks up store/coordinator
/// changes, which "take effect only after a restart" — docs storage/index.md).
pub fn restart_stalwart(cluster_id: &str, wolfnet_ip: &str, rt: &tokio::runtime::Handle) -> Result<(), String> {
    let name = super::stalwart_container(cluster_id);
    run(&["restart", &name])?;
    wait_ready(rt, wolfnet_ip, Duration::from_secs(180))
        .map_err(|e| format!("{}\n--- Stalwart log ---\n{}", e, container_logs_tail(&name)))
}

/// Remove every container of this cluster on this host and its local files.
/// Mail data lives in the Galera database, which is deliberately NOT dropped.
pub fn remove_local(cluster_id: &str) -> Result<(), String> {
    if !super::valid_cluster_id(cluster_id) {
        return Err("invalid cluster id".into());
    }
    for name in [
        super::stalwart_container(cluster_id), super::keep_container(cluster_id),
        super::valkey_container(cluster_id), super::sentinel_container(cluster_id),
    ] {
        remove_container(&name);
    }
    let dir = base_dir(cluster_id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("remove {}: {}", dir.display(), e))?;
    }
    if !std::path::Path::new("/var/lib/wolfstack/stalwart").read_dir().map(|mut d| d.next().is_some()).unwrap_or(false) {
        let _ = std::fs::remove_file("/etc/sysctl.d/90-wolfstack-stalwart-keep.conf");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kd() -> KeepDeploy {
        KeepDeploy {
            cluster_id: "mail".into(), member_id: 2,
            members: vec![
                KeepMemberSpec { member_id: 1, wolfnet_ip: "10.10.10.1".into(), shards: 2 },
                KeepMemberSpec { member_id: 2, wolfnet_ip: "10.10.10.2".into(), shards: 1 },
                KeepMemberSpec { member_id: 3, wolfnet_ip: "10.10.10.3".into(), shards: 2 },
            ],
            cluster_secret: "a".repeat(32), peer_secret: "b".repeat(32),
            server_key_pem: String::new(), servers_pem: String::new(), clients_pem: String::new(),
            needs_rto_sysctl: false,
        }
    }

    #[test]
    fn keep_member_format() {
        // keep README: "1@10.0.0.1:7000/7100/4"
        assert_eq!(keep_member_entry(&KeepMemberSpec { member_id: 1, wolfnet_ip: "10.0.0.1".into(), shards: 4 }),
                   "1@10.0.0.1:7000/10.0.0.1:7100/4");
    }

    #[test]
    fn keep_toml_binds_wolfnet_and_lists_members() {
        let t = keep_toml(&kd()).unwrap();
        assert!(t.contains("listen = \"10.10.10.2:7000\""));
        assert!(t.contains("peer-listen = \"10.10.10.2:7100\""), "peer port must never bind 0.0.0.0");
        assert!(t.contains("\"1@10.10.10.1:7000/10.10.10.1:7100/2\""));
        assert!(t.contains("\"3@10.10.10.3:7000/10.10.10.3:7100/2\""));
        assert!(t.contains("peer-secret-file"));
        assert!(!t.contains(&"a".repeat(32)), "secrets belong in files, not keep.toml");
    }

    #[test]
    fn ansi_codes_are_stripped() {
        assert_eq!(strip_ansi("\u{1b}[37m2026\u{1b}[0m \u{1b}[33;1mWARN\u{1b}[0m ok"), "2026 WARN ok");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn keep_toml_refuses_unknown_member() {
        let mut d = kd();
        d.member_id = 9;
        assert!(keep_toml(&d).is_err());
    }

    #[test]
    fn valkey_replica_only_off_primary() {
        let mut d = ValkeyDeploy {
            cluster_id: "mail".into(), wolfnet_ip: "10.10.10.1".into(), primary_ip: "10.10.10.1".into(),
            password: "p".into(), sentinel_password: "s".into(), quorum: 2,
        };
        let c = valkey_conf(&d);
        assert!(!c.contains("replicaof"));
        assert!(c.contains("protected-mode yes") && c.contains("maxmemory-policy volatile-lru"));
        d.wolfnet_ip = "10.10.10.2".into();
        assert!(valkey_conf(&d).contains("replicaof 10.10.10.1 6379"));
        let s = sentinel_conf(&d);
        let mon = s.find("sentinel monitor").unwrap();
        assert!(mon < s.find("sentinel auth-pass").unwrap(), "monitor must precede per-primary directives");
        assert!(s.contains("sentinel monitor stalwart 10.10.10.1 6379 2"));
    }
}
