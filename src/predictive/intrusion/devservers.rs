// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Development servers reachable from outside their container.
//!
//! A dev server (Vite, webpack-dev-server, `next dev`, …) is built to
//! serve its project's source tree to the developer's own browser. It
//! answers module-transform requests, serves arbitrary files under its
//! root and — across Vite's 2025-2026 advisories — has repeatedly let a
//! crafted URL read files outside it (`?raw??`, `/@fs/`, `.env`). The
//! 2026-11-16 kit's own request filter blocks exactly those URL shapes
//! (so no rival could follow it in), which is how it got in: a Vite dev
//! server published to the internet through a reverse proxy
//! (`app.example.com → localhost:5373`).
//!
//! Severity follows real reachability:
//!
//! * **Critical** — a reverse proxy or tunnel config on this node
//!   (Caddy, nginx, Apache, HAProxy, Traefik, cloudflared) points at it.
//!   Matched within the dev server's own target (localhost / its
//!   addresses) and across targets (a load-balancer CT proxying to
//!   another CT's address);
//! * **High** — listening on all interfaces in a target that holds a
//!   public address;
//! * **Warn** — listening on all interfaces, private addresses only.
//!
//! A remotely-managed Cloudflare tunnel (`cloudflared tunnel run
//! --token …`) keeps its ingress rules in the Cloudflare dashboard, so a
//! dev server behind one cannot be proven unpublished; the card says so
//! rather than claiming it is safe.

use super::net;
use super::rootfs::RootFs;
use super::targets::Target;
use std::net::IpAddr;

/// What kind of dev server a command line is, if any. `argv` is the
/// NUL-split `/proc/<pid>/cmdline`.
pub fn dev_server_kind(argv: &[String]) -> Option<&'static str> {
    if argv.is_empty() { return None; }
    let base = |s: &str| s.rsplit('/').next().unwrap_or(s).to_string();
    // The script is the first argument after the runtime and its flags
    // (`node --require x /root/app/node_modules/.bin/vite --port 1`).
    let runtime = base(&argv[0]);
    let mut rest: Vec<&String> = argv.iter().collect();
    if matches!(runtime.as_str(), "node" | "nodejs" | "bun" | "deno") {
        rest = argv.iter().skip(1).skip_while(|a| a.starts_with('-')).collect();
    }
    let script = rest.first()?.as_str();
    let args: Vec<&str> = rest.iter().skip(1).map(|s| s.as_str()).collect();
    let has = |w: &str| args.contains(&w);
    let sb = base(script);
    // Relative forms occur too: a keepalive loop running
    // `node node_modules/.bin/vite` from the project directory.
    let in_pkg = |pkg: &str| script.contains(&format!("node_modules/{}/", pkg)) || script.contains("node_modules/.bin/");
    let is_vite = ((sb == "vite" || sb == "vite.js") && in_pkg("vite"))
        || script.ends_with("vite/bin/vite.js");

    if is_vite {
        if has("preview") || has("build") || has("optimize") { return None; }
        return Some("Vite dev server");
    }
    if sb == "webpack-dev-server" || sb == "webpack-dev-server.js"
        || ((sb == "webpack" || sb == "webpack-cli" || sb == "cli.js" && script.contains("/webpack-cli/")) && has("serve")) {
        return Some("webpack-dev-server");
    }
    if sb == "next" && has("dev") { return Some("Next.js dev server"); }
    if (sb == "nuxt" || sb == "nuxi" || sb == "nuxi.mjs") && has("dev") { return Some("Nuxt dev server"); }
    if script.ends_with("/react-scripts/scripts/start.js") || (sb == "react-scripts" && has("start")) {
        return Some("Create React App dev server");
    }
    if sb == "ng" && has("serve") { return Some("Angular dev server"); }
    if sb == "astro" && has("dev") { return Some("Astro dev server"); }
    if sb == "vue-cli-service" && has("serve") { return Some("Vue CLI dev server"); }
    if sb == "parcel" && !has("build") { return Some("Parcel dev server"); }
    None
}

pub fn read_argv(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{}/cmdline", pid)).ok()
        .map(|b| b.split(|c| *c == 0).filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned()).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct DevServer {
    pub port: u16,
    pub bind: IpAddr,
    pub kind: &'static str,
    pub pid: u32,
    pub cwd: String,
    pub cmdline: String,
}

/// Dev servers in a target listening on a non-loopback address.
pub fn find(target: &Target) -> Vec<DevServer> {
    let socks = net::tcp_sockets(target.init_pid);
    let owners = net::inode_owners(&target.pids);
    let mut out: Vec<DevServer> = Vec::new();
    for s in socks.iter().filter(|s| s.state == net::TCP_LISTEN && !s.local.is_loopback()) {
        let Some(&pid) = owners.get(&s.inode) else { continue };
        let argv = read_argv(pid);
        let Some(kind) = dev_server_kind(&argv) else { continue };
        if out.iter().any(|d| d.port == s.local_port) { continue; } // v4 + v6 of the same listener
        out.push(DevServer {
            port: s.local_port,
            bind: s.local,
            kind,
            pid,
            cwd: std::fs::read_link(format!("/proc/{}/cwd", pid)).ok()
                .map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
            cmdline: argv.join(" ").chars().take(300).collect(),
        });
    }
    out
}

/// One upstream reference in a proxy config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRef {
    pub target_key: String,
    pub file: String,
    /// None = port only (`reverse_proxy :5373`).
    pub host: Option<String>,
    pub port: u16,
    pub line: String,
}

/// Config directories of the proxies and tunnels WolfStack hosts run.
const PROXY_CONFIG_DIRS: &[&str] = &[
    "etc/caddy", "etc/nginx", "etc/apache2", "etc/httpd", "etc/haproxy",
    "etc/traefik", "etc/cloudflared", "root/.cloudflared", "usr/local/etc/caddy",
];

/// Lines that name an upstream, by directive, per server's syntax.
fn upstream_line(l: &str) -> bool {
    let low = l.to_ascii_lowercase();
    ["reverse_proxy", "proxy_pass", "proxypass", "service:", "server ", "url:", "url =", "to "]
        .iter().any(|k| low.contains(k))
}

static UPSTREAM_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    // host:port with an optional scheme; host is a bracketed v6, a v4,
    // `localhost`, or empty (`:5373`).
    regex::Regex::new(r"(?i)(?:https?://)?(\[[0-9a-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}|localhost)?:(\d{2,5})\b")
        .expect("static regex")
});

pub fn refs_in_text(target_key: &str, file: &str, text: &str) -> Vec<ProxyRef> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') || !upstream_line(l) { continue; }
        for c in UPSTREAM_RE.captures_iter(l) {
            let Some(port) = c.get(2).and_then(|m| m.as_str().parse::<u16>().ok()) else { continue };
            // A bare `:5373` only means a port when it starts a word
            // (Caddy's `reverse_proxy :5373`), not inside `10:30`.
            let whole = c.get(0).map(|m| m.start()).unwrap_or(0);
            if c.get(1).is_none() && whole > 0
                && l.as_bytes()[whole - 1].is_ascii_alphanumeric() { continue; }
            out.push(ProxyRef {
                target_key: target_key.into(),
                file: file.into(),
                host: c.get(1).map(|m| m.as_str().trim_matches(|ch| ch == '[' || ch == ']').to_ascii_lowercase()),
                port,
                line: l.chars().take(200).collect(),
            });
        }
    }
    out
}

/// All upstream references in a target's proxy configs (bounded walk).
pub fn proxy_refs(target_key: &str, root: &RootFs) -> Vec<ProxyRef> {
    let mut out = Vec::new();
    let mut budget = 400usize;
    let mut stack: Vec<(String, u8)> = PROXY_CONFIG_DIRS.iter().map(|d| (d.to_string(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        for e in root.list_dir(&dir) {
            if budget == 0 { return out; }
            let p = format!("{}/{}", dir, e.name);
            // sites-enabled entries are usually symlinks into
            // sites-available — follow them by reading (in-root).
            if e.meta.is_dir() && depth < 3 {
                stack.push((p, depth + 1));
            } else if (e.meta.is_file() || e.meta.is_symlink()) && e.meta.size < (1 << 20) {
                budget -= 1;
                if let Some(t) = root.read_string(&p, 1 << 20) {
                    out.extend(refs_in_text(target_key, &format!("/{}", p), &t));
                }
            }
        }
    }
    out
}

/// Does `r` route to this dev server?
pub fn routes_to(r: &ProxyRef, dev_target_key: &str, dev_ips: &[IpAddr], port: u16) -> bool {
    if r.port != port { return false; }
    let host_ip: Option<IpAddr> = r.host.as_deref().and_then(|h| h.parse().ok());
    let same = r.target_key == dev_target_key;
    match (&r.host, host_ip) {
        (None, _) => same,
        (Some(h), _) if h == "localhost" => same,
        (_, Some(ip)) if ip.is_loopback() || ip.is_unspecified() => same,
        (_, Some(ip)) => dev_ips.contains(&ip),
        _ => false,
    }
}

/// A remotely-managed Cloudflare tunnel runs in the target.
pub fn has_token_tunnel(target: &Target) -> bool {
    target.pids.iter().any(|p| {
        let a = read_argv(*p);
        a.first().is_some_and(|x| x.ends_with("cloudflared"))
            && a.iter().any(|x| x == "--token" || x.starts_with("--token="))
    })
}

/// Globally-routable address (not RFC 1918 / CGNAT / ULA / link-local).
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified()
                || (o[0] == 100 && (64..=127).contains(&o[1])))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_loopback() || v.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> { s.split(' ').map(|x| x.to_string()).collect() }

    #[test]
    fn real_command_lines_from_the_nodejs_container() {
        assert_eq!(dev_server_kind(&argv("node /root/webapp/node_modules/.bin/vite")), Some("Vite dev server"));
        assert_eq!(dev_server_kind(&argv("node /root/landscaper/node_modules/.bin/vite --port 6473 --strictPort --host")), Some("Vite dev server"));
        // Relative path from a keepalive loop: still recognised as Vite…
        assert_eq!(dev_server_kind(&argv("node node_modules/.bin/vite --force")), Some("Vite dev server"));
        // …and `preview` (a production build server) is not a dev server.
        assert_eq!(dev_server_kind(&argv("node node_modules/.bin/vite preview --host 0.0.0.0 --port 6974 --strictPort")), None);
        assert_eq!(dev_server_kind(&argv("node /root/api/node_modules/.bin/tsx server/index.ts")), None);
        assert_eq!(dev_server_kind(&argv("node serve-prod.mjs")), None);
    }

    #[test]
    fn other_dev_servers() {
        assert_eq!(dev_server_kind(&argv("node /app/node_modules/.bin/next dev -p 3000")), Some("Next.js dev server"));
        assert_eq!(dev_server_kind(&argv("node /app/node_modules/.bin/next start")), None);
        assert_eq!(dev_server_kind(&argv("node /app/node_modules/react-scripts/scripts/start.js")), Some("Create React App dev server"));
        assert_eq!(dev_server_kind(&argv("node /app/node_modules/.bin/webpack serve")), Some("webpack-dev-server"));
    }

    #[test]
    fn proxy_refs_real_configs() {
        // Line shapes taken from real Caddy and cloudflared configs.
        let r = refs_in_text("lxc:nodejs", "/etc/caddy/Caddyfile", "\treverse_proxy localhost:5373");
        assert_eq!(r[0].host.as_deref(), Some("localhost"));
        assert_eq!(r[0].port, 5373);
        let r = refs_in_text("lxc:nodejs", "/etc/caddy/shop.caddy", "\treverse_proxy 127.0.0.1:5874");
        assert_eq!(r[0].port, 5874);
        // cloudflared ingress.
        let r = refs_in_text("lxc:nodejs", "/etc/cloudflared/app-prod.yml", "    service: http://localhost:5174");
        assert_eq!(r[0].port, 5174);
        // nginx upstream to another container.
        let r = refs_in_text("pve:100", "/etc/nginx/conf.d/x.conf", "proxy_pass http://10.0.10.118:3000;");
        assert_eq!(r[0].host.as_deref(), Some("10.0.10.118"));
        // Times and comments are not upstreams.
        assert!(refs_in_text("t", "f", "# reverse_proxy localhost:1234").is_empty());
        assert!(refs_in_text("t", "f", "log_format main 'at 10:30';").is_empty());
        // An upstream line that also carries a time: only the real
        // host:port is taken, not the bare ":30" glued to "10".
        let r = refs_in_text("t", "f", "proxy_pass http://127.0.0.1:8080; # moved 10:30");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].port, 8080);
    }

    #[test]
    fn routing_rules() {
        let ip: IpAddr = "10.0.10.118".parse().unwrap();
        let local = ProxyRef { target_key: "lxc:nodejs".into(), file: "f".into(), host: Some("localhost".into()), port: 5373, line: String::new() };
        assert!(routes_to(&local, "lxc:nodejs", &[ip], 5373));
        assert!(!routes_to(&local, "lxc:other", &[ip], 5373), "localhost in another CT is that CT");
        let cross = ProxyRef { target_key: "pve:100".into(), host: Some("10.0.10.118".into()), ..local.clone() };
        assert!(routes_to(&cross, "lxc:nodejs", &[ip], 5373));
        let port_only = ProxyRef { host: None, ..local.clone() };
        assert!(routes_to(&port_only, "lxc:nodejs", &[ip], 5373));
        assert!(!routes_to(&local, "lxc:nodejs", &[ip], 5374));
    }

    #[test]
    fn public_addresses() {
        assert!(is_public(&"116.202.127.17".parse().unwrap()));
        assert!(!is_public(&"10.0.10.118".parse().unwrap()));
        assert!(!is_public(&"100.64.12.34".parse().unwrap()), "Tailscale CGNAT is not public");
        assert!(!is_public(&"fd7a:115c:a1e0::235:db54".parse().unwrap()));
    }
}
