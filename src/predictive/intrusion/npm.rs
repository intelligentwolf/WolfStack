// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Installed npm packages compared, file by file, with the registry.
//!
//! In a November 2026 LILITH_VITE_V3 compromise, `vite/bin/vite.js`,
//! `vite/dist/node/cli.js` and `vite/dist/node/index.js` were rewritten
//! in four projects — every `vite` start re-armed the webshell. Nothing in
//! a lockfile catches that: `package-lock.json` pins the tarball hash,
//! and npm never re-checks extracted files.
//!
//! For each installed copy of a high-risk package (dev servers and the
//! loaders they run on — the code that executes every time a developer
//! or keepalive loop starts a project), this fetches the exact version
//! from registry.npmjs.org, verifies the tarball against the registry's
//! own `dist.integrity` (SRI sha512), and compares every file's SHA-256
//! with what is on disk.
//!
//! ## Trust and cost
//!
//! * The package name comes from the fixed [`WATCHLIST`], never from the
//!   target; the version string the target supplies is validated before
//!   it touches a URL or a filename. Tarball URLs must be on
//!   registry.npmjs.org.
//! * Pristine digests are cached on disk per name@version — 97 vite
//!   installs of one version are one download, ever.
//! * A verified install is re-hashed only when one of its files' ctime
//!   moves (a rewrite always moves ctime) or after [`REVERIFY_SECS`].
//! * Each tick spends at most [`TICK_BUDGET`] on this and fetches at
//!   most [`FETCHES_PER_TICK`] tarballs; the rest wait for the next tick.
//! * Offline / registry errors leave the install "unverified" — never a
//!   finding.
//!
//! `package.json` is compared by the fields that decide what code runs
//! (`main`, `module`, `exports`, `bin`, `browser`, `type`, `scripts`),
//! because npm ≤ 6 rewrote that file at install time (`_resolved`,
//! `_integrity`, …) and a byte compare would flag every old install.

use super::rootfs::RootFs;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// Packages whose code runs whenever a project is started.
pub const WATCHLIST: &[&str] = &[
    "vite", "webpack-dev-server", "next", "tsx", "esbuild",
    "@esbuild/linux-x64", "@esbuild/linux-arm64",
];
pub const REVERIFY_SECS: i64 = 24 * 3600;
pub const TICK_BUDGET: Duration = Duration::from_secs(60);
pub const FETCHES_PER_TICK: usize = 4;
const DISCOVERY_SECS: i64 = 6 * 3600;
const REGISTRY: &str = "https://registry.npmjs.org/";
const MAX_TARBALL: usize = 64 << 20;
const MAX_FILES: usize = 20_000;
const MAX_FILE: usize = 64 << 20;
/// package.json fields that decide which code executes.
const PKG_CODE_FIELDS: &[&str] = &["main", "module", "exports", "bin", "browser", "type", "scripts"];

/// A published release version: `MAJOR.MINOR.PATCH` with optional
/// `-prerelease` / `+build` (semver.org §2, §9, §10). Dist-tags such as
/// `latest` are NOT versions — fetching one would cache whatever the tag
/// points at today under that name, forever.
pub fn valid_version(v: &str) -> bool {
    if v.is_empty() || v.len() > 64
        || !v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+')) {
        return false;
    }
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Why a pristine copy could not be obtained.
#[derive(Debug, Clone, PartialEq)]
pub enum FetchErr {
    /// The registry says this name@version does not exist.
    NotPublished,
    /// Anything else (offline, timeout, bad response) — retry later.
    Other(String),
}

// ─── Minimal tar reader (ustar + PAX + GNU long names) ─────────────

/// Parse an octal or base-256 numeric tar field (POSIX ustar; GNU
/// base-256 sets the top bit of the first byte).
fn tar_num(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = (field[0] & 0x7f) as u64;
        for b in &field[1..] { v = v.checked_mul(256)?.checked_add(*b as u64)?; }
        return Some(v);
    }
    let s: String = field.iter().take_while(|b| **b != 0).map(|b| *b as char).collect();
    let s = s.trim();
    if s.is_empty() { return Some(0); }
    u64::from_str_radix(s, 8).ok()
}

fn cstr(field: &[u8]) -> String {
    String::from_utf8_lossy(&field[..field.iter().position(|b| *b == 0).unwrap_or(field.len())]).into_owned()
}

/// Header checksum: sum of all bytes with the checksum field read as spaces.
fn checksum_ok(h: &[u8]) -> bool {
    let want = match tar_num(&h[148..156]) { Some(v) => v, None => return false };
    let sum: u64 = h.iter().enumerate()
        .map(|(i, b)| if (148..156).contains(&i) { b' ' as u64 } else { *b as u64 })
        .sum();
    sum == want
}

/// Regular files of a tar archive as (path, contents).
pub fn tar_files(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut next_name: Option<String> = None;
    while off + 512 <= data.len() {
        let h = &data[off..off + 512];
        if h.iter().all(|b| *b == 0) { break; }
        if !checksum_ok(h) { return Err(format!("bad tar header checksum at {}", off)); }
        let size = tar_num(&h[124..136]).ok_or("bad size")? as usize;
        let typeflag = h[156];
        let body_start = off + 512;
        let body_end = body_start.checked_add(size).ok_or("size overflow")?;
        if body_end > data.len() { return Err("truncated tar".into()); }
        let body = &data[body_start..body_end];
        let ustar = &h[257..262] == b"ustar";
        let mut name = cstr(&h[0..100]);
        if ustar {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() { name = format!("{}/{}", prefix, name); }
        }
        match typeflag {
            b'x' => {
                // PAX records: "<len> <key>=<value>\n".
                let text = String::from_utf8_lossy(body);
                for rec in text.split('\n') {
                    if let Some((_, kv)) = rec.split_once(' ')
                        && let Some(p) = kv.strip_prefix("path=") {
                        next_name = Some(p.to_string());
                    }
                }
            }
            b'L' => next_name = Some(cstr(body)),
            b'0' | 0 => {
                let n = next_name.take().unwrap_or(name);
                out.push((n, body.to_vec()));
                if out.len() > MAX_FILES { return Err("too many files".into()); }
            }
            _ => { next_name = None; }
        }
        off = body_start + size.div_ceil(512) * 512;
    }
    Ok(out)
}

/// Drop the archive's top directory (`package/` in every npm tarball
/// checked; some old packages use another name) and refuse any path that
/// would climb (`..`) or is absolute.
pub fn package_relative(path: &str) -> Option<String> {
    let rest = path.split_once('/')?.1;
    if rest.is_empty() || rest.starts_with('/') || rest.split('/').any(|c| c == "..") { return None; }
    Some(rest.to_string())
}

// ─── Pristine digests ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pristine {
    pub name: String,
    pub version: String,
    pub integrity: String,
    /// relative path → sha256 hex
    pub files: BTreeMap<String, String>,
    /// PKG_CODE_FIELDS of the published package.json
    pub pkg_fields: BTreeMap<String, serde_json::Value>,
}

fn pristine_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/lib/wolfstack/npm-pristine")
}

fn pristine_file(name: &str, version: &str) -> std::path::PathBuf {
    pristine_dir().join(format!("{}@{}.json", name.replace('/', "__"), version))
}

fn code_fields(pkg_json: &[u8]) -> BTreeMap<String, serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(pkg_json).unwrap_or(serde_json::Value::Null);
    PKG_CODE_FIELDS.iter()
        .filter_map(|k| v.get(*k).map(|x| (k.to_string(), x.clone())))
        .collect()
}

/// SRI check: `sha512-<base64>` against the tarball bytes.
pub fn sri_matches(integrity: &str, data: &[u8]) -> bool {
    use base64::Engine;
    use sha2::{Digest, Sha512};
    let Some(b64) = integrity.strip_prefix("sha512-") else { return false };
    let got = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(data));
    got == b64
}

static HTTP: std::sync::LazyLock<Option<reqwest::blocking::Client>> = std::sync::LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        // Bound the connect as well as the request — enforced by
        // tests/resource_safety.rs after the 2026-08-05 fd exhaustion.
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .user_agent(format!("WolfStack/{} (npm-integrity)", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()
});

fn fetch_bytes(url: &str, cap: usize) -> Result<Vec<u8>, FetchErr> {
    use std::io::Read;
    let client = HTTP.as_ref().ok_or(FetchErr::Other("http client unavailable".into()))?;
    let resp = client.get(url).send().map_err(|e| FetchErr::Other(format!("GET {}: {}", url, e)))?;
    if !resp.status().is_success() {
        // Drain before leaving so the connection is released, not parked
        // in CLOSE-WAIT (tests/resource_safety.rs). Registry error bodies
        // are a few hundred bytes of JSON.
        let status = resp.status();
        let _ = resp.bytes();
        if status == reqwest::StatusCode::NOT_FOUND { return Err(FetchErr::NotPublished); }
        return Err(FetchErr::Other(format!("GET {}: HTTP {}", url, status)));
    }
    let mut buf = Vec::new();
    resp.take(cap as u64 + 1).read_to_end(&mut buf).map_err(|e| FetchErr::Other(format!("read {}: {}", url, e)))?;
    if buf.len() > cap { return Err(FetchErr::Other(format!("{} exceeds {} bytes", url, cap))); }
    Ok(buf)
}

/// Fetch, verify and digest `name@version` from the registry.
fn fetch_pristine(name: &str, version: &str) -> Result<Pristine, FetchErr> {
    let other = FetchErr::Other;
    let meta_url = format!("{}{}/{}", REGISTRY, name.replace('/', "%2f"), version);
    let meta: serde_json::Value = serde_json::from_slice(&fetch_bytes(&meta_url, 4 << 20)?)
        .map_err(|e| other(format!("registry metadata: {}", e)))?;
    let dist = meta.get("dist").ok_or(other("registry metadata has no dist".into()))?;
    let tarball = dist.get("tarball").and_then(|v| v.as_str()).ok_or(other("no dist.tarball".into()))?;
    let integrity = dist.get("integrity").and_then(|v| v.as_str()).ok_or(other("no dist.integrity".into()))?;
    if !tarball.starts_with(REGISTRY) {
        return Err(other(format!("refusing tarball outside the registry: {}", tarball)));
    }
    let gz = fetch_bytes(tarball, MAX_TARBALL)?;
    if !sri_matches(integrity, &gz) {
        return Err(other(format!("{}@{} tarball does not match dist.integrity", name, version)));
    }
    let mut tar = Vec::new();
    {
        use std::io::Read;
        flate2::read::GzDecoder::new(&gz[..]).take(MAX_TARBALL as u64 * 8)
            .read_to_end(&mut tar).map_err(|e| other(format!("gunzip: {}", e)))?;
    }
    let mut files = BTreeMap::new();
    let mut pkg_fields = BTreeMap::new();
    for (path, body) in tar_files(&tar).map_err(other)? {
        let Some(rel) = package_relative(&path) else { continue };
        if rel == "package.json" { pkg_fields = code_fields(&body); }
        files.insert(rel, super::sysfiles::sha256_hex(&body));
    }
    Ok(Pristine { name: name.into(), version: version.into(), integrity: integrity.into(), files, pkg_fields })
}

fn load_pristine(name: &str, version: &str) -> Option<Pristine> {
    let s = std::fs::read_to_string(pristine_file(name, version)).ok()?;
    serde_json::from_str(&s).ok()
}

fn store_pristine(p: &Pristine) {
    use std::os::unix::fs::DirBuilderExt;
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(pristine_dir());
    let path = pristine_file(&p.name, &p.version);
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec(p).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

// ─── Discovery ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Installed {
    /// Target-absolute package directory.
    pub dir: String,
    pub name: &'static str,
    pub version: String,
}

const SEARCH_ROOTS: &[&str] = &[
    "root", "home", "opt", "srv", "var/www", "app", "usr/lib/node_modules", "usr/local/lib/node_modules",
];
const SKIP_DIRS: &[&str] = &[".git", ".cache", ".npm", ".pnpm-store", ".yarn", "proc", "sys", "dev"];

fn installed_at(root: &RootFs, dir: &str, name: &'static str) -> Option<Installed> {
    let pj = root.read(&format!("{}/package.json", dir), 1 << 20)?;
    let v: serde_json::Value = serde_json::from_slice(&pj).ok()?;
    if v.get("name")?.as_str()? != name { return None; }
    // Kept even when the version is not a release version: an install that
    // cannot be checked against the registry is itself reported (an
    // attacker who rewrites vite can rewrite its version string too). The
    // string is bounded here and never used in a URL or path unless valid.
    let version: String = v.get("version").and_then(|x| x.as_str()).unwrap_or("")
        .chars().take(64).collect();
    Some(Installed { dir: format!("/{}", dir), name, version })
}

/// Watch-listed packages directly under a node_modules dir, under its
/// packages' own node_modules (one level of nesting), and in a pnpm
/// virtual store (`.pnpm/<name>@<ver>/node_modules/<name>`).
fn scan_node_modules(root: &RootFs, nm: &str, out: &mut Vec<Installed>, budget: &mut usize) {
    for name in WATCHLIST {
        if let Some(i) = installed_at(root, &format!("{}/{}", nm, name), name) { out.push(i); }
    }
    let ents = root.list_dir(nm);
    *budget = budget.saturating_sub(ents.len());
    for e in &ents {
        if *budget == 0 { return; }
        if !e.meta.is_dir() { continue; }
        if e.name == ".pnpm" {
            for p in root.list_dir(&format!("{}/.pnpm", nm)) {
                for name in WATCHLIST {
                    let flat = name.replace('/', "+");
                    if p.name.starts_with(&format!("{}@", flat))
                        && let Some(i) = installed_at(root, &format!("{}/.pnpm/{}/node_modules/{}", nm, p.name, name), name) {
                        out.push(i);
                    }
                }
            }
            continue;
        }
        let children: Vec<String> = if e.name.starts_with('@') {
            root.list_dir(&format!("{}/{}", nm, e.name)).into_iter()
                .filter(|c| c.meta.is_dir()).map(|c| format!("{}/{}/{}", nm, e.name, c.name)).collect()
        } else {
            vec![format!("{}/{}", nm, e.name)]
        };
        for c in children {
            let nested = format!("{}/node_modules", c);
            if !root.lstat(&nested).is_some_and(|m| m.is_dir()) { continue; }
            for name in WATCHLIST {
                if let Some(i) = installed_at(root, &format!("{}/{}", nested, name), name) { out.push(i); }
            }
        }
    }
}

/// Find watch-listed installs in a target. Bounded by a directory budget.
pub fn discover(root: &RootFs) -> Vec<Installed> {
    let mut out = Vec::new();
    let mut budget: usize = 200_000;
    let mut stack: Vec<(String, u8)> = SEARCH_ROOTS.iter().map(|r| (r.to_string(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if budget == 0 { break; }
        if dir.ends_with("node_modules") || dir == "usr/lib/node_modules" || dir == "usr/local/lib/node_modules" {
            scan_node_modules(root, &dir, &mut out, &mut budget);
            continue;
        }
        if depth >= 6 { continue; }
        let ents = root.list_dir(&dir);
        budget = budget.saturating_sub(ents.len());
        for e in ents {
            if !e.meta.is_dir() || SKIP_DIRS.contains(&e.name.as_str()) { continue; }
            stack.push((format!("{}/{}", dir, e.name), depth + 1));
        }
    }
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out.dedup_by(|a, b| a.dir == b.dir);
    out
}

// ─── Verification ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Clean,
    /// Files whose content differs from the registry, and files missing.
    Tampered { changed: Vec<String>, missing: Vec<String> },
    /// A watch-listed package that cannot exist as published: its version
    /// is not a release version, or the registry does not have it.
    Unpublished(String),
    /// Could not check this time (offline, budget spent) — never a finding.
    Unverified(String),
    /// The install directory no longer exists — a release swap, `rm -rf
    /// node_modules`, a reinstall. Nothing left to run, so nothing to
    /// report; any earlier card for it resolves.
    Gone,
}

/// (newest ctime, number of files present): a rewrite moves the first, a
/// deletion moves the second.
///
/// Installs disappear between passes all the time: discovery is cached for
/// [`DISCOVERY_SECS`], and deploy pipelines swap whole release trees. A
/// vanished install directory is [`Outcome::Gone`], never "every file
/// missing". Files missing from a directory that still exists are reported
/// only when two passes agree, so a scan that lands in the middle of an
/// `rm -rf` (files going, the directory not gone yet) raises nothing.
type Stamp = (i64, usize);

#[derive(Debug, Clone)]
struct CacheEntry {
    version: String,
    stamp: Stamp,
    checked_at: i64,
    outcome: Outcome,
}

struct State {
    /// target key → (discovered_at, installs)
    discovered: HashMap<String, (i64, Vec<Installed>)>,
    /// (target key, dir) → last verification
    verified: HashMap<(String, String), CacheEntry>,
}

static STATE: std::sync::LazyLock<std::sync::Mutex<State>> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(State { discovered: HashMap::new(), verified: HashMap::new() })
});

/// The `@esbuild/*` platform package for this build target, as esbuild's
/// install.js names it (`pkgAndSubpathForCurrentPlatform`): Linux x64 and
/// arm64 are the platforms WolfStack ships for.
pub fn esbuild_platform_package() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("@esbuild/linux-x64"),
        "aarch64" => Some("@esbuild/linux-arm64"),
        _ => None,
    }
}

/// Files a package's OWN install script legitimately replaces, and the
/// digest the replacement must have.
///
/// esbuild's postinstall (`install.js` `maybeOptimizePackage`) hard-links
/// `bin/esbuild` — published as a small JS launcher — to the platform
/// package's native binary, so the launcher no longer has to spawn it.
/// That is accepted ONLY when the installed file is byte-identical to the
/// registry-verified `bin/esbuild` of the same-version platform package;
/// anything else in that file is still reported.
pub fn install_rewrites(inst: &Installed, platform: Option<&Pristine>) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if inst.name == "esbuild"
        && let Some(p) = platform
        && p.version == inst.version
        && let Some(sha) = p.files.get("bin/esbuild") {
        m.insert("bin/esbuild".to_string(), sha.clone());
    }
    m
}

/// Compare an install with its pristine digests. `stamp` = newest ctime
/// among the package's files. `rewrites` (see [`install_rewrites`]) are
/// alternative digests a file may carry after its package's install step.
pub fn compare(root: &RootFs, inst: &Installed, p: &Pristine, rewrites: &HashMap<String, String>) -> (Outcome, Stamp) {
    let mut changed = Vec::new();
    let mut missing = Vec::new();
    let mut stamp: Stamp = (0, 0);
    for (rel, sha) in &p.files {
        let path = format!("{}/{}", inst.dir, rel);
        if let Some(m) = root.lstat(&path) { stamp = (stamp.0.max(m.ctime), stamp.1 + 1); }
        let Some(body) = root.read(&path, MAX_FILE) else { missing.push(rel.clone()); continue };
        if rel == "package.json" {
            if code_fields(&body) != p.pkg_fields { changed.push(rel.clone()); }
        } else {
            let got = super::sysfiles::sha256_hex(&body);
            if got != *sha && rewrites.get(rel) != Some(&got) {
                changed.push(rel.clone());
            }
        }
    }
    let outcome = if changed.is_empty() && missing.is_empty() {
        Outcome::Clean
    } else {
        Outcome::Tampered { changed, missing }
    };
    (outcome, stamp)
}

#[derive(Debug, PartialEq)]
enum Settled {
    /// The install directory is gone — it was deleted while (or before)
    /// being compared, not tampered with.
    Gone,
    /// Files are missing but none changed, seen for the first time: cache
    /// it and report only if the next pass agrees.
    Hold,
    Report,
}

/// What to do with a fresh comparison. `dir_gone` is asked only when
/// files are missing. `previous` is the cached outcome for the same
/// version, if any.
fn settle(outcome: &Outcome, dir_gone: impl FnOnce() -> bool, previous: Option<&Outcome>) -> Settled {
    let Outcome::Tampered { changed, missing } = outcome else { return Settled::Report };
    if missing.is_empty() { return Settled::Report; }
    if dir_gone() { return Settled::Gone; }
    if changed.is_empty() && previous != Some(outcome) { return Settled::Hold; }
    Settled::Report
}

/// Drop what is cached about an install that no longer exists, and the
/// target's discovery list with it so the next pass finds what replaced it
/// (a new release directory) instead of waiting out [`DISCOVERY_SECS`].
fn forget_install(target_key: &str, ckey: &(String, String)) {
    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    st.verified.remove(ckey);
    st.discovered.remove(target_key);
}

fn stamp_of(root: &RootFs, inst: &Installed, p: &Pristine) -> Stamp {
    p.files.keys().filter_map(|r| root.lstat(&format!("{}/{}", inst.dir, r)).map(|m| m.ctime))
        .fold((0, 0), |(t, n), c| (t.max(c), n + 1))
}

/// One target's results this tick: (install, outcome) for every install
/// with a known outcome. `deadline` and `fetches` are shared across all
/// targets of the tick.
pub fn check_target(
    target_key: &str,
    root: &RootFs,
    now: i64,
    deadline: Instant,
    fetches: &mut usize,
) -> Vec<(Installed, Outcome)> {
    let installs = {
        let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
        match st.discovered.get(target_key) {
            Some((at, list)) if now - at < DISCOVERY_SECS => list.clone(),
            _ => {
                drop(st);
                let list = discover(root);
                st = STATE.lock().unwrap_or_else(|e| e.into_inner());
                st.discovered.insert(target_key.to_string(), (now, list.clone()));
                list
            }
        }
    };
    let mut out = Vec::new();
    for inst in installs {
        let ckey = (target_key.to_string(), inst.dir.clone());
        if root.is_missing(&inst.dir) {
            forget_install(target_key, &ckey);
            out.push((inst, Outcome::Gone));
            continue;
        }
        if !valid_version(&inst.version) {
            let why = format!("its package.json version {:?} is not a release version", inst.version);
            out.push((inst, Outcome::Unpublished(why)));
            continue;
        }
        let cached = STATE.lock().unwrap_or_else(|e| e.into_inner()).verified.get(&ckey).cloned();
        let pristine = match load_pristine(inst.name, &inst.version) {
            Some(p) => Some(p),
            None if Instant::now() < deadline && *fetches < FETCHES_PER_TICK => {
                *fetches += 1;
                match fetch_pristine(inst.name, &inst.version) {
                    Ok(p) => { store_pristine(&p); Some(p) }
                    Err(FetchErr::NotPublished) => {
                        let why = format!("registry.npmjs.org has no {}@{}", inst.name, inst.version);
                        out.push((inst, Outcome::Unpublished(why)));
                        continue;
                    }
                    Err(FetchErr::Other(e)) => {
                        tracing::debug!("npm-integrity: {}@{} unverifiable: {}", inst.name, inst.version, e);
                        out.push((inst, Outcome::Unverified(e)));
                        continue;
                    }
                }
            }
            None => None,
        };
        let Some(p) = pristine else {
            // No digests yet and no budget left this tick: report the
            // last known outcome for this exact version, if any.
            if let Some(c) = cached.filter(|c| c.version == inst.version) { out.push((inst, c.outcome)); }
            continue;
        };
        if let Some(c) = &cached
            && c.version == inst.version && now - c.checked_at < REVERIFY_SECS
            && stamp_of(root, &inst, &p) == c.stamp {
            out.push((inst, c.outcome.clone()));
            continue;
        }
        if Instant::now() >= deadline {
            if let Some(c) = cached.filter(|c| c.version == inst.version) { out.push((inst, c.outcome)); }
            continue;
        }
        // esbuild's install step swaps in the platform binary — needs that
        // package's registry digests (same version) to judge bin/esbuild.
        let platform = if inst.name == "esbuild" {
            esbuild_platform_package().and_then(|pp| load_pristine(pp, &inst.version).or_else(|| {
                if *fetches >= FETCHES_PER_TICK { return None; }
                *fetches += 1;
                fetch_pristine(pp, &inst.version).ok().inspect(store_pristine)
            }))
        } else { None };
        if inst.name == "esbuild" && platform.is_none() {
            // Can't judge bin/esbuild yet; try again next tick rather than
            // reporting the legitimate native binary as tampering.
            if let Some(c) = cached.filter(|c| c.version == inst.version) { out.push((inst, c.outcome)); }
            continue;
        }
        let (outcome, stamp) = compare(root, &inst, &p, &install_rewrites(&inst, platform.as_ref()));
        let previous = cached.as_ref().filter(|c| c.version == inst.version).map(|c| &c.outcome);
        let settled = settle(&outcome, || root.is_missing(&inst.dir), previous);
        if settled == Settled::Gone {
            forget_install(target_key, &ckey);
            out.push((inst, Outcome::Gone));
            continue;
        }
        STATE.lock().unwrap_or_else(|e| e.into_inner()).verified.insert(ckey, CacheEntry {
            version: inst.version.clone(), stamp, checked_at: now, outcome: outcome.clone(),
        });
        if settled == Settled::Report { out.push((inst, outcome)); }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ustar archive the way npm's node-tar does (regular files,
    /// `package/` prefix), with a correct header checksum.
    fn ustar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, body) in entries {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            let size = format!("{:011o}", body.len());
            h[124..135].copy_from_slice(size.as_bytes());
            h[136..147].copy_from_slice(b"00000000000");
            h[156] = b'0';
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            for b in &mut h[148..156] { *b = b' '; }
            let sum: u32 = h.iter().map(|b| *b as u32).sum();
            let ck = format!("{:06o}\0 ", sum);
            h[148..156].copy_from_slice(ck.as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    #[test]
    fn reads_npm_style_ustar() {
        let t = ustar(&[("package/bin/vite.js", b"#!/usr/bin/env node\n"), ("package/package.json", b"{\"name\":\"vite\"}")]);
        let f = tar_files(&t).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].0, "package/bin/vite.js");
        assert_eq!(package_relative(&f[0].0).as_deref(), Some("bin/vite.js"));
    }

    #[test]
    fn rejects_corrupt_headers_and_climbing_paths() {
        let mut t = ustar(&[("package/a.js", b"x")]);
        t[10] ^= 0xff;
        assert!(tar_files(&t).is_err());
        assert_eq!(package_relative("package/../../etc/passwd"), None);
        assert_eq!(package_relative("package//etc/passwd"), None);
    }

    #[test]
    fn pax_path_overrides_header_name() {
        // A PAX 'x' record naming a long path, then the file it applies to.
        // Record length counts itself, the space and the newline (31).
        let rec = "31 path=package/very/long/x.js\n";
        let mut h = [0u8; 512];
        h[..14].copy_from_slice(b"PaxHeader/x.js");
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{:011o}", rec.len()).as_bytes());
        h[156] = b'x';
        h[257..263].copy_from_slice(b"ustar\0");
        for b in &mut h[148..156] { *b = b' '; }
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        let mut t = h.to_vec();
        t.extend_from_slice(rec.as_bytes());
        t.resize(t.len().div_ceil(512) * 512, 0);
        t.extend(ustar(&[("package/short.js", b"y")]));
        let f = tar_files(&t).unwrap();
        assert_eq!(f[0].0, "package/very/long/x.js");
    }

    #[test]
    fn sri_check() {
        // sha512 of the empty input, base64 (FIPS 180-4 test vector).
        assert!(sri_matches(
            "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==", b""));
        assert!(!sri_matches("sha512-AAAA", b""));
        assert!(!sri_matches("sha1-xyz", b""));
    }

    #[test]
    fn esbuild_native_binary_rewrite_is_accepted_only_when_identical() {
        let inst = Installed { dir: "/x/node_modules/esbuild".into(), name: "esbuild", version: "0.25.6".into() };
        let platform = Pristine {
            name: "@esbuild/linux-x64".into(), version: "0.25.6".into(), integrity: String::new(),
            files: [("bin/esbuild".to_string(), "native-sha".to_string())].into(),
            pkg_fields: BTreeMap::new(),
        };
        let r = install_rewrites(&inst, Some(&platform));
        assert_eq!(r.get("bin/esbuild").map(|s| s.as_str()), Some("native-sha"));
        // A different version's binary is not an acceptable replacement.
        let other = Pristine { version: "0.25.7".into(), ..platform.clone() };
        assert!(install_rewrites(&inst, Some(&other)).is_empty());
        // Other packages never get an exemption.
        let vite = Installed { name: "vite", ..inst.clone() };
        assert!(install_rewrites(&vite, Some(&platform)).is_empty());
    }

    #[test]
    fn settle_never_reports_a_deleted_install() {
        let missing = Outcome::Tampered { changed: vec![], missing: vec!["bin/vite.js".into()] };
        let rewritten = Outcome::Tampered { changed: vec!["bin/vite.js".into()], missing: vec![] };
        let both = Outcome::Tampered { changed: vec!["bin/vite.js".into()], missing: vec!["x.js".into()] };
        // The release-swap false positive: every file missing because the
        // directory went away.
        assert_eq!(settle(&missing, || true, None), Settled::Gone);
        assert_eq!(settle(&both, || true, Some(&both)), Settled::Gone);
        // Files missing from a directory that still exists: held once,
        // reported when the next pass sees the same thing.
        assert_eq!(settle(&missing, || false, None), Settled::Hold);
        assert_eq!(settle(&missing, || false, Some(&Outcome::Clean)), Settled::Hold);
        assert_eq!(settle(&missing, || false, Some(&missing)), Settled::Report);
        // A rewritten file is reported at once — the kit's signature must
        // never wait a pass — and the directory is not even consulted.
        assert_eq!(settle(&rewritten, || panic!("not needed"), None), Settled::Report);
        assert_eq!(settle(&both, || false, None), Settled::Report);
        assert_eq!(settle(&Outcome::Clean, || panic!("not needed"), None), Settled::Report);
    }

    #[test]
    fn vanished_install_is_gone_and_rediscovered() {
        let base = std::env::temp_dir().join(format!("ws-npm-gone-{}", std::process::id()));
        let dir = base.join("release-a/node_modules/vite");
        std::fs::create_dir_all(&dir).unwrap();
        let root = RootFs::for_pid(std::process::id()).expect("open own root");
        // "latest" is not a release version, so the check never reaches
        // the network: a present install is Unpublished, a deleted one Gone.
        let key = format!("test:gone-{}", std::process::id());
        let inst = Installed { dir: dir.to_str().unwrap().to_string(), name: "vite", version: "latest".into() };
        STATE.lock().unwrap().discovered.insert(key.clone(), (0, vec![inst]));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut fetches = FETCHES_PER_TICK; // no registry budget
        let r = check_target(&key, &root, 1, deadline, &mut fetches);
        assert!(matches!(r[0].1, Outcome::Unpublished(_)));
        std::fs::remove_dir_all(base.join("release-a")).unwrap();
        let r = check_target(&key, &root, 2, deadline, &mut fetches);
        assert_eq!(r[0].1, Outcome::Gone);
        // The stale discovery list is dropped so the next pass walks again.
        assert!(!STATE.lock().unwrap().discovered.contains_key(&key));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn version_validation() {
        assert!(valid_version("6.4.2"));
        assert!(valid_version("15.0.0-canary.12+build"));
        assert!(!valid_version("../../etc"));
        assert!(!valid_version("1.0.0/evil"));
        assert!(!valid_version(""));
        // Dist-tags and partial versions are not release versions.
        assert!(!valid_version("latest"));
        assert!(!valid_version("beta"));
        assert!(!valid_version("6.4"));
        assert!(!valid_version("6.x.2"));
    }

    #[test]
    fn package_json_compared_by_code_fields_only() {
        let published = br#"{"name":"vite","version":"6.4.2","bin":{"vite":"bin/vite.js"},"main":"./dist/node/index.js"}"#;
        // npm 6 adds bookkeeping fields at install time — not a change.
        let npm6 = br#"{"_resolved":"https://registry.npmjs.org/vite/-/vite-6.4.2.tgz","_integrity":"sha512-x","name":"vite","version":"6.4.2","bin":{"vite":"bin/vite.js"},"main":"./dist/node/index.js"}"#;
        assert_eq!(code_fields(published), code_fields(npm6));
        // Repointing the binary IS a change.
        let evil = br#"{"name":"vite","version":"6.4.2","bin":{"vite":"bin/.x.js"},"main":"./dist/node/index.js"}"#;
        assert_ne!(code_fields(published), code_fields(evil));
    }
}
