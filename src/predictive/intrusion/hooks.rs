// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Code-injection hooks: loader variables that make an interpreter or
//! the dynamic linker load an extra file into every process.
//!
//! The LILITH_VITE_V3 kit (seen in the wild, November 2026) persisted by
//! appending to `/etc/profile`, `/root/.bashrc` and `/root/.profile`:
//!
//! ```text
//! export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require /etc/node-telemetry-preload.cjs"
//! ```
//!
//! so every Node process started from a login shell loaded a webshell.
//! 46 production servers carried it. Nothing at the time looked.
//!
//! Variables covered, each with the flag that makes it load code:
//!
//! | variable                         | loads code when it contains            |
//! |----------------------------------|----------------------------------------|
//! | `NODE_OPTIONS`                   | `--require` `-r` `--import` `--loader` `--experimental-loader` |
//! | `LD_PRELOAD`, `LD_AUDIT`         | any value (ld.so(8))                   |
//! | `PERL5OPT`                       | `-M` / `-m` (perlrun(1))               |
//! | `RUBYOPT`                        | `-r` (ruby(1))                         |
//! | `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS` | `-javaagent` |
//!
//! Plus `/etc/ld.so.preload`, whose every line is a library the dynamic
//! linker loads into every dynamically-linked program (ld.so(8)).
//!
//! ## Verdicts
//!
//! A hook is judged by what it loads, not by its existence — APM agents
//! legitimately use `NODE_OPTIONS=--require`, and Mastodon's install
//! guide uses `LD_PRELOAD=libjemalloc.so.2`:
//!
//! * a referenced file owned by a package → not reported;
//! * an unowned file in a hiding place (`/tmp`, `/dev/shm`, `/var/tmp`,
//!   `/etc`, `/root`, `/home`, or any dot-directory) → **Critical**;
//! * any other unowned file, or a bare module name that cannot be
//!   resolved to a path → **High**.

use super::rootfs::RootFs;

/// A loader variable and the flags (empty = any value) that make it load code.
const LOADER_VARS: &[(&str, &[&str])] = &[
    ("NODE_OPTIONS", &["--require", "-r", "--import", "--loader", "--experimental-loader"]),
    ("LD_PRELOAD", &[]),
    ("LD_AUDIT", &[]),
    ("PERL5OPT", &["-M", "-m"]),
    ("RUBYOPT", &["-r"]),
    ("JAVA_TOOL_OPTIONS", &["-javaagent"]),
    ("_JAVA_OPTIONS", &["-javaagent"]),
    ("JDK_JAVA_OPTIONS", &["-javaagent"]),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub var: String,
    /// The assigned value as written (shell quoting left in place).
    pub value: String,
    /// Absolute paths or module names the hook loads.
    pub refs: Vec<String>,
}

/// Split a value into words. Shell punctuation is a separator as well
/// as whitespace: in the kit's own line the flag is glued to a
/// parameter expansion — `"${NODE_OPTIONS:+$NODE_OPTIONS }--require /etc/…"`
/// — so a whitespace-only split yields `}--require` and misses it.
fn words(value: &str) -> Vec<String> {
    value.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '{' | '}' | '(' | ')' | ';' | '`'))
        .filter(|w| !w.is_empty())
        .map(|w| w.to_string())
        .collect()
}

/// Is `var` assigned on this line? Returns the text after the `=`.
/// Recognises shell (`VAR=`, `export VAR=`, `VAR+=`), systemd
/// (`Environment=VAR=…`, `Environment="VAR=…"`), environment.d / pam_env
/// (`VAR DEFAULT=` / `VAR OVERRIDE=`). A mention that is not an
/// assignment — `${NODE_OPTIONS:-}` in a `case` — is not one.
pub fn assignment_value<'a>(line: &'a str, var: &str) -> Option<&'a str> {
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(off) = line[start..].find(var) {
        let i = start + off;
        let before_ok = i == 0 || {
            let c = bytes[i - 1];
            !(c.is_ascii_alphanumeric() || c == b'_')
        };
        let after = &line[i + var.len()..];
        if before_ok {
            if let Some(v) = after.strip_prefix('=').or_else(|| after.strip_prefix("+=")) {
                return Some(v);
            }
            let t = after.trim_start();
            if t.len() < after.len()
                && let Some(v) = t.strip_prefix("DEFAULT=").or_else(|| t.strip_prefix("OVERRIDE=")) {
                return Some(v);
            }
        }
        start = i + var.len();
    }
    None
}

/// Which loaded files/modules does a loader value reference?
/// Returns None when the value does not load code (e.g. NODE_OPTIONS
/// carrying only `--max-old-space-size`).
pub fn loaded_refs(value: &str, flags: &[&str]) -> Option<Vec<String>> {
    // Words, with `--flag=value` split into flag + value.
    let mut toks: Vec<String> = Vec::new();
    for t in words(value) {
        if let Some((a, b)) = t.split_once('=')
            && a.starts_with('-') {
            toks.push(a.to_string());
            if !b.is_empty() { toks.push(b.to_string()); }
            continue;
        }
        toks.push(t);
    }
    if flags.is_empty() {
        // LD_PRELOAD / LD_AUDIT: every token is a library; ld.so accepts
        // ':' and whitespace as separators.
        let libs: Vec<String> = toks.iter()
            .flat_map(|t| t.split(':').map(|s| s.to_string()).collect::<Vec<_>>())
            .filter(|s| !s.is_empty() && !s.starts_with('$'))
            .collect();
        return if libs.is_empty() { None } else { Some(libs) };
    }
    let mut refs = Vec::new();
    let mut hit = false;
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        if flags.iter().any(|f| t == f) {
            hit = true;
            if let Some(next) = toks.get(i + 1)
                && !next.starts_with('-') {
                refs.push(next.clone());
                i += 1;
            }
        } else if !t.starts_with("--") {
            // Joined single-dash forms: `-javaagent:/path/agent.jar`,
            // `-MModule`, `-r/path/lib.rb`. Long `--` options only ever
            // match exactly (or via `=`, split above), so
            // `--require-foo` is never read as `--require`.
            if let Some(j) = flags.iter().find_map(|f| {
                t.strip_prefix(f)
                    .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
                    .map(|rest| rest.trim_start_matches(':').to_string())
            }) {
                hit = true;
                refs.push(j);
            }
        }
        i += 1;
    }
    refs.retain(|r| !r.starts_with('$'));
    if hit { Some(refs) } else { None }
}

/// Every loader hook assigned in a text file.
pub fn hooks_in_text(text: &str) -> Vec<Hook> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim_start();
        if l.starts_with('#') || l.starts_with(';') { continue; }
        for (var, flags) in LOADER_VARS {
            let Some(v) = assignment_value(l, var) else { continue };
            if let Some(refs) = loaded_refs(v, flags) {
                out.push(Hook { var: (*var).into(), value: v.trim().to_string(), refs });
            }
        }
    }
    out
}

/// Every loader hook in a process environment (NUL-separated
/// `VAR=value` records, proc(5)).
pub fn hooks_in_environ(environ: &[u8]) -> Vec<Hook> {
    let mut out = Vec::new();
    for rec in environ.split(|b| *b == 0) {
        let Ok(s) = std::str::from_utf8(rec) else { continue };
        let Some((k, v)) = s.split_once('=') else { continue };
        if let Some((_, flags)) = LOADER_VARS.iter().find(|(n, _)| *n == k)
            && let Some(refs) = loaded_refs(v, flags) {
            out.push(Hook { var: k.to_string(), value: v.to_string(), refs });
        }
    }
    out
}

/// `/etc/ld.so.preload`: whitespace/colon separated library paths, `#`
/// comments allowed (ld.so(8)).
pub fn ld_so_preload_refs(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .flat_map(|l| l.split(|c: char| c.is_whitespace() || c == ':').map(|s| s.to_string()).collect::<Vec<_>>())
        .filter(|s| !s.is_empty())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Owned by a package — benign.
    Packaged,
    /// Unowned or unresolvable, in an ordinary location.
    Suspicious,
    /// Unowned, in a place attackers hide payloads.
    Hidden,
}

/// Where payloads are hidden. A dot-directory anywhere in the path
/// (`/root/.config/…`) counts — that was the kit's second copy.
pub fn is_hiding_place(path: &str) -> bool {
    const ROOTS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/etc/", "/root/", "/home/", "/run/"];
    ROOTS.iter().any(|r| path.starts_with(r))
        || path.split('/').any(|c| c.starts_with('.') && c != "." && c != "..")
}

/// Judge one reference. `owned` answers package ownership for absolute
/// paths (None = this target's package database is unreadable).
pub fn judge(reference: &str, owned: Option<bool>) -> Verdict {
    if !reference.starts_with('/') {
        // A bare module / library name. LD_PRELOAD=libjemalloc.so.2 is
        // resolved by ld.so from the system library path — the library
        // directories only hold packaged files on a healthy system, so
        // a bare .so name is not reported; a bare Node/Perl/Ruby module
        // name cannot be resolved without the process's cwd.
        if reference.contains(".so") && !reference.contains('/') { return Verdict::Packaged; }
        return Verdict::Suspicious;
    }
    match owned {
        Some(true) => Verdict::Packaged,
        _ if is_hiding_place(reference) => Verdict::Hidden,
        _ => Verdict::Suspicious,
    }
}

/// Start-up files a target's shells, PAM and systemd read, plus each
/// account home's dotfiles. Paths are target-relative.
pub fn startup_files(root: &RootFs) -> Vec<String> {
    let mut files: Vec<String> = [
        "etc/profile", "etc/bash.bashrc", "etc/bashrc", "etc/environment",
        "etc/zsh/zshenv", "etc/zsh/zprofile", "etc/zsh/zshrc",
        "etc/zshenv", "etc/zprofile", "etc/zshrc",
        "etc/security/pam_env.conf", "etc/systemd/system.conf",
    ].iter().map(|s| s.to_string()).collect();
    for dir in ["etc/profile.d", "etc/environment.d", "etc/systemd/system.conf.d"] {
        for e in root.list_dir(dir) {
            if e.meta.is_file() { files.push(format!("{}/{}", dir, e.name)); }
        }
    }
    // systemd units and drop-ins written by the admin (or an attacker).
    for e in root.list_dir("etc/systemd/system") {
        if e.meta.is_file() && e.name.ends_with(".service") {
            files.push(format!("etc/systemd/system/{}", e.name));
        } else if e.meta.is_dir() && e.name.ends_with(".service.d") {
            for d in root.list_dir(&format!("etc/systemd/system/{}", e.name)) {
                if d.meta.is_file() && d.name.ends_with(".conf") {
                    files.push(format!("etc/systemd/system/{}/{}", e.name, d.name));
                }
            }
        }
    }
    for home in account_homes(root) {
        for f in [".bashrc", ".profile", ".bash_profile", ".bash_login",
                  ".zshrc", ".zshenv", ".zprofile", ".pam_environment"] {
            files.push(format!("{}/{}", home, f));
        }
        let envd = format!("{}/.config/environment.d", home);
        for e in root.list_dir(&envd) {
            if e.meta.is_file() { files.push(format!("{}/{}", envd, e.name)); }
        }
    }
    files
}

/// Homes of root and of every account with a login shell, from the
/// target's own `/etc/passwd`. Service accounts are included when they
/// have a real shell (an attacker can give `postgres` an authorized_keys
/// as easily as root). Capped: a host with an LDAP-synced passwd of
/// thousands of users is scanned for the first 200.
pub fn account_homes(root: &RootFs) -> Vec<String> {
    let passwd = root.read_string("etc/passwd", 4 << 20).unwrap_or_default();
    let mut homes = Vec::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 { continue; }
        let uid: u32 = f[2].parse().unwrap_or(u32::MAX);
        let shell = f[6];
        let home = f[5].trim_end_matches('/');
        if home.is_empty() || home == "/" || home == "/nonexistent" { continue; }
        let login = !(shell.ends_with("nologin") || shell.ends_with("/false"));
        if uid == 0 || (login && uid != 65534) {
            let h = home.trim_start_matches('/').to_string();
            if !homes.contains(&h) { homes.push(h); }
        }
        if homes.len() >= 200 { break; }
    }
    homes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact line the kit wrote into /etc/profile on 2026-11-16.
    const KIT_PROFILE_LINE: &str = r#"[ -r /etc/node-telemetry-preload.cjs ] && case " ${NODE_OPTIONS:-} " in *"node-telemetry-preload.cjs"*) ;; *) export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require /etc/node-telemetry-preload.cjs" ;; esac"#;

    #[test]
    fn detects_the_kit_profile_line() {
        let h = hooks_in_text(KIT_PROFILE_LINE);
        assert_eq!(h.len(), 1, "{:?}", h);
        assert_eq!(h[0].var, "NODE_OPTIONS");
        assert_eq!(h[0].refs, vec!["/etc/node-telemetry-preload.cjs".to_string()]);
        assert_eq!(judge(&h[0].refs[0], Some(false)), Verdict::Hidden);
    }

    #[test]
    fn detects_the_kit_process_environment() {
        let env = b"PATH=/usr/bin\0NODE_OPTIONS=--require /root/.config/node-telemetry-preload.cjs\0HOME=/root\0";
        let h = hooks_in_environ(env);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].refs, vec!["/root/.config/node-telemetry-preload.cjs".to_string()]);
        assert_eq!(judge(&h[0].refs[0], None), Verdict::Hidden);
    }

    #[test]
    fn mentions_that_are_not_assignments_are_ignored() {
        assert!(assignment_value(r#"case " ${NODE_OPTIONS:-} " in"#, "NODE_OPTIONS").is_none());
        assert!(assignment_value("MY_NODE_OPTIONS=--require x", "NODE_OPTIONS").is_none());
        assert!(hooks_in_text("# export NODE_OPTIONS=--require /tmp/x.js").is_empty());
    }

    #[test]
    fn harmless_node_options_are_not_hooks() {
        assert!(hooks_in_text("export NODE_OPTIONS=--max-old-space-size=4096").is_empty());
        assert!(hooks_in_environ(b"NODE_OPTIONS=--enable-source-maps\0").is_empty());
    }

    #[test]
    fn equals_and_short_flag_forms() {
        let h = hooks_in_text("NODE_OPTIONS=--import=/opt/apm/register.mjs");
        assert_eq!(h[0].refs, vec!["/opt/apm/register.mjs".to_string()]);
        let h = hooks_in_text("NODE_OPTIONS='-r dotenv/config'");
        assert_eq!(h[0].refs, vec!["dotenv/config".to_string()]);
        assert_eq!(judge("dotenv/config", None), Verdict::Suspicious);
    }

    #[test]
    fn systemd_and_pam_env_assignment_forms() {
        let h = hooks_in_text(r#"Environment="LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2""#);
        assert_eq!(h[0].var, "LD_PRELOAD");
        assert_eq!(h[0].refs, vec!["/usr/lib/x86_64-linux-gnu/libjemalloc.so.2".to_string()]);
        assert_eq!(judge(&h[0].refs[0], Some(true)), Verdict::Packaged);
        let h = hooks_in_text("LD_AUDIT DEFAULT=/var/tmp/.a.so");
        assert_eq!(h[0].refs, vec!["/var/tmp/.a.so".to_string()]);
    }

    #[test]
    fn bare_jemalloc_preload_is_benign() {
        let h = hooks_in_environ(b"LD_PRELOAD=libjemalloc.so.2\0");
        assert_eq!(judge(&h[0].refs[0], None), Verdict::Packaged);
    }

    #[test]
    fn javaagent_perl_ruby_forms() {
        let h = hooks_in_text("JAVA_TOOL_OPTIONS=-javaagent:/opt/x/agent.jar");
        assert_eq!(h[0].refs, vec!["/opt/x/agent.jar".to_string()]);
        let h = hooks_in_text("PERL5OPT=-MEvil");
        assert_eq!(h[0].refs, vec!["Evil".to_string()]);
        let h = hooks_in_text("RUBYOPT=-r/tmp/x.rb");
        assert_eq!(h[0].refs, vec!["/tmp/x.rb".to_string()]);
        assert!(hooks_in_text("RUBYOPT=-W0").is_empty());
    }

    #[test]
    fn ld_so_preload_lines() {
        assert_eq!(ld_so_preload_refs("# comment\n/lib/libsnoopy.so\n/usr/lib/a.so:/usr/lib/b.so\n"),
            vec!["/lib/libsnoopy.so".to_string(), "/usr/lib/a.so".to_string(), "/usr/lib/b.so".to_string()]);
    }

    #[test]
    fn hiding_places() {
        assert!(is_hiding_place("/root/.config/node-telemetry-preload.cjs"));
        assert!(is_hiding_place("/opt/app/.cache/x.js"));
        assert!(is_hiding_place("/dev/shm/x.so"));
        assert!(!is_hiding_place("/opt/apm/register.mjs"));
        assert!(!is_hiding_place("/usr/local/lib/libjemalloc.so"));
    }
}
