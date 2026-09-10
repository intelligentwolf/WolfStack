// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Installer — manages installation and status of Wolf suite components

pub mod packages;
pub mod self_signed;
pub mod unraid_tools;

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;


/// All available Wolf suite components
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    WolfNet,
    WolfProxy,
    WolfServe,
    WolfDisk,
    WolfScale,
    MariaDB,
    PostgreSQL,
    Certbot,
}

impl Component {
    pub fn name(&self) -> &'static str {
        match self {
            Component::WolfNet => "WolfNet",
            Component::WolfProxy => "WolfProxy",
            Component::WolfServe => "WolfServe",
            Component::WolfDisk => "WolfDisk",
            Component::WolfScale => "WolfScale",
            Component::MariaDB => "MariaDB",
            Component::PostgreSQL => "PostgreSQL",
            Component::Certbot => "Certbot",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Component::WolfNet => "Mesh VPN with automatic peer discovery",
            Component::WolfProxy => "Reverse proxy with built-in firewall",
            Component::WolfServe => "Web server",
            Component::WolfDisk => "Distributed filesystem",
            Component::WolfScale => "MariaDB-compatible distributed database",
            Component::MariaDB => "MariaDB relational database server",
            Component::PostgreSQL => "PostgreSQL relational database server",
            Component::Certbot => "Let's Encrypt certificate manager",
        }
    }

    pub fn service_name(&self) -> &'static str {
        match self {
            Component::WolfNet => "wolfnet",
            Component::WolfProxy => "wolfproxy",
            Component::WolfServe => "wolfserve",
            Component::WolfDisk => "wolfdisk",
            Component::WolfScale => "wolfscale",
            Component::MariaDB => "mariadb",
            Component::PostgreSQL => "postgresql",
            Component::Certbot => "certbot",
        }
    }

    /// Whether this component has a config file at all. Certbot is driven
    /// entirely by CLI flags and has none, which is a different answer from
    /// "it has one but this node's copy could not be located".
    pub fn has_config_file(&self) -> bool {
        !matches!(self, Component::Certbot)
    }

    /// Absolute path of the component's config file, or None when this host
    /// has none.
    ///
    /// None is a real answer, not a failure to guess: the DB engines are
    /// packaged in layouts WolfStack does not control, and returning a path
    /// that cannot exist is exactly what produced klas's
    /// "Failed to save config: No such file or directory (os error 2)"
    /// (2026-07-27). Callers must handle None rather than write to it.
    pub fn config_path(&self) -> Option<String> {
        match self {
            Component::WolfNet => Some("/etc/wolfnet/config.toml".to_string()),
            Component::WolfProxy => Some("/opt/wolfproxy/wolfproxy.toml".to_string()),
            Component::WolfServe => Some("/opt/wolfserve/wolfserve.toml".to_string()),
            Component::WolfDisk => Some("/etc/wolfdisk/config.toml".to_string()),
            Component::WolfScale => Some("/opt/wolfscale/wolfscale.toml".to_string()),
            Component::MariaDB => mariadb_config_path(),
            Component::PostgreSQL => postgresql_config_path(),
            Component::Certbot => None,
        }
    }

}

/// Where a component's generated admin credentials are recorded, root-only.
pub const CREDENTIALS_DIR: &str = "/etc/wolfstack/credentials";

/// A database admin account WolfStack created during install.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentCredentials {
    pub component: String,
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: u16,
}

/// Read the credentials recorded for a component, if any.
pub fn load_credentials(component: Component) -> Option<ComponentCredentials> {
    let path = format!("{}/{}.json", CREDENTIALS_DIR, component.name().to_lowercase());
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Post-install bootstrap that gives a freshly-installed database engine an
/// admin account WolfStack can actually log in with, prints it, and records it
/// where the UI can show it again later.
///
/// A stock Debian/Ubuntu MariaDB authenticates `root@localhost` with the
/// `unix_socket` plugin. No Rust client in this tree can speak that —
/// mysql_async 0.34 rejects auth plugins it doesn't know — so Database
/// Management could never connect as root however the operator typed it, which
/// is what klas hit on 2026-07-27. Rather than converting `root` off socket
/// auth and weakening local admin, this creates a dedicated `wolfstack`
/// account through the local socket, where root already has the rights to do
/// so. PostgreSQL gets the same treatment via `peer`-authenticated psql.
///
/// Existing credentials are never overwritten, so re-running an install (or an
/// upgrade) can't invalidate connections the operator has already saved.
pub fn credential_bootstrap_script(component: Component) -> Option<String> {
    let (name, port) = match component {
        Component::MariaDB => ("mariadb", 3306),
        Component::PostgreSQL => ("postgresql", 5432),
        _ => return None,
    };

    // Hex, so it is safe unquoted in SQL, in JSON and in the shell below.
    let common = format!(
        r#"
echo ''
echo 'Configuring WolfStack database access...'
WS_CRED_DIR={dir}
WS_CRED_FILE=$WS_CRED_DIR/{name}.json
WS_PORT={port}
WS_PW=$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
"#,
        dir = CREDENTIALS_DIR,
        name = name,
        port = port
    );

    let engine = match component {
        Component::MariaDB => r#"
ws_apply() {
    WS_CLIENT=$(command -v mariadb 2>/dev/null || command -v mysql 2>/dev/null)
    [ -n "$WS_CLIENT" ] || return 1
    printf "CREATE USER IF NOT EXISTS 'wolfstack'@'localhost' IDENTIFIED BY '%s';
CREATE USER IF NOT EXISTS 'wolfstack'@'127.0.0.1' IDENTIFIED BY '%s';
ALTER USER 'wolfstack'@'localhost' IDENTIFIED BY '%s';
ALTER USER 'wolfstack'@'127.0.0.1' IDENTIFIED BY '%s';
GRANT ALL PRIVILEGES ON *.* TO 'wolfstack'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'wolfstack'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;
" "$WS_PW" "$WS_PW" "$WS_PW" "$WS_PW" | "$WS_CLIENT" -u root
}
"#,
        Component::PostgreSQL => r#"
ws_apply() {
    if su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='wolfstack'\"" 2>/dev/null | grep -q 1; then
        WS_SQL="ALTER ROLE wolfstack LOGIN SUPERUSER PASSWORD '$WS_PW'"
    else
        WS_SQL="CREATE ROLE wolfstack LOGIN SUPERUSER PASSWORD '$WS_PW'"
    fi
    su - postgres -c "psql -q -c \"$WS_SQL\"" >/dev/null 2>&1 || return 1
    # A password is useless if pg_hba.conf won't accept a TCP login for it.
    WS_HBA=$(su - postgres -c "psql -tAc 'SHOW hba_file'" 2>/dev/null)
    if [ -n "$WS_HBA" ] && [ -f "$WS_HBA" ] && ! grep -q '^host.*wolfstack' "$WS_HBA"; then
        printf 'host    all    wolfstack    127.0.0.1/32    scram-sha-256\nhost    all    wolfstack    ::1/128    scram-sha-256\n' >> "$WS_HBA"
        su - postgres -c 'psql -q -c "SELECT pg_reload_conf()"' >/dev/null 2>&1
    fi
    return 0
}
"#,
        _ => return None,
    };

    let tail = r#"
if [ -f "$WS_CRED_FILE" ]; then
    echo '  Existing WolfStack database credentials kept.'
    echo "  See $WS_CRED_FILE (root only), or the component page in WolfStack."
elif [ -z "$WS_PW" ]; then
    echo '  Could not generate a password — no openssl and no /dev/urandom.'
    echo '  Create a database user manually before using Database Management.'
elif ws_apply; then
    mkdir -p "$WS_CRED_DIR" && chmod 700 "$WS_CRED_DIR"
    printf '{"component":"%s","username":"wolfstack","password":"%s","host":"127.0.0.1","port":%s}\n' \
        "$WS_COMPONENT" "$WS_PW" "$WS_PORT" > "$WS_CRED_FILE"
    chmod 600 "$WS_CRED_FILE"
    echo ''
    echo '  ---------------------------------------------------------------'
    echo '  WolfStack created a database administrator account:'
    echo ''
    echo '    Username : wolfstack'
    echo "    Password : $WS_PW"
    echo "    Host     : 127.0.0.1 port $WS_PORT"
    echo ''
    echo "  Saved to $WS_CRED_FILE (readable by root only) and shown on this"
    echo '  component page in WolfStack. Use it in Databases -> Add connection.'
    echo '  ---------------------------------------------------------------'
else
    echo '  Could not create the wolfstack database user automatically.'
    echo '  The server may still be starting — create one by hand and add it'
    echo '  under Databases -> Add connection.'
fi
"#;

    Some(format!(
        "WS_COMPONENT={}\n{}{}{}",
        name, common, engine, tail
    ))
}

/// Detect the MariaDB/MySQL server config file for the current distro.
fn mariadb_config_path() -> Option<String> {
    const CANDIDATES: &[&str] = &[
        "/etc/mysql/mariadb.conf.d/50-server.cnf", // Debian/Ubuntu
        "/etc/my.cnf.d/server.cnf",                // Arch/Manjaro/CachyOS
        "/etc/my.cnf.d/mariadb-server.cnf",        // RHEL/Fedora/CentOS
        "/etc/my.cnf.d/mysql/mysqld.cnf",          // SUSE
        "/etc/mysql/my.cnf",                       // Debian aggregate include
        "/etc/my.cnf",                             // global fallback
    ];
    CANDIDATES.iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}

/// Ask a running PostgreSQL server where its config file is.
///
/// `SHOW config_file` is authoritative for every packaging layout, cluster
/// name and major version — including versions newer than this build, which
/// is what a hardcoded version list can never handle. Verified against
/// postgres:16, which answers `/var/lib/postgresql/data/postgresql.conf`.
/// Same approach as `postgres_ha::detect_pgdata`, which uses
/// `SHOW data_directory`.
fn pg_show_config_file() -> Option<String> {
    let out = Command::new("su")
        .args(["-", "postgres", "-c", "psql -tAc \"SHOW config_file\""])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() || !std::path::Path::new(&path).exists() {
        return None;
    }
    Some(path)
}

/// Find `<base>/<major>/<cluster>/postgresql.conf`, newest major first.
///
/// Debian nests a cluster name below the version (`/etc/postgresql/16/main`)
/// and RHEL uses a fixed `data` (`/var/lib/pgsql/16/data`), so walking one
/// level below the version directory covers both. Directories are
/// enumerated rather than tested against a hardcoded list of majors — that
/// list is what stopped at 17 and made PostgreSQL 18 invisible.
fn newest_versioned_pg_conf(base: &str) -> Option<String> {
    let mut versions: Vec<(u32, std::path::PathBuf)> = std::fs::read_dir(base)
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let major: u32 = e.file_name().to_str()?.parse().ok()?;
            Some((major, e.path()))
        })
        .collect();
    versions.sort_by_key(|(major, _)| std::cmp::Reverse(*major));

    for (_, version_dir) in versions {
        let mut clusters: Vec<std::path::PathBuf> = std::fs::read_dir(&version_dir)
            .ok()
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        clusters.sort();
        for cluster in clusters {
            let conf = cluster.join("postgresql.conf");
            if conf.is_file() {
                return Some(conf.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// Detect the PostgreSQL config file for the current distro.
fn postgresql_config_path() -> Option<String> {
    if let Some(path) = pg_show_config_file() {
        return Some(path);
    }
    // Server not running (or not installed) — fall back to the on-disk
    // packaging layouts.
    for base in ["/etc/postgresql", "/var/lib/pgsql"] {
        if let Some(path) = newest_versioned_pg_conf(base) {
            return Some(path);
        }
    }
    const UNVERSIONED: &[&str] = &[
        "/var/lib/pgsql/data/postgresql.conf",      // RHEL default cluster
        "/var/lib/postgres/data/postgresql.conf",   // Arch
        "/var/lib/postgresql/data/postgresql.conf", // Alpine / container images
    ];
    UNVERSIONED.iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}


impl Component {
    pub fn all() -> &'static [Component] {
        &[
            Component::WolfNet,
            Component::WolfProxy,
            Component::WolfServe,
            Component::WolfDisk,
            Component::WolfScale,
            Component::MariaDB,
            Component::PostgreSQL,
            Component::Certbot,
        ]
    }
}

/// Status of a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub component: Component,
    pub installed: bool,
    pub running: bool,
    pub enabled: bool,
    pub version: Option<String>,
}

/// Detected distro family
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DistroFamily {
    Debian,  // Debian, Ubuntu, etc.
    RedHat,  // RHEL, Fedora, CentOS, etc.
    Suse,    // SLES, openSUSE Leap, openSUSE Tumbleweed
    Arch,    // Arch, Manjaro, EndeavourOS, CachyOS, etc.
    Alpine,  // Alpine Linux (apk) — common Docker base + LXC image
    Unknown,
}

/// Detect the current distro family
pub fn detect_distro() -> DistroFamily {
    // Alpine check first — `/etc/alpine-release` is unambiguous and
    // some Alpine images also ship `/etc/debian_version` for build-tool
    // compatibility (would false-positive Debian).
    if std::path::Path::new("/etc/alpine-release").exists()
        || std::path::Path::new("/sbin/apk").exists()
    {
        return DistroFamily::Alpine;
    }
    if std::path::Path::new("/etc/arch-release").exists()
        || std::path::Path::new("/usr/bin/pacman").exists()
    {
        DistroFamily::Arch
    } else if std::path::Path::new("/etc/debian_version").exists() {
        DistroFamily::Debian
    } else if std::path::Path::new("/etc/redhat-release").exists()
        || std::path::Path::new("/etc/fedora-release").exists()
    {
        DistroFamily::RedHat
    } else if std::path::Path::new("/etc/SuSE-release").exists()
        || std::path::Path::new("/etc/SUSE-brand").exists()
        || std::path::Path::new("/usr/bin/zypper").exists()
    {
        DistroFamily::Suse
    } else {
        // Try os-release as final fallback
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let lower = content.to_lowercase();
            if lower.contains("alpine") {
                return DistroFamily::Alpine;
            }
            if lower.contains("arch") || lower.contains("manjaro") || lower.contains("endeavour") || lower.contains("cachyos") {
                return DistroFamily::Arch;
            }
            if lower.contains("suse") || lower.contains("sles") {
                return DistroFamily::Suse;
            }
            if lower.contains("rhel") || lower.contains("centos") || lower.contains("fedora") || lower.contains("red hat") {
                return DistroFamily::RedHat;
            }
        }
        DistroFamily::Unknown
    }
}

/// Get the package manager command for the current distro
pub fn pkg_install_cmd(distro: DistroFamily) -> (&'static str, &'static str) {
    match distro {
        DistroFamily::Debian => ("apt-get", "install -y"),
        DistroFamily::RedHat => ("dnf", "install -y"),
        DistroFamily::Suse => ("zypper", "install -y"),
        DistroFamily::Arch => ("pacman", "-S --noconfirm"),
        DistroFamily::Alpine => ("apk", "add --no-cache"),
        DistroFamily::Unknown => ("apt-get", "install -y"),
    }
}

/// Check if a systemd service exists and its status
pub fn check_service(service: &str) -> (bool, bool, bool) {
    let installed = Command::new("systemctl")
        .args(["cat", service])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let running = Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let enabled = Command::new("systemctl")
        .args(["is-enabled", "--quiet", service])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    (installed, running, enabled)
}

/// Check if a binary exists on PATH
fn binary_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get version of a component
pub fn get_component_version(component: Component) -> Option<String> {
    let (cmd, args): (&str, &[&str]) = match component {
        Component::MariaDB => ("mariadb", &["--version"]),
        Component::PostgreSQL => ("psql", &["--version"]),
        Component::Certbot => ("certbot", &["--version"]),
        Component::WolfNet => ("wolfnet", &["--version"]),
        Component::WolfProxy => ("wolfproxy", &["--version"]),
        Component::WolfServe => ("wolfserve", &["--version"]),
        Component::WolfDisk => ("wolfdisk", &["--version"]),
        Component::WolfScale => ("wolfscale", &["--version"]),
    };

    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
                    .map(|s| {
                        let trimmed = s.trim();
                        // Extract just the version number (e.g. "wolfdisk 2.7.4" → "2.7.4")
                        trimmed.split_whitespace()
                            .find(|w| w.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                            .unwrap_or(trimmed)
                            .to_string()
                    })
            } else {
                None
            }
        })
}

/// Get status of all components
pub fn get_all_status() -> Vec<ComponentStatus> {
    Component::all().iter().map(|comp| {
        // Unraid has no systemd; the agent bundles and supervises WolfNet
        // itself, so the Components card asks the supervisor instead of a
        // systemctl that is not there (klas, 2026-09-10).
        let (installed, mut running, enabled) =
            if matches!(comp, Component::WolfNet) && unraid_tools::is_unraid() {
                let (installed, running) = unraid_tools::wolfnet_state();
                (installed, running, unraid_tools::wolfnet_enabled())
            } else {
                check_service(comp.service_name())
            };
        let bin_exists = binary_exists(comp.service_name());
        // WolfProxy daemonizes, so its unit can read "inactive" while a forked
        // worker is still serving — an orphan systemd lost track of. If a
        // wolfproxy is actually listening on :80/:443, report it as running so
        // the UI matches reality and the operator gets Stop/Restart (which reap
        // it) instead of a Start that would collide on the ports.
        if matches!(comp, Component::WolfProxy) && !running
            && !wolfproxy_pids_on_ports(&[80, 443]).is_empty()
        {
            running = true;
        }
        ComponentStatus {
            component: *comp,
            installed: installed || bin_exists,
            running,
            enabled,
            version: get_component_version(*comp),
        }
    }).collect()
}

// Cache for get_all_status — avoids spawning ~35 subprocesses every 2 seconds.
// Component install/run status changes rarely; 10s TTL is plenty responsive.
static STATUS_CACHE: Mutex<Option<(Vec<ComponentStatus>, Instant)>> = Mutex::new(None);
const STATUS_CACHE_TTL_SECS: u64 = 10;

/// Get status of all components (cached for 10s to reduce subprocess overhead).
pub fn get_all_status_cached() -> Vec<ComponentStatus> {
    let mut cache = STATUS_CACHE.lock().unwrap();
    if let Some((ref val, ts)) = *cache
        && ts.elapsed().as_secs() < STATUS_CACHE_TTL_SECS {
            return val.clone();
        }
    let val = get_all_status();
    *cache = Some((val.clone(), Instant::now()));
    val
}

/// Install a component
pub fn install_component(component: Component) -> Result<String, String> {
    let distro = detect_distro();


    match component {
        Component::MariaDB => install_mariadb(distro),
        Component::PostgreSQL => install_postgresql(distro),
        Component::Certbot => install_certbot(distro),
        Component::WolfNet | Component::WolfProxy | Component::WolfServe
        | Component::WolfDisk | Component::WolfScale => install_wolf_component(component, distro),
    }
}

/// Run the credential bootstrap and summarise the result for the caller's
/// message. The same script the install console runs, so the two install
/// paths cannot drift apart — only the reporting differs, because this one
/// has no terminal to print to.
fn run_credential_bootstrap(component: Component) -> String {
    let script = match credential_bootstrap_script(component) {
        Some(s) => s,
        None => return String::new(),
    };
    match Command::new("sh").arg("-c").arg(&script).output() {
        Ok(_) => match load_credentials(component) {
            Some(c) => format!(
                " Database user '{}' is ready — see the component page for its password.",
                c.username
            ),
            None => " No database user could be created automatically; add one under Databases.".to_string(),
        },
        Err(e) => format!(" Database user setup could not run: {}", e),
    }
}

fn install_mariadb(distro: DistroFamily) -> Result<String, String> {
    let (pkg_mgr, install_flag) = pkg_install_cmd(distro);
    let pkg_name = match distro {
        DistroFamily::Debian => "mariadb-server",
        DistroFamily::RedHat => "mariadb-server",
        DistroFamily::Suse => "mariadb",
        DistroFamily::Arch => "mariadb",
        DistroFamily::Alpine => "mariadb",
        DistroFamily::Unknown => "mariadb-server",
    };

    let output = Command::new("sudo")
        .args([pkg_mgr])
        .args(install_flag.split_whitespace())
        .arg(pkg_name)
        .output()
        .map_err(|e| format!("Failed to run package manager: {}", e))?;

    if output.status.success() {
        // Enable and start
        let _ = Command::new("sudo").args(["systemctl", "enable", "--now", "mariadb"]).output();
        let creds = run_credential_bootstrap(Component::MariaDB);
        Ok(format!("{} installed and started.{}", pkg_name, creds))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn install_postgresql(distro: DistroFamily) -> Result<String, String> {
    let (pkg_mgr, install_flag) = pkg_install_cmd(distro);
    let pkg_name = match distro {
        DistroFamily::Debian => "postgresql",
        DistroFamily::RedHat => "postgresql-server",
        DistroFamily::Suse => "postgresql-server",
        DistroFamily::Arch => "postgresql",
        DistroFamily::Alpine => "postgresql",
        DistroFamily::Unknown => "postgresql",
    };

    let output = Command::new("sudo")
        .args([pkg_mgr])
        .args(install_flag.split_whitespace())
        .arg(pkg_name)
        .output()
        .map_err(|e| format!("Failed to run package manager: {}", e))?;

    if output.status.success() {
        // Arch needs initdb before starting (skip if data dir already exists)
        if distro == DistroFamily::Arch && !std::path::Path::new("/var/lib/postgres/data/PG_VERSION").exists() {
            let _ = Command::new("sudo").args(["-u", "postgres", "initdb", "-D", "/var/lib/postgres/data"]).output();
        }
        // RHEL needs setup (skip if already initialised)
        if distro == DistroFamily::RedHat && !std::path::Path::new("/var/lib/pgsql/data/PG_VERSION").exists() {
            let _ = Command::new("sudo").args(["postgresql-setup", "--initdb"]).output();
        }
        let _ = Command::new("sudo").args(["systemctl", "enable", "--now", "postgresql"]).output();
        let creds = run_credential_bootstrap(Component::PostgreSQL);
        Ok(format!("{} installed and started.{}", pkg_name, creds))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Install nginx via the local distro's package manager and enable
/// the service. Used by the WolfRouter HTTP proxies tab when the
/// operator picks "nginx" from the install modal. Returns the package
/// manager's stdout (or stderr on failure) so the modal can render it
/// verbatim — the operator sees the actual install output, not a
/// generic "install failed" toast.
pub fn install_nginx_pkg() -> Result<String, String> {
    let distro = detect_distro();
    let (pkg_mgr, install_flag) = pkg_install_cmd(distro);
    let output = Command::new("sudo")
        .args([pkg_mgr])
        .args(install_flag.split_whitespace())
        .arg("nginx")
        .output()
        .map_err(|e| format!("Failed to run {}: {}", pkg_mgr, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{} {} nginx failed:\n{}",
            pkg_mgr,
            install_flag,
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Enable + start the unit so the operator doesn't have to
    // remember to do it themselves. Failure is non-fatal here —
    // some package post-install hooks already do this, and we want
    // the install endpoint to succeed even if the service is in a
    // weird state the operator should look at separately.
    let _ = Command::new("sudo")
        .args(["systemctl", "enable", "--now", "nginx"])
        .output();

    Ok(format!("nginx installed via {}.\n{}", pkg_mgr, stdout))
}

fn install_certbot(distro: DistroFamily) -> Result<String, String> {
    let (pkg_mgr, install_flag) = pkg_install_cmd(distro);
    let output = Command::new("sudo")
        .args([pkg_mgr])
        .args(install_flag.split_whitespace())
        .arg("certbot")
        .output()
        .map_err(|e| format!("Failed to run package manager: {}", e))?;

    if output.status.success() {
        Ok("Certbot installed".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn install_wolf_component(component: Component, _distro: DistroFamily) -> Result<String, String> {
    let install_url = match component {
        Component::WolfNet => "https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/wolfnet/setup.sh",
        Component::WolfProxy => "https://raw.githubusercontent.com/intelligentwolf/wolfproxy/main/setup.sh",
        // wolfserve lives in its own repo since the monorepo split — the old
        // WolfScale/master/wolfserve/install.sh URL 404s (and was a from-source
        // build anyway). setup.sh downloads the latest release binary.
        Component::WolfServe => "https://raw.githubusercontent.com/intelligentwolf/wolfserve/main/setup.sh",
        Component::WolfDisk => "https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/wolfdisk/setup.sh",
        Component::WolfScale => "https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/setup_lb.sh",
        _ => return Err("Unknown component".to_string()),
    };

    let output = Command::new("bash")
        .args(["-c", &format!("curl -fsSL '{}' | bash", install_url)])
        .output()
        .map_err(|e| format!("Failed to run install script: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        // Return the full transcript so the UI can render the live
        // install log — operators want to see what happened, not
        // just "installed". The stdout has every `info` / `success`
        // line the setup script printed.
        let log = if stdout.trim().is_empty() { stderr.into_owned() } else { stdout.into_owned() };
        Ok(format!("{} installed.\n{}", component.name(), log))
    } else {
        // Wolf-* setup scripts print their `[ERROR]` lines to STDOUT
        // (via `echo -e ...`, not `>&2`). A stderr-only error message
        // surfaces an empty string to the operator and they can't tell
        // why the install died. Concatenate both so whatever stream the
        // script used is captured. Trim leading/trailing whitespace so
        // the formatted error doesn't have a blank line.
        let combined = format!("{}\n{}", stdout.trim_end(), stderr.trim_end());
        Err(format!("Install failed:\n{}", combined.trim()))
    }
}

/// Start a service
pub fn start_service(service: &str) -> Result<String, String> {
    let output = Command::new("sudo")
        .args(["systemctl", "start", service])
        .output()
        .map_err(|e| format!("Failed to start {}: {}", service, e))?;

    if output.status.success() {
        Ok(format!("{} started", service))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Stop a service
pub fn stop_service(service: &str) -> Result<String, String> {
    let output = Command::new("sudo")
        .args(["systemctl", "stop", service])
        .output()
        .map_err(|e| format!("Failed to stop {}: {}", service, e))?;

    if output.status.success() {
        Ok(format!("{} stopped", service))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Restart a service
pub fn restart_service(service: &str) -> Result<String, String> {
    let output = Command::new("sudo")
        .args(["systemctl", "restart", service])
        .output()
        .map_err(|e| format!("Failed to restart {}: {}", service, e))?;

    if output.status.success() {
        Ok(format!("{} restarted", service))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Read `/proc/<pid>/comm` — the process's executable name.
fn proc_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Host PIDs that both (a) listen on one of `ports` in the host network
/// namespace and (b) are actually `wolfproxy`.
///
/// WolfProxy daemonizes (forks a worker, parent exits), so with a
/// `Type=simple` unit systemd loses track of the worker; it lingers as an
/// orphan holding :80/:443 and the next `systemctl start` fails with
/// "Address in use" (klasSponsor 2026-06-05: `ss` showed wolfproxy pid 551997
/// on :80 while the unit's main PID had exited 0 after 25ms). This is the
/// precise, safe way to find that orphan to reap it: port-scoped so we only
/// look at the host's own listeners, and name-checked against `comm` so we
/// never kill an unrelated service holding the port — nor a wolfproxy running
/// *inside* a container, which binds its own namespaced socket that the host
/// `ss` doesn't list.
pub fn wolfproxy_pids_on_ports(ports: &[u16]) -> Vec<u32> {
    let mut found = std::collections::HashSet::new();
    for &port in ports {
        let out = match Command::new("ss")
            .args(["-H", "-ltnp", &format!("sport = :{}", port)])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue, // ss missing — nothing we can do, fall through
        };
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            // ...users:(("wolfproxy",pid=551997,fd=9)) — a line can list more
            // than one process, so scan every `pid=` occurrence.
            let mut rest = line;
            while let Some(i) = rest.find("pid=") {
                rest = &rest[i + 4..];
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(pid) = digits.parse::<u32>()
                    && proc_comm(pid).as_deref() == Some("wolfproxy") {
                        found.insert(pid);
                    }
            }
        }
    }
    found.into_iter().collect()
}

/// Marker the API layer keys off to render the "use DNS-01 / wildcard"
/// CTA instead of a raw certbot error. Kept as a stable string so the
/// frontend can match against it across builds.
pub const CERT_PORT80_BUSY_PREFIX: &str = "PORT_80_BUSY: ";

/// Probe whether anything is listening on TCP 0.0.0.0:80 / [::]:80.
/// certbot's `--standalone` mode binds port 80 to serve the HTTP-01
/// challenge; if WolfProxy / nginx / Caddy already holds it, certbot
/// fails with a noisy "Could not bind to IPv4 or IPv6". Detect first
/// so we can return a structured, actionable error instead.
///
/// We bind ourselves rather than parsing `/proc/net/tcp` so the check
/// matches certbot's actual failure mode exactly: if certbot would fail
/// to bind, we report busy; if it would succeed, we report free. Edge
/// cases like SO_REUSEPORT are intentionally consistent — both sides
/// see the same kernel.
fn port_80_busy() -> bool {
    use std::net::TcpListener;
    // Try IPv4 first; if that's free, try IPv6 too — certbot tries
    // both, so any in-use binding blocks it.
    let v4_busy = TcpListener::bind(("0.0.0.0", 80)).is_err();
    let v6_busy = TcpListener::bind(("::", 80)).is_err();
    v4_busy || v6_busy
}

/// Request a certificate via certbot. Uses `--standalone` only when
/// port 80 is free; otherwise returns a structured error that the UI
/// can route to the "add a DNS provider" flow. The legacy API
/// (`POST /api/certificates`) calls this; the new path
/// (`POST /api/certs` with `dns_provider_id`) bypasses it entirely.
pub fn request_certificate(domain: &str, email: &str) -> Result<String, String> {
    if !binary_exists("certbot") {
        install_certbot(detect_distro())?;
    }

    if port_80_busy() {
        // Surface a stable, machine-parseable prefix so the UI can pivot
        // to the wildcard / DNS-01 panel without having to grep certbot's
        // free-form stderr.
        return Err(format!(
            "{prefix}port 80 is already in use on this host (typically by WolfProxy or nginx), \
             so certbot's standalone HTTP-01 challenge can't bind it. Use the DNS-01 + wildcard \
             flow instead: Settings → Certificates → DNS-01, or add a DNS provider under \
             Settings → DNS Providers. DNS-01 also lets you issue one *.{domain} cert that covers \
             every host in the zone.",
            prefix = CERT_PORT80_BUSY_PREFIX,
            domain = domain,
        ));
    }

    // Resolve certbot via certbot_path() so snap installs at /snap/bin
    // are found — sudo's secure_path doesn't include /snap/bin on
    // Debian/Ubuntu by default, and pre-fix `sudo certbot ...` would
    // silently fail with "command not found" even when the operator's
    // login shell could run `certbot --version` fine.
    let certbot_bin = crate::certbot::certbot_path()
        .ok_or_else(crate::certbot::missing_certbot_error)?;
    let output = Command::new("sudo")
        .args([
            certbot_bin.as_str(), "certonly", "--standalone",
            "-d", domain,
            "--email", email,
            "--agree-tos", "--non-interactive",
        ])
        .output()
        .map_err(|e| format!("Failed to run certbot: {}", e))?;

    if output.status.success() {
        Ok(format!("Certificate obtained for {}. Restart WolfStack to enable HTTPS.", domain))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Parse `sudo certbot certificates` output into structured cert info
/// Returns Vec of (domains, cert_path, key_path, expiry)
fn parse_certbot_certificates() -> Vec<(String, String, String, String)> {
    // Same /snap/bin issue as request_certificate — use the resolved
    // path. If certbot isn't installed at all, fall back to the bare
    // command so the error message stays meaningful (certbot certificates
    // → "command not found" rather than panic).
    let certbot_bin = crate::certbot::certbot_path().unwrap_or_else(|| "certbot".to_string());
    let output = Command::new("sudo")
        .args([certbot_bin.as_str(), "certificates"])
        .output()
        .ok();

    let stdout = match output {
        Some(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Some(ref o) => {
            // certbot might output to stderr too
            let stderr = String::from_utf8_lossy(&o.stderr);

            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&o.stdout),
                stderr
            );
            combined
        }
        _ => {

            return Vec::new();
        }
    };

    let mut results = Vec::new();
    let mut current_domains = String::new();
    let mut current_cert = String::new();
    let mut current_key = String::new();
    let mut current_expiry = String::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Domains:") {
            // Save previous entry if complete
            if !current_domains.is_empty() && !current_cert.is_empty() && !current_key.is_empty() {
                results.push((
                    current_domains.clone(), current_cert.clone(),
                    current_key.clone(), current_expiry.clone(),
                ));
            }
            current_domains = trimmed.strip_prefix("Domains:").unwrap_or("").trim().to_string();
            current_cert.clear();
            current_key.clear();
            current_expiry.clear();
        } else if trimmed.starts_with("Certificate Path:") {
            current_cert = trimmed.strip_prefix("Certificate Path:").unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("Private Key Path:") {
            current_key = trimmed.strip_prefix("Private Key Path:").unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("Expiry Date:") {
            current_expiry = trimmed.strip_prefix("Expiry Date:").unwrap_or("").trim().to_string();
        }
    }
    // Don't forget the last entry
    if !current_domains.is_empty() && !current_cert.is_empty() && !current_key.is_empty() {
        results.push((current_domains, current_cert, current_key, current_expiry));
    }

    results
}

/// Directly scan /etc/letsencrypt/live/ for certificate directories
/// This works even when certbot CLI isn't available or sudo fails
/// Returns Vec of (domain, cert_path, key_path)
fn scan_letsencrypt_live() -> Vec<(String, String, String)> {
    let live_dir = std::path::Path::new("/etc/letsencrypt/live");
    if !live_dir.exists() {
        return Vec::new();
    }

    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(live_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Skip the README directory that certbot creates
            if path.file_name().map(|n| n == "README").unwrap_or(false) {
                continue;
            }

            let cert = path.join("fullchain.pem");
            let key = path.join("privkey.pem");
            if cert.exists() && key.exists() {
                let domain = path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                results.push((
                    domain,
                    cert.to_string_lossy().to_string(),
                    key.to_string_lossy().to_string(),
                ));
            }
        }
    }

    results
}

/// Scan Proxmox VE certificate paths
/// Returns Vec of (label, cert_path, key_path)
fn scan_pve_certificates() -> Vec<(String, String, String)> {
    let mut results = Vec::new();

    // Common Proxmox cert locations
    let pve_pairs: &[(&str, &str, &str)] = &[
        ("pveproxy-ssl (custom)", "/etc/pve/local/pveproxy-ssl.pem", "/etc/pve/local/pveproxy-ssl.key"),
        ("pve-ssl (local)",      "/etc/pve/local/pve-ssl.pem",      "/etc/pve/local/pve-ssl.key"),
    ];

    for (label, cert, key) in pve_pairs {
        if std::path::Path::new(cert).exists() && std::path::Path::new(key).exists() {
            results.push((label.to_string(), cert.to_string(), key.to_string()));
        }
    }

    // Per-node certs: /etc/pve/nodes/<hostname>/pve-ssl.pem
    let nodes_dir = std::path::Path::new("/etc/pve/nodes");
    if nodes_dir.exists()
        && let Ok(entries) = std::fs::read_dir(nodes_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() { continue; }
                let node_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                for prefix in ["pve-ssl", "pveproxy-ssl"] {
                    let cert = path.join(format!("{}.pem", prefix));
                    let key = path.join(format!("{}.key", prefix));
                    if cert.exists() && key.exists() {
                        results.push((
                            format!("{} ({})", prefix, node_name),
                            cert.to_string_lossy().to_string(),
                            key.to_string_lossy().to_string(),
                        ));
                    }
                }
            }
        }

    results
}

/// Locations under /etc/wolfstack where a user might naturally place their
/// own cert+key. We probe all of these on startup and from the
/// Certificates page so a manual `cp cert.pem /etc/wolfstack/tls/` works
/// without an explicit ExecStart override (NyvenZA's v22.6.8 issue).
///
/// Each entry is (label, cert_path, key_path). Order matters — the first
/// pair where BOTH files exist is what gets used by `find_tls_certificate`.
fn wolfstack_local_cert_paths() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("wolfstack (custom)",         "/etc/wolfstack/cert.pem",            "/etc/wolfstack/key.pem"),
        ("wolfstack (tls/)",           "/etc/wolfstack/tls/cert.pem",        "/etc/wolfstack/tls/key.pem"),
        ("wolfstack (tls/ fullchain)", "/etc/wolfstack/tls/fullchain.pem",   "/etc/wolfstack/tls/privkey.pem"),
        ("wolfstack (ssl/)",           "/etc/wolfstack/ssl/cert.pem",        "/etc/wolfstack/ssl/key.pem"),
        ("wolfstack (ssl/ fullchain)", "/etc/wolfstack/ssl/fullchain.pem",   "/etc/wolfstack/ssl/privkey.pem"),
    ]
}

/// One discoverable TLS keypair plus the two facts we rank candidates on:
/// the DNS names it asserts (SAN, falling back to CN) and whether it is
/// self-signed. Built so a real CA cert that covers the host always beats
/// the install-time self-signed placeholder that used to shadow it.
#[derive(Debug)]
struct TlsCandidate {
    cert_path: String,
    key_path: String,
    domains: Vec<String>,
    self_signed: bool,
}

impl TlsCandidate {
    fn load(cert_path: String, key_path: String) -> Self {
        let domains = cert_dns_names(&cert_path);
        let self_signed = cert_is_self_signed(&cert_path);
        TlsCandidate { cert_path, key_path, domains, self_signed }
    }

    /// Does this cert's SAN/CN cover `host`, wildcard-aware?
    fn covers(&self, host: &str) -> bool {
        self.domains.iter().any(|pat| host_matches_cert_name(pat, host))
    }
}

/// RFC 6125 host matching: exact, or a single-label `*.` wildcard.
/// `*.example.com` matches `a.example.com` but not `example.com` nor
/// `a.b.example.com`. Case- and trailing-dot-insensitive.
fn host_matches_cert_name(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard covers exactly one left-most label.
        if let Some((_label, rest)) = host.split_once('.') {
            return !suffix.is_empty() && rest == suffix;
        }
    }
    false
}

/// Read the DNS names a cert asserts: subjectAltName DNS entries, or the
/// CommonName when there's no SAN. Best-effort — an unreadable or
/// unparseable cert yields an empty list (it simply won't match a host).
fn cert_dns_names(cert_path: &str) -> Vec<String> {
    use openssl::x509::X509;
    let mut names = Vec::new();
    let Ok(bytes) = std::fs::read(cert_path) else { return names; };
    // from_pem parses the leaf (first cert) of a fullchain — exactly the
    // cert whose names a client validates.
    let Ok(cert) = X509::from_pem(&bytes) else { return names; };
    if let Some(san) = cert.subject_alt_names() {
        for gn in san.iter() {
            if let Some(dns) = gn.dnsname() {
                names.push(dns.to_string());
            }
        }
    }
    if names.is_empty() {
        for e in cert.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME) {
            if let Ok(s) = e.data().as_utf8() {
                names.push(s.to_string());
            }
        }
    }
    names
}

/// True if the leaf cert is self-signed — proven by the cert verifying
/// under its own public key. This is how we tell WolfStack's first-boot
/// placeholder from an operator's real CA-issued cert.
fn cert_is_self_signed(cert_path: &str) -> bool {
    use openssl::x509::X509;
    // Unknown (unreadable / unparseable / no public key) biases to
    // self-signed: a cert we can't vet must never out-rank a readable
    // CA-signed cert in selection. It can still be served if it's the only
    // candidate — exactly the old behaviour.
    let Ok(bytes) = std::fs::read(cert_path) else { return true; };
    let Ok(cert) = X509::from_pem(&bytes) else { return true; };
    match cert.public_key() {
        Ok(pk) => cert.verify(&pk).unwrap_or(true),
        Err(_) => true,
    }
}

/// Rank candidates and return the index of the best, or None if empty.
/// Tuple precedence, most significant first:
///   covers-host AND CA-signed → ideal: trusted and the right name
///   covers-host               → right name (even if self-signed)
///   CA-signed                 → trusted (even if the name won't match)
/// `Reverse(idx)` makes the earliest source win ties — preserving the
/// historical source-order preference, deterministically (idx is unique).
fn rank_best_candidate(candidates: &[TlsCandidate], domain: Option<&str>) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .max_by_key(|(idx, c)| {
            let covers = domain.is_some_and(|d| c.covers(d));
            (
                covers && !c.self_signed,
                covers,
                !c.self_signed,
                std::cmp::Reverse(*idx),
            )
        })
        .map(|(idx, _)| idx)
}

/// `certbot certificates` shells out to a subprocess that can be slow (or,
/// misconfigured, hang). `find_tls_certificate` runs several times at boot,
/// so cache the result for the life of the process — the cert set doesn't
/// change between those calls. The runtime cert-list API deliberately uses
/// `parse_certbot_certificates()` directly (uncached) so it always reflects
/// a freshly issued cert.
fn certbot_certificates_cached() -> &'static [(String, String, String, String)] {
    static CACHE: std::sync::OnceLock<Vec<(String, String, String, String)>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(parse_certbot_certificates)
}

/// Find TLS certificate files for a domain (Let's Encrypt or /etc/wolfstack/)
/// Returns (cert_path, key_path).
///
/// Rather than taking the first hit, discovery gathers candidates from the
/// historical sources (WolfStack-local paths, certbot, /etc/letsencrypt/live,
/// Proxmox VE) and *ranks* them. Two rules a plain first-match got wrong,
/// both of which silently ignored an operator's real cert:
///   1. A CA-signed cert beats the self-signed placeholder WolfStack writes
///      to /etc/wolfstack/tls/ at first boot — which sat earlier in the
///      search order and permanently shadowed a Let's Encrypt cert
///      (RutgerDiehard's "wildcard installed but :8553 still self-signed").
///   2. Wildcard SANs are matched against the host: a `*.example.com` cert
///      now covers `host.example.com`, where the old exact-string compare
///      never matched.
///
/// Ties fall back to the original source order, so existing single-cert
/// installs resolve exactly as before. Explicit --tls-cert/--tls-key still
/// win — they're handled by the caller before this is consulted.
pub fn find_tls_certificate(domain: Option<&str>) -> Option<(String, String)> {
    use std::path::Path;

    // Local candidates first — cheap filesystem checks.
    let mut candidates: Vec<TlsCandidate> = Vec::new();
    for (_label, cert, key) in wolfstack_local_cert_paths() {
        if Path::new(cert).exists() && Path::new(key).exists() {
            candidates.push(TlsCandidate::load(cert.to_string(), key.to_string()));
        }
    }

    // Fast path: a local CA-signed cert that already covers the host (or any
    // local CA cert when no host was requested) can't be out-ranked by a
    // remote source — remote certs tie at best and lose the earliest-source
    // tiebreak. Return it without shelling out to certbot, keeping a
    // slow/hung certbot off the boot path for operators who brought their
    // own cert (the pre-ranking behaviour for that case).
    if let Some(best) = rank_best_candidate(&candidates, domain) {
        let c = &candidates[best];
        if !c.self_signed && domain.is_none_or(|d| c.covers(d)) {
            tracing::debug!("TLS: selected local CA cert {}", c.cert_path);
            return Some((c.cert_path.clone(), c.key_path.clone()));
        }
    }

    // Otherwise gather the remote sources and rank everything together,
    // deduping by cert path so a cert found by both certbot and the
    // /etc/letsencrypt/live scan isn't read and parsed twice.
    let mut seen: std::collections::HashSet<String> =
        candidates.iter().map(|c| c.cert_path.clone()).collect();
    let remote = certbot_certificates_cached()
        .iter()
        .map(|(_d, cert, key, _e)| (cert.clone(), key.clone()))
        .chain(scan_letsencrypt_live().into_iter().map(|(_d, cert, key)| (cert, key)))
        .chain(scan_pve_certificates().into_iter().map(|(_l, cert, key)| (cert, key)));
    for (cert, key) in remote {
        if Path::new(&cert).exists() && Path::new(&key).exists() && seen.insert(cert.clone()) {
            candidates.push(TlsCandidate::load(cert, key));
        }
    }

    let best = rank_best_candidate(&candidates, domain)?;
    let c = &candidates[best];
    tracing::debug!(
        "TLS: selected cert {} (self_signed={}, covers_host={})",
        c.cert_path,
        c.self_signed,
        domain.is_some_and(|d| c.covers(d))
    );
    Some((c.cert_path.clone(), c.key_path.clone()))
}

/// List ALL TLS certificates on this server
/// Uses the same discovery methods as find_tls_certificate but collects everything
/// Read a PEM certificate and return its notAfter as
/// "YYYY-MM-DD HH:MM:SS+00:00" (UTC) — the same leading-timestamp shape
/// the certbot expiry lines carry, which is what the dashboard widget
/// and Certificates page parse to colour days-remaining. Native parse
/// via the vendored openssl crate (no `openssl` CLI dependency), so it
/// works on minimal hosts too. None when the file is unreadable or not
/// a valid certificate.
fn cert_expiry_string(cert_path: &str) -> Option<String> {
    let pem = std::fs::read(cert_path).ok()?;
    let cert = openssl::x509::X509::from_pem(&pem).ok()?;
    // Asn1Time has no direct epoch accessor; diff from the UNIX epoch
    // gives whole days + leftover seconds.
    let epoch = openssl::asn1::Asn1Time::from_unix(0).ok()?;
    let diff = epoch.diff(cert.not_after()).ok()?;
    let secs = diff.days as i64 * 86_400 + diff.secs as i64;
    let dt = chrono::DateTime::from_timestamp(secs, 0)?;
    Some(dt.format("%Y-%m-%d %H:%M:%S+00:00").to_string())
}

pub fn list_certificates() -> serde_json::Value {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut diagnostics: Vec<String> = Vec::new();

    // 1. Check every WolfStack-local cert location (cert.pem, tls/, ssl/, etc.)
    // — both files of each pair required. For pairs where only one of the
    // two files exists, surface a diagnostic so the user knows the partial
    // install isn't being silently ignored.
    for (label, cert_path, key_path) in wolfstack_local_cert_paths() {
        let cert_exists = std::path::Path::new(cert_path).exists();
        let key_exists  = std::path::Path::new(key_path).exists();
        if cert_exists && key_exists {
            if seen.contains(*cert_path) { continue; }
            seen.insert(cert_path.to_string());
            results.push(serde_json::json!({
                "domain": label,
                "cert_path": cert_path,
                "key_path": key_path,
                "expiry": cert_expiry_string(cert_path),
                "source": "custom",
                "valid": true,
            }));
        } else if cert_exists != key_exists {
            let missing = if cert_exists { key_path } else { cert_path };
            diagnostics.push(format!(
                "⚠️ Found one of {} and {} but not both — missing {}. The cert will not be loaded until both files exist.",
                cert_path, key_path, missing
            ));
        }
    }

    // 2. Certbot CLI
    let certbot_certs = parse_certbot_certificates();
    for (domains, cert_path, key_path, expiry) in &certbot_certs {
        if seen.contains(cert_path) { continue; }
        seen.insert(cert_path.clone());
        results.push(serde_json::json!({
            "domain": domains,
            "cert_path": cert_path,
            "key_path": key_path,
            "expiry": expiry,
            "source": "certbot",
            "valid": true,
        }));
    }

    // 3. Filesystem scan of /etc/letsencrypt/live/
    let fs_certs = scan_letsencrypt_live();
    for (domain, cert_path, key_path) in &fs_certs {
        if seen.contains(cert_path) { continue; }
        seen.insert(cert_path.clone());
        results.push(serde_json::json!({
            "domain": domain,
            "cert_path": cert_path,
            "key_path": key_path,
            "expiry": cert_expiry_string(cert_path),
            "source": "filesystem",
            "valid": true,
        }));
    }

    // 4. Proxmox VE certs
    let pve_certs = scan_pve_certificates();
    for (label, cert_path, key_path) in &pve_certs {
        if seen.contains(cert_path) { continue; }
        seen.insert(cert_path.clone());
        results.push(serde_json::json!({
            "domain": label,
            "cert_path": cert_path,
            "key_path": key_path,
            "expiry": cert_expiry_string(cert_path),
            "source": "proxmox",
            "valid": true,
        }));
    }

    if results.is_empty() {
        diagnostics.insert(0, "ℹ️ No TLS certificates found on this server".to_string());
    } else {
        diagnostics.insert(0, format!("✅ Found {} certificate(s)", results.len()));
    }

    serde_json::json!({
        "certs": results,
        "diagnostics": diagnostics,
    })
}

/// Whitelist of directories the user may install/update a certificate into.
/// Anything else is rejected to prevent path traversal or accidental writes
/// to arbitrary locations like /etc/ssl/certs which are managed by the OS.
fn cert_target_allowed(cert_path: &str, key_path: &str) -> Result<(), String> {
    // /etc/wolfstack/ already covers /etc/wolfstack/tls/ and /etc/wolfstack/ssl/
    // because the prefix match accepts subdirectories. We list it here for
    // clarity; both `find_tls_certificate` and `list_certificates` actively
    // probe those subdirectories so the cert-install UI can target them.
    #[cfg(not(test))]
    let allowed_prefixes: &[&str] = &[
        "/etc/wolfstack/",
        "/etc/pve/local/",
        "/etc/pve/nodes/",
    ];
    // Test builds also accept /tmp/wolfstack-test/ so the cert flow can be
    // exercised end-to-end without root or production paths.
    #[cfg(test)]
    let allowed_prefixes: &[&str] = &[
        "/etc/wolfstack/",
        "/etc/pve/local/",
        "/etc/pve/nodes/",
        "/tmp/wolfstack-test/",
    ];
    let ok = |p: &str| -> bool {
        if p.contains("..") { return false; }
        allowed_prefixes.iter().any(|prefix| p.starts_with(prefix))
    };
    if !ok(cert_path) {
        return Err(format!("cert_path not in allowed locations: {}", cert_path));
    }
    if !ok(key_path) {
        return Err(format!("key_path not in allowed locations: {}", key_path));
    }
    Ok(())
}

/// Validate that a PEM blob parses as an X.509 certificate (cert) or RSA/EC key.
fn validate_pem(pem: &str, kind: &str) -> Result<(), String> {
    let trimmed = pem.trim();
    let header_ok = match kind {
        "cert" => trimmed.starts_with("-----BEGIN CERTIFICATE-----"),
        "key"  => trimmed.starts_with("-----BEGIN ")
            && (trimmed.contains("PRIVATE KEY-----")),
        _ => false,
    };
    if !header_ok {
        return Err(format!("Provided {} does not look like a PEM block", kind));
    }
    if !trimmed.ends_with("-----") {
        return Err(format!("Provided {} PEM is truncated", kind));
    }
    Ok(())
}

/// True if this PEM is a passphrase-protected private key. Detects both
/// the modern PKCS#8 form (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) and
/// the legacy "traditional" PEM form which advertises encryption via a
/// `Proc-Type: 4,ENCRYPTED` header inside an otherwise normal RSA/EC
/// PRIVATE KEY block.
fn is_encrypted_key_pem(pem: &str) -> bool {
    let t = pem.trim();
    if t.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return true;
    }
    // Legacy: BEGIN RSA PRIVATE KEY + Proc-Type: 4,ENCRYPTED + DEK-Info
    if t.contains("Proc-Type: 4,ENCRYPTED") {
        return true;
    }
    false
}

/// Decrypt a passphrase-protected private key in place at `path`. The
/// passphrase is passed via env var (visible only to root and the
/// child process for its lifetime) — never via argv, where it would
/// leak to anyone who can read /proc/<pid>/cmdline.
fn decrypt_key_in_place(path: &str, passphrase: &str) -> Result<(), String> {
    if !binary_exists("openssl") {
        return Err("openssl binary not found — cannot decrypt key".into());
    }
    let tmp_out = format!("{}.dec", path);
    let output = Command::new("openssl")
        .args(["pkey", "-in", path, "-passin", "env:WS_KEY_PASS", "-out", &tmp_out])
        .env("WS_KEY_PASS", passphrase)
        .output()
        .map_err(|e| format!("Failed to run openssl pkey: {}", e))?;
    if !output.status.success() {
        let _ = std::fs::remove_file(&tmp_out);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lower = stderr.to_lowercase();
        if lower.contains("bad decrypt")
            || lower.contains("bad password")
            || lower.contains("wrong password")
        {
            return Err("Wrong passphrase for the supplied private key.".into());
        }
        return Err(format!("Key decryption failed: {}", stderr.trim()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_out, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp_out, path)
        .map_err(|e| format!("Failed to replace encrypted key with decrypted version: {}", e))
}

/// Confirm cert and key actually pair up by comparing their public-key moduli.
/// Uses openssl, which is present on every distro WolfStack supports.
fn verify_cert_key_pair(cert_path: &str, key_path: &str) -> Result<(), String> {
    if !binary_exists("openssl") {
        return Err("openssl binary not found — cannot verify certificate".into());
    }
    let cert_mod = Command::new("openssl")
        .args(["x509", "-noout", "-modulus", "-in", cert_path])
        .output()
        .map_err(|e| format!("openssl x509 failed: {}", e))?;
    if !cert_mod.status.success() {
        return Err(format!(
            "Certificate parse failed: {}",
            String::from_utf8_lossy(&cert_mod.stderr).trim()
        ));
    }
    // Try RSA first, fall back to generic pkey for EC keys.
    let key_mod = Command::new("openssl")
        .args(["rsa", "-noout", "-modulus", "-in", key_path])
        .output()
        .map_err(|e| format!("openssl rsa failed: {}", e))?;
    if key_mod.status.success() {
        if cert_mod.stdout != key_mod.stdout {
            return Err("Certificate and private key do not match (modulus mismatch)".into());
        }
        return Ok(());
    }
    // EC key — compare public keys instead of moduli.
    let cert_pub = Command::new("openssl")
        .args(["x509", "-pubkey", "-noout", "-in", cert_path])
        .output()
        .map_err(|e| format!("openssl x509 pubkey failed: {}", e))?;
    let key_pub = Command::new("openssl")
        .args(["pkey", "-pubout", "-in", key_path])
        .output()
        .map_err(|e| format!("openssl pkey failed: {}", e))?;
    if !cert_pub.status.success() || !key_pub.status.success() {
        return Err("Could not extract public keys from cert/key for comparison".into());
    }
    if cert_pub.stdout != key_pub.stdout {
        return Err("Certificate and private key do not match (public key mismatch)".into());
    }
    Ok(())
}

/// Install or update a certificate by writing user-supplied PEM blobs to disk.
/// Defaults to /etc/wolfstack/{cert,key}.pem when target paths are not given.
///
/// The new files are written to `<path>.new` and validated against each other
/// (cert <-> key modulus match) before being atomically renamed into place,
/// so a bad upload never overwrites a working certificate.
///
/// `key_passphrase`: if the supplied private key is passphrase-protected
/// (PKCS#8 ENCRYPTED PRIVATE KEY or legacy Proc-Type: ENCRYPTED), the
/// passphrase is used to decrypt the key in place before validation. The
/// stored key on disk is always unencrypted — wolfstack/pveproxy don't
/// support prompting for a passphrase at startup.
pub fn install_certificate_files(
    cert_pem: &str,
    key_pem: &str,
    cert_path: Option<&str>,
    key_path: Option<&str>,
    key_passphrase: Option<&str>,
) -> Result<String, String> {
    let cert_path = cert_path.unwrap_or("/etc/wolfstack/cert.pem").to_string();
    let key_path  = key_path.unwrap_or("/etc/wolfstack/key.pem").to_string();
    cert_target_allowed(&cert_path, &key_path)?;
    validate_pem(cert_pem, "cert")?;
    validate_pem(key_pem, "key")?;

    let key_is_encrypted = is_encrypted_key_pem(key_pem);
    if key_is_encrypted && key_passphrase.map(|p| p.is_empty()).unwrap_or(true) {
        return Err(
            "Private key is passphrase-protected. Provide the passphrase in the \"Key passphrase\" field, or decrypt the key with `openssl pkey -in key.pem -out decrypted.pem` first."
                .into(),
        );
    }

    if let Some(parent) = std::path::Path::new(&cert_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    if let Some(parent) = std::path::Path::new(&key_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }

    let cert_tmp = format!("{}.new", cert_path);
    let key_tmp  = format!("{}.new", key_path);

    let cleanup = |paths: &[&str]| {
        for p in paths { let _ = std::fs::remove_file(p); }
    };

    if let Err(e) = std::fs::write(&cert_tmp, cert_pem.trim_end().to_string() + "\n") {
        cleanup(&[&cert_tmp]);
        return Err(format!("Failed to write {}: {}", cert_tmp, e));
    }
    if let Err(e) = std::fs::write(&key_tmp, key_pem.trim_end().to_string() + "\n") {
        cleanup(&[&cert_tmp, &key_tmp]);
        return Err(format!("Failed to write {}: {}", key_tmp, e));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cert_tmp, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::set_permissions(&key_tmp,  std::fs::Permissions::from_mode(0o600));
    }

    // If the key is encrypted, decrypt it on disk now that it's at .new.
    // The decrypted version replaces the .new file; the unencrypted form
    // is what gets atomically renamed into place at the end.
    if key_is_encrypted
        && let Err(e) = decrypt_key_in_place(&key_tmp, key_passphrase.unwrap_or("")) {
            cleanup(&[&cert_tmp, &key_tmp]);
            return Err(e);
        }

    if let Err(e) = verify_cert_key_pair(&cert_tmp, &key_tmp) {
        cleanup(&[&cert_tmp, &key_tmp]);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&cert_tmp, &cert_path) {
        cleanup(&[&cert_tmp, &key_tmp]);
        return Err(format!("Failed to move cert into place ({}): {}", cert_path, e));
    }
    if let Err(e) = std::fs::rename(&key_tmp, &key_path) {
        cleanup(&[&key_tmp]);
        return Err(format!("Failed to move key into place ({}): {}", key_path, e));
    }

    let restart_hint = cert_restart_hint(&cert_path);
    Ok(format!(
        "Certificate installed to {} (key: {}). {}",
        cert_path, key_path, restart_hint
    ))
}

/// What service needs reloading after writing to this cert path.
fn cert_restart_hint(cert_path: &str) -> &'static str {
    if cert_path.starts_with("/etc/pve/") {
        "Restart pveproxy on the Proxmox host to activate."
    } else {
        "Restart WolfStack to activate."
    }
}

/// Which systemd unit needs reloading for a given cert path.
/// Proxmox certs → `pveproxy`; everything else → `wolfstack`.
pub fn restart_service_name_for_cert(cert_path: &str) -> &'static str {
    if cert_path.starts_with("/etc/pve/") { "pveproxy" } else { "wolfstack" }
}

/// Schedule a deferred restart of one of the two services we touch from
/// the cert flow. The restart runs in a detached thread after a short
/// delay so the HTTP response that triggered it can flush back to the
/// caller before systemd kills us. Only `wolfstack` and `pveproxy` are
/// accepted — arbitrary unit names are rejected so this can't be used
/// as a generic systemctl-restart wrapper.
pub fn restart_cert_service(service: &str) -> Result<String, String> {
    let delay_ms = match service {
        "wolfstack" => 1500u64, // we're being killed — flush response first
        "pveproxy"  => 100u64,  // separate process, no flush concern
        other => return Err(format!("Refusing to restart unexpected service '{}'", other)),
    };
    let svc = service.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let _ = Command::new("systemctl")
            .args(["restart", &svc])
            .output();
    });
    Ok(format!("Restart of {} scheduled (in {}ms).", service, delay_ms))
}

/// Generate a self-signed certificate via openssl and install it.
/// `host` is the primary CN; `alt_names` may add additional DNS/IP SANs.
pub fn generate_self_signed_certificate(
    host: &str,
    alt_names: &[String],
    cert_path: Option<&str>,
    key_path: Option<&str>,
    days: u32,
) -> Result<String, String> {
    if host.trim().is_empty() {
        return Err("Hostname / CN is required".into());
    }
    if !binary_exists("openssl") {
        return Err("openssl binary not found — install openssl to generate self-signed certs".into());
    }
    let cert_path = cert_path.unwrap_or("/etc/wolfstack/cert.pem").to_string();
    let key_path  = key_path.unwrap_or("/etc/wolfstack/key.pem").to_string();
    cert_target_allowed(&cert_path, &key_path)?;

    if let Some(parent) = std::path::Path::new(&cert_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    if let Some(parent) = std::path::Path::new(&key_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }

    // Build the SAN list — always include the CN, plus any user-supplied alt names.
    let mut sans: Vec<String> = Vec::new();
    let push_san = |sans: &mut Vec<String>, v: &str| {
        let v = v.trim();
        if v.is_empty() { return; }
        let entry = if v.parse::<std::net::IpAddr>().is_ok() {
            format!("IP:{}", v)
        } else {
            format!("DNS:{}", v)
        };
        if !sans.contains(&entry) { sans.push(entry); }
    };
    push_san(&mut sans, host);
    for n in alt_names { push_san(&mut sans, n); }
    let san_arg = format!("subjectAltName={}", sans.join(","));
    let subj = format!("/CN={}", host);
    let days_str = days.max(1).to_string();

    // Generate to .new and atomically rename, so a failed openssl invocation
    // doesn't clobber an existing certificate.
    let cert_tmp = format!("{}.new", cert_path);
    let key_tmp  = format!("{}.new", key_path);

    let output = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-keyout", &key_tmp,
            "-out",    &cert_tmp,
            "-days",   &days_str,
            "-subj",   &subj,
            "-addext", &san_arg,
        ])
        .output()
        .map_err(|e| format!("Failed to run openssl: {}", e))?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&cert_tmp);
        let _ = std::fs::remove_file(&key_tmp);
        return Err(format!(
            "openssl req failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cert_tmp, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::set_permissions(&key_tmp,  std::fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = std::fs::rename(&cert_tmp, &cert_path) {
        let _ = std::fs::remove_file(&cert_tmp);
        let _ = std::fs::remove_file(&key_tmp);
        return Err(format!("Failed to move cert into place ({}): {}", cert_path, e));
    }
    if let Err(e) = std::fs::rename(&key_tmp, &key_path) {
        let _ = std::fs::remove_file(&key_tmp);
        return Err(format!("Failed to move key into place ({}): {}", key_path, e));
    }

    Ok(format!(
        "Self-signed certificate for {} generated at {} (key: {}). {}",
        host, cert_path, key_path, cert_restart_hint(&cert_path)
    ))
}

#[cfg(test)]
mod cert_tests {
    use super::*;
    use std::process::Command;

    /// Each test gets its own isolated subdirectory under /tmp/wolfstack-test/
    /// so they can run in parallel without trampling each other's files.
    /// Returns (cert_path, key_path) for the test to use.
    fn isolated_paths(test_name: &str) -> (String, String) {
        let dir = format!("/tmp/wolfstack-test/{}", test_name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        (format!("{}/cert.pem", dir), format!("{}/key.pem", dir))
    }

    fn cleanup(test_name: &str) {
        let dir = format!("/tmp/wolfstack-test/{}", test_name);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Monotonic counter so each helper invocation gets a unique scratch dir.
    /// Tests within one process all share PID, so basing the dir name on
    /// PID + counter avoids collisions when tests run in parallel and
    /// stops the dir-deleted-by-one-test-while-another-uses-it race.
    fn unique_id() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    /// Helper: generate a real RSA key + self-signed cert pair via openssl,
    /// return (cert_pem, key_pem) strings.
    fn make_rsa_pair(cn: &str) -> (String, String) {
        let dir = format!("/tmp/wolfstack-test/_helper-{}-{}", std::process::id(), unique_id());
        std::fs::create_dir_all(&dir).expect("create helper dir");
        let key_path = format!("{}/k.pem", dir);
        let cert_path = format!("{}/c.pem", dir);
        let out = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                   "-keyout", &key_path, "-out", &cert_path,
                   "-days", "1", "-subj", &format!("/CN={}", cn)])
            .output().unwrap();
        assert!(out.status.success(), "openssl req failed: {}", String::from_utf8_lossy(&out.stderr));
        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (cert_pem, key_pem)
    }

    fn make_encrypted_pkcs8_key(passphrase: &str) -> String {
        let dir = format!("/tmp/wolfstack-test/_helper-enc-{}-{}", std::process::id(), unique_id());
        std::fs::create_dir_all(&dir).expect("create helper dir");
        let plain = format!("{}/plain.pem", dir);
        let enc = format!("{}/enc.pem", dir);
        let out = Command::new("openssl").args(["genrsa", "-out", &plain, "2048"]).output().unwrap();
        assert!(out.status.success(), "openssl genrsa failed: {}", String::from_utf8_lossy(&out.stderr));
        let out = Command::new("openssl")
            .args(["pkcs8", "-topk8", "-in", &plain,
                   "-passout", &format!("pass:{}", passphrase),
                   "-out", &enc])
            .output().unwrap();
        assert!(out.status.success(), "openssl pkcs8 failed: {}", String::from_utf8_lossy(&out.stderr));
        let pem = std::fs::read_to_string(&enc).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        pem
    }

    // ─── validate_pem ─────────────────────────────────────────────────────
    #[test]
    fn validate_pem_accepts_valid_cert() {
        let (cert, _) = make_rsa_pair("validate-cert.test");
        assert!(validate_pem(&cert, "cert").is_ok());
    }
    #[test]
    fn validate_pem_accepts_valid_key() {
        let (_, key) = make_rsa_pair("validate-key.test");
        assert!(validate_pem(&key, "key").is_ok());
    }
    #[test]
    fn validate_pem_rejects_garbage() {
        assert!(validate_pem("not a pem block", "cert").is_err());
        assert!(validate_pem("not a pem block", "key").is_err());
    }
    #[test]
    fn validate_pem_rejects_truncated() {
        assert!(validate_pem("-----BEGIN CERTIFICATE-----\nMIIBIj", "cert").is_err());
    }
    #[test]
    fn validate_pem_accepts_encrypted_key() {
        let pem = make_encrypted_pkcs8_key("hunter2");
        // Encrypted PKCS#8 starts with BEGIN ENCRYPTED PRIVATE KEY which still
        // matches the "PRIVATE KEY-----" substring rule.
        assert!(validate_pem(&pem, "key").is_ok());
    }

    // ─── is_encrypted_key_pem ─────────────────────────────────────────────
    #[test]
    fn detects_pkcs8_encrypted() {
        let pem = make_encrypted_pkcs8_key("foo");
        assert!(is_encrypted_key_pem(&pem));
    }
    #[test]
    fn detects_legacy_proc_type_encrypted() {
        // Hand-crafted minimal PEM with the legacy header. We don't need a
        // real key body — is_encrypted_key_pem only inspects headers.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,1234\n\nABCD\n-----END RSA PRIVATE KEY-----\n";
        assert!(is_encrypted_key_pem(pem));
    }
    #[test]
    fn unencrypted_key_not_detected_as_encrypted() {
        let (_, key) = make_rsa_pair("unenc.test");
        assert!(!is_encrypted_key_pem(&key));
    }

    // ─── verify_cert_key_pair ─────────────────────────────────────────────
    #[test]
    fn verify_matching_rsa_pair() {
        let (cert_path, key_path) = isolated_paths("verify-rsa-match");
        let (cert, key) = make_rsa_pair("verify-rsa.test");
        std::fs::write(&cert_path, cert).unwrap();
        std::fs::write(&key_path, key).unwrap();
        assert!(verify_cert_key_pair(&cert_path, &key_path).is_ok());
        cleanup("verify-rsa-match");
    }
    #[test]
    fn verify_mismatched_rsa_pair_rejects() {
        let (cert_path, key_path) = isolated_paths("verify-rsa-mismatch");
        let (cert_a, _) = make_rsa_pair("a.test");
        let (_, key_b) = make_rsa_pair("b.test");
        std::fs::write(&cert_path, cert_a).unwrap();
        std::fs::write(&key_path, key_b).unwrap();
        let r = verify_cert_key_pair(&cert_path, &key_path);
        assert!(r.is_err(), "expected mismatch rejection");
        assert!(r.unwrap_err().to_lowercase().contains("do not match"));
        cleanup("verify-rsa-mismatch");
    }

    // ─── decrypt_key_in_place ─────────────────────────────────────────────
    #[test]
    fn decrypt_with_correct_passphrase() {
        let dir = "/tmp/wolfstack-test/decrypt-ok";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let path = format!("{}/key.pem", dir);
        std::fs::write(&path, make_encrypted_pkcs8_key("rightpass")).unwrap();
        assert!(decrypt_key_in_place(&path, "rightpass").is_ok());
        // After decrypt, file should now be a plain (unencrypted) PRIVATE KEY.
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(!after.contains("ENCRYPTED PRIVATE KEY"));
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn decrypt_with_wrong_passphrase_errors() {
        let dir = "/tmp/wolfstack-test/decrypt-bad";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let path = format!("{}/key.pem", dir);
        std::fs::write(&path, make_encrypted_pkcs8_key("rightpass")).unwrap();
        let r = decrypt_key_in_place(&path, "wrongpass");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_lowercase().contains("wrong passphrase"));
        let _ = std::fs::remove_dir_all(dir);
    }

    // ─── cert_target_allowed ──────────────────────────────────────────────
    #[test]
    fn whitelist_accepts_wolfstack_paths() {
        assert!(cert_target_allowed(
            "/etc/wolfstack/cert.pem", "/etc/wolfstack/key.pem"
        ).is_ok());
    }
    #[test]
    fn whitelist_accepts_proxmox_paths() {
        assert!(cert_target_allowed(
            "/etc/pve/local/pveproxy-ssl.pem", "/etc/pve/local/pveproxy-ssl.key"
        ).is_ok());
        assert!(cert_target_allowed(
            "/etc/pve/nodes/pve1/pveproxy-ssl.pem", "/etc/pve/nodes/pve1/pveproxy-ssl.key"
        ).is_ok());
    }
    #[test]
    fn whitelist_rejects_arbitrary_paths() {
        assert!(cert_target_allowed("/etc/passwd", "/etc/wolfstack/key.pem").is_err());
        assert!(cert_target_allowed("/var/lib/cert.pem", "/var/lib/key.pem").is_err());
    }
    #[test]
    fn whitelist_rejects_path_traversal() {
        assert!(cert_target_allowed(
            "/etc/wolfstack/../passwd", "/etc/wolfstack/key.pem"
        ).is_err());
    }
    #[test]
    fn whitelist_accepts_wolfstack_subdirectories() {
        // NyvenZA's path — /etc/wolfstack/tls/ is a natural place users put
        // certs and the cert-install UI must accept it as a write target.
        assert!(cert_target_allowed(
            "/etc/wolfstack/tls/cert.pem", "/etc/wolfstack/tls/key.pem"
        ).is_ok());
        assert!(cert_target_allowed(
            "/etc/wolfstack/ssl/fullchain.pem", "/etc/wolfstack/ssl/privkey.pem"
        ).is_ok());
    }

    #[test]
    fn local_cert_paths_table_includes_tls_and_ssl_subdirs() {
        // Regression test for NyvenZA — the bug was that the discovery code
        // only looked at /etc/wolfstack/cert.pem and /etc/wolfstack/key.pem,
        // ignoring /etc/wolfstack/tls/ entirely. Verify the path table that
        // both find_tls_certificate and list_certificates iterate over now
        // includes the tls/ and ssl/ subdirectories.
        let paths = wolfstack_local_cert_paths();
        let cert_paths: Vec<&str> = paths.iter().map(|(_, c, _)| *c).collect();
        assert!(cert_paths.contains(&"/etc/wolfstack/cert.pem"),
            "must keep the original /etc/wolfstack/cert.pem entry");
        assert!(cert_paths.contains(&"/etc/wolfstack/tls/cert.pem"),
            "must probe /etc/wolfstack/tls/cert.pem (NyvenZA's path)");
        assert!(cert_paths.contains(&"/etc/wolfstack/tls/fullchain.pem"),
            "must probe /etc/wolfstack/tls/fullchain.pem (Let's-Encrypt-style naming)");
        assert!(cert_paths.contains(&"/etc/wolfstack/ssl/cert.pem"),
            "must probe /etc/wolfstack/ssl/cert.pem (alt convention)");
    }

    // ─── generate_self_signed_certificate ─────────────────────────────────
    #[test]
    fn self_signed_end_to_end() {
        let (cert_path, key_path) = isolated_paths("self-signed-e2e");
        let r = generate_self_signed_certificate(
            "test.lan",
            &["test".to_string(), "192.168.1.10".to_string()],
            Some(&cert_path),
            Some(&key_path),
            30,
        );
        assert!(r.is_ok(), "{:?}", r);
        // Cert exists, key exists, modulus matches.
        assert!(std::path::Path::new(&cert_path).exists());
        assert!(std::path::Path::new(&key_path).exists());
        assert!(verify_cert_key_pair(&cert_path, &key_path).is_ok());
        // SANs include both the DNS name and the IP.
        let san_out = Command::new("openssl")
            .args(["x509", "-in", &cert_path, "-noout", "-ext", "subjectAltName"])
            .output().unwrap();
        let san = String::from_utf8_lossy(&san_out.stdout);
        assert!(san.contains("DNS:test.lan"), "expected DNS:test.lan in SANs, got: {}", san);
        assert!(san.contains("DNS:test"), "expected DNS:test in SANs, got: {}", san);
        assert!(san.contains("IP Address:192.168.1.10"), "expected IP SAN, got: {}", san);
        cleanup("self-signed-e2e");
    }
    #[test]
    fn self_signed_rejects_empty_host() {
        let (cert_path, key_path) = isolated_paths("self-signed-empty");
        let r = generate_self_signed_certificate("", &[], Some(&cert_path), Some(&key_path), 30);
        assert!(r.is_err());
        cleanup("self-signed-empty");
    }
    #[test]
    fn self_signed_rejects_bad_path() {
        let r = generate_self_signed_certificate(
            "test.lan", &[],
            Some("/etc/passwd"), Some("/etc/wolfstack/key.pem"),
            30,
        );
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("not in allowed"));
    }

    // ─── install_certificate_files ────────────────────────────────────────
    #[test]
    fn install_unencrypted_pair() {
        let (cert_path, key_path) = isolated_paths("install-plain");
        let (cert, key) = make_rsa_pair("install-plain.test");
        let r = install_certificate_files(
            &cert, &key, Some(&cert_path), Some(&key_path), None,
        );
        assert!(r.is_ok(), "{:?}", r);
        assert!(std::path::Path::new(&cert_path).exists());
        assert!(std::path::Path::new(&key_path).exists());
        // Modes: cert 0644, key 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
            let key_mode  = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(cert_mode, 0o644, "cert mode should be 0644");
            assert_eq!(key_mode,  0o600, "key mode should be 0600");
        }
        cleanup("install-plain");
    }
    #[test]
    fn install_mismatched_pair_does_not_overwrite_existing() {
        let (cert_path, key_path) = isolated_paths("install-mismatch");
        // Pre-populate with a known-good pair.
        let (good_cert, good_key) = make_rsa_pair("good.test");
        std::fs::write(&cert_path, &good_cert).unwrap();
        std::fs::write(&key_path,  &good_key).unwrap();
        // Try to install a mismatched pair (cert from A, key from B).
        let (bad_cert, _) = make_rsa_pair("bad-A.test");
        let (_, bad_key)  = make_rsa_pair("bad-B.test");
        let r = install_certificate_files(
            &bad_cert, &bad_key, Some(&cert_path), Some(&key_path), None,
        );
        assert!(r.is_err());
        // Original files MUST be untouched.
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), good_cert);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(),  good_key);
        // No leftover .new files.
        assert!(!std::path::Path::new(&format!("{}.new", cert_path)).exists());
        assert!(!std::path::Path::new(&format!("{}.new", key_path)).exists());
        cleanup("install-mismatch");
    }
    #[test]
    fn install_encrypted_key_without_passphrase_errors() {
        let (cert_path, key_path) = isolated_paths("install-enc-no-pass");
        let (cert, _) = make_rsa_pair("enc-no-pass.test");
        let enc_key = make_encrypted_pkcs8_key("secret");
        let r = install_certificate_files(
            &cert, &enc_key, Some(&cert_path), Some(&key_path), None,
        );
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.to_lowercase().contains("passphrase-protected") || msg.to_lowercase().contains("passphrase"),
            "expected passphrase prompt message, got: {}", msg);
        cleanup("install-enc-no-pass");
    }
    #[test]
    fn install_encrypted_key_with_correct_passphrase_works() {
        // Generate a real keypair, encrypt the key, then install with passphrase.
        // The decrypted key must match the cert.
        let dir = "/tmp/wolfstack-test/install-enc-ok";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();

        let plain_key_path = format!("{}/plain.key", dir);
        let cert_path_helper = format!("{}/c.pem", dir);
        // Make matching cert+key in one shot.
        let out = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                   "-keyout", &plain_key_path, "-out", &cert_path_helper,
                   "-days", "1", "-subj", "/CN=enc-install.test"])
            .output().unwrap();
        assert!(out.status.success());
        let cert_pem = std::fs::read_to_string(&cert_path_helper).unwrap();
        // Encrypt the key.
        let enc_key_path = format!("{}/enc.key", dir);
        let out = Command::new("openssl")
            .args(["pkcs8", "-topk8", "-in", &plain_key_path,
                   "-passout", "pass:s3cret", "-out", &enc_key_path])
            .output().unwrap();
        assert!(out.status.success());
        let enc_key_pem = std::fs::read_to_string(&enc_key_path).unwrap();

        // Install target paths.
        let install_cert = format!("{}/installed.pem", dir);
        let install_key  = format!("{}/installed.key", dir);
        let r = install_certificate_files(
            &cert_pem, &enc_key_pem,
            Some(&install_cert), Some(&install_key),
            Some("s3cret"),
        );
        assert!(r.is_ok(), "{:?}", r);
        // Installed key on disk is now unencrypted (nothing supports prompting).
        let installed_key = std::fs::read_to_string(&install_key).unwrap();
        assert!(installed_key.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(!installed_key.contains("ENCRYPTED"));

        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn install_encrypted_key_with_wrong_passphrase_errors_and_preserves_existing() {
        let dir = "/tmp/wolfstack-test/install-enc-bad";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let cert_path = format!("{}/cert.pem", dir);
        let key_path  = format!("{}/key.pem", dir);
        // Pre-existing valid pair.
        let (good_cert, good_key) = make_rsa_pair("preserve.test");
        std::fs::write(&cert_path, &good_cert).unwrap();
        std::fs::write(&key_path,  &good_key).unwrap();
        // Try install with encrypted key + wrong passphrase.
        let (new_cert, _) = make_rsa_pair("new.test");
        let enc_key = make_encrypted_pkcs8_key("rightpass");
        let r = install_certificate_files(
            &new_cert, &enc_key, Some(&cert_path), Some(&key_path), Some("WRONG"),
        );
        assert!(r.is_err());
        // Existing files preserved.
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), good_cert);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(),  good_key);
        let _ = std::fs::remove_dir_all(dir);
    }

    // ─── restart_service_name_for_cert ────────────────────────────────────
    #[test]
    fn restart_name_for_pve_paths() {
        assert_eq!(restart_service_name_for_cert("/etc/pve/local/x.pem"), "pveproxy");
        assert_eq!(restart_service_name_for_cert("/etc/pve/nodes/pve1/x.pem"), "pveproxy");
    }
    #[test]
    fn restart_name_for_wolfstack_paths() {
        assert_eq!(restart_service_name_for_cert("/etc/wolfstack/cert.pem"), "wolfstack");
    }

    // ─── restart_cert_service ─────────────────────────────────────────────
    #[test]
    fn restart_cert_service_rejects_arbitrary_unit() {
        let r = restart_cert_service("nginx");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Refusing"));
    }
    #[test]
    fn restart_cert_service_accepts_known_units() {
        // We don't actually want to restart these in the test env. The
        // function spawns a thread with a delay; we verify it returns Ok
        // without waiting for the thread (the systemctl call inside the
        // thread will fail without root, but we don't care — we're testing
        // input validation, not the thread side-effect).
        assert!(restart_cert_service("wolfstack").is_ok());
        assert!(restart_cert_service("pveproxy").is_ok());
    }

    #[test]
    fn host_matches_exact_and_case_and_trailing_dot() {
        assert!(host_matches_cert_name("host.example.com", "host.example.com"));
        assert!(host_matches_cert_name("Host.Example.COM", "host.example.com"));
        assert!(host_matches_cert_name("host.example.com.", "host.example.com"));
        assert!(!host_matches_cert_name("host.example.com", "other.example.com"));
        assert!(!host_matches_cert_name("", "host.example.com"));
    }

    #[test]
    fn host_matches_wildcard_single_label_only() {
        // Covers exactly one left-most label (RutgerDiehard's case).
        assert!(host_matches_cert_name("*.example.com", "host.example.com"));
        assert!(host_matches_cert_name("*.example.com", "anything.example.com"));
        // Must NOT match the bare apex or a deeper subdomain.
        assert!(!host_matches_cert_name("*.example.com", "example.com"));
        assert!(!host_matches_cert_name("*.example.com", "a.b.example.com"));
        // Wrong parent zone.
        assert!(!host_matches_cert_name("*.example.com", "host.example.org"));
        // A bare "*." pattern matches nothing.
        assert!(!host_matches_cert_name("*.", "host.example.com"));
    }
}

#[cfg(test)]
mod credential_bootstrap_tests {
    use super::*;

    #[test]
    fn only_database_components_bootstrap_credentials() {
        assert!(credential_bootstrap_script(Component::MariaDB).is_some());
        assert!(credential_bootstrap_script(Component::PostgreSQL).is_some());
        for c in [Component::WolfNet, Component::WolfProxy, Component::Certbot] {
            assert!(credential_bootstrap_script(c).is_none(), "{:?} must not bootstrap", c);
        }
    }

    #[test]
    fn bootstrap_never_overwrites_recorded_credentials() {
        // The guard is what stops a re-install or an upgrade invalidating
        // connections the operator has already saved.
        for c in [Component::MariaDB, Component::PostgreSQL] {
            let s = credential_bootstrap_script(c).unwrap();
            assert!(s.contains("if [ -f \"$WS_CRED_FILE\" ]"), "{:?} lost its keep-existing guard", c);
            assert!(s.contains("chmod 600 \"$WS_CRED_FILE\""), "{:?} must keep the file root-only", c);
        }
    }

    #[test]
    fn bootstrap_grants_a_usable_account() {
        let mariadb = credential_bootstrap_script(Component::MariaDB).unwrap();
        assert!(mariadb.contains("CREATE USER IF NOT EXISTS 'wolfstack'@'127.0.0.1'"));
        assert!(mariadb.contains("GRANT ALL PRIVILEGES ON *.* TO 'wolfstack'@'127.0.0.1'"));

        let postgres = credential_bootstrap_script(Component::PostgreSQL).unwrap();
        assert!(postgres.contains("CREATE ROLE wolfstack LOGIN SUPERUSER PASSWORD"));
        // A password with no matching pg_hba rule is not a usable account.
        assert!(postgres.contains("scram-sha-256"));
    }

    /// Dump the exact generated script so it can be run against a real server.
    /// Ignored by default — `cargo test -- --ignored dump_bootstrap_scripts`.
    #[test]
    #[ignore]
    fn dump_bootstrap_scripts() {
        for (c, name) in [(Component::MariaDB, "mariadb"), (Component::PostgreSQL, "postgresql")] {
            let path = format!("/tmp/wolfstack-bootstrap-{}.sh", name);
            std::fs::write(&path, credential_bootstrap_script(c).unwrap()).unwrap();
            println!("wrote {}", path);
        }
    }
}
