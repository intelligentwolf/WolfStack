// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Icon pack management — scan, install, and serve Linux icon themes
//!
//! Supports the freedesktop.org icon theme specification so users can install
//! any standard Linux icon pack (Candy, Papirus, Tela, etc.) and use it
//! throughout the WolfStack UI.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::info;

/// Where custom-installed icon packs are stored
fn icon_packs_dir() -> String { crate::paths::get().icon_packs_dir }

/// How long a pack scan stays valid. Icon packs only change when an
/// operator installs or removes one, and both paths call
/// [`invalidate_caches`], so this TTL only bounds staleness for packs
/// dropped into /usr/share/icons behind our back.
const PACK_SCAN_TTL: Duration = Duration::from_secs(300);

type PackScan = Option<(Instant, Vec<IconPack>)>;
type IconPaths = HashMap<(String, String), Option<PathBuf>>;

static PACK_SCAN_CACHE: OnceLock<Mutex<PackScan>> = OnceLock::new();
/// (pack_id, semantic_name) -> resolved file, memoised. `None` is cached
/// too: a miss is the *expensive* answer (~15k failed stat() calls once
/// every candidate and every fallback has been tried), so never paying
/// for the same miss twice is the whole point.
static ICON_PATH_CACHE: OnceLock<Mutex<IconPaths>> = OnceLock::new();

fn pack_scan_cache() -> &'static Mutex<PackScan> {
    PACK_SCAN_CACHE.get_or_init(|| Mutex::new(None))
}

fn icon_path_cache() -> &'static Mutex<IconPaths> {
    ICON_PATH_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Drop both caches. Called after any install/remove so the next request
/// re-scans instead of serving a pack that is no longer on disk.
pub fn invalidate_caches() {
    if let Ok(mut c) = pack_scan_cache().lock() { *c = None; }
    if let Ok(mut c) = icon_path_cache().lock() { c.clear(); }
}

/// Cached form of [`scan_all_packs`].
///
/// Every `/api/icon-packs/{pack}/icon/{name}` request used to call
/// `scan_all_packs()` just to turn a pack id into a directory — a full
/// read_dir of every icon theme on the box, including `count_icons_rough`
/// walking seven subdirectories per pack. Selecting an icon pack fires one
/// request per `[data-icon]` placeholder (1,022 on the datacenter page), so
/// that scan ran a thousand times in a burst and starved every actix worker:
/// an idle `/api/agent/status` went from 4 ms to 4,092 ms and the whole UI
/// rendered empty (Paul, 2026-08-13, wolfstack-1).
pub fn scan_all_packs_cached() -> Vec<IconPack> {
    if let Ok(guard) = pack_scan_cache().lock()
        && let Some((at, packs)) = guard.as_ref()
            && at.elapsed() < PACK_SCAN_TTL {
                return packs.clone();
            }
    // Scan outside the lock — a cold scan on a box with large packs takes
    // long enough that holding the mutex would serialise every caller
    // behind it. A concurrent burst may scan more than once; that is
    // strictly better than a queue of threads waiting on one scan.
    let packs = scan_all_packs();
    if let Ok(mut guard) = pack_scan_cache().lock() {
        *guard = Some((Instant::now(), packs.clone()));
    }
    packs
}

/// Set of names we are willing to memoise. See [`resolve_icon_cached`].
static KNOWN_SEMANTICS: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();

fn is_known_semantic(name: &str) -> bool {
    KNOWN_SEMANTICS
        .get_or_init(|| semantic_to_freedesktop().keys().copied().collect())
        .contains(name)
}

/// Cached form of [`resolve_icon`], keyed by pack id + semantic name.
///
/// Only *known* semantic names are memoised. `semantic_name` arrives from
/// the request path, so caching it unconditionally would let any logged-in
/// user grow this map without bound by requesting made-up icon names. The
/// frontend only ever asks for names from `semantic_names()`, so the cache
/// stays bounded at (packs x semantics) and nothing real loses its cache
/// entry. Unknown names still resolve correctly, just without memoisation.
pub fn resolve_icon_cached(pack_id: &str, theme_dir: &Path, semantic_name: &str) -> Option<PathBuf> {
    if !is_known_semantic(semantic_name) {
        return resolve_icon(theme_dir, semantic_name);
    }
    let key = (pack_id.to_string(), semantic_name.to_string());
    if let Ok(cache) = icon_path_cache().lock()
        && let Some(hit) = cache.get(&key) {
            return hit.clone();
        }
    // Resolve outside the lock — this is the multi-thousand-stat() call the
    // cache exists to avoid, and holding the mutex across it would put every
    // other icon request behind this one.
    let resolved = resolve_icon(theme_dir, semantic_name);
    if let Ok(mut cache) = icon_path_cache().lock() {
        cache.insert(key, resolved.clone());
    }
    resolved
}

/// Standard system icon theme paths to scan
const SYSTEM_ICON_DIRS: &[&str] = &[
    "/usr/share/icons",
    "/usr/local/share/icons",
];

/// Mapping from WolfStack semantic icon names to freedesktop.org standard names.
/// The frontend sends these semantic names; we resolve them to actual files.
/// got AI to do this bit PC
pub fn semantic_to_freedesktop() -> HashMap<&'static str, &'static [&'static str]> {
    let mut m: HashMap<&str, &[&str]> = HashMap::new();
    // Navigation — verified against Candy, Papirus, Mint-Y, Tela, Breeze
    m.insert("home",           &["user-home", "go-home", "folder-home", "start-here-kde", "cs-desktop"]);
    m.insert("settings",       &["preferences-system", "systemsettings", "cs-general", "gnome-settings", "gtk-preferences", "preferences", "configure", "system-settings", "cs-themes", "gnome-control-center"]);
    m.insert("network",        &["network-workgroup", "preferences-system-network", "cs-network", "network-wired", "network-server", "nm-device-wired", "gnome-nettool", "network-manager"]);
    m.insert("globe",          &["applications-internet", "internet-web-browser", "web-browser", "cs-network", "preferences-system-network-proxy"]);
    m.insert("appstore",       &["system-software-install", "gnome-software", "org.gnome.Software", "plasmadiscover", "mintinstall", "applications-other", "folder-download"]);
    m.insert("warning",        &["dialog-warning", "emblem-warning", "folder-important", "messagebox_warning"]);
    m.insert("help",           &["help-faq", "help-about", "help-contents", "system-help", "help-browser", "gtk-help", "gnome-help"]);
    m.insert("add",            &["list-add", "add", "contact-new", "folder-new", "gtk-add"]);
    m.insert("logout",         &["system-log-out", "application-exit", "cs-user", "gnome-logout", "xfce-system-exit"]);
    // Settings tabs
    m.insert("palette",        &["preferences-desktop-theme", "preferences-desktop-theme-applications", "cs-cat-appearance", "cs-themes", "cs-backgrounds", "applications-graphics", "preferences-desktop-wallpaper"]);
    m.insert("bell",           &["bell", "preferences-desktop-notification", "preferences-desktop-notification-bell", "notification-active", "notifications", "cs-notifications"]);
    m.insert("robot",          &["utilities-terminal", "application-x-executable", "applications-development", "cs-sources", "terminal", "yakuake"]);
    m.insert("package",        &["package-x-generic", "folder-tar", "folder-deb", "applications-utilities", "system-software-install"]);
    m.insert("lock",           &["system-lock-screen", "preferences-security", "cs-privacy", "cs-screensaver", "folder-locked", "security-high", "dialog-password", "changes-prevent", "preferences-desktop-screensaver"]);
    m.insert("heart",          &["emblem-favorite", "favorites", "folder-favorites", "love", "help-donate"]);
    // Components
    m.insert("shield",         &["security-high", "preferences-security-firewall", "firewall-config", "cs-firewall", "preferences-system-firewall", "folder-locked", "network-server-security", "shield"]);
    m.insert("satellite",      &["network-wireless-connected-100", "network-wireless", "nm-signal-100", "network-transmit-receive", "cs-network"]);
    m.insert("save",           &["drive-harddisk", "media-floppy", "document-save", "gtk-save"]);
    m.insert("scale",          &["preferences-desktop-display", "preferences-desktop-display-randr", "cs-display", "video-display", "utilities-system-monitor", "cs-screen", "gnome-monitor"]);
    m.insert("database",       &["folder-database", "drive-multidisk", "network-server", "database", "db", "application-x-sqlite3"]);
    m.insert("certbot",        &["certificate-server", "application-certificate", "preferences-security", "folder-locked", "security-high", "dialog-password"]);
    // Storage
    m.insert("cloud",          &["folder-cloud", "weather-overcast", "folder-gdrive", "folder-nextcloud", "cs-network", "owncloud", "knetattach"]);
    m.insert("folder",         &["folder", "inode-directory", "system-file-manager", "gtk-directory", "stock_folder"]);
    m.insert("folder-open",    &["folder-open", "folder-visiting", "folder-drag-accept"]);
    m.insert("disk",           &["drive-harddisk", "drive-removable-media", "drive-multidisk", "gnome-dev-harddisk", "preferences-system-disks"]);
    // Containers
    m.insert("docker",         &["folder-docker", "docker", "container", "application-x-container", "applications-utilities", "gnome-boxes"]);
    m.insert("container",      &["container", "package-x-generic", "folder-tar", "folder-deb", "applications-utilities", "application-x-archive"]);
    m.insert("computer",       &["computer", "user-desktop", "cs-desktop", "system", "gnome-computer"]);
    // Status
    m.insert("fire",           &["dialog-warning", "emblem-important", "folder-important", "security-low", "cs-firewall", "preferences-security-firewall"]);
    m.insert("chat",           &["internet-group-chat", "empathy", "pidgin", "konversation", "folder-mail", "preferences-desktop-notification", "cs-notifications"]);
    m.insert("email",          &["internet-mail", "mail-unread", "mail-message-new", "kmail", "folder-mail", "evolution", "thunderbird", "cs-send"]);
    m.insert("rocket",         &["media-playback-playing", "system-run", "media-playback-start", "cs-startup", "preferences-system-startup"]);
    m.insert("lightning",      &["battery-full-charging", "battery-good-charging", "weather-storm", "cs-power", "gnome-power-manager", "preferences-system-power-management", "utilities-energy-monitor"]);
    m.insert("laptop",         &["computer-laptop", "computer", "user-desktop", "cs-desktop"]);
    m.insert("brain",          &["preferences-system", "systemsettings", "cs-general", "applications-development", "preferences", "gnome-settings"]);
    m.insert("lightbulb",      &["dialog-information", "help-faq", "preferences-desktop-accessibility", "cs-accessibility", "gnome-accessibility", "kaccess"]);
    m.insert("document",       &["folder-text", "text-x-generic", "folder-documents", "document-new", "accessories-text-editor"]);
    m.insert("pin",            &["folder-bookmark", "folder-favorites", "bookmark-new", "emblem-important"]);
    m.insert("link",           &["emblem-symbolic-link", "folder-remote", "folder-network", "cs-network", "preferences-system-network-sharing"]);
    m.insert("clipboard",      &["edit-paste", "edit-copy", "accessories-clipboard", "klipper", "folder-notes", "gtk-paste"]);
    m.insert("chart",          &["utilities-system-monitor", "gnome-system-monitor", "org.gnome.SystemMonitor", "ksysguardd", "folder-chart", "ksysguard"]);
    m.insert("chart-up",       &["folder-chart", "go-up", "utilities-system-monitor", "gnome-system-monitor"]);
    m.insert("wrench",         &["preferences-other", "preferences-system", "preferences", "gtk-preferences", "cs-general"]);
    m.insert("tools",          &["applications-system", "preferences-system", "systemsettings", "preferences", "cs-general", "gnome-control-center"]);
    m.insert("edit",           &["accessories-text-editor", "text-editor", "kate", "kwrite", "folder-text", "gtk-edit", "gedit"]);
    m.insert("search",         &["edit-find", "system-search", "kfind", "folder-recent", "gtk-find", "gnome-searchtool", "plasma-search"]);
    m.insert("image",          &["folder-image", "folder-pictures", "image-x-generic", "applications-graphics", "gwenview", "eog"]);
    m.insert("key",            &["dialog-password", "preferences-security", "cs-privacy", "folder-locked", "changes-allow", "gcr-key", "kwalletmanager"]);
    m.insert("megaphone",      &["notification-active", "notifications", "preferences-desktop-notification", "preferences-desktop-notification-bell", "cs-notifications"]);
    // File types
    m.insert("file-code",      &["applications-development", "text-x-script", "folder-development", "text-x-source", "text-x-csrc", "kdevelop"]);
    m.insert("file-config",    &["preferences-other", "text-x-generic", "folder-script", "text-x-cmake", "application-x-yaml"]);
    m.insert("file-archive",   &["folder-tar", "application-x-archive", "package-x-generic", "application-x-compressed-tar", "ark"]);
    m.insert("file-image",     &["folder-image", "image-x-generic", "folder-pictures", "image-png"]);
    m.insert("file-text",      &["folder-text", "text-plain", "text-x-generic", "text-x-readme"]);
    m.insert("file-data",      &["folder-database", "application-x-sqlite3", "drive-multidisk", "database"]);
    m.insert("file-shell",     &["utilities-terminal", "text-x-script", "folder-script", "bash", "terminal"]);
    // Monitoring
    m.insert("cpu",            &["utilities-system-monitor", "preferences-devices-cpu", "cpu", "hwinfo", "gnome-system-monitor", "ksysguardd", "ksysguard"]);
    m.insert("memory",         &["drive-harddisk", "utilities-system-monitor", "media-memory", "gnome-dev-memory"]);
    m.insert("swap",           &["drive-removable-media", "view-refresh", "system-reboot", "media-removable"]);
    m.insert("load",           &["utilities-system-monitor", "gnome-system-monitor", "ksysguardd", "folder-chart", "go-up"]);
    m.insert("service",        &["preferences-system-services", "preferences-system", "cs-startup", "system-run", "preferences", "gnome-session"]);
    // Misc
    m.insert("door",           &["system-log-out", "application-exit", "cs-user", "gnome-logout"]);
    m.insert("wolf",           &["emblem-system", "applications-system", "security-high", "gnome-app-install", "kde"]);
    m.insert("gamepad",        &["applications-games", "input-gaming", "folder-games", "cs-cat-games", "preferences-desktop-gaming"]);
    m.insert("music",          &["folder-music", "audio-x-generic", "applications-multimedia", "amarok", "elisa", "rhythmbox", "cs-sound"]);
    m.insert("camera",         &["accessories-camera", "camera-photo", "spectacle", "folder-pictures", "cs-media"]);
    m.insert("cart",           &["folder-download", "applications-other", "system-software-install", "plasmadiscover"]);
    m.insert("money",          &["accessories-calculator", "kcalc", "galculator", "folder-calculate", "applications-office"]);
    m.insert("book",           &["accessories-dictionary", "folder-book", "help-contents", "cs-info", "okular"]);
    m.insert("lab",            &["applications-science", "applications-development", "utilities-system-monitor"]);
    m.insert("star",           &["emblem-favorite", "favorites", "folder-favorites", "starred"]);
    m.insert("runner",         &["media-playback-playing", "system-run", "media-playback-start", "cs-startup"]);
    // VM-specific (Breeze has dedicated VM icons)
    m.insert("vm",             &["vm", "virt-manager", "preferences-system-linux", "computer"]);
    // App-specific icons (for app store entries)
    m.insert("fox",            &["firefox", "org.mozilla.firefox", "falkon", "internet-web-browser", "applications-internet"]);
    m.insert("elephant",       &["folder-database", "drive-multidisk", "database", "application-x-sqlite3"]);
    m.insert("whale",          &["folder-docker", "docker", "container", "applications-utilities", "gnome-boxes"]);
    m.insert("penguin",        &["folder-linux", "preferences-system-linux", "applications-system", "utilities-terminal", "tux"]);
    m.insert("movie",          &["folder-video", "folder-videos", "applications-multimedia", "dragonplayer", "totem", "vlc"]);
    m.insert("target",         &["folder-bookmark", "folder-important", "emblem-favorite", "cs-cat-overview"]);
    m.insert("alien",          &["applications-games", "folder-games", "input-gaming", "cs-cat-games"]);
    m
    // dont forget to put m on its own on the last line or it will break the code and cause a compile error. PC
}

/// Fallback icon names to try when no semantic match is found.
/// These are common icons that most freedesktop packs include.
const FALLBACK_ICONS: &[&str] = &[
    "applications-other",
    "application-default-icon",
    "preferences",
    "folder",
    "emblem-system",
    "applications-utilities",
    "text-x-generic",
];

/// Metadata about an installed icon pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IconPack {
    pub id: String,
    pub name: String,
    pub comment: String,
    pub path: String,
    /// "system" | "custom"
    pub source: String,
    /// Whether this pack has scalable SVGs
    pub has_scalable: bool,
    /// Number of icons found
    pub icon_count: usize,
    /// Sample icon names available
    #[serde(default)]
    pub sample_icons: Vec<String>,
}

/// Parse a freedesktop index.theme file to extract name and comment
fn parse_index_theme(path: &Path) -> Option<(String, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut name = String::new();
    let mut comment = String::new();
    let mut in_icon_theme = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[Icon Theme]" {
            in_icon_theme = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_icon_theme = false;
            continue;
        }
        if !in_icon_theme { continue; }
        if let Some(val) = trimmed.strip_prefix("Name=") {
            if name.is_empty() { name = val.to_string(); }
        } else if let Some(val) = trimmed.strip_prefix("Comment=")
            && comment.is_empty() { comment = val.to_string(); }
    }
    if name.is_empty() { return None; }
    Some((name, comment))
}

/// Find a .theme.in template file in a directory (used by KDE repos like Breeze).
/// Returns the first non-dark .theme.in that is a *valid* icon theme (a real
/// `[Icon Theme]` section with a `Name=`), falling back to a dark variant.
///
/// Validation matters: KDE's `icons/` ships helper fragments alongside the real
/// theme — e.g. `commonthemeinfo.theme.in` has no `[Icon Theme]`/`Name=`. Picking
/// one of those (read_dir order is arbitrary) and copying it to `index.theme`
/// produced an unparseable theme, so `scan_icon_dir` skipped the pack: it stayed
/// "installed" (dir present, blocks reinstall) yet unlisted and unselectable.
fn find_theme_in_file(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut fallback: Option<PathBuf> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".theme.in") { continue; }
        let path = entry.path();
        // Must be a real icon theme, not a config fragment.
        if parse_index_theme(&path).is_none() { continue; }
        // Prefer the non-dark variant.
        if !name.to_lowercase().contains("dark") {
            return Some(path);
        }
        if fallback.is_none() {
            fallback = Some(path);
        }
    }
    fallback
}

/// Search an icon theme directory for a named icon, returning the file path.
/// Prefers scalable SVGs, then larger PNGs.
///
/// Handles all common freedesktop.org icon theme layouts:
///   - Papirus-style:  `48x48/apps/icon.svg`   (size-first, NxN)
///   - Mint-Y-style:   `apps/48/icon.svg`       (category-first, bare number)
///   - Candy-style:    `apps/scalable/icon.svg`  (category-first, scalable)
///   - Flat:           `scalable/apps/icon.svg`  (scalable-first)
pub fn find_icon_file(theme_dir: &Path, icon_name: &str) -> Option<PathBuf> {
    let scalable_dirs = ["scalable", "symbolic"];
    // NxN format (Papirus, Adwaita, etc.)
    let nxn_sizes = ["512x512", "256x256", "128x128", "96x96", "64x64",
                     "48x48", "42x42", "32x32", "24x24", "22x22", "18x18", "16x16"];
    // Bare number format (Mint-Y, elementary, etc.)
    let bare_sizes = ["256", "128", "96", "64", "48", "32", "24", "22", "16"];
    let context_dirs = ["apps", "actions", "categories", "devices", "emblems",
                        "mimetypes", "places", "status", "preferences", "panel",
                        "stock", "legacy"];
    let extensions = ["svg", "png", "xpm"];

    // 1. scalable/category/ or symbolic/category/ (flat scalable-first)
    for sc in &scalable_dirs {
        for ctx in &context_dirs {
            for ext in &extensions {
                let p = theme_dir.join(sc).join(ctx).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
        for ext in &extensions {
            let p = theme_dir.join(sc).join(format!("{}.{}", icon_name, ext));
            if p.exists() { return Some(p); }
        }
    }

    // 2. category/scalable/ or category/symbolic/ (Candy-style)
    for ctx in &context_dirs {
        for sc in &scalable_dirs {
            for ext in &extensions {
                let p = theme_dir.join(ctx).join(sc).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
    }

    // 3. category/size/ — bare numbers, biggest first (Mint-Y-style)
    for ctx in &context_dirs {
        for sz in &bare_sizes {
            for ext in &extensions {
                let p = theme_dir.join(ctx).join(sz).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
    }

    // 4. NxN/category/ — biggest first (Papirus-style)
    for sz in &nxn_sizes {
        for ctx in &context_dirs {
            for ext in &extensions {
                let p = theme_dir.join(sz).join(ctx).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
    }

    None
}

/// Resolve a WolfStack semantic icon name to a file in the given theme.
/// Tries: specific candidates → semantic name directly → fallback icons.
pub fn resolve_icon(theme_dir: &Path, semantic_name: &str) -> Option<PathBuf> {
    let map = semantic_to_freedesktop();
    if let Some(candidates) = map.get(semantic_name) {
        for name in *candidates {
            if let Some(p) = find_icon_file(theme_dir, name) {
                return Some(p);
            }
        }
    }
    // Try the semantic name directly (some packs may have custom names)
    if let Some(p) = find_icon_file(theme_dir, semantic_name) {
        return Some(p);
    }
    // Use a fallback icon so we never show a mix of emojis and pack icons
    resolve_fallback(theme_dir)
}

/// Find any generic fallback icon from the pack
fn resolve_fallback(theme_dir: &Path) -> Option<PathBuf> {
    for name in FALLBACK_ICONS {
        if let Some(p) = find_icon_file(theme_dir, name) {
            return Some(p);
        }
    }
    None
}

/// Scan a directory for valid icon themes (must have index.theme)
fn scan_icon_dir(base: &Path, source: &str) -> Vec<IconPack> {
    let mut packs = Vec::new();
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return packs,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        let index = path.join("index.theme");
        if !index.exists() { continue; }
        let (name, comment) = match parse_index_theme(&index) {
            Some(v) => v,
            None => continue,
        };
        // Skip cursor-only themes or hicolor
        let dir_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if dir_name == "hicolor" || dir_name == "default" { continue; }
        if name.to_lowercase().contains("cursor") { continue; }

        let has_scalable = path.join("scalable").exists()
            || path.join("apps").join("scalable").exists();

        let icon_count = count_icons_rough(&path);

        packs.push(IconPack {
            id: dir_name,
            name,
            comment,
            path: path.to_string_lossy().to_string(),
            source: source.to_string(),
            has_scalable,
            icon_count,
            sample_icons: Vec::new(),
        });
    }
    packs
}

/// Rough count of icon files in a theme
fn count_icons_rough(dir: &Path) -> usize {
    let mut count = 0;
    // Just count in a few common subdirectories to keep it fast
    let check_dirs = ["scalable/apps", "48x48/apps", "scalable/places", "scalable/categories",
                      "apps/scalable", "apps/48", "places/scalable"];
    for sub in &check_dirs {
        let p = dir.join(sub);
        if let Ok(entries) = std::fs::read_dir(&p) {
            count += entries.flatten()
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.ends_with(".svg") || name.ends_with(".png")
                })
                .count();
        }
    }
    count
}

/// Scan all known icon directories for available themes
pub fn scan_all_packs() -> Vec<IconPack> {
    let mut packs = Vec::new();

    // System icon dirs
    for dir in SYSTEM_ICON_DIRS {
        packs.extend(scan_icon_dir(Path::new(dir), "system"));
    }

    // Custom-installed packs
    let icon_packs = icon_packs_dir();
    let custom_dir = Path::new(&icon_packs);
    if custom_dir.exists() {
        packs.extend(scan_icon_dir(custom_dir, "custom"));
    }

    // Sort: custom first, then by name
    packs.sort_by(|a, b| {
        if a.source != b.source {
            if a.source == "custom" { return std::cmp::Ordering::Less; }
            return std::cmp::Ordering::Greater;
        }
        a.name.cmp(&b.name)
    });

    packs
}

/// Install an icon pack from a GitHub repository URL.
/// Clones with --depth 1 to save space, moves to /etc/wolfstack/icon-packs/{name}.
pub async fn install_from_github(url: &str) -> Result<IconPack, String> {
    // Validate URL looks like a GitHub repo
    if !url.contains("github.com/") {
        return Err("URL must be a GitHub repository (e.g. https://github.com/user/repo)".into());
    }

    // Extract repo name from URL
    let repo_name = url
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .rsplit('/')
        .next()
        .ok_or("Could not parse repository name from URL")?
        .to_string();

    // Harden against path traversal. repo_name flows into `dest =
    // install_dir.join(repo_name)` and then into git clone AND remove_dir_all
    // (the self-heal path below). A crafted URL like `https://github.com/u/..`
    // still contains "github.com/" but yields repo_name ".." → dest would escape
    // the icon-packs dir and a remove_dir_all could wipe /etc/wolfstack. Require
    // a single safe path component (git repo names are `[A-Za-z0-9._-]`).
    let safe_name = !repo_name.is_empty()
        && repo_name != "."
        && repo_name != ".."
        && repo_name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !safe_name {
        return Err(format!("Refusing to install: '{}' is not a valid repository name", repo_name));
    }

    let install_dir = PathBuf::from(icon_packs_dir());
    let dest = install_dir.join(&repo_name);

    if dest.exists() {
        // Only block reinstall if what's there is actually a usable pack. A
        // previous broken install (e.g. an unparseable index.theme) is NOT
        // listed by scan_all_packs, so the UI can't offer to delete it either —
        // the user gets stuck on "already installed" with nothing selectable.
        // Self-heal: remove the broken dir and continue with a fresh install.
        if parse_index_theme(&dest.join("index.theme")).is_some() {
            return Err(format!("Icon pack '{}' is already installed", repo_name));
        }
        info!("Removing broken/incomplete icon pack '{}' before reinstall", repo_name);
        std::fs::remove_dir_all(&dest)
            .map_err(|e| format!("Failed to remove broken icon pack '{}' for reinstall: {}", repo_name, e))?;
    }

    // Ensure parent dir exists
    std::fs::create_dir_all(&install_dir)
        .map_err(|e| format!("Failed to create icon packs directory: {}", e))?;

    info!("Installing icon pack from {} to {:?}", url, dest);

    // Clone with depth 1
    let output = tokio::process::Command::new("git")
        .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
        .output()
        .await
        .map_err(|e| format!("Failed to run git clone: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git clone failed: {}", stderr));
    }

    // Remove .git directory to save space
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        let _ = std::fs::remove_dir_all(&git_dir);
    }

    // Verify it's a valid icon theme
    let index = dest.join("index.theme");
    if !index.exists() {
        // Some repos (KDE Breeze) use .theme.in template files instead of index.theme
        if let Some(theme_in) = find_theme_in_file(&dest) {
            std::fs::copy(&theme_in, &index)
                .map_err(|e| format!("Failed to create index.theme from template: {}", e))?;
        } else {
            // Check one level deep — theme may be inside a subdirectory
            let mut found = false;
            if let Ok(entries) = std::fs::read_dir(&dest) {
                for entry in entries.flatten() {
                    let sub = entry.path();
                    if !sub.is_dir() { continue; }
                    let sub_index = sub.join("index.theme");
                    let has_index = sub_index.exists();
                    // Also check for a valid .theme.in in the subdirectory.
                    // Resolve it once and reuse (find_theme_in_file does a full
                    // read_dir + parse of every candidate).
                    let theme_in = if has_index { None } else { find_theme_in_file(&sub) };

                    if has_index || theme_in.is_some() {
                        // If only .theme.in exists, create index.theme from it
                        if let Some(ref tin) = theme_in {
                            let _ = std::fs::copy(tin, &sub_index);
                        }
                        // Move subdirectory contents up
                        let tmp = install_dir.join(format!("{}-tmp", repo_name));
                        std::fs::rename(&sub, &tmp)
                            .map_err(|e| format!("Failed to reorganize: {}", e))?;
                        std::fs::remove_dir_all(&dest)
                            .map_err(|e| format!("Failed to clean up: {}", e))?;
                        std::fs::rename(&tmp, &dest)
                            .map_err(|e| format!("Failed to finalize: {}", e))?;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                let _ = std::fs::remove_dir_all(&dest);
                return Err("Repository does not contain a valid icon theme (no index.theme found)".into());
            }
        }
    }

    // Parse and return the pack info. If the resulting index.theme isn't a
    // valid icon theme, scan_all_packs would skip it (leaving the same stuck
    // "installed but unlisted" state) — so fail loudly and clean up instead of
    // falling back to the repo name and reporting a phantom success.
    let (name, comment) = match parse_index_theme(&dest.join("index.theme")) {
        Some(v) => v,
        None => {
            let _ = std::fs::remove_dir_all(&dest);
            return Err("Repository did not yield a valid icon theme (its index.theme has no [Icon Theme]/Name=). It may not be a freedesktop-style icon pack.".into());
        }
    };

    let has_scalable = dest.join("scalable").exists()
        || dest.join("apps").join("scalable").exists();

    let mut sample_icons = Vec::new();
    let semantic_map = semantic_to_freedesktop();
    for semantic in semantic_map.keys() {
        if sample_icons.len() >= 6 { break; }
        if resolve_icon(&dest, semantic).is_some() {
            sample_icons.push(semantic.to_string());
        }
    }

    let icon_count = count_icons_rough(&dest);

    // A newly installed pack must show up immediately, and any negative
    // resolutions cached while it was absent are now wrong.
    invalidate_caches();

    Ok(IconPack {
        id: repo_name,
        name,
        comment,
        path: dest.to_string_lossy().to_string(),
        source: "custom".to_string(),
        has_scalable,
        icon_count,
        sample_icons,
    })
}

/// Remove a custom-installed icon pack
pub fn remove_pack(pack_id: &str) -> Result<(), String> {
    let icon_packs = icon_packs_dir();
    let dest = PathBuf::from(&icon_packs).join(pack_id);
    if !dest.exists() {
        return Err(format!("Icon pack '{}' not found", pack_id));
    }
    // Safety: only allow removing from our managed directory
    if !dest.starts_with(&icon_packs) {
        return Err("Cannot remove system icon themes".into());
    }
    std::fs::remove_dir_all(&dest)
        .map_err(|e| format!("Failed to remove icon pack: {}", e))?;
    // The pack is gone from disk — drop the scan and every resolved path
    // that pointed into it, or we keep serving a deleted pack for the TTL.
    invalidate_caches();
    info!("Removed icon pack '{}'", pack_id);
    Ok(())
}

/// Get the MIME type for an icon file
pub fn icon_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("xpm") => "image/x-xpixmap",
        _ => "application/octet-stream",
    }
}

/// Get the list of all semantic icon names (for the frontend)
pub fn semantic_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = semantic_to_freedesktop().keys().copied().collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_map_complete() {
        let map = semantic_to_freedesktop();
        // Every entry should have at least one freedesktop name
        for (key, candidates) in &map {
            assert!(!candidates.is_empty(), "semantic icon '{}' has no candidates", key);
        }
    }

    #[test]
    fn test_icon_mime_types() {
        assert_eq!(icon_mime(Path::new("foo.svg")), "image/svg+xml");
        assert_eq!(icon_mime(Path::new("foo.png")), "image/png");
        assert_eq!(icon_mime(Path::new("foo.xpm")), "image/x-xpixmap");
    }

    #[test]
    fn test_parse_index_theme() {
        let dir = std::env::temp_dir().join("wolfstack-test-icons");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("index.theme"), "[Icon Theme]\nName=Test Theme\nComment=A test\n").unwrap();
        let result = parse_index_theme(&dir.join("index.theme"));
        assert_eq!(result, Some(("Test Theme".into(), "A test".into())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_find_theme_in_skips_fragment() {
        // Mirrors KDE Breeze's icons/ dir: a real theme template plus the
        // commonthemeinfo.theme.in fragment (no [Icon Theme]/Name=). The
        // fragment must NEVER be chosen — picking it produced an unparseable
        // index.theme and left the pack installed-but-unlisted.
        let dir = std::env::temp_dir().join(format!("wolfstack-test-themein-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("commonthemeinfo.theme.in"),
            "DisplayDepth=32\nDesktopDefault=48\n").unwrap();
        std::fs::write(dir.join("breeze.theme.in"),
            "[Icon Theme]\nName=Breeze\nComment=Breeze Team\n").unwrap();
        std::fs::write(dir.join("breeze-dark.theme.in"),
            "[Icon Theme]\nName=Breeze Dark\n").unwrap();
        let chosen = find_theme_in_file(&dir).expect("should find a valid theme template");
        assert_eq!(chosen.file_name().unwrap().to_string_lossy(), "breeze.theme.in",
            "must pick the valid non-dark theme, never the fragment");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
