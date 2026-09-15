// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Plugin system — load, manage, and serve plugins from /etc/wolfstack/plugins/
//!
//! Plugin directory structure:
//!   /etc/wolfstack/plugins/{id}/
//!     manifest.json    — plugin metadata
//!     web/plugin.js    — frontend code (injected into the SPA)
//!     web/plugin.css   — styles (optional)
//!     bin/handler       — standalone backend binary (optional, listens on api_port)

use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};

const PLUGINS_DIR: &str = "/etc/wolfstack/plugins";

/// Shared HTTP client for proxying UI requests through to loopback
/// plugin backends. Each proxied request used to build a fresh
/// `reqwest::Client` — one leaked pool per UI click.
static PLUGIN_PROXY_CLIENT: LazyLock<reqwest::Client> =
    LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub enterprise_only: bool,
    #[serde(default)]
    pub menu: Option<PluginMenu>,
    /// API prefix — requests to /api/plugins/{id}/* are proxied to this port
    #[serde(default)]
    pub api_port: Option<u16>,
    /// Optional: settings schema for a settings panel
    #[serde(default)]
    pub settings: Vec<PluginSetting>,
    /// Whether the plugin has a web/plugin.js file
    #[serde(default)]
    pub has_frontend: bool,
    /// Whether the plugin has a web/plugin.css file
    #[serde(default)]
    pub has_css: bool,
    /// Whether the plugin has a bin/handler binary
    #[serde(default)]
    pub has_backend: bool,
    /// Whether the plugin is currently enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMenu {
    /// Where in the nav: "datacenter", "server", or "settings"
    pub section: String,
    /// Display label
    pub label: String,
    /// View ID (used as page-{view} in the frontend)
    pub view: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSetting {
    pub id: String,
    pub label: String,
    #[serde(default = "default_text")]
    pub input_type: String,  // "text", "number", "password", "toggle", "select"
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,  // for select type
    #[serde(default)]
    pub description: String,
}

fn default_text() -> String { "text".into() }

/// Runtime plugin state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedPlugin {
    pub manifest: PluginManifest,
    pub path: String,
    #[serde(default)]
    pub status: String,  // "active", "stopped", "error", "disabled"
    #[serde(default)]
    pub error: Option<String>,
}

static PLUGINS: LazyLock<RwLock<Vec<LoadedPlugin>>> = LazyLock::new(|| {
    RwLock::new(scan_plugins())
});

/// Scan the plugins directory and load all valid manifests
fn scan_plugins() -> Vec<LoadedPlugin> {
    let mut plugins = Vec::new();
    let dir = std::path::Path::new(PLUGINS_DIR);
    if !dir.is_dir() { return plugins; }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return plugins,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }

        let manifest_path = path.join("manifest.json");
        if !manifest_path.exists() { continue; }

        match load_manifest(&manifest_path) {
            Ok(mut manifest) => {
                // Auto-detect available files
                manifest.has_frontend = path.join("web/plugin.js").exists();
                manifest.has_css = path.join("web/plugin.css").exists();
                manifest.has_backend = path.join("bin/handler").exists();

                // Plugins require an Enterprise license
                let status = if !manifest.enabled {
                    "disabled".to_string()
                } else if !crate::compat::platform_ready() {
                    "requires_license".to_string()
                } else {
                    "active".to_string()
                };

                plugins.push(LoadedPlugin {
                    manifest,
                    path: path.to_string_lossy().to_string(),
                    status,
                    error: None,
                });
            }
            Err(e) => {
                let id = path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                plugins.push(LoadedPlugin {
                    manifest: PluginManifest {
                        id: id.clone(),
                        name: id,
                        version: String::new(),
                        description: String::new(),
                        author: String::new(),
                        icon: String::new(),
                        enterprise_only: false,
                        menu: None,
                        api_port: None,
                        settings: Vec::new(),
                        has_frontend: false,
                        has_css: false,
                        has_backend: false,
                        enabled: false,
                    },
                    path: path.to_string_lossy().to_string(),
                    status: "error".to_string(),
                    error: Some(e),
                });
            }
        }
    }

    plugins.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
    plugins
}

fn load_manifest(path: &std::path::Path) -> Result<PluginManifest, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read manifest: {}", e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Invalid manifest JSON: {}", e))
}

/// Reload all plugins (called after install/uninstall)
pub fn reload() {
    let mut plugins = PLUGINS.write().unwrap();
    *plugins = scan_plugins();
    drop(plugins);
    start_all_backends();
}

/// Get all loaded plugins
pub fn list() -> Vec<LoadedPlugin> {
    PLUGINS.read().unwrap().clone()
}

/// Get a specific plugin by ID
pub fn get(id: &str) -> Option<LoadedPlugin> {
    PLUGINS.read().unwrap().iter().find(|p| p.manifest.id == id).cloned()
}

/// Get plugin file content (for serving JS/CSS)
pub fn read_file(plugin_id: &str, file_path: &str) -> Option<Vec<u8>> {
    let plugins = PLUGINS.read().unwrap();
    let plugin = plugins.iter().find(|p| p.manifest.id == plugin_id)?;

    // Security: only allow files under the plugin's web/ directory
    if file_path.contains("..") { return None; }

    let full_path = format!("{}/web/{}", plugin.path, file_path);
    std::fs::read(&full_path).ok()
}

/// Install a plugin from a URL (downloads and extracts to plugins dir)
pub fn install_from_url(url: &str) -> Result<String, String> {
    let _ = std::fs::create_dir_all(PLUGINS_DIR);

    // Stop any existing backend processes for plugins being reinstalled
    for plugin in list() {
        if plugin.manifest.has_backend {
            stop_backend(&plugin.manifest.id);
        }
    }

    // Download to temp file
    let tmp = format!("/tmp/wolfstack-plugin-{}.tar.gz",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    let output = std::process::Command::new("curl")
        .args(["-fsSL", "-o", &tmp, url])
        .output()
        .map_err(|e| format!("Download failed: {}", e))?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Download failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Extract to plugins dir
    let output = std::process::Command::new("tar")
        .args(["xzf", &tmp, "-C", PLUGINS_DIR])
        .output()
        .map_err(|e| format!("Extract failed: {}", e))?;

    let _ = std::fs::remove_file(&tmp);

    if !output.status.success() {
        return Err(format!("Extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    reload();
    Ok("Plugin installed successfully".to_string())
}

/// Uninstall a plugin by ID
pub fn uninstall(id: &str) -> Result<String, String> {
    let plugin = get(id).ok_or_else(|| format!("Plugin '{}' not found", id))?;
    std::fs::remove_dir_all(&plugin.path)
        .map_err(|e| format!("Failed to remove plugin: {}", e))?;
    reload();
    Ok(format!("Plugin '{}' uninstalled", id))
}

/// Enable/disable a plugin
pub fn set_enabled(id: &str, enabled: bool) -> Result<String, String> {
    let plugin = get(id).ok_or_else(|| format!("Plugin '{}' not found", id))?;
    let manifest_path = format!("{}/manifest.json", plugin.path);
    let mut manifest = plugin.manifest;
    manifest.enabled = enabled;
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    std::fs::write(&manifest_path, json)
        .map_err(|e| format!("Failed to write manifest: {}", e))?;
    reload();
    Ok(format!("Plugin '{}' {}", id, if enabled { "enabled" } else { "disabled" }))
}

/// Start all enabled plugin backends (called on startup and after reload)
pub fn start_all_backends() {
    let plugins = PLUGINS.read().unwrap().clone();
    for plugin in &plugins {
        if plugin.status == "active" && plugin.manifest.has_backend {
            if let Err(e) = start_backend(&plugin.manifest.id) {
                tracing::warn!("Failed to start plugin '{}' backend: {}", plugin.manifest.id, e);
            } else if let Some(port) = plugin.manifest.api_port {
                tracing::info!("Started plugin '{}' backend on port {}",
                    plugin.manifest.id, port);
            }
        }
    }
}

/// Stop a plugin's backend process (if running)
pub fn stop_backend(id: &str) {
    let plugin = match get(id) { Some(p) => p, None => return };
    if !plugin.manifest.has_backend { return; }
    let port = plugin.manifest.api_port.unwrap_or(0);
    if port == 0 { return; }

    // Kill any handler process listening on this port
    let _ = std::process::Command::new("sh")
        .args(["-c", &format!("fuser -k {}/tcp 2>/dev/null || pkill -f '{}/bin/handler'", port, plugin.path)])
        .status();

    // Give it a moment to die
    std::thread::sleep(std::time::Duration::from_millis(500));
    tracing::info!("Stopped plugin '{}' backend (port {})", id, port);
}

/// Start a plugin's backend binary (if it has one)
pub fn start_backend(id: &str) -> Result<(), String> {
    let plugin = get(id).ok_or_else(|| format!("Plugin '{}' not found", id))?;
    if !plugin.manifest.has_backend { return Ok(()); }

    let handler_path = format!("{}/bin/handler", plugin.path);
    let port = plugin.manifest.api_port.unwrap_or(0);
    if port == 0 { return Ok(()); }

    // Check if already running
    let check = std::process::Command::new("sh")
        .args(["-c", &format!("ss -tlnp | grep :{} | grep -q handler", port)])
        .status();
    if check.map(|s| s.success()).unwrap_or(false) {
        return Ok(());  // Already running
    }

    // Start in background
    let _ = std::process::Command::new(&handler_path)
        .env("PORT", port.to_string())
        .env("PLUGIN_DIR", &plugin.path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start plugin backend: {}", e))?;

    Ok(())
}

/// Proxy an API request to a plugin's backend
pub async fn proxy_request(
    plugin_id: &str,
    method: &str,
    sub_path: &str,
    body: Option<&[u8]>,
    headers: &[(String, String)],
) -> Result<(u16, String, Vec<u8>), String> {
    let plugin = get(plugin_id).ok_or_else(|| format!("Plugin '{}' not found", plugin_id))?;
    let port = plugin.manifest.api_port.ok_or("Plugin has no API port")?;

    // All plugins require an Enterprise license
    if !crate::compat::platform_ready() {
        return Err("Enterprise license required to use plugins".to_string());
    }

    let url = format!("http://127.0.0.1:{}/{}", port, sub_path.trim_start_matches('/'));

    let client = &*PLUGIN_PROXY_CLIENT;
    let mut req = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        _ => client.get(&url),
    };

    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }

    if let Some(body) = body {
        req = req.body(body.to_vec());
    }

    let resp = req.send().await.map_err(|e| format!("Plugin request failed: {}", e))?;
    let status = resp.status().as_u16();
    let content_type = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let body = resp.bytes().await.map_err(|e| format!("Failed to read response: {}", e))?;

    Ok((status, content_type, body.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_parse() {
        let json = r#"{
            "id": "test-plugin",
            "name": "Test Plugin",
            "version": "1.0.0",
            "description": "A test plugin",
            "icon": "🧪",
            "enterprise_only": true,
            "menu": {
                "section": "datacenter",
                "label": "Test",
                "view": "test-plugin"
            },
            "api_port": 9100,
            "settings": [
                {"id": "api_key", "label": "API Key", "input_type": "password"}
            ]
        }"#;

        let manifest: PluginManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.id, "test-plugin");
        assert!(manifest.enterprise_only);
        assert_eq!(manifest.menu.unwrap().view, "test-plugin");
        assert_eq!(manifest.api_port, Some(9100));
        assert_eq!(manifest.settings.len(), 1);
    }

    #[test]
    fn test_default_enabled() {
        let json = r#"{"id": "x", "name": "X"}"#;
        let m: PluginManifest = serde_json::from_str(json).unwrap();
        assert!(m.enabled);
    }
}
