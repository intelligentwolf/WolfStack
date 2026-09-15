// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Kubernetes Management — k3s/k8s cluster provisioning, resource management,
//! and application deployment via kubectl CLI integration.
//!
//! Supports multiple clusters (k3s, k8s, EKS, GKE, AKS) with per-cluster
//! kubeconfig files. All interactions go through `kubectl` CLI rather than
//! the Kubernetes API directly, keeping the dependency footprint small.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;

fn default_true() -> bool { true }
use tracing::{error, info, warn};

fn config_file() -> String { crate::paths::get().kubernetes_config }

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum K8sClusterType {
    K3s,
    K8s,
    MicroK8s,
    K0s,
    Rke2,
    Eks,
    Gke,
    Aks,
    Other,
}

impl std::fmt::Display for K8sClusterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::K3s => write!(f, "k3s"),
            Self::K8s => write!(f, "k8s"),
            Self::MicroK8s => write!(f, "microk8s"),
            Self::K0s => write!(f, "k0s"),
            Self::Rke2 => write!(f, "rke2"),
            Self::Eks => write!(f, "eks"),
            Self::Gke => write!(f, "gke"),
            Self::Aks => write!(f, "aks"),
            Self::Other => write!(f, "other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum K8sNodeRole {
    Server,
    Agent,
}

impl std::fmt::Display for K8sNodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server => write!(f, "server"),
            Self::Agent => write!(f, "agent"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sClusterNode {
    pub node_id: String,
    pub role: K8sNodeRole,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sCluster {
    pub id: String,
    pub name: String,
    pub kubeconfig_path: String,
    pub api_url: String,
    pub cluster_type: K8sClusterType,
    pub created_at: String,
    #[serde(default)]
    pub nodes: Vec<K8sClusterNode>,
    #[serde(default)]
    pub wolfnet_server: String,
    #[serde(default)]
    pub wolfnet_network: String,
    #[serde(default = "default_true")]
    pub wolfnet_auto_deploy: bool,
    #[serde(default)]
    pub wolfnet_routes: Vec<K8sWolfNetRoute>,
    /// The WolfStack node ID of the server node that hosts this K8s cluster.
    /// WolfNet routes and DNAT rules are applied on this node, not the UI node.
    #[serde(default)]
    pub owner_node_id: String,
}

// ─── Runtime Info (returned from kubectl) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNamespace {
    pub name: String,
    pub status: String,
    pub age: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sPod {
    pub name: String,
    pub namespace: String,
    pub status: String,
    pub ready: String,
    pub restarts: u32,
    pub age: String,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sDeployment {
    pub name: String,
    pub namespace: String,
    pub ready_replicas: u32,
    pub desired_replicas: u32,
    pub available: u32,
    pub age: String,
    #[serde(default)]
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sService {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub cluster_ip: String,
    #[serde(default)]
    pub external_ip: String,
    pub ports: String,
    pub age: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNode {
    pub name: String,
    pub status: String,
    pub roles: String,
    pub version: String,
    pub age: String,
    #[serde(default)]
    pub cpu_capacity: String,
    #[serde(default)]
    pub memory_capacity: String,
    #[serde(default)]
    pub cpu_usage: String,
    #[serde(default)]
    pub memory_usage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sClusterStatus {
    pub healthy: bool,
    pub nodes_ready: u32,
    pub nodes_total: u32,
    pub pods_running: u32,
    pub pods_total: u32,
    pub namespaces: u32,
    pub api_version: String,
}

// ─── WolfNet Route Types ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sWolfNetRoute {
    pub deployment_name: String,
    pub namespace: String,
    pub wolfnet_ip: String,
    pub port_mappings: Vec<K8sWolfNetPortMap>,
    /// InternalIP of a k8s node to DNAT traffic to (NodePort is cluster-wide)
    #[serde(default)]
    pub target_node_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sWolfNetPortMap {
    pub service_port: u16,
    pub node_port: u16,
    pub protocol: String,
}

// ─── Config ───

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct KubernetesConfig {
    #[serde(default)]
    pub clusters: Vec<K8sCluster>,
}


// ═══════════════════════════════════════════════
// ─── Config Persistence ───
// ═══════════════════════════════════════════════

pub fn load_config() -> KubernetesConfig {
    match fs::read_to_string(config_file()) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => KubernetesConfig::default(),
    }
}

pub fn save_config(config: &KubernetesConfig) -> Result<(), String> {
    let path = config_file();
    let dir = Path::new(&path).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize kubernetes config: {}", e))?;
    fs::write(&path, json)
        .map_err(|e| format!("Failed to write kubernetes config: {}", e))
}

// ═══════════════════════════════════════════════
// ─── Cluster CRUD ───
// ═══════════════════════════════════════════════

pub fn add_cluster(
    id: String,
    name: String,
    kubeconfig_path: String,
    api_url: String,
    cluster_type: K8sClusterType,
) -> Result<K8sCluster, String> {
    let mut config = load_config();

    if config.clusters.iter().any(|c| c.id == id) {
        return Err(format!("Cluster with id '{}' already exists", id));
    }

    let cluster = K8sCluster {
        id,
        name,
        kubeconfig_path,
        api_url,
        cluster_type,
        created_at: chrono::Utc::now().to_rfc3339(),
        nodes: Vec::new(),
        wolfnet_server: String::new(),
        wolfnet_network: String::new(),
        wolfnet_auto_deploy: true,
        wolfnet_routes: Vec::new(),
        owner_node_id: String::new(),
    };

    config.clusters.push(cluster.clone());
    save_config(&config)?;
    info!("Added Kubernetes cluster '{}'", cluster.name);
    Ok(cluster)
}

pub fn remove_cluster(id: &str) -> Result<(), String> {
    let mut config = load_config();
    let before = config.clusters.len();
    config.clusters.retain(|c| c.id != id);
    if config.clusters.len() == before {
        return Err(format!("Cluster '{}' not found", id));
    }
    save_config(&config)?;
    info!("Removed Kubernetes cluster '{}'", id);
    Ok(())
}

/// The canonical location the import handler writes a pasted kubeconfig to
/// (api::k8s_create_cluster). Used to recover a cluster whose stored path was
/// lost or points at a now-missing file.
fn canonical_kubeconfig_path(id: &str) -> String {
    format!("/etc/wolfstack/kubernetes/{}.yaml", id)
}

/// Repair a cluster whose `kubeconfig_path` is blank or points at a file that
/// no longer exists, by falling back to the canonical import location. Returns
/// true if it changed the path. Without this, such a cluster silently runs
/// kubectl with no config and hits kubectl's `localhost:8080` default — the
/// cluster shows the right API IP but every action "can't reach localhost:8080"
/// (HoXsan 2026-06-05). Self-healing means an already-broken cluster fixes
/// itself the next time it's loaded, as long as the kubeconfig file is still on
/// disk; if it isn't, the kubectl() guard returns a clear "re-import" error.
fn heal_cluster_kubeconfig(cluster: &mut K8sCluster) -> bool {
    let current_ok = !cluster.kubeconfig_path.trim().is_empty()
        && Path::new(&cluster.kubeconfig_path).is_file();
    if current_ok {
        return false;
    }
    let canonical = canonical_kubeconfig_path(&cluster.id);
    if canonical != cluster.kubeconfig_path && Path::new(&canonical).is_file() {
        cluster.kubeconfig_path = canonical;
        return true;
    }
    false
}

pub fn get_cluster(id: &str) -> Option<K8sCluster> {
    let mut config = load_config();
    let idx = config.clusters.iter().position(|c| c.id == id)?;
    if heal_cluster_kubeconfig(&mut config.clusters[idx]) {
        let healed = config.clusters[idx].clone();
        let _ = save_config(&config);
        info!("WolfKube: recovered kubeconfig path for cluster '{}' → {}", healed.id, healed.kubeconfig_path);
        return Some(healed);
    }
    Some(config.clusters[idx].clone())
}

pub fn list_clusters() -> Vec<K8sCluster> {
    let mut config = load_config();
    let mut changed = false;
    for c in &mut config.clusters {
        if heal_cluster_kubeconfig(c) { changed = true; }
    }
    if changed {
        let _ = save_config(&config);
    }
    config.clusters
}

// ═══════════════════════════════════════════════
// ─── kubectl Helper ───
// ═══════════════════════════════════════════════

/// Find the best kubectl binary on the system.
/// Tries: kubectl, k3s kubectl, microk8s kubectl, /usr/local/bin/kubectl
/// Public wrapper for console.rs to build kubectl commands
pub fn find_kubectl_pub() -> (&'static str, &'static [&'static str]) {
    find_kubectl()
}

fn find_kubectl() -> (&'static str, &'static [&'static str]) {
    // Check standalone kubectl first
    if Command::new("kubectl").arg("version").arg("--client")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
    {
        return ("kubectl", &[]);
    }
    // k3s ships its own kubectl
    if Command::new("k3s").arg("kubectl").arg("version").arg("--client")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
    {
        return ("k3s", &["kubectl"]);
    }
    // microk8s ships its own kubectl
    if Command::new("microk8s").arg("kubectl").arg("version").arg("--client")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
    {
        return ("microk8s", &["kubectl"]);
    }
    // Fallback to kubectl (will fail with a clear error if not found)
    ("kubectl", &[])
}

pub fn kubectl(kubeconfig: &str, args: &[&str]) -> Result<String, String> {
    // A blank or missing kubeconfig makes kubectl silently fall back to its
    // built-in default endpoint (http://localhost:8080), which then surfaces as
    // a baffling "connection to the server localhost:8080 was refused" — even
    // though the cluster shows the right API IP in the UI. That's never what we
    // want; fail with a clear, actionable error instead (HoXsan 2026-06-05).
    if kubeconfig.trim().is_empty() {
        return Err("No kubeconfig is configured for this cluster on this node. \
                    Re-import the cluster (paste its kubeconfig) so kubectl has a \
                    config to use — otherwise it falls back to its localhost:8080 \
                    default and can't reach your cluster.".to_string());
    }
    if !std::path::Path::new(kubeconfig).is_file() {
        return Err(format!(
            "Kubeconfig '{}' was not found on this node. If the cluster was \
             imported on a different node, run the action from that node, or \
             re-import the cluster here.", kubeconfig));
    }
    let (binary, prefix_args) = find_kubectl();
    let mut cmd = Command::new(binary);
    cmd.args(prefix_args);
    cmd.arg("--kubeconfig").arg(kubeconfig);
    cmd.args(args);

    let output = cmd.output()
        .map_err(|e| format!("Failed to execute kubectl (tried '{} {}'): {}. Is kubectl, k3s, or microk8s installed?", binary, prefix_args.join(" "), e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("kubectl command failed: {}", stderr);
        Err(stderr)
    }
}

/// Detect existing Kubernetes installations on this node.
/// Returns a list of detected clusters with their kubeconfig paths and types.
pub fn detect_existing_clusters() -> Vec<(String, String, K8sClusterType)> {
    let mut found = Vec::new();

    // k3s: kubeconfig at /etc/rancher/k3s/k3s.yaml
    if Path::new("/etc/rancher/k3s/k3s.yaml").exists() {
        found.push((
            "k3s (local)".to_string(),
            "/etc/rancher/k3s/k3s.yaml".to_string(),
            K8sClusterType::K3s,
        ));
    }

    // microk8s: config via `microk8s config`
    let microk8s_config = "/var/snap/microk8s/current/credentials/client.config";
    if Path::new(microk8s_config).exists() {
        found.push((
            "microk8s (local)".to_string(),
            microk8s_config.to_string(),
            K8sClusterType::MicroK8s,
        ));
    }

    // kubeadm / standard k8s: ~/.kube/config or /etc/kubernetes/admin.conf
    if Path::new("/etc/kubernetes/admin.conf").exists() {
        found.push((
            "kubernetes (local)".to_string(),
            "/etc/kubernetes/admin.conf".to_string(),
            K8sClusterType::K8s,
        ));
    }

    // k0s: kubeconfig generated via k0s kubeconfig admin
    if Path::new("/var/lib/k0s").exists() {
        // k0s stores data in /var/lib/k0s, kubeconfig via command
        if let Ok(output) = Command::new("k0s")
            .args(["kubeconfig", "admin"])
            .output()
            && output.status.success() {
                // Write kubeconfig to a known location
                let kc_path = "/etc/k0s/kubeconfig";
                let _ = fs::create_dir_all("/etc/k0s");
                let _ = fs::write(kc_path, &output.stdout);
                found.push((
                    "k0s (local)".to_string(),
                    kc_path.to_string(),
                    K8sClusterType::K0s,
                ));
            }
    }

    // RKE2: kubeconfig at /etc/rancher/rke2/rke2.yaml
    if Path::new("/etc/rancher/rke2/rke2.yaml").exists() {
        found.push((
            "rke2 (local)".to_string(),
            "/etc/rancher/rke2/rke2.yaml".to_string(),
            K8sClusterType::Rke2,
        ));
    }

    // User kubeconfig at /root/.kube/config (WolfStack runs as root)
    let home_kubeconfig = "/root/.kube/config";
    if Path::new(home_kubeconfig).exists() {
        found.push((
            "kubernetes (~/.kube/config)".to_string(),
            home_kubeconfig.to_string(),
            K8sClusterType::K8s,
        ));
    }

    found
}

// ═══════════════════════════════════════════════
// ─── Provisioning ───
// ═══════════════════════════════════════════════

/// Generate a bash script that installs k3s server on a node.
/// The script installs k3s, waits for it to be ready, and prints the join token.
pub fn provision_k3s_server(node_address: &str, cluster_name: &str) -> Result<String, String> {
    info!(
        "Generating k3s server provisioning script for {} (cluster: {})",
        node_address, cluster_name
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Installing k3s server on {node_address} for cluster '{cluster_name}' ==="

# Install dependencies
if ! command -v curl &>/dev/null; then
    echo "Installing curl..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl
    elif command -v yum &>/dev/null; then
        yum install -y -q curl
    elif command -v zypper &>/dev/null; then
        zypper install -y curl
    else
        echo "ERROR: curl is not installed and no supported package manager found"
        exit 1
    fi
fi

# Build TLS SAN list — include the configured address, hostname, and all IPs
TLS_SANS="--tls-san {node_address}"
TLS_SANS="$TLS_SANS --tls-san $(hostname)"
TLS_SANS="$TLS_SANS --tls-san $(hostname -f 2>/dev/null || hostname)"
for IP in $(hostname -I 2>/dev/null); do TLS_SANS="$TLS_SANS --tls-san $IP"; done

# Install k3s server
curl -sfL https://get.k3s.io | sh -s - server $TLS_SANS

# Wait for k3s to be ready
echo "Waiting for k3s to be ready..."
for i in $(seq 1 60); do
    if kubectl get nodes &>/dev/null; then
        echo "k3s is ready!"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: k3s failed to start within 60 seconds"
        exit 1
    fi
    sleep 1
done

# Display connection info
echo ""
echo "=== k3s Server Installed Successfully ==="
echo "Kubeconfig: /etc/rancher/k3s/k3s.yaml"
echo "Join token: $(cat /var/lib/rancher/k3s/server/node-token)"
echo "API URL: https://{node_address}:6443"
echo ""
echo "To add agent nodes, run:"
echo "  curl -sfL https://get.k3s.io | K3S_URL=https://{node_address}:6443 K3S_TOKEN=<token> sh -s - agent"
"#,
        node_address = node_address,
        cluster_name = cluster_name,
    );

    Ok(script)
}

/// Generate a bash script that joins a node to a k3s cluster as an agent.
pub fn provision_k3s_agent(
    node_address: &str,
    server_url: &str,
    token: &str,
) -> Result<String, String> {
    info!(
        "Generating k3s agent provisioning script for {} (server: {})",
        node_address, server_url
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Joining {node_address} as k3s agent to {server_url} ==="

# Install dependencies
if ! command -v curl &>/dev/null; then
    echo "Installing curl..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl
    elif command -v yum &>/dev/null; then
        yum install -y -q curl
    elif command -v zypper &>/dev/null; then
        zypper install -y curl
    else
        echo "ERROR: curl is not installed and no supported package manager found"
        exit 1
    fi
fi

# Install k3s agent
curl -sfL https://get.k3s.io | K3S_URL={server_url} K3S_TOKEN={token} sh -s - agent

# Wait for the agent to register
echo "Waiting for k3s agent to register..."
sleep 5

echo ""
echo "=== k3s Agent Installed Successfully ==="
echo "Node {node_address} has joined the cluster as an agent."
echo "Check status on the server with: kubectl get nodes"
"#,
        node_address = node_address,
        server_url = server_url,
        token = token,
    );

    Ok(script)
}

/// Read the k3s join token from a server node.
/// This reads `/var/lib/rancher/k3s/server/node-token` via the local filesystem
/// or falls back to using kubectl to read the node-token secret.
pub fn get_k3s_token(kubeconfig: &str) -> Result<String, String> {
    // Try reading the token file directly (works if running on the server node)
    let token_path = "/var/lib/rancher/k3s/server/node-token";
    if let Ok(token) = fs::read_to_string(token_path) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    // Fall back to kubectl — read the k3s token from the node
    warn!("Could not read k3s token file directly, trying kubectl");
    let output = kubectl(
        kubeconfig,
        &[
            "get",
            "secret",
            "-n",
            "kube-system",
            "k3s-serving",
            "-o",
            "jsonpath={.data.token}",
        ],
    )?;

    if output.is_empty() {
        Err("k3s join token not found".to_string())
    } else {
        Ok(output.trim().to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── MicroK8s Provisioning ───
// ═══════════════════════════════════════════════

/// Generate a bash script that installs MicroK8s on a node.
pub fn provision_microk8s_server(node_address: &str, cluster_name: &str) -> Result<String, String> {
    info!(
        "Generating MicroK8s provisioning script for {} (cluster: {})",
        node_address, cluster_name
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Installing MicroK8s on {node_address} for cluster '{cluster_name}' ==="

# Install snapd if not present
if ! command -v snap &>/dev/null; then
    echo "Installing snapd..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq snapd
    elif command -v dnf &>/dev/null; then
        dnf install -y -q snapd
        systemctl enable --now snapd.socket
        # snapd needs a symlink on some distros
        ln -sf /var/lib/snapd/snap /snap 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y -q epel-release
        yum install -y -q snapd
        systemctl enable --now snapd.socket
        ln -sf /var/lib/snapd/snap /snap 2>/dev/null || true
    elif command -v zypper &>/dev/null; then
        zypper install -y snapd
        systemctl enable --now snapd.socket
        ln -sf /var/lib/snapd/snap /snap 2>/dev/null || true
    else
        echo "ERROR: snapd is not installed and no supported package manager found"
        exit 1
    fi
    # Wait for snapd to be ready
    echo "Waiting for snapd to initialize..."
    sleep 5
    snap wait system seed.loaded 2>/dev/null || sleep 10
fi

# Install MicroK8s
snap install microk8s --classic

# Wait for MicroK8s to be ready
echo "Waiting for MicroK8s to be ready..."
microk8s status --wait-ready --timeout 120

# Enable essential addons
microk8s enable dns storage

echo ""
echo "=== MicroK8s Installed Successfully ==="
echo "Kubeconfig: /var/snap/microk8s/current/credentials/client.config"
echo "To add nodes, run: microk8s add-node"
"#,
        node_address = node_address,
        cluster_name = cluster_name,
    );

    Ok(script)
}

/// Generate a bash script that joins a node to a MicroK8s cluster.
pub fn provision_microk8s_agent(join_url: &str) -> Result<String, String> {
    info!("Generating MicroK8s agent join script");

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Joining MicroK8s cluster ==="

# Install snapd if not present
if ! command -v snap &>/dev/null; then
    echo "Installing snapd..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq snapd
    elif command -v dnf &>/dev/null; then
        dnf install -y -q snapd
        systemctl enable --now snapd.socket
        ln -sf /var/lib/snapd/snap /snap 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y -q epel-release
        yum install -y -q snapd
        systemctl enable --now snapd.socket
        ln -sf /var/lib/snapd/snap /snap 2>/dev/null || true
    elif command -v zypper &>/dev/null; then
        zypper install -y snapd
        systemctl enable --now snapd.socket
        ln -sf /var/lib/snapd/snap /snap 2>/dev/null || true
    else
        echo "ERROR: snapd is not installed and no supported package manager found"
        exit 1
    fi
    echo "Waiting for snapd to initialize..."
    sleep 5
    snap wait system seed.loaded 2>/dev/null || sleep 10
fi

# Install MicroK8s if not present
if ! command -v microk8s &>/dev/null; then
    snap install microk8s --classic
    microk8s status --wait-ready --timeout 120
fi

# Join the cluster
{join_url}

echo "=== MicroK8s node joined successfully ==="
"#,
        join_url = join_url,
    );

    Ok(script)
}

/// Get the MicroK8s add-node command from a server node.
pub fn get_microk8s_join_command() -> Result<String, String> {
    let output = Command::new("microk8s")
        .args(["add-node", "--token-ttl", "3600"])
        .output()
        .map_err(|e| format!("Failed to run microk8s add-node: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        // Extract the "microk8s join ..." line
        if let Some(join_line) = stdout.lines().find(|l| l.trim().starts_with("microk8s join")) {
            Ok(join_line.trim().to_string())
        } else {
            Ok(stdout)
        }
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── kubeadm Provisioning ───
// ═══════════════════════════════════════════════

/// Generate a bash script that installs Kubernetes via kubeadm on a node.
pub fn provision_kubeadm_server(node_address: &str, cluster_name: &str) -> Result<String, String> {
    info!(
        "Generating kubeadm provisioning script for {} (cluster: {})",
        node_address, cluster_name
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Installing Kubernetes (kubeadm) on {node_address} for cluster '{cluster_name}' ==="

# Disable swap (required by kubeadm)
swapoff -a
sed -i '/swap/d' /etc/fstab

# Enable kernel modules
modprobe br_netfilter overlay
cat > /etc/modules-load.d/k8s.conf <<MODULES
br_netfilter
overlay
MODULES

cat > /etc/sysctl.d/k8s.conf <<SYSCTL
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
SYSCTL
sysctl --system

# Detect package manager and install dependencies
if command -v apt-get &>/dev/null; then
    export PKG_MGR=apt
    apt-get update -qq
    apt-get install -y -qq containerd apt-transport-https ca-certificates curl gpg

    # Set up containerd
    mkdir -p /etc/containerd
    containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    systemctl restart containerd
    systemctl enable containerd

    # Add Kubernetes apt repo
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' > /etc/apt/sources.list.d/kubernetes.list
    apt-get update -qq
    apt-get install -y -qq kubelet kubeadm kubectl
    apt-mark hold kubelet kubeadm kubectl

elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
    export PKG_MGR=rpm
    PKG_CMD=$(command -v dnf &>/dev/null && echo "dnf" || echo "yum")

    $PKG_CMD install -y -q containerd curl

    # Set up containerd
    mkdir -p /etc/containerd
    containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    systemctl restart containerd
    systemctl enable containerd

    # Add Kubernetes yum repo
    cat > /etc/yum.repos.d/kubernetes.repo <<REPO
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.31/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.31/rpm/repodata/repomd.xml.key
REPO
    $PKG_CMD install -y -q kubelet kubeadm kubectl

elif command -v zypper &>/dev/null; then
    export PKG_MGR=zypper

    zypper install -y containerd curl

    mkdir -p /etc/containerd
    containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    systemctl restart containerd
    systemctl enable containerd

    zypper addrepo -G https://pkgs.k8s.io/core:/stable:/v1.31/rpm/ kubernetes
    zypper install -y kubelet kubeadm kubectl
else
    echo "ERROR: No supported package manager found (apt, dnf, yum, zypper)"
    exit 1
fi

systemctl enable kubelet

# Initialize cluster
kubeadm init --apiserver-advertise-address={node_address} --pod-network-cidr=10.244.0.0/16

# Set up kubeconfig
export KUBECONFIG=/etc/kubernetes/admin.conf
mkdir -p /root/.kube
cp /etc/kubernetes/admin.conf /root/.kube/config

# Install Flannel CNI
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml

# Wait for node to be ready
echo "Waiting for node to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s

echo ""
echo "=== Kubernetes (kubeadm) Installed Successfully ==="
echo "Kubeconfig: /etc/kubernetes/admin.conf"
echo "Join command: $(kubeadm token create --print-join-command)"
"#,
        node_address = node_address,
        cluster_name = cluster_name,
    );

    Ok(script)
}

/// Generate a bash script that joins a node to a kubeadm cluster as a worker.
pub fn provision_kubeadm_agent(join_command: &str) -> Result<String, String> {
    info!("Generating kubeadm agent join script");

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Joining Kubernetes cluster as worker node ==="

# Disable swap
swapoff -a
sed -i '/swap/d' /etc/fstab

# Enable kernel modules
modprobe br_netfilter overlay
cat > /etc/modules-load.d/k8s.conf <<MODULES
br_netfilter
overlay
MODULES

cat > /etc/sysctl.d/k8s.conf <<SYSCTL
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
SYSCTL
sysctl --system

# Detect package manager and install dependencies
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq containerd apt-transport-https ca-certificates curl gpg

    mkdir -p /etc/containerd
    containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    systemctl restart containerd
    systemctl enable containerd

    mkdir -p /etc/apt/keyrings
    curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' > /etc/apt/sources.list.d/kubernetes.list
    apt-get update -qq
    apt-get install -y -qq kubelet kubeadm
    apt-mark hold kubelet kubeadm

elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
    PKG_CMD=$(command -v dnf &>/dev/null && echo "dnf" || echo "yum")
    $PKG_CMD install -y -q containerd curl

    mkdir -p /etc/containerd
    containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    systemctl restart containerd
    systemctl enable containerd

    cat > /etc/yum.repos.d/kubernetes.repo <<REPO
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.31/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.31/rpm/repodata/repomd.xml.key
REPO
    $PKG_CMD install -y -q kubelet kubeadm

elif command -v zypper &>/dev/null; then
    zypper install -y containerd curl

    mkdir -p /etc/containerd
    containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    systemctl restart containerd
    systemctl enable containerd

    zypper addrepo -G https://pkgs.k8s.io/core:/stable:/v1.31/rpm/ kubernetes
    zypper install -y kubelet kubeadm
else
    echo "ERROR: No supported package manager found (apt, dnf, yum, zypper)"
    exit 1
fi

systemctl enable kubelet

# Join the cluster
{join_command}

echo "=== Node joined the cluster successfully ==="
"#,
        join_command = join_command,
    );

    Ok(script)
}

/// Get the kubeadm join command from a server node.
pub fn get_kubeadm_join_command() -> Result<String, String> {
    let output = Command::new("kubeadm")
        .args(["token", "create", "--print-join-command"])
        .output()
        .map_err(|e| format!("Failed to run kubeadm token create: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── k0s Provisioning ───
// ═══════════════════════════════════════════════

/// Generate a bash script that installs k0s controller on a node.
pub fn provision_k0s_server(node_address: &str, cluster_name: &str) -> Result<String, String> {
    info!(
        "Generating k0s controller provisioning script for {} (cluster: {})",
        node_address, cluster_name
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Installing k0s controller on {node_address} for cluster '{cluster_name}' ==="

# Install dependencies
if ! command -v curl &>/dev/null; then
    echo "Installing curl..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl
    elif command -v yum &>/dev/null; then
        yum install -y -q curl
    elif command -v zypper &>/dev/null; then
        zypper install -y curl
    else
        echo "ERROR: curl is not installed and no supported package manager found"
        exit 1
    fi
fi

# Install k0s
curl -sSLf https://get.k0s.sh | sh

# Create minimal config with TLS SANs for remote access
mkdir -p /etc/k0s
{{
echo "apiVersion: k0s.k0sproject.io/v1beta1"
echo "kind: ClusterConfig"
echo "spec:"
echo "  api:"
echo "    sans:"
echo "      - {node_address}"
echo "      - $(hostname)"
echo "      - $(hostname -f 2>/dev/null || hostname)"
for IP in $(hostname -I 2>/dev/null); do echo "      - $IP"; done
}} > /etc/k0s/k0s.yaml

# Install and start as controller with worker capabilities
k0s install controller --single --config /etc/k0s/k0s.yaml

# Start the service
k0s start

# Wait for k0s to be ready
echo "Waiting for k0s to be ready..."
for i in $(seq 1 90); do
    if k0s kubectl get nodes &>/dev/null; then
        echo "k0s is ready!"
        break
    fi
    if [ "$i" -eq 90 ]; then
        echo "ERROR: k0s failed to start within 90 seconds"
        exit 1
    fi
    sleep 1
done

# Generate kubeconfig
mkdir -p /root/.kube
k0s kubeconfig admin > /root/.kube/config 2>/dev/null || true

echo ""
echo "=== k0s Controller Installed Successfully ==="
echo "Kubeconfig: k0s kubeconfig admin"
echo "To add workers, generate a join token: k0s token create --role=worker"
"#,
        node_address = node_address,
        cluster_name = cluster_name,
    );

    Ok(script)
}

/// Generate a bash script that joins a node to a k0s cluster as a worker.
pub fn provision_k0s_agent(token: &str) -> Result<String, String> {
    info!("Generating k0s worker join script");

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Joining k0s cluster as worker node ==="

# Install dependencies
if ! command -v curl &>/dev/null; then
    echo "Installing curl..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl
    elif command -v yum &>/dev/null; then
        yum install -y -q curl
    elif command -v zypper &>/dev/null; then
        zypper install -y curl
    else
        echo "ERROR: curl is not installed and no supported package manager found"
        exit 1
    fi
fi

# Install k0s
curl -sSLf https://get.k0s.sh | sh

# Write join token
mkdir -p /etc/k0s
cat > /etc/k0s/worker-token <<'TOKEN'
{token}
TOKEN

# Install and start as worker
k0s install worker --token-file /etc/k0s/worker-token
k0s start

echo "=== k0s worker joined successfully ==="
"#,
        token = token,
    );

    Ok(script)
}

/// Get the k0s worker join token from a controller node.
pub fn get_k0s_join_token() -> Result<String, String> {
    let output = Command::new("k0s")
        .args(["token", "create", "--role=worker"])
        .output()
        .map_err(|e| format!("Failed to run k0s token create: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ═══════════════════════════════════════════════
// ─── RKE2 Provisioning ───
// ═══════════════════════════════════════════════

/// Generate a bash script that installs RKE2 server on a node.
pub fn provision_rke2_server(node_address: &str, cluster_name: &str) -> Result<String, String> {
    info!(
        "Generating RKE2 server provisioning script for {} (cluster: {})",
        node_address, cluster_name
    );

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Installing RKE2 server on {node_address} for cluster '{cluster_name}' ==="

# Install dependencies
if ! command -v curl &>/dev/null; then
    echo "Installing curl..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl
    elif command -v yum &>/dev/null; then
        yum install -y -q curl
    elif command -v zypper &>/dev/null; then
        zypper install -y curl
    else
        echo "ERROR: curl is not installed and no supported package manager found"
        exit 1
    fi
fi

# Install RKE2 server
curl -sfL https://get.rke2.io | sh -

# Configure TLS SAN for remote access — include address, hostname, and all IPs
mkdir -p /etc/rancher/rke2
{{
echo "tls-san:"
echo "  - {node_address}"
echo "  - $(hostname)"
echo "  - $(hostname -f 2>/dev/null || hostname)"
for IP in $(hostname -I 2>/dev/null); do echo "  - $IP"; done
}} > /etc/rancher/rke2/config.yaml

# Enable and start RKE2
systemctl enable rke2-server.service
systemctl start rke2-server.service

# Wait for RKE2 to be ready
echo "Waiting for RKE2 to be ready..."
for i in $(seq 1 120); do
    if /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes &>/dev/null; then
        echo "RKE2 is ready!"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "ERROR: RKE2 failed to start within 120 seconds"
        exit 1
    fi
    sleep 1
done

# Set up kubectl access
mkdir -p /root/.kube
cp /etc/rancher/rke2/rke2.yaml /root/.kube/config
chmod 600 /root/.kube/config

# Add RKE2 bins to PATH
echo 'export PATH=$PATH:/var/lib/rancher/rke2/bin' >> /root/.bashrc
export PATH=$PATH:/var/lib/rancher/rke2/bin

echo ""
echo "=== RKE2 Server Installed Successfully ==="
echo "Kubeconfig: /etc/rancher/rke2/rke2.yaml"
echo "Join token: $(cat /var/lib/rancher/rke2/server/node-token)"
echo "API URL: https://{node_address}:9345"
"#,
        node_address = node_address,
        cluster_name = cluster_name,
    );

    Ok(script)
}

/// Generate a bash script that joins a node to an RKE2 cluster as an agent.
pub fn provision_rke2_agent(server_url: &str, token: &str) -> Result<String, String> {
    info!("Generating RKE2 agent join script");

    let script = format!(
        r#"#!/bin/bash
set -euo pipefail

echo "=== Joining RKE2 cluster as agent node ==="

# Install dependencies
if ! command -v curl &>/dev/null; then
    echo "Installing curl..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v dnf &>/dev/null; then
        dnf install -y -q curl
    elif command -v yum &>/dev/null; then
        yum install -y -q curl
    elif command -v zypper &>/dev/null; then
        zypper install -y curl
    else
        echo "ERROR: curl is not installed and no supported package manager found"
        exit 1
    fi
fi

# Install RKE2 agent
curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="agent" sh -

# Configure RKE2 agent
mkdir -p /etc/rancher/rke2
cat > /etc/rancher/rke2/config.yaml <<CONFIG
server: {server_url}
token: {token}
CONFIG

# Enable and start RKE2 agent
systemctl enable rke2-agent.service
systemctl start rke2-agent.service

echo "=== RKE2 agent joined successfully ==="
"#,
        server_url = server_url,
        token = token,
    );

    Ok(script)
}

/// Get the RKE2 join token from a server node.
pub fn get_rke2_join_token() -> Result<String, String> {
    let token_path = "/var/lib/rancher/rke2/server/node-token";
    match fs::read_to_string(token_path) {
        Ok(token) => {
            let token = token.trim().to_string();
            if token.is_empty() {
                Err("RKE2 token file is empty".to_string())
            } else {
                Ok(token)
            }
        }
        Err(e) => Err(format!("Failed to read RKE2 token: {}", e)),
    }
}

// ═══════════════════════════════════════════════
// ─── WolfNet Integration ───
// ═══════════════════════════════════════════════

/// Get WolfNet status for all nodes in a k8s cluster.
/// Matches k8s node hostnames against WolfNet peers and the local server
/// to find their WolfNet IPs. No DaemonSet needed — WolfNet runs on the
/// host servers, and k8s services are accessible via NodePort on WolfNet IPs.
pub fn get_wolfnet_node_status(kubeconfig: &str) -> serde_json::Value {
    let k8s_nodes = get_nodes(kubeconfig);
    let wolfnet_status = crate::networking::get_wolfnet_status();
    let local_hostname = hostname::get().unwrap_or_default().to_string_lossy().to_string();
    let local_short = local_hostname.split('.').next().unwrap_or(&local_hostname).to_lowercase();

    // Get full node JSON to extract InternalIP addresses for matching
    let node_ips: std::collections::HashMap<String, String> = kubectl(kubeconfig, &["get", "nodes", "-o", "json"])
        .ok()
        .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
        .and_then(|v| v["items"].as_array().map(|items| {
            items.iter().filter_map(|item| {
                let name = item["metadata"]["name"].as_str()?.to_lowercase();
                let ip = item["status"]["addresses"].as_array()
                    .and_then(|addrs| addrs.iter()
                        .find(|a| a["type"].as_str() == Some("InternalIP"))
                        .and_then(|a| a["address"].as_str()))
                    .map(|s| s.to_string())?;
                Some((name, ip))
            }).collect()
        }))
        .unwrap_or_default();

    let mut node_info = Vec::new();

    for node in &k8s_nodes {
        let node_name_lower = node.name.to_lowercase();
        let node_short = node_name_lower.split('.').next().unwrap_or(&node_name_lower);
        let node_internal_ip = node_ips.get(&node_name_lower);

        // Check if this node is the local server
        let mut wolfnet_ip = None;
        let mut connected = false;

        if node_short == local_short || node_name_lower == local_hostname.to_lowercase() {
            // This k8s node is the local server
            if let Some(ref ip) = wolfnet_status.ip {
                wolfnet_ip = Some(ip.split('/').next().unwrap_or(ip).to_string());
                connected = wolfnet_status.running;
            }
        } else {
            // Check against WolfNet peers by hostname AND by IP
            for peer in &wolfnet_status.peers {
                let peer_name_lower = peer.name.to_lowercase();
                let peer_short = peer_name_lower.split('.').next().unwrap_or(&peer_name_lower);

                // Extract the real IP from peer endpoint (format: "host:port")
                let peer_endpoint_ip = peer.endpoint.split(':').next().unwrap_or("");

                let hostname_match = peer_short == node_short || peer_name_lower == node_name_lower;
                let ip_match = !peer_endpoint_ip.is_empty()
                    && node_internal_ip.is_some_and(|nip| nip == peer_endpoint_ip);

                if hostname_match || ip_match {
                    if !peer.ip.is_empty() {
                        wolfnet_ip = Some(peer.ip.split('/').next().unwrap_or(&peer.ip).to_string());
                        connected = peer.connected;
                    }
                    break;
                }
            }
        }

        node_info.push(serde_json::json!({
            "name": node.name,
            "status": node.status,
            "roles": node.roles,
            "wolfnet_ip": wolfnet_ip,
            "connected": connected,
        }));
    }

    let all_have_wolfnet = !node_info.is_empty() && node_info.iter().all(|n| !n["wolfnet_ip"].is_null());

    serde_json::json!({
        "wolfnet_installed": wolfnet_status.installed,
        "wolfnet_running": wolfnet_status.running,
        "local_ip": wolfnet_status.ip.as_deref().map(|ip| ip.split('/').next().unwrap_or(ip)),
        "nodes": node_info,
        "all_nodes_have_wolfnet": all_have_wolfnet,
    })
}

/// Get NodePort assignments for a k8s Service.
fn get_service_node_ports(kubeconfig: &str, name: &str, namespace: &str) -> Vec<K8sWolfNetPortMap> {
    let output = match kubectl(kubeconfig, &["get", "service", name, "-n", namespace, "-o", "json"]) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    json["spec"]["ports"].as_array()
        .map(|ports| ports.iter().filter_map(|p| {
            let service_port = p["port"].as_u64()? as u16;
            let node_port = p["nodePort"].as_u64()? as u16;
            let protocol = p["protocol"].as_str().unwrap_or("TCP").to_string();
            Some(K8sWolfNetPortMap { service_port, node_port, protocol })
        }).collect())
        .unwrap_or_default()
}

/// Find the next available WolfNet IP that doesn't conflict with any existing
/// allocations (containers, VMs, WolfRun, k8s routes, peers, or live IPs).
fn find_available_k8s_wolfnet_ip(config: &KubernetesConfig) -> Option<String> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();

    // All container/VM/WolfRun used IPs (Docker, LXC, VMs, WolfRun VIPs)
    for ip in crate::containers::wolfnet_used_ips() {
        used.insert(ip);
    }

    // All k8s-allocated WolfNet routes across all clusters
    for cluster in &config.clusters {
        for route in &cluster.wolfnet_routes {
            used.insert(route.wolfnet_ip.clone());
        }
    }

    // WolfNet config file: node IPs and peer IPs
    if let Ok(content) = fs::read_to_string("/etc/wolfnet/config.toml") {
        for line in content.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("address") || trimmed.starts_with("allowed_ip")) && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1) {
                    let ip = val.trim().trim_matches('"').trim().to_string();
                    if !ip.is_empty() { used.insert(ip); }
                }
        }
    }

    // Live IPs on wolfnet0 interface
    if let Ok(output) = Command::new("ip").args(["addr", "show", "wolfnet0"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ")
                && let Some(cidr) = trimmed.split_whitespace().nth(1) {
                    let ip = cidr.split('/').next().unwrap_or("").to_string();
                    if !ip.is_empty() { used.insert(ip); }
                }
        }
    }

    // WolfRun service VIPs and route cache
    if let Ok(content) = fs::read_to_string(&crate::paths::get().wolfrun_services)
        && let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
            for svc in &services {
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str())
                    && !vip.is_empty() { used.insert(vip.to_string()); }
                if let Some(instances) = svc.get("instances").and_then(|v| v.as_array()) {
                    for inst in instances {
                        if let Some(ip) = inst.get("wolfnet_ip").and_then(|v| v.as_str())
                            && !ip.is_empty() { used.insert(ip.to_string()); }
                    }
                }
            }
        }

    // Route cache
    if let Ok(content) = fs::read_to_string("/var/run/wolfnet/routes.json")
        && let Ok(routes) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
            for ip in routes.keys() {
                used.insert(ip.clone());
            }
        }

    let prefix = crate::containers::wolfnet_subnet_prefix()?;

    // Reserve gateway and broadcast
    used.insert(format!("{}.1", prefix));
    used.insert(format!("{}.255", prefix));

    // Find next available in the WolfNet /24 range
    for i in 2..=254u8 {
        let candidate = format!("{}.{}", prefix, i);
        if !used.contains(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Allocate a WolfNet IP for a k8s deployment and set up iptables routing.
/// The WolfNet IP is added as a secondary address on wolfnet0 and iptables
/// DNAT rules forward traffic to a k8s node's NodePort.
pub fn allocate_wolfnet_route(cluster_id: &str, deployment_name: &str, namespace: &str) -> Result<K8sWolfNetRoute, String> {
    let config = load_config();
    let cluster = config.clusters.iter().find(|c| c.id == cluster_id)
        .ok_or_else(|| format!("Cluster '{}' not found", cluster_id))?;

    // Return existing route if already allocated
    if let Some(existing) = cluster.wolfnet_routes.iter().find(|r| r.deployment_name == deployment_name && r.namespace == namespace) {
        return Ok(existing.clone());
    }

    // Get NodePort assignments from the k8s Service
    let kubeconfig = cluster.kubeconfig_path.clone();
    let port_mappings = get_service_node_ports(&kubeconfig, deployment_name, namespace);
    if port_mappings.is_empty() {
        return Err("No NodePort service found for this deployment. Deploy the app first, and ensure it exposes ports.".to_string());
    }

    // Find a Ready k8s node to DNAT traffic to (NodePort is cluster-wide)
    let target_node_ip = find_k8s_node_ip(&kubeconfig)
        .ok_or_else(|| "No Ready k8s node found with an InternalIP".to_string())?;

    // Find next available WolfNet IP
    let wolfnet_ip = find_available_k8s_wolfnet_ip(&config)
        .ok_or_else(|| "No available WolfNet IPs in the WolfNet subnet".to_string())?;

    // Add IP as secondary address on wolfnet0
    let add_result = Command::new("ip")
        .args(["addr", "add", &format!("{}/32", wolfnet_ip), "dev", "wolfnet0"])
        .output();
    if let Err(e) = add_result {
        return Err(format!("Failed to add IP to wolfnet0: {}. Is WolfNet running?", e));
    }

    // Add explicit local route so the kernel knows this IP is ours
    // (matches how Docker containers get `ip route replace X/32 dev docker0`)
    let _ = Command::new("ip")
        .args(["route", "replace", &format!("{}/32", wolfnet_ip), "dev", "wolfnet0"])
        .output();

    // Enable forwarding so DNAT packets can be routed
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();

    // Set up iptables rules via k3s KUBE-SVC chains (not PREROUTING DNAT)
    apply_kube_svc_rules(&wolfnet_ip, &kubeconfig, deployment_name, namespace, &port_mappings);

    // Register route in WolfNet so other peers can reach this IP
    let wn_status = crate::networking::get_wolfnet_status();
    if let Some(ref local_wn_ip) = wn_status.ip {
        let local_ip = local_wn_ip.split('/').next().unwrap_or(local_wn_ip).to_string();
        let mut routes = std::collections::HashMap::new();
        routes.insert(wolfnet_ip.clone(), local_ip);
        crate::containers::update_wolfnet_routes(&routes);
    }

    let route = K8sWolfNetRoute {
        deployment_name: deployment_name.to_string(),
        namespace: namespace.to_string(),
        wolfnet_ip: wolfnet_ip.clone(),
        port_mappings,
        target_node_ip: target_node_ip.clone(),
    };

    // Re-load config for mutable update (avoids borrow conflict)
    let mut config = load_config();
    if let Some(cluster) = config.clusters.iter_mut().find(|c| c.id == cluster_id) {
        cluster.wolfnet_routes.push(route.clone());
    }
    save_config(&config)?;

    info!("Allocated WolfNet IP {} → {}(NodePort) for k8s deployment '{}'", wolfnet_ip, target_node_ip, deployment_name);
    Ok(route)
}

/// Find the InternalIP of the first Ready k8s node.
fn find_k8s_node_ip(kubeconfig: &str) -> Option<String> {
    let output = kubectl(kubeconfig, &["get", "nodes", "-o", "json"]).ok()?;
    let json: serde_json::Value = serde_json::from_str(&output).ok()?;
    json["items"].as_array()?.iter().find_map(|item| {
        // Prefer Ready nodes
        let ready = item["status"]["conditions"].as_array()
            .and_then(|c| c.iter().find(|cond| cond["type"].as_str() == Some("Ready")))
            .and_then(|c| c["status"].as_str())
            .map(|s| s == "True")
            .unwrap_or(false);
        if !ready { return None; }
        item["status"]["addresses"].as_array()
            .and_then(|addrs| addrs.iter()
                .find(|a| a["type"].as_str() == Some("InternalIP"))
                .and_then(|a| a["address"].as_str()))
            .map(|s| s.to_string())
    })
}

/// Get the ClusterIP of a Kubernetes service.
fn get_service_cluster_ip(kubeconfig: &str, name: &str, namespace: &str) -> Option<String> {
    let output = kubectl(kubeconfig, &["get", "service", name, "-n", namespace,
                         "-o", "jsonpath={.spec.clusterIP}"]).ok()?;
    let ip = output.trim().to_string();
    if ip.is_empty() || ip == "None" { None } else { Some(ip) }
}

/// Find the KUBE-SVC chain name for a given ClusterIP, port, and protocol
/// by parsing `iptables -t nat -S KUBE-SERVICES`.
fn find_kube_svc_chain(cluster_ip: &str, service_port: u16, protocol: &str) -> Option<String> {
    let output = Command::new("iptables")
        .args(["-t", "nat", "-S", "KUBE-SERVICES"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let proto = protocol.to_lowercase();
    let dest = format!("{}/32", cluster_ip);
    let dport_str = format!("--dport {}", service_port);

    for line in stdout.lines() {
        if line.contains(&dest) && line.contains(&dport_str) && line.contains(&format!("-p {}", proto))
            && let Some(pos) = line.find("-j KUBE-SVC-") {
                let chain = line[pos + 3..].split_whitespace().next()?;
                return Some(chain.to_string());
            }
    }
    None
}

/// Apply iptables rules to route WolfNet IP traffic through k3s KUBE-SVC chains.
/// Instead of PREROUTING DNAT (which conflicts with k3s's own NAT rules),
/// we insert rules in the KUBE-SERVICES chain that jump directly to the
/// service's KUBE-SVC-* chain, letting k3s handle pod routing natively.
fn apply_kube_svc_rules(wolfnet_ip: &str, kubeconfig: &str, service_name: &str,
                        namespace: &str, port_mappings: &[K8sWolfNetPortMap]) {
    let cluster_ip = match get_service_cluster_ip(kubeconfig, service_name, namespace) {
        Some(ip) => ip,
        None => {
            warn!("Could not find ClusterIP for service {}/{} — KUBE-SVC rules not applied", namespace, service_name);
            return;
        }
    };

    for pm in port_mappings {
        let proto = pm.protocol.to_lowercase();
        let chain = match find_kube_svc_chain(&cluster_ip, pm.service_port, &proto) {
            Some(c) => c,
            None => {
                warn!("Could not find KUBE-SVC chain for {}:{}/{} — skipping", cluster_ip, pm.service_port, proto);
                continue;
            }
        };

        let wolfnet_cidr = format!("{}/32", wolfnet_ip);
        let sport = pm.service_port.to_string();

        // Check if our KUBE-SVC jump rule already exists
        let svc_exists = Command::new("iptables")
            .args(["-t", "nat", "-C", "KUBE-SERVICES",
                   "-d", &wolfnet_cidr, "-p", &proto,
                   "-m", "comment", "--comment", "wolfstack-wolfnet",
                   "--dport", &sport,
                   "-j", &chain])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !svc_exists {
            // Insert KUBE-SVC jump rule (goes to position 1)
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-I", "KUBE-SERVICES",
                       "-d", &wolfnet_cidr, "-p", &proto,
                       "-m", "comment", "--comment", "wolfstack-wolfnet",
                       "--dport", &sport,
                       "-j", &chain])
                .output();
            // Insert KUBE-MARK-MASQ rule before it (goes to position 1, pushing SVC to position 2)
            // This ensures return traffic from pods gets masqueraded back through the node
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-I", "KUBE-SERVICES",
                       "-d", &wolfnet_cidr, "-p", &proto,
                       "-m", "comment", "--comment", "wolfstack-wolfnet",
                       "--dport", &sport,
                       "-j", "KUBE-MARK-MASQ"])
                .output();
            info!("Added KUBE-SERVICES rules: {} → {} for port {}/{}", wolfnet_ip, chain, pm.service_port, proto);
        }
    }
}

/// Remove iptables KUBE-SERVICES rules for a k8s WolfNet route.
/// Also cleans up any legacy PREROUTING DNAT + MASQUERADE rules from older versions.
fn remove_kube_svc_rules(wolfnet_ip: &str, target_node_ip: &str, port_mappings: &[K8sWolfNetPortMap]) {
    // Remove our rules from KUBE-SERVICES by scanning for wolfnet_ip
    if let Ok(output) = Command::new("iptables")
        .args(["-t", "nat", "-S", "KUBE-SERVICES"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let dest = format!("{}/32", wolfnet_ip);
        for line in stdout.lines() {
            if line.contains(&dest) && line.starts_with("-A KUBE-SERVICES") {
                // Convert "-A KUBE-SERVICES ..." to delete args
                let delete_rule = line.replacen("-A ", "", 1);
                let parts: Vec<&str> = delete_rule.split_whitespace().collect();
                let _ = Command::new("iptables")
                    .args(["-t", "nat", "-D"])
                    .args(&parts)
                    .output();
            }
        }
    }

    // Clean up legacy PREROUTING DNAT + MASQUERADE rules from older WolfStack versions
    for pm in port_mappings {
        let proto = pm.protocol.to_lowercase();
        if !target_node_ip.is_empty() {
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-D", "PREROUTING",
                       "-d", wolfnet_ip, "-p", &proto,
                       "--dport", &pm.service_port.to_string(),
                       "-j", "DNAT", "--to-destination",
                       &format!("{}:{}", target_node_ip, pm.node_port)])
                .output();
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-D", "POSTROUTING",
                       "-d", target_node_ip, "-p", &proto,
                       "--dport", &pm.node_port.to_string(),
                       "-j", "MASQUERADE"])
                .output();
        } else {
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-D", "PREROUTING",
                       "-d", wolfnet_ip, "-p", &proto,
                       "--dport", &pm.service_port.to_string(),
                       "-j", "REDIRECT", "--to-port", &pm.node_port.to_string()])
                .output();
        }
    }
}

/// Remove the WolfNet IP route for a k8s deployment.
/// Removes iptables rules and the secondary IP from wolfnet0.
pub fn remove_wolfnet_route(cluster_id: &str, deployment_name: &str, namespace: &str) -> Result<(), String> {
    let mut config = load_config();
    let cluster = config.clusters.iter_mut().find(|c| c.id == cluster_id)
        .ok_or_else(|| format!("Cluster '{}' not found", cluster_id))?;

    let route = cluster.wolfnet_routes.iter()
        .find(|r| r.deployment_name == deployment_name && r.namespace == namespace)
        .cloned()
        .ok_or_else(|| "No WolfNet route found for this deployment".to_string())?;

    // Remove iptables KUBE-SERVICES rules (and legacy DNAT rules)
    remove_kube_svc_rules(&route.wolfnet_ip, &route.target_node_ip, &route.port_mappings);

    // Remove kernel route and secondary IP from wolfnet0
    let _ = Command::new("ip")
        .args(["route", "del", &format!("{}/32", route.wolfnet_ip), "dev", "wolfnet0"])
        .output();
    let _ = Command::new("ip")
        .args(["addr", "del", &format!("{}/32", route.wolfnet_ip), "dev", "wolfnet0"])
        .output();

    // Remove from WolfNet routes so other peers stop routing to this IP
    {
        let mut cache = crate::containers::WOLFNET_ROUTES.lock().unwrap();
        cache.remove(&route.wolfnet_ip);
        crate::containers::flush_routes_to_disk(&cache);
    }

    cluster.wolfnet_routes.retain(|r| !(r.deployment_name == deployment_name && r.namespace == namespace));
    save_config(&config)?;

    info!("Removed WolfNet route {} for k8s deployment '{}'", route.wolfnet_ip, deployment_name);
    Ok(())
}

/// Re-apply all WolfNet routes on startup (add secondary IPs and iptables rules).
/// Called from main.rs background tasks after WolfNet is running.
pub fn apply_all_wolfnet_routes() {
    let config = load_config();

    // Collect all k8s route IPs to register with WolfNet
    let wn_status = crate::networking::get_wolfnet_status();
    let local_wn_ip = wn_status.ip.as_deref()
        .map(|ip| ip.split('/').next().unwrap_or(ip).to_string());
    let mut wn_routes = std::collections::HashMap::new();

    // Enable forwarding for routed traffic
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();

    for cluster in &config.clusters {
        for route in &cluster.wolfnet_routes {
            // Add secondary IP to wolfnet0 (ignore errors if already exists)
            let _ = Command::new("ip")
                .args(["addr", "add", &format!("{}/32", route.wolfnet_ip), "dev", "wolfnet0"])
                .output();

            // Add explicit route so the kernel knows this IP is local
            let _ = Command::new("ip")
                .args(["route", "replace", &format!("{}/32", route.wolfnet_ip), "dev", "wolfnet0"])
                .output();

            // Clean up any legacy PREROUTING DNAT rules from older versions
            for pm in &route.port_mappings {
                let proto = pm.protocol.to_lowercase();
                if !route.target_node_ip.is_empty() {
                    let _ = Command::new("iptables")
                        .args(["-t", "nat", "-D", "PREROUTING",
                               "-d", &route.wolfnet_ip, "-p", &proto,
                               "--dport", &pm.service_port.to_string(),
                               "-j", "DNAT", "--to-destination",
                               &format!("{}:{}", route.target_node_ip, pm.node_port)])
                        .output();
                    let _ = Command::new("iptables")
                        .args(["-t", "nat", "-D", "POSTROUTING",
                               "-d", &route.target_node_ip, "-p", &proto,
                               "--dport", &pm.node_port.to_string(),
                               "-j", "MASQUERADE"])
                        .output();
                }
            }

            // Apply KUBE-SVC rules (hooks into k3s's own iptables chains)
            apply_kube_svc_rules(&route.wolfnet_ip, &cluster.kubeconfig_path,
                                 &route.deployment_name, &route.namespace, &route.port_mappings);

            // Register route so other WolfNet peers can reach this IP
            if let Some(ref lip) = local_wn_ip {
                wn_routes.insert(route.wolfnet_ip.clone(), lip.clone());
            }

            info!("Re-applied WolfNet route {} for k8s deployment '{}'",
                route.wolfnet_ip, route.deployment_name);
        }
    }

    // Write all k8s routes to routes.json so WolfNet peers can route to them
    if !wn_routes.is_empty() {
        crate::containers::update_wolfnet_routes(&wn_routes);
    }
}


// ═══════════════════════════════════════════════
// ─── Resource Queries ───
// ═══════════════════════════════════════════════

/// Helper to compute a human-readable age string from a creation timestamp.
fn compute_age(creation_timestamp: &str) -> String {
    if let Ok(created) = chrono::DateTime::parse_from_rfc3339(creation_timestamp) {
        let duration = chrono::Utc::now().signed_duration_since(created);
        if duration.num_days() > 0 {
            format!("{}d", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{}h", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{}m", duration.num_minutes())
        } else {
            format!("{}s", duration.num_seconds())
        }
    } else {
        "unknown".to_string()
    }
}

pub fn get_namespaces(kubeconfig: &str) -> Vec<K8sNamespace> {
    let args = vec!["get", "namespaces", "-o", "json"];
    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get namespaces: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse namespace JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let status = item["status"]["phase"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();
            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            K8sNamespace { name, status, age }
        })
        .collect()
}

pub fn get_pods(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sPod> {
    let mut args = vec!["get", "pods", "-o", "json"];
    if let Some(ns) = namespace {
        args.extend_from_slice(&["-n", ns]);
    } else {
        args.push("--all-namespaces");
    }

    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get pods: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse pod JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ns = item["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let phase = item["status"]["phase"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();

            // Compute ready count
            let container_statuses = item["status"]["containerStatuses"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let total_containers = container_statuses.len();
            let ready_containers = container_statuses
                .iter()
                .filter(|cs| cs["ready"].as_bool().unwrap_or(false))
                .count();
            let ready = format!("{}/{}", ready_containers, total_containers);

            let restarts: u32 = container_statuses
                .iter()
                .map(|cs| cs["restartCount"].as_u64().unwrap_or(0) as u32)
                .sum();

            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            let node = item["spec"]["nodeName"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ip = item["status"]["podIP"]
                .as_str()
                .unwrap_or("")
                .to_string();

            K8sPod {
                name,
                namespace: ns,
                status: phase,
                ready,
                restarts,
                age,
                node,
                ip,
            }
        })
        .collect()
}

pub fn get_deployments(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sDeployment> {
    let mut args = vec!["get", "deployments", "-o", "json"];
    if let Some(ns) = namespace {
        args.extend_from_slice(&["-n", ns]);
    } else {
        args.push("--all-namespaces");
    }

    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get deployments: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse deployment JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ns = item["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let desired_replicas = item["spec"]["replicas"].as_u64().unwrap_or(0) as u32;
            let ready_replicas = item["status"]["readyReplicas"].as_u64().unwrap_or(0) as u32;
            let available = item["status"]["availableReplicas"]
                .as_u64()
                .unwrap_or(0) as u32;
            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            // Get the image from the first container spec
            let image = item["spec"]["template"]["spec"]["containers"]
                .as_array()
                .and_then(|containers| containers.first())
                .and_then(|c| c["image"].as_str())
                .unwrap_or("")
                .to_string();

            K8sDeployment {
                name,
                namespace: ns,
                ready_replicas,
                desired_replicas,
                available,
                age,
                image,
            }
        })
        .collect()
}

pub fn get_services(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sService> {
    let mut args = vec!["get", "services", "-o", "json"];
    if let Some(ns) = namespace {
        args.extend_from_slice(&["-n", ns]);
    } else {
        args.push("--all-namespaces");
    }

    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get services: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse service JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let ns = item["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let service_type = item["spec"]["type"]
                .as_str()
                .unwrap_or("ClusterIP")
                .to_string();
            let cluster_ip = item["spec"]["clusterIP"]
                .as_str()
                .unwrap_or("")
                .to_string();

            // External IP: from status.loadBalancer.ingress or spec.externalIPs
            let external_ip = item["status"]["loadBalancer"]["ingress"]
                .as_array()
                .and_then(|ingresses| ingresses.first())
                .and_then(|ing| ing["ip"].as_str().or_else(|| ing["hostname"].as_str()))
                .or_else(|| {
                    item["spec"]["externalIPs"]
                        .as_array()
                        .and_then(|ips| ips.first())
                        .and_then(|ip| ip.as_str())
                })
                .unwrap_or("<none>")
                .to_string();

            // Format ports as "80:30080/TCP,443:30443/TCP"
            let ports = item["spec"]["ports"]
                .as_array()
                .map(|ports| {
                    ports
                        .iter()
                        .map(|p| {
                            let port = p["port"].as_u64().unwrap_or(0);
                            let node_port = p["nodePort"].as_u64();
                            let protocol = p["protocol"].as_str().unwrap_or("TCP");
                            if let Some(np) = node_port {
                                format!("{}:{}/{}", port, np, protocol)
                            } else {
                                format!("{}/{}", port, protocol)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();

            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            K8sService {
                name,
                namespace: ns,
                service_type,
                cluster_ip,
                external_ip,
                ports,
                age,
            }
        })
        .collect()
}

pub fn get_nodes(kubeconfig: &str) -> Vec<K8sNode> {
    let output = match kubectl(kubeconfig, &["get", "nodes", "-o", "json"]) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to get nodes: {}", e);
            return Vec::new();
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to parse node JSON: {}", e);
            return Vec::new();
        }
    };

    let items = match json["items"].as_array() {
        Some(items) => items,
        None => return Vec::new(),
    };

    // Try to get metrics for CPU/memory usage (kubectl top doesn't support -o json)
    // Output format: "node-name   123m   4%   456Mi   12%"
    let metrics_text = kubectl(kubeconfig, &["top", "nodes", "--no-headers"]).ok();
    let mut node_metrics: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    if let Some(ref text) = metrics_text {
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let node_name = parts[0].to_string();
                let cpu = parts[1].to_string();    // e.g. "123m"
                let mem = parts[3].to_string();    // e.g. "456Mi"
                node_metrics.insert(node_name, (cpu, mem));
            }
        }
    }

    items
        .iter()
        .map(|item| {
            let name = item["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();

            // Status: look at conditions for "Ready"
            let conditions = item["status"]["conditions"].as_array();
            let status = conditions
                .and_then(|conds| {
                    conds.iter().find(|c| c["type"].as_str() == Some("Ready"))
                })
                .map(|c| {
                    if c["status"].as_str() == Some("True") {
                        "Ready".to_string()
                    } else {
                        "NotReady".to_string()
                    }
                })
                .unwrap_or_else(|| "Unknown".to_string());

            // Roles from labels
            let labels = &item["metadata"]["labels"];
            let mut roles = Vec::new();
            if let Some(obj) = labels.as_object() {
                for (key, _) in obj {
                    if key.starts_with("node-role.kubernetes.io/")
                        && let Some(role) = key.strip_prefix("node-role.kubernetes.io/")
                            && !role.is_empty() {
                                roles.push(role.to_string());
                            }
                }
            }
            let roles_str = if roles.is_empty() {
                "<none>".to_string()
            } else {
                roles.join(",")
            };

            let version = item["status"]["nodeInfo"]["kubeletVersion"]
                .as_str()
                .unwrap_or("")
                .to_string();

            let creation = item["metadata"]["creationTimestamp"]
                .as_str()
                .unwrap_or("");
            let age = compute_age(creation);

            let cpu_capacity = item["status"]["capacity"]["cpu"]
                .as_str()
                .unwrap_or("0")
                .to_string();
            let memory_capacity = item["status"]["capacity"]["memory"]
                .as_str()
                .unwrap_or("0")
                .to_string();

            // Try to find usage from metrics
            let (cpu_usage, memory_usage) = node_metrics
                .get(&name)
                .map(|(cpu, mem)| (cpu.clone(), mem.clone()))
                .unwrap_or_else(|| ("0".to_string(), "0".to_string()));

            K8sNode {
                name,
                status,
                roles: roles_str,
                version,
                age,
                cpu_capacity,
                memory_capacity,
                cpu_usage,
                memory_usage,
            }
        })
        .collect()
}

pub fn get_cluster_status(kubeconfig: &str) -> K8sClusterStatus {
    // Try normal kubectl first, fall back to --insecure-skip-tls-verify for
    // clusters whose TLS cert doesn't include the remote hostname/IP
    let nodes = get_nodes(kubeconfig);
    let (kubeconfig_to_use, insecure) = if nodes.is_empty() {
        // Check if the issue is TLS by retrying with skip-verify
        let test = kubectl_insecure(kubeconfig, &["get", "nodes", "-o", "json"]);
        if test.is_ok() {
            (kubeconfig.to_string(), true)
        } else {
            (kubeconfig.to_string(), false)
        }
    } else {
        (kubeconfig.to_string(), false)
    };
    let kc = kubeconfig_to_use.as_str();

    let kctl = if insecure { kubectl_insecure } else { kubectl };

    // Get API version
    let api_version = kctl(kc, &["version", "-o", "json"])
        .ok()
        .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
        .and_then(|v| v["serverVersion"]["gitVersion"].as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string());

    // Get nodes
    let nodes = if insecure { get_nodes_insecure(kc) } else { get_nodes(kc) };
    let nodes_total = nodes.len() as u32;
    let nodes_ready = nodes.iter().filter(|n| n.status == "Ready").count() as u32;

    // Get pods (exclude Succeeded/Completed — these are finished Jobs/init containers)
    let pods = if insecure { get_pods_insecure(kc, None) } else { get_pods(kc, None) };
    let active_pods: Vec<_> = pods.iter().filter(|p| p.status != "Succeeded").collect();
    let pods_total = active_pods.len() as u32;
    let pods_running = active_pods.iter().filter(|p| p.status == "Running").count() as u32;

    // Get namespaces
    let namespaces = if insecure {
        kctl(kc, &["get", "namespaces", "-o", "json"]).ok()
            .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
            .and_then(|v| v["items"].as_array().map(|a| a.len()))
            .unwrap_or(0) as u32
    } else {
        get_namespaces(kc).len() as u32
    };

    let healthy = nodes_total > 0 && nodes_ready == nodes_total;

    K8sClusterStatus {
        healthy,
        nodes_ready,
        nodes_total,
        pods_running,
        pods_total,
        namespaces,
        api_version,
    }
}

/// kubectl with --insecure-skip-tls-verify for clusters with mismatched certs
fn kubectl_insecure(kubeconfig: &str, args: &[&str]) -> Result<String, String> {
    let (binary, prefix_args) = find_kubectl();
    let mut cmd = Command::new(binary);
    cmd.args(prefix_args);
    cmd.arg("--kubeconfig").arg(kubeconfig);
    cmd.arg("--insecure-skip-tls-verify");
    cmd.args(args);
    let output = cmd.output()
        .map_err(|e| format!("kubectl error: {}", e))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn get_nodes_insecure(kubeconfig: &str) -> Vec<K8sNode> {
    kubectl_insecure(kubeconfig, &["get", "nodes", "-o", "json"])
        .ok()
        .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
        .and_then(|v| v["items"].as_array().map(|items| {
            items.iter().map(|n| {
                let name = n["metadata"]["name"].as_str().unwrap_or("").to_string();
                let status = n["status"]["conditions"].as_array()
                    .and_then(|c| c.iter().find(|cond| cond["type"] == "Ready"))
                    .and_then(|c| c["status"].as_str())
                    .map(|s| if s == "True" { "Ready" } else { "NotReady" })
                    .unwrap_or("Unknown").to_string();
                let roles = n["metadata"]["labels"].as_object()
                    .map(|l| l.keys().filter(|k| k.starts_with("node-role.kubernetes.io/"))
                        .map(|k| k.trim_start_matches("node-role.kubernetes.io/").to_string())
                        .collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                K8sNode { name, status, roles, age: String::new(), version: String::new(),
                    cpu_capacity: String::new(), memory_capacity: String::new(),
                    cpu_usage: String::new(), memory_usage: String::new() }
            }).collect()
        }))
        .unwrap_or_default()
}

fn get_pods_insecure(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sPod> {
    let mut args = vec!["get", "pods", "-o", "json"];
    if let Some(ns) = namespace { args.extend(["-n", ns]); } else { args.push("--all-namespaces"); }
    kubectl_insecure(kubeconfig, &args)
        .ok()
        .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
        .and_then(|v| v["items"].as_array().map(|items| {
            items.iter().map(|p| {
                K8sPod {
                    name: p["metadata"]["name"].as_str().unwrap_or("").to_string(),
                    namespace: p["metadata"]["namespace"].as_str().unwrap_or("").to_string(),
                    status: p["status"]["phase"].as_str().unwrap_or("Unknown").to_string(),
                    node: p["spec"]["nodeName"].as_str().unwrap_or("").to_string(),
                    ip: p["status"]["podIP"].as_str().unwrap_or("").to_string(),
                    ready: String::new(),
                    restarts: 0, age: String::new(),
                }
            }).collect()
        }))
        .unwrap_or_default()
}

/// Public wrapper for insecure pod fetching (used by daily report when normal TLS fails)
pub fn get_pods_insecure_pub(kubeconfig: &str, namespace: Option<&str>) -> Vec<K8sPod> {
    get_pods_insecure(kubeconfig, namespace)
}

// ═══════════════════════════════════════════════
// ─── Resource Management ───
// ═══════════════════════════════════════════════

pub fn create_namespace(kubeconfig: &str, name: &str) -> Result<String, String> {
    info!("Creating namespace '{}'", name);
    kubectl(kubeconfig, &["create", "namespace", name])
}

pub fn delete_namespace(kubeconfig: &str, name: &str) -> Result<String, String> {
    info!("Deleting namespace '{}'", name);
    kubectl(kubeconfig, &["delete", "namespace", name])
}

pub fn delete_pod(kubeconfig: &str, name: &str, namespace: &str) -> Result<String, String> {
    info!("Deleting pod '{}' in namespace '{}'", name, namespace);
    kubectl(kubeconfig, &["delete", "pod", name, "-n", namespace])
}

pub fn scale_deployment(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
    replicas: u32,
) -> Result<String, String> {
    info!(
        "Scaling deployment '{}' in namespace '{}' to {} replicas",
        name, namespace, replicas
    );
    let replicas_arg = format!("--replicas={}", replicas);
    kubectl(
        kubeconfig,
        &["scale", "deployment", name, "-n", namespace, &replicas_arg],
    )
}

pub fn delete_deployment(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<String, String> {
    info!("Deleting deployment '{}' in namespace '{}'", name, namespace);
    kubectl(
        kubeconfig,
        &["delete", "deployment", name, "-n", namespace],
    )
}

pub fn restart_deployment(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<String, String> {
    info!(
        "Restarting deployment '{}' in namespace '{}'",
        name, namespace
    );
    kubectl(
        kubeconfig,
        &["rollout", "restart", "deployment", name, "-n", namespace],
    )
}

pub fn delete_service(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<String, String> {
    info!("Deleting service '{}' in namespace '{}'", name, namespace);
    kubectl(
        kubeconfig,
        &["delete", "service", name, "-n", namespace],
    )
}

pub fn get_pod_logs(
    kubeconfig: &str,
    pod: &str,
    namespace: &str,
    container: Option<&str>,
    tail_lines: u32,
) -> Result<String, String> {
    let tail_arg = format!("--tail={}", tail_lines);
    let mut args = vec!["logs", pod, "-n", namespace, &tail_arg];
    if let Some(c) = container {
        args.extend_from_slice(&["-c", c]);
    }
    kubectl(kubeconfig, &args)
}

/// Get detailed pod information (describe-like) as JSON
pub fn get_pod_detail(kubeconfig: &str, name: &str, namespace: &str) -> Result<serde_json::Value, String> {
    let output = kubectl(kubeconfig, &["get", "pod", name, "-n", namespace, "-o", "json"])?;
    let json: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse pod JSON: {}", e))?;

    // Extract container info
    let containers: Vec<serde_json::Value> = json["spec"]["containers"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c["name"],
                "image": c["image"],
                "ports": c["ports"],
                "env": c["env"],
                "volume_mounts": c["volumeMounts"],
                "resources": c["resources"],
                "command": c["command"],
                "args": c["args"],
            })
        })
        .collect();

    // Extract container statuses
    let container_statuses = json["status"]["containerStatuses"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let conditions = json["status"]["conditions"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let volumes = json["spec"]["volumes"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    Ok(serde_json::json!({
        "name": json["metadata"]["name"],
        "namespace": json["metadata"]["namespace"],
        "labels": json["metadata"]["labels"],
        "annotations": json["metadata"]["annotations"],
        "creation_timestamp": json["metadata"]["creationTimestamp"],
        "owner_references": json["metadata"]["ownerReferences"],
        "status": json["status"]["phase"],
        "pod_ip": json["status"]["podIP"],
        "host_ip": json["status"]["hostIP"],
        "node_name": json["spec"]["nodeName"],
        "service_account": json["spec"]["serviceAccountName"],
        "restart_policy": json["spec"]["restartPolicy"],
        "dns_policy": json["spec"]["dnsPolicy"],
        "containers": containers,
        "container_statuses": container_statuses,
        "conditions": conditions,
        "volumes": volumes,
        "qos_class": json["status"]["qosClass"],
    }))
}

/// Get resource usage for a specific pod via `kubectl top pod`
pub fn get_pod_top(kubeconfig: &str, name: &str, namespace: &str) -> Result<serde_json::Value, String> {
    let output = kubectl(kubeconfig, &["top", "pod", name, "-n", namespace, "--no-headers"]);
    match output {
        Ok(text) => {
            // Output format: "pod-name   CPU(cores)   MEMORY(bytes)"
            let parts: Vec<&str> = text.split_whitespace().collect();
            if parts.len() >= 3 {
                Ok(serde_json::json!({
                    "cpu": parts[1],
                    "memory": parts[2],
                }))
            } else {
                Ok(serde_json::json!({ "cpu": "N/A", "memory": "N/A" }))
            }
        }
        Err(e) => {
            // Metrics server may not be installed
            Err(format!("Metrics not available (metrics-server may not be installed): {}", e))
        }
    }
}

/// Execute a command inside a pod and return stdout
pub fn exec_in_pod(kubeconfig: &str, name: &str, namespace: &str, container: Option<&str>, command: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec", name, "-n", namespace];
    if let Some(c) = container {
        args.extend_from_slice(&["-c", c]);
    }
    args.push("--");
    args.extend_from_slice(command);
    kubectl(kubeconfig, &args)
}

/// Get events related to a specific pod
pub fn get_pod_events(kubeconfig: &str, name: &str, namespace: &str) -> Result<Vec<serde_json::Value>, String> {
    let field_selector = format!("involvedObject.name={}", name);
    let output = kubectl(kubeconfig, &["get", "events", "-n", namespace, "--field-selector", &field_selector, "-o", "json"])?;
    let json: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse events JSON: {}", e))?;
    Ok(json["items"].as_array().cloned().unwrap_or_default())
}

// ═══════════════════════════════════════════════
// ─── Storage Management ───
// ═══════════════════════════════════════════════

/// List all StorageClasses in the cluster
pub fn get_storage_classes(kubeconfig: &str) -> Vec<serde_json::Value> {
    let output = match kubectl(kubeconfig, &["get", "storageclass", "-o", "json"]) {
        Ok(o) => o,
        Err(e) => { error!("Failed to get storage classes: {}", e); return Vec::new(); }
    };
    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    json["items"].as_array().unwrap_or(&vec![]).iter().map(|sc| {
        let is_default = sc["metadata"]["annotations"]["storageclass.kubernetes.io/is-default-class"]
            .as_str().unwrap_or("false") == "true";
        serde_json::json!({
            "name": sc["metadata"]["name"].as_str().unwrap_or(""),
            "provisioner": sc["provisioner"].as_str().unwrap_or("unknown"),
            "reclaim_policy": sc["reclaimPolicy"].as_str().unwrap_or("Delete"),
            "volume_binding_mode": sc["volumeBindingMode"].as_str().unwrap_or("Immediate"),
            "is_default": is_default,
            "allow_volume_expansion": sc["allowVolumeExpansion"].as_bool().unwrap_or(false),
        })
    }).collect()
}

/// List all PersistentVolumes in the cluster
pub fn get_persistent_volumes(kubeconfig: &str) -> Vec<serde_json::Value> {
    let output = match kubectl(kubeconfig, &["get", "pv", "-o", "json"]) {
        Ok(o) => o,
        Err(e) => { error!("Failed to get PVs: {}", e); return Vec::new(); }
    };
    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    json["items"].as_array().unwrap_or(&vec![]).iter().map(|pv| {
        let claim = pv["spec"]["claimRef"]["name"].as_str().unwrap_or("");
        let claim_ns = pv["spec"]["claimRef"]["namespace"].as_str().unwrap_or("");
        serde_json::json!({
            "name": pv["metadata"]["name"].as_str().unwrap_or(""),
            "capacity": pv["spec"]["capacity"]["storage"].as_str().unwrap_or(""),
            "access_modes": pv["spec"]["accessModes"].as_array()
                .map(|a| a.iter().map(|v| v.as_str().unwrap_or("")).collect::<Vec<_>>())
                .unwrap_or_default(),
            "reclaim_policy": pv["spec"]["persistentVolumeReclaimPolicy"].as_str().unwrap_or(""),
            "status": pv["status"]["phase"].as_str().unwrap_or(""),
            "storage_class": pv["spec"]["storageClassName"].as_str().unwrap_or(""),
            "claim": if claim.is_empty() { String::new() } else { format!("{}/{}", claim_ns, claim) },
            "age": compute_age(pv["metadata"]["creationTimestamp"].as_str().unwrap_or("")),
        })
    }).collect()
}

/// List PersistentVolumeClaims, optionally filtered by namespace
pub fn get_persistent_volume_claims(kubeconfig: &str, namespace: Option<&str>) -> Vec<serde_json::Value> {
    let mut args = vec!["get", "pvc", "-o", "json"];
    if let Some(ns) = namespace {
        args.extend_from_slice(&["-n", ns]);
    } else {
        args.push("--all-namespaces");
    }
    let output = match kubectl(kubeconfig, &args) {
        Ok(o) => o,
        Err(e) => { error!("Failed to get PVCs: {}", e); return Vec::new(); }
    };
    let json: serde_json::Value = match serde_json::from_str(&output) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    json["items"].as_array().unwrap_or(&vec![]).iter().map(|pvc| {
        let access_modes = pvc["spec"]["accessModes"].as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap_or("")).collect::<Vec<_>>())
            .unwrap_or_default();
        serde_json::json!({
            "name": pvc["metadata"]["name"].as_str().unwrap_or(""),
            "namespace": pvc["metadata"]["namespace"].as_str().unwrap_or("default"),
            "status": pvc["status"]["phase"].as_str().unwrap_or(""),
            "volume": pvc["spec"]["volumeName"].as_str().unwrap_or(""),
            "capacity": pvc["status"]["capacity"]["storage"].as_str().unwrap_or(
                pvc["spec"]["resources"]["requests"]["storage"].as_str().unwrap_or("")
            ),
            "access_modes": access_modes,
            "storage_class": pvc["spec"]["storageClassName"].as_str().unwrap_or(""),
            "age": compute_age(pvc["metadata"]["creationTimestamp"].as_str().unwrap_or("")),
        })
    }).collect()
}

/// Create a PersistentVolumeClaim
pub fn create_pvc(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
    storage_class: &str,
    size: &str,
    access_mode: &str,
) -> Result<String, String> {
    info!("Creating PVC '{}' in namespace '{}' — {}  {} (class: {})", name, namespace, size, access_mode, storage_class);
    let yaml = format!(
        r#"apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {}
  namespace: {}
spec:
  accessModes:
    - {}
  resources:
    requests:
      storage: {}
  storageClassName: {}"#,
        name, namespace, access_mode, size, storage_class
    );

    // Write to temp file and apply
    let tmp = format!("/tmp/wolfstack-pvc-{}.yaml", uuid::Uuid::new_v4());
    std::fs::write(&tmp, &yaml).map_err(|e| format!("Failed to write temp YAML: {}", e))?;
    let result = kubectl(kubeconfig, &["apply", "-f", &tmp]);
    let _ = std::fs::remove_file(&tmp);
    result
}

pub struct PersistentVolumeRequest<'a> {
    pub name: &'a str,
    pub namespace: &'a str,
    pub size: &'a str,
    pub access_mode: &'a str,
    pub storage_type: &'a str,
    pub host_path: Option<&'a str>,
    pub nfs_server: Option<&'a str>,
    pub nfs_path: Option<&'a str>,
}

/// Create a PersistentVolume + PVC with a specific backing storage (hostPath or NFS)
pub fn create_pv_and_pvc(kubeconfig: &str, request: PersistentVolumeRequest<'_>) -> Result<String, String> {
    let PersistentVolumeRequest { name, namespace, size, access_mode, storage_type, host_path, nfs_server, nfs_path } = request;
    let pv_name = format!("{}-pv", name);

    let volume_source = match storage_type {
        "host_path" | "local" => {
            let path = host_path.ok_or("host_path is required for local storage")?;
            info!("Creating hostPath PV '{}' at '{}' + PVC '{}'", pv_name, path, name);
            format!("  hostPath:\n    path: {}\n    type: DirectoryOrCreate", path)
        }
        "nfs" => {
            let server = nfs_server.ok_or("nfs_server is required for NFS storage")?;
            let path = nfs_path.ok_or("nfs_path is required for NFS storage")?;
            info!("Creating NFS PV '{}' ({}:{}) + PVC '{}'", pv_name, server, path, name);
            format!("  nfs:\n    server: {}\n    path: {}", server, path)
        }
        _ => return Err(format!("Unknown storage type: {}", storage_type)),
    };

    let yaml = format!(
        r#"apiVersion: v1
kind: PersistentVolume
metadata:
  name: {pv_name}
  labels:
    wolfstack-pvc: {name}
spec:
  capacity:
    storage: {size}
  accessModes:
    - {access_mode}
  persistentVolumeReclaimPolicy: Retain
{volume_source}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {name}
  namespace: {namespace}
spec:
  accessModes:
    - {access_mode}
  resources:
    requests:
      storage: {size}
  storageClassName: ""
  selector:
    matchLabels:
      wolfstack-pvc: {name}"#,
        pv_name = pv_name,
        name = name,
        namespace = namespace,
        size = size,
        access_mode = access_mode,
        volume_source = volume_source,
    );

    let tmp = format!("/tmp/wolfstack-pv-pvc-{}.yaml", uuid::Uuid::new_v4());
    std::fs::write(&tmp, &yaml).map_err(|e| format!("Failed to write temp YAML: {}", e))?;
    let result = kubectl(kubeconfig, &["apply", "-f", &tmp]);
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Delete a PersistentVolumeClaim (and its associated PV if created by WolfStack)
pub fn delete_pvc(kubeconfig: &str, name: &str, namespace: &str) -> Result<String, String> {
    info!("Deleting PVC '{}' in namespace '{}'", name, namespace);
    let result = kubectl(kubeconfig, &["delete", "pvc", name, "-n", namespace]);
    // Also try to delete the associated PV (created by create_pv_and_pvc)
    let pv_name = format!("{}-pv", name);
    let _ = kubectl(kubeconfig, &["delete", "pv", &pv_name, "--ignore-not-found"]);
    result
}

/// Add a PVC volume mount to a deployment via kubectl patch
pub fn add_volume_to_deployment(
    kubeconfig: &str,
    deployment: &str,
    namespace: &str,
    pvc_name: &str,
    mount_path: &str,
    container_name: Option<&str>,
) -> Result<String, String> {
    info!("Adding PVC '{}' to deployment '{}' at '{}'", pvc_name, deployment, mount_path);

    // Get existing deployment to find container name and existing volumes
    let output = kubectl(kubeconfig, &["get", "deployment", deployment, "-n", namespace, "-o", "json"])?;
    let dep: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse deployment: {}", e))?;

    // Determine target container
    let containers = dep["spec"]["template"]["spec"]["containers"]
        .as_array()
        .ok_or("No containers in deployment")?;
    let target_container = if let Some(cn) = container_name {
        cn.to_string()
    } else {
        containers.first()
            .and_then(|c| c["name"].as_str())
            .ok_or("No containers found")?
            .to_string()
    };

    // Generate a volume name from PVC name (sanitise)
    let vol_name = format!("pvc-{}", pvc_name);

    // Build the JSON patch to add volume and volumeMount
    // Use strategic merge patch which handles arrays properly
    let patch = serde_json::json!({
        "spec": {
            "template": {
                "spec": {
                    "volumes": [{
                        "name": vol_name,
                        "persistentVolumeClaim": {
                            "claimName": pvc_name
                        }
                    }],
                    "containers": [{
                        "name": target_container,
                        "volumeMounts": [{
                            "name": vol_name,
                            "mountPath": mount_path
                        }]
                    }]
                }
            }
        }
    });

    let patch_str = serde_json::to_string(&patch)
        .map_err(|e| format!("Failed to serialize patch: {}", e))?;

    kubectl(kubeconfig, &[
        "patch", "deployment", deployment,
        "-n", namespace,
        "--type", "strategic",
        "-p", &patch_str,
    ])
}

/// Remove a volume from a deployment using a JSON patch
pub fn remove_volume_from_deployment(
    kubeconfig: &str,
    deployment: &str,
    namespace: &str,
    volume_name: &str,
) -> Result<String, String> {
    info!("Removing volume '{}' from deployment '{}'", volume_name, deployment);

    // Get current deployment spec
    let output = kubectl(kubeconfig, &["get", "deployment", deployment, "-n", namespace, "-o", "json"])?;
    let dep: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse deployment: {}", e))?;

    // Filter out the volume
    let volumes: Vec<serde_json::Value> = dep["spec"]["template"]["spec"]["volumes"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter(|v| v["name"].as_str().unwrap_or("") != volume_name)
        .cloned()
        .collect();

    // Filter out volumeMounts from all containers
    let mut containers = dep["spec"]["template"]["spec"]["containers"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    for container in containers.iter_mut() {
        if let Some(mounts) = container["volumeMounts"].as_array() {
            let filtered: Vec<serde_json::Value> = mounts.iter()
                .filter(|vm| vm["name"].as_str().unwrap_or("") != volume_name)
                .cloned()
                .collect();
            container["volumeMounts"] = serde_json::Value::Array(filtered);
        }
    }

    // Build replacement patch
    let patch = serde_json::json!({
        "spec": {
            "template": {
                "spec": {
                    "volumes": volumes,
                    "containers": containers
                }
            }
        }
    });

    let patch_str = serde_json::to_string(&patch)
        .map_err(|e| format!("Failed to serialize patch: {}", e))?;

    kubectl(kubeconfig, &[
        "patch", "deployment", deployment,
        "-n", namespace,
        "--type", "strategic",
        "-p", &patch_str,
    ])
}

/// Get detailed info about a single deployment (env vars, labels, strategy, volumes, etc.)
pub fn get_deployment_detail(kubeconfig: &str, name: &str, namespace: &str) -> Result<serde_json::Value, String> {
    let output = kubectl(kubeconfig, &["get", "deployment", name, "-n", namespace, "-o", "json"])?;
    let json: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse deployment JSON: {}", e))?;

    let containers = json["spec"]["template"]["spec"]["containers"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let strategy = json["spec"]["strategy"]["type"]
        .as_str()
        .unwrap_or("RollingUpdate")
        .to_string();

    let labels = json["metadata"]["labels"].clone();
    let selector = json["spec"]["selector"]["matchLabels"].clone();
    let replicas = json["spec"]["replicas"].as_u64().unwrap_or(1);
    let ready_replicas = json["status"]["readyReplicas"].as_u64().unwrap_or(0);
    let available = json["status"]["availableReplicas"].as_u64().unwrap_or(0);
    let creation = json["metadata"]["creationTimestamp"].as_str().unwrap_or("");
    let age = compute_age(creation);

    // Extract container details
    let container_details: Vec<serde_json::Value> = containers.iter().map(|c| {
        let env_vars: Vec<serde_json::Value> = c["env"].as_array()
            .map(|envs| envs.iter().map(|e| {
                serde_json::json!({
                    "name": e["name"].as_str().unwrap_or(""),
                    "value": e["value"].as_str().unwrap_or(""),
                })
            }).collect())
            .unwrap_or_default();

        let volume_mounts: Vec<serde_json::Value> = c["volumeMounts"].as_array()
            .map(|vms| vms.iter().map(|vm| {
                serde_json::json!({
                    "name": vm["name"].as_str().unwrap_or(""),
                    "mount_path": vm["mountPath"].as_str().unwrap_or(""),
                    "read_only": vm["readOnly"].as_bool().unwrap_or(false),
                })
            }).collect())
            .unwrap_or_default();

        let ports: Vec<serde_json::Value> = c["ports"].as_array()
            .map(|ps| ps.iter().map(|p| {
                serde_json::json!({
                    "container_port": p["containerPort"].as_u64().unwrap_or(0),
                    "protocol": p["protocol"].as_str().unwrap_or("TCP"),
                    "name": p["name"].as_str().unwrap_or(""),
                })
            }).collect())
            .unwrap_or_default();

        serde_json::json!({
            "name": c["name"].as_str().unwrap_or(""),
            "image": c["image"].as_str().unwrap_or(""),
            "env": env_vars,
            "volume_mounts": volume_mounts,
            "ports": ports,
        })
    }).collect();

    // Volumes
    let volumes: Vec<serde_json::Value> = json["spec"]["template"]["spec"]["volumes"]
        .as_array()
        .map(|vols| vols.iter().map(|v| {
            let vol_type = if v["hostPath"].is_object() {
                format!("hostPath: {}", v["hostPath"]["path"].as_str().unwrap_or(""))
            } else if v["emptyDir"].is_object() || v["emptyDir"].is_null() && v.get("emptyDir").is_some() {
                "emptyDir".to_string()
            } else if v["persistentVolumeClaim"].is_object() {
                format!("pvc: {}", v["persistentVolumeClaim"]["claimName"].as_str().unwrap_or(""))
            } else if v["configMap"].is_object() {
                format!("configMap: {}", v["configMap"]["name"].as_str().unwrap_or(""))
            } else if v["secret"].is_object() {
                format!("secret: {}", v["secret"]["secretName"].as_str().unwrap_or(""))
            } else {
                "unknown".to_string()
            };
            serde_json::json!({
                "name": v["name"].as_str().unwrap_or(""),
                "type": vol_type,
            })
        }).collect())
        .unwrap_or_default();

    // Conditions
    let conditions: Vec<serde_json::Value> = json["status"]["conditions"]
        .as_array()
        .map(|conds| conds.iter().map(|c| {
            serde_json::json!({
                "type": c["type"].as_str().unwrap_or(""),
                "status": c["status"].as_str().unwrap_or(""),
                "reason": c["reason"].as_str().unwrap_or(""),
                "message": c["message"].as_str().unwrap_or(""),
            })
        }).collect())
        .unwrap_or_default();

    Ok(serde_json::json!({
        "name": name,
        "namespace": namespace,
        "replicas": replicas,
        "ready_replicas": ready_replicas,
        "available": available,
        "age": age,
        "strategy": strategy,
        "labels": labels,
        "selector": selector,
        "containers": container_details,
        "volumes": volumes,
        "conditions": conditions,
    }))
}

/// Update the image of a deployment's container
pub fn set_deployment_image(kubeconfig: &str, name: &str, namespace: &str, container: &str, image: &str) -> Result<String, String> {
    info!("Setting image for deployment '{}' container '{}' to '{}'", name, container, image);
    let set_arg = format!("{}={}", container, image);
    kubectl(kubeconfig, &["set", "image", &format!("deployment/{}", name), &set_arg, "-n", namespace])
}

/// Update environment variables on a deployment
pub fn set_deployment_env(kubeconfig: &str, name: &str, namespace: &str, env_vars: &[(String, String)]) -> Result<String, String> {
    info!("Setting {} env vars on deployment '{}' in '{}'", env_vars.len(), name, namespace);
    let dep_ref = format!("deployment/{}", name);
    let env_strs: Vec<String> = env_vars.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
    let mut args: Vec<&str> = vec!["set", "env", &dep_ref, "-n", namespace];
    for s in &env_strs {
        args.push(s);
    }
    kubectl(kubeconfig, &args)
}

/// Delete a deployment and its matching service (if any)
pub fn delete_deployment_and_service(kubeconfig: &str, name: &str, namespace: &str) -> Result<String, String> {
    info!("Deleting deployment '{}' and associated service in '{}'", name, namespace);
    let dep_result = kubectl(kubeconfig, &["delete", "deployment", name, "-n", namespace]);
    // Also delete the service with the same name, ignoring if it doesn't exist
    let _ = kubectl(kubeconfig, &["delete", "service", name, "-n", namespace, "--ignore-not-found"]);
    dep_result
}

/// Update cluster WolfNet settings
pub fn update_cluster_settings(id: &str, wolfnet_server: Option<&str>, wolfnet_network: Option<&str>, wolfnet_auto_deploy: Option<bool>) -> Result<K8sCluster, String> {
    let mut config = load_config();
    let cluster = config.clusters.iter_mut().find(|c| c.id == id)
        .ok_or_else(|| format!("Cluster '{}' not found", id))?;
    if let Some(s) = wolfnet_server { cluster.wolfnet_server = s.to_string(); }
    if let Some(n) = wolfnet_network { cluster.wolfnet_network = n.to_string(); }
    if let Some(a) = wolfnet_auto_deploy { cluster.wolfnet_auto_deploy = a; }
    let updated = cluster.clone();
    save_config(&config)?;
    Ok(updated)
}

/// Get the YAML definition of a Kubernetes resource
pub fn get_resource_yaml(kubeconfig: &str, kind: &str, name: &str, namespace: &str) -> Result<String, String> {
    let mut args = vec!["get", kind, name, "-o", "yaml"];
    if !namespace.is_empty() {
        args.push("-n");
        args.push(namespace);
    }
    kubectl(kubeconfig, &args)
}

pub fn apply_yaml(kubeconfig: &str, yaml_content: &str) -> Result<String, String> {
    // Write YAML to a temporary file
    let tmp_path = format!(
        "/tmp/wolfstack-k8s-apply-{}.yaml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    fs::write(&tmp_path, yaml_content)
        .map_err(|e| format!("Failed to write temp YAML file: {}", e))?;

    let result = kubectl(kubeconfig, &["apply", "-f", &tmp_path]);

    // Clean up temp file
    let _ = fs::remove_file(&tmp_path);

    result
}

// ═══════════════════════════════════════════════
// ─── App Deployment ───
// ═══════════════════════════════════════════════

pub struct AppDeployment<'a> {
    pub app_name: &'a str,
    pub container_name: &'a str,
    pub namespace: &'a str,
    pub image: &'a str,
    pub ports: &'a [String],
    pub env: &'a [String],
    pub volumes: &'a [String],
    pub replicas: u32,
}

/// Deploy an application to Kubernetes by generating Deployment + Service YAML
/// and applying it. Converts Docker-style port mappings and env vars to k8s format.
///
/// * `ports` — Docker-style port mappings, e.g. ["8080:80", "443:443"]
///   Format: "hostPort:containerPort" where hostPort becomes nodePort
/// * `env` — Docker-style env vars, e.g. ["KEY=value", "DB_HOST=localhost"]
/// * `volumes` — Docker-style volume mounts, e.g. ["/host/path:/container/path"]
pub fn deploy_app_to_k8s(kubeconfig: &str, request: AppDeployment<'_>) -> Result<String, String> {
    let AppDeployment { app_name, container_name, namespace, image, ports, env, volumes, replicas } = request;
    // Sanitize container name for k8s (lowercase, alphanumeric + hyphens only)
    let container_name: String = container_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let app_name: String = app_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();

    info!(
        "Deploying app '{}' (container: {}, image: {}) to namespace '{}' with {} replicas",
        app_name, container_name, image, namespace, replicas
    );

    // Strip protocol suffix (e.g. "80/tcp" → "80") from port strings
    fn strip_proto(s: &str) -> &str { s.split('/').next().unwrap_or(s) }

    // Build container ports YAML
    let container_ports_yaml = if ports.is_empty() {
        String::new()
    } else {
        let port_entries: Vec<String> = ports
            .iter()
            .filter_map(|p| {
                let parts: Vec<&str> = p.split(':').collect();
                let container_port = if parts.len() == 2 {
                    strip_proto(parts[1])
                } else {
                    strip_proto(parts[0])
                };
                container_port
                    .parse::<u32>()
                    .ok()
                    .map(|cp| format!("        - containerPort: {}", cp))
            })
            .collect();
        if port_entries.is_empty() {
            String::new()
        } else {
            format!("        ports:\n{}\n", port_entries.join("\n"))
        }
    };

    // Build env YAML
    let env_yaml = if env.is_empty() {
        String::new()
    } else {
        let env_entries: Vec<String> = env
            .iter()
            .filter_map(|e| {
                let parts: Vec<&str> = e.splitn(2, '=').collect();
                if parts.len() == 2 {
                    Some(format!(
                        "        - name: {}\n          value: \"{}\"",
                        parts[0],
                        parts[1].replace('"', "\\\"")
                    ))
                } else {
                    None
                }
            })
            .collect();
        if env_entries.is_empty() {
            String::new()
        } else {
            format!("        env:\n{}\n", env_entries.join("\n"))
        }
    };

    // Build volume mounts and volumes YAML
    let (volume_mounts_yaml, volumes_yaml) = if volumes.is_empty() {
        (String::new(), String::new())
    } else {
        let mut mounts = Vec::new();
        let mut vols = Vec::new();

        for (i, v) in volumes.iter().enumerate() {
            let parts: Vec<&str> = v.splitn(2, ':').collect();
            if parts.len() == 2 {
                let vol_name = format!("vol-{}", i);
                mounts.push(format!(
                    "        - name: {}\n          mountPath: {}",
                    vol_name, parts[1]
                ));
                // Named Docker volumes (no leading /) → emptyDir; actual paths → hostPath
                if parts[0].starts_with('/') {
                    vols.push(format!(
                        "      - name: {}\n        hostPath:\n          path: {}",
                        vol_name, parts[0]
                    ));
                } else {
                    vols.push(format!(
                        "      - name: {}\n        emptyDir: {{}}",
                        vol_name
                    ));
                }
            }
        }

        let mounts_yaml = if mounts.is_empty() {
            String::new()
        } else {
            format!("        volumeMounts:\n{}\n", mounts.join("\n"))
        };
        let vols_yaml = if vols.is_empty() {
            String::new()
        } else {
            format!("      volumes:\n{}\n", vols.join("\n"))
        };
        (mounts_yaml, vols_yaml)
    };

    // Build Service ports YAML
    let service_ports_yaml = if ports.is_empty() {
        String::new()
    } else {
        let svc_port_entries: Vec<String> = ports
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                let parts: Vec<&str> = p.split(':').collect();
                if parts.len() == 2 {
                    let host_port = strip_proto(parts[0]).parse::<u32>().ok()?;
                    let container_port = strip_proto(parts[1]).parse::<u32>().ok()?;
                    // NodePort must be in range 30000-32767; map host ports accordingly
                    let node_port = if (30000..=32767).contains(&host_port) {
                        Some(host_port)
                    } else {
                        None
                    };
                    let mut entry = format!(
                        "  - name: port-{}\n    port: {}\n    targetPort: {}",
                        i, container_port, container_port
                    );
                    if let Some(np) = node_port {
                        entry.push_str(&format!("\n    nodePort: {}", np));
                    }
                    Some(entry)
                } else {
                    let port = strip_proto(parts[0]).parse::<u32>().ok()?;
                    Some(format!("  - name: port-{}\n    port: {}\n    targetPort: {}", i, port, port))
                }
            })
            .collect();
        if svc_port_entries.is_empty() {
            String::new()
        } else {
            format!("  ports:\n{}\n", svc_port_entries.join("\n"))
        }
    };

    // Assemble the Deployment YAML
    let mut yaml = format!(
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {container_name}
  namespace: {namespace}
  labels:
    app: {container_name}
    wolfstack/app: {app_name}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app: {container_name}
  template:
    metadata:
      labels:
        app: {container_name}
    spec:
      containers:
      - name: {container_name}
        image: {image}
{container_ports}{env}{volume_mounts}{volumes_spec}"#,
        container_name = container_name,
        namespace = namespace,
        app_name = app_name,
        replicas = replicas,
        image = image,
        container_ports = container_ports_yaml,
        env = env_yaml,
        volume_mounts = volume_mounts_yaml,
        volumes_spec = volumes_yaml,
    );

    // Only create a Service if the app exposes ports
    if !service_ports_yaml.is_empty() {
        yaml.push_str(&format!(
            r#"---
apiVersion: v1
kind: Service
metadata:
  name: {container_name}
  namespace: {namespace}
spec:
  selector:
    app: {container_name}
{service_ports}  type: NodePort
"#,
            container_name = container_name,
            namespace = namespace,
            service_ports = service_ports_yaml,
        ));
    }

    apply_yaml(kubeconfig, &yaml)
}

/// Generate a shell script to uninstall a Kubernetes distribution from this node
pub fn uninstall_script(cluster_type: &str) -> Result<String, String> {
    let script = match cluster_type {
        "k3s" => r#"
echo 'Stopping k3s services...'
systemctl stop k3s 2>/dev/null || true
systemctl stop k3s-agent 2>/dev/null || true

if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
    echo 'Running k3s server uninstall script...'
    /usr/local/bin/k3s-uninstall.sh
elif [ -f /usr/local/bin/k3s-agent-uninstall.sh ]; then
    echo 'Running k3s agent uninstall script...'
    /usr/local/bin/k3s-agent-uninstall.sh
else
    echo 'No k3s uninstall script found, cleaning up manually...'
    systemctl disable k3s k3s-agent 2>/dev/null || true
    rm -f /usr/local/bin/k3s /usr/local/bin/kubectl /usr/local/bin/crictl /usr/local/bin/ctr
    rm -rf /etc/rancher/k3s /var/lib/rancher/k3s /run/k3s
    rm -f /etc/systemd/system/k3s.service /etc/systemd/system/k3s-agent.service
    systemctl daemon-reload
fi
echo 'k3s uninstalled.'
"#,
        "microk8s" | "micro_k8s" => r#"
echo 'Removing MicroK8s...'
microk8s stop 2>/dev/null || true
snap remove microk8s --purge 2>/dev/null || true
echo 'MicroK8s uninstalled.'
"#,
        "kubeadm" | "k8s" => r#"
echo 'Resetting kubeadm...'
kubeadm reset -f 2>/dev/null || true
echo 'Removing kubernetes packages...'
if command -v apt-get &>/dev/null; then
    apt-get purge -y kubeadm kubelet kubectl 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
elif command -v dnf &>/dev/null; then
    dnf remove -y kubeadm kubelet kubectl 2>/dev/null || true
elif command -v yum &>/dev/null; then
    yum remove -y kubeadm kubelet kubectl 2>/dev/null || true
elif command -v zypper &>/dev/null; then
    zypper remove -y kubeadm kubelet kubectl 2>/dev/null || true
fi
rm -rf /etc/kubernetes /var/lib/kubelet /var/lib/etcd /root/.kube
echo 'kubeadm uninstalled.'
"#,
        "k0s" => r#"
echo 'Stopping k0s...'
k0s stop 2>/dev/null || true
echo 'Resetting k0s...'
k0s reset --cri-socket docker:unix:///var/run/docker.sock 2>/dev/null || k0s reset 2>/dev/null || true
rm -rf /var/lib/k0s /etc/k0s /usr/local/bin/k0s
echo 'k0s uninstalled.'
"#,
        "rke2" => r#"
echo 'Stopping RKE2 services...'
systemctl stop rke2-server 2>/dev/null || true
systemctl stop rke2-agent 2>/dev/null || true

if [ -f /usr/local/bin/rke2-uninstall.sh ]; then
    echo 'Running RKE2 server uninstall script...'
    /usr/local/bin/rke2-uninstall.sh
elif [ -f /usr/local/bin/rke2-agent-uninstall.sh ]; then
    echo 'Running RKE2 agent uninstall script...'
    /usr/local/bin/rke2-agent-uninstall.sh
else
    echo 'No RKE2 uninstall script found, cleaning up manually...'
    systemctl disable rke2-server rke2-agent 2>/dev/null || true
    rm -rf /etc/rancher/rke2 /var/lib/rancher/rke2 /usr/local/bin/rke2
    rm -f /etc/systemd/system/rke2-server.service /etc/systemd/system/rke2-agent.service
    systemctl daemon-reload
fi
echo 'RKE2 uninstalled.'
"#,
        _ => return Err(format!("Unknown distribution: {}", cluster_type)),
    };
    Ok(script.to_string())
}

// ─── AI Health Summary ───

/// Build a text summary of all Kubernetes clusters for the AI health monitor.
/// Returns None if no clusters are registered.
pub fn health_summary() -> Option<String> {
    let clusters = list_clusters();
    if clusters.is_empty() {
        return None;
    }

    let mut lines = Vec::new();
    lines.push("Kubernetes Clusters:".to_string());

    for cluster in &clusters {
        let status = get_cluster_status(&cluster.kubeconfig_path);
        let health = if status.healthy { "Healthy" } else { "UNHEALTHY" };
        lines.push(format!(
            "  Cluster '{}' ({}): {} — {}/{} nodes ready, {}/{} pods running, {} namespaces, API {}",
            cluster.name,
            cluster.cluster_type,
            health,
            status.nodes_ready, status.nodes_total,
            status.pods_running, status.pods_total,
            status.namespaces,
            status.api_version,
        ));

        // Get nodes and flag any NotReady
        let nodes = get_nodes(&cluster.kubeconfig_path);
        if nodes.is_empty() {
            // Try insecure fallback
            let nodes = get_nodes_insecure(&cluster.kubeconfig_path);
            for n in &nodes {
                if n.status != "Ready" {
                    lines.push(format!("    WARNING: Node '{}' status: {} (role: {})", n.name, n.status, n.roles));
                }
            }
        } else {
            for n in &nodes {
                if n.status != "Ready" {
                    lines.push(format!("    WARNING: Node '{}' status: {} (role: {})", n.name, n.status, n.roles));
                }
            }
        }

        // Get pods and flag problematic ones
        let pods = get_pods(&cluster.kubeconfig_path, None);
        let pods = if pods.is_empty() {
            get_pods_insecure(&cluster.kubeconfig_path, None)
        } else {
            pods
        };
        let mut problems: Vec<String> = Vec::new();
        for p in &pods {
            let is_problem = match p.status.as_str() {
                "Failed" | "Unknown" => true,
                "Pending" => true,
                _ => p.restarts >= 10,
            };
            if is_problem {
                problems.push(format!(
                    "    {} Pod '{}' in {}: status={}, restarts={}, ready={}",
                    if p.status == "Failed" || p.status == "Unknown" { "CRITICAL:" } else { "WARNING:" },
                    p.name, p.namespace, p.status, p.restarts, p.ready,
                ));
            }
        }
        if !problems.is_empty() {
            // Cap at 15 to avoid overwhelming the AI
            for line in problems.iter().take(15) {
                lines.push(line.clone());
            }
            if problems.len() > 15 {
                lines.push(format!("    ... and {} more problem pods", problems.len() - 15));
            }
        }
    }

    Some(lines.join("\n"))
}
