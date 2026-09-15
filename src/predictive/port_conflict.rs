// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Host-port collision and silent-publish-failure detector.
//!
//! Two failure modes this analyzer surfaces:
//!
//! 1. **Silent publish failure.** A Docker container's
//!    `HostConfig.PortBindings` requested a host port, but
//!    `NetworkSettings.Ports` shows the daemon never bound it. The
//!    container is running, but the URL the operator sent to their
//!    users is dead. This is the bug Klas hit after a reboot:
//!    compose project A grabbed the host port first, project B's
//!    container started anyway, and the Docker tab silently showed
//!    no ports for the second container. Severity: **High** — a
//!    user-visible service is offline and the operator wasn't told.
//!
//! 2. **Host-port collision detected.** Two or more owners want the
//!    same `(host_ip, host_port, proto)` tuple — could be two Docker
//!    containers (only one will actually bind), a Docker container
//!    plus a host process, or two host processes. We don't know
//!    which is "right"; we just report the collision so the operator
//!    can choose. Severity: **Warn**.
//!
//! Both findings auto-resolve when the underlying state clears (the
//! second container is rebuilt with a different port; the conflicting
//! host process is stopped). Scope keys include the host_ip+port+proto
//! tuple so `covered_scopes` can drive the resolver correctly.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::containers::{HostListener, PortMapping};
use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
};

/// Finding type for "container requested a host port but daemon never
/// bound it". One per affected container; scope keyed on container
/// name.
pub const FINDING_TYPE_UNPUBLISHED: &str = "docker_port_publish_failed";

/// Finding type for "two or more owners want the same host port".
/// One per (host_ip, host_port, proto) tuple; scope keyed on that
/// tuple so the inbox card collapses cross-tick.
pub const FINDING_TYPE_CONFLICT: &str = "host_port_conflict_detected";

/// One owner of a `(host_ip, host_port, proto)` tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Owner {
    /// A Docker container whose `NetworkSettings.Ports` confirms it
    /// holds this binding.
    DockerContainerPublished(String),
    /// A Docker container whose `HostConfig.PortBindings` requested
    /// this binding but `NetworkSettings.Ports` does NOT confirm it —
    /// i.e. the daemon never published it. Still listed as a
    /// requestor so the operator sees who's asking for the port.
    DockerContainerRequested(String),
    /// A non-Docker host process bound to this port. Captured from
    /// `ss -tlnp` / `ss -ulnp`. The string is the process name (or
    /// empty when ss couldn't read /proc due to a permission issue).
    HostProcess(String),
}

impl Owner {
    pub fn label(&self) -> String {
        match self {
            Owner::DockerContainerPublished(n) => format!("Docker container `{}` (published)", n),
            Owner::DockerContainerRequested(n) => format!("Docker container `{}` (requested but UNPUBLISHED)", n),
            Owner::HostProcess(p) if p.is_empty() => "host process (unknown)".to_string(),
            Owner::HostProcess(p) => format!("host process `{}`", p),
        }
    }
}

/// One detected collision: 2+ owners on the same host endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub host_ip: String,
    pub host_port: u16,
    pub proto: String,
    pub owners: Vec<Owner>,
}

impl Conflict {
    pub fn endpoint_label(&self) -> String {
        let ip = if self.host_ip.is_empty() || self.host_ip == "0.0.0.0" {
            "*".to_string()
        } else {
            self.host_ip.clone()
        };
        format!("{}:{}/{}", ip, self.host_port, self.proto)
    }

    pub fn resource_id(&self) -> String {
        format!(
            "port-conflict:{}:{}:{}",
            self.proto,
            if self.host_ip.is_empty() { "0.0.0.0" } else { &self.host_ip },
            self.host_port,
        )
    }
}

/// One container with at least one requested-but-unpublished port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpublishedContainer {
    pub container: String,
    /// Per-mapping breakdown — the operator wants to see which host
    /// port specifically failed (vs. all of them just stating the
    /// container is broken).
    pub mappings: Vec<PortMapping>,
}

impl UnpublishedContainer {
    pub fn resource_id(&self) -> String {
        format!("port-unpublished:docker:{}", self.container)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortConflictFacts {
    /// True iff we successfully sampled both Docker and host listener
    /// state on this tick. False means we should not auto-resolve
    /// anything — the data source is down.
    pub scanned: bool,
    pub conflicts: Vec<Conflict>,
    pub unpublished: Vec<UnpublishedContainer>,
    /// Every Docker container we evaluated this tick, regardless of
    /// state or whether we emitted a finding. Drives covered_scopes:
    /// when a container goes from "unpublished while running" back to
    /// stopped, the resolver clears the stale `port_publish_failed`
    /// proposal because the container is in `evaluated_containers`
    /// but not in `unpublished`. Without this, stopping a flagged
    /// container would leave its red finding in the inbox forever.
    pub evaluated_containers: Vec<String>,
    /// Every (host_ip, host_port, proto) tuple we saw on this tick,
    /// for the same auto-resolve reason: when a conflict clears
    /// (one owner releases the port), the resolver needs the scope
    /// in its covered set to drop the stale conflict proposal.
    pub evaluated_endpoints: Vec<(String, u16, String)>,
}

/// Sample current port state. Synchronous, runs inside `spawn_blocking`
/// from the orchestrator. Mirrors `vulnerability::sample_now` shape.
pub fn sample_now() -> PortConflictFacts {
    let containers = crate::containers::docker_list_all_cached();
    let host_listeners = crate::containers::sample_host_listeners();
    detect(&containers, &host_listeners)
}

pub async fn sample_now_async(timeout: Duration) -> PortConflictFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => PortConflictFacts::default(),
    }
}

/// Pure detection logic — separated from sampling so unit tests can
/// drive it with synthetic inputs without touching the Docker daemon
/// or `ss`. Builds an `(host_ip, host_port, proto) → Vec<Owner>`
/// owner map, then emits a `Conflict` for every entry with more than
/// one owner. Containers with at least one unpublished requested
/// mapping are emitted as `UnpublishedContainer` records.
pub fn detect(
    containers: &[crate::containers::ContainerInfo],
    host_listeners: &[HostListener],
) -> PortConflictFacts {
    let mut owners: HashMap<(String, u16, String), Vec<Owner>> = HashMap::new();
    let mut unpublished_by_container: HashMap<String, Vec<PortMapping>> = HashMap::new();

    // Step 1: walk every Docker container's port_mappings. Each
    // requested binding contributes one Owner entry; whether it's
    // Published or Requested-but-unpublished depends on the flag.
    //
    // Stopped containers are intentionally skipped: it is NORMAL for
    // a stopped container's NetworkSettings.Ports to be empty (the
    // daemon doesn't hold bindings for non-running containers), so
    // calling that "unpublished" would spam the inbox with every
    // stopped container the operator has ever created. We only care
    // about RUNNING containers whose published state diverges from
    // their requested state — that's the genuine bug case.
    for c in containers {
        if c.runtime != "docker" { continue; }
        let is_running = c.state == "running";
        for m in &c.port_mappings {
            if m.host_port == 0 { continue; } // skip random/unparsed
            let key = ip_key(&m.host_ip, m.host_port, &m.proto);
            let entry = owners.entry(key).or_default();
            if m.published {
                entry.push(Owner::DockerContainerPublished(c.name.clone()));
            } else if is_running {
                entry.push(Owner::DockerContainerRequested(c.name.clone()));
                unpublished_by_container
                    .entry(c.name.clone())
                    .or_default()
                    .push(m.clone());
            }
            // Stopped + unpublished → expected state. Skip silently.
        }
    }

    // Step 2: walk host listeners. Add an Owner entry for each.
    // Skip Docker's own proxy entries — the daemon's `docker-proxy`
    // userspace listener IS the published binding, and counting it
    // again would flag every healthy Docker port as a "conflict" with
    // itself.
    for hl in host_listeners {
        if hl.process == "docker-proxy" { continue; }
        let key = ip_key(&hl.host_ip, hl.host_port, &hl.proto);
        owners.entry(key).or_default().push(Owner::HostProcess(hl.process.clone()));
    }

    // Step 3: any bucket with > 1 owner is a conflict, but only when
    // at least one owner is a Docker container.
    //
    // Two pure host processes on the same port is usually SO_REUSEPORT
    // (mDNS on :5353/udp via systemd-resolved + avahi-daemon, multiple
    // workers behind a load-balancer pattern, etc.) — flagging that
    // as a "conflict" would spam every Linux box. The bug class
    // WolfStack actually catches is the Docker side: silent unbound
    // ports after a compose collision (Klas's case) or container vs.
    // host service contention. We require Docker involvement so the
    // signal stays high.
    //
    // Self-conflicts (a single Docker container with both v4 and v6
    // entries for the same binding) are suppressed via the de-dup of
    // owners by name + role.
    let mut conflicts: Vec<Conflict> = Vec::new();
    for ((host_ip, host_port, proto), os) in owners {
        if os.len() < 2 { continue; }
        let mut deduped: Vec<Owner> = Vec::new();
        for o in os {
            if !deduped.contains(&o) { deduped.push(o); }
        }
        if deduped.len() < 2 { continue; }
        let docker_involved = deduped.iter().any(|o| matches!(
            o,
            Owner::DockerContainerPublished(_) | Owner::DockerContainerRequested(_),
        ));
        if !docker_involved { continue; }
        conflicts.push(Conflict {
            host_ip,
            host_port,
            proto,
            owners: deduped,
        });
    }
    // Stable order: by host_port ascending so the inbox layout is
    // deterministic across ticks.
    conflicts.sort_by_key(|c| (c.host_port, c.proto.clone(), c.host_ip.clone()));

    // Step 4: emit unpublished-container records.
    let mut unpublished: Vec<UnpublishedContainer> = unpublished_by_container
        .into_iter()
        .map(|(container, mappings)| UnpublishedContainer { container, mappings })
        .collect();
    unpublished.sort_by(|a, b| a.container.cmp(&b.container));

    let evaluated_containers: Vec<String> = containers.iter()
        .filter(|c| c.runtime == "docker")
        .map(|c| c.name.clone())
        .collect();
    let mut evaluated_endpoints: Vec<(String, u16, String)> = Vec::new();
    for c in containers {
        if c.runtime != "docker" { continue; }
        for m in &c.port_mappings {
            if m.host_port == 0 { continue; }
            let key = ip_key(&m.host_ip, m.host_port, &m.proto);
            if !evaluated_endpoints.contains(&key) {
                evaluated_endpoints.push(key);
            }
        }
    }
    for hl in host_listeners {
        if hl.process == "docker-proxy" { continue; }
        let key = ip_key(&hl.host_ip, hl.host_port, &hl.proto);
        if !evaluated_endpoints.contains(&key) {
            evaluated_endpoints.push(key);
        }
    }

    PortConflictFacts {
        scanned: true,
        conflicts,
        unpublished,
        evaluated_containers,
        evaluated_endpoints,
    }
}

// HostListener / sample_host_listeners / parse_ss_output live in
// crate::containers — keeping the listener parser close to the
// container listing API avoids the layer violation we'd get by
// having containers/mod.rs reach back up into predictive::.

/// Build the lookup key for the conflict map. Wildcard `0.0.0.0`
/// addresses on IPv4 collapse to the same bucket regardless of
/// whether they came from PortBindings (`""`) or ss (`"0.0.0.0"`).
/// `::` (v6 wildcard) is its own bucket — a process binding `::`
/// does conflict with `0.0.0.0` in practice on dual-stack Linux, but
/// we'd need explicit IPv6 to know that. Treat them separately to
/// avoid false positives.
fn ip_key(host_ip: &str, host_port: u16, proto: &str) -> (String, u16, String) {
    let ip = if host_ip.is_empty() || host_ip == "*" {
        "0.0.0.0".to_string()
    } else {
        host_ip.to_string()
    };
    (ip, host_port, proto.to_string())
}

/// Public analyzer entry point. Emits two finding types:
///   * `docker_port_publish_failed` — one per container with at least
///     one unpublished requested mapping (severity: High).
///   * `host_port_conflict_detected` — one per (host_ip, port, proto)
///     bucket with 2+ owners (severity: Warn).
pub fn analyze(
    ctx: &Context,
    facts: &PortConflictFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    for u in &facts.unpublished {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(u.resource_id()),
        };
        if acks.suppresses(FINDING_TYPE_UNPUBLISHED, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE_UNPUBLISHED, &scope) { continue; }
        out.push(build_unpublished_proposal(u, &scope));
    }

    for c in &facts.conflicts {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(c.resource_id()),
        };
        if acks.suppresses(FINDING_TYPE_CONFLICT, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE_CONFLICT, &scope) { continue; }
        out.push(build_conflict_proposal(c, &scope));
    }

    out
}

/// Scopes covered by THIS sample tick — used by the orchestrator's
/// auto-resolve pass. We only return scopes when `scanned` is true;
/// otherwise the resolver would close findings the moment Docker is
/// unreachable.
pub fn covered_scopes(
    ctx: &Context,
    facts: &PortConflictFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    let mut out: Vec<(String, ProposalScope)> = Vec::new();
    // Cover EVERY Docker container we evaluated this tick — not just
    // the ones we flagged. When a container that was previously
    // flagged stops (or its port becomes published), it disappears
    // from `unpublished` but stays in `evaluated_containers`, so the
    // resolver sees "we looked, no longer broken" and clears the
    // stale finding from the inbox.
    for name in &facts.evaluated_containers {
        out.push((FINDING_TYPE_UNPUBLISHED.to_string(), ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("port-unpublished:docker:{}", name)),
        }));
    }
    // Same logic for conflicts: cover every endpoint we looked at,
    // whether or not it had > 1 owner. A conflict clearing now
    // auto-resolves on the next tick because the endpoint is still
    // in the covered set but not in `conflicts`.
    for (host_ip, host_port, proto) in &facts.evaluated_endpoints {
        let ip_for_id = if host_ip.is_empty() { "0.0.0.0".to_string() } else { host_ip.clone() };
        let resource_id = format!("port-conflict:{}:{}:{}", proto, ip_for_id, host_port);
        out.push((FINDING_TYPE_CONFLICT.to_string(), ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(resource_id),
        }));
    }
    out
}

fn build_unpublished_proposal(u: &UnpublishedContainer, scope: &ProposalScope) -> Proposal {
    let mapping_summary: Vec<String> = u.mappings.iter()
        .map(|m| {
            let ip = if m.host_ip.is_empty() || m.host_ip == "0.0.0.0" {
                "*".to_string()
            } else {
                m.host_ip.clone()
            };
            format!("{}:{} → :{}/{}", ip, m.host_port, m.container_port, m.proto)
        })
        .collect();
    let title = format!(
        "Docker container `{}` has {} unpublished port{} — service is offline",
        u.container, u.mappings.len(), if u.mappings.len() == 1 { "" } else { "s" },
    );
    let why = format!(
        "Docker accepted the start of `{c}` and the container is running, but the daemon \
         did NOT bind the host port{s} {ports} that compose / `docker run -p` asked for. \
         The most common cause is a host-port collision: another container or process \
         had already grabbed the port, so Docker's bind() failed silently after the \
         container was created. Anyone hitting that URL is talking to the wrong service \
         (or to nothing at all). Open the conflict finding to see who else is on the \
         port; rebuild `{c}` with a free host port, or stop the conflicting owner.",
        c = u.container,
        s = if u.mappings.len() == 1 { "" } else { "s" },
        ports = mapping_summary.join(", "),
    );
    let mut evidence = vec![Evidence {
        label: "Container".into(),
        value: u.container.clone(),
        detail: Some("`docker ps` shows it running, but published ports are missing".into()),
        links: Vec::new(),
    }];
    for m in &u.mappings {
        let ip = if m.host_ip.is_empty() || m.host_ip == "0.0.0.0" {
            "*".to_string()
        } else {
            m.host_ip.clone()
        };
        evidence.push(Evidence {
            label: format!("Unpublished {}/{}", m.host_port, m.proto),
            value: format!("{}:{} → container :{}", ip, m.host_port, m.container_port),
            detail: Some("Requested in HostConfig.PortBindings; missing from NetworkSettings.Ports".into()),
            links: Vec::new(),
        });
    }
    let commands = vec![
        format!("docker logs --tail 50 {}", u.container),
        format!("docker inspect {} --format '{{{{json .NetworkSettings.Ports}}}}'", u.container),
        format!("docker stop {} && docker start {}", u.container, u.container),
    ];
    Proposal::new_rule(
        FINDING_TYPE_UNPUBLISHED,
        Severity::High,
        title,
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "Find the conflicting owner (open the related host-port \
                conflict finding if one exists), free the port, then restart this \
                container. If two of YOUR own containers want the same host port, \
                edit the compose file or `docker run -p` line to give each a unique \
                host port. Restart alone won't fix a real collision — the next \
                start will lose the same race.".into(),
            commands,
        },
        scope.clone(),
    )
}

fn build_conflict_proposal(c: &Conflict, scope: &ProposalScope) -> Proposal {
    let endpoint = c.endpoint_label();
    let title = format!(
        "Host-port conflict on {} — {} owners",
        endpoint, c.owners.len(),
    );
    let why = format!(
        "WolfStack found {} different owners claiming {}. Only one of them is \
         actually bound; the others are either silently failing to publish \
         (Docker container) or have their `bind()` calls rejected (host \
         process). This is the failure mode where `docker compose up` \
         appears to succeed but a service goes dead — the second-to-start \
         container's request is registered without a published port.",
        c.owners.len(), endpoint,
    );
    let mut evidence = vec![
        Evidence {
            label: "Endpoint".into(),
            value: endpoint.clone(),
            detail: Some(format!("{} owners contending for this host port", c.owners.len())),
            links: Vec::new(),
        },
    ];
    for (i, o) in c.owners.iter().enumerate() {
        evidence.push(Evidence {
            label: format!("Owner {}", i + 1),
            value: o.label(),
            detail: None,
            links: Vec::new(),
        });
    }
    Proposal::new_rule(
        FINDING_TYPE_CONFLICT,
        Severity::Warn,
        title,
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "Decide which owner should keep the port. Stop or \
                reconfigure the others. For two Docker containers, change one \
                container's host-port mapping to a free port and recreate it. \
                For a Docker container vs. a host service, either pick a \
                different host port for the container or stop the host service.".into(),
            commands: vec![
                format!("ss -tlnp 'sport = :{}' || true", c.host_port),
                format!("ss -ulnp 'sport = :{}' || true", c.host_port),
                format!("docker ps --format 'table {{{{.Names}}}}\\t{{{{.Ports}}}}' | grep ':{}'", c.host_port),
            ],
        },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::{ContainerInfo, PortMapping};

    /// Test helper. Defaults to `state: "running"` because the
    /// detector intentionally ignores stopped containers; tests that
    /// want a stopped container should reassign `state` after.
    fn mk_container(name: &str, mappings: Vec<PortMapping>) -> ContainerInfo {
        ContainerInfo {
            id: name.into(),
            name: name.into(),
            image: "img".into(),
            status: "Up".into(),
            state: "running".into(),
            created: String::new(),
            ports: Vec::new(),
            runtime: "docker".into(),
            ip_address: String::new(),
            autostart: false,
            hostname: String::new(),
            storage_path: None,
            disk_usage: None,
            disk_total: None,
            fs_type: None,
            version: None,
            services: Vec::new(),
            gateway: String::new(),
            mac_address: String::new(),
            network_name: String::new(),
            restart_count: None,
            port_mappings: mappings,
            possible_ghost: false,
            ha_replica: false,
        }
    }

    fn mk_pm(host_ip: &str, host_port: u16, container_port: u16, proto: &str, published: bool) -> PortMapping {
        PortMapping {
            host_ip: host_ip.into(),
            host_port,
            container_port,
            proto: proto.into(),
            published,
        }
    }

    #[test]
    fn detects_two_containers_on_same_host_port() {
        let containers = vec![
            mk_container("a", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", true)]),
            mk_container("b", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", false)]),
        ];
        let facts = detect(&containers, &[]);
        assert_eq!(facts.conflicts.len(), 1, "two containers on :8080 must produce one conflict");
        assert_eq!(facts.conflicts[0].host_port, 8080);
        assert_eq!(facts.unpublished.len(), 1,
            "container `b` had a requested-but-unpublished mapping");
        assert_eq!(facts.unpublished[0].container, "b");
    }

    #[test]
    fn detects_container_vs_host_listener() {
        let containers = vec![
            mk_container("svc", vec![mk_pm("0.0.0.0", 9000, 9000, "tcp", false)]),
        ];
        let host = vec![HostListener {
            host_ip: "0.0.0.0".into(),
            host_port: 9000,
            proto: "tcp".into(),
            process: "minio".into(),
        }];
        let facts = detect(&containers, &host);
        assert_eq!(facts.conflicts.len(), 1);
        let owners = &facts.conflicts[0].owners;
        assert!(owners.iter().any(|o| matches!(o, Owner::DockerContainerRequested(n) if n == "svc")));
        assert!(owners.iter().any(|o| matches!(o, Owner::HostProcess(p) if p == "minio")));
    }

    #[test]
    fn ignores_docker_proxy_self_listener() {
        // Docker's own user-space proxy WOULD show in `ss` for every
        // published port. Without the docker-proxy filter this would
        // tag every healthy container as "in conflict" with itself.
        let containers = vec![
            mk_container("a", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", true)]),
        ];
        let host = vec![HostListener {
            host_ip: "0.0.0.0".into(),
            host_port: 8080,
            proto: "tcp".into(),
            process: "docker-proxy".into(),
        }];
        let facts = detect(&containers, &host);
        assert_eq!(facts.conflicts.len(), 0,
            "docker-proxy entries on a published port must NOT be flagged");
    }

    #[test]
    fn does_not_flag_dual_stack_v4_v6_for_same_container() {
        // One container with two PortMapping entries (one v4, one v6)
        // for the same logical binding must NOT produce a self-
        // conflict. We don't currently emit dual-stack PortBindings,
        // but the de-dup in `detect` guards against it anyway.
        let mut a = mk_container("a", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", true)]);
        a.port_mappings.push(mk_pm("::", 8080, 80, "tcp", true));
        let facts = detect(&[a], &[]);
        // Different IPs → different keys → no collision.
        assert_eq!(facts.conflicts.len(), 0);
        assert_eq!(facts.unpublished.len(), 0);
    }

    #[test]
    fn does_not_flag_two_host_processes_sharing_udp_port() {
        // mDNS on :5353/udp is bound by both systemd-resolved and
        // avahi-daemon via SO_REUSEPORT on most Linux distros — that
        // is intentional and not a conflict the operator should chase.
        // Same pattern with worker pools sharing TCP listening sockets.
        let host = vec![
            HostListener {
                host_ip: "0.0.0.0".into(), host_port: 5353,
                proto: "udp".into(), process: "systemd-resolve".into(),
            },
            HostListener {
                host_ip: "0.0.0.0".into(), host_port: 5353,
                proto: "udp".into(), process: "avahi-daemon".into(),
            },
        ];
        let facts = detect(&[], &host);
        assert_eq!(facts.conflicts.len(), 0,
            "two host processes on the same port = usually SO_REUSEPORT, not a conflict");
    }

    #[test]
    fn stopped_container_with_unpublished_ports_is_silent() {
        // A stopped container's NetworkSettings.Ports is empty by
        // definition — the daemon doesn't hold bindings for non-
        // running containers. Without this guard the inbox would
        // light up red for every container the operator ever stopped.
        let mut c = mk_container("stopped-svc", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", false)]);
        c.state = "exited".into();
        let facts = detect(&[c], &[]);
        assert_eq!(facts.unpublished.len(), 0,
            "stopped containers must not be flagged as unpublished — that's the expected state");
        assert_eq!(facts.conflicts.len(), 0,
            "a stopped container's request alone is not a host-port conflict");
    }

    #[test]
    fn skips_lxc_containers_in_collision_check() {
        let mut lxc = mk_container("ct1", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", true)]);
        lxc.runtime = "lxc".into();
        let containers = vec![
            lxc,
            mk_container("d", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", true)]),
        ];
        // Only the docker container counts; LXC's port_mappings is
        // always empty in the listing path anyway, but explicitly
        // ignore non-docker runtimes so future runtime additions
        // don't break the analyzer.
        let facts = detect(&containers, &[]);
        assert_eq!(facts.conflicts.len(), 0);
    }

    #[test]
    fn unpublished_emits_high_severity_proposal() {
        use crate::predictive::Context;
        use crate::predictive::proposal::ProposalStore;
        let ctx = Context::for_node("n");
        let containers = vec![
            mk_container("svc", vec![mk_pm("0.0.0.0", 9000, 9000, "tcp", false)]),
        ];
        let facts = detect(&containers, &[]);
        let store = ProposalStore::default();
        let acks = AckStore::default();
        let props = analyze(&ctx, &facts, &acks, &store);
        let unpub = props.iter().find(|p| p.finding_type == FINDING_TYPE_UNPUBLISHED)
            .expect("unpublished proposal must be emitted");
        assert_eq!(unpub.severity, Severity::High,
            "unpublished port = user-visible offline service = High");
        assert!(unpub.title.contains("svc"));
    }

    #[test]
    fn parse_ss_output_handles_v4_wildcard_with_process() {
        let raw = "State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n\
                   LISTEN   0       1024    0.0.0.0:8553        0.0.0.0:*          users:((\"wolfstack\",pid=1485,fd=23))";
        let entries = crate::containers::parse_ss_output(raw, "tcp");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host_ip, "0.0.0.0");
        assert_eq!(entries[0].host_port, 8553);
        assert_eq!(entries[0].process, "wolfstack");
    }

    #[test]
    fn parse_ss_output_handles_bracketed_v6() {
        let raw = "State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n\
                   LISTEN   0       1024    [::]:9000           [::]:*             users:((\"node\",pid=2,fd=4))";
        let entries = crate::containers::parse_ss_output(raw, "tcp");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host_ip, "::");
        assert_eq!(entries[0].host_port, 9000);
        assert_eq!(entries[0].process, "node");
    }

    #[test]
    fn parse_ss_output_handles_wildcard_star_form() {
        let raw = "State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n\
                   LISTEN   0       1024    *:53                *:*";
        let entries = crate::containers::parse_ss_output(raw, "udp");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host_ip, "0.0.0.0");
        assert_eq!(entries[0].host_port, 53);
        assert_eq!(entries[0].process, "");
    }

    #[test]
    fn covered_scopes_empty_when_not_scanned() {
        let ctx = crate::predictive::Context::for_node("n");
        let facts = PortConflictFacts {
            scanned: false,
            conflicts: Vec::new(),
            unpublished: Vec::new(),
            evaluated_containers: Vec::new(),
            evaluated_endpoints: Vec::new(),
        };
        let cov = covered_scopes(&ctx, &facts);
        assert!(cov.is_empty(),
            "must not advertise coverage when sampling failed — would falsely auto-resolve");
    }

    #[test]
    fn covered_scopes_includes_every_evaluated_container_and_endpoint() {
        // Two docker containers, both touching port 8080 → covered
        // scope set = both container scopes + the one endpoint scope.
        // The "every container, not just flagged" rule is what lets a
        // resolved finding clear from the inbox once the container
        // stops or the conflict goes away.
        let ctx = crate::predictive::Context::for_node("n");
        let containers = vec![
            mk_container("a", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", true)]),
            mk_container("b", vec![mk_pm("0.0.0.0", 8080, 80, "tcp", false)]),
        ];
        let facts = detect(&containers, &[]);
        let cov = covered_scopes(&ctx, &facts);
        let unpub_count = cov.iter()
            .filter(|(t, _)| t == FINDING_TYPE_UNPUBLISHED).count();
        let conflict_count = cov.iter()
            .filter(|(t, _)| t == FINDING_TYPE_CONFLICT).count();
        assert_eq!(unpub_count, 2,
            "must cover BOTH containers — including `a` which had a published port — \
             so the resolver can clear stale findings on previously-flagged ones");
        assert_eq!(conflict_count, 1,
            "must cover the single endpoint we evaluated");
    }

    #[test]
    fn covered_scopes_includes_stopped_container_so_resolver_can_clear() {
        // The original Klas case in production: a flagged running
        // container later stops. The resolver needs to see its
        // scope in covered_scopes to clear the stale red finding.
        let ctx = crate::predictive::Context::for_node("n");
        let mut stopped = mk_container("offline", vec![mk_pm("0.0.0.0", 9999, 80, "tcp", false)]);
        stopped.state = "exited".into();
        let facts = detect(&[stopped], &[]);
        // detect() doesn't flag this container (stopped), so unpublished is empty…
        assert_eq!(facts.unpublished.len(), 0);
        // …but covered_scopes still includes it so a previously-emitted
        // proposal with the same scope auto-resolves on this tick.
        let cov = covered_scopes(&ctx, &facts);
        assert!(cov.iter().any(|(t, s)|
            t == FINDING_TYPE_UNPUBLISHED &&
            s.resource_id.as_deref() == Some("port-unpublished:docker:offline")
        ), "stopped container's scope must still be covered for auto-resolve");
    }
}
