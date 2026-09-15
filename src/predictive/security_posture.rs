// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Security posture findings — Item 8 + partial Convergence C.
//!
//! First analyzer in the predictive pipeline whose severity depends
//! on `NetworkReachability` — this is the consumer that the
//! reachability classifier was built for. Same shape of finding
//! that `security.rs::scan_listening_services` and `scan_sshd_config`
//! produce, but routed through the unified Inbox so operators get:
//! - Snooze / dismiss / ack-as-intentional semantics
//! - Cluster-aware aggregation
//! - First-appearance notification dispatch on Critical/High
//!
//! ## Findings
//!
//! - `service_bound_publicly` — a well-known risky service is
//!   listening on an interface reachable from the public internet
//!   (per `NetworkReachability`). Severity by service-class +
//!   reachability matrix.
//! - `sshd_password_auth_enabled` — sshd has
//!   `PasswordAuthentication yes`. Severity higher when sshd is
//!   reachable from the public internet.
//! - `sshd_root_login_enabled` — sshd has `PermitRootLogin yes`.
//!   Severity higher when sshd is reachable from the public
//!   internet.
//!
//! ## Convergence note
//!
//! `security.rs` keeps its active-attack scans (SSH brute-force,
//! crypto miners, /tmp binaries, outbound suspicious) for now —
//! those are event-detection at a different cadence and the
//! convergence shape is non-trivial (they're "things happening
//! right now", not "posture that should be true"). Migrating them
//! is a follow-up; the duplication on these three POSTURE findings
//! is what this delta retires.

use std::time::Duration;

use crate::predictive::{
    Context, NetworkReachability, NetworkSnapshot, classify_bind,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    ack::AckStore,
};

pub const FINDING_SERVICE_PUBLIC: &str = "service_bound_publicly";
pub const FINDING_SSHD_PASSWORD_AUTH: &str = "sshd_password_auth_enabled";
pub const FINDING_SSHD_ROOT_LOGIN: &str = "sshd_root_login_enabled";
pub const FINDING_SCAN_DETECTOR_DISABLED: &str = "scan_detector_disabled";

/// Which transport a risky-port rule applies to.
///
/// Most entries are `Any`: an exposed Redis is an exposed Redis whether
/// you reached it over TCP or UDP. Reflection rules are the exception —
/// amplification is a UDP property, and firing them on a TCP listener
/// would be a false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortProto { Any, Tcp, Udp }

impl PortProto {
    fn matches(self, p: crate::predictive::SocketProtocol) -> bool {
        use crate::predictive::SocketProtocol as S;
        matches!(
            (self, p),
            (PortProto::Any, _) | (PortProto::Tcp, S::Tcp) | (PortProto::Udp, S::Udp)
        )
    }
}

/// What KIND of problem an exposed port is.
///
/// `Exposure` — someone reaches your data or your host.
/// `Reflection` — they never touch your data; they spoof your victim's
/// address, and your host does the attacking. The distinction matters
/// because the operator-facing message is completely different, and
/// because reflection is what gets a provider abuse notice raised
/// against you by a national CERT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RiskClass { Exposure, Reflection }

/// Well-known services that should generally not be reachable from
/// outside loopback. The bool flags "extreme blast radius" — Docker
/// API plain on the public internet is *catastrophic*; an exposed
/// PostgreSQL is bad but not as instantly-game-over.
///
/// rpcbind/portmap is the first `Reflection` entry. It is worth being
/// explicit about why it is here: it is almost never *needed*. On a
/// host with no NFS server and no NFSv3 client it registers nothing but
/// itself, yet ships enabled on most distros and answers the internet
/// on 111/udp with a 7-28x bandwidth amplification factor (CERT
/// TA14-017A). That combination — useless by default, loudly abusable,
/// and reported by CERTs to the hosting provider rather than to the
/// operator — is why an exposed portmapper is usually discovered via an
/// abuse ticket instead of by the person running the box.
const RISKY_PORTS: &[(u16, PortProto, RiskClass, &str, bool)] = &[
    (2375, PortProto::Any, RiskClass::Exposure,   "docker-api-plain", true),  // root via container escape, no auth
    (2376, PortProto::Any, RiskClass::Exposure,   "docker-api-tls",   false),
    (6379, PortProto::Any, RiskClass::Exposure,   "redis",            false),
    (27017,PortProto::Any, RiskClass::Exposure,   "mongodb",          false),
    (9200, PortProto::Any, RiskClass::Exposure,   "elasticsearch",    false),
    (3306, PortProto::Any, RiskClass::Exposure,   "mysql",            false),
    (5432, PortProto::Any, RiskClass::Exposure,   "postgres",         false),
    (11211,PortProto::Any, RiskClass::Exposure,   "memcached",        false),
    (5601, PortProto::Any, RiskClass::Exposure,   "kibana",           false),
    // UDP is the amplification vector — critical class, so a public
    // bind lands on Severity::Critical via the matrix below.
    (111,  PortProto::Udp, RiskClass::Reflection, "rpcbind-portmap",  true),
    // TCP/111 cannot be used for reflection (the handshake defeats
    // source spoofing), but it still enumerates RPC services and NFS
    // exports to anyone who asks. Real, lesser, non-critical.
    (111,  PortProto::Tcp, RiskClass::Exposure,   "rpcbind-portmap",  false),
];

/// Per-tick snapshot of sshd config state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshdConfig {
    pub password_auth: bool,
    pub root_login: bool,
}

/// Sample sshd config from the EFFECTIVE settings (`sshd -T`), so drop-in files
/// and Match blocks are honored — a `prohibit-password` drop-in reads as
/// not-root-login even when the main file still says `yes`.
pub fn sample_sshd_config_now() -> SshdConfig {
    SshdConfig {
        root_login: crate::security::sshd_effective("permitrootlogin").as_deref() == Some("yes"),
        password_auth: crate::security::sshd_effective("passwordauthentication").as_deref() == Some("yes"),
    }
}

pub async fn sample_sshd_config_now_async(timeout: Duration) -> SshdConfig {
    let fut = tokio::task::spawn_blocking(sample_sshd_config_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(c)) => c,
        _ => SshdConfig::default(),
    }
}

/// Run the analyzer. Consumes the network snapshot from `ctx` for
/// per-bind reachability classification.
pub fn analyze(
    ctx: &Context,
    sshd: &SshdConfig,
    scan_detector_enabled: bool,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    out.extend(analyze_listening_services(ctx, &ctx.network, acks, proposals));
    out.extend(analyze_sshd(ctx, sshd, &ctx.network, acks, proposals));
    out.extend(analyze_scan_detector(ctx, scan_detector_enabled, acks, proposals));
    out
}

/// Covered scopes for auto-resolve. Includes one entry per
/// (finding_type, scope) the analyzer evaluated this tick.
pub fn covered_scopes(
    ctx: &Context,
    sshd: &SshdConfig,
) -> Vec<(String, ProposalScope)> {
    let mut out = Vec::new();
    let snap = &ctx.network;
    for sock in &snap.listening_sockets {
        if let Some((_, proto_rule, _, _, _)) = lookup_risky(sock.port, sock.protocol) {
            out.push((
                FINDING_SERVICE_PUBLIC.to_string(),
                ProposalScope {
                    node_id: ctx.node_id.clone(),
                    // MUST match analyze_listening_services exactly, or a
                    // fixed finding never auto-resolves. Shared helper so
                    // the two cannot drift apart.
                    resource_id: Some(risky_resource_id(sock, proto_rule)),
                },
            ));
        }
    }
    // Always cover the sshd findings — the file either says yes
    // or no, so a clearance-from-yes-to-no should auto-resolve.
    let _ = sshd;
    let sshd_scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("sshd".into()),
    };
    out.push((FINDING_SSHD_PASSWORD_AUTH.to_string(), sshd_scope.clone()));
    out.push((FINDING_SSHD_ROOT_LOGIN.to_string(), sshd_scope));
    // Always cover the scan-detector posture so enabling it clears the
    // finding (analyze_scan_detector emits nothing once enabled).
    out.push((
        FINDING_SCAN_DETECTOR_DISABLED.to_string(),
        ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some("scan_detector".into()),
        },
    ));
    out
}

/// Resource id a risky-port finding is scoped to — what an ack silences
/// and what auto-resolve matches on.
///
/// Protocol is appended ONLY for protocol-specific rules, so 111/udp and
/// 111/tcp can be acked independently while every pre-existing `Any`
/// entry keeps a byte-identical id and no operator's existing ack is
/// invalidated.
fn risky_resource_id(
    sock: &crate::predictive::ListeningSocket,
    proto_rule: PortProto,
) -> String {
    match proto_rule {
        PortProto::Any => format!("{}:{}", sock.bind, sock.port),
        PortProto::Tcp => format!("{}:{}/tcp", sock.bind, sock.port),
        PortProto::Udp => format!("{}:{}/udp", sock.bind, sock.port),
    }
}

/// Resolve a listening socket to its risky-port rule.
///
/// Matching is on (port, protocol), not port alone: 111/udp and 111/tcp
/// are separate entries with different classes, so a TCP portmapper is
/// never reported as an amplification risk.
fn lookup_risky(
    port: u16,
    proto: crate::predictive::SocketProtocol,
) -> Option<(u16, PortProto, RiskClass, &'static str, bool)> {
    RISKY_PORTS
        .iter()
        .find(|(p, pp, _, _, _)| *p == port && pp.matches(proto))
        .copied()
}

fn analyze_listening_services(
    ctx: &Context,
    snap: &NetworkSnapshot,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    for sock in &snap.listening_sockets {
        let Some((_, proto_rule, class, service, is_critical_class)) =
            lookup_risky(sock.port, sock.protocol) else { continue; };

        let reach = classify_bind(sock.bind, snap);
        if matches!(reach, NetworkReachability::LoopbackOnly) {
            continue;  // bound to lo only — that's the correct posture
        }

        // Severity matrix: reachability × service-class.
        let severity = match (&reach, is_critical_class) {
            (NetworkReachability::PublicInternet, true)  => Severity::Critical,
            (NetworkReachability::PublicInternet, false) => Severity::High,
            (NetworkReachability::LocalNetwork, true)    => Severity::High,
            (NetworkReachability::LocalNetwork, false)   => Severity::Warn,
            (NetworkReachability::OverlayOnly { .. }, _) => Severity::Info,
            (NetworkReachability::Unknown, true)         => Severity::High,
            (NetworkReachability::Unknown, false)        => Severity::Warn,
            (NetworkReachability::LoopbackOnly, _)       => continue,
        };

        let resource = risky_resource_id(sock, proto_rule);
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(resource.clone()),
        };
        if acks.suppresses(FINDING_SERVICE_PUBLIC, &scope) { continue; }
        if proposals.is_suppressed(FINDING_SERVICE_PUBLIC, &scope) { continue; }

        out.push(build_listening_proposal(sock, service, class, &reach, severity, &scope));
    }
    out
}

fn build_listening_proposal(
    sock: &crate::predictive::ListeningSocket,
    service: &str,
    class: RiskClass,
    reach: &NetworkReachability,
    severity: Severity,
    scope: &ProposalScope,
) -> Proposal {
    let proto = match sock.protocol {
        crate::predictive::SocketProtocol::Tcp => "tcp",
        crate::predictive::SocketProtocol::Udp => "udp",
    };
    let reach_label = match reach {
        NetworkReachability::PublicInternet => "the public internet",
        NetworkReachability::LocalNetwork   => "the local network",
        NetworkReachability::OverlayOnly { network } => {
            return Proposal::new_rule(
                FINDING_SERVICE_PUBLIC, severity,
                format!("{} ({}/{}) on overlay {}", service, proto, sock.port, network),
                format!(
                    "{} is listening on overlay '{}'. Overlay-only \
                     bindings are usually intentional (the operator \
                     deliberately exposed this service to peers via \
                     the overlay), so this finding is informational. \
                     Acknowledge to silence it permanently if that's \
                     the case.",
                    service, network,
                ),
                vec![Evidence {
                    label: "Bind".into(),
                    value: format!("{}:{} ({})", sock.bind, sock.port, proto),
                    detail: sock.process.clone(),
                    links: Vec::new(),
                }],
                RemediationPlan::Manual {
                    instructions: format!("Bind '{}' is overlay-scoped — review whether the exposure is intentional.", service),
                    commands: vec![
                        format!("ss -tlnp | grep ':{}\\b'", sock.port),
                    ],
                },
                scope.clone(),
            );
        }
        NetworkReachability::Unknown => "an unclassified interface",
        NetworkReachability::LoopbackOnly => "loopback (this should not have fired)",
    };

    let title = match class {
        RiskClass::Reflection => format!(
            "{} ({}/{}) can be abused to attack others — reachable from {}",
            service, proto, sock.port, reach_label,
        ),
        RiskClass::Exposure => format!(
            "{} ({}/{}) reachable from {}",
            service, proto, sock.port, reach_label,
        ),
    };

    // A reflection finding is not "someone can read your data" — it is
    // "someone can point your host at a victim". Operators act on that
    // differently, and it is what a national CERT reports to your hosting
    // provider, so it is spelled out rather than folded into the generic
    // exposure wording.
    let why = match class {
        RiskClass::Reflection => format!(
            "Service `{}` is answering on {}/{} at `{}`, reachable from {}. \
             This is a UDP amplification vector: an attacker sends a small \
             query with your victim's address spoofed as the source, and \
             THIS HOST sends the much larger reply to that victim. \
             Portmapper amplifies roughly 7-28x (CERT TA14-017A), so your \
             bandwidth is used to attack someone else. \
             \n\nTwo things follow. First, you are unlikely to notice: the \
             traffic leaves your host and the damage lands elsewhere. \
             Second, this is what national CERTs scan for and report — the \
             notice usually reaches your hosting provider's abuse desk \
             before it reaches you. \
             \n\nOn most hosts rpcbind is not needed at all: with no NFS \
             server and no NFSv3 client it registers nothing but itself. \
             Check with `rpcinfo -p 127.0.0.1` before assuming it is load-\
             bearing. If this exposure is deliberate, acknowledge it to \
             silence the finding.",
            service, proto, sock.port, sock.bind, reach_label,
        ),
        RiskClass::Exposure => format!(
            "Service `{}` (port {}/{}) is bound to `{}`, which makes it \
             reachable from {}. The bind address resolves to that \
             reachability class via the unified `NetworkReachability` \
             classifier — see the resource_id `{}:{}` for filtering. \
             If the exposure is intentional (e.g. an opt-in public \
             endpoint with its own auth in front), acknowledge as \
             intentional to silence permanently.",
            service, sock.port, proto, sock.bind, reach_label,
            sock.bind, sock.port,
        ),
    };

    let evidence = vec![
        Evidence {
            label: "Service".into(),
            value: format!("{} ({}/{})", service, proto, sock.port),
            detail: sock.process.clone(),
            links: Vec::new(),
        },
        Evidence {
            label: "Bind".into(),
            value: format!("{}:{}", sock.bind, sock.port),
            detail: Some(format!("Reachability class: {:?}", reach)),
            links: Vec::new(),
        },
    ];

    // rpcbind gets its own remediation because "bind it to 127.0.0.1" does
    // not actually close it: `-h` (/etc/default/rpcbind) restricts UDP binds
    // only, while TCP/111 is held by `rpcbind.socket`'s ListenStream. The real
    // fix is to turn it off, and on a host with no NFS server and no NFSv3
    // client that costs nothing. Masking (not just disabling) is deliberate:
    // the socket unit is what holds 111, and a masked unit cannot be pulled
    // back up by a dependency or a package update.
    //
    // `predictive::rpcbind` performs exactly these steps behind
    // POST /api/proposals/{id}/apply (the inbox's "Switch rpcbind off"
    // button), after re-checking that nothing on the host uses RPC. The
    // commands stay listed here so the manual route, and the audit of what
    // the button does, are both visible.
    let remediation = if sock.port == 111 {
        RemediationPlan::Manual {
            instructions:
                "Check whether anything actually uses RPC on this host first: \
                 `rpcinfo -p 127.0.0.1`. If the only program registered is \
                 `portmapper` itself, and there are no NFS mounts, nothing \
                 needs rpcbind and it can be switched off outright. Mask BOTH \
                 units — the socket unit is what holds port 111, so stopping \
                 only the service leaves the listener in place. If you do serve \
                 NFS, firewall 111 to your storage network instead. \
                 \n\n\"Switch rpcbind off\" below does all of this for you, \
                 including the checks — it refuses if this host turns out to \
                 need RPC, and publishing an NFS share through WolfStack later \
                 switches rpcbind back on automatically."
                    .to_string(),
            commands: vec![
                "rpcinfo -p 127.0.0.1".to_string(),
                "mount | grep 'type nfs'".to_string(),
                "sudo systemctl stop rpcbind.socket rpcbind.service".to_string(),
                "sudo systemctl mask rpcbind.socket rpcbind.service".to_string(),
            ],
        }
    } else {
        RemediationPlan::Manual {
            instructions: format!(
                "Bind {} to 127.0.0.1 in its config OR firewall the port \
                 from external networks. If this is an intentional \
                 exposure, the cleanest path is to ack the finding so \
                 future scans don't re-flag it.",
                service,
            ),
            commands: vec![
                format!("ss -tlnp 'sport = :{}'", sock.port),
                format!("sudo iptables -A INPUT -p {} --dport {} ! -s 127.0.0.1 -j DROP", proto, sock.port),
            ],
        }
    };

    Proposal::new_rule(
        FINDING_SERVICE_PUBLIC, severity,
        title, why, evidence, remediation, scope.clone(),
    )
}

fn analyze_sshd(
    ctx: &Context,
    sshd: &SshdConfig,
    snap: &NetworkSnapshot,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    let sshd_reach = sshd_reachability(snap);

    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("sshd".into()),
    };

    // Proxmox uses root SSH for cluster operations and re-asserts
    // PermitRootLogin on its own, so the finding is un-actionable there —
    // suppress it on Proxmox (in addition to the operator ack / proposal
    // suppression). A prohibit-password drop-in is the way to harden.
    if sshd.root_login
        && !crate::containers::is_proxmox()
        && !acks.suppresses(FINDING_SSHD_ROOT_LOGIN, &scope)
        && !proposals.is_suppressed(FINDING_SSHD_ROOT_LOGIN, &scope)
    {
        let severity = match sshd_reach {
            NetworkReachability::PublicInternet => Severity::Critical,
            NetworkReachability::LocalNetwork   => Severity::High,
            _                                   => Severity::Warn,
        };
        out.push(build_sshd_root_proposal(&sshd_reach, severity, &scope));
    }

    if sshd.password_auth
        && !acks.suppresses(FINDING_SSHD_PASSWORD_AUTH, &scope)
        && !proposals.is_suppressed(FINDING_SSHD_PASSWORD_AUTH, &scope)
    {
        let severity = match sshd_reach {
            NetworkReachability::PublicInternet => Severity::High,
            NetworkReachability::LocalNetwork   => Severity::Warn,
            _                                   => Severity::Info,
        };
        out.push(build_sshd_password_proposal(&sshd_reach, severity, &scope));
    }

    out
}

/// Flag when the outbound scan detector is disabled. It ships default-OFF
/// (v23.12.3, after an enabled + kill_and_block build SIGKILL'd pmxcfs on a
/// Proxmox host during a backup-driven replication burst), which is a safe
/// default but a silent one: with the detector off, a compromised or misused
/// host can port-scan or flood outbound with nothing on the box watching —
/// exactly the gap that ends in a provider abuse-lock. Surface it as a Warn
/// (visible in the inbox, no first-appearance alarm) so the operator makes a
/// deliberate choice instead of being unaware it's off. Ackable for anyone
/// who leaves it off on purpose.
fn analyze_scan_detector(
    ctx: &Context,
    scan_detector_enabled: bool,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    if scan_detector_enabled {
        return Vec::new();
    }
    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("scan_detector".into()),
    };
    if acks.suppresses(FINDING_SCAN_DETECTOR_DISABLED, &scope)
        || proposals.is_suppressed(FINDING_SCAN_DETECTOR_DISABLED, &scope)
    {
        return Vec::new();
    }
    vec![Proposal::new_rule(
        FINDING_SCAN_DETECTOR_DISABLED,
        Severity::Warn,
        "Outbound scan detection is disabled".to_string(),
        "The outbound scan detector is turned off on this node. It ships \
         disabled by default, so unless it was deliberately enabled nothing \
         is watching for a local process fanning out to many destinations \
         (port-scanning) or a raw-socket scanner such as zmap / masscan — the \
         behaviour that gets a host flagged for abuse and network-locked by \
         the hosting provider. Enable it, starting with 'Alert only (no kill)' \
         so nothing is killed while you confirm there are no false positives, \
         then promote to 'Kill + block'. Acknowledge this finding to silence \
         it if leaving the detector off is a deliberate choice."
            .to_string(),
        vec![Evidence {
            label: "Scan detector".into(),
            value: "disabled".into(),
            detail: Some(
                "Enable under Fleet Security \u{2192} Scan Detector (persisted in scan-detector.json)."
                    .into(),
            ),
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Open Fleet Security \u{2192} Scan Detector, tick 'Enabled', choose \
                           'Alert only (no kill)' for the first few days, review 'Recent detections', \
                           add any legitimate high-fanout processes to the allowlist, then switch the \
                           action to 'Kill + block' and push to every node."
                .into(),
            commands: Vec::new(),
        },
        scope,
    )]
}

/// What reachability class does sshd's binding fall into? Walk the
/// listening sockets snapshot for port 22; classify each bind via
/// the existing classifier; pick the most-permissive (worst-case).
fn sshd_reachability(snap: &NetworkSnapshot) -> NetworkReachability {
    let mut worst = NetworkReachability::LoopbackOnly;
    for sock in &snap.listening_sockets {
        if sock.port != 22 { continue; }
        let r = classify_bind(sock.bind, snap);
        worst = pick_worst(worst, r);
    }
    worst
}

/// "Worst" = most exposed. PublicInternet beats LocalNetwork beats
/// OverlayOnly beats Unknown beats LoopbackOnly.
fn pick_worst(a: NetworkReachability, b: NetworkReachability) -> NetworkReachability {
    fn rank(r: &NetworkReachability) -> u8 {
        match r {
            NetworkReachability::PublicInternet => 4,
            NetworkReachability::LocalNetwork   => 3,
            NetworkReachability::OverlayOnly { .. } => 2,
            NetworkReachability::Unknown        => 1,
            NetworkReachability::LoopbackOnly   => 0,
        }
    }
    if rank(&a) >= rank(&b) { a } else { b }
}

fn build_sshd_root_proposal(
    reach: &NetworkReachability,
    severity: Severity,
    scope: &ProposalScope,
) -> Proposal {
    Proposal::new_rule(
        FINDING_SSHD_ROOT_LOGIN, severity,
        format!("sshd allows root login (sshd reachable from: {:?})", reach),
        format!(
            "/etc/ssh/sshd_config has `PermitRootLogin yes`. Severity \
             scales with sshd's actual exposure — currently classified \
             as {:?}. Direct root-over-SSH on a publicly-reachable \
             endpoint is a primary brute-force target; even on local \
             networks the audit trail loses meaning when everyone is \
             logging in as `root`.",
            reach,
        ),
        vec![Evidence {
            label: "sshd reachability".into(),
            value: format!("{:?}", reach),
            detail: Some("Computed via `NetworkReachability::classify_bind` on every listener for port 22.".into()),
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Set `PermitRootLogin no` in /etc/ssh/sshd_config and reload sshd. Make sure you have a non-root user with sudo first.".into(),
            commands: vec![
                "grep -i 'PermitRootLogin' /etc/ssh/sshd_config".into(),
                "sudo sed -i 's/^[# ]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config".into(),
                "sudo sshd -t && sudo systemctl reload sshd".into(),
            ],
        },
        scope.clone(),
    )
}

fn build_sshd_password_proposal(
    reach: &NetworkReachability,
    severity: Severity,
    scope: &ProposalScope,
) -> Proposal {
    Proposal::new_rule(
        FINDING_SSHD_PASSWORD_AUTH, severity,
        format!("sshd accepts password auth (sshd reachable from: {:?})", reach),
        format!(
            "/etc/ssh/sshd_config has `PasswordAuthentication yes`. \
             Public SSH endpoints with password auth are the single \
             most-attacked surface on a Linux host; key-only auth + \
             fail2ban (or sshguard) cuts log noise dramatically and \
             makes credential-stuffing irrelevant. Reachability \
             class: {:?}.",
            reach,
        ),
        vec![Evidence {
            label: "sshd reachability".into(),
            value: format!("{:?}", reach),
            detail: None,
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Set `PasswordAuthentication no` in /etc/ssh/sshd_config — confirm your key works first by logging in via key in a separate session BEFORE you reload sshd.".into(),
            commands: vec![
                "grep -iE 'PasswordAuthentication|PubkeyAuthentication' /etc/ssh/sshd_config".into(),
                "# In a SECOND ssh session, confirm key-only auth works:".into(),
                "ssh -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o PasswordAuthentication=no <user>@<host>".into(),
                "sudo sed -i 's/^[# ]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config".into(),
                "sudo sshd -t && sudo systemctl reload sshd".into(),
            ],
        },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::{ListeningSocket, NetworkSnapshot, SocketProtocol};
    use crate::predictive::proposal::ProposalStore;
    use crate::networking::{InterfaceAddress, NetworkInterface};
    use std::net::IpAddr;

    fn iface(name: &str, addr: &str, family: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            mac: "00:00:00:00:00:00".into(),
            state: "up".into(), mtu: 1500,
            addresses: vec![InterfaceAddress {
                address: addr.into(),
                prefix: if family == "inet" { 24 } else { 64 },
                family: family.into(),
                scope: "global".into(),
            }],
            is_vlan: false, vlan_id: None, parent: None,
            speed: None, driver: None,
        }
    }

    fn sock(addr: &str, port: u16) -> ListeningSocket {
        ListeningSocket {
            bind: addr.parse::<IpAddr>().unwrap(),
            port,
            protocol: SocketProtocol::Tcp,
            process: Some(format!("svc-{}", port)),
        }
    }

    fn udp_sock(addr: &str, port: u16) -> ListeningSocket {
        ListeningSocket {
            bind: addr.parse::<IpAddr>().unwrap(),
            port,
            protocol: SocketProtocol::Udp,
            process: Some(format!("svc-{}", port)),
        }
    }

    fn ctx_with(interfaces: Vec<NetworkInterface>, sockets: Vec<ListeningSocket>) -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(interfaces, sockets),
        }
    }

    // ── Listening services ──────────────────────────────────────

    #[test]
    fn mariadb_on_public_ip_is_high() {
        // The exact false-positive scenario from session memory:
        // the Inbox's binding-on-public finding scaled by reachability.
        // The doc-range 203.0.113.0/24 is treated as non-routable by
        // `is_publicly_routable_v4` (it's RFC 5737 documentation
        // space), so the fixture uses a real-world public IP.
        let socks = vec![sock("0.0.0.0", 3306)];
        let ifaces = vec![iface("eth0", "145.224.67.239", "inet")];
        let p = analyze_listening_services(
            &ctx_with(ifaces, socks),
            &NetworkSnapshot::from_parts(
                vec![iface("eth0", "145.224.67.239", "inet")],
                vec![sock("0.0.0.0", 3306)],
            ),
            &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::High);
        assert!(p[0].title.contains("mysql"));
    }

    #[test]
    fn docker_api_plain_on_public_is_critical() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("0.0.0.0", 2375)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::Critical,
            "docker-api-plain on public internet must be Critical");
    }

    #[test]
    fn rpcbind_udp_on_public_is_critical() {
        let ctx = ctx_with(
            vec![iface("eth0", "176.9.119.111", "inet")],
            vec![udp_sock("0.0.0.0", 111)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::Critical,
            "rpcbind on udp/111 reachable from the internet is an amplification \
             vector and must be Critical");
        assert!(p[0].title.contains("attack others"),
            "reflection findings must say the host attacks THIRD PARTIES, not \
             that the host's own data is at risk: {}", p[0].title);
    }

    #[test]
    fn rpcbind_tcp_on_public_is_not_critical() {
        let ctx = ctx_with(
            vec![iface("eth0", "176.9.119.111", "inet")],
            vec![sock("0.0.0.0", 111)],   // TCP
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_ne!(p[0].severity, Severity::Critical,
            "tcp/111 cannot be spoofed for reflection — it is an information \
             leak, not an amplifier, and must not share the UDP severity");
        assert!(!p[0].title.contains("attack others"),
            "tcp/111 must not claim to be a reflection vector: {}", p[0].title);
    }

    #[test]
    fn rpcbind_udp_and_tcp_are_independently_ackable() {
        // Both protocols exposed on the same address. They are distinct
        // findings with different severities, so acking one must never
        // silence the other.
        let ctx = ctx_with(
            vec![iface("eth0", "176.9.119.111", "inet")],
            vec![udp_sock("0.0.0.0", 111), sock("0.0.0.0", 111)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 2, "udp/111 and tcp/111 must be separate findings");
        let ids: Vec<_> = p.iter()
            .map(|x| x.scope.resource_id.clone().unwrap())
            .collect();
        assert_ne!(ids[0], ids[1],
            "resource ids must differ or an ack on one silences the other: {:?}", ids);
    }

    #[test]
    fn rpcbind_on_loopback_is_silent() {
        // The correct posture. Must not nag.
        let ctx = ctx_with(
            vec![iface("lo", "127.0.0.1", "inet")],
            vec![udp_sock("127.0.0.1", 111)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty(), "loopback-only rpcbind is correct, not a finding");
    }

    #[test]
    fn existing_any_proto_rules_keep_their_resource_id() {
        // Guards the ack-compatibility promise: entries that are not
        // protocol-specific must keep the exact pre-change id, or every
        // operator's existing acknowledgement silently stops matching.
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("0.0.0.0", 3306)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].scope.resource_id.as_deref(), Some("0.0.0.0:3306"),
            "non-protocol-specific rules must not gain a /tcp or /udp suffix");
    }

    #[test]
    fn covered_scopes_match_finding_ids_for_rpcbind() {
        // If these drift, a fixed rpcbind finding never auto-resolves.
        let ctx = ctx_with(
            vec![iface("eth0", "176.9.119.111", "inet")],
            vec![udp_sock("0.0.0.0", 111)],
        );
        let findings = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        let covered = covered_scopes(&ctx, &SshdConfig::default());
        let finding_id = findings[0].scope.resource_id.clone().unwrap();
        assert!(
            covered.iter().any(|(f, s)| f == FINDING_SERVICE_PUBLIC
                && s.resource_id.as_deref() == Some(finding_id.as_str())),
            "covered_scopes must produce the same resource_id as the finding \
             ({}), otherwise auto-resolve breaks", finding_id,
        );
    }

    #[test]
    fn mariadb_on_lan_only_is_warn() {
        // The MariaDB-on-private-LAN false-positive case the user
        // called out two sessions ago — must downgrade, not Critical.
        let ctx = ctx_with(
            vec![iface("eth0", "192.168.1.10", "inet")],
            vec![sock("0.0.0.0", 3306)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::Warn,
            "MariaDB on RFC1918-only host must be Warn, never Critical");
    }

    #[test]
    fn loopback_only_silent() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306)],
        );
        let p = analyze_listening_services(
            &ctx, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty(),
            "lo-only bindings are correct posture; never fire");
    }

    #[test]
    fn ack_silences_specific_binding() {
        let ctx = ctx_with(
            vec![iface("eth0", "192.168.1.10", "inet")],
            vec![sock("0.0.0.0", 3306)],
        );
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_SERVICE_PUBLIC,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "0.0.0.0:3306".into(),
            },
            "Analytics LAN; intentional exposure to internal tools",
            "paul", None,
        ));
        let p = analyze_listening_services(
            &ctx, &ctx.network, &acks, &ProposalStore::default(),
        );
        assert!(p.is_empty());
    }

    // ── sshd config × reachability ──────────────────────────────

    #[test]
    fn sshd_root_on_public_is_critical() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("0.0.0.0", 22)],
        );
        let cfg = SshdConfig { root_login: true, password_auth: false };
        let p = analyze_sshd(
            &ctx, &cfg, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        let root = p.iter().find(|p| p.finding_type == FINDING_SSHD_ROOT_LOGIN).unwrap();
        assert_eq!(root.severity, Severity::Critical);
    }

    #[test]
    fn sshd_password_on_lan_is_warn() {
        let ctx = ctx_with(
            vec![iface("eth0", "192.168.1.10", "inet")],
            vec![sock("0.0.0.0", 22)],
        );
        let cfg = SshdConfig { root_login: false, password_auth: true };
        let p = analyze_sshd(
            &ctx, &cfg, &ctx.network, &AckStore::default(), &ProposalStore::default(),
        );
        let pa = p.iter().find(|p| p.finding_type == FINDING_SSHD_PASSWORD_AUTH).unwrap();
        assert_eq!(pa.severity, Severity::Warn);
    }

    #[test]
    fn analyzer_can_stay_quiet_on_clean_host() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306), sock("0.0.0.0", 22)],
        );
        let cfg = SshdConfig { root_login: false, password_auth: false };
        let p = analyze(
            &ctx, &cfg, true, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty(),
            "a clean host (services on lo, ssh keys-only, scan detector on) produces no posture findings");
    }

    /// Guards the discipline rule from the original predictive
    /// plan: every analyzer must produce at least one combination
    /// of inputs that yields no finding. Listening services on
    /// loopback and an SSH config with no password/root flags
    /// satisfies that.
    #[test]
    fn discipline_one_input_class_silent() {
        // LoopbackOnly + clean sshd → analyzer stays quiet.
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306)],
        );
        let cfg = SshdConfig::default();
        let p = analyze(&ctx, &cfg, true, &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }

    // ── Outbound scan detector posture ──────────────────────────

    #[test]
    fn scan_detector_disabled_fires_warn() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306)],
        );
        let p = analyze_scan_detector(
            &ctx, false, &AckStore::default(), &ProposalStore::default(),
        );
        assert_eq!(p.len(), 1, "a disabled detector must produce exactly one finding");
        assert_eq!(p[0].severity, Severity::Warn,
            "disabled scan detector is a Warn — surfaced, but not a first-appearance alarm");
        assert_eq!(p[0].finding_type, FINDING_SCAN_DETECTOR_DISABLED);
        assert_eq!(p[0].scope.resource_id.as_deref(), Some("scan_detector"));
    }

    #[test]
    fn scan_detector_enabled_is_silent() {
        let ctx = ctx_with(
            vec![iface("eth0", "145.224.67.239", "inet")],
            vec![sock("127.0.0.1", 3306)],
        );
        let p = analyze_scan_detector(
            &ctx, true, &AckStore::default(), &ProposalStore::default(),
        );
        assert!(p.is_empty(), "an enabled detector produces no finding (posture is correct)");
    }

    #[test]
    fn scan_detector_disabled_but_acked_is_silent() {
        let ctx = ctx_with(vec![iface("eth0", "145.224.67.239", "inet")], vec![]);
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_SCAN_DETECTOR_DISABLED,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "scan_detector".into(),
            },
            "intentionally off on this host",
            "paul", None,
        ));
        let p = analyze_scan_detector(&ctx, false, &acks, &ProposalStore::default());
        assert!(p.is_empty(), "an operator ack silences the disabled-detector finding");
    }
}
