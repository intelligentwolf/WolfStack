// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! PVE Console — WebSocket proxy for Proxmox VE terminal and VNC sessions.
//! Provides two modes:
//! 1. Terminal (termproxy) — xterm.js for text shells (LXC, node shell)
//! 2. VNC (vncproxy) — noVNC for graphical VM consoles (QEMU VMs)

use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::Message;
use futures::StreamExt;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;
use tracing::error;

use super::AppState;

/// Temporary storage for VNC proxy ports created by the ticket endpoint.
/// Key: vmid, Value: (port, ticket, creation_time)
type VncProxyTicket = (u16, String, std::time::Instant);
static VNC_PORTS: std::sync::LazyLock<Mutex<HashMap<u64, VncProxyTicket>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));


/// REST endpoint: GET /api/pve-vnc-ticket/{vmid}
/// Creates a PVE VNC proxy via pvesh and returns the ticket for noVNC auth.
/// The VNC proxy port is stored in memory for the subsequent WS connection.
pub async fn pve_vnc_ticket(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_operator_auth(&req, &state) { return Ok(resp); }
    let vmid_str = path.into_inner();
    let vmid: u64 = match vmid_str.parse() {
        Ok(v) => v,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid VMID" }))),
    };

    if !crate::containers::is_proxmox() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox host" })));
    }

    let (port, ticket) = match create_vnc_proxy(vmid) {
        Ok(r) => r,
        Err(e) => {
            error!("PVE vncproxy failed for VMID {}: {}", vmid, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })));
        }
    };

    // Store for the WS handler to pick up
    if let Ok(mut map) = VNC_PORTS.lock() {
        // Clean expired entries (older than 30 seconds)
        let now = std::time::Instant::now();
        map.retain(|_, (_, _, t)| now.duration_since(*t).as_secs() < 30);
        map.insert(vmid, (port, ticket.clone(), now));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "ticket": ticket,
        "vmid": vmid,
    })))
}

/// Create a PVE VNC proxy for a VM and return (port, ticket).
fn create_vnc_proxy(vmid: u64) -> Result<(u16, String), String> {
    // PVE node names are short hostnames (no FQDN) — use `hostname -s`
    let pve_node = Command::new("hostname").arg("-s").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    // Determine guest type (qemu or lxc)
    let qemu_check = Command::new("pvesh")
        .args(["get", &format!("/nodes/{}/qemu/{}/status/current", pve_node, vmid), "--output-format", "json"])
        .output();
    let guest_type = if qemu_check.map(|o| o.status.success()).unwrap_or(false) {
        "qemu"
    } else {
        "lxc"
    };

    // Create standard VNC proxy (no --websocket flag = plain TCP VNC)
    let vncproxy_path = format!("/nodes/{}/{}/{}/vncproxy", pve_node, guest_type, vmid);
    let vp_output = Command::new("pvesh")
        .args(["create", &vncproxy_path, "--output-format", "json"])
        .output();

    let vp_data = match vp_output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            serde_json::from_str::<serde_json::Value>(&text)
                .map_err(|e| format!("Failed to parse vncproxy response: {}", e))
        }
        Ok(o) => Err(format!("pvesh vncproxy failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(format!("Failed to run pvesh: {}", e)),
    };

    let vp_data = vp_data?;

    let port = vp_data.get("port")
        .and_then(|v| v.as_str().and_then(|s| s.parse::<u16>().ok()).or_else(|| v.as_u64().map(|n| n as u16)))
        .unwrap_or(0);
    let ticket = vp_data.get("ticket")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if port == 0 {
        return Err("No VNC port in vncproxy response".to_string());
    }

    Ok((port, ticket))
}


/// WebSocket endpoint: /ws/pve-vnc/{vmid}
/// Bridges browser noVNC ↔ PVE VNC proxy via TCP.
/// The VNC proxy port is looked up from the ticket endpoint, or created on demand.
pub async fn pve_vnc_ws(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_operator_auth(&req, &state) { return Ok(resp); }
    let vmid_str = path.into_inner();
    let vmid: u64 = match vmid_str.parse() {
        Ok(v) => v,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid VMID" }))),
    };

    if !crate::containers::is_proxmox() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox host" })));
    }

    // Look up the stored port, or create a new VNC proxy on demand
    let port = {
        let stored = VNC_PORTS.lock().ok().and_then(|map| map.get(&vmid).map(|(p, _, _)| *p));
        match stored {
            Some(p) => p,
            None => {
                // Create VNC proxy on the fly
                match create_vnc_proxy(vmid) {
                    Ok((p, _)) => p,
                    Err(e) => {
                        error!("PVE vncproxy failed for VMID {}: {}", vmid, e);
                        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })));
                    }
                }
            }
        }
    };

    // Connect TCP to the PVE VNC proxy port
    let tcp_stream = match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to PVE VNC proxy port {}: {}", port, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to connect to VNC proxy: {}", e)
            })));
        }
    };

    // Upgrade browser connection to WebSocket
    let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;

    // Bridge WebSocket ↔ TCP
    actix_rt::spawn(vnc_tcp_bridge(session, msg_stream, tcp_stream));

    Ok(res)
}

/// Bridge browser noVNC WebSocket ↔ PVE VNC proxy TCP connection.
/// Pure binary passthrough — noVNC speaks RFB protocol directly to PVE's VNC proxy.
async fn vnc_tcp_bridge(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    tcp_stream: TcpStream,
) {
    let (mut tcp_rx, mut tcp_tx) = tcp_stream.into_split();
    let mut buf = [0u8; 8192];

    loop {
        tokio::select! {
            // TCP (VNC proxy) → WebSocket (noVNC browser)
            result = tcp_rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if session.binary(buf[..n].to_vec()).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }

            // WebSocket (noVNC browser) → TCP (VNC proxy)
            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if tcp_tx.write_all(&data).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(text))) => {
                        // noVNC may send text frames for some protocol messages
                        if tcp_tx.write_all(text.as_bytes()).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        let _ = session.pong(&bytes).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    // An errored browser stream MUST end the bridge.
                    //
                    // actix-ws does NOT terminate its stream after an error:
                    // `MessageStream::poll_next` returns it WITHOUT setting
                    // `closing` (actix-ws 0.3.1 stream.rs:176; the `?` on
                    // codec.decode at :189 does the same while the offending
                    // bytes stay buffered). Every later poll therefore yields
                    // the same error, immediately ready, for ever.
                    //
                    // A catch-all `_ => {}` let that fall through, so the select
                    // loop re-polled with nothing to await — a hot spin that also
                    // never dropped either side's socket. Measured on a user's
                    // node 2026-08-06: seven actix workers pegged, 29,344 sockets
                    // stranded in CLOSE-WAIT and 42 leaked /dev/ptmx handles,
                    // until the fd table hit its 65,535 ceiling and accept()
                    // began failing.
                    Some(Err(e)) => {
                        error!("pve_console: browser websocket error: {} — closing", e);
                        break;
                    }
                    // Pong / Continuation / Nop — nothing to forward.
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    let _ = session.close(None).await;
}


/// WebSocket endpoint: /ws/vm-vnc/{name}
/// Bridges browser noVNC ↔ a VM's VNC endpoint. Two flavours supported:
///
/// * **Native QEMU** — VmConfig has `vnc_ws_port` set (QEMU was started
///   with `-vnc … ,websocket=N`). We connect as a WebSocket client and
///   shuttle frames.
/// * **Libvirt** — VmConfig has only `vnc_port` set (virsh doesn't
///   expose a WebSocket VNC port by default). We connect a raw TCP
///   socket to 127.0.0.1:vnc_port and bridge browser WS frames ↔
///   TCP bytes. noVNC handles the RFB protocol in-frame either way.
pub async fn vm_vnc_ws(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_operator_auth(&req, &state) { return Ok(resp); }
    let vm_name = path.into_inner();

    // Pick the connection strategy from the VmConfig. Prefer ws_port
    // when present (native QEMU), fall back to raw TCP vnc_port
    // (libvirt).
    let (ws_port_opt, vnc_port_opt) = {
        let manager = state.vms.lock().unwrap();
        let vm = manager.get_vm(&vm_name);
        (vm.as_ref().and_then(|v| v.vnc_ws_port),
         vm.as_ref().and_then(|v| v.vnc_port))
    };

    if let Some(ws_port) = ws_port_opt {
        // Native-QEMU path — WebSocket ↔ WebSocket.
        let qemu_url = format!("ws://127.0.0.1:{}", ws_port);
        let (qemu_ws, _) = match tokio_tungstenite::connect_async(&qemu_url).await {
            Ok(pair) => pair,
            Err(e) => {
                error!("Failed to connect to QEMU VNC WebSocket port {} for VM '{}': {}", ws_port, vm_name, e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to connect to VM console: {}", e)
                })));
            }
        };
        let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;
        actix_rt::spawn(vnc_ws_bridge(session, msg_stream, qemu_ws));
        return Ok(res);
    }

    if let Some(vnc_port) = vnc_port_opt {
        // Libvirt path — WebSocket ↔ raw TCP.
        let tcp = match TcpStream::connect(("127.0.0.1", vnc_port)).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to libvirt VNC TCP port {} for VM '{}': {}", vnc_port, vm_name, e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to connect to VM console: {}", e)
                })));
            }
        };
        let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;
        actix_rt::spawn(vnc_tcp_bridge(session, msg_stream, tcp));
        return Ok(res);
    }

    Ok(HttpResponse::NotFound().json(serde_json::json!({
        "error": format!("VM '{}' not found or has no VNC configured", vm_name)
    })))
}

// Libvirt path reuses the existing `vnc_tcp_bridge` helper defined
// above — same passthrough shape (raw TCP ↔ binary WS frames).

/// Bridge browser noVNC WebSocket ↔ QEMU's WebSocket VNC.
/// Both sides are WebSocket — we just shuttle binary frames between them.
async fn vnc_ws_bridge(
    mut browser_session: actix_ws::Session,
    mut browser_stream: actix_ws::MessageStream,
    qemu_ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
) {
    use futures::SinkExt;
    let (mut qemu_tx, mut qemu_rx) = qemu_ws.split();

    loop {
        tokio::select! {
            // QEMU → Browser
            msg = qemu_rx.next() => {
                match msg {
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        if browser_session.binary(data.to_vec()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        if browser_session.text(text.to_string()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Ping(data))) => {
                        let _ = qemu_tx.send(tungstenite::Message::Pong(data)).await;
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    // Break on an upstream error too. tungstenite is better
                    // behaved than actix-ws here, but a bridge whose remote leg
                    // has errored cannot do anything useful, and swallowing it
                    // risks the same never-terminating loop as the browser side.
                    Some(Err(e)) => {
                        error!("pve_console: upstream websocket error: {} — closing", e);
                        break;
                    }
                    // Pong / Frame / Continuation — nothing to forward.
                    Some(Ok(_)) => {}
                }
            }
            // Browser → QEMU
            msg = browser_stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if qemu_tx.send(tungstenite::Message::Binary(data.into())).await.is_err() { break; }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if qemu_tx.send(tungstenite::Message::Text(text.to_string())).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        let _ = browser_session.pong(&bytes).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    // An errored browser stream MUST end the bridge.
                    //
                    // actix-ws does NOT terminate its stream after an error:
                    // `MessageStream::poll_next` returns it WITHOUT setting
                    // `closing` (actix-ws 0.3.1 stream.rs:176; the `?` on
                    // codec.decode at :189 does the same while the offending
                    // bytes stay buffered). Every later poll therefore yields
                    // the same error, immediately ready, for ever.
                    //
                    // A catch-all `_ => {}` let that fall through, so the select
                    // loop re-polled with nothing to await — a hot spin that also
                    // never dropped either side's socket. Measured on a user's
                    // node 2026-08-06: seven actix workers pegged, 29,344 sockets
                    // stranded in CLOSE-WAIT and 42 leaked /dev/ptmx handles,
                    // until the fd table hit its 65,535 ceiling and accept()
                    // began failing.
                    Some(Err(e)) => {
                        error!("pve_console: browser websocket error: {} — closing", e);
                        break;
                    }
                    // Pong / Continuation / Nop — nothing to forward.
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    let _ = browser_session.close(None).await;
    let _ = qemu_tx.close().await;
}

/// WebSocket endpoint: /ws/pve-console/{node_id}/{vmid}
/// Connects to a Proxmox VE terminal through the termproxy API.
/// vmid=0 means "node shell" (PVE host terminal), vmid>0 means guest console.
pub async fn pve_console_ws(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    if let Err(resp) = super::require_operator_auth(&req, &state) { return Ok(resp); }

    let (node_id, vmid_str) = path.into_inner();

    let vmid: u64 = match vmid_str.parse() {
        Ok(v) => v,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid VMID" }))),
    };

    // Look up the PVE node
    let node = match state.cluster.get_node(&node_id) {
        Some(n) if n.node_type == "proxmox" => n,
        Some(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({ "error": "Not a Proxmox node" }))),
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({ "error": "Node not found" }))),
    };

    let token = node.pve_token.clone().unwrap_or_default();
    let pve_name = node.pve_node_name.clone().unwrap_or_default();
    let fp = node.pve_fingerprint.clone();
    let address = node.address.clone();
    let port = node.port;

    let client = crate::proxmox::PveClient::new(&address, port, &token, fp.as_deref(), &pve_name);

    // Get termproxy ticket — node shell (vmid=0) or guest terminal (vmid>0)
    let (term_port, ticket, guest_type) = if vmid == 0 {
        // Node shell
        let (tp, tk, _user) = match client.node_termproxy().await {
            Ok(t) => t,
            Err(e) => {
                error!("PVE node termproxy failed: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })));
            }
        };

        (tp, tk, "node".to_string())
    } else {
        // Guest terminal — determine type
        let guests = client.list_all_guests().await.unwrap_or_default();
        let gt = guests.iter()
            .find(|g| g.vmid == vmid)
            .map(|g| g.guest_type.clone())
            .unwrap_or_else(|| "lxc".to_string());

        let (tp, tk, _user) = match client.termproxy(vmid, &gt).await {
            Ok(t) => t,
            Err(e) => {
                error!("PVE termproxy failed for VMID {}: {}", vmid, e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })));
            }
        };

        (tp, tk, gt)
    };

    // Upgrade to WebSocket on the browser side
    let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;

    // Spawn the bridge task
    actix_rt::spawn(pve_bridge(session, msg_stream, PveBridgeTarget { pve_host: address, pve_port: port, pve_node: pve_name, term_port, ticket, token, _fingerprint: fp, vmid, guest_type }));

    Ok(res)
}

struct PveBridgeTarget {
    pve_host: String,
    pve_port: u16,
    pve_node: String,
    term_port: u16,
    ticket: String,
    token: String,
    _fingerprint: Option<String>,
    vmid: u64,
    guest_type: String,
}

/// Bridge browser WS ↔ PVE termproxy WS
async fn pve_bridge(
    mut session: actix_ws::Session,
    mut msg_stream: actix_ws::MessageStream,
    target: PveBridgeTarget,
) {
    let PveBridgeTarget { pve_host, pve_port, pve_node, term_port, ticket, token, _fingerprint, vmid, guest_type } = target;
    // Build PVE WebSocket URL — percent-encode the ticket
    let vncticket: String = ticket.bytes().map(|b| {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            format!("{}", b as char)
        } else {
            format!("%{:02X}", b)
        }
    }).collect();
    // Node shell vs guest terminal have different WebSocket URLs
    let pve_ws_host = crate::netaddr::bracket_host(&pve_host);
    let pve_ws_url = if guest_type == "node" {
        format!(
            "wss://{}:{}/api2/json/nodes/{}/vncwebsocket?port={}&vncticket={}",
            pve_ws_host, pve_port, pve_node, term_port, vncticket
        )
    } else {
        format!(
            "wss://{}:{}/api2/json/nodes/{}/{}/{}/vncwebsocket?port={}&vncticket={}",
            pve_ws_host, pve_port, pve_node, guest_type, vmid, term_port, vncticket
        )
    };


    // Build TLS connector that accepts self-signed certs (PVE default)
    let tls_connector = {
        let mut builder = native_tls::TlsConnector::builder();
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
        match builder.build() {
            Ok(c) => Some(tokio_tungstenite::Connector::NativeTls(c)),
            Err(e) => {
                error!("TLS connector error: {}", e);
                let _ = session.text(format!("\r\n\x1b[31mTLS error: {}\x1b[0m\r\n", e)).await;
                let _ = session.close(None).await;
                return;
            }
        }
    };

    // Connect to PVE WebSocket
    let ws_request = match tungstenite::client::IntoClientRequest::into_client_request(pve_ws_url.as_str()) {
        Ok(mut req) => {
            // Add PVE auth — API token or auth cookie
            // Add PVE API auth header
            let auth = if token.starts_with("PVEAPIToken=") {
                token.clone()
            } else {
                format!("PVEAPIToken={}", token)
            };
            req.headers_mut().insert("Authorization", auth.parse().unwrap());
            req
        }
        Err(e) => {
            error!("Failed to build PVE WS request: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mConnection error: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };

    let pve_stream = match tokio_tungstenite::connect_async_tls_with_config(
        ws_request,
        None,
        false,
        tls_connector,
    ).await {
        Ok((stream, _response)) => stream,
        Err(e) => {
            error!("Failed to connect to PVE WebSocket: {}", e);
            let _ = session.text(format!("\r\n\x1b[31mPVE WebSocket connection failed: {}\x1b[0m\r\n", e)).await;
            let _ = session.close(None).await;
            return;
        }
    };

    let (mut pve_sink, mut pve_stream_rx) = pve_stream.split();

    // Send the ticket as the first message to authenticate with PVE termproxy
    // PVE expects the auth wrapped in termproxy protocol: 0:len:username:ticket\n
    let auth_payload = format!("{}:{}\n", _user_from_token(&token), ticket);
    let auth_msg = format!("0:{}:{}", auth_payload.len(), auth_payload);
    if let Err(e) = futures::SinkExt::send(&mut pve_sink, tungstenite::Message::Text(auth_msg)).await {
        error!("Failed to send PVE auth ticket: {}", e);
        let _ = session.close(None).await;
        return;
    }



    // Bridge loop
    loop {
        tokio::select! {
            // PVE → Browser: PVE sends terminal output wrapped in protocol (channel:length:data)
            // We need to strip the protocol prefix and forward only the data payload
            msg = pve_stream_rx.next() => {
                match msg {
                    Some(Ok(tungstenite::Message::Text(text))) => {
                        // Parse PVE termproxy protocol: "channel:length:data"
                        // Channel 0 = terminal data, channel 1 = resize
                        let payload = if text.starts_with("0:") || text.starts_with("1:") {
                            // Find the second colon (after channel:length)
                            if let Some(first_colon) = text.find(':') {
                                if let Some(second_colon) = text[first_colon + 1..].find(':') {
                                    let data_start = first_colon + 1 + second_colon + 1;
                                    &text[data_start..]
                                } else {
                                    &text
                                }
                            } else {
                                &text
                            }
                        } else {
                            &text
                        };
                        if !payload.is_empty()
                            && session.text(payload.to_string()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Binary(data))) => {
                        if session.binary(data.to_vec()).await.is_err() { break; }
                    }
                    Some(Ok(tungstenite::Message::Ping(data))) => {
                        let _ = futures::SinkExt::send(&mut pve_sink,
                            tungstenite::Message::Pong(data)).await;
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => break,
                    // Break on an upstream error too. tungstenite is better
                    // behaved than actix-ws here, but a bridge whose remote leg
                    // has errored cannot do anything useful, and swallowing it
                    // risks the same never-terminating loop as the browser side.
                    Some(Err(e)) => {
                        error!("pve_console: upstream websocket error: {} — closing", e);
                        break;
                    }
                    // Pong / Frame / Continuation — nothing to forward.
                    Some(Ok(_)) => {}
                }
            }

            // Browser → PVE: wrap in PVE termproxy protocol (0:len:msg)
            msg = msg_stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let pve_msg = format!("0:{}:{}", text.len(), text);
                        if futures::SinkExt::send(&mut pve_sink,
                            tungstenite::Message::Text(pve_msg)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        let text = String::from_utf8_lossy(&data);
                        let pve_msg = format!("0:{}:{}", text.len(), text);
                        if futures::SinkExt::send(&mut pve_sink,
                            tungstenite::Message::Text(pve_msg)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        let _ = session.pong(&bytes).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    // An errored browser stream MUST end the bridge.
                    //
                    // actix-ws does NOT terminate its stream after an error:
                    // `MessageStream::poll_next` returns it WITHOUT setting
                    // `closing` (actix-ws 0.3.1 stream.rs:176; the `?` on
                    // codec.decode at :189 does the same while the offending
                    // bytes stay buffered). Every later poll therefore yields
                    // the same error, immediately ready, for ever.
                    //
                    // A catch-all `_ => {}` let that fall through, so the select
                    // loop re-polled with nothing to await — a hot spin that also
                    // never dropped either side's socket. Measured on a user's
                    // node 2026-08-06: seven actix workers pegged, 29,344 sockets
                    // stranded in CLOSE-WAIT and 42 leaked /dev/ptmx handles,
                    // until the fd table hit its 65,535 ceiling and accept()
                    // began failing.
                    Some(Err(e)) => {
                        error!("pve_console: browser websocket error: {} — closing", e);
                        break;
                    }
                    // Pong / Continuation / Nop — nothing to forward.
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    // Cleanup
    let _ = futures::SinkExt::close(&mut pve_sink).await;
    let _ = session.close(None).await;

}

/// Extract username from PVE API token
/// Token format: "user@realm!tokenid=secret-uuid" or "PVEAPIToken=user@realm!tokenid=secret-uuid"
fn _user_from_token(token: &str) -> String {
    let t = token.strip_prefix("PVEAPIToken=").unwrap_or(token);
    // user@realm!tokenid=secret → user@realm
    if let Some(pos) = t.find('!') {
        t[..pos].to_string()
    } else {
        "root@pam".to_string()
    }
}
