// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Discord gateway receiver — reads messages posted in channels bound
//! to WolfAgents and replies with the agent's response.
//!
//! Protocol: hand-rolled against Discord's v10 gateway. We already have
//! tokio-tungstenite (for KasmVNC proxy) and reqwest (everywhere), so
//! no new dependency is pulled in; avoids serenity's ~50 transitive
//! crates for a surface that's maybe 300 lines of protocol.
//!
//! Security posture:
//!
//! * **Bot token** lives in `AlertConfig.discord_bot_token` (file
//!   mode 0o600 — see `alerting::AlertConfig::save`). Never logged —
//!   we mask on display and only send it over the authenticated TLS
//!   gateway connection.
//!
//! * **Abuse guard**. The `chat_with_agent` path has a per-agent
//!   rate limit (20 chats/min). Anyone with posting rights in a
//!   bound Discord channel can talk to the agent — that's the
//!   feature — but they can't burn unbounded AI tokens.
//!
//! * **Self-message skip**. We ignore messages authored by our own
//!   user-id so the bot doesn't reply to itself and infinite-loop.
//!
//! * **Channel binding = authorisation**. An agent only processes
//!   messages in the channel its operator bound it to. Change
//!   binding = change access, controlled from the WolfStack UI.
//!
//! * **Reconnect**. If the gateway drops, the caller (main.rs) sleeps
//!   30s and spawns us again. Discord rate-limits session creates at
//!   1 per 5s per token so a tight reconnect loop on a bad token
//!   would be our fault; 30s is well over that.

use actix_web::web;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{info, warn};

type AppData = web::Data<crate::api::AppState>;

/// Shared HTTP client for every Discord bot. Same pattern as
/// src/telegram_bot/mod.rs — one connection pool for all bots
/// combined. Each outbound call sets its own timeout via
/// `RequestBuilder::timeout` because the gateway lookup (15s) and
/// send-message (implicit default) differ.
pub(crate) static DISCORD_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Gateway opcodes we care about. Full list is in the Discord docs;
/// opcodes we don't send never need to appear here.
const OP_DISPATCH: u64 = 0;
const OP_HEARTBEAT: u64 = 1;
const OP_IDENTIFY: u64 = 2;
const OP_RECONNECT: u64 = 7;
const OP_INVALID_SESSION: u64 = 9;
const OP_HELLO: u64 = 10;
const OP_HEARTBEAT_ACK: u64 = 11;

/// Intent bits we need. GUILDS so we see the guild+channel structure;
/// GUILD_MESSAGES so we see messages; MESSAGE_CONTENT so we see the
/// actual text of those messages (privileged — has to be toggled ON
/// in the Discord developer portal for the bot).
const INTENT_GUILDS: u64 = 1 << 0;
const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;

/// Minimal shape of a Discord message. Only the fields we route on.
#[derive(Debug, Clone, Deserialize)]
struct DiscordMessage {
    id: String,
    channel_id: String,
    content: String,
    author: DiscordUser,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscordUser {
    id: String,
    #[serde(default)]
    bot: bool,
    /// Legacy Discord handle (e.g. "paulc"). Always present on real
    /// users, sometimes empty on bots / webhooks.
    #[serde(default)]
    username: String,
    /// Modern display name (Discord moved away from #discriminators).
    /// Optional — falls back to `username` when not set.
    #[serde(default)]
    global_name: Option<String>,
}

impl DiscordUser {
    /// Best display name for the user — global_name when set (modern
    /// Discord display), else falls back to the legacy username, else
    /// the numeric ID. Used to tell agents who they're talking to.
    fn display_name(&self) -> String {
        if let Some(g) = self.global_name.as_ref().filter(|s| !s.is_empty()) {
            return g.clone();
        }
        if !self.username.is_empty() {
            return self.username.clone();
        }
        self.id.clone()
    }
}

/// Where to connect the gateway. Discord will route us to the nearest
/// edge and tell us session limits — we only use the URL.
#[derive(Debug, Deserialize)]
struct GatewayInfo {
    url: String,
}

/// Outbound identify payload. We don't use sharding, compression,
/// presence or voice — a single bot instance listening for messages.
#[derive(Serialize)]
struct IdentifyProperties {
    os: &'static str,
    browser: &'static str,
    device: &'static str,
}

/// Main entry point — spawned from `main.rs` as a long-lived tokio
/// task. Returns when the connection dies (caller restarts us).
pub async fn run_once(bot_token: String, state: AppData) -> Result<(), String> {
    // ── Step 1: resolve gateway URL ─────────────────────────────
    // Shared pool — see DISCORD_CLIENT. Every bot gateway session
    // and every send_discord_message reuses the same connection pool.
    let http = &*DISCORD_CLIENT;
    let gateway_resp = http
        .get("https://discord.com/api/v10/gateway/bot")
        .header("Authorization", format!("Bot {}", bot_token))
        .header("User-Agent", "WolfStack/18 (https://wolf.uk.com)")
        .timeout(Duration::from_secs(15))
        .send().await
        .map_err(|e| format!("gateway lookup: {}", e))?;
    // Capture status then drain → parse in one path so the socket
    // always goes back to the pool cleanly (error_for_status drops
    // the unread body on non-2xx, which was a latent leak here).
    let gateway_status = gateway_resp.status();
    let gateway_body = gateway_resp.text().await
        .map_err(|e| format!("gateway read: {}", e))?;
    if !gateway_status.is_success() {
        return Err(format!("gateway status {}: {}", gateway_status, gateway_body.chars().take(200).collect::<String>()));
    }
    let gateway: GatewayInfo = serde_json::from_str(&gateway_body)
        .map_err(|e| format!("gateway decode: {}", e))?;

    let ws_url = format!("{}/?v=10&encoding=json", gateway.url);
    info!("discord_bot: connecting to {}", gateway.url);

    // ── Step 2: connect the WebSocket ───────────────────────────
    let (ws_stream, _resp) = tokio_tungstenite::connect_async(&ws_url).await
        .map_err(|e| format!("ws connect: {}", e))?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Sequence number is shared between the main recv loop (which
    // updates it on every dispatch frame) and the heartbeat task
    // (which reads it when crafting heartbeat payloads). -1 marks
    // "haven't seen any events yet" per Discord spec.
    let last_seq = Arc::new(AtomicI64::new(-1));
    let mut own_user_id: Option<String> = None;

    // Hand-rolled MPSC so the heartbeat task can enqueue frames for
    // ws_tx. actix/tokio mpsc is fine; bounded tiny capacity.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<String>(32);
    let out_tx_heartbeat = out_tx.clone();

    // ── Step 3: read HELLO to learn the heartbeat interval ──────
    let hello_frame = ws_rx.next().await
        .ok_or("gateway closed before HELLO")?
        .map_err(|e| format!("hello read: {}", e))?;
    let hello_text = match hello_frame {
        WsMessage::Text(t) => t.to_string(),
        WsMessage::Binary(b) => String::from_utf8_lossy(&b).to_string(),
        _ => return Err("unexpected hello frame type".into()),
    };
    let hello_val: serde_json::Value = serde_json::from_str(&hello_text)
        .map_err(|e| format!("hello parse: {}", e))?;
    if hello_val.get("op").and_then(|v| v.as_u64()) != Some(OP_HELLO) {
        return Err(format!("expected HELLO, got op {:?}", hello_val.get("op")));
    }
    let heartbeat_ms = hello_val.pointer("/d/heartbeat_interval")
        .and_then(|v| v.as_u64())
        .ok_or("HELLO missing heartbeat_interval")?;

    // ── Step 4: spawn heartbeat task ────────────────────────────
    let seq_hb = last_seq.clone();
    tokio::spawn(async move {
        // First heartbeat is jittered per Discord recommendation.
        let initial = (heartbeat_ms as f64 * 0.5) as u64;
        tokio::time::sleep(Duration::from_millis(initial)).await;
        loop {
            let seq = seq_hb.load(Ordering::Acquire);
            let payload = if seq < 0 {
                serde_json::json!({"op": OP_HEARTBEAT, "d": serde_json::Value::Null})
            } else {
                serde_json::json!({"op": OP_HEARTBEAT, "d": seq})
            };
            if out_tx_heartbeat.send(payload.to_string()).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(heartbeat_ms)).await;
        }
    });

    // ── Step 5: send IDENTIFY ───────────────────────────────────
    let intents = INTENT_GUILDS | INTENT_GUILD_MESSAGES | INTENT_MESSAGE_CONTENT;
    let identify = serde_json::json!({
        "op": OP_IDENTIFY,
        "d": {
            "token": bot_token,
            "intents": intents,
            "properties": IdentifyProperties {
                os: std::env::consts::OS,
                browser: "wolfstack",
                device: "wolfstack",
            },
        }
    });
    out_tx.send(identify.to_string()).await
        .map_err(|e| format!("identify enqueue: {}", e))?;

    // ── Step 6: ferry outbound messages to the socket ───────────
    // Separate task so the recv loop doesn't block on writer I/O.
    tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if ws_tx.send(WsMessage::Text(frame)).await.is_err() {
                break;
            }
        }
    });

    // ── Step 7: main receive loop ───────────────────────────────
    while let Some(frame) = ws_rx.next().await {
        let text = match frame {
            Ok(WsMessage::Text(t)) => t.to_string(),
            Ok(WsMessage::Binary(b)) => String::from_utf8_lossy(&b).to_string(),
            Ok(WsMessage::Close(reason)) => {
                warn!("discord_bot: gateway closed — {:?}", reason);
                break;
            }
            Ok(_) => continue,
            Err(e) => {
                warn!("discord_bot: ws error — {}", e);
                break;
            }
        };
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => { warn!("discord_bot: bad frame json — {}", e); continue; }
        };
        let op = v.get("op").and_then(|x| x.as_u64()).unwrap_or(OP_DISPATCH);
        if let Some(s) = v.get("s").and_then(|x| x.as_i64()) {
            last_seq.store(s, Ordering::Release);
        }
        match op {
            OP_HEARTBEAT_ACK => { /* healthy */ }
            OP_RECONNECT => {
                info!("discord_bot: server requested reconnect");
                break;
            }
            OP_INVALID_SESSION => {
                warn!("discord_bot: invalid session — caller should re-identify");
                break;
            }
            OP_DISPATCH => {
                let event_type = v.get("t").and_then(|x| x.as_str()).unwrap_or("");
                match event_type {
                    "READY" => {
                        // Stash our own user id so we can skip our own
                        // messages.
                        own_user_id = v.pointer("/d/user/id")
                            .and_then(|x| x.as_str())
                            .map(String::from);
                        info!("discord_bot: connected as user {:?}", own_user_id);
                    }
                    "MESSAGE_CREATE" => {
                        let Some(d) = v.get("d") else { continue; };
                        let msg: DiscordMessage = match serde_json::from_value(d.clone()) {
                            Ok(m) => m,
                            Err(e) => { warn!("discord_bot: malformed message: {}", e); continue; }
                        };
                        // Skip our own + any other bot to stop loops.
                        if msg.author.bot { continue; }
                        if own_user_id.as_deref() == Some(&msg.author.id) { continue; }
                        // Find the bound agent for this channel AND this
                        // specific bot. In a multi-bot deployment two
                        // agents might share a channel_id on different
                        // bots; matching on token too stops bot X from
                        // replying for agent B which is actually on bot Y.
                        let global_token = crate::alerting::AlertConfig::load().discord_bot_token;
                        let agents = crate::wolfagents::load_all();
                        let Some(agent) = agents.iter().find(|a| {
                            let Some(d) = &a.discord else { return false; };
                            if d.channel_id != msg.channel_id { return false; }
                            let agent_token = d.bot_token.as_deref()
                                .filter(|t| !t.trim().is_empty())
                                .unwrap_or(global_token.as_str());
                            agent_token == bot_token
                        }).cloned() else { continue; };
                        // Fire the chat turn in a task so the recv
                        // loop keeps draining. Agent turns can take
                        // seconds; blocking the loop would stall
                        // heartbeat seq updates.
                        // UFCS clone forces an owned `Client` (cheap
                        // Arc clone) instead of cloning the &Client
                        // reference — spawned futures need 'static.
                        let http_reply: reqwest::Client = reqwest::Client::clone(http);
                        let token = bot_token.clone();
                        let s = state.clone();
                        tokio::spawn(async move {
                            handle_discord_chat(http_reply, &token, &agent, msg, s).await;
                        });
                    }
                    _ => { /* ignore — presence, typing, etc. */ }
                }
            }
            _ => { /* ignore other opcodes */ }
        }
    }

    Ok(())
}

/// Process one incoming Discord message: run the agent, post the
/// reply back to the same channel.
async fn handle_discord_chat(
    http: reqwest::Client,
    bot_token: &str,
    agent: &crate::wolfagents::Agent,
    msg: DiscordMessage,
    state: AppData,
) {
    // Quick input trim — Discord messages are up to 2000 chars; no
    // need for a server-side cap on top of the agent's own cap.
    let content = msg.content.trim();
    if content.is_empty() { return; }

    // Tell the agent who's asking. Without this the agent has no way
    // to address users by name or distinguish between people in a
    // shared channel. Format chosen so the LLM treats it as metadata
    // about the speaker rather than part of the question.
    let display = msg.author.display_name();
    let with_speaker = if display.is_empty() {
        content.to_string()
    } else {
        format!("[from Discord user \"{}\"] {}", display, content)
    };

    // Full tool-use loop, same as the dashboard path — lets Discord
    // callers invoke tools the agent has granted instead of silently
    // falling back to simple_chat.
    let reply = match crate::wolfagents::chat_with_agent_full(
        &agent.id, &with_speaker, state.get_ref(),
        crate::wolfagents::ChatSurface::Discord,
    ).await {
        Ok(r) => r,
        Err(e) => format!("(agent error) {}", e),
    };
    // Discord caps messages at 2000 chars per message. Chunk the reply
    // on paragraph / line boundaries so long agent outputs (logs, code
    // blocks, diagnostic dumps) arrive in full instead of being clipped
    // at 1900 chars with a "…(truncated)" suffix that loses data.
    for chunk in chunk_for_discord(&reply) {
        if let Err(e) = send_discord_message(&http, bot_token, &msg.channel_id, &chunk).await {
            warn!("discord_bot: reply failed for agent {} msg {}: {}", agent.id, msg.id, e);
            break;
        }
    }
}

/// Split `text` into Discord-sized chunks (&lt;= 1900 chars each, leaving
/// headroom under the 2000-char hard cap for the odd extra codepoint).
/// Prefers splitting at paragraph breaks, then lines, then spaces,
/// falling back to a raw char-boundary cut only when a single line is
/// longer than the limit. Returns at least one element even for empty
/// input so callers can iterate without a None-check.
fn chunk_for_discord(text: &str) -> Vec<String> {
    const LIMIT: usize = 1900;
    if text.is_empty() { return vec![String::new()]; }
    if text.chars().count() <= LIMIT { return vec![text.to_string()]; }
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    // Walk paragraph-by-paragraph so we keep markdown formatting intact.
    // If a single paragraph exceeds the limit we break it at newlines,
    // then spaces, then a hard cut. The inner helper is inlined for
    // locality — this is the only caller.
    for para in text.split("\n\n") {
        let needed = para.chars().count() + if current.is_empty() { 0 } else { 2 };
        if !current.is_empty() && current.chars().count() + needed > LIMIT {
            out.push(std::mem::take(&mut current));
        }
        if para.chars().count() <= LIMIT {
            if !current.is_empty() { current.push_str("\n\n"); }
            current.push_str(para);
            continue;
        }
        // Paragraph too long on its own — split on single newlines.
        if !current.is_empty() { out.push(std::mem::take(&mut current)); }
        for line in para.split('\n') {
            if current.chars().count() + line.chars().count() + 1 > LIMIT && !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            if line.chars().count() <= LIMIT {
                if !current.is_empty() { current.push('\n'); }
                current.push_str(line);
                continue;
            }
            // Single line still too long — break by char count, respecting
            // codepoint boundaries so we don't split a multi-byte char.
            let mut remaining = line;
            while remaining.chars().count() > LIMIT {
                let cut = remaining.char_indices().nth(LIMIT).map(|(i, _)| i).unwrap_or(remaining.len());
                if !current.is_empty() { out.push(std::mem::take(&mut current)); }
                out.push(remaining[..cut].to_string());
                remaining = &remaining[cut..];
            }
            if !remaining.is_empty() {
                if !current.is_empty() { current.push('\n'); }
                current.push_str(remaining);
            }
        }
    }
    if !current.is_empty() { out.push(current); }
    if out.is_empty() { out.push(String::new()); }
    out
}

/// POST a message to a Discord channel. Thin wrapper around the HTTP
/// API so the gateway code doesn't need to know REST endpoints.
pub async fn send_discord_message(
    http: &reqwest::Client,
    bot_token: &str,
    channel_id: &str,
    content: &str,
) -> Result<(), String> {
    let url = format!("https://discord.com/api/v10/channels/{}/messages", channel_id);
    let body = serde_json::json!({ "content": content });
    let resp = http.post(&url)
        .header("Authorization", format!("Bot {}", bot_token))
        .header("User-Agent", "WolfStack/18 (https://wolf.uk.com)")
        .json(&body)
        .send().await
        .map_err(|e| format!("http send: {}", e))?;
    let status = resp.status();
    // `.text()` drains the body whether success or error, so the
    // socket returns to the keep-alive pool in both paths.
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Discord API {}: {}", status.as_u16(), body.chars().take(200).collect::<String>()));
    }
    Ok(())
}

/// Supervisor loop — spawned once at startup. Reconciles the set of
/// Discord bot tokens that should have a gateway session running. The
/// desired set is the union of:
///   - the global `AlertConfig.discord_bot_token` (when non-empty), and
///   - every per-agent `discord.bot_token` override.
///
/// For each unique token the supervisor keeps one gateway session
/// (run_once) alive; tokens that leave the set have their session
/// aborted. Sessions that exit on their own (gateway dropped, error)
/// are auto-restarted on the next reconciliation tick, with a 30s
/// cooldown to avoid hammering the gateway.
pub async fn supervise_forever(state: AppData) {
    // Short startup delay so the rest of the stack initialises first.
    tokio::time::sleep(Duration::from_secs(30)).await;
    use std::collections::HashMap;
    use tokio::task::JoinHandle;
    let mut running: HashMap<String, JoinHandle<()>> = HashMap::new();
    loop {
        let desired = desired_token_set();
        // Prune finished / dead tasks so they restart on the next pass.
        let finished: Vec<String> = running.iter()
            .filter(|(_, h)| h.is_finished())
            .map(|(k, _)| k.clone()).collect();
        for token in finished { running.remove(&token); }
        // Spawn sessions for newly-desired tokens.
        for token in &desired {
            if !running.contains_key(token) {
                let tok = token.clone();
                let s = state.clone();
                info!("discord_bot: starting gateway session for bot ending …{}", tok_tail(&tok));
                let handle = tokio::spawn(async move {
                    match run_once(tok.clone(), s).await {
                        Ok(()) => info!("discord_bot (…{}): gateway exited cleanly", tok_tail(&tok)),
                        Err(e) => warn!("discord_bot (…{}): gateway errored: {}", tok_tail(&tok), e),
                    }
                });
                running.insert(token.clone(), handle);
            }
        }
        // Abort sessions whose tokens are no longer in the desired set.
        let stale: Vec<String> = running.keys()
            .filter(|k| !desired.contains(*k)).cloned().collect();
        for token in stale {
            if let Some(h) = running.remove(&token) {
                info!("discord_bot: stopping gateway session for bot ending …{}", tok_tail(&token));
                h.abort();
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// Desired set of bot tokens — union of global and per-agent overrides.
fn desired_token_set() -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let cfg = crate::alerting::AlertConfig::load();
    if !cfg.discord_bot_token.trim().is_empty() {
        out.insert(cfg.discord_bot_token.clone());
    }
    for agent in crate::wolfagents::load_all() {
        if let Some(d) = &agent.discord
            && let Some(t) = &d.bot_token {
                let t = t.trim();
                if !t.is_empty() { out.insert(t.to_string()); }
            }
    }
    out
}

fn tok_tail(t: &str) -> String {
    t.chars().rev().take(6).collect::<String>().chars().rev().collect()
}
