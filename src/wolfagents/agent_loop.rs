// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Multi-round tool_use loop for WolfAgents.
//!
//! `simple_chat` is a one-shot prompt → text call — fine for stateless
//! AiInvoke workflow steps, useless for agents that need to look up
//! cluster state and take action. This loop implements Anthropic's
//! tool_use protocol end-to-end:
//!
//! 1. Build tool definitions from the agent's allowed_tools list.
//! 2. POST /v1/messages with `tools: [...]` and the conversation so far.
//! 3. Parse response blocks. If `stop_reason == "tool_use"`:
//!    a. For each tool_use block, dispatch via `dispatch::dispatch`.
//!    b. Build matching tool_result blocks.
//!    c. Append both the assistant turn AND the tool_result turn to
//!    the conversation and loop.
//! 4. Stop when `stop_reason` is `end_turn` / `max_tokens` / reach the
//!    per-turn round cap (so a bad response can't spin forever).
//! 5. Return the final assistant text + a compact trace of tool calls
//!    the caller can log/display.
//!
//! For Gemini / OpenRouter / local providers we fall back to
//! `simple_chat` — their function-calling wire formats differ enough
//! that reusing Claude's pipeline wholesale doesn't work. That means
//! agents on non-Claude providers lose tool access but keep basic
//! chat; documenting this in the UI is the operator's safety net.

use serde::{Deserialize, Serialize};

/// Shared HTTP client for every agent tool-use turn (OpenAI-compat,
/// Gemini, Claude). Per-turn `crate::api::ipv4_only_client_builder()` was
/// leaking a connection pool on every round of every agent
/// conversation. 180s timeout set per-request via RequestBuilder.
static AGENT_LOOP_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            // Never leave a connect hanging for the kernel's SYN retry
            // window — see POLL_CLIENT (2026-08-05 fd exhaustion).
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });
use tracing::warn;

use super::{Agent, dispatch, tools::{ToolId, Danger}};

/// Summary of one completed agent turn. Returned to the caller (REST
/// API handler or WolfFlow AgentChat) so they can render the final
/// assistant text plus an audit trail of what the agent did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTurn {
    /// Model's final text response to the user.
    pub response: String,
    /// Per-round tool invocations, in order. Useful for the UI's
    /// "show what the agent did" panel.
    pub tool_calls: Vec<ToolCallTrace>,
    /// Why the loop ended. "end_turn" (normal), "max_rounds"
    /// (hit the guard), "error:...", or "fallback_no_tools" when the
    /// provider doesn't support tool use.
    pub stop_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallTrace {
    pub tool: String,
    pub arguments: serde_json::Value,
    pub ok: bool,
    pub status: String,
}

/// Drive a full agent turn. Assembles the conversation (history +
/// optional cluster context + this user message), chooses the provider
/// path, and returns an AgentTurn summary.
pub async fn run_turn(
    agent: &Agent,
    history: Vec<crate::ai::ChatMessage>,
    user_message: &str,
    state: &crate::api::AppState,
) -> Result<AgentTurn, String> {
    let mut cfg = crate::ai::AiConfig::load();
    // Per-agent override (empty = inherit from global settings).
    if !agent.provider.is_empty() { cfg.provider = agent.provider.clone(); }
    if !agent.model.is_empty() { cfg.model = agent.model.clone(); }
    if !cfg.is_configured() {
        return Err("AI not configured — set provider/key in Settings → AI Agent".to_string());
    }

    let system_prompt = build_system_prompt(agent, state).await;

    // Claude and Gemini both get native tool loops. OpenRouter /
    // local fall back to plain chat without tool access — their
    // function-calling protocols differ enough that implementing each
    // is a separate ship. Gemini's addition closes the old gap where
    // the system prompt advertised tools and Gemini "complied" by
    // emitting tool-looking TEXT (e.g. ``**tool_code** print(list_nodes())``)
    // instead of a real function call.
    match cfg.provider.as_str() {
        "claude" => {
            claude_tool_loop(agent, &cfg, &system_prompt, &history, user_message, state).await
        }
        "gemini" => {
            gemini_tool_loop(agent, &cfg, &system_prompt, &history, user_message, state).await
        }
        "openrouter" => {
            openai_tool_loop(
                agent, &cfg, OpenAiEndpoint { base_url: "https://openrouter.ai/api/v1", api_key: &cfg.openrouter_api_key },
                &system_prompt, &history,
                user_message, state,
            ).await
        }
        "openai" => {
            openai_tool_loop(
                agent, &cfg, OpenAiEndpoint { base_url: "https://api.openai.com/v1", api_key: &cfg.openai_api_key },
                &system_prompt, &history,
                user_message, state,
            ).await
        }
        "local" => {
            openai_tool_loop(
                agent, &cfg, OpenAiEndpoint { base_url: &cfg.local_url, api_key: &cfg.local_api_key },
                &system_prompt, &history,
                user_message, state,
            ).await
        }
        _ => {
            // Anything truly unknown still falls through so misconfig
            // doesn't kill the chat — e.g. a provider name typo.
            let reply = crate::ai::simple_chat(&cfg, &system_prompt, &history, user_message).await?;
            Ok(AgentTurn {
                response: reply,
                tool_calls: Vec::new(),
                stop_reason: "fallback_no_tools".to_string(),
            })
        }
    }
}

struct OpenAiEndpoint<'a> {
    base_url: &'a str,
    api_key: &'a str,
}

/// OpenAI-compatible tool loop — used for OpenRouter and any local
/// OpenAI-compatible server (Ollama, LM Studio, vLLM, llama.cpp
/// server, etc.). The wire format is standardised: `tools` carries an
/// array of `{"type": "function", "function": {...}}` entries, the
/// model responds with a `tool_calls` field on the assistant message,
/// tool results come back as `{"role": "tool", "tool_call_id": ..., "content": ...}`.
///
/// Not every local model supports this — Ollama gates it behind model
/// families that were fine-tuned for function calling (llama3.1+,
/// qwen2.5, etc.). When the server returns a plain text reply without
/// `tool_calls`, we treat it as the final answer same as Claude/Gemini.
async fn openai_tool_loop(
    agent: &Agent,
    cfg: &crate::ai::AiConfig,
    endpoint: OpenAiEndpoint<'_>,
    system_prompt: &str,
    history: &[crate::ai::ChatMessage],
    user_message: &str,
    state: &crate::api::AppState,
) -> Result<AgentTurn, String> {
    let OpenAiEndpoint { base_url, api_key } = endpoint;
    if base_url.trim().is_empty() {
        return Err("Local/OpenRouter base URL not configured — set it in Settings → AI Agent".into());
    }
    let client = &*AGENT_LOOP_CLIENT;

    // Normalise base_url → fully-qualified chat/completions URL. Matches
    // the heuristic in ai::call_local so operators can paste either
    // `http://host:11434`, `http://host:11434/v1`, or the fully-
    // qualified `/chat/completions` URL.
    let url = {
        let trimmed = base_url.trim_end_matches('/');
        if trimmed.ends_with("/chat/completions") { trimmed.to_string() }
        else if trimmed.ends_with("/v1") { format!("{}/chat/completions", trimmed) }
        else { format!("{}/v1/chat/completions", trimmed) }
    };

    // Initial messages: system + history + new user turn. `role: "tool"`
    // entries will be appended when we dispatch tool calls.
    let mut messages: Vec<serde_json::Value> = Vec::new();
    messages.push(serde_json::json!({ "role": "system", "content": system_prompt }));
    for m in history {
        if m.role != "user" && m.role != "assistant" { continue; }
        messages.push(serde_json::json!({ "role": m.role, "content": m.content }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": user_message }));

    let tools_json = build_openai_tools(agent);
    let mut trace: Vec<ToolCallTrace> = Vec::new();
    let max_rounds = cfg.effective_agent_max_tool_calls();

    for _round in 0..max_rounds {
        let mut body = serde_json::json!({
            "model": cfg.model,
            "messages": messages,
            "temperature": 0.7,
        });
        if !tools_json.is_empty() {
            body["tools"] = serde_json::json!(tools_json);
            body["tool_choice"] = serde_json::json!("auto");
        }

        let mut req = client.post(&url)
            .timeout(std::time::Duration::from_secs(180))
            .header("content-type", "application/json")
            .json(&body);
        if !api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", api_key));
        }
        let resp = req.send().await
            .map_err(|e| format!("OpenAI-compat API error ({}): {}", url, e))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("read body: {}", e))?;
        if !status.is_success() {
            return Err(format!("OpenAI-compat API {} — {}", status, text));
        }
        let payload: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("parse response: {} — body: {}",
                e, text.chars().take(200).collect::<String>()))?;

        let choice = &payload["choices"][0];
        let msg = &choice["message"];
        let finish_reason = choice["finish_reason"].as_str().unwrap_or("").to_string();
        let content_text = msg["content"].as_str().unwrap_or("").to_string();
        let mut tool_calls_json = msg["tool_calls"].as_array().cloned().unwrap_or_default();

        // Recover tool calls that the model emitted as JSON inside
        // `content` instead of in the structured `tool_calls` field.
        // Common with smaller / not-tool-fine-tuned local models
        // (qwen2.5 below 7B, several llama-coder variants, gemma
        // tunes). Without this, tool calls get returned to the user
        // as raw JSON "responses" and never execute.
        //
        // Allowlist is the agent's own `allowed_tools` set — an
        // extracted name not in there is dropped, preventing prose
        // like `{"name": "some_service", "status": "x"}` from
        // synthesising a phantom call. Tool-call IDs use the
        // OpenAI `call_<hex>` format so a future swap to OpenAI
        // proper (which validates ID shape) doesn't reject the
        // recovered turn's history.
        if tool_calls_json.is_empty() && !content_text.is_empty() {
            let allowed: Vec<&str> = agent.allowed_tools.iter().map(|s| s.as_str()).collect();
            if let Some(extracted) = crate::ai::extract_tool_calls_from_content(&content_text, &allowed) {
                tracing::info!(
                    target: "wolfstack::wolfagents",
                    "openai_tool_loop: model emitted {} tool call(s) inside content \
                     (no structured tool_calls field) — recovered via fallback parser. \
                     agent={} model={} finish_reason={}",
                    extracted.len(), agent.id, cfg.model, finish_reason,
                );
                for (i, (name, args)) in extracted.into_iter().enumerate() {
                    tool_calls_json.push(serde_json::json!({
                        "id": format!("call_{:016x}",
                            // Mix the round counter, agent id length,
                            // and a millisecond timestamp so two
                            // recovered turns in the same session
                            // never collide.
                            (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                                .wrapping_add(agent.id.len() as u64)
                                .wrapping_add(
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_millis() as u64)
                                        .unwrap_or(0)
                                )
                        ),
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()),
                        },
                    }));
                }
            }
        }

        // No tool calls → terminal turn. Some local servers never emit
        // tool_calls even when given tools; the content is their final
        // answer.
        if tool_calls_json.is_empty() {
            return Ok(AgentTurn {
                response: if content_text.is_empty() {
                    format!("(empty response; finish_reason={})", finish_reason)
                } else { content_text },
                tool_calls: trace,
                stop_reason: finish_reason,
            });
        }

        // Parse each tool_call into (id, name, parsed_args).
        struct PendingCall { id: String, name: String, args: serde_json::Value }
        let mut pending: Vec<PendingCall> = Vec::new();
        for tc in &tool_calls_json {
            let id = tc["id"].as_str().unwrap_or("").to_string();
            let name = tc["function"]["name"].as_str().unwrap_or("").to_string();
            // `arguments` is a JSON-encoded string per OpenAI's spec.
            // Parse defensively — some local models emit the raw object.
            let args_raw = &tc["function"]["arguments"];
            let args: serde_json::Value = if let Some(s) = args_raw.as_str() {
                serde_json::from_str(s).unwrap_or_else(|_| serde_json::json!({}))
            } else {
                args_raw.clone()
            };
            pending.push(PendingCall { id, name, args });
        }

        // Echo the assistant turn (including tool_calls) back so the
        // next request has the context OpenAI expects.
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": if content_text.is_empty() { serde_json::Value::Null }
                       else { serde_json::Value::String(content_text) },
            "tool_calls": tool_calls_json,
        }));

        // Dispatch each call and append a tool-role message per result.
        for call in &pending {
            let result = dispatch::dispatch(agent, &call.name, &call.args, state).await;
            trace.push(ToolCallTrace {
                tool: call.name.clone(),
                arguments: call.args.clone(),
                ok: result.ok,
                status: result.status.clone(),
            });
            let content = serde_json::to_string(&serde_json::json!({
                "status": result.status,
                "ok": result.ok,
                "data": result.data,
            })).unwrap_or_else(|_| result.status.clone());
            messages.push(serde_json::json!({
                "role": "tool",
                "tool_call_id": call.id,
                "content": content,
            }));
        }
    }

    warn!("wolfagents: agent {} (openai-compat) hit max_rounds={}", agent.id, max_rounds);
    Ok(AgentTurn {
        response: format!(
            "(agent aborted after {} tool-use rounds — raise the limit in \
             Settings → AI Agent → \"Cap agent tool-calls per turn\", or tighten the \
             system prompt so the agent reaches a conclusion faster)",
            max_rounds
        ),
        tool_calls: trace,
        stop_reason: "max_rounds".to_string(),
    })
}

/// Build OpenAI-shaped tool descriptors. No schema rewriting needed —
/// OpenAI's Chat Completions API accepts full JSON Schema.
fn build_openai_tools(agent: &Agent) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for name in &agent.allowed_tools {
        let Some(tool) = ToolId::from_str(name) else { continue; };
        out.push(serde_json::json!({
            "type": "function",
            "function": {
                "name": tool.as_str(),
                "description": tool.risk_note(),
                "parameters": input_schema_for(tool),
            }
        }));
    }
    out
}

/// Gemini tool loop — mirrors the Claude loop but on Google's
/// `generateContent` endpoint with `functionDeclarations`.
///
/// Differences from Claude:
/// - System instruction is a top-level `systemInstruction` field, not
///   part of the messages array.
/// - Messages are called `contents`; roles are `user` and `model`
///   (not `user`/`assistant`).
/// - Tool calls come back as a `functionCall` part on a model turn.
/// - Tool results are sent as a `functionResponse` part on a user turn.
/// - No explicit stop_reason — we stop when the model emits text with
///   no functionCall, or we hit the configured max_rounds.
async fn gemini_tool_loop(
    agent: &Agent,
    cfg: &crate::ai::AiConfig,
    system_prompt: &str,
    history: &[crate::ai::ChatMessage],
    user_message: &str,
    state: &crate::api::AppState,
) -> Result<AgentTurn, String> {
    let client = &*AGENT_LOOP_CLIENT;

    // Build the initial contents array. Gemini uses "model" for the
    // assistant role; translate from our canonical "assistant".
    let mut contents: Vec<serde_json::Value> = Vec::new();
    for m in history {
        if m.role != "user" && m.role != "assistant" { continue; }
        let role = if m.role == "assistant" { "model" } else { "user" };
        contents.push(serde_json::json!({
            "role": role,
            "parts": [{ "text": m.content }],
        }));
    }
    contents.push(serde_json::json!({
        "role": "user",
        "parts": [{ "text": user_message }],
    }));

    let function_decls = build_gemini_function_decls(agent);
    let mut trace: Vec<ToolCallTrace> = Vec::new();
    let max_rounds = cfg.effective_agent_max_tool_calls();

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        cfg.model, cfg.gemini_api_key
    );

    for _round in 0..max_rounds {
        let mut body = serde_json::json!({
            "contents": contents,
            "systemInstruction": {
                "parts": [{ "text": system_prompt }]
            },
        });
        if !function_decls.is_empty() {
            body["tools"] = serde_json::json!([{
                "functionDeclarations": function_decls.clone(),
            }]);
            // AUTO lets the model decide; forced would demand a call
            // every turn which breaks the natural "answer when done"
            // termination condition.
            body["toolConfig"] = serde_json::json!({
                "functionCallingConfig": { "mode": "AUTO" }
            });
        }

        let resp = client.post(&url)
            .timeout(std::time::Duration::from_secs(120))
            .json(&body).send().await
            .map_err(|e| format!("Gemini API error: {}", e))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("read body: {}", e))?;
        if !status.is_success() {
            return Err(format!("Gemini API {} — {}", status, text));
        }
        let payload: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("parse response: {} — body: {}",
                e, text.chars().take(200).collect::<String>()))?;

        let parts = payload["candidates"][0]["content"]["parts"]
            .as_array().cloned().unwrap_or_default();
        let finish_reason = payload["candidates"][0]["finishReason"]
            .as_str().unwrap_or("").to_string();

        let mut text_pieces: Vec<String> = Vec::new();
        let mut function_calls: Vec<(String, serde_json::Value)> = Vec::new();
        for part in &parts {
            if let Some(t) = part.get("text").and_then(|v| v.as_str())
                && !t.is_empty() { text_pieces.push(t.to_string()); }
            if let Some(fc) = part.get("functionCall") {
                let name = fc.get("name").and_then(|v| v.as_str())
                    .unwrap_or("").to_string();
                let args = fc.get("args").cloned()
                    .unwrap_or(serde_json::json!({}));
                if !name.is_empty() {
                    function_calls.push((name, args));
                }
            }
        }

        // No tool call → we've landed. Return whatever text Gemini
        // produced (or a helpful placeholder if the model returned an
        // empty model turn, which happens when safety filters trim).
        if function_calls.is_empty() {
            let reply = if text_pieces.is_empty() {
                match finish_reason.as_str() {
                    "SAFETY" => "(Gemini blocked the response under its safety filters. Rephrase the request.)".to_string(),
                    "RECITATION" => "(Gemini blocked the response as possible copyright recitation.)".to_string(),
                    "MAX_TOKENS" => "(Gemini hit max tokens before producing any text.)".to_string(),
                    other if !other.is_empty() => format!("(Gemini returned finishReason={} with no text)", other),
                    _ => "(Gemini returned an empty response)".to_string(),
                }
            } else {
                text_pieces.join("\n")
            };
            return Ok(AgentTurn {
                response: reply,
                tool_calls: trace,
                stop_reason: finish_reason,
            });
        }

        // Persist the model turn carrying the functionCall(s) so the
        // next request shows Gemini its own previous output.
        contents.push(serde_json::json!({
            "role": "model",
            "parts": parts,
        }));

        // Dispatch each functionCall, collect functionResponse parts.
        let mut response_parts: Vec<serde_json::Value> = Vec::new();
        for (name, args) in &function_calls {
            let result = dispatch::dispatch(agent, name, args, state).await;
            trace.push(ToolCallTrace {
                tool: name.clone(),
                arguments: args.clone(),
                ok: result.ok,
                status: result.status.clone(),
            });
            // Gemini expects the response under a named key; use the
            // function name itself to keep it self-describing.
            response_parts.push(serde_json::json!({
                "functionResponse": {
                    "name": name,
                    "response": {
                        "status": result.status,
                        "ok": result.ok,
                        "data": result.data,
                    }
                }
            }));
        }
        contents.push(serde_json::json!({
            "role": "user",
            "parts": response_parts,
        }));
    }

    warn!("wolfagents: agent {} (gemini) hit max_rounds={} — abandoning turn", agent.id, max_rounds);
    Ok(AgentTurn {
        response: format!(
            "(agent aborted after {} tool-use rounds — raise the limit in \
             Settings → AI Agent → \"Cap agent tool-calls per turn\", or tighten the \
             system prompt so the agent reaches a conclusion faster)",
            max_rounds
        ),
        tool_calls: trace,
        stop_reason: "max_rounds".to_string(),
    })
}

/// Build Gemini-shaped function declarations from the agent's
/// allowed_tools list. Same pool of ToolId + input_schema_for as the
/// Claude path — only the envelope differs. Gemini's Schema-ish
/// subset doesn't support some JSON-Schema keywords (e.g. `default`,
/// `anyOf` with null); we strip those via `normalise_schema_for_gemini`.
fn build_gemini_function_decls(agent: &Agent) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for name in &agent.allowed_tools {
        let Some(tool) = ToolId::from_str(name) else { continue; };
        let raw_schema = input_schema_for(tool);
        let parameters = normalise_schema_for_gemini(raw_schema);
        out.push(serde_json::json!({
            "name": tool.as_str(),
            "description": tool.risk_note(),
            "parameters": parameters,
        }));
    }
    out
}

/// Gemini accepts a subset of JSON Schema under the name "Schema".
/// In particular it rejects `["string", "null"]` unions (use nullable),
/// doesn't understand `default`, and doesn't allow `additionalProperties`.
/// This function walks the schema and rewrites the few forms we actually
/// emit. New schema shapes added later may need extensions here.
fn normalise_schema_for_gemini(mut v: serde_json::Value) -> serde_json::Value {
    // Gemini rejects multi-type unions in `type`. Narrow every array form to a
    // single type. Prefer "array" when the union allows it AND an `items`
    // schema is present, so the array+items pair stays valid — Gemini accepts
    // `items` only on ARRAY types. Otherwise take the first non-null type.
    // `["string","null"]` → "string" + nullable; `["string","array","null"]`
    // with items → "array" + nullable.
    if let Some(t) = v.get("type").cloned()
        && let Some(arr) = t.as_array() {
            let non_null: Vec<&serde_json::Value> = arr.iter()
                .filter(|x| x.as_str() != Some("null")).collect();
            let has_null = arr.iter().any(|x| x.as_str() == Some("null"));
            if !non_null.is_empty() {
                let prefer_array = v.get("items").is_some()
                    && non_null.iter().any(|x| x.as_str() == Some("array"));
                v["type"] = if prefer_array {
                    serde_json::Value::String("array".to_string())
                } else {
                    non_null[0].clone()
                };
                if has_null { v["nullable"] = serde_json::Value::Bool(true); }
            } else if has_null {
                // Pure `["null"]` — fall back to string+nullable so the
                // field remains present in the declaration.
                v["type"] = serde_json::Value::String("string".to_string());
                v["nullable"] = serde_json::Value::Bool(true);
            }
        }
    // Gemini accepts `items` ONLY on ARRAY types. A non-array schema carrying a
    // stray `items` — e.g. the SendEmail `to` union narrowed to "string" while
    // keeping its items — fails with
    // "properties[to].items: field predicate failed: $type == Type.ARRAY"
    // (Tor 2026-06-05). Drop `items` unless the (now single) type is array.
    if v.get("type").and_then(|t| t.as_str()) != Some("array")
        && let Some(obj) = v.as_object_mut() { obj.remove("items"); }
    // Recurse into `properties`.
    if let Some(props) = v.get_mut("properties").and_then(|p| p.as_object_mut()) {
        let keys: Vec<String> = props.keys().cloned().collect();
        for k in keys {
            if let Some(child) = props.remove(&k) {
                props.insert(k, normalise_schema_for_gemini(child));
            }
        }
    }
    // Recurse into `items`.
    if let Some(items) = v.get("items").cloned() {
        v["items"] = normalise_schema_for_gemini(items);
    }
    // Strip `default` and `additionalProperties` — Gemini ignores or
    // rejects these; our callers don't rely on them.
    if let Some(obj) = v.as_object_mut() {
        obj.remove("default");
        obj.remove("additionalProperties");
    }
    v
}

/// Compose the per-turn system prompt. Order: agent's personality
/// prompt (operator-authored) first, then — when enabled — the
/// WolfStack knowledge base and a live cluster snapshot. Keeping the
/// operator's text at the top means the model reads its role before
/// the platform details, which matters for behaviour on
/// tiny-context-window models.
async fn build_system_prompt(agent: &Agent, state: &crate::api::AppState) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(agent.system_prompt.clone());

    if agent.include_cluster_context {
        parts.push(wolfstack_kb_section());
        parts.push(cluster_snapshot_section(agent, state).await);
        parts.push(agent_scope_section(agent));
    }
    parts.join("\n\n---\n\n")
}

/// Embed the WolfStack knowledge base — bundled at compile time.
/// The same file the existing AI Agent uses, so there's a single
/// authoritative description of WolfStack in the binary.
fn wolfstack_kb_section() -> String {
    const KB: &str = include_str!("../ai/wolfstack-kb.md");
    format!("## WolfStack Knowledge Base\n{}", KB)
}

/// Live-ish snapshot of cluster state — recomputed per turn so the
/// model always sees current membership + container counts without
/// spending a tool call to get them.
async fn cluster_snapshot_section(agent: &Agent, state: &crate::api::AppState) -> String {
    let nodes = state.cluster.get_all_nodes();
    let mut clusters: std::collections::BTreeMap<String, Vec<_>> = Default::default();
    for n in &nodes {
        let cname = n.cluster_name.clone().unwrap_or_else(|| "WolfStack".into());
        // Respect the agent's scope when building the snapshot — an
        // agent with allowed_clusters=["wolfgrid"] shouldn't see
        // nodes from other clusters in its system context.
        if !agent.target_scope.allowed_clusters.is_empty()
            && !agent.target_scope.allowed_clusters.iter().any(|c| c == &cname)
        { continue; }
        clusters.entry(cname).or_default().push(n);
    }
    let mut out = String::from("## Live Cluster Snapshot\n");
    out.push_str(&format!("(captured at {} — refreshed each turn)\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    if clusters.is_empty() {
        out.push_str("No clusters visible within this agent's allowed scope.\n");
        return out;
    }
    for (cname, ns) in &clusters {
        let online = ns.iter().filter(|n| n.online).count();
        let docker: u32 = ns.iter().map(|n| n.docker_count).sum();
        let lxc: u32 = ns.iter().map(|n| n.lxc_count).sum();
        let vm: u32 = ns.iter().map(|n| n.vm_count).sum();
        out.push_str(&format!(
            "### Cluster `{}` — {} nodes ({} online), {} docker + {} lxc + {} vm\n",
            cname, ns.len(), online, docker, lxc, vm
        ));
        for n in ns {
            out.push_str(&format!(
                "- `{}` ({}{}) — {}docker: {}, lxc: {}, vm: {}\n",
                n.hostname,
                n.id,
                if n.is_self { ", SELF" } else { "" },
                if n.online { "" } else { "OFFLINE — " },
                n.docker_count, n.lxc_count, n.vm_count
            ));
        }
        out.push('\n');
    }
    out
}

/// Describe the agent's own target scope so it knows what it's
/// allowed to see and act on. Prevents the model wasting tool calls
/// on containers it can't touch.
fn agent_scope_section(agent: &Agent) -> String {
    let scope = &agent.target_scope;
    let mut out = String::from("## Your Scope\n");
    // Enumerate safe tools live from the tool registry so the hint stays
    // correct when new tools are added — no risk of the prompt drifting
    // from the authoriser's classification.
    let safe_tools: Vec<&str> = ToolId::ALL.iter()
        .filter(|t| t.danger() == Danger::Safe)
        .map(|t| t.as_str())
        .collect();
    let level_hint = match agent.access_level {
        crate::wolfagents::AccessLevel::ReadOnly => format!(
            "read_only — safe/read tools run freely ({}). Mutating and destructive \
             tools are refused. This is NOT a chat-only agent — you SHOULD call \
             read tools to answer questions about the cluster.",
            safe_tools.join(", ")),
        crate::wolfagents::AccessLevel::ReadWrite =>
            "read_write — safe and mutating tools run freely. Destructive tools \
             queue for operator approval.".to_string(),
        crate::wolfagents::AccessLevel::ConfirmAll =>
            "confirm_all — every non-read tool queues for operator approval.".to_string(),
        crate::wolfagents::AccessLevel::Trusted =>
            "trusted — all tools run freely, subject only to the hardcoded safety denylist.".to_string(),
    };
    out.push_str(&format!("- access_level: `{:?}` — {}\n", agent.access_level, level_hint));
    if scope.allowed_clusters.is_empty() {
        out.push_str("- clusters: (all)\n");
    } else {
        out.push_str(&format!("- clusters: {}\n", scope.allowed_clusters.join(", ")));
    }
    if scope.allowed_container_patterns.is_empty() {
        out.push_str("- container patterns: (all)\n");
    } else {
        out.push_str(&format!(
            "- container patterns: {}\n",
            scope.allowed_container_patterns.join(", ")
        ));
    }
    if scope.allowed_hosts.is_empty() {
        out.push_str("- specific hosts: (all within scope)\n");
    } else {
        out.push_str(&format!("- specific hosts: {}\n", scope.allowed_hosts.join(", ")));
    }
    if scope.allowed_paths.is_empty() {
        out.push_str("- filesystem paths: (none — write/exec tools may still refuse)\n");
    } else {
        out.push_str(&format!(
            "- filesystem paths: {}\n",
            scope.allowed_paths.join(", ")
        ));
    }
    out.push_str(&format!(
        "- allowed tools: {}\n",
        if agent.allowed_tools.is_empty() { "(none — chat only)".to_string() }
        else { agent.allowed_tools.join(", ") }
    ));
    out.push_str("\nA hardcoded safety denylist (`rm -rf /`, disk wipes, firewall flush, etc.) always applies regardless of your access level.\n");
    out.push_str(
        "\nIMPORTANT: the access level and scope above are the CURRENT values as of this turn. \
         If earlier messages in this conversation show you refusing an action based on a stricter \
         setting, that refusal is outdated — the operator has since adjusted your permissions. \
         Re-evaluate the current request against the values above, not against your prior replies.\n"
    );
    out.push_str(
        "\nCRITICAL: Your tools are your access. Before refusing any user request with a \
         generic 'I'm an AI and can't do that' disclaimer, check the `allowed tools` list above. \
         If a matching tool is listed, CALL IT — do not say you can't. Specifically:\n\
         - User asks to email / notify / send a message → use `send_email` if present.\n\
         - User asks to run / check / inspect something → use `exec_in_container`, `exec_on_node`, \
           `check_disk_usage`, `read_log`, `get_metrics` as appropriate.\n\
         - User asks to schedule / run daily / run every hour → use `schedule_workflow` or \
           `run_workflow`.\n\
         - User asks about past incidents or history → use `semantic_search`.\n\
         - User asks about a website → use `web_fetch` or `web_render`.\n\
         Only refuse if the required tool is NOT in your allowed_tools list, or if the access \
         level forbids it. In that case, say exactly which tool would be needed so the operator \
         can grant it.\n"
    );
    out.push_str(
        "\nCRITICAL: Do NOT claim you have performed an action unless you actually issued a \
         `tool_use` block for it AND received a successful `tool_result` back. No pre-emptive \
         confirmations, no 'sending now…' theatre. If you didn't call the tool, you didn't do \
         the thing. If a tool returned an error, tell the user the error verbatim — never \
         summarise a failure as success. This is especially true for `send_email`, \
         `exec_*`, and anything that touches cluster state: lying about success here causes \
         real operational confusion.\n"
    );
    out
}

/// The core ping-pong loop against Anthropic's /v1/messages endpoint.
/// Sends the conversation + tool schemas, parses tool_use blocks,
/// dispatches them through our gatekeeper, appends tool_result blocks,
/// sends the whole lot back — repeat until stop_reason is terminal.
async fn claude_tool_loop(
    agent: &Agent,
    cfg: &crate::ai::AiConfig,
    system_prompt: &str,
    history: &[crate::ai::ChatMessage],
    user_message: &str,
    state: &crate::api::AppState,
) -> Result<AgentTurn, String> {
    let client = &*AGENT_LOOP_CLIENT;

    // Build the initial messages array. Claude's format uses role +
    // content blocks (content can be a string for simple turns).
    let mut messages: Vec<serde_json::Value> = Vec::new();
    for m in history {
        // Skip anything that isn't a plain user/assistant text turn —
        // old memory may have additional shapes.
        if m.role != "user" && m.role != "assistant" { continue; }
        messages.push(serde_json::json!({
            "role": m.role,
            "content": m.content,
        }));
    }
    messages.push(serde_json::json!({
        "role": "user",
        "content": user_message,
    }));

    let tools_json = build_claude_tools(agent);
    let mut trace: Vec<ToolCallTrace> = Vec::new();
    let max_rounds = cfg.effective_agent_max_tool_calls();

    for round in 0..max_rounds {
        let mut body = serde_json::json!({
            "model": cfg.model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": messages,
        });
        if !tools_json.is_empty() {
            body["tools"] = serde_json::json!(tools_json);
        }

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .timeout(std::time::Duration::from_secs(120))
            .header("x-api-key", &cfg.claude_api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Claude API error: {}", e))?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("read body: {}", e))?;
        if !status.is_success() {
            return Err(format!("Claude API {} — {}", status, text));
        }

        let payload: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("parse response: {} — body: {}", e, text.chars().take(200).collect::<String>()))?;

        let stop_reason = payload.get("stop_reason").and_then(|v| v.as_str()).unwrap_or("");
        let content = payload.get("content").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        // Extract terminal text (if any) and tool_use blocks.
        let mut text_pieces: Vec<String> = Vec::new();
        let mut tool_uses: Vec<(String, String, serde_json::Value)> = Vec::new(); // (id, name, input)
        for block in &content {
            let btype = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match btype {
                "text" => {
                    if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                        text_pieces.push(t.to_string());
                    }
                }
                "tool_use" => {
                    let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let input = block.get("input").cloned().unwrap_or(serde_json::json!({}));
                    tool_uses.push((id, name, input));
                }
                _ => {} // ignore other block types
            }
        }

        // If the model didn't ask for any tools, we're done.
        if tool_uses.is_empty() {
            return Ok(AgentTurn {
                response: text_pieces.join("\n"),
                tool_calls: trace,
                stop_reason: stop_reason.to_string(),
            });
        }

        // Append the assistant turn (with tool_use blocks intact) to
        // the message history — Claude requires this before the
        // tool_result turn or it returns 400.
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": content,
        }));

        // Dispatch each tool_use, collect tool_result blocks.
        let mut tool_result_blocks: Vec<serde_json::Value> = Vec::new();
        for (use_id, name, input) in &tool_uses {
            let result = dispatch::dispatch(agent, name, input, state).await;
            trace.push(ToolCallTrace {
                tool: name.clone(),
                arguments: input.clone(),
                ok: result.ok,
                status: result.status.clone(),
            });
            // Pack the result as MCP-style content: single text block
            // containing a compact JSON summary so Claude can parse it.
            let content_text = serde_json::to_string(&serde_json::json!({
                "status": result.status,
                "ok": result.ok,
                "data": result.data,
            })).unwrap_or_else(|_| result.status.clone());
            tool_result_blocks.push(serde_json::json!({
                "type": "tool_result",
                "tool_use_id": use_id,
                "content": content_text,
                "is_error": !result.ok,
            }));
        }

        // Append the user turn carrying all tool_result blocks.
        messages.push(serde_json::json!({
            "role": "user",
            "content": tool_result_blocks,
        }));

        // If Claude signalled end_turn despite emitting tool_use (rare
        // but possible when max_tokens cuts off mid-turn), stop.
        if stop_reason == "end_turn" {
            // Collect any text pieces we saw and call it done.
            let last_text = text_pieces.join("\n");
            return Ok(AgentTurn {
                response: if last_text.is_empty() {
                    "(agent ran tools but returned no text; see tool_calls for the result)".into()
                } else {
                    last_text
                },
                tool_calls: trace,
                stop_reason: stop_reason.to_string(),
            });
        }

        // Otherwise loop — next round sends the tool_result back up
        // and we wait for the model's next move.
        let _ = round;
    }

    warn!("wolfagents: agent {} hit max_rounds={} — abandoning turn", agent.id, max_rounds);
    Ok(AgentTurn {
        response: format!(
            "(agent aborted after {} tool-use rounds — raise the limit in \
             Settings → AI Agent → \"Cap agent tool-calls per turn\", or tighten the \
             system prompt so the agent reaches a conclusion faster)",
            max_rounds
        ),
        tool_calls: trace,
        stop_reason: "max_rounds".to_string(),
    })
}

/// Build Anthropic tool schemas from the agent's allowed_tools list.
/// Each schema includes a JSON Schema for inputs so Claude knows what
/// shape to emit. Hand-maintained per-tool; a shared source-of-truth
/// would be nice but the schemas are small and stable enough that
/// duplication is cheaper than the abstraction.
fn build_claude_tools(agent: &Agent) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for name in &agent.allowed_tools {
        let Some(tool) = ToolId::from_str(name) else { continue; };
        let schema = input_schema_for(tool);
        let description = tool.risk_note();
        out.push(serde_json::json!({
            "name": tool.as_str(),
            "description": format!("{} — {}", tool.label(), description),
            "input_schema": schema,
        }));
    }
    out
}

/// Input JSON Schema per tool — mirrors the arguments the dispatcher
/// actually reads.
fn input_schema_for(tool: ToolId) -> serde_json::Value {
    match tool {
        ToolId::ListNodes | ToolId::ListAlerts | ToolId::GetMetrics
        | ToolId::ListApiEndpoints => serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        ToolId::ListContainers => serde_json::json!({
            "type": "object",
            "properties": {
                "cluster": { "type": "string", "description": "Optional cluster-name filter" },
                "name_pattern": { "type": "string", "description": "Optional glob, e.g. 'regions*'" }
            }
        }),
        ToolId::ReadLog => serde_json::json!({
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": { "type": "string", "description": "Container name or systemd unit" },
                "lines": { "type": "integer", "minimum": 1, "maximum": 2000 }
            }
        }),
        ToolId::CheckDiskUsage => serde_json::json!({
            "type": "object",
            "properties": {
                "container_pattern": { "type": "string", "description": "Glob, e.g. 'regions*'" },
                "threshold_pct": { "type": "integer", "minimum": 0, "maximum": 100 }
            }
        }),
        ToolId::ReadFile => serde_json::json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": { "type": "string" },
                "max_bytes": { "type": "integer", "minimum": 1, "maximum": 1048576 },
                "node": {
                    "type": "string",
                    "description": "Cluster node to read from — hostname or node id. Omit / 'self' = this node. Example: 'wolf-1' to read /etc/motd on wolf-1."
                }
            }
        }),
        ToolId::DescribeCluster => serde_json::json!({
            "type": "object",
            "properties": {
                "cluster_name": { "type": "string" }
            }
        }),
        ToolId::RestartContainer => serde_json::json!({
            "type": "object",
            "required": ["runtime", "name"],
            "properties": {
                "runtime": { "type": "string", "enum": ["docker", "lxc"] },
                "name": { "type": "string" }
            }
        }),
        ToolId::ListWorkflows => serde_json::json!({
            "type": "object",
            "properties": {
                "cluster": { "type": "string", "description": "Optional cluster name filter" }
            }
        }),
        ToolId::WebFetch => serde_json::json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string", "description": "http:// or https:// URL. Private/loopback/link-local addresses are refused." }
            }
        }),
        ToolId::WebRender => serde_json::json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string", "description": "URL to render via headless Chromium. Use for JS-heavy sites when web_fetch returns empty text. Requires chromium on the host." }
            }
        }),
        ToolId::SemanticSearch => serde_json::json!({
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": { "type": "string", "description": "Natural-language keywords. BM25 ranked." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 50, "default": 10 },
                "sources": {
                    "type": "array",
                    "items": { "type": "string", "enum": ["memory", "audit", "alerts"] },
                    "description": "Which corpora to search. Default: all three."
                },
                "node": {
                    "type": "string",
                    "description": "Which node's memory / audit / alert files to search. Omit or 'self' = this node only. A hostname or node id = just that remote. '*' or 'all' = fan out to every online node and merge results."
                }
            }
        }),
        ToolId::RunWorkflow => serde_json::json!({
            "type": "object",
            "required": ["workflow_id"],
            "properties": { "workflow_id": { "type": "string" } }
        }),
        ToolId::ScheduleWorkflow => serde_json::json!({
            "type": "object",
            "required": ["workflow_id"],
            "properties": {
                "workflow_id": { "type": "string" },
                "schedule": {
                    "type": ["string", "null"],
                    "description": "5-field cron expression (min hour dom month dow), or null to clear the schedule"
                },
                "enabled": {
                    "type": "boolean",
                    "description": "Explicit enable/disable. Omit to enable automatically when setting a schedule, or leave the workflow's current state when clearing one."
                }
            }
        }),
        ToolId::SendEmail => serde_json::json!({
            "type": "object",
            "required": ["subject", "body"],
            "properties": {
                "to": {
                    "type": ["string", "array", "null"],
                    "description": "Recipient email address, or an array of addresses. Omit to use the default alerting recipient from Settings → AI Agent. Recipients must fall under the agent's allowed_email_recipients scope.",
                    "items": { "type": "string" }
                },
                "subject": { "type": "string" },
                "body": { "type": "string", "description": "Plain text body, or HTML when `html` is true." },
                "html": { "type": "boolean", "description": "Send as HTML. Default false (plain text).", "default": false }
            }
        }),
        ToolId::WriteFile => serde_json::json!({
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": { "type": "string" },
                "content": { "type": "string" },
                "append": { "type": "boolean", "default": false },
                "node": {
                    "type": "string",
                    "description": "Cluster node to write to — hostname or node id. Omit / 'self' = this node."
                }
            }
        }),
        ToolId::ExecInContainer => serde_json::json!({
            "type": "object",
            "required": ["name", "command"],
            "properties": {
                "runtime": { "type": "string", "enum": ["docker", "lxc"], "default": "docker" },
                "name": { "type": "string" },
                "command": { "type": "string", "description": "Shell command, run via sh -c inside the container" },
                "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 600 }
            }
        }),
        ToolId::ExecOnNode => serde_json::json!({
            "type": "object",
            "required": ["node_id", "command"],
            "properties": {
                "node_id": { "type": "string" },
                "command": { "type": "string" },
                "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 600 }
            }
        }),
        ToolId::DeleteFile => serde_json::json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": { "type": "string" },
                "node": {
                    "type": "string",
                    "description": "Cluster node to delete on — hostname or node id. Omit / 'self' = this node."
                }
            }
        }),
        ToolId::WolfstackApi => serde_json::json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                    "default": "GET"
                },
                "path": { "type": "string", "description": "Path starting with /api/... or /cluster-home, etc." },
                "body": { "description": "Optional JSON body for POST/PUT/PATCH" }
            }
        }),
        // One schema for all three SQL tools. The dispatcher picks
        // Read / Update / Delete based on which tool name the model
        // emits; the sqlparser classifier rejects any statement that
        // exceeds that tier at execution time.
        ToolId::SqlRead | ToolId::SqlUpdate | ToolId::SqlDelete => serde_json::json!({
            "type": "object",
            "required": ["connection_id", "query"],
            "properties": {
                "connection_id": {
                    "type": "string",
                    "description": "ID of a configured SQL connection (see allowed_sql_connections in the agent's scope)."
                },
                "query": {
                    "type": "string",
                    "description": "A single SQL statement. SELECT/SHOW/EXPLAIN for sql_read; INSERT/UPDATE additionally for sql_update; DELETE/TRUNCATE additionally for sql_delete. Multi-statement queries are rejected."
                },
                "timeout_secs": {
                    "type": "integer", "minimum": 1, "maximum": 300,
                    "description": "Override the default 30s execution timeout."
                }
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Tor 2026-06-05: the SendEmail `to` union (`["string","array","null"]`
    // with `items`) was narrowed to "string" while keeping `items`, so Gemini
    // rejected it with "properties[to].items: ... $type == Type.ARRAY".
    #[test]
    fn gemini_union_with_items_becomes_array() {
        let schema = json!({
            "type": "object",
            "properties": {
                "to": {
                    "type": ["string", "array", "null"],
                    "items": { "type": "string" }
                }
            }
        });
        let out = normalise_schema_for_gemini(schema);
        let to = &out["properties"]["to"];
        assert_eq!(to["type"], json!("array"), "items present → type must be array");
        assert!(to.get("items").is_some(), "array must keep its items");
        assert_eq!(to["items"]["type"], json!("string"));
        assert_eq!(to["nullable"], json!(true));
    }

    #[test]
    fn gemini_nullable_string_union_has_no_items() {
        let schema = json!({
            "type": "object",
            "properties": { "name": { "type": ["string", "null"] } }
        });
        let out = normalise_schema_for_gemini(schema);
        let name = &out["properties"]["name"];
        assert_eq!(name["type"], json!("string"));
        assert_eq!(name["nullable"], json!(true));
        assert!(name.get("items").is_none());
    }

    // A stray `items` on a plain (single-type) non-array property must be
    // dropped too, not just on narrowed unions.
    #[test]
    fn gemini_strips_stray_items_on_non_array() {
        let schema = json!({ "type": "string", "items": { "type": "string" } });
        let out = normalise_schema_for_gemini(schema);
        assert_eq!(out["type"], json!("string"));
        assert!(out.get("items").is_none());
    }
}
