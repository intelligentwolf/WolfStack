// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Build-time enforcement of the resource rules WolfStack must never break.
//!
//! WHY THIS FILE EXISTS
//!
//! On 2026-08-05 a production fleet of twelve nodes melted down. Every node
//! climbed to 60-80% system CPU, descriptors grew ~700/min until the table was
//! exhausted at 65,535, and restarting bought only minutes. Workloads survived
//! only because systemd's `KillMode=process` kept guests out of the blast.
//!
//! Two defects, both invisible in review and both trivially preventable:
//!
//!   1. `POLL_CLIENT` — the client that dials EVERY cluster peer every 10
//!      seconds — set a total `.timeout()` but no `.connect_timeout()`. A total
//!      timeout does nothing for a connection that never establishes: a SYN to
//!      a black-holed address holds a descriptor for the kernel's full retry
//!      window (~130s at tcp_syn_retries=6). Measured: 2,422 sockets in
//!      SYN-SENT and 2,868 in CLOSE-WAIT on one node.
//!
//!   2. `SystemMonitor` refreshed ALL processes on a timer and at construction.
//!      sysinfo caches an open `/proc/<pid>/stat` handle per process and grants
//!      itself HALF of RLIMIT_NOFILE to do it — 32,767 descriptors claimed
//!      before a single metric was read.
//!
//! A management plane must not be capable of taking down the estate it
//! manages. These are not style preferences; they are the difference between a
//! bug and an outage.
//!
//! HOW THIS IS ACTUALLY ENFORCED
//!
//! By the "Resource-safety gate + test suite" step in
//! `.github/workflows/release.yml`, which runs `cargo test --locked` on the
//! x86_64 leg before the cross builds. That step was added at the same time as
//! this file — and had to be, because the release workflow previously ran only
//! `cargo check`, which compiles without executing a single test. Every rule
//! in here would have been advisory.
//!
//! If that step is ever removed, this file stops enforcing anything and
//! silently becomes documentation. The two must live or die together.
//!
//! ADDING AN EXCEPTION
//!
//! Put the file in the relevant allowlist below WITH a reason. An allowlist
//! entry is a deliberate, reviewable decision. Deleting the check is not.

use std::fs;
use std::path::{Path, PathBuf};

/// A received unblock must terminate on that node. Together with the limiter's
/// runtime hook-count tests, this guards the HTTP wiring that caused the fleet
/// storm: peer deliveries re-entered the operator path and every node fanned out.
#[test]
fn unblock_handlers_do_not_create_propagation_cycles() {
    let src = strip_line_comments(include_str!("../src/api/mod.rs"));
    let handler = |name: &str| {
        src.split(&format!("pub async fn {name}("))
            .nth(1).expect("unblock handler must exist")
            .split("\n}\n").next().unwrap().to_string()
    };
    let peer = handler("security_auth_unblock_peer");
    assert!(peer.contains(".unblock_local(&body.ip)"), "peer must only clear local state");
    assert!(!peer.contains(".unblock("), "peer must not invoke the propagation hook");
    assert!(!peer.contains("propagate_kernel_unblock_to_peers"));

    let operator = handler("security_auth_unblock");
    let branches = operator.split("if body.propagate {").nth(1).unwrap();
    let (propagating, local) = branches.split_once("} else {").unwrap();
    assert!(propagating.contains(".unblock(&body.ip)"));
    assert!(!propagating.contains(".unblock_local("));
    assert!(local.contains(".unblock_local(&body.ip)"));
    assert_eq!(operator.matches(".unblock(&body.ip)").count(), 1);
    assert_eq!(operator.matches(".unblock_local(&body.ip)").count(), 1);
    assert!(!operator.contains("propagate_kernel_unblock_to_peers"),
        "the limiter hook owns the one operator fanout");
    assert!(!operator.contains("tokio::spawn"));
    for body in [&operator, &peer] {
        assert!(body.contains("web::block"), "kernel commands and persistence must leave the HTTP worker");
        assert!(body.contains(".await"), "the unblock must finish before returning success");
    }
}

/// Every `.rs` file under src/.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("src"), &mut out);
    assert!(!out.is_empty(), "found no source files — is the test running from the crate root?");
    out
}

/// Strip `//` line comments so a builder mentioned in prose doesn't register
/// as a real call site. Block comments are rare here and deliberately not
/// handled — a false positive is a nudge to look, which is the safe direction.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            // Don't cut inside a string literal containing "//" (e.g. a URL).
            Some(i) if l[..i].matches('"').count() % 2 == 0 => &l[..i],
            _ => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// EVERY outbound HTTP client must bound its CONNECT, not just the request.
///
/// This is the rule that would have prevented the 2026-08-05 outage outright.
#[test]
fn every_http_client_bounds_its_connect() {
    // Reason required for each entry. These build a client from operator-
    // supplied per-request settings and are constructed per call rather than
    // held on a timer, so they cannot accumulate across poll cycles.
    const ALLOWED: &[(&str, &str)] = &[
        // (path fragment, why)
    ];

    let mut violations = Vec::new();

    for path in source_files() {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        let src = strip_line_comments(&raw);
        let display = path.display().to_string();

        if ALLOWED.iter().any(|(frag, _)| display.contains(frag)) {
            continue;
        }

        // Find each builder chain and inspect it up to its .build().
        let mut idx = 0;
        while let Some(rel) = src[idx..].find("Client::builder()")
            .or_else(|| src[idx..].find("ClientBuilder::new()"))
        {
            let start = idx + rel;
            // A chain always terminates in .build(); cap the window so a
            // missing .build() can't swallow the rest of the file.
            let window_end = src[start..]
                .find(".build()")
                .map(|e| start + e + ".build()".len())
                .unwrap_or_else(|| (start + 2000).min(src.len()));
            let chain = &src[start..window_end];

            if !chain.contains(".connect_timeout(") {
                let line = src[..start].matches('\n').count() + 1;
                violations.push(format!("{}:{}", display, line));
            }
            idx = window_end.max(start + 1);
        }
    }

    assert!(
        violations.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: HTTP client without .connect_timeout() ═══\n\n\
         {} client builder(s) can hang on connect:\n  {}\n\n\
         A total `.timeout()` does NOT bound a connection that never establishes.\n\
         A SYN to an unroutable address holds a file descriptor for the kernel's\n\
         full retry window (~130s at tcp_syn_retries=6). Any client called on a\n\
         timer then stacks those until the descriptor table is exhausted — that\n\
         is exactly how the 2026-08-05 fleet meltdown happened (2,422 SYN-SENT,\n\
         2,868 CLOSE-WAIT, ~700 sockets/min, twelve nodes).\n\n\
         FIX: add `.connect_timeout(Duration::from_secs(3..5))` to the builder.\n\
         A connect timeout is never wrong — a peer that cannot answer a SYN in\n\
         five seconds is not going to serve the request either.\n\n\
         If an exception is genuinely justified, add the file to ALLOWED in\n\
         tests/resource_safety.rs WITH a reason.\n",
        violations.len(),
        violations.join("\n  "),
    );
}

/// sysinfo's process refresh claims HALF of RLIMIT_NOFILE as a permanent
/// `/proc/<pid>/stat` handle cache. It must never run on a timer or at
/// construction — only on demand, for the one endpoint that wants a process
/// list.
#[test]
fn sysinfo_never_refreshes_processes_off_demand() {
    // `top_processes()` is the ONLY legitimate caller: it backs
    // GET /api/metrics/processes, refreshes when asked, and is not on a timer.
    const ALLOWED_FN: &str = "pub fn top_processes";

    let mut violations = Vec::new();

    for path in source_files() {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        let src = strip_line_comments(&raw);
        let display = path.display().to_string();

        for pattern in ["System::new_all(", "refresh_all(", "refresh_processes("] {
            let mut idx = 0;
            while let Some(rel) = src[idx..].find(pattern) {
                let at = idx + rel;
                // Allowed only inside top_processes().
                let inside_allowed = src[..at]
                    .rfind(ALLOWED_FN)
                    .map(|f| !src[f..at].contains("\n    pub fn ") && !src[f..at].contains("\n    fn "))
                    .unwrap_or(false);
                if !inside_allowed {
                    let line = src[..at].matches('\n').count() + 1;
                    violations.push(format!("{}:{} — {}", display, line, pattern));
                }
                idx = at + pattern.len();
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: sysinfo process refresh off the demand path ═══\n\n\
         {} occurrence(s):\n  {}\n\n\
         sysinfo's Linux backend keeps an OPEN /proc/<pid>/stat handle per\n\
         process (`stat_file: Option<FileCounter>`) and budgets itself HALF of\n\
         RLIMIT_NOFILE for that cache — it raises our soft limit to the hard\n\
         limit first to get it. At LimitNOFILE=65535 that is 32,767 descriptors\n\
         claimed before a single metric is read, and on a host with 50,766\n\
         threads the scan alone cost ~390% CPU every 30 seconds.\n\n\
         `System::new_all()` and `refresh_all()` both mean RefreshKind::everything(),\n\
         which INCLUDES processes — they are not safe alternatives.\n\n\
         FIX: refresh only what you read (`refresh_cpu_all`, `refresh_memory`).\n\
         For a process COUNT use monitoring::count_processes(), which reads\n\
         /proc directly and opens nothing. Only top_processes() may refresh the\n\
         full list, on demand.\n",
        violations.len(),
        violations.join("\n  "),
    );
}

/// A full process scan must be RATE-LIMITED, not merely "on demand".
///
/// v25.10.4 moved `refresh_processes` off the metrics loop and left
/// `top_processes()` as the sole caller, reasoning that an on-demand endpoint
/// is safe. It is not. `startProcessPolling()` in web/js/app.js polls
/// GET /api/metrics/processes every 15 SECONDS while the dashboard is open —
/// a FASTER timer than the 30s loop that was removed. Anyone parked on the
/// dashboard reinstated the whole fault, four scans a minute, once per viewer
/// (reported by JJ, 2026-08-06: nodes at 100% CPU on a version that was
/// supposed to have fixed exactly this).
///
/// The lesson generalises: "on demand" means nothing when a UI timer is the
/// demand. Any path that can walk every process must carry its own cache, so
/// the cost is bounded by the clock rather than by client behaviour.
#[test]
fn process_scans_are_rate_limited() {
    let src = fs::read_to_string("src/monitoring/mod.rs")
        .expect("monitoring/mod.rs must exist");

    assert!(
        src.contains("TOP_PROC_CACHE") && src.contains("TOP_PROC_TTL"),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: unbounded process scan ═══\n\n\
         top_processes() has lost its cache (TOP_PROC_CACHE / TOP_PROC_TTL).\n\n\
         The dashboard polls /api/metrics/processes every 15 seconds PER VIEWER.\n\
         Without a server-side cache, every poll walks every process on the box\n\
         and re-claims sysinfo's /proc/<pid>/stat handle cache (half of\n\
         RLIMIT_NOFILE). That is how v25.10.4 still pegged user nodes at 100%\n\
         CPU after the metrics-loop scan had been removed.\n\n\
         FIX: keep the TTL cache. Do not make the scan cheaper-looking by\n\
         removing it.\n",
    );

    // The scan must run on a throwaway System so its descriptors are freed.
    let scan_fn = src
        .split("pub fn top_processes")
        .nth(1)
        .expect("top_processes must exist");
    let body = &scan_fn[..scan_fn.find("\n    }").unwrap_or(scan_fn.len())];
    assert!(
        body.contains("System::new()") && !body.contains("self.sys.refresh_processes"),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: process scan on the long-lived System ═══\n\n\
         top_processes() must scan a THROWAWAY `System::new()`, never\n\
         `self.sys`. sysinfo holds an open /proc/<pid>/stat handle per process\n\
         for the lifetime of the System it scanned with — on the shared monitor\n\
         those descriptors are permanent (32,767 on a busy host). Scoped to a\n\
         temporary System they are released when it drops.\n",
    );
}

/// A WebSocket bridge must END on a stream error, never swallow it.
///
/// `actix-ws` does NOT terminate its stream after an error: `MessageStream`
/// returns the error WITHOUT setting `closing` (0.3.1 stream.rs:176), and the
/// `?` on `codec.decode` at :189 behaves the same while the offending bytes
/// stay buffered. Every subsequent poll therefore yields the SAME error,
/// immediately ready, for ever.
///
/// Four bridges — terminal console, Proxmox console, container VNC and the
/// cluster browser — each ended their message match with a catch-all
/// `_ => {}`. That arm caught `Some(Err(_))`, so the surrounding
/// `loop { select! { .. } }` re-polled with nothing to await: a hot spin that
/// ALSO never dropped either side's socket. On a user's node this produced
/// seven pegged actix workers, 29,344 sockets stranded in CLOSE-WAIT and 42
/// leaked /dev/ptmx handles, until the descriptor table hit 65,535 and
/// accept() began failing (2026-08-06).
///
/// The rule: in any match over WebSocket stream items, `Some(Err(..))` must be
/// handled explicitly. A bare `_ => {}` next to a `None => break` is the exact
/// shape that hides it, so that shape is what this test bans.
#[test]
fn websocket_bridges_do_not_swallow_stream_errors() {
    let mut violations = Vec::new();

    for path in source_files() {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        if !raw.contains("actix_ws") && !raw.contains("tungstenite") {
            continue;
        }
        let display = path.display().to_string();

        // A `None => break` arm means this match is over stream items. If the
        // very next arm is a catch-all, it is swallowing Some(Err(..)).
        let lines: Vec<&str> = raw.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("None => break") {
                continue;
            }
            // Skip forward over comment lines to the next real arm.
            let mut j = i + 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() || t.starts_with("//") { j += 1; continue; }
                break;
            }
            if j < lines.len() {
                let next = lines[j].trim();
                if next == "_ => {}" || next == "_ => {}," || next.starts_with("_ =>") {
                    violations.push(format!("{}:{}", display, j + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: WebSocket bridge swallows stream errors ═══\n\n\
         {} catch-all arm(s) directly after a `None => break`:\n  {}\n\n\
         A catch-all there absorbs `Some(Err(..))`. actix-ws does NOT end its\n\
         stream after an error (0.3.1 stream.rs:176 returns the error without\n\
         setting `closing`), so the next poll yields the SAME error immediately,\n\
         for ever. Inside `loop {{ select! {{ .. }} }}` that is a hot spin which\n\
         also never drops either socket.\n\n\
         Measured on a user's node 2026-08-06: 7 actix workers pegged, 29,344\n\
         sockets in CLOSE-WAIT, 42 leaked /dev/ptmx, fd table exhausted at\n\
         65,535 and accept() failing.\n\n\
         FIX: handle `Some(Err(e))` explicitly — log it and `break`. Use\n\
         `Some(Ok(_)) => {{}}` for the genuinely-ignorable frames (Pong,\n\
         Continuation, Nop) so a future variant cannot hide in the catch-all.\n",
        violations.len(),
        violations.join("\n  "),
    );
}

/// A `reqwest::Response` that leaves scope without its body being read never
/// releases its socket. On an error path that exits early — `continue`,
/// `break`, `return` — that is a per-call leak, and the callers that check
/// `.status()` are almost always the ones on a timer dialling every peer.
#[test]
fn non_success_response_is_drained_before_early_exit() {
    const NEEDLE: &str = "status().is_success()";

    let mut violations = Vec::new();

    for path in source_files() {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        let src = strip_line_comments(&raw);
        let display = path.display().to_string();

        let mut idx = 0;
        while let Some(rel) = src[idx..].find(NEEDLE) {
            let at = idx + rel;
            idx = at + NEEDLE.len();

            // Only the negated form (`if !resp.status().is_success()`) guards
            // an early exit; the positive form falls through to real work.
            let back = at.saturating_sub(40);
            if !src[back..at].contains("if !") {
                continue;
            }

            // Walk the guard body from its `{` to the matching `}`.
            let Some(open_rel) = src[at..].find('{') else { continue };
            let open = at + open_rel;
            let mut depth = 0usize;
            let mut close = None;
            for (i, c) in src[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 { close = Some(open + i); break; }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else { continue };
            let body = &src[open..=close];

            // A long body is doing real work (building an error, logging
            // context) rather than bailing out — out of scope for this rule.
            if body.matches('\n').count() > 6 {
                continue;
            }

            let exits = body.contains("continue")
                || body.contains("break")
                || body.contains("return");
            let drains = body.contains(".bytes()")
                || body.contains(".json()")
                || body.contains(".text()")
                || body.contains("drain_response")
                || body.contains("send_and_drain");

            if exits && !drains {
                let line = src[..at].matches('\n').count() + 1;
                violations.push(format!("{}:{}", display, line));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: response dropped undrained on an early exit ═══\n\n\
         {} site(s):\n  {}\n\n\
         reqwest cannot release a connection until the response body is\n\
         consumed. A guard that inspects only `.status()` and then exits\n\
         leaves the socket alive; when the peer has already sent FIN it parks\n\
         in CLOSE-WAIT and never leaves.\n\n\
         Measured on a user's node 2026-08-12: the cluster poller (every peer,\n\
         every 10s) hit two peers answering non-2xx and leaked ~8,640 sockets\n\
         per peer per day — 18,122 in CLOSE-WAIT, fd table exhausted at 65,535,\n\
         actix_server failing accept() with 'No file descriptors available'.\n\
         It never reproduced in-house because a healthy peer answers 200 and\n\
         is drained by the `.json()` on the success path.\n\n\
         FIX: drain before leaving — `drain_response(resp).await;` where that\n\
         helper is in scope, otherwise `let _ = resp.bytes().await;`.\n",
        violations.len(),
        violations.join("\n  "),
    );
}

/// `local_address()` costs a `bind()` syscall on EVERY outbound connection,
/// and it is almost always reached for by someone who only wants IPv4.
///
/// hyper-util binds the socket whenever a source address is set
/// (`bind_local_address`, client/legacy/connect/http.rs:800-803). The bind
/// is to port 0, so the kernel runs `inet_csk_find_open_port` — a scan of
/// the host's bind table, taken under a spinlock. It is invisible on an
/// idle node and catastrophic on a busy one, because the cost scales with
/// the number of sockets the process already holds.
///
/// Use `ipv4_only_client_builder()`, which filters address families in the
/// DNS resolver instead and issues no bind at all.
#[test]
fn no_http_client_pins_a_source_address() {
    // Reason required for each entry. Binding a source address is legitimate
    // when the operator has genuinely asked to egress from a specific
    // interface — that is a routing requirement, not an address-family one.
    const ALLOWED: &[(&str, &str)] = &[
        // (path fragment, why)
    ];

    let mut violations = Vec::new();

    for path in source_files() {
        let raw = fs::read_to_string(&path).unwrap_or_default();
        let src = strip_line_comments(&raw);
        let display = path.display().to_string();

        if ALLOWED.iter().any(|(frag, _)| display.contains(frag)) {
            continue;
        }

        let mut idx = 0;
        while let Some(rel) = src[idx..].find(".local_address(") {
            let start = idx + rel;
            let line = src[..start].matches('\n').count() + 1;
            violations.push(format!("{}:{}", display, line));
            idx = start + 1;
        }
    }

    assert!(
        violations.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: HTTP client pins a source address ═══\n\n\
         {} site(s):\n  {}\n\n\
         Setting `.local_address(..)` makes hyper-util `bind()` the socket on\n\
         every outbound connection (bind_local_address, hyper-util\n\
         client/legacy/connect/http.rs:800-803). Binding to port 0 sends the\n\
         kernel into `inet_csk_find_open_port`, which scans the bind table\n\
         under a spinlock — cost proportional to the sockets already open.\n\n\
         Measured on a user's node 2026-08-13: 77.7% of ALL process CPU was in\n\
         `bind`, across 14 actix workers colliding in\n\
         `native_queued_spin_lock_slowpath`, with 15,296 sockets in the table.\n\
         The node had been carrying it for days as unexplained ~350% CPU.\n\n\
         FIX: if you wanted IPv4-only, use `api::ipv4_only_client_builder()` —\n\
         it filters address families in the DNS resolver and issues no bind.\n\
         If you genuinely need to egress from a specific interface, add the\n\
         file to ALLOWED in tests/resource_safety.rs WITH a reason.\n",
        violations.len(),
        violations.join("\n  "),
    );
}

/// The shared client factory MUST NOT bound its idle connection pool, and
/// this test exists to stop the "obvious" fix being re-applied.
///
/// v25.12.3 added `pool_max_idle_per_host(8)` + `pool_idle_timeout(15s)`
/// because reqwest's `usize::MAX` default (reqwest-0.12.28
/// src/async_impl/client.rs:302) lets request concurrency become a
/// permanent socket population. Correct in isolation; catastrophic here.
///
/// Once the pool is at its cap for a peer, every further returned
/// connection is dropped immediately, and a short idle timeout reaps the
/// rest far more often. Both make the CLIENT close first — and WolfStack's
/// server has a separate, older defect where an inbound connection is not
/// closed after the peer's FIN. Every client-side close therefore becomes a
/// permanent CLOSE-WAIT on the peer.
///
/// Measured on a user's node, same machine and cluster, across the upgrade:
/// inbound CLOSE-WAIT grew 2.3/min on v25.12.2 and 326/min on v25.12.3 —
/// 140x — taking it from degraded to descriptor-exhausted in minutes.
///
/// Re-bound the pool ONLY after the server-side close is fixed and proven.
#[test]
fn shared_client_factory_does_not_bound_its_pool() {
    let src = fs::read_to_string("src/api/mod.rs")
        .expect("src/api/mod.rs must exist — the shared client factory lives there");

    let start = src
        .find("pub(crate) fn ipv4_only_client_builder()")
        .expect("ipv4_only_client_builder() must exist — it is the shared client factory");
    let end = src[start..]
        .find("\n}")
        .map(|e| start + e)
        .unwrap_or(src.len());
    let body = strip_line_comments(&src[start..end]);

    let mut reintroduced = Vec::new();
    if body.contains(".pool_max_idle_per_host(") {
        reintroduced.push(".pool_max_idle_per_host(..)");
    }
    if body.contains(".pool_idle_timeout(") {
        reintroduced.push(".pool_idle_timeout(..)");
    }

    assert!(
        reintroduced.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: idle pool bounded on the shared factory ═══\n\n\
         Reintroduced: {}\n\n\
         This looks like a fix and is a regression until the server-side\n\
         close bug is fixed. Bounding the pool makes OUR side close first;\n\
         the peer then holds the socket in CLOSE-WAIT forever because it\n\
         does not close after our FIN.\n\n\
         Measured on a user's node across exactly this change: inbound\n\
         CLOSE-WAIT went from 2.3/min to 326/min (140x) on the same machine,\n\
         and the node exhausted all 65,535 descriptors within the hour.\n\n\
         An individual caller may still opt out with\n\
         `pool_max_idle_per_host(0)` — this gate covers the shared factory\n\
         that ~40 call sites inherit, not those deliberate choices.\n",
        reintroduced.join(", "),
    );

    // The connect bound is still mandatory and unrelated to pooling.
    assert!(
        body.contains(".connect_timeout("),
        "ipv4_only_client_builder() must keep .connect_timeout(..)"
    );
}

/// `agent_status` is the endpoint every peer polls. It must be served from
/// the cache and must NEVER do collection work itself.
///
/// It used to fall back to a full collection — sysinfo, docker, lxc, VM
/// enumeration — whenever the cache was empty, taking a blocking-pool
/// thread and the `monitor` mutex. That is fine for one request at startup
/// and fatal at a cluster's poll rate: every poll arriving before the cache
/// was first populated took that path together, capped the 512-thread pool,
/// and left tokio's UNBOUNDED blocking queue growing. The background
/// refresher's own spawn_blocking then queued behind the stampede it had
/// caused, so the cache could never be published and the node never
/// recovered. Handlers stopped returning, actix could not close their
/// sockets, and inbound CLOSE-WAIT grew until the descriptor table was
/// exhausted — ~320 leaked sockets/second on a real cluster, within seconds
/// of every restart.
///
/// A cache miss must stay cheap. Return 503 and let the refresher publish.
#[test]
fn agent_status_never_collects_on_a_cache_miss() {
    let src = fs::read_to_string("src/api/mod.rs")
        .expect("src/api/mod.rs must exist");

    let start = src
        .find("pub async fn agent_status(")
        .expect("agent_status must exist — it is the endpoint peers poll");
    // Function body ends at the first closing brace in column 0.
    let end = src[start..]
        .find("\n}\n")
        .map(|e| start + e)
        .expect("agent_status must have a closing brace");
    let body = strip_line_comments(&src[start..end]);

    let mut offenders = Vec::new();
    if body.contains("spawn_blocking(") {
        offenders.push("tokio::task::spawn_blocking");
    }
    if body.contains("web::block(") {
        offenders.push("web::block");
    }

    assert!(
        offenders.is_empty(),
        "\n\n\
         ═══ RESOURCE SAFETY VIOLATION: agent_status does blocking work ═══\n\n\
         Found: {}\n\n\
         Every peer in the cluster polls this endpoint. If a cache miss can\n\
         trigger collection, then every poll arriving before the cache is\n\
         populated triggers it AT ONCE — one blocking-pool thread each, all\n\
         contending on the same mutex.\n\n\
         tokio caps the pool at 512 and its blocking queue is unbounded, so\n\
         the background refresher's own spawn_blocking queues behind the\n\
         stampede and can never publish the cache that would end it. The\n\
         node cannot recover: requests stop returning, actix cannot close\n\
         their sockets, and inbound CLOSE-WAIT grows until the descriptor\n\
         table is gone.\n\n\
         Measured on a user's cluster 2026-08-13: ~320 leaked sockets per\n\
         second, reproducible within seconds of every restart.\n\n\
         FIX: serve from the cache; on a miss return 503 with Retry-After\n\
         and let the background refresher publish.\n",
        offenders.join(", "),
    );
}
