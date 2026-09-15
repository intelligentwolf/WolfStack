// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Firewall rule translator.
//!
//! Compiles `Vec<FirewallRule>` + `ZoneAssignments` into an
//! `iptables-restore` script for the filter table, tests it, and swaps
//! atomically. Keeps the existing WolfStack nat-table rules untouched —
//! those are still owned by networking::mod.rs (DNAT for IP mappings)
//! and vms::manager (MASQUERADE for WolfNet). We only touch filter.
//!
//! Atomicity model:
//!   1. Build full ruleset as a single iptables-save-format string.
//!   2. `iptables-restore --test` — rejects malformed rules without
//!      touching the live table.
//!   3. `iptables-restore` — swaps the whole filter table atomically.
//!   4. Store the previous dump in memory for safe-mode rollback.
//!
//! Safe-mode:
//!   If `safe_mode_seconds > 0`, apply() sets a rollback deadline and
//!   returns. A background task (installed by RouterState or the main
//!   tick loop) checks the deadline each second and reverts if not
//!   confirmed. `confirm()` clears the deadline.

use super::*;
use std::collections::HashSet;
use std::process::Command;
#[allow(unused_imports)]
use tracing::{info, warn};

const FILTER_CHAINS: &[&str] = &["WOLFROUTER_FWD", "WOLFROUTER_IN", "WOLFROUTER_OUT"];

/// Build the iptables-save-format text for the filter table from the
/// current config. Idempotent: callers can compare output bytes to
/// detect no-op applies.
pub fn build_ruleset(config: &RouterConfig, self_node_id: &str) -> String {
    let mut out = String::new();
    out.push_str("*filter\n");
    // Declare/refill ONLY our own chains — never the built-in INPUT/FORWARD/
    // OUTPUT. Under the iptables-nft backend, `iptables-restore -n` (noflush)
    // STILL flushes any chain *named* in the file, so declaring `:FORWARD …`
    // here wiped the FORWARD chain on every apply — destroying Docker's and the
    // operator's own FORWARD rules on nft hosts (legacy hosts were unaffected,
    // which is why it looked node-specific). The built-in -> WOLFROUTER jumps
    // are installed idempotently in `apply` (`-C` probe + `-I 1`), exactly like
    // apply_v6_companion, so they never appear in the restore file and never
    // flush a built-in. This is the v4 twin of the fix build_ruleset_v6 carries.
    for chain in FILTER_CHAINS {
        out.push_str(&format!(":{} - [0:0]\n", chain));
    }

    // Blanket state rule — accept ESTABLISHED,RELATED. Users only ever
    // write NEW rules (unless they disable state_track for a specific
    // rule), so replies to allowed outbound traffic come back without
    // needing explicit rules.
    for ch in FILTER_CHAINS {
        out.push_str(&format!(
            "-A {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", ch
        ));
        // Allow loopback unconditionally — nothing good ever comes from
        // blocking 127.0.0.0/8 on a Linux host.
        out.push_str(&format!("-A {} -i lo -j ACCEPT\n", ch));
    }

    // Threat Intel — when enabled and not in dry-run, inject a chain that
    // matches against the wolfstack-threat-intel ipset and DROPs. Empty
    // string when threat-intel is off or dry-running, so the ruleset is
    // unchanged for users not opting in.
    out.push_str(&crate::threat_intel::firewall::iptables_lines_v4());

    // User rules in order. Rules without a node_id match on any node;
    // rules with node_id set only apply on that node.
    let mut rules: Vec<&FirewallRule> = config.rules.iter()
        .filter(|r| r.enabled)
        .filter(|r| r.node_id.as_deref().map(|n| n == self_node_id).unwrap_or(true))
        .collect();
    rules.sort_by_key(|r| r.order);

    for r in rules {
        for line in compile_rule(r, config, self_node_id) {
            out.push_str(&line);
            out.push('\n');
        }
    }

    out.push_str("COMMIT\n");
    out
}

/// Compile one FirewallRule into one OR MORE iptables-restore lines.
/// Returns multiple rules when:
///   • Protocol is Tcpudp → emits one rule for tcp + one for udp
///   • A zone endpoint has N>1 interfaces → emits N rules (one per iface)
/// Returns empty Vec if the rule can't be compiled (zone with no
/// members on this node, etc.) — misconfigured rules don't break the
/// ruleset; they just no-op silently and a comment is included so
/// debugging is possible.
fn compile_rule(rule: &FirewallRule, config: &RouterConfig, self_node_id: &str) -> Vec<String> {
    let chain = match rule.direction {
        Direction::Forward => "WOLFROUTER_FWD",
        Direction::Input => "WOLFROUTER_IN",
        Direction::Output => "WOLFROUTER_OUT",
    };

    // Resolve "from" and "to" endpoints into one or more (arg-vec) match
    // sets. The cartesian product of these expands a single rule into
    // multiple iptables lines for multi-iface zones.
    let from_opts = match expand_endpoint(&rule.from, "src", config, self_node_id) {
        Ok(v) if v.is_empty() => return vec![format!(
            "# wolfrouter rule {} skipped: 'from' endpoint resolved to nothing on this node",
            rule.id
        )],
        Ok(v) => v,
        Err(reason) => return vec![format!("# wolfrouter rule {} skipped: {}", rule.id, reason)],
    };
    let to_opts = match expand_endpoint(&rule.to, "dst", config, self_node_id) {
        Ok(v) if v.is_empty() => return vec![format!(
            "# wolfrouter rule {} skipped: 'to' endpoint resolved to nothing on this node",
            rule.id
        )],
        Ok(v) => v,
        Err(reason) => return vec![format!("# wolfrouter rule {} skipped: {}", rule.id, reason)],
    };

    // Tcpudp expands into [Tcp, Udp]; everything else is a single proto.
    let protos: Vec<Option<&str>> = match rule.protocol {
        Protocol::Tcp => vec![Some("tcp")],
        Protocol::Udp => vec![Some("udp")],
        Protocol::Icmp => vec![Some("icmp")],
        Protocol::Tcpudp => vec![Some("tcp"), Some("udp")],
        Protocol::Any => vec![None],
    };

    let mut out: Vec<String> = Vec::new();
    for proto in &protos {
        for from in &from_opts {
            for to in &to_opts {
                out.extend(emit_rule(rule, chain, *proto, from, to));
            }
        }
    }
    out
}

/// Build the actual iptables-restore line for a fully-resolved rule
/// instance: one chain, one protocol, one from-match, one to-match.
fn emit_rule(
    rule: &FirewallRule,
    chain: &str,
    proto: Option<&str>,
    from: &[String],
    to: &[String],
) -> Vec<String> {
    let mut parts: Vec<String> = vec![format!("-A {}", chain)];
    if let Some(p) = proto { parts.push(format!("-p {}", p)); }
    for f in from { parts.push(f.clone()); }
    for t in to { parts.push(t.clone()); }

    // Ports — only meaningful for tcp/udp
    if matches!(proto, Some("tcp") | Some("udp")) {
        for ps in &rule.ports {
            let flag = if ps.side == PortSide::Dst { "--dport" } else { "--sport" };
            let port = ps.port.replace('-', ":");
            parts.push(format!("{} {}", flag, port));
        }
    }

    // State tracking — limit user rules to NEW connections; the global
    // ESTABLISHED,RELATED accept rule at the top of each chain handles
    // return traffic.
    if rule.state_track {
        parts.push("-m conntrack --ctstate NEW".into());
    }

    let action_flag = match rule.action {
        Action::Allow => "-j ACCEPT",
        Action::Deny => "-j DROP",
        Action::Reject => "-j REJECT",
        // `Action::Log` is paired with `-j NFLOG` below — by itself
        // `-j RETURN` would silently exit the WOLFROUTER chain with
        // no record of the match (the bug fixed by H4). Treating the
        // Log action as implicitly setting log_match=true ensures the
        // NFLOG line is always emitted alongside the RETURN.
        Action::Log => "-j RETURN",
    };

    // H4 fix: Action::Log MUST emit the NFLOG line. Pre-fix, it compiled
    // to just `-j RETURN` which exits the chain without logging — a
    // silent no-op that turned a "Log this match" rule into a no-record
    // accept-bypass. Now Log is treated as if log_match=true regardless
    // of the operator's separate log_match toggle (it's nonsensical to
    // pick the Log action and disable logging on the same rule).
    let want_log_emit = rule.log_match || matches!(rule.action, Action::Log);

    if want_log_emit {
        // Emit the NFLOG copy first (doesn't terminate), then the action.
        let prefix = format!("wolfrouter-{} ", &rule.id[..rule.id.len().min(8)]);
        let mut log_parts = parts.clone();
        log_parts.push("-j NFLOG".into());
        log_parts.push("--nflog-group 1".into());
        log_parts.push(format!("--nflog-prefix \"{}\"", prefix));
        let log_line = log_parts.join(" ");
        parts.push(action_flag.into());
        let action_line = parts.join(" ");
        vec![log_line, action_line]
    } else {
        parts.push(action_flag.into());
        vec![parts.join(" ")]
    }
}

/// Expand an Endpoint into one or more match-arg vectors. Each inner
/// vector is the args for one rule instance. Multi-member zones return
/// multiple instances; single-IP/iface returns one; Any returns one
/// empty vector (no constraint). Returns Err with a human reason if
/// the endpoint can't be resolved at all.
fn expand_endpoint(
    ep: &Endpoint,
    side: &str,
    config: &RouterConfig,
    self_node_id: &str,
) -> Result<Vec<Vec<String>>, String> {
    match ep {
        Endpoint::Any => Ok(vec![vec![]]),

        Endpoint::Ip { cidr } => {
            let flag = if side == "src" { "-s" } else { "-d" };
            Ok(vec![vec![format!("{} {}", flag, cidr)]])
        }

        Endpoint::Interface { name } => {
            let flag = if side == "src" { "-i" } else { "-o" };
            Ok(vec![vec![format!("{} {}", flag, name)]])
        }

        Endpoint::Zone { zone } => {
            let members = config.zones.members_for_zone_on_node(self_node_id, zone);
            if members.is_empty() {
                return Ok(vec![]);  // zone has no members on this node — rule no-ops here
            }
            let flag = if side == "src" { "-i" } else { "-o" };
            // Multi-iface: emit one rule instance per member interface
            // (cartesian-expanded by compile_rule). Avoids the ipset
            // dependency for now while still being correct.
            Ok(members.into_iter().map(|m| vec![format!("{} {}", flag, m)]).collect())
        }

        Endpoint::Lan { id } => {
            // Resolve LAN id → subnet CIDR. Source/dest match by IP.
            let lan = config.lans.iter().find(|l| &l.id == id);
            match lan {
                Some(l) => {
                    let flag = if side == "src" { "-s" } else { "-d" };
                    Ok(vec![vec![format!("{} {}", flag, l.subnet_cidr)]])
                }
                None => Err(format!("LAN '{}' not found", id)),
            }
        }

        Endpoint::Vm { name } | Endpoint::Container { name } => {
            // Resolve via WolfNet IP (the only VM IP we know without
            // querying the guest). VMs without a WolfNet IP can't be
            // matched — flag the rule as skipped so the user can fix it.
            let vmm = crate::vms::manager::VmManager::new();
            let vm = vmm.list_vms().into_iter().find(|v| &v.name == name);
            match vm {
                Some(v) => match v.wolfnet_ip {
                    Some(ip) => {
                        let flag = if side == "src" { "-s" } else { "-d" };
                        Ok(vec![vec![format!("{} {}/32", flag, ip)]])
                    }
                    None => Err(format!("VM '{}' has no WolfNet IP — assign one before referencing it in a rule", name)),
                },
                None => Err(format!("VM/container '{}' not found", name)),
            }
        }
    }
}

/// Pre-flight check — scan a proposed iptables-save-format ruleset for
/// rules that would lock the caller out of the management interface.
/// Returns a list of concerns (empty = ruleset looks safe).
///
/// Heuristic, not a simulator: we parse `-A INPUT … --dport <mgmt_port>
/// … -j DROP|REJECT` lines and check whether the caller's peer IP
/// matches the rule's `-s` clause (or whether the rule has no `-s`,
/// matching everyone). False positives are possible (layered rules
/// where a later ACCEPT supersedes the DROP) but false negatives are
/// bounded — we catch the common "DROP tcp/8553 from 0.0.0.0/0" bullet
/// the operator would otherwise take to the face.
///
/// `mgmt_ports` is typically `[8553, 8554]` (primary + inter-node). If
/// a rule would block any of these for the caller, it's a concern.
pub fn analyse_ruleset_against_session(
    ruleset: &str,
    peer_ip: Option<&str>,
    mgmt_ports: &[u16],
) -> Vec<String> {
    let mut concerns = Vec::new();
    let peer = match peer_ip { Some(p) if !p.is_empty() => p, _ => return concerns };
    // Only look at INPUT-chain rules — FORWARD/OUTPUT can't block our
    // session from reaching this box.
    for line in ruleset.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("-A INPUT ") && !trimmed.starts_with("-I INPUT ") {
            continue;
        }
        // Target must be a drop/reject variant.
        let drops = trimmed.contains("-j DROP") || trimmed.contains("-j REJECT");
        if !drops { continue; }
        // Must mention at least one of the mgmt ports on --dport or
        // --dports. Check all the forms iptables actually emits:
        //   --dport 8553
        //   --dport 8000:9000        (port range — port falls inside)
        //   -m multiport --dports 22,8553,8554   (any slot matches)
        //   -m multiport --dports 8000:9000      (range inside multiport)
        // The range handling is what upgrades this from "lazy substring
        // match" to something an attacker can't slip a multiport or
        // range rule past. See the firewall-apply test plan.
        let matches_port = rule_matches_any_port(trimmed, mgmt_ports);
        if !matches_port { continue; }
        // Would this rule match the session's peer? If the rule has a
        // -s clause we compare it to peer_ip; if it has no -s clause
        // it matches every source (which definitely includes peer_ip).
        let source_matches = if let Some(idx) = trimmed.find("-s ") {
            let after = &trimmed[idx + 3..];
            let src = after.split_whitespace().next().unwrap_or("");
            cidr_matches_ip(src, peer)
        } else {
            true
        };
        if source_matches {
            concerns.push(format!(
                "rule `{}` would DROP/REJECT traffic from your current session source ({}) to a WolfStack management port. \
                 Applying this would lock your browser out of this node.",
                trimmed, peer
            ));
        }
    }
    concerns
}

/// Does an iptables rule line cover any of the given management
/// ports? Handles every form iptables-save emits that we've actually
/// seen: single port, colon range, `-m multiport --dports` with a
/// comma-separated list which can itself contain ranges. Anything
/// else (e.g. `--match-set`, `ipset`) returns false — those would
/// need the ipset content to evaluate and the pre-flight can't
/// simulate that. iptables-save uses `--source` rarely but `-s`
/// always; we anchor on `-s`.
fn rule_matches_any_port(rule: &str, mgmt_ports: &[u16]) -> bool {
    // --dport <X> (single port or single range).
    if let Some(v) = find_flag_value(rule, "--dport")
        && port_spec_covers_any(v, mgmt_ports) { return true; }
    // -m multiport --dports <comma-separated, each can be a range>
    if let Some(v) = find_flag_value(rule, "--dports") {
        for chunk in v.split(',') {
            if port_spec_covers_any(chunk.trim(), mgmt_ports) { return true; }
        }
    }
    false
}

/// Pull the single whitespace-delimited value after a named flag.
/// Returns None if the flag isn't present. Flags in iptables-save
/// never take quoted values, so whitespace split is sufficient.
fn find_flag_value<'a>(rule: &'a str, flag: &str) -> Option<&'a str> {
    let tokens: Vec<&str> = rule.split_whitespace().collect();
    for (i, t) in tokens.iter().enumerate() {
        if *t == flag {
            return tokens.get(i + 1).copied();
        }
    }
    None
}

/// Does the port-spec `spec` (e.g. "8553", "8000:9000") cover any of
/// `wanted`? Used to test both the `--dport` argument and each slot
/// of a `--dports` comma-separated list.
fn port_spec_covers_any(spec: &str, wanted: &[u16]) -> bool {
    if let Some((lo_s, hi_s)) = spec.split_once(':') {
        let (Ok(lo), Ok(hi)) = (lo_s.parse::<u16>(), hi_s.parse::<u16>()) else { return false; };
        if lo > hi { return false; }
        return wanted.iter().any(|p| *p >= lo && *p <= hi);
    }
    let Ok(p) = spec.parse::<u16>() else { return false; };
    wanted.contains(&p)
}

/// Cheap best-effort "does this CIDR-ish string cover this IP?" for
/// the pre-flight analyser. Handles `a.b.c.d`, `a.b.c.d/32`, and
/// `a.b.c.d/24`. Anything weirder (IPv6, range syntax) returns true
/// so we err on the side of flagging a concern rather than hiding it.
fn cidr_matches_ip(cidr: &str, ip: &str) -> bool {
    let ip_octets: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if ip_octets.len() != 4 { return true; }
    let (addr_part, mask_str) = match cidr.split_once('/') {
        Some((a, m)) => (a, m),
        None => (cidr, "32"),
    };
    let mask: u8 = mask_str.parse().unwrap_or(32);
    if mask > 32 { return true; }
    let addr_octets: Vec<u8> = addr_part.split('.').filter_map(|s| s.parse().ok()).collect();
    if addr_octets.len() != 4 { return true; }
    let ip_u32 = ((ip_octets[0] as u32) << 24) | ((ip_octets[1] as u32) << 16)
        | ((ip_octets[2] as u32) << 8) | (ip_octets[3] as u32);
    let addr_u32 = ((addr_octets[0] as u32) << 24) | ((addr_octets[1] as u32) << 16)
        | ((addr_octets[2] as u32) << 8) | (addr_octets[3] as u32);
    let mask_u32: u32 = if mask == 0 { 0 } else { u32::MAX << (32 - mask) };
    (ip_u32 & mask_u32) == (addr_u32 & mask_u32)
}

/// Build the ip6tables-save-format companion for the filter table.
///
/// Deliberately does NOT declare or append to the built-in chains
/// (INPUT/FORWARD/OUTPUT). We always restore with `-n` (noflush), and
/// verified on this host's iptables-nft backend that under `-n`:
///   * a built-in chain is NOT flushed, so any `-A INPUT -j …` line
///     APPENDS — applying the companion N times would leave N duplicate
///     `-j WOLFROUTER_IN` jumps in INPUT (the actual bug; operator rules
///     in INPUT are untouched precisely because INPUT is never flushed);
///   * a user chain declared `:WOLFROUTER_IN - [0:0]` IS flushed and
///     refilled wholesale — exactly the v4 lifecycle we want.
///     So: declare/refill only OUR chains here, and let `apply_v6_companion`
///     add the built-in→WOLFROUTER jumps idempotently (`-C` probe, `-I 1` on
///     miss). That keeps operator/`kernel_block_ip` v6 rules in the built-in
///     chains intact and the jump count pinned at exactly one.
///
/// Content: the same state/loopback accepts as v4 plus the threat-intel
/// v6 chain when enforcement is active. NO user rules — those compile to
/// iptables semantics only (v6 routing is future work) — so this ruleset
/// can never lock an operator out: with threat-intel off it is pure
/// no-op scaffolding, and re-applying it on a threat-intel disable is
/// precisely what removes the stale v6 DROP rules.
pub fn build_ruleset_v6() -> String {
    let mut out = String::new();
    out.push_str("*filter\n");
    for chain in FILTER_CHAINS {
        out.push_str(&format!(":{} - [0:0]\n", chain));
    }
    for ch in FILTER_CHAINS {
        out.push_str(&format!(
            "-A {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", ch
        ));
        out.push_str(&format!("-A {} -i lo -j ACCEPT\n", ch));
    }
    out.push_str(&crate::threat_intel::firewall::ip6tables_lines());
    out.push_str("COMMIT\n");
    out
}

/// Apply a ruleset. `test_only = true` runs `iptables-restore --test`
/// without swapping. Returns the previous ruleset (as iptables-save
/// text) on success so callers can stash it for rollback.
///
/// Every real (non-test) apply also applies the v6 companion ruleset —
/// see `build_ruleset_v6`. A v6 failure never fails the v4 apply: hosts
/// without ip6tables (or with a v6-less kernel) must keep working exactly
/// as before, and the companion contains no user rules to lose.
pub fn apply(ruleset: &str, test_only: bool) -> Result<String, String> {
    // Dump current filter table for rollback.
    let current = dump_filter_table().unwrap_or_default();

    // Validate first.
    if !run_restore(ruleset, true)? {
        return Err("iptables-restore --test rejected the ruleset".into());
    }
    if test_only {
        return Ok(current);
    }

    // Flush ONLY our own chains before the restore. Under legacy iptables,
    // `iptables-restore -n` does NOT flush a declared chain, so without this our
    // chains' rules would duplicate on every apply; under nft it's a harmless
    // double-flush. We never flush the built-in chains — the ruleset no longer
    // declares them, so Docker's and the operator's own INPUT/FORWARD/OUTPUT
    // rules survive every apply. (-F on a not-yet-created chain errors
    // harmlessly on first run; the restore then creates them.)
    for chain in FILTER_CHAINS.iter().copied().chain([crate::threat_intel::CHAIN_NAME]) {
        let _ = Command::new("iptables").args(["-F", chain]).output();
    }

    // Swap.
    if !run_restore(ruleset, false)? {
        return Err("iptables-restore failed to apply (ruleset reverted to previous)".into());
    }

    // Hook our chains into the built-ins idempotently — one jump each, never via
    // the restore file (which would flush the built-in on the nft backend).
    ensure_builtin_jumps_v4();

    info!("WolfRouter firewall applied ({} bytes)", ruleset.len());
    apply_v6_companion();
    Ok(current)
}

/// Ensure exactly one jump from each built-in filter chain into the matching
/// WOLFROUTER chain (`-C` probe + `-I 1`), the same idempotent pattern as
/// apply_v6_companion. Done out-of-band rather than in the restore file because
/// naming a built-in chain in an `iptables-restore -n` file flushes it on the
/// nft backend — which would wipe Docker's and the operator's own rules.
fn ensure_builtin_jumps_v4() {
    for (builtin, ours) in [
        ("INPUT", "WOLFROUTER_IN"),
        ("FORWARD", "WOLFROUTER_FWD"),
        ("OUTPUT", "WOLFROUTER_OUT"),
    ] {
        // Count existing jumps via `-S`. The PRE-fix v4 code appended this jump
        // through the restore file with no `-C` guard, so on legacy hosts that
        // ran it every reconcile there can be MANY duplicate jumps. Steady state
        // is exactly one → leave it untouched (no churn, no apply-time window).
        // Anything else (0, or N>1 legacy duplicates) → drain all and insert one.
        let jump_line = format!("-A {} -j {}", builtin, ours);
        let count = Command::new("iptables").args(["-S", builtin]).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout)
                .lines().filter(|l| l.trim() == jump_line).count())
            .unwrap_or(0);
        if count == 1 { continue; }

        let mut guard = 0;
        while Command::new("iptables").args(["-D", builtin, "-j", ours]).output()
            .map(|o| o.status.success()).unwrap_or(false)
        {
            guard += 1;
            if guard > 100_000 { break; }
        }
        let _ = Command::new("iptables").args(["-I", builtin, "1", "-j", ours]).output();
    }
}

/// Apply the v6 companion. Best-effort by design (see `apply`): a
/// failure is loud only when threat-intel v6 enforcement is supposed to
/// be live — then the operator must know the v6 blocklist is NOT being
/// enforced — and a debug whisper otherwise (logged once per state
/// change, not per apply).
///
/// Sequence, chosen so operator ip6tables rules are never touched:
/// 1. Flush OUR chains with `ip6tables -F` (legacy ip6tables-restore
///    --noflush does NOT flush declared chains, so without this, rules
///    inside our chains would duplicate on every apply there; under nft
///    it's a harmless double-flush).
/// 2. `ip6tables-restore -n` the companion (declares/refills our chains
///    only — never the built-ins).
/// 3. Idempotently ensure the single jump from each built-in chain into
///    the matching WOLFROUTER chain (`-C` probe, `-I 1` on miss) — the
///    same pattern `insert_drop_rule` uses.
fn apply_v6_companion() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static V6_FAIL_LOGGED: AtomicBool = AtomicBool::new(false);

    let ruleset_v6 = build_ruleset_v6();
    let ti_active = ruleset_v6.contains(crate::threat_intel::CHAIN_NAME);

    // Step 1 — flush our own chains (ignore errors: first run, no chains
    // yet; missing binary surfaces in step 2). The threat-intel chain is
    // flushed too so a disable empties it even on legacy ip6tables.
    for chain in FILTER_CHAINS.iter().copied().chain([crate::threat_intel::CHAIN_NAME]) {
        let _ = Command::new("ip6tables").args(["-F", chain]).output();
    }

    // Step 2 — restore our chains.
    let restored = matches!(run_restore_cmd("ip6tables-restore", &ruleset_v6, false), Ok(true));

    // Step 3 — single jump from each built-in into our chain.
    let mut jumps_ok = restored;
    if restored {
        for (builtin, ours) in [
            ("INPUT", "WOLFROUTER_IN"),
            ("FORWARD", "WOLFROUTER_FWD"),
            ("OUTPUT", "WOLFROUTER_OUT"),
        ] {
            let present = Command::new("ip6tables")
                .args(["-C", builtin, "-j", ours])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !present {
                let ins = Command::new("ip6tables")
                    .args(["-I", builtin, "1", "-j", ours])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ins { jumps_ok = false; }
            }
        }
    }

    if jumps_ok {
        if V6_FAIL_LOGGED.swap(false, Ordering::Relaxed) {
            info!("ip6tables v6 companion recovered — v6 enforcement restored");
        }
    } else if !V6_FAIL_LOGGED.swap(true, Ordering::Relaxed) {
        if ti_active {
            warn!(
                "ip6tables apply failed — threat-intel v6 blocklist is NOT \
                 enforced on this host (v4 enforcement unaffected). Install \
                 ip6tables or disable IPv6 to silence this."
            );
        } else {
            tracing::debug!("ip6tables unavailable — v6 companion skipped");
        }
    }
}

/// Revert to a previously-captured iptables-save dump. v4 only by
/// design: the v6 companion carries no user rules (it tracks the
/// threat-intel config, which a rules rollback doesn't change), so
/// there is nothing v6-side for a safe-mode revert to undo.
pub fn revert(previous: &str) -> Result<(), String> {
    if !run_restore(previous, false)? {
        return Err("Failed to revert firewall to previous state".into());
    }
    warn!("WolfRouter firewall reverted to previous ruleset");
    Ok(())
}

/// Dump the current filter table in iptables-save format.
pub fn dump_filter_table() -> Result<String, String> {
    let out = Command::new("iptables-save")
        .args(["-t", "filter"])
        .output()
        .map_err(|e| format!("iptables-save: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "iptables-save exited {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Run iptables-restore on the given input. Returns true on success.
fn run_restore(input: &str, test_only: bool) -> Result<bool, String> {
    run_restore_cmd("iptables-restore", input, test_only)
}

/// Run the given restore binary (iptables-restore / ip6tables-restore)
/// on the input. Returns true on success.
fn run_restore_cmd(restore_bin: &str, input: &str, test_only: bool) -> Result<bool, String> {
    use std::io::Write;
    let mut cmd = Command::new(restore_bin);
    if test_only { cmd.arg("--test"); }
    // -n = don't flush other tables. Critical: we're only writing
    // *filter, and we don't want to wipe out *nat (DNAT/SNAT rules
    // owned by other subsystems) or *mangle.
    cmd.arg("-n");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn iptables-restore: {}", e))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())
            .map_err(|e| format!("write to iptables-restore stdin: {}", e))?;
    }
    let out = child.wait_with_output()
        .map_err(|e| format!("wait iptables-restore: {}", e))?;
    if !out.status.success() {
        warn!(
            "iptables-restore stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return Ok(false);
    }
    Ok(true)
}

/// Sanity-check rules without touching the live table. Returns list of
/// compile errors / warnings keyed by rule id.
pub fn validate(config: &RouterConfig, self_node_id: &str) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    let mut seen_ids: HashSet<&str> = HashSet::new();
    for r in &config.rules {
        if !seen_ids.insert(&r.id) {
            issues.push((r.id.clone(), format!("Duplicate rule id: {}", r.id)));
        }
        if matches!(r.protocol, Protocol::Any) && !r.ports.is_empty() {
            issues.push((
                r.id.clone(),
                "Port match has no effect when protocol is Any — set protocol to TCP or UDP".into(),
            ));
        }
    }
    // Test-apply the whole ruleset.
    let ruleset = build_ruleset(config, self_node_id);
    if let Err(e) = apply(&ruleset, true) {
        issues.push(("_ruleset_".into(), e));
    }
    issues
}

#[cfg(test)]
mod preflight_tests {
    use super::*;

    fn flag(rule: &str, ports: &[u16]) -> bool {
        rule_matches_any_port(rule, ports)
    }

    #[test]
    fn v4_build_ruleset_never_declares_builtin_chains() {
        // The v4 ruleset must NOT name a built-in chain either — under
        // iptables-nft, `iptables-restore -n` flushes any chain named in the
        // file, so declaring `:FORWARD` would wipe Docker's / the operator's
        // FORWARD rules every apply (the bug this guards against). The built-in
        // -> WOLFROUTER jumps are installed out-of-band in `apply` instead.
        let rs = build_ruleset(&RouterConfig::default(), "test-node");
        assert!(rs.starts_with("*filter\n"));
        assert!(rs.ends_with("COMMIT\n"));
        for builtin in [":INPUT", ":FORWARD", ":OUTPUT",
                        "-A INPUT", "-A FORWARD", "-A OUTPUT"] {
            assert!(!rs.contains(builtin),
                "v4 build_ruleset must not name a built-in chain ({builtin}) — naming it flushes the chain on iptables-nft");
        }
        for chain in FILTER_CHAINS {
            assert!(rs.contains(&format!(":{} - [0:0]", chain)),
                "v4 build_ruleset must still declare its own chain {chain}");
        }
    }

    #[test]
    fn v6_companion_is_scaffolding_plus_threat_intel_only() {
        let rs = build_ruleset_v6();
        assert!(rs.starts_with("*filter\n"));
        assert!(rs.ends_with("COMMIT\n"));
        // The companion must NEVER declare the built-in chains: under
        // iptables-nft, restore --noflush flushes every chain named in
        // the file — declaring INPUT/FORWARD would wipe operator v6
        // rules and kernel_block_ip's own v6 DROPs on every apply.
        for builtin in [":INPUT", ":FORWARD", ":OUTPUT",
                        "-A INPUT", "-A FORWARD", "-A OUTPUT"] {
            assert!(
                !rs.contains(builtin),
                "v6 companion must not touch built-in chain ({builtin})"
            );
        }
        for chain in FILTER_CHAINS {
            assert!(rs.contains(&format!(":{} - [0:0]", chain)));
        }
        assert!(rs.contains("-A WOLFROUTER_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"));
        // The ONLY permissible DROPs are threat-intel ipset matches — user
        // rules are v4-only and must never leak into the companion.
        for line in rs.lines().filter(|l| l.contains("-j DROP")) {
            assert!(
                line.contains("--match-set"),
                "unexpected non-threat-intel DROP in v6 companion: {line}"
            );
        }
    }

    #[test]
    fn single_port_matches() {
        assert!(flag("-A INPUT -p tcp --dport 8553 -j DROP", &[8553, 8554]));
        assert!(!flag("-A INPUT -p tcp --dport 22 -j DROP", &[8553, 8554]));
    }

    #[test]
    fn port_range_matches_if_target_inside() {
        // The bug the reviewer found — 8553 inside 8000:9000.
        assert!(flag("-A INPUT -p tcp --dport 8000:9000 -j DROP", &[8553]));
        // Outside the range.
        assert!(!flag("-A INPUT -p tcp --dport 1000:2000 -j DROP", &[8553]));
        // Reversed range (malformed) — don't flag, iptables would reject anyway.
        assert!(!flag("-A INPUT -p tcp --dport 9000:8000 -j DROP", &[8553]));
    }

    #[test]
    fn multiport_dports_any_slot_matches() {
        // The second reviewer bug — 8553 isn't the first port.
        assert!(flag(
            "-A INPUT -p tcp -m multiport --dports 22,8553,8554 -j DROP",
            &[8553, 8554],
        ));
        // Also works when combined with ranges in a slot.
        assert!(flag(
            "-A INPUT -p tcp -m multiport --dports 22,8000:9000,443 -j DROP",
            &[8553],
        ));
        // No slot matches.
        assert!(!flag(
            "-A INPUT -p tcp -m multiport --dports 22,443,80 -j DROP",
            &[8553, 8554],
        ));
    }

    #[test]
    fn cidr_match() {
        assert!(cidr_matches_ip("10.0.0.0/8", "10.1.2.3"));
        assert!(cidr_matches_ip("192.168.1.0/24", "192.168.1.100"));
        assert!(!cidr_matches_ip("192.168.1.0/24", "192.168.2.100"));
        assert!(cidr_matches_ip("0.0.0.0/0", "203.0.113.1")); // match all
        assert!(cidr_matches_ip("203.0.113.7", "203.0.113.7")); // bare address = /32
        assert!(!cidr_matches_ip("203.0.113.7", "203.0.113.8"));
    }

    #[test]
    fn analyser_end_to_end() {
        let rule = "*filter\n:INPUT ACCEPT [0:0]\n\
                    -A INPUT -p tcp -m multiport --dports 22,8553,8554 -j DROP\n\
                    COMMIT\n";
        let concerns = analyse_ruleset_against_session(
            rule, Some("192.168.1.50"), &[8553, 8554]
        );
        assert_eq!(concerns.len(), 1, "should flag the multiport DROP");
    }

    #[test]
    fn analyser_narrow_source_misses_session() {
        // Rule only affects 10.0.0.0/24 — session is elsewhere.
        let rule = "-A INPUT -s 10.0.0.0/24 -p tcp --dport 8553 -j DROP\n";
        let concerns = analyse_ruleset_against_session(
            rule, Some("192.168.1.50"), &[8553]
        );
        assert!(concerns.is_empty(), "source scope excludes session — shouldn't flag");
    }
}
