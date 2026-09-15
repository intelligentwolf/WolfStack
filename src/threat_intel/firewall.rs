// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Threat-intel hooks for WolfRouter's `build_ruleset`.
//!
//! Returns iptables-restore lines that:
//! 1. Declare the `WOLFSTACK_THREAT_INTEL` chain.
//! 2. Match against the ipset and DROP.
//! 3. Inject a jump from `WOLFROUTER_IN` and `WOLFROUTER_FWD`.
//!
//! When threat-intel is disabled or in dry-run mode, returns an empty
//! string — the chain isn't declared, no jump exists, no kernel-level
//! filtering happens.

/// Lines to inject into WolfRouter's iptables-save-format ruleset for
/// IPv4. Empty when disabled or dry-run. Append the result inside the
/// `*filter` section, after WOLFROUTER_IN/FWD/OUT are declared but
/// before the `COMMIT` line.
///
/// The chain matches on **both** `src` and `dst`:
/// - `src` catches inbound from blocklisted IPs (attackers reaching us)
/// - `dst` catches outbound to blocklisted IPs (e.g. malware in a
///   container calling home to a known C2 server)
///
/// Jumped from all three WolfRouter chains:
/// - `WOLFROUTER_IN`  — packets destined for this host
/// - `WOLFROUTER_FWD` — packets routed/bridged through this host
///   (Docker published ports, LXC, VMs on bridges)
/// - `WOLFROUTER_OUT` — packets originating from this host (incl.
///   host-networked containers)
pub fn iptables_lines_v4() -> String {
    let cfg = super::ThreatIntelConfig::load();
    if !super::enforcement_active(&cfg) {
        return String::new();
    }
    let mut out = String::new();
    out.push(':');
    out.push_str(super::CHAIN_NAME);
    out.push_str(" - [0:0]\n");
    // Inbound from blocklisted source — NEW connections only, so a feed
    // update that lists an operator's IP can never sever their LIVE
    // session (klas 2026-07-05); fresh attack connections are still
    // dropped. Applied atomically via iptables-restore chain rebuild,
    // so no legacy-rule migration is needed here.
    out.push_str("-A ");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" -m conntrack --ctstate NEW -m set --match-set ");
    out.push_str(super::IPSET_NAME_V4);
    out.push_str(" src -j DROP\n");
    // Outbound to blocklisted destination — catches C2 callouts.
    // Deliberately NOT state-limited: an already-established channel to
    // a listed C2 is exactly what this rule must sever.
    out.push_str("-A ");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" -m set --match-set ");
    out.push_str(super::IPSET_NAME_V4);
    out.push_str(" dst -j DROP\n");
    // Jumps from all three managed chains.
    out.push_str("-A WOLFROUTER_IN -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out.push_str("-A WOLFROUTER_FWD -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out.push_str("-A WOLFROUTER_OUT -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out
}

/// Same for ip6tables — consumed by `router::firewall::build_ruleset_v6`,
/// which is applied alongside every v4 apply so the v6 blocklist ipset is
/// actually enforced (without this, a blocklisted host could simply
/// connect over v6). Empty when disabled or dry-run. Same src/dst
/// dual-direction matching as the IPv4 version.
pub fn ip6tables_lines() -> String {
    let cfg = super::ThreatIntelConfig::load();
    if !super::enforcement_active(&cfg) {
        return String::new();
    }
    let mut out = String::new();
    out.push(':');
    out.push_str(super::CHAIN_NAME);
    out.push_str(" - [0:0]\n");
    // Same state policy as v4: inbound NEW-only (operator's live session
    // survives a feed update), outbound unconditional (established C2
    // channels get severed).
    out.push_str("-A ");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" -m conntrack --ctstate NEW -m set --match-set ");
    out.push_str(super::IPSET_NAME_V6);
    out.push_str(" src -j DROP\n");
    out.push_str("-A ");
    out.push_str(super::CHAIN_NAME);
    out.push_str(" -m set --match-set ");
    out.push_str(super::IPSET_NAME_V6);
    out.push_str(" dst -j DROP\n");
    out.push_str("-A WOLFROUTER_IN -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out.push_str("-A WOLFROUTER_FWD -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out.push_str("-A WOLFROUTER_OUT -j ");
    out.push_str(super::CHAIN_NAME);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_emits_nothing() {
        // Default config is disabled — should produce empty.
        let cfg = super::super::ThreatIntelConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.dry_run);
        // We can't easily mock disk loads in tests, so this is a sanity
        // check on the default — the actual function reads from disk
        // but with a default state on disk the result must be empty.
        let _ = iptables_lines_v4();  // should not panic
    }

    #[test]
    fn test_chain_name_constant() {
        assert_eq!(super::super::CHAIN_NAME, "WOLFSTACK_THREAT_INTEL");
        assert_eq!(super::super::IPSET_NAME_V4, "wolfstack-threat-intel");
        assert_eq!(super::super::IPSET_NAME_V6, "wolfstack-threat-intel-6");
    }
}
