// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Socket tables and local addresses, per network namespace.
//!
//! `/proc/<pid>/net/*` shows the network namespace of `<pid>`, so reading
//! it through a container's init gives that container's sockets without
//! entering the namespace (no `nsenter`, no `ss` inside the target).
//!
//! Formats, as written by the kernel (`tcp4_seq_show` / `tcp6_seq_show`)
//! and checked against a live host:
//!
//! ```text
//!   sl  local_address rem_address   st ... uid  timeout inode
//!    0: 3600007F:0035 00000000:0000 0A ...  974        0 6474936 ...
//! ```
//!
//! IPv4 addresses are one 32-bit word in host byte order (little-endian
//! on every platform WolfStack ships to — `127.0.0.54` is `3600007F`);
//! IPv6 is four such words. Ports are big-endian hex. State `0A` is
//! LISTEN, `01` ESTABLISHED (include/net/tcp_states.h).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_LISTEN: u8 = 0x0A;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub state: u8,
    pub inode: u64,
}

fn word_le(hex: &str) -> Option<[u8; 4]> {
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(v.to_le_bytes())
}

pub fn parse_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => Some(IpAddr::V4(Ipv4Addr::from(word_le(hex)?))),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word_le(&hex[i * 8..i * 8 + 8])?);
            }
            let v6 = Ipv6Addr::from(b);
            Some(match v6.to_ipv4_mapped() { Some(v4) => IpAddr::V4(v4), None => IpAddr::V6(v6) })
        }
        _ => None,
    }
}

fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    Some((parse_addr(a)?, u16::from_str_radix(p, 16).ok()?))
}

/// Parse a `/proc/net/tcp` or `tcp6` body.
pub fn parse_tcp_table(body: &str) -> Vec<Sock> {
    let mut out = Vec::new();
    for line in body.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 { continue; }
        let (Some((local, lp)), Some((remote, rp))) = (parse_endpoint(f[1]), parse_endpoint(f[2])) else { continue };
        let (Ok(state), Ok(inode)) = (u8::from_str_radix(f[3], 16), f[9].parse::<u64>()) else { continue };
        out.push(Sock { local, local_port: lp, remote, remote_port: rp, state, inode });
    }
    out
}

/// All TCP sockets of the network namespace `pid` lives in.
pub fn tcp_sockets(pid: u32) -> Vec<Sock> {
    let mut out = Vec::new();
    for f in ["tcp", "tcp6"] {
        if let Ok(body) = std::fs::read_to_string(format!("/proc/{}/net/{}", pid, f)) {
            out.extend(parse_tcp_table(&body));
        }
    }
    out
}

/// Socket inodes a process holds open (`/proc/<pid>/fd/* -> socket:[N]`).
pub fn socket_inodes(pid: u32) -> Vec<u64> {
    let Ok(rd) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else { return Vec::new() };
    rd.flatten().filter_map(|e| {
        let l = std::fs::read_link(e.path()).ok()?;
        let s = l.to_str()?;
        s.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
    }).collect()
}

/// inode → owning PID for the given processes.
pub fn inode_owners(pids: &[u32]) -> HashMap<u64, u32> {
    let mut m = HashMap::new();
    for p in pids {
        for i in socket_inodes(*p) { m.entry(i).or_insert(*p); }
    }
    m
}

/// Local unicast addresses of a namespace, from `/proc/<pid>/net/fib_trie`:
/// an address line `|-- a.b.c.d` followed by `/32 host LOCAL`
/// (fib_trie_seq_show / fib_route_seq_show).
pub fn parse_fib_trie_locals(body: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut last: Option<IpAddr> = None;
    for line in body.lines() {
        let t = line.trim();
        if let Some(a) = t.strip_prefix("|-- ") {
            last = a.parse().ok();
        } else if t.starts_with("/32 host LOCAL")
            && let Some(ip) = last.take()
            && !out.contains(&ip) && !ip.is_loopback() {
            out.push(ip);
        }
    }
    out
}

pub fn local_addresses(pid: u32) -> Vec<IpAddr> {
    std::fs::read_to_string(format!("/proc/{}/net/fib_trie", pid))
        .map(|b| parse_fib_trie_locals(&b))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_ipv4_and_ipv6_rows() {
        // Rows captured from a live host's /proc/net/tcp and tcp6.
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   974        0 6474936 1 0000000025139262 100 0 0 10 5\n";
        let s = parse_tcp_table(v4);
        assert_eq!(s[0].local, "127.0.0.54".parse::<IpAddr>().unwrap());
        assert_eq!(s[0].local_port, 53);
        assert_eq!(s[0].state, TCP_LISTEN);
        assert_eq!(s[0].inode, 6474936);
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31828 1 0000000005834871 100 0 0 10 0\n";
        let s = parse_tcp_table(v6);
        assert_eq!(s[0].local, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(s[0].local_port, 631);
    }

    #[test]
    fn v4_mapped_v6_is_normalised() {
        // ::ffff:10.0.10.118 as the kernel prints it.
        assert_eq!(parse_addr("0000000000000000FFFF0000760A000A"),
            Some("10.0.10.118".parse().unwrap()));
    }

    #[test]
    fn fib_trie_locals() {
        let body = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     +-- 10.0.10.0/24 2 0 2\n        |-- 10.0.10.0\n           /24 link UNICAST\n        |-- 10.0.10.118\n           /32 host LOCAL\n     |-- 127.0.0.1\n        /32 host LOCAL\n";
        assert_eq!(parse_fib_trie_locals(body), vec!["10.0.10.118".parse::<IpAddr>().unwrap()]);
    }
}
