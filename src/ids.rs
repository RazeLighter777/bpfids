use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum IdsAction {
    XdpDrop,
    XdpPass,
    Alert,
    Log,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub(crate) enum IdsMatch {
    SourceHost(IpAddr),
    DestinationHost(IpAddr),
    SourceNet(IpAddr, u8),
    DestinationNet(IpAddr, u8),
    // TCP/UDP port (single or inclusive range). If end is None => single port.
    SourcePortTcp(u16, Option<u16>),
    DestinationPortTcp(u16, Option<u16>),
    SourcePortUdp(u16, Option<u16>),
    DestinationPortUdp(u16, Option<u16>),
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum IdsExpr {
    Match(IdsMatch),
    And(Box<IdsExpr>, Box<IdsExpr>),
    Or(Box<IdsExpr>, Box<IdsExpr>),
    Not(Box<IdsExpr>),
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct IdsRule {
    pub action: IdsAction,
    pub expr: IdsExpr,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Config {
    pub rules: Vec<IdsRule>,
}

use std::collections::HashSet;
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclDependency {
    EthHeader,
    IpHeader,
    Ipv6Header,
    TcpHeader,
    UdpHeader,
    TcpSrcPort,
    TcpDstPort,
    UdpSrcPort,
    UdpDstPort,
}

fn direct_dependencies(d: DeclDependency) -> Vec<DeclDependency> {
    match d {
        DeclDependency::EthHeader => vec![],
        DeclDependency::IpHeader => vec![DeclDependency::EthHeader],
        DeclDependency::Ipv6Header => vec![DeclDependency::EthHeader],
        DeclDependency::TcpHeader => vec![DeclDependency::EthHeader],
        DeclDependency::UdpHeader => vec![DeclDependency::EthHeader],
        DeclDependency::TcpSrcPort => vec![DeclDependency::TcpHeader],
        DeclDependency::TcpDstPort => vec![DeclDependency::TcpHeader],
        DeclDependency::UdpSrcPort => vec![DeclDependency::UdpHeader],
        DeclDependency::UdpDstPort => vec![DeclDependency::UdpHeader],
    }
}

// Topologically order dependencies (parents before dependents) using DFS
fn ordered_dependency_chain(root: DeclDependency) -> Vec<DeclDependency> {
    fn dfs(d: DeclDependency, out: &mut Vec<DeclDependency>, seen: &mut HashSet<DeclDependency>) {
        if seen.contains(&d) { return; }
        for dep in direct_dependencies(d).into_iter() { dfs(dep, out, seen); }
        if !seen.contains(&d) { out.push(d); seen.insert(d); }
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    dfs(root, &mut out, &mut seen);
    out
}

impl DeclDependency {
    pub fn to_c_code(&self) -> &'static str {
        match self {
            DeclDependency::EthHeader => "if (fctx.eth == NULL) { fctx.eth = parse_ethhdr(data, data_end); }",
            DeclDependency::IpHeader => "if (fctx.ip == NULL && fctx.eth != NULL) { fctx.ip = parse_iphdr(fctx.eth, data_end); if (fctx.ip) { fctx.src_ip = extract_src_ipv4(fctx.ip); fctx.dst_ip = extract_dst_ipv4(fctx.ip); } }",
            DeclDependency::Ipv6Header => "if (fctx.ip6 == NULL && fctx.eth != NULL) { fctx.ip6 = parse_ipv6hdr(fctx.eth, data_end); if (fctx.ip6) { fctx.src_ip6 = extract_src_ipv6(fctx.ip6); fctx.dst_ip6 = extract_dst_ipv6(fctx.ip6); } }",
            DeclDependency::TcpHeader => "if (fctx.tcp == NULL && fctx.eth != NULL) { fctx.tcp = parse_tcphdr(fctx.eth, data_end); }",
            DeclDependency::UdpHeader => "if (fctx.udp == NULL && fctx.eth != NULL) { fctx.udp = parse_udphdr(fctx.eth, data_end); }",
            DeclDependency::TcpSrcPort => "if (fctx.tcp != NULL) { fctx.tcp_src_port = extract_tcp_src_port(fctx.tcp); }",
            DeclDependency::TcpDstPort => "if (fctx.tcp != NULL) { fctx.tcp_dst_port = extract_tcp_dst_port(fctx.tcp); }",
            DeclDependency::UdpSrcPort => "if (fctx.udp != NULL) { fctx.udp_src_port = extract_udp_src_port(fctx.udp); }",
            DeclDependency::UdpDstPort => "if (fctx.udp != NULL) { fctx.udp_dst_port = extract_udp_dst_port(fctx.udp); }",
        }
    }

    pub fn from_ids_match(m: &IdsMatch) -> Vec<DeclDependency> {
        match m {
            IdsMatch::SourceHost(IpAddr::V4(_)) | IdsMatch::DestinationHost(IpAddr::V4(_)) |
            IdsMatch::SourceNet(IpAddr::V4(_), _) | IdsMatch::DestinationNet(IpAddr::V4(_), _) => vec![DeclDependency::IpHeader],
            IdsMatch::SourceHost(IpAddr::V6(_)) | IdsMatch::DestinationHost(IpAddr::V6(_)) |
            IdsMatch::SourceNet(IpAddr::V6(_), _) | IdsMatch::DestinationNet(IpAddr::V6(_), _) => vec![DeclDependency::Ipv6Header],
            IdsMatch::SourcePortTcp(_, _) => vec![DeclDependency::TcpSrcPort],
            IdsMatch::DestinationPortTcp(_, _) => vec![DeclDependency::TcpDstPort],
            IdsMatch::SourcePortUdp(_, _) => vec![DeclDependency::UdpSrcPort],
            IdsMatch::DestinationPortUdp(_, _) => vec![DeclDependency::UdpDstPort],
        }
    }
}

impl IdsExpr {
    // Generate C code with lazy dependency evaluation
    pub fn to_c_lazy(&self, emitted_deps: &mut HashSet<DeclDependency>) -> (String, String) {
        match self {
            IdsExpr::Match(m) => {
                let mut dep_code = String::new();
                // Emit dependencies for this match if not already emitted
                for base in DeclDependency::from_ids_match(m) {
                    for dep in ordered_dependency_chain(base).into_iter() {
                        if !emitted_deps.contains(&dep) {
                            emitted_deps.insert(dep);
                            dep_code.push_str(dep.to_c_code());
                            dep_code.push_str("\n");
                        }
                    }
                }
                (dep_code, m.to_c())
            }
            IdsExpr::And(l, r) => {
                let (ldep, lcond) = l.to_c_lazy(emitted_deps);
                let (rdep, rcond) = r.to_c_lazy(emitted_deps);
                (format!("{}{}", ldep, rdep), format!("({})&&({})", lcond, rcond))
            }
            IdsExpr::Or(l, r) => {
                let (ldep, lcond) = l.to_c_lazy(emitted_deps);
                let (rdep, rcond) = r.to_c_lazy(emitted_deps);
                (format!("{}{}", ldep, rdep), format!("({})||({})", lcond, rcond))
            }
            IdsExpr::Not(x) => {
                let (dep, cond) = x.to_c_lazy(emitted_deps);
                (dep, format!("!({})", cond))
            }
        }
    }
}

impl IdsRule {
    pub fn to_c_lazy(&self, rule_num: u32, global_emitted_deps: &mut HashSet<DeclDependency>) -> String {
        let (dep_code, expr_c) = self.expr.to_c_lazy(global_emitted_deps);
        let rule_description = format!("{:?}", self.expr).replace("\"", "\\\"");
        let action_c = match self.action {
            IdsAction::XdpDrop => format!("rule_hit({}); return XDP_DROP;", rule_num),
            IdsAction::XdpPass => format!("rule_hit({}); return XDP_PASS;", rule_num),
            IdsAction::Alert => format!(
                "bpf_printk(\"ALERT: Rule matched - {}\\n\"); rule_hit({}); return XDP_PASS;",
                rule_description, rule_num
            ),
            IdsAction::Log => format!(
                "bpf_printk(\"LOG: Rule matched - {}\\n\"); rule_hit({}); return XDP_PASS;",
                rule_description, rule_num
            ),
        };
        format!("{}if ({}) {{ {} }}", dep_code, expr_c, action_c)
    }
}

impl Config {
    pub fn to_c_memoized(&self) -> String {
        let mut global_emitted_deps = HashSet::new();
        let mut out = String::new();
        
        for (i, r) in self.rules.iter().enumerate() {
            let rule_line = r.to_c_lazy(i as u32, &mut global_emitted_deps);
            out.push_str(&format!("// Rule: {:?}\n{}\n", r, rule_line));
        }
        out
    }
}

impl IdsMatch {
    fn ipv6_to_in6_addr(ipv6: &std::net::Ipv6Addr) -> String {
        // Produce a byte-accurate initializer so memcmp matches wire/network order
        let o = ipv6.octets();
        let bytes: Vec<String> = o.iter().map(|b| format!("0x{:02x}", b)).collect();
        // Need to escape literal braces for format! macro
        format!(
            "(struct in6_addr){{ .s6_addr = {{ {} }} }}",
            bytes.join(", ")
        )
    }
    fn ipv6_to_in6_addr_masked(ipv6: &std::net::Ipv6Addr, prefix: u8) -> String {
        // Mask after the prefix bits, zero remaining bits. Work at byte granularity.
        let mut o = ipv6.octets();
        if prefix < 128 {
            let full_bytes = (prefix / 8) as usize;
            let rem_bits = prefix % 8;
            if rem_bits != 0 {
                // Keep high rem_bits of the next byte
                let mask: u8 = 0xFF << (8 - rem_bits);
                o[full_bytes] &= mask;
                for b in &mut o[full_bytes + 1..] {
                    *b = 0;
                }
            } else {
                for b in &mut o[full_bytes..] {
                    *b = 0;
                }
            }
        }
        let bytes: Vec<String> = o.iter().map(|b| format!("0x{:02x}", b)).collect();
        format!(
            "(struct in6_addr){{ .s6_addr = {{ {} }} }}",
            bytes.join(", ")
        )
    }

    pub fn to_c(&self) -> String {
        match self {
            // L4 port matches (ranges inclusive)
            IdsMatch::SourcePortTcp(start, end_opt) => {
                let port_check = match end_opt {
                    Some(end) => format!("fctx.tcp_src_port >= {} && fctx.tcp_src_port <= {}", start, end),
                    None => format!("fctx.tcp_src_port == {}", start),
                };
                format!("(fctx.tcp != NULL && {})", port_check)
            }
            IdsMatch::DestinationPortTcp(start, end_opt) => {
                let port_check = match end_opt {
                    Some(end) => format!("fctx.tcp_dst_port >= {} && fctx.tcp_dst_port <= {}", start, end),
                    None => format!("fctx.tcp_dst_port == {}", start),
                };
                format!("(fctx.tcp != NULL && {})", port_check)
            }
            IdsMatch::SourcePortUdp(start, end_opt) => {
                let port_check = match end_opt {
                    Some(end) => format!("fctx.udp_src_port >= {} && fctx.udp_src_port <= {}", start, end),
                    None => format!("fctx.udp_src_port == {}", start),
                };
                format!("(fctx.udp != NULL && {})", port_check)
            }
            IdsMatch::DestinationPortUdp(start, end_opt) => {
                let port_check = match end_opt {
                    Some(end) => format!("fctx.udp_dst_port >= {} && fctx.udp_dst_port <= {}", start, end),
                    None => format!("fctx.udp_dst_port == {}", start),
                };
                format!("(fctx.udp != NULL && {})", port_check)
            }
            // IPv6 network matches need special handling
            IdsMatch::SourceNet(IpAddr::V6(ipv6), prefix) => {
                let masked_addr = Self::ipv6_to_in6_addr_masked(ipv6, *prefix);
                format!(
                    "({{ struct in6_addr tmp1 = apply_ipv6_netmask(&fctx.src_ip6, {}); struct in6_addr tmp2 = {}; __builtin_memcmp((const void*)&tmp1, (const void*)&tmp2, 16) == 0; }})",
                    prefix, masked_addr
                )
            }
            IdsMatch::DestinationNet(IpAddr::V6(ipv6), prefix) => {
                let masked_addr = Self::ipv6_to_in6_addr_masked(ipv6, *prefix);
                format!(
                    "({{ struct in6_addr tmp1 = apply_ipv6_netmask(&fctx.dst_ip6, {}); struct in6_addr tmp2 = {}; __builtin_memcmp((const void*)&tmp1, (const void*)&tmp2, 16) == 0; }})",
                    prefix, masked_addr
                )
            }
            // All other matches use common logic
            _ => {
                match self {
                    IdsMatch::SourceHost(IpAddr::V4(ip)) => {
                        format!("fctx.src_ip == 0x{:08x}", (u32::from(*ip)).to_le())
                    }
                    IdsMatch::DestinationHost(IpAddr::V4(ip)) => {
                        format!("fctx.dst_ip == 0x{:08x}", (u32::from(*ip)).to_le())
                    }
                    IdsMatch::SourceNet(IpAddr::V4(ip), prefix) => {
                        format!("(fctx.src_ip & {}) == 0x{:08x}", 
                               u32::MAX << (32 - prefix),
                               ((u32::from(*ip) & (u32::MAX << (32 - prefix))).to_le()))
                    }
                    IdsMatch::DestinationNet(IpAddr::V4(ip), prefix) => {
                        format!("(fctx.dst_ip & {}) == 0x{:08x}", 
                               u32::MAX << (32 - prefix),
                               ((u32::from(*ip) & (u32::MAX << (32 - prefix))).to_le()))
                    }
                    IdsMatch::SourceHost(IpAddr::V6(ipv6)) => {
                        format!("__builtin_memcmp((const void*)&fctx.src_ip6, (const void*)&{}, 16) == 0", 
                               Self::ipv6_to_in6_addr(ipv6))
                    }
                    IdsMatch::DestinationHost(IpAddr::V6(ipv6)) => {
                        format!("__builtin_memcmp((const void*)&fctx.dst_ip6, (const void*)&{}, 16) == 0", 
                               Self::ipv6_to_in6_addr(ipv6))
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}
