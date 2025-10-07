use clap::Id;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use crate::iplist;
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) enum PortSpec {
    Range(u16, u16), // start, end (inclusive)
    List(Vec<u16>),  // list of specific ports
}

impl PortSpec {
    pub fn to_c_condition(&self, port_var: &str) -> String {
        match self {
            PortSpec::Range(start, end) => {
                if start == end {
                    format!("{} == {}", port_var, start)
                } else {
                    format!("{} >= {} && {} <= {}", port_var, start, port_var, end)
                }
            }
            PortSpec::List(ports) => {
                if ports.len() == 1 {
                    format!("{} == {}", port_var, ports[0])
                } else {
                    let conditions: Vec<String> = ports.iter()
                        .map(|port| format!("{} == {}", port_var, port))
                        .collect();
                    format!("({})", conditions.join(" || "))
                }
            }
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        match self {
            PortSpec::Range(start, end) => {
                if start > end {
                    Err("Port range start must be less than or equal to end".to_string())
                } else {
                    Ok(())
                }
            }
            PortSpec::List(ports) => {
                //disallow duplicates
                let mut seen = std::collections::HashSet::new();
                for port in ports {
                    if !seen.insert(port) {
                        return Err(format!("Duplicate port {} in port list", port));
                    }
                }   
                Ok(())
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum IdsAction {
    SilentlyDrop,
    Pass,
    AlertButStillPass,
    LogButStillPass,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) enum IdsMatch {
    IpListSourceAddress(String),
    IpListDestinationAddress(String),
    SourceHost(IpAddr),
    DestinationHost(IpAddr),
    SourceNet(IpAddr, u8),
    DestinationNet(IpAddr, u8),
    // TCP/UDP port specifications
    SourcePortTcp(PortSpec),
    DestinationPortTcp(PortSpec),
    SourcePortUdp(PortSpec),
    DestinationPortUdp(PortSpec),
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
    #[serde(default)]
    pub ip_lists: Vec<iplist::IpList>,
    #[serde(default)]
    pub rules: Vec<IdsRule>,
    #[serde(default)]
    pub interfaces: Vec<String>,
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
            IdsMatch::SourcePortTcp(_) => vec![DeclDependency::TcpSrcPort],
            IdsMatch::DestinationPortTcp(_) => vec![DeclDependency::TcpDstPort],
            IdsMatch::SourcePortUdp(_) => vec![DeclDependency::UdpSrcPort],
            IdsMatch::DestinationPortUdp(_) => vec![DeclDependency::UdpDstPort],
            IdsMatch::IpListSourceAddress(_) | IdsMatch::IpListDestinationAddress(_) => vec![DeclDependency::IpHeader, DeclDependency::Ipv6Header],
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

    pub fn validate(&self) -> Result<(), String> {
        match self {
            IdsExpr::Match(m) => m.validate(),
            IdsExpr::And(l, r) | IdsExpr::Or(l, r) => {
                l.validate()?;
                r.validate()
            },
            //disallow double negation
            IdsExpr::Not(inner) => match inner.as_ref() {
                IdsExpr::Not(_) => Err("Double negation is not allowed".to_string()),
                _ => inner.validate(),
            },
        }
    }
}

impl IdsRule {
    pub fn to_c_lazy(&self, rule_num: u32, global_emitted_deps: &mut HashSet<DeclDependency>) -> String {
        let (dep_code, expr_c) = self.expr.to_c_lazy(global_emitted_deps);
        let rule_description = format!("{:?}", self.expr).replace("\"", "\\\"");
        let action_c = match self.action {
            IdsAction::SilentlyDrop => format!("rule_hit({}); return XDP_DROP;", rule_num),
            IdsAction::Pass => format!("rule_hit({}); return XDP_PASS;", rule_num),
            IdsAction::AlertButStillPass => format!(
                "bpf_printk(\"ALERT: Rule matched - {}\\n\"); rule_hit({}); return XDP_PASS;",
                rule_description, rule_num
            ),
            IdsAction::LogButStillPass => format!(
                "bpf_printk(\"LOG: Rule matched - {}\\n\"); rule_hit({}); return XDP_PASS;",
                rule_description, rule_num
            ),
        };
        format!("{}if ({}) {{ {} }}", dep_code, expr_c, action_c)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.expr.validate()
    }
}

impl Config {
    pub fn to_c_memoized(&self) -> String {
        let mut global_emitted_deps = HashSet::new();
        let mut out = String::new();
        
        for ip_list in &self.ip_lists {
            out.push_str(&ip_list.get_c_bpf_trie_repr());
            out.push_str("\n");
        }
        out.push_str("const static int evaluate_rules(struct filter_context fctx, void *data, void* data_end) {\n");
        for (i, r) in self.rules.iter().enumerate() {
            let rule_line = r.to_c_lazy(i as u32, &mut global_emitted_deps);
            out.push_str(&format!("// Rule: {:?}\n{}\n", r, rule_line));
        }
        out.push_str("return XDP_PASS;\n");
        out.push_str("}\n");
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

    fn ip_list_lookup_condition(list_name: &str, ipv4_data_expr: &str, ipv6_data_expr: &str) -> String {
        format!(
            "({{ int found = 0; if (fctx.ip != NULL) {{ \
                struct ipv4_lpm_key key = {{ .prefixlen = 32, .data = {ipv4_data} }}; \
                void *val = bpf_map_lookup_elem(&{name}_ipv4, &key); \
                if (val != NULL) {{ found = 1; }} \
            }} else if (fctx.ip6 != NULL) {{ \
                struct ipv6_lpm_key key = {{ .prefixlen = 128, .data = {ipv6_data} }}; \
                void *val = bpf_map_lookup_elem(&{name}_ipv6, &key); \
                if (val != NULL) {{ found = 1; }} \
            }} found; }})",
            name = list_name,
            ipv4_data = ipv4_data_expr,
            ipv6_data = ipv6_data_expr,
        )
    }

    pub fn to_c(&self) -> String {
        match self {
            // L4 port matches using PortSpec
            IdsMatch::SourcePortTcp(port_spec) => {
                let port_check = port_spec.to_c_condition("fctx.tcp_src_port");
                format!("(fctx.tcp != NULL && {})", port_check)
            }
            IdsMatch::DestinationPortTcp(port_spec) => {
                let port_check = port_spec.to_c_condition("fctx.tcp_dst_port");
                format!("(fctx.tcp != NULL && {})", port_check)
            }
            IdsMatch::SourcePortUdp(port_spec) => {
                let port_check = port_spec.to_c_condition("fctx.udp_src_port");
                format!("(fctx.udp != NULL && {})", port_check)
            }
            IdsMatch::DestinationPortUdp(port_spec) => {
                let port_check = port_spec.to_c_condition("fctx.udp_dst_port");
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
                    IdsMatch::IpListSourceAddress(list_name) => {
                        Self::ip_list_lookup_condition(list_name.as_str(), "bpf_htonl(fctx.src_ip)", "fctx.src_ip6")
                    }
                    IdsMatch::IpListDestinationAddress(list_name) => {
                        Self::ip_list_lookup_condition(list_name.as_str(), "bpf_htonl(fctx.dst_ip)", "fctx.dst_ip6")
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            IdsMatch::SourceNet(_, prefix) | IdsMatch::DestinationNet(_, prefix) => {
                match self {
                    IdsMatch::SourceNet(IpAddr::V4(_), p) | IdsMatch::DestinationNet(IpAddr::V4(_), p) 
                        if *p > 32 => Err("IPv4 prefix cannot exceed 32".to_string()),
                    IdsMatch::SourceNet(IpAddr::V6(_), p) | IdsMatch::DestinationNet(IpAddr::V6(_), p) 
                        if *p > 128 => Err("IPv6 prefix cannot exceed 128".to_string()),
                    _ => Ok(())
                }
            }
            IdsMatch::SourcePortTcp(ps) | IdsMatch::DestinationPortTcp(ps) |
            IdsMatch::SourcePortUdp(ps) | IdsMatch::DestinationPortUdp(ps) => {
                ps.validate()
            }
            _ => Ok(())
        }
    }
}
