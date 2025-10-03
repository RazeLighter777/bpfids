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

use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Default)]
pub(crate) struct MemoTable {
    next: usize,
    vars: HashMap<IdsMatch, String>,
    inits: Vec<(String, String)>, // (var, code)
}

impl MemoTable {
    fn var_for(&mut self, m: IdsMatch) -> String {
        if let Some(v) = self.vars.get(&m) {
            return v.clone();
        }
        let name = format!("mm{}", self.next);
        self.next += 1;
        let code = format!("const int {} = ({});", name, m.to_c());
        self.vars.insert(m, name.clone());
        self.inits.push((name.clone(), code));
        name
    }
    pub fn emit_decls(&self) -> String {
        self.inits
            .iter()
            .map(|(_, c)| c.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl IdsExpr {
    // New variant that memoizes across calls via shared RefCell<MemoTable>
    pub fn to_c_with_memo(&self, memo: &RefCell<MemoTable>) -> String {
        match self {
            IdsExpr::Match(m) => memo.borrow_mut().var_for(*m),
            IdsExpr::And(l, r) => {
                format!("({})&&({})", l.to_c_with_memo(memo), r.to_c_with_memo(memo))
            }
            IdsExpr::Or(l, r) => {
                format!("({})||({})", l.to_c_with_memo(memo), r.to_c_with_memo(memo))
            }
            IdsExpr::Not(x) => format!("!({})", x.to_c_with_memo(memo)),
        }
    }
}

impl IdsRule {
    pub fn to_c_with_memo(&self, memo: &RefCell<MemoTable>, rule_num: u32) -> String {
        let expr_c = self.expr.to_c_with_memo(memo);
        let rule_description = format!("{:?}", self.expr).replace("\"", "\\\"");
        let action_c = match self.action {
            IdsAction::XdpDrop => format!("rule_hit({}); return XDP_DROP;", rule_num,),
            IdsAction::XdpPass => format!("rule_hit({}); return XDP_PASS;", rule_num,),
            IdsAction::Alert => format!(
                "bpf_printk(\"ALERT: Rule matched - {}\\n\"); rule_hit({}); return XDP_PASS;",
                rule_description, rule_num,
            ),
            IdsAction::Log => format!(
                "bpf_printk(\"LOG: Rule matched - {}\\n\"); rule_hit({}); return XDP_PASS;",
                rule_description, rule_num
            ),
        };
        format!("if ({}) {{ {} }}", expr_c, action_c)
    }
}

impl Config {
    pub fn to_c_memoized(&self) -> String {
        let memo = RefCell::new(MemoTable::default());
        let mut out = String::new();
        // Build rule code first so memo table fills in deterministic encounter order
        let mut rule_lines: Vec<String> = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            rule_lines.push(r.to_c_with_memo(&memo, i as u32));
        }
        let decls = memo.borrow().emit_decls();
        if !decls.is_empty() {
            out.push_str("// Memoized match computations (once per packet)\n");
            out.push_str(&decls);
            out.push('\n');
        }
        for (r, line) in self.rules.iter().zip(rule_lines.iter()) {
            out.push_str(&format!("// Rule: {:?}\n{}\n", r, line));
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
                match end_opt {
                    Some(end) => format!("(fctx.is_tcp && fctx.src_port >= {} && fctx.src_port <= {})", start, end),
                    None => format!("(fctx.is_tcp && fctx.src_port == {})", start),
                }
            }
            IdsMatch::DestinationPortTcp(start, end_opt) => {
                match end_opt {
                    Some(end) => format!("(fctx.is_tcp && fctx.dst_port >= {} && fctx.dst_port <= {})", start, end),
                    None => format!("(fctx.is_tcp && fctx.dst_port == {})", start),
                }
            }
            IdsMatch::SourcePortUdp(start, end_opt) => {
                match end_opt {
                    Some(end) => format!("(fctx.is_udp && fctx.src_port >= {} && fctx.src_port <= {})", start, end),
                    None => format!("(fctx.is_udp && fctx.src_port == {})", start),
                }
            }
            IdsMatch::DestinationPortUdp(start, end_opt) => {
                match end_opt {
                    Some(end) => format!("(fctx.is_udp && fctx.dst_port >= {} && fctx.dst_port <= {})", start, end),
                    None => format!("(fctx.is_udp && fctx.dst_port == {})", start),
                }
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
            // All other matches use the original logic
            _ => {
                // Remember the IP addresses are in network byte order
                let memcmp_arg1 = match self {
                    IdsMatch::SourceHost(IpAddr::V4(_)) => format!("fctx.src_ip"),
                    IdsMatch::DestinationHost(IpAddr::V4(_)) => format!("fctx.dst_ip"),
                    // netmask is opposite because endianess
                    IdsMatch::SourceNet(IpAddr::V4(_), prefix) => {
                        format!("(fctx.src_ip & {})", u32::MAX << (32 - prefix))
                    }
                    IdsMatch::DestinationNet(IpAddr::V4(_), prefix) => {
                        format!("(fctx.dst_ip & {})", u32::MAX << (32 - prefix))
                    }
                    IdsMatch::SourceHost(IpAddr::V6(_)) => format!("fctx.src_ip6"),
                    IdsMatch::DestinationHost(IpAddr::V6(_)) => format!("fctx.dst_ip6"),
                    // These cases are handled above
                    IdsMatch::SourceNet(IpAddr::V6(_), _) => unreachable!(),
                    IdsMatch::DestinationNet(IpAddr::V6(_), _) => unreachable!(),
                    // Port variants handled earlier
                    IdsMatch::SourcePortTcp(_, _) => unreachable!(),
                    IdsMatch::DestinationPortTcp(_, _) => unreachable!(),
                    IdsMatch::SourcePortUdp(_, _) => unreachable!(),
                    IdsMatch::DestinationPortUdp(_, _) => unreachable!(),
                };
                let memcmp_arg2 = match self {
                    IdsMatch::SourceHost(IpAddr::V4(ip)) => {
                        format!("0x{:08x}", (u32::from(*ip)).to_le())
                    }
                    IdsMatch::DestinationHost(IpAddr::V4(ip)) => {
                        format!("0x{:08x}", (u32::from(*ip)).to_le())
                    }
                    IdsMatch::SourceNet(IpAddr::V4(ip), l) => format!(
                        "0x{:08x}",
                        ((u32::from(*ip) & (u32::MAX << (32 - l))).to_le())
                    ),
                    IdsMatch::DestinationNet(IpAddr::V4(ip), l) => format!(
                        "0x{:08x}",
                        ((u32::from(*ip) & (u32::MAX << (32 - l))).to_le())
                    ),
                    IdsMatch::SourceHost(IpAddr::V6(ipv6)) => Self::ipv6_to_in6_addr(ipv6),
                    IdsMatch::DestinationHost(IpAddr::V6(ipv6)) => Self::ipv6_to_in6_addr(ipv6),
                    // These cases are handled above
                    IdsMatch::SourceNet(IpAddr::V6(_), _) => unreachable!(),
                    IdsMatch::DestinationNet(IpAddr::V6(_), _) => unreachable!(),
                    IdsMatch::SourcePortTcp(_, _) => unreachable!(),
                    IdsMatch::DestinationPortTcp(_, _) => unreachable!(),
                    IdsMatch::SourcePortUdp(_, _) => unreachable!(),
                    IdsMatch::DestinationPortUdp(_, _) => unreachable!(),
                };
                let use_eq_not_memcmp = match self {
                    IdsMatch::SourceHost(IpAddr::V4(_)) => true,
                    IdsMatch::DestinationHost(IpAddr::V4(_)) => true,
                    IdsMatch::SourceNet(IpAddr::V4(_), _) => true,
                    IdsMatch::DestinationNet(IpAddr::V4(_), _) => true,
                    _ => false, // for ipv6 we always use memcmp
                };
                if use_eq_not_memcmp {
                    format!("({} == {})", memcmp_arg1, memcmp_arg2)
                } else {
                    format!(
                        "(__builtin_memcmp((const void*)&{}, (const void*)&{}, {}) == 0)",
                        memcmp_arg1, memcmp_arg2, 16
                    )
                }
            }
        }
    }
}
