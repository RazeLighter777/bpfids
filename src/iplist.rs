use std::net::IpAddr;
use std::net::Ipv4Addr;

use cidr::AnyIpCidr;
use libbpf_rs::MapCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use libbpf_rs::{MapHandle, MapType};
use crate::bpfbindings::ipv4_lpm_key;
use crate::bpfbindings::ipv6_lpm_key;
#[derive(Error, Debug)]
pub enum IpListError {
    #[error("Invalid IP list name: {0}")]
    InvalidName(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("No Any allowed in CIDR")]
    NoAnyAllowedInCidr(),
    #[error("BPF error: {0}")]
    Bpf(#[from] libbpf_rs::Error),
    #[error("Map incorrect size")]
    MapIncorrectSize(),
    #[error("Map type mismatch")]
    MapTypeMismatch(),
}


#[derive(Deserialize, Serialize, Clone, Debug, Hash)]
pub struct IpList {
    name: String,
    #[serde(default)]
    ips: Vec<AnyIpCidr>,
    file : Option<String>,
}

impl IpList {
    fn new_from_file(name : String, path: &str)-> Result<Self, IpListError> {
        println!("Loading IP list from file: {}", path);
        //1st try json 
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(list) = serde_json::from_str::<IpList>(&content) {
                println!("Loaded IP list from json file: {:?}", list);
                return Ok(list);
            } 
            // next newline separated, ignore empty lines and comments starting with #
            let mut ips = Vec::new();
            for line in content.lines() {
                println!("Parsing line: {}", line);
                let line = line.trim();
                //remove comments
                let line = if let Some(pos) = line.find('#') {
                    &line[..pos]
                } else {
                    line
                };
                if line.is_empty() {
                    continue;   
                }
                if let Ok(cidr) = line.parse::<AnyIpCidr>() {
                    ips.push(cidr);
                }
            }
            if !ips.is_empty() {
                return Ok(IpList::new(&name, ips.into_iter())?);
            }
        }
        Err(IpListError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Failed to read IP list from {}", path),
        )))
    }
    fn cidr_to_map_handle(&self, cidr: &AnyIpCidr) -> Result<MapHandle, IpListError> {
        match cidr {
            AnyIpCidr::V4(_) => {
                MapHandle::from_pinned_path(self.get_trie_fs_path_v4()).map_err(|e| {
                    IpListError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "Failed to open IPv4 map at {}: {}. Is the map created?",
                            self.get_trie_fs_path_v4(),
                            e
                        ),
                    ))
                })
            }
            AnyIpCidr::V6(_) => {
                MapHandle::from_pinned_path(self.get_trie_fs_path_v6()).map_err(|e| {
                    IpListError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "Failed to open IPv6 map at {}: {}. Is the map created?",
                            self.get_trie_fs_path_v6(),
                            e
                        ),
                    ))
                })
            }
            AnyIpCidr::Any => Err(IpListError::NoAnyAllowedInCidr()),
        }
    }
    pub fn new(name: &str, ips: impl Iterator<Item = AnyIpCidr>) -> Result<Self, IpListError> {
        // name must be valid c identifier
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.chars().next().unwrap().is_ascii_digit()
        {
            return Err(IpListError::InvalidName(name.to_string()));
        }
        let ips: Vec<AnyIpCidr> = ips.collect();
        //check for AnyIpCidr::Any
        for cidr in &ips {
            if let AnyIpCidr::Any = cidr {
                return Err(IpListError::NoAnyAllowedInCidr());
            }
        }
        Ok(IpList {
            name: name.to_string(),
            ips,
            file: None,
        })
    }
    pub fn get_name(&self) -> &str {
        &self.name
    }
    /*
example output:
//already in code
struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};
struct ipv6_lpm_key {
        __u32 prefixlen;
        struct in6_addr data;
};
// this is returned with <map_name> replaced with the actual name of the iplist
struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} <map_name>_ipv4 SEC(".maps");
struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv6_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} <map_name>_ipv6 SEC(".maps");
    */
    pub fn get_c_bpf_trie_repr(&self) -> String {
        let mut ipv4_count = 1;
        let mut ipv6_count = 1;
        for cidr in &self.ips {
            match cidr {
                AnyIpCidr::V4(_) => ipv4_count += 1,
                AnyIpCidr::V6(_) => ipv6_count += 1,
                _ => unimplemented!(), // should be unreachable due to checks in new()
            }
        }
        // also load the file if set
        if let Some(ref path) = self.file {
            if let Ok(file_list) = IpList::new_from_file(self.name.clone(),path) {
                println!("Loaded {} entries from file {}", file_list.ips.len(), path);
                for cidr in &file_list.ips {
                    println!("Loaded IP from file: {:?}", cidr);
                    match cidr {
                        AnyIpCidr::V4(_) => ipv4_count += 1,
                        AnyIpCidr::V6(_) => ipv6_count += 1,
                        _ => unimplemented!(), // should be unreachable due to checks in new()
                    }
                }
            }
        }
        // quadruple the count to allow for future growth
        ipv4_count *= 4;
        ipv6_count *= 4;
        format!(
            r#"
struct {{
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, {ipv4_count});
        __uint(pinning, LIBBPF_PIN_BY_NAME);
}} {map_name}_ipv4 SEC(".maps");
struct {{
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv6_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(max_entries, {ipv6_count});
}} {map_name}_ipv6 SEC(".maps");
"#,
            map_name = self.name,
            ipv4_count = ipv4_count,
            ipv6_count = ipv6_count
        )
    }
    fn get_trie_fs_path_v4(&self) -> String {
        format!("/sys/fs/bpf/tc/globals/{}_ipv4", self.name)
    }
    fn get_trie_fs_path_v6(&self) -> String {
        format!("/sys/fs/bpf/tc/globals/{}_ipv6", self.name)
    }
    fn cidr_to_key_bytes(&self, cidr: &AnyIpCidr) -> Result<Vec<u8>, IpListError> {
        match cidr {
            AnyIpCidr::V4(cidr) => {
                let (ip, prefixlen) = (cidr.first_address(), cidr.network_length());
                let key = ipv4_lpm_key {
                    prefixlen: prefixlen as u32,
                    // convert to native-endian u32. Meaning first octet is bytes[0]
                    data: u32::from_ne_bytes(ip.octets())
                };
                println!("Inserting IPv4 key: {:?} with prefixlen {}", ip, key.prefixlen);
                Ok(unsafe {
                    std::slice::from_raw_parts(
                        &key as *const ipv4_lpm_key as *const u8,
                        std::mem::size_of::<ipv4_lpm_key>(),
                    )
                    .to_vec()
                })
            }
            AnyIpCidr::V6(cidr) => {
                let (ip, prefixlen) = (cidr.first_address(), cidr.network_length());
                let key = ipv6_lpm_key {
                    prefixlen: prefixlen as u32,
                    data: crate::bpfbindings::in6_addr { in6_u : crate::bpfbindings::in6_addr__bindgen_ty_1 {
                        u6_addr8: ip.octets(),
                    } },
                };
                Ok(unsafe {
                    std::slice::from_raw_parts(
                        &key as *const ipv6_lpm_key as *const u8,
                        std::mem::size_of::<ipv6_lpm_key>(),
                    )
                    .to_vec()
                })
            }
            AnyIpCidr::Any => Err(IpListError::NoAnyAllowedInCidr()),
        }
    }

    fn insert_entry(&self, cidr: &AnyIpCidr) -> Result<(), IpListError> {
        let map_handle = self.cidr_to_map_handle(cidr)?;
        let value_bytes = self.cidr_to_key_bytes(cidr)?;
        // insert value into the trie, value is always 1u32
        map_handle.update(&value_bytes, &1u32.to_ne_bytes(), libbpf_rs::MapFlags::empty())?;
        Ok(())
    }
    fn delete_entry(&self, cidr: &AnyIpCidr) -> Result<(), IpListError> {
        let map_handle = self.cidr_to_map_handle(cidr)?;
        let value_bytes = self.cidr_to_key_bytes(cidr)?;
        let lookup = map_handle.lookup(&value_bytes, libbpf_rs::MapFlags::empty())?;
        if lookup.is_none() {
            return Err(IpListError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Entry not found in map",
            )));
        }
        // delete value from the trie
        map_handle.delete(&value_bytes)?;
        Ok(())
    }
    pub fn apply(&self) -> Result<(), IpListError> {
        // read the file if set
        if let Some(ref path) = self.file {
            let file_list = IpList::new_from_file(self.name.clone(), path)?;
            for cidr in file_list.ips {
                self.insert_entry(&cidr)?;
            }
        }
        for cidr in &self.ips {
            self.insert_entry(cidr)?;
        }
        Ok(())
    }
    pub fn clear(&self) -> Result<(), IpListError> {
        for cidr in &self.ips {
            self.delete_entry(cidr)?;
        }
        Ok(())
    }
    pub fn read_loaded_ips(&self) -> Result<Vec<AnyIpCidr>, IpListError> {
        let mut result = Vec::new();
        let ipv4_map = MapHandle::from_pinned_path(self.get_trie_fs_path_v4())?;
        let ipv6_map = MapHandle::from_pinned_path(self.get_trie_fs_path_v6())?;
        if ipv4_map.map_type() != MapType::LpmTrie || ipv6_map.map_type() != MapType::LpmTrie {
            return Err(IpListError::MapTypeMismatch());
        }
        for v4key in ipv4_map.keys() {
            if v4key.len() != std::mem::size_of::<ipv4_lpm_key>() {
                return Err(IpListError::MapIncorrectSize());
            }
            let key: ipv4_lpm_key = unsafe { std::ptr::read(v4key.as_ptr() as *const _) };
            //TRIE stores in big-endian, despite being u32, so convert back
            let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(key.data)));
            println!("Found IPv4 key: {:?} with prefixlen {}", ip, key.prefixlen);
            let cidr = AnyIpCidr::V4(cidr::Ipv4Cidr::new(ip.to_string().parse().unwrap(), key.prefixlen as u8).unwrap());
            result.push(cidr);
        }
        for v6key in ipv6_map.keys() {
            if v6key.len() != std::mem::size_of::<ipv6_lpm_key>() {
                return Err(IpListError::MapIncorrectSize());
            }
            let key: ipv6_lpm_key = unsafe { std::ptr::read(v6key.as_ptr() as *const _) };
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(unsafe { key.data.in6_u.u6_addr8 }));
            let cidr = AnyIpCidr::V6(cidr::Ipv6Cidr::new(ip.to_string().parse().unwrap(), key.prefixlen as u8).unwrap());
            result.push(cidr);
        }
        Ok(result)
    }
}