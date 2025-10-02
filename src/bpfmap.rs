use libbpf_rs::{MapCore, MapFlags, MapHandle};
use std::path::Path;
/*
struct rule_counters {
    struct bpf_timer timer;      /* MUST be first field */ /*struct bpf_timer { __u64 :64; __u64 :64; };*/
    __u64 total;                 /* Monotonic total hits */
    __u64 snap_1s;               /* Total value captured >=1s ago */
    __u64 snap_60s;              /* Captured >=60s ago */
    __u64 snap_3600s;            /* Captured >=3600s ago */
    __u64 snap_86400s;           /* Captured >=86400s ago */
    __u64 ts_1s;                 /* Last time snap_1s updated */
    __u64 ts_60s;                /* Last time snap_60s updated */
    __u64 ts_3600s;              /* Last time snap_3600s updated */
    __u64 ts_86400s;             /* Last time snap_86400s updated */
    __u8  initialized;           /* One-time timer init guard */
};
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct rule_counters);
        __uint(max_entries, 1024);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_counters_map SEC(".maps");
*/
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Timer  {
    pub _reserved: u64,
    pub expires: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuleCounters {
    pub timer: Timer,
    pub total: u64,
    pub snap_1s: u64,
    pub snap_60s: u64,
    pub snap_3600s: u64,
    pub snap_86400s: u64,
    pub ts_1s: u64,
    pub ts_60s: u64,
    pub ts_3600s: u64,
    pub ts_86400s: u64,
    pub initialized: u8,
}

pub fn open_bpf_map<P: AsRef<Path>>(path: P, map_name: &str) -> Result<MapHandle, Box<dyn std::error::Error>> {
    let map = libbpf_rs::MapHandle::from_pinned_path(path)?;
    // map type should be array.
    if map.map_type() != libbpf_rs::MapType::Array {
        return Err(format!("Map {} is not of type Array", map_name).into());
    }
    // key size should be 4 bytes (u32)
    if map.key_size() != std::mem::size_of::<u32>() as u32 {
        return Err(format!("Map {} has unexpected key size: {}", map_name, map.key_size()).into());
    }
    // value size should be size of RuleCounters
    if map.value_size() != std::mem::size_of::<RuleCounters>() as u32 {
        return Err(format!("Map {} has unexpected value size: {}", map_name, map.value_size()).into());
    }
    Ok(map)
}

pub fn get_rule_counters(map: &MapHandle, rule_id: u32) -> Result<RuleCounters, Box<dyn std::error::Error>> {
    let key = rule_id.to_ne_bytes();
    let value = map.lookup(&key, MapFlags::empty())?.ok_or("Key not found in map")?;
    if value.len() != std::mem::size_of::<RuleCounters>() {
        return Err(format!("Unexpected value size: {}", value.len()).into());
    }
    let counters: RuleCounters = unsafe { std::ptr::read(value.as_ptr() as *const _) };
    Ok(counters)
}