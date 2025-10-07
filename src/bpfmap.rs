use libbpf_rs::{MapCore, MapFlags, MapHandle};
use std::path::Path;
use crate::bpfbindings::rule_counters;
pub fn open_bpf_map<P: AsRef<Path>>(
    path: P,
    map_name: &str,
) -> Result<MapHandle, Box<dyn std::error::Error>> {
    let map = libbpf_rs::MapHandle::from_pinned_path(path)?;
    // map type should be array.
    if map.map_type() != libbpf_rs::MapType::Array {
        return Err(format!("Map {} is not of type Array", map_name).into());
    }
    // key size should be 4 bytes (u32)
    if map.key_size() != std::mem::size_of::<u32>() as u32 {
        return Err(format!(
            "Map {} has unexpected key size: {}",
            map_name,
            map.key_size()
        )
        .into());
    }
    // value size should be size of RuleCounters
    if map.value_size() != std::mem::size_of::<rule_counters>() as u32 {
        return Err(format!(
            "Map {} has unexpected value size: {}",
            map_name,
            map.value_size()
        )
        .into());
    }
    Ok(map)
}

pub fn get_rule_counters(
    map: &MapHandle,
    rule_id: u32,
) -> Result<rule_counters, Box<dyn std::error::Error>> {
    let key = rule_id.to_ne_bytes();
    let value = map
        .lookup(&key, MapFlags::empty())?
        .ok_or("Key not found in map")?;
    if value.len() != std::mem::size_of::<rule_counters>() {
        return Err(format!("Unexpected value size: {}", value.len()).into());
    }
    let counters: rule_counters = unsafe { std::ptr::read(value.as_ptr() as *const _) };
    Ok(counters)
}

pub fn compute_rulecounters_last_intervals_string(counter: &rule_counters) -> String {
    format!(
        "(last 1s: {}, last 1min: {}, last 1h: {}, last 1d: {})",
        counter.total - counter.snap_1s,
        counter.total - counter.snap_60s,
        counter.total - counter.snap_3600s,
        counter.total - counter.snap_86400s
    )
}
