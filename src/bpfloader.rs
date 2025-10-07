use std::os::fd::AsFd;
use std::path::PathBuf;

use libbpf_rs::{self, ProgramImpl};
use libbpf_rs::Xdp;
use nix::net::if_::*;


use crate::ids::Config;

pub fn load_bpf_program(path: &str, config : &Config) -> Result<PathBuf, anyhow::Error> {
    let mut builder = libbpf_rs::ObjectBuilder::default();
    builder.debug(true);
    let mut obj = builder.open_file(path)?.load()?;
    for prog in obj.progs_mut() {
        println!(
            "Loaded BPF program: {}",
            prog.name()
                .to_str()
                .unwrap_or_else(|| "<invalid utf-8>")
        );

        // Attach XDP program "packet_filter" to all interfaces specified in the config
        if prog.name() == "packet_filter" {
            for iface in &config.interfaces {
                let if_index = if_nametoindex(iface.as_str()).map_err(|e| {
                    anyhow::anyhow!("Failed to get index for interface {}: {}", iface, e)
                })? as i32;
                println!("Attaching XDP program to interface {} (index {})", iface, if_index);
                let xdp = Xdp::new(prog.as_fd());
                xdp.attach(if_index, libbpf_rs::XdpFlags::UPDATE_IF_NOEXIST)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to attach XDP program to interface {}: {}",
                            iface,
                            e
                        )
                    })?;
                return Ok(PathBuf::from(path));
            }
        }
    }
    Err(anyhow::anyhow!("No XDP program named 'packet_filter' found"))
}

pub fn detach_bpf_program(config: &Config, path: &str) -> Result<(), anyhow::Error> {
    let mut builder = libbpf_rs::ObjectBuilder::default();
    let mut obj = builder.open_file(path)?.load()?;
    for prog in obj.progs_mut() {
        if prog.name() == "packet_filter" {
            for iface in &config.interfaces {
                let if_index = if_nametoindex(iface.as_str()).map_err(|e| {
                    anyhow::anyhow!("Failed to get index for interface {}: {}", iface, e)
                })? as i32;
                println!("Detaching XDP program from interface {} (index {})", iface, if_index);
                let xdp = Xdp::new(prog.as_fd());
                xdp.detach(if_index, libbpf_rs::XdpFlags::UPDATE_IF_NOEXIST)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to detach XDP program from interface {}: {}",
                            iface,
                            e
                        )
                    })?;
            }
            return Ok(());
        }
    }
    Err(anyhow::anyhow!("No XDP program named 'packet_filter' found"))
}