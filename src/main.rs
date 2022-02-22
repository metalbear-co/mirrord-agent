use anyhow::{anyhow, Result};
use containerd_client::connect;
use containerd_client::with_namespace;
use nix;
use pnet::packet::ethernet::EthernetPacket;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{IntoRawFd, RawFd};

use containerd_client::services::v1::containers_client::ContainersClient;
use containerd_client::services::v1::GetContainerRequest;
use serde::{Deserialize, Serialize};
use tonic::Request;

use pcap::{Capture, Device, Linktype};

use std::hash::{Hash, Hasher};
mod api;
mod cli;
use api::*;
use cli::parse_args;

const CONTAINERD_SOCK_PATH: &str = "/run/containerd/containerd.sock";
const DEFAULT_CONTAINERD_NAMESPACE: &str = "k8s.io";
const DEFAULT_INTERFACE_NAME: &str = "eth0";

#[derive(Serialize, Deserialize, Debug)]
struct Namespace {
    #[serde(rename = "type")]
    ns_type: String,
    path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct LinuxInfo {
    namespaces: Vec<Namespace>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Spec {
    linux: LinuxInfo,
}

#[derive(Debug, Eq, Copy, Clone)]
pub struct TCPSession {
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    connection_id: ConnectionID,
}

impl PartialEq for TCPSession {
    /// It's the same session if 4 tuple is same/opposite.
    fn eq(&self, other: &TCPSession) -> bool {
        self.source_addr == other.source_addr
            && self.dest_addr == other.dest_addr
            && self.source_port == other.source_port
            && self.dest_port == other.dest_port
            || self.source_addr == other.dest_addr
                && self.dest_addr == other.source_addr
                && self.source_port == other.dest_port
                && self.dest_port == other.source_port
    }
}

impl Hash for TCPSession {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.source_addr > self.dest_addr {
            self.source_addr.hash(state);
            self.dest_addr.hash(state);
        } else {
            self.dest_addr.hash(state);
            self.source_addr.hash(state);
        }
        if self.source_port > self.dest_port {
            self.source_port.hash(state);
            self.dest_port.hash(state);
        } else {
            self.dest_port.hash(state);
            self.source_port.hash(state);
        }
    }
}

fn prepare_sniffer(ports: &Vec<u16>) -> Result<Capture<pcap::Active>> {
    let interface_names_match = |iface: &Device| iface.name == DEFAULT_INTERFACE_NAME;
    let interfaces = Device::list()?;
    let interface = interfaces
        .into_iter()
        .find(interface_names_match)
        .ok_or(anyhow!("Interface not found"))?;

    let mut cap = Capture::from_device(interface)?.open()?;
    cap.set_datalink(Linktype::ETHERNET)?;
    // Build a filter of format: "tcp port (80 or 443 or 50 or 90)"
    let filter = format!(
        "tcp port ({})",
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(" or")
    );
    cap.filter(&filter, true)?;
    Ok(cap)
}

fn capture(ports: &Vec<u16>) -> Result<()> {
    let mut cap = prepare_sniffer(ports)?;
    while let Ok(packet) = cap.next() {
        let packet =
            EthernetPacket::new(&packet).ok_or(anyhow!("Packet is not an ethernet packet"))?;
        // match assembler.add_eth_packet(&packet.payload()) {
        //     Ok(_) => {}
        //     Err(e) => {
        //         println!("add packet error {:?}", e);
        //     }
        // }
    }
    Ok(())
    // loop {
    //     match rx.next() {
    //         Ok(packet) => {
    //             let packet = match EthernetPacket::new(packet) {
    //                 Some(packet) => packet,
    //                 None => continue,
    //             };
    //             match assembler.add_eth_packet(&packet.payload()) {
    //                 Ok(_) => {}
    //                 Err(e) => {
    //                     println!("add packet error {:?}", e);
    //                 }
    //             }
    //         }
    //         Err(e) => {
    //             write_message(&Message {
    //                 event: Event::Error(AgentError::from_error(Box::new(e))),
    //                 connection_id: None,
    //             });
    //         }
    //     }
    // }
}

async fn get_container_namespace(container_id: String) -> Result<String> {
    let channel = connect(CONTAINERD_SOCK_PATH).await?;

    let mut client = ContainersClient::new(channel);
    let request = GetContainerRequest { id: container_id };
    let request = with_namespace!(request, DEFAULT_CONTAINERD_NAMESPACE);
    let resp = client.get(request).await?;
    let resp = resp.into_inner();
    let container = resp.container.ok_or(anyhow!("container not found"))?;
    let spec: Spec = serde_json::from_slice(
        &container
            .spec
            .ok_or(anyhow!("invalid data from containerd"))?
            .value,
    )?;
    let ns_path = spec
        .linux
        .namespaces
        .iter()
        .find(|ns| ns.ns_type == "network")
        .ok_or(anyhow!("network namespace not found"))?
        .path.as_ref()
        .ok_or(anyhow!("no network namespace path"))?;
    Ok(ns_path.to_owned())
}

fn set_namespace(ns_path: &String) -> Result<()> {
    let fd: RawFd = std::fs::File::open(ns_path)?.into_raw_fd();
    nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET)?;
    Ok(())
}

/// Wrapper around main so we can handle all errors in one place.
async fn wrapped_main() -> Result<()> {
    let args = parse_args();
    let namespace = get_container_namespace(args.container_id).await?;
    set_namespace(&namespace)?;
    capture(&args.ports)
}

fn write_message(message: &Message) -> () {
    let serialized = serde_json::to_string(&message).unwrap();
    io::stdout().write_all(serialized.as_bytes()).unwrap();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match wrapped_main().await {
        Ok(_) => (),
        Err(e) => {
            write_message(&Message {
                event: Event::Error(AgentError::from_error(e)),
                connection_id: None,
            });
        }
    }
    Ok(())
}
