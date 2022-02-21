use anyhow::Result;
use containerd_client::connect;
use containerd_client::with_namespace;
use nix;
use std::net::Ipv4Addr;
use std::os::unix::io::{IntoRawFd, RawFd};

use containerd_client::services::v1::containers_client::ContainersClient;
use containerd_client::services::v1::GetContainerRequest;
use serde::{Deserialize, Serialize};
use tonic::Request;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

use std::hash::Hash;
mod api;
use tcpassembler::TCPAssembler;

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

#[derive(Hash, Debug, Eq)]
struct SessionIdentifier {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

impl PartialEq for SessionIdentifier {
    fn eq(&self, other: &SessionIdentifier) -> bool {
        self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
    }
}



fn capture() {
    let interface_name = "eth0";
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let mut cfg = datalink::Config::default();
    cfg.promiscuous = false;
    cfg.channel_type = datalink::ChannelType::Layer2;
    let (tx, mut rx) = match datalink::channel(&interface, cfg) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    let mut assembler = TCPAssembler::new();
    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = match EthernetPacket::new(packet) {
                    Some(packet) => packet,
                    None => {
                        println!("ignored invalid ethernet");
                        continue;
                    },
                };
                match assembler.add_eth_packet(&packet.payload()) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("add packet error {:?}", e);
                    }
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = connect("/run/containerd/containerd.sock").await.unwrap();

    let mut client = ContainersClient::new(channel);
    let request = GetContainerRequest {
        id: "d675d90211da2967d36f4c604458de59c2bb44e5da5da29dbcd0d769482ccadb".to_string(),
    };
    let request = with_namespace!(request, "k8s.io");
    let resp = client.get(request).await.unwrap();
    let resp = resp.into_inner();
    let container = resp.container.unwrap();
    let spec: Spec = serde_json::from_slice(&container.spec.unwrap().value).unwrap();
    let mut ns_path = None;
    for ns in spec.linux.namespaces {
        if ns.ns_type == "network" {
            println!("{:?}", ns.path);
            ns_path = ns.path;
            break;
        }
    }
    let f: RawFd = std::fs::File::open(ns_path.unwrap()).unwrap().into_raw_fd();
    nix::sched::setns(f, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    capture();
    Ok(())
}
