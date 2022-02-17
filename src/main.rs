use anyhow::Result;
use containerd_client::connect;
use containerd_client::with_namespace;
use nix;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::collections::HashMap;

use containerd_client::services::v1::containers_client::ContainersClient;
use containerd_client::services::v1::GetContainerRequest;
use pnet::datalink::EtherType;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use serde::{Deserialize, Serialize};
use tonic::Request;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;

use std::hash::{Hash, Hasher};
mod api;
use api::*;

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

#[derive(Debug, Eq)]
struct TCPSession {
    pub parts: HashMap<u32, Vec<u8>>,
    pub data: Vec<u8>,
    pub current_seq: usize,
    pub fin_seq: Option<usize>,
    identifier: SessionIdentifier,
}

impl TCPSession {
    fn new(start_seq: u32, identifier: SessionIdentifier) -> Self {
        TCPSession {
            parts: HashMap::new(),
            data: Vec::new(),
            current_seq: start_seq,
            fin_seq: None,
            identifier,
        }
    }
    
    fn add_packet(&mut self, packet: &TcpPacket) -> Option<Vec<u8>> {
        let seq = packet.get_sequence();
        let data = packet.payload();
        if seq as usize == self.current_seq {
            
        } else if seq > self.current_seq {
            let mut missing_data = Vec::new();
            let mut missing_seq = self.current_seq;
            while missing_seq < seq {
                missing_data.push(0);
                missing_seq += 1;
            }
            missing_data.extend(data);
            self.parts.insert(seq, missing_data);
            self.current_seq = seq + data.len() as u32;
            None
        } else {
            Some(data)
        }
        self.parts.insert(seq, data.to_vec());
        if packet.flags() == TcpFlags::FIN {
            self.fin_seq = Some(seq + data.len() as u32);
        }
    }
}

enum TCPResult {
    MoreData(Vec<u8>), // Session has ready data
    ClosedMoreData(Vec<u8>), // Session has closed but has more data.
    NoData, // Session has no data (received frame without data or data is not complete [out of sequence])
    Closed, // Session has been closed
}

impl Hash for TCPSession {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identifier.hash(state)
    }
}

impl PartialEq for TCPSession {
    fn eq(&self, other: &TCPSession) -> bool {
        self.identifier == other.identifier
    }
}

impl Borrow<SessionIdentifier> for TCPSession {
    fn borrow(&self) -> &SessionIdentifier {
        &self.identifier
    }
}

struct SessionManager {
    sessions: HashSet<TCPSession>,
}

impl SessionManager {
    fn new() -> Self {
        Self {
            sessions: HashSet::new(),
        }
    }

    fn add_packet(&mut self, packet: &EthernetPacket) -> Result<()> {
        // match packet.get_ethertype() {
        //     EtherTypes::Ipv4 => {
        //         let packet = Ipv4Packet::new(packet.payload()).unwrap();
        //         match packet.get_next_level_protocol() {
        //             IpNextHeaderProtocols::Tcp => {
        //                 let packet = TcpPacket::new(packet.payload()).unwrap();
        //                 println!("TCP packet received, {:?}", packet.payload().len());
        //             },
        //             _ => {
        //                 println!("ignored");
        //             }
        //         }
        //     },
        //     _ => {
        //         println!("ignored")
        //     }
        if packet.get_ethertype() != EtherTypes::Ipv4 {
            return Ok(());
        }
        let ip_packet = Ipv4Packet::new(packet.payload())
            .ok_or(anyhow::anyhow!("failed to parse ipv4 packet"))?;

        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return Ok(());
        }
        let tcp_packet = TcpPacket::new(ip_packet.payload())
            .ok_or(anyhow::anyhow!("failed to parse tcp packet"))?;

        let src_ip = ip_packet.get_source();
        let dst_ip = ip_packet.get_destination();
        let src_port = tcp_packet.get_source();
        let dst_port = tcp_packet.get_destination();
        let identifier = SessionIdentifier {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };

        let session = match self.sessions.take(&identifier) {
            Some(session) => {
                println!("session found, {:?}", tcp_packet.payload());
                session
            }
            None => {
                if tcp_packet.get_flags() & TcpFlags::SYN == 0 {
                    println!("Not first packet of session");
                    return Ok(());
                }
                let event = Event::Connected(TCPConnected { port: src_port });
                println!("connected event {:?}", event);
                TCPSession::new(tcp_packet.get_sequence(), identifier)
            }
        };
        self.sessions.insert(session);
        Ok(())
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
    let mut session_manager = SessionManager::new();
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
                match session_manager.add_packet(&packet) {
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
