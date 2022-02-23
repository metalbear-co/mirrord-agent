use anyhow::{anyhow, Result};
use containerd_client::connect;
use containerd_client::with_namespace;
use pcap::Active;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::mem::ManuallyDrop;
use std::net::Ipv4Addr;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};


use containerd_client::services::v1::containers_client::ContainersClient;
use containerd_client::services::v1::GetContainerRequest;
use pcap::{Capture, Device, Linktype};
use pnet::packet::Packet;
use rmp_serde::encode::to_vec;
use serde::{Deserialize, Serialize};
use tonic::Request;

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
pub struct TCPSessionIdentifier {
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
}

impl PartialEq for TCPSessionIdentifier {
    /// It's the same session if 4 tuple is same/opposite.
    fn eq(&self, other: &TCPSessionIdentifier) -> bool {
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

impl Hash for TCPSessionIdentifier {
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

type Session = ConnectionID;
type SessionMap = HashMap<TCPSessionIdentifier, Session>;

fn prepare_sniffer(ports: &[u16]) -> Result<Capture<pcap::Active>> {
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

fn is_new_connection(flags: u16) -> bool {
    flags == TcpFlags::SYN
}

fn is_closed_connection(flags: u16) -> bool {
    0 != flags & (TcpFlags::FIN | TcpFlags::RST)
}

struct ConnectionManager {
    sessions: SessionMap,
    connection_index: ConnectionID,
    ports: Vec<u16>,
}

impl ConnectionManager {
    fn new(ports: Vec<u16>) -> Self {
        ConnectionManager {
            sessions: HashMap::new(),
            connection_index: 0,
            ports,
        }
    }

    fn qualified_port(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    fn handle_packet(&mut self, eth_packet: &EthernetPacket) -> Result<()> {
        let ip_packet = match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                Ipv4Packet::new(eth_packet.payload()).ok_or(anyhow!("Invalid IPv4 Packet"))?
            }
            _ => return Err(anyhow!("Not IPv4 Packet")),
        };
        let tcp_packet = match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                TcpPacket::new(ip_packet.payload()).ok_or(anyhow!("Invalid TCP Packet"))?
            }
            _ => return Err(anyhow!("Not TCP Packet")),
        };
        let dest_port = tcp_packet.get_destination();
        let tcp_flags = tcp_packet.get_flags();
        let identifier = TCPSessionIdentifier {
            source_addr: ip_packet.get_source(),
            dest_addr: ip_packet.get_destination(),
            source_port: tcp_packet.get_source(),
            dest_port,
        };
        let is_client_packet = self.qualified_port(dest_port);
        let session = match self.sessions.remove(&identifier) {
            Some(session) => session,
            None => {
                if !is_new_connection(tcp_flags) {
                    return Err(anyhow!("Mid session traffic"));
                }
                if !is_client_packet {
                    return Err(anyhow!("Unqualified port"));
                }

                let id = self.connection_index;
                self.connection_index += 1;
                write_event(&Event::Connected(TCPConnected {
                    port: dest_port,
                    connection_id: id,
                }));
                id
            }
        };
        if is_client_packet {
            let data = tcp_packet.payload();
            if !data.is_empty() {
                write_event(&Event::Data(TCPData {
                    data: data.to_vec(),
                    connection_id: session,
                }));
            }
        }
        if is_closed_connection(tcp_flags) {
            write_event(&Event::TCPEnded);
        } else {
            self.sessions.insert(identifier, session);
        }
        Ok(())
    }
}

fn capture(mut sniffer: Capture<Active>, ports: &[u16]) -> Result<()> {
    while let Ok(packet) = sniffer.next() {
        let mut connection_manager = ConnectionManager::new(ports.to_owned());
        let packet =
            EthernetPacket::new(&packet).ok_or(anyhow!("Packet is not an ethernet packet"))?;
        let _ = connection_manager.handle_packet(&packet);
    }
    Ok(())
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
        .path
        .as_ref()
        .ok_or(anyhow!("no network namespace path"))?;
    Ok(ns_path.to_owned())
}

fn set_namespace(ns_path: &str) -> Result<()> {
    let fd: RawFd = std::fs::File::open(ns_path)?.into_raw_fd();
    nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET)?;
    Ok(())
}

/// Wrapper around main so we can handle all errors in one place.
async fn wrapped_main() -> Result<()> {
    let args = parse_args();
    info_message(&format!("mirrod-agent starting with args {:?}", args));
    let namespace = get_container_namespace(args.container_id).await?;
    info_message(&format!("Using namespace {}", namespace));
    set_namespace(&namespace)?;
    info_message("Preparing sniffer");
    let sniffer = prepare_sniffer(&args.ports)?;
    info_message("Capture starting now");
    capture(sniffer, &args.ports)
}

fn info_message(msg: &str) {
    write_event(&Event::InfoMessage(msg.to_owned()));
}

fn write_event(message: &Event) {
    let serialized = to_vec(message).unwrap();
    // Rust stdio is buffering lines and doing mayhem.
    let mut stdout = unsafe { ManuallyDrop::new(std::fs::File::from_raw_fd(1)) };
    stdout.write_all(&serialized).unwrap();
    stdout.flush().unwrap();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match wrapped_main().await {
        Ok(_) => (),
        Err(e) => {
            write_event(&Event::Error(AgentError::from_error(e)));
        }
    }
    write_event(&Event::Done);
    Ok(())
}
