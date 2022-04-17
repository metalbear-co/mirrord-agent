// use mirrord_protocol::{MirrordMessage, NewTCPConnection, TCPClose, TCPData};

use pcap::{Active, Capture, Device, Linktype};
use pnet::packet::Packet;
use tokio::sync::mpsc::{Sender, Receiver};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use pcap::stream::PacketCodec;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, IpAddr};
use tokio::select;
use tokio::time::{timeout_at, Duration, Instant};

use crate::protocol::{ClientMessage, DaemonMessage, NewTCPConnection, TCPClose, TCPData};

const DEFAULT_INTERFACE_NAME: &str = "eth0";
const DUMMY_BPF: &str = "tcp dst port 1 and tcp src port 1 and dst host 8.1.2.3 and src host 8.1.2.3";


type ConnectionID = u16;

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

fn is_new_connection(flags: u16) -> bool {
    flags == TcpFlags::SYN
}

fn is_closed_connection(flags: u16) -> bool {
    0 != (flags & (TcpFlags::FIN | TcpFlags::RST))
}

struct ConnectionManager {
    sessions: SessionMap,
    connection_index: ConnectionID,
    ports: HashSet<u16>,
}


/// Build a filter of format: "tcp port (80 or 443 or 50 or 90)"
fn format_bpf(ports: &[u16]) -> String {
    format!(
        "tcp port ({})",
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(" or")
    )
}


impl ConnectionManager {
    fn new() -> Self {
        ConnectionManager {
            sessions: HashMap::new(),
            connection_index: 0,
            ports: HashSet::new(),
        }
    }

    fn qualified_port(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    fn add_ports(&mut self, ports: &[u16]) -> Vec<u16> {
        ports.iter().for_each(
            |port| {self.ports.insert(*port);}
        );
        self.get_ports()
    }

    fn get_ports(&self) -> Vec<u16> {
        Vec::from_iter(self.ports)
    }

    fn handle_packet(&mut self, eth_packet: &EthernetPacket) -> Option<Vec<DaemonMessage>> {
        let mut messages = vec![];
        let ip_packet = match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => Ipv4Packet::new(eth_packet.payload())?,
            _ => return None,
        };
        let tcp_packet = match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                TcpPacket::new(ip_packet.payload())?
            }
            _ => return None,
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
                    return None;
                }
                if !is_client_packet {
                    return None;
                }

                let id = self.connection_index;
                self.connection_index += 1;
                messages.push(DaemonMessage::NewTCPConnection(NewTCPConnection {
                    port: dest_port,
                    connection_id: id,
                    address: IpAddr::V4(identifier.source_addr)
                }));
                id
            }
        };
        if is_client_packet {
            let data = tcp_packet.payload();
            if !data.is_empty() {
                messages.push(DaemonMessage::TCPData(TCPData {
                    data: base64::encode(data).into_bytes(),
                    connection_id: session,
                }));
            }
        }
        if is_closed_connection(tcp_flags) {
            messages.push(DaemonMessage::TCPClose(TCPClose {
                connection_id: session,
            }));
        } else {
            self.sessions.insert(identifier, session);
        }
        Some(messages)
    }
}

pub struct TCPManagerCodec {}

impl PacketCodec for TCPManagerCodec {
    type Type = Vec<u8>;

    fn decode(&mut self, packet: pcap::Packet) -> Result<Self::Type, pcap::Error> {
        Vec::from_iter(packet.data)
        // let res = match EthernetPacket::new(packet.data) {
        //     Some(packet) => self
        //         .connection_manager
        //         .handle_packet(&packet)
        //         .unwrap_or(vec![]),
        //     _ => vec![],
        // };
        // Ok(res)
    }
}



fn prepare_sniffer() -> Result<Capture<Active>> {
    let interface_names_match = |iface: &Device| iface.name == DEFAULT_INTERFACE_NAME;
    let interfaces = Device::list()?;
    let interface = interfaces
        .into_iter()
        .find(interface_names_match)
        .ok_or_else(|| anyhow!("Interface not found"))?;

    let mut cap = Capture::from_device(interface)?
        .immediate_mode(true)
        .open()?;
    cap.set_datalink(Linktype::ETHERNET)?;
    // Set a dummy filter that shouldn't capture anything. This makes the code easier.
    cap.filter(DUMMY_BPF, true)?;
    Ok(cap)
}

pub async fn packet_worker(tx: Sender<DaemonMessage>, mut rx: Receiver<ClientMessage>) -> Result<()> {
    let sniffer = prepare_sniffer()?;
    let mut codec = TCPManagerCodec::new();
    let mut connection_manager = ConnectionManager::new();
    let mut stream = sniffer.stream(codec)?;
    loop {
        select! {
            Some(packet) = stream.next() => {
                    let messages = match EthernetPacket::new(packet.data) {
                        Some(packet) => 
                            connection_manager
                            .handle_packet(&packet)
                            .unwrap_or(vec![]),
                        _ => vec![],
                    };
                    for message in messages?.into_iter() {
                        tx.send(message).await?;
                    }

            },
            Some(message) = rx.recv() => {
                match message {
                    ClientMessage::PortSubscribe(new_ports) => {
                        let ports = connection_manager.add_ports(&new_ports);
                        let sniffer = stream.inner_mut();
                        sniffer.filter(&format_bpf(&ports), true);
                    }
                }
            }
            _ = tx.closed() => {
                break;
            }

        }
    }
    Ok(())
}
