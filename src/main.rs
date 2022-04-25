use anyhow::Result;

use futures::SinkExt;
use tokio::{select, task};
use tokio_stream::StreamExt;
use tracing::{debug, error, info};

use std::borrow::Borrow;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
// use mirrord_protocol::{MirrordCodec, MirrordMessage};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::net::{TcpListener, TcpStream};

use tokio::sync::mpsc::{self};

mod cli;
mod common;
mod protocol;
mod runtime;
mod sniffer;
mod util;

use cli::parse_args;
use common::PeerID;
use protocol::{ClientMessage, ConnectionID, DaemonCodec, DaemonMessage};
use runtime::{get_container_namespace, set_namespace};
use sniffer::{packet_worker, SnifferCommand, SnifferOutput};
use util::{IndexAllocator, Subscriptions};

type Port = u16;

#[derive(Debug)]
struct Peer {
    id: PeerID,
    channel: mpsc::Sender<DaemonMessage>,
}

impl Peer {
    pub fn new(id: PeerID, channel: mpsc::Sender<DaemonMessage>) -> Peer {
        Peer { id, channel }
    }
}
impl Eq for Peer {}

impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        self.id == other.id
    }
}

impl Hash for Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Borrow<PeerID> for Peer {
    fn borrow(&self) -> &PeerID {
        &self.id
    }
}

#[derive(Debug)]
struct State {
    pub peers: HashSet<Peer>,
    index_allocator: IndexAllocator<PeerID>,
    pub port_subscriptions: Subscriptions<Port, PeerID>,
    pub connections_subscriptions: Subscriptions<ConnectionID, PeerID>,
}

impl State {
    pub fn new() -> State {
        State {
            peers: HashSet::new(),
            index_allocator: IndexAllocator::new(),
            port_subscriptions: Subscriptions::new(),
            connections_subscriptions: Subscriptions::new(),
        }
    }

    pub fn generate_id(&mut self) -> Option<PeerID> {
        self.index_allocator.next_index()
    }

    pub fn remove_peer(&mut self, peer_id: PeerID) {
        self.peers.remove(&peer_id);
        self.port_subscriptions.remove_client(peer_id);
        self.connections_subscriptions.remove_client(peer_id);
        self.index_allocator.free_index(peer_id)
    }
}

#[derive(Debug)]
struct PeerMessage {
    msg: ClientMessage,
    peer_id: PeerID,
}

async fn peer_handler(
    mut rx: mpsc::Receiver<DaemonMessage>,
    tx: mpsc::Sender<PeerMessage>,
    stream: TcpStream,
    peer_id: PeerID,
) -> Result<()> {
    let mut stream = actix_codec::Framed::new(stream, DaemonCodec::new());
    loop {
        select! {
            message = stream.next() => {
                match message {
                    Some(message) => {
                        let message = PeerMessage {
                            msg: message?,
                            peer_id
                        };
                        debug!("client sent message {:?}", &message);
                        tx.send(message).await?;
                    }
                    None => break
                }

            },
            message = rx.recv() => {
                match message {
                    Some(message) => {
                        debug!("send message to client {:?}", &message);
                        stream.send(message).await?;
                    }
                    None => break
                }

            }
        }
    }
    Ok(())
}

async fn start() -> Result<()> {
    let args = parse_args();
    debug!("mirrod-agent starting with args {:?}", args);
    if let Some(container_id) = args.container_id {
        let namespace = get_container_namespace(container_id).await?;
        debug!("Found namespace to attach to {:?}", &namespace);
        set_namespace(&namespace)?;
    }

    let listener = TcpListener::bind(SocketAddrV4::new(
        Ipv4Addr::new(0, 0, 0, 0),
        args.communicate_port,
    ))
    .await?;

    let mut state = State::new();
    let (peers_tx, mut peers_rx) = mpsc::channel::<PeerMessage>(1000);
    let (packet_sniffer_tx, mut packet_sniffer_rx) = mpsc::channel::<SnifferOutput>(1000);
    let (packet_command_tx, packet_command_rx) = mpsc::channel::<SnifferCommand>(1000);
    let packet_task = task::spawn(packet_worker(packet_sniffer_tx, packet_command_rx));
    loop {
        select! {
            Ok((stream, addr)) = listener.accept() => {
                debug!("Connection accepeted from {:?}", addr);
                if let Some(id) = state.generate_id() {
                    let (tx, rx) = mpsc::channel::<DaemonMessage>(1000);
                    state.peers.insert(Peer::new(id, tx));
                    let worker_tx = peers_tx.clone();
                    tokio::spawn(async move {
                        match peer_handler(rx, worker_tx, stream, id).await {
                            Ok(()) => {debug!("Peer closed")},
                            Err(err) => {error!("Peer encountered error {}", err.to_string());}
                        };
                    });
                }
                else {
                    error!("ran out of connections, dropping new connection");
                }

            },
            Some(message) = peers_rx.recv() => {
                match message.msg {
                    ClientMessage::PortSubscribe(ports) => {
                        debug!("peer id {:?} asked to subscribe to {:?}", message.peer_id, ports);
                        state.port_subscriptions.subscribe_many(message.peer_id, ports);
                        let ports = state.port_subscriptions.get_subscribed_topics();
                        packet_command_tx.send(SnifferCommand::SetPorts(ports)).await?;
                    }
                    ClientMessage::Close => {
                        state.remove_peer(message.peer_id);
                        let ports = state.port_subscriptions.get_subscribed_topics();
                        packet_command_tx.send(SnifferCommand::SetPorts(ports)).await?;
                    }
                }
            },
            message = packet_sniffer_rx.recv() => {
                match message {
                    Some(message) => {
                        match message {
                            SnifferOutput::NewTCPConnection(conn) => {
                                let peer_ids = state.port_subscriptions.get_topic_subscribers(conn.port);
                                for peer_id in peer_ids {
                                    state.connections_subscriptions.subscribe(peer_id, conn.connection_id);
                                    if let Some(peer) = state.peers.get(&peer_id) {
                                        match peer.channel.send(DaemonMessage::NewTCPConnection(conn.clone())).await {
                                            Ok(_) => {},
                                            Err(err) => {
                                                error!("error sending message {:?}", err);
                                            }
                                        }
                                    }
                                }
                                debug!("new tcp connection {:?}", conn);
                            },
                            SnifferOutput::TCPClose(close) => {
                                let peer_ids = state.connections_subscriptions.get_topic_subscribers(close.connection_id);
                                for peer_id in peer_ids {
                                    if let Some(peer) = state.peers.get(&peer_id) {
                                        match peer.channel.send(DaemonMessage::TCPClose(close.clone())).await {
                                            Ok(_) => {},
                                            Err(err) => {
                                                error!("error sending message {:?}", err);
                                            }
                                        }
                                    }
                                }
                                state.connections_subscriptions.remove_topic(close.connection_id);
                                debug!("tcp close {:?}", close);
                            },
                            SnifferOutput::TCPData(data) => {
                                let peer_ids = state.connections_subscriptions.get_topic_subscribers(data.connection_id);
                                for peer_id in peer_ids {
                                    if let Some(peer) = state.peers.get(&peer_id) {
                                        match peer.channel.send(DaemonMessage::TCPData(data.clone())).await {
                                            Ok(_) => {},
                                            Err(err) => {
                                                error!("error sending message {:?}", err);
                                            }
                                        }
                                    }
                                }
                                debug!("new data {:?}", data);
                            },
                        }
                    }
                    None => {
                        info!("sniffer died, exiting");
                        break;
                    }
                }

            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                if state.peers.is_empty() {
                    debug!("main thread timeout, no peers connected");
                    break;
                }
            }
        }
    }
    debug!("shutting down start");
    if !packet_command_tx.is_closed() {
        packet_command_tx.send(SnifferCommand::Close).await?;
    };
    drop(packet_command_tx);
    drop(packet_sniffer_rx);
    tokio::time::timeout(std::time::Duration::from_secs(10), packet_task).await???;
    // let stream = timeout_at(Instant::now() + Duration::from_secs(10), io.accept())
    //     .await??
    //     .0;
    // debug!("Preparing sniffer");
    // debug!("Capture starting now");
    // let (tx, mut rx) = mpsc::channel::<MirrordMessage>(1000);
    // let task = task::spawn(packet_worker(args.ports, tx));

    // loop {
    //     select! {
    //         message => rx.recv() => {
    //             streamma
    //         }
    //     }
    // }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    match start().await {
        Ok(_) => {
            info!("Done!")
        }
        Err(err) => {
            error!("error occured: {:?}", err.to_string())
        }
    }
    Ok(())
}
