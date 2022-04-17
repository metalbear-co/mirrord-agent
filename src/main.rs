use anyhow::{anyhow, Result};


use tracing::{debug, info, error};
use pcap::Active;
use tokio::task;
use tokio::select;
use tokio_stream::StreamExt;
use futures::SinkExt;

use std::borrow::Borrow;
use std::collections::HashSet;
use std::hash::{Hasher, Hash};
// use mirrord_protocol::{MirrordCodec, MirrordMessage};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout_at, Duration, Instant};

use pcap::Capture;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    RwLock
};

mod cli;
mod runtime;
mod sniffer;
mod protocol;
use protocol::{ClientMessage, DaemonMessage, DaemonCodec};
use cli::parse_args;
use runtime::{get_container_namespace, set_namespace};
use sniffer::packet_worker;

// fn capture(mut sniffer: Capture<Active>, ports: &[u16], tx: Sender<pcap::Packet>) -> Result<()> {
//     while let Ok(packet) = sniffer.next() {
//         tx.blocking_send(packet)?;
//     }
//     Ok(())
//     // let mut connection_manager = ConnectionManager::new(ports.to_owned());
//     // while let Ok(packet) = sniffer.next() {
//     //     let packet = EthernetPacket::new(&packet)
//     //         .ok_or_else(|| anyhow!("Packet is not an ethernet packet"))?;
//     //     let _ = connection_manager.handle_packet(&packet);
//     // }
//     // Ok(())
// }

type PeerID = u32;

#[derive(Debug)]
struct Peer {
    id: PeerID,
    channel: mpsc::Sender<DaemonMessage>
}

impl Peer {
    pub fn new(id: PeerID, channel: mpsc::Sender<DaemonMessage>) -> Peer {
        Peer {
            id,
            channel
        }
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
   current_id: PeerID,
}

impl State {
    pub fn new() -> State {
        State { peers: HashSet::new(), current_id : 0 }
    }

    pub fn generate_id(&mut self) -> PeerID {
        let res = self.current_id;
        self.current_id += 1;
        res
    }
}


#[derive(Debug)]
struct PeerMessage {
    msg: ClientMessage,
    peer_id: PeerID
}

async fn peer_handler(mut rx: mpsc::Receiver<DaemonMessage>, tx: mpsc::Sender<PeerMessage>, stream: TcpStream, peer_id: PeerID) -> Result<()>
{
    let mut stream = actix_codec::Framed::new(stream, DaemonCodec::new());
    loop {
        select! {
            Some(message) = stream.next() => {
                let message = PeerMessage {
                    msg: message?,
                    peer_id
                };
                debug!("client sent message {:?}", &message);
                tx.send(message).await?;
            },
            Some(message) = rx.recv() => {
                debug!("send message to client {:?}", &message);
                stream.send(message).await?;
            }
        }
    }
    Ok(())
}

async fn start() -> Result<()> {
    let args = parse_args();
    debug!("mirrod-agent starting with args {:?}", args);
    let namespace = get_container_namespace(args.container_id).await?;
    debug!("Found namespace to attach to {:?}", &namespace);
    set_namespace(&namespace)?;

    let listener = TcpListener::bind(SocketAddrV4::new(
        Ipv4Addr::new(0, 0, 0, 0),
        args.communicate_port,
    ))
    .await?;

    let mut state = State::new();
    let (peers_tx, mut peers_rx) = mpsc::channel::<PeerMessage>(1000);
    loop {
        select! {
            Ok((stream, addr)) = listener.accept() => {
                debug!("Connection accepeted from {:?}", addr);
                let id = state.generate_id();
                let (tx, rx) = mpsc::channel::<DaemonMessage>(1000);
                state.peers.insert(Peer::new(id, tx));
                let worker_tx = peers_tx.clone();
                tokio::spawn(async move {
                    match peer_handler(rx, worker_tx, stream, id).await {
                        Ok(()) => {debug!("Peer closed")},
                        Err(err) => {error!("Peer encountered error {}", err.to_string());}
                    };
                });
            },
            Some(message) = peers_rx.recv() => {
                match message.msg {
                    ClientMessage::PortSubscribe(ports) => {
                        debug!("peer id {:?} asked to subscribe to {:?}", message.peer_id, ports)
                    }
                }
            }
        }
    }

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
