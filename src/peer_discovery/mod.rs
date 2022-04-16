use crate::rope::wires::{Transport, Tx};
use crate::rope::{rpv6, Router, Socket, ExternalAddr};
use itertools::Itertools;
use log::*;
use std::collections::HashMap;
use std::io;
use parking_lot::RwLock;

use std::sync::{Arc, Weak};

use self::proto::{CopiedProtocolMessage, ProtocolMessage, SyncContent, AskContent, AskQuestion};

mod proto;

pub trait DefaultTransport: std::fmt::Debug + Sync + Send {
    fn create_tx_from_exaddr(&self, addr: ExternalAddr) -> Result<Box<dyn Tx>, &'static str>;
}

pub struct PeerDiscoveryServ {
    router: Weak<Router>,
    socket: Arc<Socket>,
    default_transports: RwLock<HashMap<String, Arc<dyn DefaultTransport>>>,
}

impl PeerDiscoveryServ {
    fn get_router(&self) -> Option<Arc<Router>> {
        self.router.upgrade()
    }

    pub fn new(router: Arc<Router>, backlog: usize) -> Arc<Self> {
        let socket = router.clone().bind(6, backlog).unwrap(); // The error is impossible in paper
        let obj = Arc::new(Self {
            router: Arc::downgrade(&router),
            socket,
            default_transports: RwLock::new(HashMap::new()),
        });
        tokio::spawn(socket_handler(obj.clone()));
        obj
    }

    /// Send a ND_ASK message to ask the detail of one peer. If you need to broadcast the message, use the broadcast ID(`0`) as `ask_peer`.
    async fn ask(&self, ask_for_peer_id: u128, questions: &[AskQuestion], ask_peer: u128) {
        let msg = proto::AskContent::new(ask_for_peer_id, questions.iter().map(|v| v.clone().into()).collect());
        let mut src = Vec::new();
        src.resize(msg.required_size(), 0);
        msg.write(&mut src).unwrap(); // Here should not error
        let _ = self.socket.send_to(ask_peer, 6, &src, 0).await;
    }

    /// Set a default transport handler.
    pub fn set_default_transport(&self, protocol: &str, transport: Arc<dyn DefaultTransport>) {
        let mut defaults = self.default_transports.write();
        let _ = defaults.insert(protocol.to_string(), transport);
    }
}

enum HandlerError {
    RouterDropped,
    Other,
}

async fn handle_nd_sync(pdserv: Arc<PeerDiscoveryServ>, content: SyncContent, src_addr: u128, exaddr: ExternalAddr) -> Result<(), HandlerError> {
    use rand::seq::IteratorRandom;
    use tokio::time::{Duration, sleep};
    let remote_knowns = content.get_known();
    {
        let local_knowns: Vec<u128> = {
            let router = pdserv.get_router().ok_or(HandlerError::RouterDropped)?;
            let peers = router.get_peers();
            peers.iter().map(|p| p.get_id()).collect()
        };
        let local_unknowns = remote_knowns.iter().filter(|id| !local_knowns.contains(id));
        for unknown_id in local_unknowns {
            pdserv.ask(*unknown_id, &[AskQuestion::PublicKey, AskQuestion::PhysicalWires], src_addr).await;
        }
    }
    sleep(Duration::from_secs((rand::random::<u8>() / 10).into())).await; // sleep 0 - 12 seconds
    if let Some(router) = pdserv.get_router() {
        let delta = {
            let peers = router.get_peers();
            let local_knowns = peers.iter().map(|p| p.get_id());
            let mut rng = rand::thread_rng();
            local_knowns
            .filter(|id| remote_knowns.contains(id))
            .choose_multiple(&mut rng, 64) // limit to 64 entries
        };
        add_external_addr_as_tx(&pdserv, &router, src_addr, exaddr);
        let msg = SyncContent::new(delta);
        let mut buf = Vec::new();
        buf.reserve(msg.required_size() + 40);
        buf[..40].copy_from_slice(&[0; 40]);
        match msg.write(&mut buf) {
            Ok(size) => {
                let local_port = pdserv.socket.get_local_port();
                let packet = rpv6::BoxedPacket::new(
                    rpv6::Header::new(
                        0,
                        local_port,
                        size.try_into().unwrap(),
                        6,
                        router.get_id(),
                        0,
                    ),
                    buf,
                    true,
                );
                let _ = pdserv.socket.send_packet(packet).await;
                Ok(())
            }
            Err(e) => {
                error!("handle_nd_sync, encode error: {:?}", e);
                trace!("handle_nd_sync, encode error when encoding: {:?}", msg);
                Err(HandlerError::RouterDropped)
            }
        }
    } else {
        Err(HandlerError::Other)
    }
}

fn handle_nd_bye(pdserv: Arc<PeerDiscoveryServ>, src_peer_id: u128) -> Result<(), HandlerError> {
    if let Some(router) = pdserv.get_router() {
        if let Some(peer) = router.find_peer_by_id(src_peer_id) {
            peer.clear_tx();
            Ok(())
        } else {
            Ok(())
        }
    } else {
        Err(HandlerError::RouterDropped)
    }
}

fn add_external_addr_as_tx(pdserv: &PeerDiscoveryServ, router: &Router, src_addr: u128, exaddr: ExternalAddr) {
    if let Some(peer) = router.find_peer_by_id(src_addr) {
        if let None = peer.find_tx_of_addr(exaddr.clone()) {
            if let Some(default_transport) = pdserv.default_transports.read().get(exaddr.protocol()) {
                match default_transport.create_tx_from_exaddr(exaddr.clone()) {
                    Ok(tx) => peer.add_tx(tx),
                    Err(e) => error!("default transport {:?} could not create tx from external addr {:?}: {:?}", default_transport, exaddr, e),
                }
            }
        }
    }
}

fn handle_nd_ask(
    pdserv: Arc<PeerDiscoveryServ>,
    ask_content: AskContent, msg_dst_addr: u128) -> Result<(), HandlerError> {
    let router = pdserv.get_router().ok_or(HandlerError::RouterDropped)?;
    if msg_dst_addr != 0 && (msg_dst_addr == 0 && ask_content.get_id() == router.get_id()) {
        let target_id = ask_content.get_id();
        if let Some(peer) = router.find_peer_by_id(target_id) {
            for q in ask_content.get_questions() {
                let msg = match q {
                    AskQuestion::PublicKey => {
                        todo!()
                    },
                    AskQuestion::PhysicalWires => {
                        todo!()
                    },
                };
            }
            Ok(())
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

async fn socket_handler(pdserv: Arc<PeerDiscoveryServ>) {
    loop {
        match pdserv.socket.recv_packet().await {
            Ok(msg) => match proto::parse(msg.get_payload()) {
                Ok(message) => {
                    use proto::AnyMessage::*;
                    match message {
                        NDSync(content) => {
                            if let Err(HandlerError::RouterDropped) = handle_nd_sync(pdserv.clone(), content, msg.get_header().src_addr_int(), msg.get_src_external_addr()).await {
                                break;
                            }
                        },
                        NDBye(_) => {
                            let peer_id = msg.get_header().src_addr_int();
                            if let Err(HandlerError::RouterDropped) = handle_nd_bye(pdserv.clone(), peer_id) {
                                break;
                            }
                        },
                        NDAsk(content) => {
                            let dst_addr = msg.get_header().src_addr_int();
                            if let Err(HandlerError::RouterDropped) = handle_nd_ask(pdserv.clone(), content, dst_addr) {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("socket_handler, decoding error: {:?}", e);
                    trace!("socket_handler, decodeing error for \"{:?}\"", msg);
                }
            },
            Err(e) => match e.kind() {
                io::ErrorKind::BrokenPipe => break, // The router have been dropped
                _ => {
                    error!("socket_handler, i/o error: {:?}", e);
                }
            },
        }
    }
}
