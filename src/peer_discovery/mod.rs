use crate::rope::wires::{Transport, UdpTransport};
use crate::rope::{rpv6, Router, Socket, ExternalAddr};
use log::*;
use std::io;

use std::sync::{Arc, Weak};

use self::proto::{CopiedProtocolMessage, ProtocolMessage, SyncContent};

mod proto;


pub struct PeerDiscoveryServ {
    router: Weak<Router>,
    socket: Arc<Socket>,
    default_udp_transport: Option<UdpTransport>,
}

impl PeerDiscoveryServ {
    fn get_router(&self) -> Option<Arc<Router>> {
        self.router.upgrade()
    }

    pub fn new(router: Arc<Router>, backlog: usize, default_udp_transport: Option<UdpTransport>) -> Arc<Self> {
        let socket = router.clone().bind(6, backlog).unwrap(); // The error is impossible in paper
        let obj = Arc::new(Self {
            router: Arc::downgrade(&router),
            socket,
            default_udp_transport,
        });
        tokio::spawn(socket_handler(obj.clone()));
        obj
    }

    async fn ask(&self, peer_id: u128) { todo!() }
}

enum HandlerError {
    RouterDropped,
    Other,
}

async fn handle_nd_sync(pdserv: Arc<PeerDiscoveryServ>, content: SyncContent, src_addr: u128, exaddr: ExternalAddr) -> Result<(), HandlerError> {
    use rand::seq::IteratorRandom;
    use tokio::time::{Duration, sleep};
    let remote_knowns = content.get_known();
    // TODO: ask unknown peer's detail and add them into router.
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
        if let None = peer.find_tx_of_addr(exaddr) {
            match exaddr {
                ExternalAddr::Udp(sockaddr) => {
                    if let Some(udp_transport) = &pdserv.default_udp_transport {
                        peer.add_tx(udp_transport.create_tx(sockaddr));
                    }
                },
                _ => {},
            }
        }
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
