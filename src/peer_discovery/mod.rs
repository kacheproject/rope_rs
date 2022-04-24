use crate::peer_discovery::proto::SetContent;
use crate::rope::{rpv6, ExternalAddr, Router, Socket};
use boringtun::crypto::X25519PublicKey;
use log::*;
use std::io;

use std::str::FromStr;
use std::sync::{Arc, Weak};

use self::proto::{AskContent, AskQuestion, CopiedProtocolMessage, ProtocolMessage, SyncContent};

mod proto;

pub struct PeerDiscoveryServ {
    router: Weak<Router>,
    socket: Arc<Socket>,
}

impl PeerDiscoveryServ {
    pub const DEFAULT_PORT: u16 = 6;

    fn get_router(&self) -> Option<Arc<Router>> {
        self.router.upgrade()
    }

    pub fn new(router: Arc<Router>, backlog: usize) -> Arc<Self> {
        let socket = router.clone().bind(6, backlog).unwrap(); // The error is impossible in paper
        let obj = Arc::new(Self {
            router: Arc::downgrade(&router),
            socket,
        });
        tokio::spawn(socket_handler(obj.clone()));
        obj
    }

    /// Send a ND_ASK message to ask the detail of one peer. If you need to broadcast the message, use the broadcast ID(`0`) as `ask_peer`.
    async fn ask(&self, ask_for_peer_id: u128, questions: &[AskQuestion], ask_peer: u128) {
        let msg = proto::AskContent::new(
            ask_for_peer_id,
            questions.iter().map(|v| v.clone().into()).collect(),
        );
        let mut src = Vec::new();
        src.resize(msg.required_size(), 0);
        msg.write(&mut src).unwrap(); // Here should not error
        let _ = self.socket.send_to(ask_peer, 6, &src, 0).await;
    }

    async fn reply_ask(&self, reply_to: u128, ask_for: u128, q: AskQuestion) {
        if let Some(router) = self.get_router() {
            if let Some(peer) = router.find_peer_by_id(ask_for) {
                match q {
                    AskQuestion::PublicKey => {
                        use base64::encode_config;
                        let pk = peer.get_public_key();
                        let pk_bytes = pk.as_bytes();
                        let pk_base64 = encode_config(pk_bytes, base64::URL_SAFE_NO_PAD);
                        let msg = SetContent::new(ask_for, q, pk_base64);
                        let mut buf = Vec::new();
                        buf.resize(msg.required_size(), 0);
                        msg.write(&mut buf).unwrap(); // Should not error here
                        let _ = self.socket.send_to(reply_to, Self::DEFAULT_PORT, &buf, 0).await;
                    }
                    AskQuestion::PhysicalWires => {
                        if let Some(peer) = router.find_peer_by_id(ask_for) {
                            let addrs: Vec<ExternalAddr> = {
                                let all_txs = peer.get_all_tx();
                                all_txs
                                    .iter()
                                    .filter_map(|v| {
                                        let exaddr = v.get_external_address();
                                        if exaddr != ExternalAddr::None {
                                            Some(exaddr)
                                        } else {
                                            None
                                        }
                                    })
                                    .collect()
                            };
                            for addr in addrs {
                                let msg = SetContent::new(ask_for, q, addr.to_string());
                                let mut buf = Vec::new();
                                buf.resize(msg.required_size(), 0);
                                msg.write(&mut buf).unwrap();
                                let _ = self.socket.send_to(reply_to, Self::DEFAULT_PORT, &buf, 0).await;
                            }
                        }
                    }
                };
            }
        }
    }

    /// Send a ND_SYNC message.
    /// You should call this method when you first connect to network.
    pub async fn sync(&self) {
        if let Some(router) = self.get_router() {
            let mut all_ids = {
                use rand::seq::IteratorRandom;
                let peers = router.get_peers();
                let mut rng = rand::thread_rng();
                peers
                    .iter()
                    .map(|p| p.get_id())
                    .choose_multiple(&mut rng, 63)
            };
            all_ids.push(router.get_id());
            let msg = SyncContent::new(all_ids);
            let mut buf = Vec::new();
            buf.resize(msg.required_size(), 0);
            msg.write(&mut buf).unwrap();
            let result = self.socket.send_to(0, Self::DEFAULT_PORT, &buf, 0).await;
            debug!("router {}: ND_SYNC sent, {:?}", router.get_id(), result);
        }
    }
}

enum HandlerError {
    RouterDropped,
    Other,
}

async fn handle_nd_sync(
    pdserv: Arc<PeerDiscoveryServ>,
    content: SyncContent,
    src_addr: u128,
    exaddr: ExternalAddr,
) -> Result<(), HandlerError> {
    use rand::seq::IteratorRandom;
    use tokio::time::{sleep, Duration};
    let remote_knowns = content.get_known();
    {
        let local_knowns: Vec<u128> = {
            let router = pdserv.get_router().ok_or(HandlerError::RouterDropped)?;
            let peers = router.get_peers();
            peers.iter().map(|p| p.get_id()).collect()
        };
        let local_unknowns = remote_knowns.iter().filter(|id| !local_knowns.contains(id));
        for unknown_id in local_unknowns {
            pdserv
                .ask(
                    *unknown_id,
                    &[AskQuestion::PublicKey, AskQuestion::PhysicalWires],
                    src_addr,
                )
                .await;
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
        add_external_addr_as_tx(&router, src_addr, exaddr);
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

fn add_external_addr_as_tx(router: &Router, src_addr: u128, exaddr: ExternalAddr) {
    if let Some(peer) = router.find_peer_by_id(src_addr) {
        if let None = peer.find_tx_of_addr(exaddr.clone()) {
            if let Some(default_transport) = router.get_default_transport(exaddr.protocol()) {
                match default_transport.create_tx_from_exaddr(&exaddr) {
                    Ok(tx) => peer.add_tx(tx),
                    Err(e) => error!(
                        "default transport {:?} could not create tx from external addr {:?}: {:?}",
                        default_transport, exaddr, e
                    ),
                }
            }
        }
    }
}

async fn handle_nd_ask(
    pdserv: Arc<PeerDiscoveryServ>,
    ask_content: AskContent,
    msg_dst_addr: u128,
    msg_src_addr: u128,
) -> Result<(), HandlerError> {
    let router = pdserv.get_router().ok_or(HandlerError::RouterDropped)?;
    if msg_dst_addr != 0 && (msg_dst_addr == 0 && ask_content.get_id() == router.get_id()) {
        let target_id = ask_content.get_id();
        if let Some(_) = router.find_peer_by_id(target_id) {
            for q in ask_content.get_questions() {
                pdserv.reply_ask(msg_src_addr, target_id, q).await
            }
        }
    }
    Ok(())
}

fn handle_nd_set(
    pdserv: Arc<PeerDiscoveryServ>,
    set_content: SetContent,
) -> Result<(), HandlerError> {
    let router = pdserv.get_router().ok_or(HandlerError::RouterDropped)?;
    if let Some(q) = set_content.get_q() {
        match q {
            AskQuestion::PublicKey => {
                use base64::decode_config_slice;
                let mut pk_bytes = [0u8; 32];
                match decode_config_slice(
                    set_content.get_ans(),
                    base64::URL_SAFE_NO_PAD,
                    &mut pk_bytes,
                ) {
                    Ok(size) => {
                        if size == 32 {
                            let pk = X25519PublicKey::from(&pk_bytes[..]);
                            match router.new_peer(set_content.get_id(), Arc::new(pk)) {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("NDSet processed, but making peer is error: {:?}", e);
                                }
                            };
                        } else {
                            warn!(
                                "NDSet invalid public key for {}: insuffient length {}",
                                set_content.get_id(),
                                size
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                                    "while processing NDSet public key for {}, could not decode public key: {}",
                                    set_content.get_id(),
                                    e,
                                );
                    }
                };
            }
            AskQuestion::PhysicalWires => match ExternalAddr::from_str(set_content.get_ans()) {
                Ok(exaddr) => {
                    add_external_addr_as_tx(&router, set_content.get_id(), exaddr);
                }
                Err(e) => {
                    error!("could not handle NDSet message: {:?}", e);
                }
            },
        }
        Ok(())
    } else {
        warn!("unknown NDSet question: {}", set_content.get_q_int());
        Ok(())
    }
}

async fn socket_handler(pdserv: Arc<PeerDiscoveryServ>) {
    loop {
        match pdserv.socket.recv_packet().await {
            Ok(msg) => match proto::parse(msg.get_payload()) {
                Ok(message) => {
                    use proto::AnyMessage::*;
                    trace!("receive message {:?}", message);
                    match message {
                        NDSync(content) => {
                            if let Err(HandlerError::RouterDropped) = handle_nd_sync(
                                pdserv.clone(),
                                content,
                                msg.get_header().src_addr_int(),
                                msg.get_src_external_addr(),
                            )
                            .await
                            {
                                break;
                            }
                        }
                        NDBye(_) => {
                            let peer_id = msg.get_header().src_addr_int();
                            if let Err(HandlerError::RouterDropped) =
                                handle_nd_bye(pdserv.clone(), peer_id)
                            {
                                break;
                            }
                        }
                        NDAsk(content) => {
                            let dst_addr = msg.get_header().src_addr_int();
                            let src_addr = msg.get_header().src_addr_int();
                            if let Err(HandlerError::RouterDropped) =
                                handle_nd_ask(pdserv.clone(), content, dst_addr, src_addr).await
                            {
                                break;
                            }
                        }
                        NDSet(content) => {
                            if let Err(HandlerError::RouterDropped) =
                                handle_nd_set(pdserv.clone(), content)
                            {
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
