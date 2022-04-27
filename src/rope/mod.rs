use boringtun::crypto::{X25519PublicKey, X25519SecretKey};

use boringtun::noise::TunnResult;
use log::*;
use parking_lot::{Mutex, RwLock};
use rpv6::{BoxedPacket, Packet};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Weak};
use tokio::sync::{mpsc, broadcast};

pub mod rpv6;
mod utils;
mod wgdispatcher;
use wgdispatcher::WireGuardDispatcher;
pub mod wires;
use wires::*;

use self::wgdispatcher::NewTunnelError;
pub mod exaddr;
pub type ExternalAddr = exaddr::ExternalAddr;
mod msg;

mod peer;
use peer::*;
pub type Peer = peer::Peer;

pub type Msg = msg::Msg;

pub mod events;

async fn router_routing_rx_thread_body(
    router_ref: Weak<Router>,
    mut consumer: mpsc::Receiver<(bytes::Bytes, ExternalAddr)>,
) {
    let router_id = if let Some(router) = router_ref.upgrade() {
        router.id
    } else {return};
    info!("start router({}) rx thread.", router_id);
    use wgdispatcher::DispatchResult::*;
    loop {
        match consumer.recv().await {
            Some((data, sockaddr)) => {
                trace!("receive external data from {:?}", sockaddr);
                if let Some(router) = router_ref.upgrade() {
                    let bufsize = std::cmp::max(148, data.len());
                    let mut buf = bytes::BytesMut::new();
                    buf.resize(bufsize, 0);
                    match router.wg_dispatcher.dispatch(&data) {
                        NewTunnel(pk) => {
                            if let Some(peer) = router.find_peer_by_public_key(&pk) {
                                { // It's a good chance to add new address into peer
                                    let all_tx = peer.get_all_tx();
                                    // TODO: avoid operate the internal structure directly, replace with a method
                                    if all_tx.len() == 0 {
                                        // It very costs to scan all txs, so we just do it when no tx available.
                                        std::mem::drop(all_tx); // avoid deadlock
                                        if let Some(dtransport) = router.get_default_transport(sockaddr.protocol()) {
                                            match dtransport.create_tx_from_exaddr(&sockaddr) {
                                                Result::Ok(tx) => {
                                                    info!("single-way path discover: {} for {}", sockaddr, peer.get_id());
                                                    peer.add_tx(tx);
                                                },
                                                Result::Err(e) => error!("could not create tx from {:?}: {:?}", sockaddr, e),
                                            };
                                        }
                                    }
                                };
                                let ipaddr = sockaddr.clone().into();
                                let mut src: &[u8] = &data;
                                loop {
                                    match peer.wgtunn.decapsulate(ipaddr, src, &mut buf) {
                                        TunnResult::Done => break,
                                        TunnResult::WriteToNetwork(data) => {
                                            if let Some(e) = peer.send(data, Some(&sockaddr)).await.err() {
                                                error!("Error while writing to network: {:?}", e);
                                            }
                                        }
                                        TunnResult::WriteToTunnelV6(data, _) => {
                                            match BoxedPacket::parse(Vec::from(data)) {
                                                Ok(packet) => {
                                                    let mut msg = Msg::new(packet);
                                                    msg.set_src_external_addr(sockaddr.clone());
                                                    let _ = router.route_packet(msg).await;
                                                }
                                                Result::Err(e) => {
                                                    error!("Error when parsing packet: {:?}", e);
                                                }
                                            }
                                        }
                                        TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
                                        TunnResult::Err(e) => {
                                            error!("WireGuard Error: {:?}", e);
                                        }
                                    }
                                    src = &[];
                                }
                            } else {
                                error!("Could not found peer: {:?}", pk);
                                break;
                            }
                        }
                        Dispatch(tunn, peer_ref, idx) => {
                            let ipaddr = sockaddr.clone().into();
                            if let Some(peer) = peer_ref.upgrade() {
                                let mut src: &[u8] = &data;
                                loop {
                                    match tunn.decapsulate(ipaddr, src, &mut buf) {
                                        TunnResult::Done => break,
                                        TunnResult::WriteToNetwork(data) => {
                                            if let Some(e) = peer.send(data, None).await.err() {
                                                error!("Error while writing to network: {:?}", e);
                                            }
                                        }
                                        TunnResult::WriteToTunnelV6(data, _) => {
                                            match BoxedPacket::parse(Vec::from(data)) {
                                                Ok(packet) => {
                                                    let mut msg = Msg::new(packet);
                                                    msg.set_src_external_addr(sockaddr.clone());
                                                    let _ = router.route_packet(msg).await;
                                                }
                                                Result::Err(e) => {
                                                    error!("Error when parsing packet: {:?}", e);
                                                }
                                            }
                                        }
                                        TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
                                        TunnResult::Err(e) => {
                                            error!("WireGuard Error: {:?}", e);
                                        }
                                    }
                                    src = &[];
                                }
                            } else {
                                router.wg_dispatcher.unset_tunnel(idx);
                            }
                        }
                        Err(e) => {
                            error!("Dispatch Error: {:?}", e);
                            trace!("Raw packet data ({} byte(s)): {:?}", &data.len(), &data as &[u8]);
                        }
                    }
                } else {
                    break;
                }
            }
            None => break,
        }
    };
    info!("router({}) rx thread exit.", router_id);
}

async fn router_routing_thread(router_ref: Weak<Router>, mut consumer: mpsc::Receiver<Msg>) {
    loop {
        match consumer.recv().await {
            Some(msg) => {
                if let Some(router) = router_ref.upgrade() {
                    let _ = router.route_packet(msg).await;
                } else {
                    break;
                }
            },
            None => {
                break;
            }
        }
    }
}

struct RouterEvents {
    new_peer_sender: broadcast::Sender<events::NewPeerEvent>,
}

impl RouterEvents {
    fn new(backlog: usize) -> Self {
        Self {
            new_peer_sender: broadcast::channel(backlog).0,
        }
    }
}

pub struct Router {
    id: u128,
    static_private_key: Arc<X25519SecretKey>,
    static_public_key: Arc<X25519PublicKey>,
    peers: RwLock<Vec<Arc<Peer>>>,
    opened_sockets: RwLock<HashMap<u16, (Weak<Socket>, ringbuf::Producer<Msg>)>>,
    wg_dispatcher: WireGuardDispatcher<Weak<Peer>>,
    raw_packet_tx: mpsc::Sender<(bytes::Bytes, ExternalAddr)>,
    routing_msg_tx: mpsc::Sender<Msg>,
    default_transports: RwLock<HashMap<String, Arc<dyn DefaultTransport>>>,
    router_events: RouterEvents,
}

pub enum RoutingResult {
    Ok,
    IOE(io::Error),
    BrokenPipe,
    QueueFull,
    UnboundPort,
    NoDest,
}

#[derive(Debug, Clone, Copy)]
pub enum NewPeerError {
    TunnelNotAvaliable,
    BroadcastId,
}

impl From<NewTunnelError> for NewPeerError {
    fn from(_: NewTunnelError) -> Self {
        NewPeerError::TunnelNotAvaliable
    }
}

impl Router {
    pub fn new(id: u128, static_private_key: Arc<X25519SecretKey>) -> Arc<Self> {
        if id == 0 {
            panic!("Router could not use id 0");
        }
        let static_public_key = Arc::new(static_private_key.clone().public_key());
        let (producer, consumer) = mpsc::channel(128);
        let (routing_producer, routing_consumer) = mpsc::channel(128);
        let router_events = RouterEvents::new( 8); // TODO: allow the user to customize this backlog
        let router = Arc::new(Self {
            id,
            static_private_key: static_private_key.clone(),
            static_public_key: static_public_key.clone(),
            peers: RwLock::new(Vec::new()),
            opened_sockets: RwLock::new(HashMap::new()),
            wg_dispatcher: WireGuardDispatcher::new(
                static_private_key.clone(),
                static_public_key.clone(),
            ),
            raw_packet_tx: producer,
            routing_msg_tx: routing_producer,
            default_transports: RwLock::new(HashMap::new()),
            router_events,
        });
        tokio::spawn(router_routing_rx_thread_body(
            Arc::downgrade(&router),
            consumer,
        ));
        tokio::spawn(router_routing_thread(
            Arc::downgrade(&router),
            routing_consumer,
        ));
        router
    }

    pub fn new_random() -> Arc<Self> {
        use crate::kssid;
        
        let id = kssid::gen_long();
        let seck = Arc::new(X25519SecretKey::new());
        Self::new(id, seck)
    }

    pub fn find_peer_by_public_key(&self, key: &X25519PublicKey) -> Option<Arc<Peer>> {
        let peers = self.peers.read();
        for peer in peers.iter() {
            if let Ok(_) = peer.get_public_key().constant_time_is_equal(key) {
                return Some(peer.clone());
            }
        }
        None
    }

    pub fn find_peer_by_id(&self, id: u128) -> Option<Arc<Peer>> {
        let peers = self.peers.read();
        for peer in peers.iter() {
            if peer.get_id() == id {
                return Some(peer.clone());
            }
        }
        None
    }

    pub fn new_peer(&self, id: u128, static_public_key: Arc<X25519PublicKey>) -> Result<Arc<Peer>, NewPeerError> {
        if id != 0 {
            let tunidx = self.wg_dispatcher.next_idx()?;
            let tunn = self.wg_dispatcher.new_tunnel(tunidx, static_public_key.clone(), None, None)?;
            let peer = Peer::new_arc(id, static_public_key.clone(), tunn.clone());
            self.wg_dispatcher.set_tunnel(tunidx, tunn, Arc::downgrade(&peer));
            let mut peers = self.peers.write();
            peers.push(peer.clone()); 
            let event = events::NewPeerEvent {
                peer: peer.clone(),
            };
            let _ = self.router_events.new_peer_sender.send(event);
            Ok(peer)
        } else {
            Err(NewPeerError::BroadcastId)
        }
    }

    pub fn get_peers<'a>(&'a self) -> parking_lot::RwLockReadGuard<'a, Vec<Arc<Peer>>> {
        self.peers.read()
    }

    /// Get a socket at port_number. Try to use an available port if port_number is zero.
    /// If there is already a socket available, the available socket will be return and `rx_backlog` will be ignored.
    /// Note: port_number <= 1023 is reserved for rope internal services.
    /// Though this function won't check this condition, please don't use them in your application.
    /// ## Errors
    /// - `AddrInUse`: no available ports
    pub fn bind(&self, port_number: u16, rx_backlog: usize) -> io::Result<Arc<Socket>> {
        let mut opened_sockets = self.opened_sockets.write();
        let port = if port_number == 0 {
            match Self::find_avaliable_application_port(&mut opened_sockets) {
                Some(port) => port,
                None => return Err(io::Error::from(io::ErrorKind::AddrInUse)),
            }
        } else {
            if let Some((socket_ref, _)) = opened_sockets.get(&port_number) {
                if let Some(socket) = socket_ref.upgrade() {
                    return Ok(socket)
                }
            }
            port_number
        };
        let (socket, prod) = Socket::new(
            self.id,
            port,
            rx_backlog,
            self.routing_msg_tx.clone(),
        );
        opened_sockets.insert(port, (Arc::downgrade(&socket), prod));
        Ok(socket)
    }

    fn find_avaliable_application_port(
        opened_sockets: &mut HashMap<u16, (Weak<Socket>, ringbuf::Producer<Msg>)>,
    ) -> Option<u16> {
        let mut result = Option::None;
        for port in 1024..u16::MAX {
            if let Some((weakref, _)) = opened_sockets.get(&port) {
                if let None = weakref.upgrade() {
                    result = Some(port);
                    break;
                }
            } else {
                result = Some(port);
                break;
            }
        }
        result
    }

    async fn route_packet(&self, packet: Msg) -> RoutingResult {
        let header = packet.get_header();
        if header.dst_addr_cmp(self.id) {
            self.route_packet_local(packet)
        } else if header.dst_addr_cmp(0){
            self.route_packet_broadcast(packet).await;
            RoutingResult::Ok.into()
        } else {
            self.route_packet_remote(packet).await
        }
    }

    async fn route_packet_broadcast(&self, packet: Msg) {
        let header = packet.get_header();
        let peers = self.peers.read().clone();
        trace!("broadcasting {:?} to {} peer(s).", packet, peers.len());
        match self.bind(header.src_port, peers.len()) {
            Ok(socket) => {
                for peer in peers {
                    let mut new_header = header.clone();
                    new_header.set_dst_addr(peer.get_id());
                    let new_packet = packet.clone().replace_header(new_header);
                    let _ = socket.send_msg(new_packet).await;
                }
            },
            Err(e) => {
                error!("could not bind port {} for broadcasting: {:?}, packet dropped.", header.src_port, e);
            }
        }
    }

    fn route_packet_local(&self, packet: Msg) -> RoutingResult {
        trace!(target: "Router.route_packet_local", "routing {:?}", packet);
        let mut opened_sockets = self.opened_sockets.write();
        let header = packet.get_header();
        if let Some((sockref, prod)) = opened_sockets.get_mut(&header.dst_port) {
            if let Some(sock) = sockref.upgrade() {
                match prod.push(packet) {
                    Ok(_) => {
                        sock.rx_notify.notify_one();
                        RoutingResult::Ok
                    }
                    Err(_) => RoutingResult::QueueFull,
                }
            } else {
                debug!("No one refer socket on port {}, remove it from mapping table.", header.dst_port);
                opened_sockets.remove(&header.dst_port);
                RoutingResult::BrokenPipe
            }
        } else {
            RoutingResult::UnboundPort
        }
    }

    async fn route_packet_remote(&self, packet: Msg) -> RoutingResult {
        trace!(target: "Router.route_packet_remote", "routing {:?}", packet);
        let header = packet.get_header();
        if let Some(peer) = self.find_peer_by_id(header.dst_addr_int()) {
            let data = packet.to_buffer();
            let buf_length = std::cmp::max(data.len()+32, 148);
            let mut buf = Vec::new();
            buf.resize(buf_length, 0);
            match peer.send_encrypted(&data, &mut buf).await {
                Ok(_) => RoutingResult::Ok,
                Err(EncryptedSendError::WireGuard(e)) => {
                    error!("routing failed: WireGuard Error {:?}, packet dropped.", e);
                    RoutingResult::Ok
                },
                Err(EncryptedSendError::IOE(e)) => {
                    RoutingResult::IOE(e)
                }
            }
        } else {
            warn!("Peer {} not found", header.dst_addr_int());
            RoutingResult::NoDest
        }
    }

    pub fn attach_rx(&self, rx: Box<dyn Rx>) {
        let sender = self.raw_packet_tx.clone();
        tokio::spawn(async move {
            loop {
                let mut buf = bytes::BytesMut::new();
                buf.resize(65535, 0);
                match rx.recv_from(&mut buf).await {
                    Ok((size, exaddr)) => {
                        buf.resize(size, 0);
                        match sender.send((buf.freeze(), exaddr)).await {
                            Ok(_) => {},
                            Err(_) => break,
                        }
                    },
                    Err(e) => {
                        use io::ErrorKind::*;
                        error!("IO Error: {:?}", e);
                        match e.kind() {
                            BrokenPipe => break,
                            _ => {},
                        }
                    }
                }
            }
        });
    }

    pub fn get_public_key(&self) -> Arc<X25519PublicKey> {
        self.static_public_key.clone()
    }

    pub fn get_id(&self) -> u128 {
        self.id
    }

    /// Set a default transport.
    /// Default transport helps router handle unknown incoming external address,
    pub fn set_default_transport(&self, protocol: &str, transport: Arc<dyn DefaultTransport>) {
        let mut defaults = self.default_transports.write();
        let _ = defaults.insert(protocol.to_string(), transport);
    }

    /// Get a default transport.
    pub fn get_default_transport(&self, protocol: &str) -> Option<Arc<dyn DefaultTransport>> {
        let defaults = self.default_transports.read();
        defaults.get(protocol).cloned()
    }

    pub fn subscribe_new_peer_events(&self) -> broadcast::Receiver<events::NewPeerEvent> {
        self.router_events.new_peer_sender.subscribe()
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        { // Clean up sockets: notify them before dropping
            let mut opened_sockets = self.opened_sockets.write();
            let mut iter = opened_sockets.iter();
            loop {
                if let Some((_, (sockref, _))) = iter.next() {
                    if let Some(socket) = sockref.upgrade() {
                        socket.set_router_dropped(true);
                        socket.rx_notify.notify_waiters();
                    }
                } else {
                    break;
                }
            }
            opened_sockets.drain();
        }
    }
}

struct SockOpts {
    router_dropped: bool,
}

impl SockOpts {
    fn new() -> Self {
        Self {
            router_dropped: false,
        }
    }
}

pub struct Socket {
    router_id: u128,
    port: u16,
    rx_ringbuf_cons: Mutex<ringbuf::Consumer<Msg>>,
    rx_notify: tokio::sync::Notify,
    tx: mpsc::Sender<Msg>,
    opts: RwLock<SockOpts>,
}

impl Socket {
    fn new(
        router_id: u128,
        port: u16,
        rx_backlog: usize,
        tx: mpsc::Sender<Msg>,
    ) -> (Arc<Self>, ringbuf::Producer<Msg>) {
        let (prod, cons) = ringbuf::RingBuffer::new(rx_backlog).split();
        (
            Arc::new(Self {
                router_id,
                port,
                rx_ringbuf_cons: Mutex::new(cons),
                rx_notify: tokio::sync::Notify::new(),
                tx,
                opts: RwLock::new(SockOpts::new()),
            }),
            prod,
        )
    }

    fn get_router_dropped(&self) -> bool {
        self.opts.read().router_dropped
    }

    fn set_router_dropped(&self, value: bool) -> bool {
        let mut opts = self.opts.write();
        let old = opts.router_dropped;
        opts.router_dropped = value;
        old
    }

    /// Try pop a packet up from ring buffer.
    /// Return WouldBlock if no packet in the buffer.
    fn try_recv(&self) -> io::Result<Msg> {
        let mut ringbuf = self.rx_ringbuf_cons.lock();
        if let Some(data) = ringbuf.pop() {
            Ok(data)
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub async fn recv_packet(&self) -> io::Result<Msg> {
        loop {
            match self.try_recv() {
                Ok(packet) => break Ok(packet),
                Err(e) => if e.kind() == io::ErrorKind::WouldBlock {
                    if !self.get_router_dropped() {
                        self.rx_notify.notified().await;
                    } else {
                        break Err(io::ErrorKind::BrokenPipe.into())
                    }
                } else {
                    break Err(e);
                }
            }
        }
    }

    pub async fn send_packet(&self, packet: BoxedPacket) -> io::Result<()> {
        let msg = Msg::new(packet);
        self.send_msg(msg).await
    }

    pub async fn send_msg(&self, msg: Msg) -> io::Result<()> {
        match self.tx.send(msg).await {
            Ok(_) => Ok(()),
            Err(_) => Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    pub async fn send_to(
        &self,
        dst_addr: u128,
        dst_port: u16,
        buf: &[u8],
        flags: u8,
    ) -> io::Result<()> {
        let buf_len = rpv6::enforce_payload_size(buf.len())?;
        let packet = Packet::new(
            rpv6::Header::new(
                flags,
                self.port,
                buf_len,
                dst_port,
                self.router_id,
                dst_addr,
            ),
            buf,
        );
        self.send_packet((&packet).into()).await
    }

    pub fn get_local_port(&self) -> u16 {
        self.port
    }
}
