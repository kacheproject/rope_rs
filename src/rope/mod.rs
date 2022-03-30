use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use log::*;
use parking_lot::{Mutex, RwLock};
use rpv6::{BoxedPacket, Packet};
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use tokio::sync::mpsc;

mod rpv6;
mod utils;
mod wgdispatcher;
use wgdispatcher::WireGuardDispatcher;
pub mod wires;
use wires::*;

use self::wgdispatcher::NewTunnelError;
mod netmeter;

pub struct Peer {
    id: u128,
    static_public_key: Arc<X25519PublicKey>,
    txs: RwLock<Vec<Arc<Tx>>>,
    wgtunn: Arc<Tunn>,
}

pub enum EncryptedSendError {
    IOE(io::Error),
    WireGuard(WireGuardError),
}

impl Peer {
    /// Initialise a new peer object in Arc.
    /// ## Safety
    /// It's safe to fill any of arguments with MaybeUninit and set them later.
    /// Make sure all of them are properly set before calling any method.
    pub fn new_arc(id: u128, static_public_key: Arc<X25519PublicKey>, wgtunn: Arc<Tunn>) -> Arc<Self> {
        Arc::new(Self::new(id, static_public_key, wgtunn))
    }

    /// Initialise a new peer object.
    /// ## Safety
    /// It's safe to fill any of arguments with MaybeUninit and set them later.
    /// Make sure all of them are properly set before calling any method.
    pub fn new(id: u128, static_public_key: Arc<X25519PublicKey>, wgtunn: Arc<Tunn>) -> Self {
        Self {
            id,
            static_public_key,
            txs: RwLock::new(Vec::new()),
            wgtunn,
        }
    }

    fn select_tx(&self) -> Option<Arc<Tx>> {
        let txs = self.txs.read();
        if txs.len() > 0 {
            Some(txs[0].clone())
        } else {
            None
        }
    }


    /// Encrypt src, write to dst, and send.
    /// The size of dst should be src.len() + 32 and should not be less than 148 bytes.
    async fn send_encrypted<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Result<usize, EncryptedSendError> {
        let mut data = src;
        let mut tx_bytes = 0usize;
        loop {
            match self.wgtunn.encapsulate(data, dst) {
                TunnResult::Done => break Ok(tx_bytes),
                TunnResult::WriteToNetwork(buf) => {
                    match self.send(buf).await {
                        Ok(size) => tx_bytes += size,
                        Err(e) => break Err(EncryptedSendError::IOE(e)),
                    }
                },
                TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
                TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
                TunnResult::Err(e) => break Err(EncryptedSendError::WireGuard(e)),
            };
            data = &[];
        }
    }

    /// Send cleartext though any tx.
    /// Return WouldBlock if no tx avaliable.
    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        if let Some(tx) = self.select_tx() {
            tx.send_to(data).await
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub fn add_tx(&self, tx: Tx) {
        let mut txs = self.txs.write();
        txs.push(Arc::new(tx));
    }
}

async fn router_routing_rx_thread_body(
    router_ref: Weak<Router>,
    mut consumer: mpsc::Receiver<(bytes::Bytes, Option<SocketAddr>)>,
) {
    let router_id = if let Some(router) = router_ref.upgrade() {
        router.id
    } else {return};
    info!("start router({}) rx thread.", router_id);
    use wgdispatcher::DispatchResult::*;
    loop {
        match consumer.recv().await {
            Some((data, sockaddr)) => {
                if let Some(router) = router_ref.upgrade() {
                    let bufsize = std::cmp::max(148, data.len());
                    let mut buf = bytes::BytesMut::new();
                    buf.resize(bufsize, 0);
                    match router.wg_dispatcher.dispatch(&data) {
                        NewTunnel(pk) => {
                            if let Some(peer) = router.find_peer_by_public_key(&pk) {
                                let ipaddr = sockaddr.map(|addr| addr.ip());
                                let mut src: &[u8] = &data;
                                loop {
                                    match peer.wgtunn.decapsulate(ipaddr, src, &mut buf) {
                                        TunnResult::Done => break,
                                        TunnResult::WriteToNetwork(data) => {
                                            if let Some(e) = peer.send(data).await.err() {
                                                error!("Error while writing to network: {:?}", e);
                                            }
                                        }
                                        TunnResult::WriteToTunnelV6(data, _) => {
                                            match BoxedPacket::parse(Vec::from(data)) {
                                                Ok(packet) => {
                                                    let _ = router.route_packet(packet).await;
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
                            let ipaddr = sockaddr.map(|addr| addr.ip());
                            if let Some(peer) = peer_ref.upgrade() {
                                let mut src: &[u8] = &data;
                                loop {
                                    match tunn.decapsulate(ipaddr, src, &mut buf) {
                                        TunnResult::Done => break,
                                        TunnResult::WriteToNetwork(data) => {
                                            if let Some(e) = peer.send(data).await.err() {
                                                error!("Error while writing to network: {:?}", e);
                                            }
                                        }
                                        TunnResult::WriteToTunnelV6(data, _) => {
                                            match BoxedPacket::parse(Vec::from(data)) {
                                                Ok(packet) => {
                                                    let _ = router.route_packet(packet).await;
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
                            trace!("Raw packet data: {:?}", &data as &[u8]);
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

pub struct Router {
    id: u128,
    static_private_key: Arc<X25519SecretKey>,
    static_public_key: Arc<X25519PublicKey>,
    peers: RwLock<Vec<Arc<Peer>>>,
    opened_sockets: RwLock<HashMap<u16, (Weak<Socket>, ringbuf::Producer<BoxedPacket>)>>,
    wg_dispatcher: WireGuardDispatcher<Weak<Peer>>,
    raw_packet_tx: mpsc::Sender<(bytes::Bytes, Option<SocketAddr>)>,
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
}

impl From<NewTunnelError> for NewPeerError {
    fn from(_: NewTunnelError) -> Self {
        NewPeerError::TunnelNotAvaliable
    }
}

impl Router {
    pub fn new(id: u128, static_private_key: Arc<X25519SecretKey>) -> Arc<Self> {
        let static_public_key = Arc::new(static_private_key.clone().public_key());
        let (producer, consumer) = mpsc::channel(128);
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
        });
        tokio::spawn(router_routing_rx_thread_body(
            Arc::downgrade(&router),
            consumer,
        ));
        router
    }

    pub fn find_peer_by_public_key(&self, key: &X25519PublicKey) -> Option<Arc<Peer>> {
        let peers = self.peers.read();
        for peer in peers.iter() {
            if let Ok(_) = peer.static_public_key.constant_time_is_equal(key) {
                return Some(peer.clone());
            }
        }
        None
    }

    pub fn find_peer_by_id(&self, id: u128) -> Option<Arc<Peer>> {
        let peers = self.peers.read();
        for peer in peers.iter() {
            if peer.id == id {
                return Some(peer.clone());
            }
        }
        None
    }

    pub fn new_peer(&self, id: u128, static_public_key: Arc<X25519PublicKey>) -> Result<Arc<Peer>, NewPeerError> {
        let tunidx = self.wg_dispatcher.next_idx()?;
        let tunn = self.wg_dispatcher.new_tunnel(tunidx, static_public_key.clone(), None, None)?;
        let peer = Peer::new_arc(id, static_public_key.clone(), tunn.clone());
        self.wg_dispatcher.set_tunnel(tunidx, tunn, Arc::downgrade(&peer));
        let mut peers = self.peers.write();
        peers.push(peer.clone());
        Ok(peer)
    }

    pub fn bind(self: Arc<Self>, port_number: u16, rx_backlog: usize) -> io::Result<Arc<Socket>> {
        let mut opened_sockets = self.opened_sockets.write();
        let port = if port_number == 0 {
            match Self::find_avaliable_application_port(&mut opened_sockets) {
                Some(port) => port,
                None => return Err(io::Error::from(io::ErrorKind::AddrInUse)),
            }
        } else {
            port_number
        };
        let (socket, prod) = Socket::new(self.clone(), port, rx_backlog);
        opened_sockets.insert(port, (Arc::downgrade(&socket), prod));
        Ok(socket)
    }

    fn find_avaliable_application_port(
        opened_sockets: &mut HashMap<u16, (Weak<Socket>, ringbuf::Producer<BoxedPacket>)>,
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

    async fn route_packet(&self, packet: BoxedPacket) -> RoutingResult {
        let header = packet.get_header();
        if header.dst_addr_cmp(self.id) {
            self.route_packet_local(packet)
        } else {
            self.route_packet_remote(packet).await
        }
    }

    fn route_packet_local(&self, packet: BoxedPacket) -> RoutingResult {
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

    async fn route_packet_remote(&self, packet: BoxedPacket) -> RoutingResult {
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

    pub fn attach_rx(&self, rx: Rx) {
        let sender = self.raw_packet_tx.clone();
        tokio::spawn(async move {
            loop {
                let mut buf = bytes::BytesMut::new();
                buf.resize(65535, 0);
                match rx.recv_from(&mut buf).await {
                    Ok((size, addr)) => {
                        buf.resize(size, 0);
                        match sender.send((buf.freeze(), addr)).await {
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
}

pub struct Socket {
    router: Arc<Router>,
    port: u16,
    rx_ringbuf_cons: Mutex<ringbuf::Consumer<BoxedPacket>>,
    rx_notify: tokio::sync::Notify,
}

impl Socket {
    fn new(
        router: Arc<Router>,
        port: u16,
        rx_backlog: usize,
    ) -> (Arc<Self>, ringbuf::Producer<BoxedPacket>) {
        let (prod, cons) = ringbuf::RingBuffer::new(rx_backlog).split();
        (
            Arc::new(Self {
                router,
                port,
                rx_ringbuf_cons: Mutex::new(cons),
                rx_notify: tokio::sync::Notify::new(),
            }),
            prod,
        )
    }

    fn try_recv(&self) -> Option<BoxedPacket> {
        self.rx_ringbuf_cons.lock().pop()
    }

    pub async fn recv_packet(&self) -> BoxedPacket {
        loop {
            if let Some(packet) = self.try_recv() {
                break packet;
            } else {
                self.rx_notify.notified().await;
            }
        }
    }

    pub async fn send_packet(&self, packet: BoxedPacket) -> io::Result<()> {
        let header = packet.get_header();
        match self.router.route_packet(packet).await {
            RoutingResult::Ok => Ok(()),
            RoutingResult::IOE(e) => Err(e),
            RoutingResult::BrokenPipe => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            RoutingResult::QueueFull => {
                warn!(target: "Socket.send_packet", "({}) Queue is full.", self.get_local_port());
                Ok(())
            } // drop in slient
            RoutingResult::UnboundPort => {
                warn!(target: "Socket.send_packet", "Unbound port {}.", header.dst_port);
                Ok(())
            }
            RoutingResult::NoDest => {
                warn!(target: "Socket.send_packet", "No destination avaliable for {}.", header.dst_addr_int());
                Ok(())
            }
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
                self.router.id,
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
