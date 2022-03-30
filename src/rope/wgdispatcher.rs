use crate::rope::utils;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{handshake, Tunn};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use log::*;
use super::utils::NoDupSenderIdCounter;

/// A WireGuard Tunnel Dispatcher.
/// ## Safety
/// This object is completely thread-safe. The user value will be cloned for the dispatch and will not be used by this object.
pub struct WireGuardDispatcher<T: Clone> {
    static_secret: Arc<X25519SecretKey>,
    static_public: Arc<X25519PublicKey>,
    mapping: RwLock<HashMap<u32, (Arc<Tunn>, T)>>,
    counter: Mutex<utils::NoDupSenderIdCounter>,
}

pub enum DispatchResult<T> {
    NewTunnel(X25519PublicKey),
    Dispatch(Arc<Tunn>, T, u32),
    Err(DispatchError),
}

#[derive(Debug)]
pub enum DispatchError {
    WireGuard(WireGuardError),
    TunnelNotFound([u8; 4]),
}

impl<T> From<DispatchError> for DispatchResult<T> {
    fn from(e: DispatchError) -> Self {
        DispatchResult::Err(e)
    }
}

#[derive(Debug)]
pub enum NewTunnelError {
    InvalidParameter,
    NoAvaliableIdx,
}

impl<T: Clone> WireGuardDispatcher<T> {
    fn dispatch_to<'a>(&self, peeridx: u32) -> DispatchResult<T> {
        let mapping = self.mapping.read();
        if let Some((tunnel, t)) = mapping.get(&peeridx) {
            DispatchResult::Dispatch(tunnel.clone(), t.clone(), peeridx)
        } else {
            DispatchResult::Err(DispatchError::TunnelNotFound(peeridx.to_le_bytes()))
        }
    }

    /// boringtun use first 24 bits as peer index.
    fn get_peer_index(index: u32) -> u32 {
        index >> 8
    }

    pub fn dispatch<'a>(&self, data: &'a [u8]) -> DispatchResult<T> {
        use boringtun::noise::Packet;
        match Tunn::parse_incoming_packet(data) {
            Ok(packet) => match packet {
                Packet::HandshakeInit(init) => {
                    match handshake::parse_handshake_anon(
                        &self.static_secret,
                        &self.static_public,
                        &init,
                    ) {
                        Ok(half_handshake) => DispatchResult::NewTunnel(X25519PublicKey::from(
                            &half_handshake.peer_static_public[..],
                        )),
                        Err(e) => DispatchError::WireGuard(e).into(),
                    }
                }
                Packet::HandshakeResponse(response) => self.dispatch_to(Self::get_peer_index(response.receiver_idx)),
                Packet::PacketCookieReply(reply) => self.dispatch_to(Self::get_peer_index(reply.receiver_idx)),
                Packet::PacketData(packet_data) => self.dispatch_to(Self::get_peer_index(packet_data.receiver_idx)),
            },
            Err(e) => DispatchResult::Err(DispatchError::WireGuard(e)),
        }
    }

    pub fn new_tunnel_and_set(
        &self,
        peer_pk: Arc<X25519PublicKey>,
        preshared_key: Option<[u8; 32]>,
        presistent_keepalive: Option<u16>,
        user_value: T,
    ) -> Result<(u32, Arc<Tunn>), NewTunnelError> {
        let idx = self.next_idx()?;
        let tunn = self.new_tunnel(idx, peer_pk, preshared_key, presistent_keepalive)?;
        self.set_tunnel(idx, tunn.clone(), user_value);
        Ok((idx, tunn))
    }

    pub fn next_idx(&self) -> Result<u32, NewTunnelError> {
        if let Some(idx) = self.counter.lock().next() {
            Ok(idx)
        } else {
            Err(NewTunnelError::NoAvaliableIdx)
        }
    }

    pub fn set_tunnel(&self, idx: u32, tunnel: Arc<Tunn>, user_value: T) {
        let mut mapping = self.mapping.write();
        let _ = mapping.insert(idx, (tunnel, user_value));
        trace!("tunnel {:?} is set.", idx.to_le_bytes());
    }

    pub fn new_tunnel(
        &self,
        idx: u32,
        peer_pk: Arc<X25519PublicKey>,
        preshared_key: Option<[u8; 32]>,
        presistent_keepalive: Option<u16>,
    ) -> Result<Arc<Tunn>, NewTunnelError> {
        if let Ok(tun) = Tunn::new(
            self.static_secret.clone(),
            peer_pk.clone(),
            preshared_key,
            presistent_keepalive,
            idx,
            None,
        ) {
            Ok(Arc::from(tun))
        } else {
            Err(NewTunnelError::InvalidParameter)
        }
    }

    pub fn unset_tunnel(&self, idx: u32) {
        let mut mapping = self.mapping.write();
        let _ = mapping.remove(&idx);
    }

    pub fn new(static_secret: Arc<X25519SecretKey>, static_public: Arc<X25519PublicKey>) -> Self {
        Self {
            static_public,
            static_secret,
            mapping: RwLock::new(HashMap::new()),
            counter: Mutex::new(NoDupSenderIdCounter::new()),
        }
    }
}
