use boringtun::crypto::X25519PublicKey;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use log::*;
use parking_lot::{Mutex, RwLock};
use std::io;
use std::ops::Deref;
use std::sync::{Arc, Weak};
use super::wires::Tx;
use super::ExternalAddr;

pub struct Peer {
    id: u128,
    static_public_key: Arc<X25519PublicKey>,
    txs: RwLock<Vec<Arc<dyn Tx>>>,
    pub(crate) wgtunn: Arc<Tunn>,
    current_tx: Mutex<Option<Weak<dyn Tx>>>,
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
            current_tx: Mutex::new(None),
        }
    }

    /// Scan all txs and remove the ones are removable.
    /// This function will hold read-write lock on .txs.
    pub fn gc_tx(&self) {
        let mut txs = self.txs.write();
        let old_len = txs.len();
        txs.retain(|v| !v.is_removable());
        debug!("Peer {} tx garbage collected: from {} to {}.", self.get_id(), old_len, txs.len());
    }

    /// Scan all txs and choose one with largest availability.
    /// This function will hold lock on .current_tx and read-write lock on .txs.
    fn select_tx_slow(&self) -> Option<Arc<dyn Tx>> {
        self.gc_tx();
        let txs = self.txs.read();
        let best_tx = txs.iter().fold(None, |prev: Option<&Arc<dyn Tx>>, next| match prev {
            Some(prev_tx) => if next.get_availability() > prev_tx.get_availability() { Some(next) } else { Some(prev_tx) },
            None => Some(next)
        }).cloned();
        *self.current_tx.lock() = match best_tx.clone() {
            Some(tx) => Some(Arc::downgrade(&tx)),
            None => None,
        };
        debug!("choose {:?} for peer {}, {} tx available.", best_tx, self.id, txs.len());
        best_tx
    }

    fn select_tx(&self, prefer_address: Option<&ExternalAddr>) -> Option<Arc<dyn Tx>> {
        if let Some(addr) = prefer_address {
            if let Some(tx) = self.find_tx_of_addr(addr.clone()) {
                return Some(tx)
            }
        }
        let current_tx = self.current_tx.lock();
        if let Some(tx_weakref) = current_tx.deref() {
            if let Some(tx) = tx_weakref.upgrade() {
                if tx.get_availability() <= 0.6 {
                    std::mem::drop(current_tx); // avoid deadlock
                    self.select_tx_slow()
                } else {
                    Some(tx)
                }
            } else {
                std::mem::drop(current_tx); // avoid deadlock
                self.select_tx_slow()
            }
        } else {
            std::mem::drop(current_tx); // avoid deadlock
            self.select_tx_slow()
        }
    }


    /// Encrypt src, write to dst, and send.
    /// The size of dst should be src.len() + 32 and should not be less than 148 bytes.
    pub(crate) async fn send_encrypted<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Result<usize, EncryptedSendError> {
        match self.wgtunn.encapsulate(src, dst) { // encapsulate() won't return TunnResult::Done
            TunnResult::Done => unreachable!(),
            TunnResult::WriteToNetwork(buf) => {
                match self.send(buf, None).await {
                    Ok(size) => Ok(size),
                    Err(e) => Err(EncryptedSendError::IOE(e)),
                }
                
            },
            TunnResult::WriteToTunnelV4(_, _) => unreachable!(),
            TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
            TunnResult::Err(e) => Err(EncryptedSendError::WireGuard(e)),
        }
    }

    /// Send cleartext though any tx.
    /// Return WouldBlock if no tx avaliable.
    pub(crate) async fn send(&self, data: &[u8], prefer_address: Option<&ExternalAddr>) -> io::Result<usize> {
        if let Some(tx) = self.select_tx(prefer_address) {
            tx.send_to(data).await
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    /// Add a tx to peer.
    pub fn add_tx(&self, tx: Box<dyn Tx>) {
        let mut txs = self.txs.write();
        let txref: Arc<dyn Tx> = Arc::from(tx);
        txs.push(txref.clone());
        trace!("Peer {} add tx: {:?}", self.get_id(), txref);
    }

    pub fn clear_tx(&self) {
        let mut txs = self.txs.write();
        txs.clear();
        txs.shrink_to(0);
    }

    pub fn get_id(&self) -> u128 {
        self.id
    }

    pub fn find_tx_of_addr(&self, exaddr: ExternalAddr) -> Option<Arc<dyn Tx>> {
        let txs = self.txs.read();
        let mut result = None;
        for tx in txs.iter() {
            if tx.is_match_addr(exaddr.clone()) {
                result =  Some(tx.clone());
                break;
            }
        }
        result
    }

    pub fn get_public_key(&self) -> Arc<X25519PublicKey> {
        self.static_public_key.clone()
    }

    pub(crate) fn get_all_tx(&self) -> parking_lot::RwLockReadGuard<'_, Vec<Arc<dyn Tx>>> {
        self.txs.read()
    }
}
