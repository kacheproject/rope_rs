use async_trait::async_trait;
use tokio::sync::mpsc;
use crate::rope::wires::{Tx, Rx, ConnectedTransport};
use tokio::sync::Mutex;
use std::sync::Arc;
use crate::rope::ExternalAddr;
use std::io;

#[derive(Clone, Debug)]
pub struct InprocTransport {
    sender: mpsc::Sender<Box<[u8]>>,
    receiver: Arc<Mutex<mpsc::Receiver<Box<[u8]>>>>,
}

impl ConnectedTransport for InprocTransport {
    fn create_tx(&self) -> Box<dyn Tx> {
        Box::new(ChanPairTx::new(self.sender.clone()))
    }

    fn create_rx(&self) -> Box<dyn Rx> {
        Box::new(self.receiver.clone())
    }
}

pub type ChanPairRx = Arc<Mutex<mpsc::Receiver<Box<[u8]>>>>;

#[async_trait]
impl Rx for ChanPairRx {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, ExternalAddr)> {
        let mut rx = self.lock().await;
        if let Some(data) = rx.recv().await {
            let copy_size = std::cmp::min(data.len(), buf.len());
            for i in 0..copy_size {
                buf[i] = data[i]
            }
            Ok((data.len(), ExternalAddr::None))
        } else {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }
}

#[derive(Debug)]
pub struct ChanPairTx { tx: mpsc::Sender<Box<[u8]>> }

impl ChanPairTx {
    pub fn new(tx: mpsc::Sender<Box<[u8]>>) -> Self {
        Self {
            tx,
        }
    }
}

#[async_trait]
impl Tx for ChanPairTx {
    async fn send_to(&self, buf: &[u8]) -> io::Result<usize> {
        let tx = &self.tx;
        let boxed_slice = Vec::from(buf).into_boxed_slice();
        let size = buf.len();
        match tx.send(boxed_slice).await {
            Ok(_) => Ok(size),
            Err(_) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }


    fn get_availability(&self) -> f64 {
        if !self.tx.is_closed() {
            1.0
        } else {
            0.0
        }
    }


    fn is_removable(&self) -> bool {
        self.tx.is_closed()
    }

    fn is_match_addr(&self, exaddr: ExternalAddr) -> bool {
        false
    }

    fn get_external_address(&self) -> ExternalAddr {
        ExternalAddr::None
    }
}
