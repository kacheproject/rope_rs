use async_trait::async_trait;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};


use super::netmeter::NetworkMeter;
use super::ExternalAddr;

#[async_trait]
pub trait Tx: Debug + Send + Sync {
    async fn send_to(&self, buf: &[u8]) -> io::Result<usize>;

    fn get_availability(&self) -> f64;

    fn is_removable(&self) -> bool;
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

}

#[async_trait]
pub trait Rx: Debug + Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, ExternalAddr)>;
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

/// Transport is for two-way connection-less data delivery methods.
pub trait Transport
where
    Self: Sized,
{
    type Addr;

    fn create_tx(&self, addr: Self::Addr) -> Box<dyn Tx>;

    fn create_rx(&self) -> Box<dyn Rx>;
}

/// ConnectedTransport is for two way connected data delivery methods.
pub trait ConnectedTransport
where
    Self: Sized,
{
    fn create_tx(&self) -> Box<dyn Tx>;
    fn create_rx(&self) -> Box<dyn Rx>;
}

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
