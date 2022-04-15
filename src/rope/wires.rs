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
pub struct UdpTx {
    transport: UdpTransport,
    dst_addr: SocketAddr,
}

impl UdpTx {
    pub fn new(transport: UdpTransport, dst_addr: SocketAddr) -> Self {
        Self {
            transport,
            dst_addr,
        }
    }
}

#[async_trait]
impl Tx for UdpTx {
    async fn send_to(
        &self,
        buf: &[u8],
    ) -> io::Result<usize>
    {
        let socket = &self.transport;
        let addr = &self.dst_addr;
        {
            let mut stat = socket.status.lock();
            let time = chrono::Utc::now().timestamp();
            stat.time_last_sent = time;
            let timeout = stat.is_timeout(2);
            let meter = &mut stat.meter;
            meter.note_tx(time, buf.len());
            if timeout {
                meter.note_unavaliable(time);
            }
        }
        socket.send_to(buf, addr).await
    }

    fn get_availability(&self) -> f64 {
        self.transport.status.lock().meter.get_availability()
    }

    fn is_removable(&self) -> bool {
        let transport = &self.transport;
        let status = transport.status.lock();
        let is_receiving = chrono::Utc::now().timestamp().saturating_sub(status.time_last_recv) > 300; // 5 mins
        let is_timeout = status.is_timeout(300);
        is_receiving && is_timeout
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

}

#[async_trait]
pub trait Rx: Debug + Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, ExternalAddr)>;
}

#[derive(Debug)]
pub struct UdpTransportRx {
    transport: UdpTransport
}

impl UdpTransportRx {
    pub fn new(transport: UdpTransport) -> Self {
        Self {
            transport,
        }
    }
}

#[async_trait]
impl Rx for UdpTransportRx {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, ExternalAddr)> {
        match self.transport.recv_from(buf).await {
            Ok((size, addr)) => {
                {
                    let mut stat = self.transport.status.lock();
                    let time = chrono::Utc::now().timestamp();
                    stat.time_last_recv = time;
                    let meter = &mut stat.meter;
                    meter.note_rx(time, size);
                    meter.note_avaliable(time);
                }
                Result::Ok((size, ExternalAddr::Udp(addr)))
            }
            Err(e) => Result::Err(e),
        }
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

#[derive(Debug)]
struct UdpTransportStatus {
    meter: NetworkMeter,
    time_last_sent: i64,
    time_last_recv: i64,
}

impl UdpTransportStatus {
    pub fn is_timeout(&self, timeout: i64) -> bool {
        self.time_last_recv
            .saturating_sub(self.time_last_sent)
            .abs()
            >= timeout
    }

    pub fn new() -> Self {
        UdpTransportStatus {
            meter: NetworkMeter::new(),
            time_last_recv: 0,
            time_last_sent: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    status: Arc<parking_lot::Mutex<UdpTransportStatus>>,
}

impl std::ops::Deref for UdpTransport {
    type Target = UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl Transport for UdpTransport {
    type Addr = SocketAddr;

    fn create_tx(&self, addr: SocketAddr) -> Box<dyn Tx> {
        Box::new(UdpTx::new(self.clone(), addr))
    }

    fn create_rx(&self) -> Box<dyn Rx> {
        Box::new(UdpTransportRx::new(self.clone()))
    }
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            status: Arc::new(parking_lot::Mutex::new(UdpTransportStatus::new())),
        }
    }
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
