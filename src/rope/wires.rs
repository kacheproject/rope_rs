use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use super::netmeter::NetworkMeter;

#[derive(Debug, Clone)]
pub enum Tx {
    Udp((UdpTransport, <UdpTransport as Transport>::Addr)),
    ChanPair(mpsc::Sender<Box<[u8]>>),
}

impl Tx {
    pub async fn send_to(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Tx::Udp((socket, addr)) => {
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
            Tx::ChanPair(tx) => {
                let boxed_slice = Vec::from(buf).into_boxed_slice();
                let size = buf.len();
                match tx.send(boxed_slice).await {
                    Ok(_) => Ok(size),
                    Err(_) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                }
            }
        }
    }

    pub fn get_availability(&self) -> f64 {
        match self {
            Tx::ChanPair(tx) => {
                if !tx.is_closed() {
                    1.0
                } else {
                    0.0
                }
            },
            Tx::Udp((transport, _)) => {
                transport.status.lock().meter.get_availability()
            },
        }
    }
}

#[derive(Debug)]
pub enum Rx {
    Udp(UdpTransport),
    ChanPair(Arc<Mutex<mpsc::Receiver<Box<[u8]>>>>),
}

impl Rx {
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
        match self {
            Rx::Udp(socket) => match socket.recv_from(buf).await {
                Ok((size, addr)) => {
                    {
                        let mut stat = socket.status.lock();
                        let time = chrono::Utc::now().timestamp();
                        stat.time_last_recv = time;
                        let meter = &mut stat.meter;
                        meter.note_rx(time, size);
                        meter.note_avaliable(time);
                    }
                    Result::Ok((size, Option::Some(addr)))
                }
                Err(e) => Result::Err(e),
            },
            Rx::ChanPair(rx_mutex) => {
                let mut rx = rx_mutex.lock().await;
                if let Some(data) = rx.recv().await {
                    let copy_size = std::cmp::min(data.len(), buf.len());
                    for i in 0..copy_size {
                        buf[i] = data[i]
                    }
                    Ok((data.len(), Option::None))
                } else {
                    Err(io::Error::from(io::ErrorKind::BrokenPipe))
                }
            }
        }
    }
}

/// Transport is for two-way connection-less data delivery methods.
pub trait Transport
where
    Self: Sized,
{
    type Addr;

    fn create_tx(&self, addr: Self::Addr) -> Tx;

    fn create_rx(&self) -> Rx;
}

/// ConnectedTransport is for two way connected data delivery methods.
pub trait ConnectedTransport
where
    Self: Sized,
{
    fn create_tx(&self) -> Tx;
    fn create_rx(&self) -> Rx;
}

#[derive(Debug)]
struct UdpTransportStatus {
    meter: NetworkMeter,
    time_last_sent: i64,
    time_last_recv: i64,
}

impl UdpTransportStatus {
    pub fn is_timeout(&self, timeout: i64) -> bool {
        self.time_last_recv.saturating_sub(self.time_last_sent).abs() >= timeout
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

    fn create_tx(&self, addr: SocketAddr) -> Tx {
        Tx::Udp((self.clone(), addr))
    }

    fn create_rx(&self) -> Rx {
        Rx::Udp(self.clone())
    }
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            status: Arc::new(parking_lot::Mutex::new(UdpTransportStatus {
                meter: NetworkMeter::new(),
                time_last_recv: 0,
                time_last_sent: 0,
            })),
        }
    }
}

#[derive(Clone, Debug)]
pub struct InprocTransport {
    sender: mpsc::Sender<Box<[u8]>>,
    receiver: Arc<Mutex<mpsc::Receiver<Box<[u8]>>>>,
}

impl ConnectedTransport for InprocTransport {
    fn create_tx(&self) -> Tx {
        Tx::ChanPair(self.sender.clone())
    }

    fn create_rx(&self) -> Rx {
        Rx::ChanPair(self.receiver.clone())
    }
}
