use std::io;
use std::sync::Arc;
use tokio::net::UdpSocket;
use async_trait::async_trait;
use std::net::SocketAddr;
use crate::rope::wires::{Tx, Rx, Transport, DefaultTransport};
use crate::utils::netmeter::NetworkMeter;
use crate::rope::ExternalAddr;

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
            let timeout = stat.time_last_sent.saturating_sub(stat.time_last_recv);
            // TODO: use beter algorithm to estimate is this tx alive since
            // we allow different tx and rx for single transmission.
            let time = chrono::Utc::now().timestamp();
            stat.time_last_sent = time;
            let meter = &mut stat.meter;
            meter.note_tx(time, buf.len());
            match timeout {
                300.. => {
                    meter.note_unavaliable(time);
                },
                _ => {},
            }
        }
        socket.send_to(buf, addr).await
    }

    fn get_availability(&self) -> f64 {
        self.transport.status.lock().meter.get_availability()
    }

    fn is_removable(&self) -> bool {
        let transport = &self.transport;
        let stat = transport.status.lock();
        stat.time_last_recv.saturating_sub(stat.time_last_sent) >= 300
    }

    fn is_match_addr(&self, exaddr: ExternalAddr) -> bool {
        match exaddr {
            ExternalAddr::Udp(sockaddr) => self.dst_addr == sockaddr,
            _ => false
        }
    }

    fn get_external_address(&self) -> ExternalAddr {
        ExternalAddr::Udp(self.dst_addr)
    }
}

#[derive(Debug)]
struct UdpTransportStatus {
    meter: NetworkMeter,
    time_last_sent: i64,
    time_last_recv: i64,
}

impl UdpTransportStatus {
    pub fn new() -> Self {
        UdpTransportStatus {
            meter: NetworkMeter::new(),
            time_last_recv: 0,
            time_last_sent: 0,
        }
    }
}

#[derive(Clone)]
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

impl std::fmt::Debug for UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("UdpTransport {{ socket.local_addr(): {:?}, status: {:?} }}", self.socket.local_addr(), self.status))
    }
}

impl Transport for UdpTransport {
    type Addr = SocketAddr;

    fn create_tx(&self, addr: SocketAddr) -> Box<dyn Tx> {
        Box::new(UdpTx::new(self.clone(), addr))
    }

    fn create_rx(&self) -> Box<dyn Rx> {
        Box::new(UdpRx::new(self.clone()))
    }
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            status: Arc::new(parking_lot::Mutex::new(UdpTransportStatus::new())),
        }
    }

    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self::new(socket))
    }

    fn with_fresh_status(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            status: Arc::new(parking_lot::Mutex::new(UdpTransportStatus::new())),
        }
    }
}


impl DefaultTransport for UdpTransport {
    fn create_tx_from_exaddr(&self, addr: &ExternalAddr) -> Result<Box<dyn Tx>, &'static str> {
        match addr {
            ExternalAddr::Udp(sockaddr) => {
                Ok(self.with_fresh_status().create_tx(sockaddr.clone()))
            },
            _ => Err("unexpected protocol")
        }
    }
}

#[derive(Debug)]
pub struct UdpRx {
    transport: UdpTransport
}

impl UdpRx {
    pub fn new(transport: UdpTransport) -> Self {
        Self {
            transport,
        }
    }
}

#[async_trait]
impl Rx for UdpRx {
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
