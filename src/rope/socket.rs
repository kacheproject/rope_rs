use std::io;
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;
use std::sync::Arc;
use super::Msg;
use super::rpv6::{BoxedPacket, Packet, self};

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
    pub(super) fn new(
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

    pub(super) fn get_router_dropped(&self) -> bool {
        self.opts.read().router_dropped
    }

    pub(super) fn set_router_dropped(&self, value: bool) -> bool {
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

    pub fn get_router_id(&self) -> u128 {
        self.router_id
    }

    pub(super) fn notify_one(&self) {
        self.rx_notify.notify_one();
    }

    pub(super) fn notify_waiters(&self) {
        self.rx_notify.notify_waiters()
    }
}
