use async_trait::async_trait;
use std::fmt::Debug;
use std::io;


use super::ExternalAddr;

#[async_trait]
pub trait Tx: Debug + Send + Sync {
    async fn send_to(&self, buf: &[u8]) -> io::Result<usize>;

    fn get_availability(&self) -> f64;

    fn is_removable(&self) -> bool;

    fn is_match_addr(&self, exaddr: ExternalAddr) -> bool;

    /// Return the external destination address
    fn get_external_address(&self) -> ExternalAddr;
}

#[async_trait]
pub trait Rx: Debug + Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, ExternalAddr)>;
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

pub trait DefaultTransport: std::fmt::Debug + Sync + Send {
    fn create_tx_from_exaddr(&self, addr: &ExternalAddr) -> Result<Box<dyn Tx>, &'static str>;
}
