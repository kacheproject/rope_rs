use std::net::SocketAddr;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ExternalAddr {
    None,
    Udp(SocketAddr),
}

impl From<&ExternalAddr> for Option<std::net::IpAddr> {
    fn from(value: &ExternalAddr) -> Self {
        match value {
            ExternalAddr::None => None,
            ExternalAddr::Udp(sockaddr) => Some(sockaddr.ip()),
        }
    }
}

impl From<ExternalAddr> for Option<std::net::IpAddr> {
    fn from(value: ExternalAddr) -> Self {
        (&value).into()
    }
}

impl From<&ExternalAddr> for Option<SocketAddr> {
    fn from(value: &ExternalAddr) -> Self {
        match value {
            ExternalAddr::None => None,
            ExternalAddr::Udp(sockaddr) => Some(sockaddr.clone()),
        }
    }
}

impl From<ExternalAddr> for Option<std::net::SocketAddr> {
    fn from(value: ExternalAddr) -> Self {
        (&value).into()
    }
}
