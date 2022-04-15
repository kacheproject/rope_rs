use std::{net::{SocketAddr, IpAddr}, str::FromStr};
use url::Url;

#[derive(Clone, PartialEq, Debug)]
pub enum ExternalAddr {
    None,
    Udp(SocketAddr),
    Other(Url),
}

impl From<&ExternalAddr> for Option<std::net::IpAddr> {
    fn from(value: &ExternalAddr) -> Self {
        match value {
            ExternalAddr::None => None,
            ExternalAddr::Udp(sockaddr) => Some(sockaddr.ip()),
            ExternalAddr::Other(_) => None,
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
            ExternalAddr::Other(_) => None,
        }
    }
}

impl From<ExternalAddr> for Option<std::net::SocketAddr> {
    fn from(value: ExternalAddr) -> Self {
        (&value).into()
    }
}

impl ExternalAddr {
    pub fn protocol<'a>(&'a self) -> &'a str {
        match self {
            Self::None => "none",
            Self::Udp(_) => "udp",
            Self::Other(uri) => uri.scheme(),
        }
    }
}


impl From<ExternalAddr> for Option<Url> {
    fn from(addr: ExternalAddr) -> Self {
        match addr {
            ExternalAddr::None => None,
            ExternalAddr::Udp(sockaddr) => {
                let uri_str = match sockaddr.ip() {
                    std::net::IpAddr::V4(ipv4) => format!("udp://{}:{}", ipv4, sockaddr.port()),
                    std::net::IpAddr::V6(ipv6) => format!("udp://[{}]:{}", ipv6, sockaddr.port()),
                };
                let uri = url::Url::parse(&uri_str).unwrap(); // It should not fail
                Some(uri)
            },
            ExternalAddr::Other(uri) => Some(uri),
        }
    }
}

pub enum ParseError {
    UrlParseError(url::ParseError),
    HostInvalid,
    PortNotFound,
}

impl FromStr for ExternalAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = Url::parse(s).map_err(ParseError::UrlParseError)?;
        match uri.scheme() {
            "udp" => {
                if let Some(host) = uri.host() {
                    let ip = match host {
                        url::Host::Domain(_) => return Err(ParseError::HostInvalid), // We could not resolve domain here
                        url::Host::Ipv4(ipv4) => IpAddr::V4(ipv4),
                        url::Host::Ipv6(ipv6) => IpAddr::V6(ipv6),
                    };
                    let port = match uri.port() {
                        Some(n) => n,
                        None => return Err(ParseError::PortNotFound),
                    };
                    Ok(ExternalAddr::Udp(SocketAddr::new(ip, port)))
                } else {
                    Err(ParseError::HostInvalid)
                }
            },
            _ => Ok(ExternalAddr::Other(uri))
        }
    }
}
