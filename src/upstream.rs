use crate::error::Result;
use crate::socks5::{self, UpstreamAuth};
use std::net::IpAddr;
use tokio::net::TcpStream;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5Proxy {
    pub address: String,
    pub auth: Option<UpstreamAuth>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum UpstreamProxy {
    #[default]
    Direct,
    Socks5(Socks5Proxy),
}

impl UpstreamProxy {
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        match self {
            Self::Direct => Ok(TcpStream::connect(tcp_target(host, port)).await?),
            Self::Socks5(proxy) => {
                let mut stream = TcpStream::connect(proxy.address.as_str()).await?;
                socks5::connect_upstream(&mut stream, host, port, proxy.auth.as_ref()).await?;
                Ok(stream)
            }
        }
    }
}

fn tcp_target(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}
