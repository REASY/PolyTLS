use crate::error::Result;
use crate::socks5::{self, UpstreamAuth};
use std::io;
use std::net::IpAddr;
use tokio::net::{TcpStream, lookup_host};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5Proxy {
    pub address: String,
    pub auth: Option<UpstreamAuth>,
    pub dns: Socks5DnsPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Socks5DnsPolicy {
    #[default]
    Proxy,
    Local,
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
                let target = proxy.connect_target(host, port).await?;
                socks5::connect_upstream(
                    &mut stream,
                    target.host.as_str(),
                    target.port,
                    proxy.auth.as_ref(),
                )
                .await?;
                Ok(stream)
            }
        }
    }
}

impl Socks5Proxy {
    async fn connect_target(&self, host: &str, port: u16) -> Result<UpstreamTarget> {
        match self.dns {
            Socks5DnsPolicy::Proxy => Ok(UpstreamTarget {
                host: host.to_string(),
                port,
            }),
            Socks5DnsPolicy::Local => resolve_locally(host, port).await,
        }
    }
}

struct UpstreamTarget {
    host: String,
    port: u16,
}

async fn resolve_locally(host: &str, port: u16) -> Result<UpstreamTarget> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(UpstreamTarget {
            host: host.to_string(),
            port,
        });
    }

    let addrs: Vec<_> = lookup_host(tcp_target(host, port)).await?.collect();
    let selected = addrs
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("local DNS lookup returned no addresses for {host}:{port}"),
            )
        })?;

    tracing::info!(
        target_host = %host,
        target_port = port,
        upstream_host = %selected.ip(),
        upstream_port = selected.port(),
        "resolved upstream SOCKS5 target locally"
    );

    Ok(UpstreamTarget {
        host: selected.ip().to_string(),
        port: selected.port(),
    })
}

fn tcp_target(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}
