use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const USERPASS_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressKind {
    Domain,
    Ip,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksConnectRequest {
    pub host: String,
    pub port: u16,
    pub address_kind: AddressKind,
    pub profile: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Error, Debug)]
pub enum SocksError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),

    #[error("SOCKS5 client offered no acceptable authentication method")]
    NoAcceptableAuthMethod,

    #[error("invalid SOCKS5 username/password auth version: {0}")]
    InvalidAuthVersion(u8),

    #[error("unsupported SOCKS5 command: {0}")]
    UnsupportedCommand(u8),

    #[error("invalid SOCKS5 reserved byte: {0}")]
    InvalidReservedByte(u8),

    #[error("unsupported SOCKS5 address type: {0}")]
    UnsupportedAddressType(u8),

    #[error("invalid SOCKS5 domain address")]
    InvalidDomain,
}

pub async fn accept_connect<S>(stream: &mut S) -> Result<SocksConnectRequest, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let username = negotiate_auth(stream).await?;
    read_connect_request(stream, username).await
}

async fn negotiate_auth<S>(stream: &mut S) -> Result<Option<String>, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let selected = if methods.contains(&METHOD_USERNAME_PASSWORD) {
        METHOD_USERNAME_PASSWORD
    } else if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        stream.write_all(&[VERSION, METHOD_NO_ACCEPTABLE]).await?;
        return Err(SocksError::NoAcceptableAuthMethod);
    };

    stream.write_all(&[VERSION, selected]).await?;

    if selected == METHOD_USERNAME_PASSWORD {
        let username = read_username_password_auth(stream).await?;
        Ok(parse_profile_username(&username))
    } else {
        Ok(None)
    }
}

async fn read_username_password_auth<S>(stream: &mut S) -> Result<String, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != USERPASS_VERSION {
        stream.write_all(&[USERPASS_VERSION, 0x01]).await.ok();
        return Err(SocksError::InvalidAuthVersion(version));
    }

    let ulen = stream.read_u8().await? as usize;
    let mut username = vec![0u8; ulen];
    stream.read_exact(&mut username).await?;

    let plen = stream.read_u8().await? as usize;
    let mut password = vec![0u8; plen];
    stream.read_exact(&mut password).await?;

    stream.write_all(&[USERPASS_VERSION, 0x00]).await?;

    Ok(String::from_utf8_lossy(&username).into_owned())
}

fn parse_profile_username(username: &str) -> Option<String> {
    let value = username.trim();
    if value.is_empty() {
        return None;
    }

    let profile = value.strip_prefix("profile=").unwrap_or(value).trim();
    if profile.is_empty() {
        None
    } else {
        Some(profile.to_string())
    }
}

async fn read_connect_request<S>(
    stream: &mut S,
    profile: Option<String>,
) -> Result<SocksConnectRequest, SocksError>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let command = stream.read_u8().await?;
    if command != CMD_CONNECT {
        return Err(SocksError::UnsupportedCommand(command));
    }

    let reserved = stream.read_u8().await?;
    if reserved != 0x00 {
        return Err(SocksError::InvalidReservedByte(reserved));
    }

    let atyp = stream.read_u8().await?;
    let (host, address_kind) = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            (
                IpAddr::V4(Ipv4Addr::from(octets)).to_string(),
                AddressKind::Ip,
            )
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                return Err(SocksError::InvalidDomain);
            }
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            let host = String::from_utf8(name).map_err(|_| SocksError::InvalidDomain)?;
            (host, AddressKind::Domain)
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            (
                IpAddr::V6(Ipv6Addr::from(octets)).to_string(),
                AddressKind::Ip,
            )
        }
        other => return Err(SocksError::UnsupportedAddressType(other)),
    };

    let port = stream.read_u16().await?;

    Ok(SocksConnectRequest {
        host,
        port,
        address_kind,
        profile,
    })
}

pub async fn write_reply<S>(stream: &mut S, reply: Reply) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, reply as u8, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn accepts_username_profile_and_domain_connect() {
        let (mut client, mut server) = duplex(256);

        let client_task = tokio::spawn(async move {
            client
                .write_all(&[0x05, 0x01, 0x02])
                .await
                .expect("write greeting");
            let mut method_resp = [0u8; 2];
            client
                .read_exact(&mut method_resp)
                .await
                .expect("read method response");
            assert_eq!(method_resp, [0x05, 0x02]);

            client
                .write_all(&[0x01, 0x0f])
                .await
                .expect("write auth prefix");
            client
                .write_all(b"profile=firefox")
                .await
                .expect("write username");
            client
                .write_all(&[0x00])
                .await
                .expect("write empty password");
            let mut auth_resp = [0u8; 2];
            client
                .read_exact(&mut auth_resp)
                .await
                .expect("read auth response");
            assert_eq!(auth_resp, [0x01, 0x00]);

            client
                .write_all(&[0x05, 0x01, 0x00, 0x03, 0x0b])
                .await
                .expect("write request prefix");
            client
                .write_all(b"example.com")
                .await
                .expect("write domain");
            client
                .write_all(&443u16.to_be_bytes())
                .await
                .expect("write port");
        });

        let req = accept_connect(&mut server)
            .await
            .expect("SOCKS5 request should parse");
        client_task.await.expect("client task");

        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert_eq!(req.address_kind, AddressKind::Domain);
        assert_eq!(req.profile.as_deref(), Some("firefox"));
    }
}
