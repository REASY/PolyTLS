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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamAuth {
    pub username: String,
    pub password: String,
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

    #[error("SOCKS5 upstream selected unsupported auth method: {0:#x}")]
    UpstreamMethodRejected(u8),

    #[error("SOCKS5 upstream username/password auth failed: {0:#x}")]
    UpstreamAuthRejected(u8),

    #[error("SOCKS5 upstream CONNECT rejected: {0:#x}")]
    UpstreamConnectRejected(u8),

    #[error("invalid SOCKS5 upstream reply: {0}")]
    InvalidUpstreamReply(String),
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

pub async fn connect_upstream<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<&UpstreamAuth>,
) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method = if auth.is_some() {
        METHOD_USERNAME_PASSWORD
    } else {
        METHOD_NO_AUTH
    };
    stream.write_all(&[VERSION, 0x01, method]).await?;

    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let selected = stream.read_u8().await?;
    if selected != method {
        return Err(SocksError::UpstreamMethodRejected(selected));
    }

    if let Some(auth) = auth {
        write_upstream_auth(stream, auth).await?;
    }

    write_upstream_connect_request(stream, host, port).await?;
    read_upstream_connect_reply(stream).await
}

async fn write_upstream_auth<S>(stream: &mut S, auth: &UpstreamAuth) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(SocksError::InvalidUpstreamReply(
            "SOCKS5 username/password length exceeds 255 bytes".to_string(),
        ));
    }

    stream
        .write_all(&[USERPASS_VERSION, username.len() as u8])
        .await?;
    stream.write_all(username).await?;
    stream.write_all(&[password.len() as u8]).await?;
    stream.write_all(password).await?;

    let version = stream.read_u8().await?;
    if version != USERPASS_VERSION {
        return Err(SocksError::InvalidAuthVersion(version));
    }

    let status = stream.read_u8().await?;
    if status != 0x00 {
        return Err(SocksError::UpstreamAuthRejected(status));
    }

    Ok(())
}

async fn write_upstream_connect_request<S>(
    stream: &mut S,
    host: &str,
    port: u16,
) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[VERSION, CMD_CONNECT, 0x00]).await?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(addr) => {
                stream.write_all(&[ATYP_IPV4]).await?;
                stream.write_all(&addr.octets()).await?;
            }
            IpAddr::V6(addr) => {
                stream.write_all(&[ATYP_IPV6]).await?;
                stream.write_all(&addr.octets()).await?;
            }
        }
    } else {
        let host = host.as_bytes();
        if host.is_empty() || host.len() > u8::MAX as usize {
            return Err(SocksError::InvalidDomain);
        }
        stream.write_all(&[ATYP_DOMAIN, host.len() as u8]).await?;
        stream.write_all(host).await?;
    }

    stream.write_all(&port.to_be_bytes()).await?;
    Ok(())
}

async fn read_upstream_connect_reply<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let status = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    if reserved != 0x00 {
        return Err(SocksError::InvalidReservedByte(reserved));
    }

    let atyp = stream.read_u8().await?;
    read_upstream_bound_address(stream, atyp).await?;

    if status != 0x00 {
        return Err(SocksError::UpstreamConnectRejected(status));
    }

    Ok(())
}

async fn read_upstream_bound_address<S>(stream: &mut S, atyp: u8) -> Result<(), SocksError>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut discard = [0u8; 4 + 2];
            stream.read_exact(&mut discard).await?;
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut discard = vec![0u8; len + 2];
            stream.read_exact(&mut discard).await?;
        }
        ATYP_IPV6 => {
            let mut discard = [0u8; 16 + 2];
            stream.read_exact(&mut discard).await?;
        }
        other => return Err(SocksError::UnsupportedAddressType(other)),
    }
    Ok(())
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

    #[tokio::test]
    async fn upstream_connect_writes_no_auth_domain_request() {
        let (mut client, mut server) = duplex(256);

        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            server
                .write_all(&[0x05, 0x00])
                .await
                .expect("write method response");

            let mut request_prefix = [0u8; 5];
            server
                .read_exact(&mut request_prefix)
                .await
                .expect("read request prefix");
            assert_eq!(request_prefix, [0x05, 0x01, 0x00, 0x03, 0x0b]);

            let mut domain = [0u8; 11];
            server.read_exact(&mut domain).await.expect("read domain");
            assert_eq!(&domain, b"example.com");

            let mut port = [0u8; 2];
            server.read_exact(&mut port).await.expect("read port");
            assert_eq!(u16::from_be_bytes(port), 443);

            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34])
                .await
                .expect("write success reply");
        });

        connect_upstream(&mut client, "example.com", 443, None)
            .await
            .expect("upstream SOCKS5 connect should succeed");
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn upstream_connect_writes_username_password_auth() {
        let (mut client, mut server) = duplex(256);

        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x02]);
            server
                .write_all(&[0x05, 0x02])
                .await
                .expect("write method response");

            let mut auth_prefix = [0u8; 2];
            server
                .read_exact(&mut auth_prefix)
                .await
                .expect("read auth prefix");
            assert_eq!(auth_prefix, [0x01, 0x04]);

            let mut username = [0u8; 4];
            server
                .read_exact(&mut username)
                .await
                .expect("read username");
            assert_eq!(&username, b"user");

            let password_len = server.read_u8().await.expect("read password len");
            assert_eq!(password_len, 4);
            let mut password = [0u8; 4];
            server
                .read_exact(&mut password)
                .await
                .expect("read password");
            assert_eq!(&password, b"pass");

            server
                .write_all(&[0x01, 0x00])
                .await
                .expect("write auth success");

            let mut request = [0u8; 10];
            server
                .read_exact(&mut request)
                .await
                .expect("read IPv4 request");
            assert_eq!(
                request,
                [0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x01, 0xbb]
            );

            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34])
                .await
                .expect("write success reply");
        });

        let auth = UpstreamAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        connect_upstream(&mut client, "203.0.113.7", 443, Some(&auth))
            .await
            .expect("upstream SOCKS5 connect should succeed");
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn upstream_connect_rejects_non_success_reply() {
        let (mut client, mut server) = duplex(256);

        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            server
                .write_all(&[0x05, 0x00])
                .await
                .expect("write method response");

            let mut request = [0u8; 22];
            server
                .read_exact(&mut request)
                .await
                .expect("read IPv6 request");
            assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x04]);
            assert_eq!(&request[20..], &443u16.to_be_bytes());

            server
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("write refused reply");
        });

        let err = connect_upstream(&mut client, "2001:db8::1", 443, None)
            .await
            .expect_err("upstream SOCKS5 connect should fail");
        assert!(matches!(err, SocksError::UpstreamConnectRejected(0x05)));
        server_task.await.expect("server task");
    }
}
