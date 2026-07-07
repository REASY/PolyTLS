use crate::alpn::AlpnProtocol;
use crate::error::ErrorKind::TlsHandshake;
use crate::error::{ErrorKind, PolyTlsError, Result};
use crate::http_connect::{ConnectError, read_connect_request};
use crate::mitm::{MitmState, build_client_acceptor, sni_mismatch};
use crate::prefixed_stream::PrefixedStream;
use crate::profile::{
    add_application_settings, set_alps_use_new_codepoint, set_upstream_session_key,
    upstream_session_cache,
};
use crate::socks5::{self, AddressKind, Reply as SocksReply, SocksConnectRequest};
use boring::ssl::NameType;
use std::net::SocketAddr;
use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
enum HttpProxyError {
    BadRequest,
    MethodNotAllowed,
    RequestHeaderFieldsTooLarge,
    BadGateway,
    GatewayTimeout,
}

impl HttpProxyError {
    fn status(self) -> (u16, &'static str) {
        match self {
            Self::BadRequest => (400, "Bad Request"),
            Self::MethodNotAllowed => (405, "Method Not Allowed"),
            Self::RequestHeaderFieldsTooLarge => (431, "Request Header Fields Too Large"),
            Self::BadGateway => (502, "Bad Gateway"),
            Self::GatewayTimeout => (504, "Gateway Timeout"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ProxyProtocol {
    HttpConnect,
    Socks5,
}

#[derive(Clone)]
pub enum ProxyMode {
    Passthrough,
    Mitm(MitmState),
}

#[derive(Clone)]
pub struct ProxySettings {
    pub protocol: ProxyProtocol,
    pub mode: ProxyMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetAddressKind {
    Domain,
    Ip,
}

#[derive(Debug)]
struct TunnelRequest {
    authority: String,
    host: String,
    port: u16,
    profile: Option<String>,
    leftover: Vec<u8>,
    address_kind: TargetAddressKind,
}

#[derive(Clone, Copy, Debug)]
enum ClientTlsIdentityPolicy {
    ConnectHost,
    Socks5,
}

struct ClientTlsStart {
    stream: PrefixedStream<TcpStream>,
    cert_host: String,
    upstream_tls_name: String,
    sni_validation_host: String,
}

struct MitmTunnelRun {
    client: TcpStream,
    peer_addr: SocketAddr,
    mitm: MitmState,
    tunnel: TunnelRequest,
    upstream: TcpStream,
    profile_name: String,
    upstream_connector: std::sync::Arc<boring::ssl::SslConnector>,
    identity_policy: ClientTlsIdentityPolicy,
}

pub async fn run(
    listen_addr: SocketAddr,
    settings: ProxySettings,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    run_with_listener(listener, settings, shutdown).await
}

async fn run_with_listener(
    listener: TcpListener,
    settings: ProxySettings,
    shutdown: CancellationToken,
) -> Result<()> {
    let listen_addr = listener.local_addr()?;
    tracing::info!(%listen_addr, "proxy listening");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("shutdown requested");
                break;
            }
            accept = listener.accept() => {
                let (stream, peer_addr) = accept?;
                let settings = settings.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_client(stream, peer_addr, settings).await {
                        match err.kind() {
                            ErrorKind::Connect(ConnectError::UnexpectedEof { bytes_read })
                                if *bytes_read == 0 =>
                            {
                                tracing::debug!(
                                    %peer_addr,
                                    "client disconnected before sending CONNECT"
                                );
                            }
                            _ => {
                                tracing::warn!(%peer_addr, error = %err, "connection failed");
                            }
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_client(
    client: TcpStream,
    peer_addr: SocketAddr,
    settings: ProxySettings,
) -> Result<()> {
    match (settings.protocol, settings.mode) {
        (ProxyProtocol::HttpConnect, ProxyMode::Passthrough) => {
            handle_http_passthrough(client, peer_addr).await
        }
        (ProxyProtocol::HttpConnect, ProxyMode::Mitm(mitm)) => {
            handle_http_mitm(client, peer_addr, mitm).await
        }
        (ProxyProtocol::Socks5, ProxyMode::Passthrough) => {
            handle_socks5_passthrough(client, peer_addr).await
        }
        (ProxyProtocol::Socks5, ProxyMode::Mitm(mitm)) => {
            handle_socks5_mitm(client, peer_addr, mitm).await
        }
    }
}

async fn handle_http_passthrough(mut client: TcpStream, peer_addr: SocketAddr) -> Result<()> {
    let connect = match read_connect_request(&mut client).await {
        Ok(req) => req,
        Err(err) => {
            write_connect_error(&mut client, &err).await.ok();
            return Err(err.into());
        }
    };

    tracing::info!(
        %peer_addr,
        authority = %connect.authority,
        host = %connect.host,
        port = connect.port,
        "CONNECT request"
    );

    let upstream_target = format!("{}:{}", connect.host, connect.port);
    let mut upstream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream_target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            write_http_error(&mut client, HttpProxyError::BadGateway)
                .await
                .ok();
            return Err(ErrorKind::Io(e).into());
        }
        Err(_) => {
            write_http_error(&mut client, HttpProxyError::GatewayTimeout)
                .await
                .ok();
            return Err(ErrorKind::Timeout.into());
        }
    };

    write_connect_ok(&mut client).await?;

    let mut client = PrefixedStream::new(connect.leftover, client);
    let (client_to_upstream, upstream_to_client) =
        copy_bidirectional(&mut client, &mut upstream).await?;

    tracing::info!(
        %peer_addr,
        client_to_upstream,
        upstream_to_client,
        "tunnel closed"
    );

    Ok(())
}

async fn handle_socks5_passthrough(mut client: TcpStream, peer_addr: SocketAddr) -> Result<()> {
    let socks_req = match socks5::accept_connect(&mut client).await {
        Ok(req) => req,
        Err(err) => {
            if let Some(reply) = socks_reply_for_accept_error(&err) {
                socks5::write_reply(&mut client, reply).await.ok();
            }
            return Err(err.into());
        }
    };
    let tunnel = tunnel_from_socks5(socks_req);

    tracing::info!(
        %peer_addr,
        authority = %tunnel.authority,
        host = %tunnel.host,
        port = tunnel.port,
        "SOCKS5 CONNECT request"
    );

    let upstream_target = format!("{}:{}", tunnel.host, tunnel.port);
    let mut upstream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream_target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            socks5::write_reply(&mut client, SocksReply::GeneralFailure)
                .await
                .ok();
            return Err(ErrorKind::Io(e).into());
        }
        Err(_) => {
            socks5::write_reply(&mut client, SocksReply::GeneralFailure)
                .await
                .ok();
            return Err(ErrorKind::Timeout.into());
        }
    };

    socks5::write_reply(&mut client, SocksReply::Succeeded).await?;

    let mut client = PrefixedStream::new(tunnel.leftover, client);
    let (client_to_upstream, upstream_to_client) =
        copy_bidirectional(&mut client, &mut upstream).await?;

    tracing::info!(
        %peer_addr,
        client_to_upstream,
        upstream_to_client,
        "SOCKS5 tunnel closed"
    );

    Ok(())
}

async fn handle_http_mitm(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    mitm: MitmState,
) -> Result<()> {
    let connect = match read_connect_request(&mut client).await {
        Ok(req) => req,
        Err(err) => {
            write_connect_error(&mut client, &err).await.ok();
            return Err(err.into());
        }
    };

    let tunnel = TunnelRequest {
        authority: connect.authority,
        host: connect.host,
        port: connect.port,
        profile: connect.profile,
        leftover: connect.leftover,
        address_kind: TargetAddressKind::Domain,
    };

    let requested_profile = tunnel.profile.as_deref();
    let (profile_name, upstream_connector) = match mitm
        .upstream_profiles
        .connector_for(requested_profile, &mitm.upstream_verification)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            let http_err = match err.kind() {
                ErrorKind::UnknownUpstreamProfile(_) => HttpProxyError::BadRequest,
                _ => HttpProxyError::BadGateway,
            };
            write_http_error(&mut client, http_err).await.ok();
            return Err(err);
        }
    };

    tracing::info!(
        %peer_addr,
        authority = %tunnel.authority,
        host = %tunnel.host,
        port = tunnel.port,
        requested_profile = requested_profile.unwrap_or("<default>"),
        upstream_profile = %profile_name,
        "CONNECT request (mitm)"
    );

    let upstream_target = format!("{}:{}", tunnel.host, tunnel.port);
    let upstream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream_target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            write_http_error(&mut client, HttpProxyError::BadGateway)
                .await
                .ok();
            return Err(ErrorKind::Io(e).into());
        }
        Err(_) => {
            write_http_error(&mut client, HttpProxyError::GatewayTimeout)
                .await
                .ok();
            return Err(ErrorKind::Timeout.into());
        }
    };

    write_connect_ok(&mut client).await?;

    run_mitm_tunnel(MitmTunnelRun {
        client,
        peer_addr,
        mitm,
        tunnel,
        upstream,
        profile_name,
        upstream_connector,
        identity_policy: ClientTlsIdentityPolicy::ConnectHost,
    })
    .await
}

async fn handle_socks5_mitm(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    mitm: MitmState,
) -> Result<()> {
    let socks_req = match socks5::accept_connect(&mut client).await {
        Ok(req) => req,
        Err(err) => {
            if let Some(reply) = socks_reply_for_accept_error(&err) {
                socks5::write_reply(&mut client, reply).await.ok();
            }
            return Err(err.into());
        }
    };
    let tunnel = tunnel_from_socks5(socks_req);

    let requested_profile = tunnel.profile.as_deref();
    let (profile_name, upstream_connector) = match mitm
        .upstream_profiles
        .connector_for(requested_profile, &mitm.upstream_verification)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            socks5::write_reply(&mut client, SocksReply::GeneralFailure)
                .await
                .ok();
            return Err(err);
        }
    };

    tracing::info!(
        %peer_addr,
        authority = %tunnel.authority,
        host = %tunnel.host,
        port = tunnel.port,
        requested_profile = requested_profile.unwrap_or("<default>"),
        upstream_profile = %profile_name,
        "SOCKS5 CONNECT request (mitm)"
    );

    let upstream_target = format!("{}:{}", tunnel.host, tunnel.port);
    let upstream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream_target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            socks5::write_reply(&mut client, SocksReply::GeneralFailure)
                .await
                .ok();
            return Err(ErrorKind::Io(e).into());
        }
        Err(_) => {
            socks5::write_reply(&mut client, SocksReply::GeneralFailure)
                .await
                .ok();
            return Err(ErrorKind::Timeout.into());
        }
    };

    socks5::write_reply(&mut client, SocksReply::Succeeded).await?;

    run_mitm_tunnel(MitmTunnelRun {
        client,
        peer_addr,
        mitm,
        tunnel,
        upstream,
        profile_name,
        upstream_connector,
        identity_policy: ClientTlsIdentityPolicy::Socks5,
    })
    .await
}

async fn run_mitm_tunnel(run: MitmTunnelRun) -> Result<()> {
    let MitmTunnelRun {
        client,
        peer_addr,
        mitm,
        tunnel,
        upstream,
        profile_name,
        upstream_connector,
        identity_policy,
    } = run;

    let upstream_profile = mitm
        .upstream_profiles
        .profile(&profile_name)
        .ok_or_else(|| {
            ErrorKind::Config(format!(
                "upstream profile {profile_name:?} missing after selection"
            ))
        })?;

    let client_start = prepare_client_tls_start(client, &tunnel, identity_policy).await?;
    let (leaf_cert, leaf_key) = mitm.ca.leaf_for_host(&client_start.cert_host).await?;
    let acceptor = build_client_acceptor(&leaf_cert, &leaf_key, &upstream_profile.alpn_protos)?;

    let mut client_tls = tokio_boring::accept(&acceptor, client_start.stream)
        .await
        .map_err(|e| ErrorKind::TlsHandshake(e.to_string()))?;

    let client_tls_sni = client_tls.ssl().servername(NameType::HOST_NAME);
    tracing::info!(
        %peer_addr,
        authority = %tunnel.authority,
        cert_host = %client_start.cert_host,
        upstream_tls_name = %client_start.upstream_tls_name,
        sni_validation_host = %client_start.sni_validation_host,
        client_hello_sni = %client_tls_sni.unwrap_or("<none>"),
        "client TLS accepted"
    );

    if let Some(err) = sni_mismatch(&client_start.sni_validation_host, client_tls_sni) {
        return Err(err);
    }

    let mut connect_config = upstream_connector
        .configure()
        .map_err(|e| ErrorKind::TlsHandshake(e.to_string()))?;

    let session_key = format!("{}:{}", tunnel.host, tunnel.port);
    set_upstream_session_key(&mut connect_config, session_key.clone());
    let session_cache = upstream_session_cache(upstream_connector.as_ref())
        .ok_or_else(|| ErrorKind::Config("upstream connector session cache missing".to_string()))?;
    let session_to_resume = {
        let guard = session_cache.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&session_key).cloned()
    };
    if let Some(session) = &session_to_resume {
        unsafe {
            connect_config
                .set_session(session)
                .map_err(|e| ErrorKind::TlsHandshake(format!("failed to set session: {e}")))?;
        }
    }

    connect_config.set_enable_ech_grease(upstream_profile.enable_ech_grease);
    connect_config.set_verify_hostname(mitm.upstream_verification.effective_verify_hostname());

    let client_alpn_bytes = client_tls.ssl().selected_alpn_protocol();
    let client_alpn: Option<AlpnProtocol> = get_alpn_protocol(client_alpn_bytes)?;
    let upstream_alpn_protos = select_upstream_alpn_proto(client_alpn.as_ref())?;

    connect_config
        .set_alpn_protos(&upstream_alpn_protos)
        .map_err(|e| ErrorKind::TlsHandshake(format!("failed to set ALPN: {e}")))?;

    if matches!(client_alpn, Some(AlpnProtocol::H2))
        && upstream_profile
            .alps_protos
            .iter()
            .any(|proto| proto == "h2")
    {
        set_alps_use_new_codepoint(&mut connect_config, upstream_profile.alps_use_new_codepoint);
        add_application_settings(&mut connect_config, "h2", &[])?;
    }

    let mut upstream_tls =
        tokio_boring::connect(connect_config, &client_start.upstream_tls_name, upstream)
            .await
            .map_err(|e| ErrorKind::TlsHandshake(e.to_string()))?;

    let upstream_alpn_bytes = upstream_tls.ssl().selected_alpn_protocol();

    let upstream_alpn: Option<AlpnProtocol> = get_alpn_protocol(upstream_alpn_bytes)?;

    // Enforce ALPN compatibility to avoid protocol confusion (e.g., client negotiates `h2` while
    // upstream negotiates `http/1.1`). Some upstreams omit ALPN when implicitly selecting
    // HTTP/1.1, so treat `None` as compatible with `http/1.1`.
    let alpn_compatible = match (&client_alpn, &upstream_alpn) {
        (Some(client), Some(upstream)) => client == upstream,
        (Some(client), None) => *client == AlpnProtocol::Http11,
        (None, Some(upstream)) => *upstream == AlpnProtocol::Http11,
        (None, None) => true,
    };
    tracing::info!(
        ?client_alpn,
        ?upstream_alpn,
        alpn_compatible = ?alpn_compatible,
        "ALPN negotiated"
    );

    if !alpn_compatible {
        let client_alpn_str = client_alpn
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "<none>".to_string());
        let upstream_alpn_str = upstream_alpn
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "<none>".to_string());
        return Err(ErrorKind::TlsHandshake(format!(
            "ALPN mismatch: client={client_alpn_str} upstream={upstream_alpn_str}"
        ))
        .into());
    }

    let (client_to_upstream, upstream_to_client) =
        copy_bidirectional(&mut client_tls, &mut upstream_tls).await?;

    tracing::info!(
        %peer_addr,
        client_to_upstream,
        upstream_to_client,
        ?client_alpn,
        ?upstream_alpn,
        "mitm tunnel closed"
    );

    Ok(())
}

fn tunnel_from_socks5(req: SocksConnectRequest) -> TunnelRequest {
    let address_kind = match req.address_kind {
        AddressKind::Domain => TargetAddressKind::Domain,
        AddressKind::Ip => TargetAddressKind::Ip,
    };
    let authority = format!("{}:{}", req.host, req.port);

    TunnelRequest {
        authority,
        host: req.host,
        port: req.port,
        profile: req.profile,
        leftover: Vec::new(),
        address_kind,
    }
}

fn socks_reply_for_accept_error(err: &socks5::SocksError) -> Option<SocksReply> {
    match err {
        socks5::SocksError::UnsupportedCommand(_) => Some(SocksReply::CommandNotSupported),
        socks5::SocksError::UnsupportedAddressType(_) => Some(SocksReply::AddressTypeNotSupported),
        socks5::SocksError::InvalidReservedByte(_) | socks5::SocksError::InvalidDomain => {
            Some(SocksReply::GeneralFailure)
        }
        socks5::SocksError::Io(_)
        | socks5::SocksError::UnsupportedVersion(_)
        | socks5::SocksError::NoAcceptableAuthMethod
        | socks5::SocksError::InvalidAuthVersion(_) => None,
    }
}

async fn prepare_client_tls_start(
    mut client: TcpStream,
    tunnel: &TunnelRequest,
    policy: ClientTlsIdentityPolicy,
) -> Result<ClientTlsStart> {
    match policy {
        ClientTlsIdentityPolicy::ConnectHost => Ok(ClientTlsStart {
            stream: PrefixedStream::new(tunnel.leftover.clone(), client),
            cert_host: tunnel.host.clone(),
            upstream_tls_name: tunnel.host.clone(),
            sni_validation_host: tunnel.host.clone(),
        }),
        ClientTlsIdentityPolicy::Socks5 if tunnel.address_kind == TargetAddressKind::Ip => {
            let peeked = crate::tls_client_hello::peek_client_hello(&mut client).await?;
            tracing::info!(
                authority = %tunnel.authority,
                target_host = %tunnel.host,
                port = tunnel.port,
                client_hello_sni = %peeked.sni.as_deref().unwrap_or("<none>"),
                client_hello_bytes = peeked.prefix.len(),
                "peeked SOCKS5 ClientHello"
            );

            let Some(sni) = peeked.sni else {
                return Err(ErrorKind::TlsHandshake(
                    "SOCKS5 MITM requires ClientHello SNI when the target address is an IP"
                        .to_string(),
                )
                .into());
            };

            Ok(ClientTlsStart {
                stream: PrefixedStream::new(peeked.prefix, client),
                cert_host: sni.clone(),
                upstream_tls_name: sni.clone(),
                sni_validation_host: sni,
            })
        }
        ClientTlsIdentityPolicy::Socks5 => Ok(ClientTlsStart {
            stream: PrefixedStream::new(tunnel.leftover.clone(), client),
            cert_host: tunnel.host.clone(),
            upstream_tls_name: tunnel.host.clone(),
            sni_validation_host: tunnel.host.clone(),
        }),
    }
}

fn get_alpn_protocol(client_alpn: Option<&[u8]>) -> Result<Option<crate::alpn::AlpnProtocol>> {
    match client_alpn {
        Some(bytes) => crate::alpn::AlpnProtocol::from_bytes(bytes)
            .map(Some)
            .map_err(|err| PolyTlsError::new(TlsHandshake(err.to_string()))),
        None => Ok(None),
    }
}

fn select_upstream_alpn_proto(client_alpn: Option<&AlpnProtocol>) -> Result<Vec<u8>> {
    match client_alpn {
        Some(proto) if *proto == AlpnProtocol::H2 => {
            const CAP: usize =
                AlpnProtocol::H2.as_bytes().len() + AlpnProtocol::Http11.as_bytes().len() + 2;
            let mut v = Vec::with_capacity(CAP);
            v.push(AlpnProtocol::H2.as_bytes().len() as u8);
            v.extend_from_slice(AlpnProtocol::H2.as_bytes());

            v.push(AlpnProtocol::Http11.as_bytes().len() as u8);
            v.extend_from_slice(AlpnProtocol::Http11.as_bytes());

            Ok(v)
        }
        Some(proto) if *proto == AlpnProtocol::Http11 => {
            let mut v = Vec::with_capacity(AlpnProtocol::Http11.as_bytes().len() + 1);
            v.push(AlpnProtocol::Http11.as_bytes().len() as u8);
            v.extend_from_slice(AlpnProtocol::Http11.as_bytes());
            Ok(v)
        }
        Some(other) => Err(PolyTlsError::new(TlsHandshake(format!(
            "Cannot work with {:?}",
            other
        )))),
        None => Ok(b"\x08http/1.1".to_vec()),
    }
}

async fn write_connect_ok(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: PolyTLS\r\n\r\n")
        .await?;
    Ok(())
}

async fn write_connect_error(stream: &mut TcpStream, err: &ConnectError) -> Result<()> {
    let http_err = match err {
        ConnectError::UnsupportedMethod(_) => HttpProxyError::MethodNotAllowed,
        ConnectError::UnexpectedEof { .. } => HttpProxyError::BadRequest,
        ConnectError::RequestTooLarge => HttpProxyError::RequestHeaderFieldsTooLarge,
        ConnectError::HttpParse(_) | ConnectError::InvalidAuthority(_) | ConnectError::Io(_) => {
            HttpProxyError::BadRequest
        }
    };
    write_http_error(stream, http_err).await
}

async fn write_http_error(stream: &mut TcpStream, err: HttpProxyError) -> Result<()> {
    let (code, reason) = err.status();
    write_http_error_response(stream, code, reason).await
}

async fn write_http_error_response(stream: &mut TcpStream, code: u16, reason: &str) -> Result<()> {
    let body = format!("{reason}\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}",
        body.len()
    );

    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
#[path = "proxy/e2e_test.rs"]
mod tests;

#[cfg(test)]
#[path = "proxy/stress_test.rs"]
mod stress_test;
