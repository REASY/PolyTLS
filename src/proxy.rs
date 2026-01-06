use crate::alpn::AlpnProtocol;
use crate::error::{ErrorKind, Result};
use crate::http_connect::{ConnectError, read_connect_request};
use crate::mitm::{MitmState, build_client_acceptor, sni_mismatch};
use crate::prefixed_stream::PrefixedStream;
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

#[derive(Clone)]
pub enum ProxyMode {
    Passthrough,
    Mitm(MitmState),
}

#[derive(Clone)]
pub struct ProxySettings {
    pub mode: ProxyMode,
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
    match settings.mode {
        ProxyMode::Passthrough => handle_passthrough(client, peer_addr).await,
        ProxyMode::Mitm(mitm) => handle_mitm(client, peer_addr, mitm).await,
    }
}

async fn handle_passthrough(mut client: TcpStream, peer_addr: SocketAddr) -> Result<()> {
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

async fn handle_mitm(mut client: TcpStream, peer_addr: SocketAddr, mitm: MitmState) -> Result<()> {
    let connect = match read_connect_request(&mut client).await {
        Ok(req) => req,
        Err(err) => {
            write_connect_error(&mut client, &err).await.ok();
            return Err(err.into());
        }
    };

    let requested_profile = connect.profile.as_deref();
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
        authority = %connect.authority,
        host = %connect.host,
        port = connect.port,
        requested_profile = requested_profile.unwrap_or("<default>"),
        upstream_profile = %profile_name,
        "CONNECT request (mitm)"
    );

    let upstream_target = format!("{}:{}", connect.host, connect.port);
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

    let upstream_profile = mitm
        .upstream_profiles
        .profile(&profile_name)
        .ok_or_else(|| {
            ErrorKind::Config(format!(
                "upstream profile {profile_name:?} missing after selection"
            ))
        })?;

    let client = PrefixedStream::new(connect.leftover, client);
    let (leaf_cert, leaf_key) = mitm.ca.leaf_for_host(&connect.host).await?;
    let acceptor = build_client_acceptor(&leaf_cert, &leaf_key, &upstream_profile.alpn_protos)?;

    let mut client_tls = tokio_boring::accept(&acceptor, client)
        .await
        .map_err(|e| ErrorKind::TlsHandshake(e.to_string()))?;

    if let Some(err) = sni_mismatch(
        &connect.host,
        client_tls.ssl().servername(NameType::HOST_NAME),
    ) {
        return Err(err);
    }

    let mut connect_config = upstream_connector
        .configure()
        .map_err(|e| ErrorKind::TlsHandshake(e.to_string()))?;
    connect_config.set_enable_ech_grease(upstream_profile.enable_ech_grease);
    connect_config.set_verify_hostname(mitm.upstream_verification.effective_verify_hostname());

    let client_alpn_bytes = client_tls.ssl().selected_alpn_protocol();
    let upstream_alpn_protos = select_upstream_alpn_proto(client_alpn_bytes)?;

    connect_config
        .set_alpn_protos(&upstream_alpn_protos)
        .map_err(|e| ErrorKind::TlsHandshake(format!("failed to set ALPN: {e}")))?;

    let mut upstream_tls = tokio_boring::connect(connect_config, &connect.host, upstream)
        .await
        .map_err(|e| ErrorKind::TlsHandshake(e.to_string()))?;

    let client_alpn_bytes = client_tls.ssl().selected_alpn_protocol();
    let upstream_alpn_bytes = upstream_tls.ssl().selected_alpn_protocol();

    let client_alpn: Option<AlpnProtocol> = get_alpn_protocol(client_alpn_bytes);
    let upstream_alpn: Option<AlpnProtocol> = get_alpn_protocol(upstream_alpn_bytes);

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

fn get_alpn_protocol(client_alpn: Option<&[u8]>) -> Option<crate::alpn::AlpnProtocol> {
    client_alpn.map(crate::alpn::AlpnProtocol::from_bytes)
}

fn select_upstream_alpn_proto(client_alpn_bytes: Option<&[u8]>) -> Result<Vec<u8>> {
    match client_alpn_bytes {
        Some(proto) => {
            let len = proto.len();
            if len > 255 {
                return Err(ErrorKind::TlsHandshake(format!("client ALPN too long: {len}")).into());
            }
            let mut v = Vec::with_capacity(1 + len);
            v.push(len as u8);
            v.extend_from_slice(proto);
            Ok(v)
        }
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
