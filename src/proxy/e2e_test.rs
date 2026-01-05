use super::*;
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

struct TestProxy {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl TestProxy {
    async fn spawn(settings: ProxySettings) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener should bind");
        let addr = listener.local_addr().expect("proxy addr should resolve");

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let (stream, peer_addr) = match accept {
                            Ok(v) => v,
                            Err(err) => {
                                tracing::warn!(error=%err, "proxy accept failed");
                                break;
                            }
                        };

                        let settings = settings.clone();
                        tokio::spawn(async move {
                            let _ = handle_client(stream, peer_addr, settings).await;
                        });
                    }
                }
            }
        });

        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
            task,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

fn unique_temp_dir(prefix: &str) -> tempfile::TempDir {
    let prefix = format!("polytls-{prefix}-");
    tempfile::Builder::new()
        .prefix(&prefix)
        .tempdir()
        .expect("temp dir should be created")
}

struct TestCa {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    manager: Arc<crate::ca::CaManager>,
    ca_cert_path: PathBuf,
}

impl TestCa {
    async fn new(prefix: &str) -> Self {
        use crate::ca::{CaConfig, CaManager};

        let dir = unique_temp_dir(prefix);
        let ca_cert_path = dir.path().join("ca.crt");
        let ca_key_path = dir.path().join("ca.key");

        let ca = CaManager::load_or_create(CaConfig {
            ca_key_path,
            ca_cert_path: ca_cert_path.clone(),
            leaf_ttl: Duration::from_secs(3600),
        })
        .await
        .expect("CA should be created");

        Self {
            dir,
            manager: Arc::new(ca),
            ca_cert_path,
        }
    }

    fn ca_cert_path_str(&self) -> String {
        self.ca_cert_path.to_string_lossy().to_string()
    }
}

struct TestTlsOrigin {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl TestTlsOrigin {
    async fn spawn_http(host: &str, ca: &TestCa, alpn_protos: Vec<String>, body: &str) -> Self {
        let (leaf_cert, leaf_key) = ca
            .manager
            .leaf_for_host(host)
            .await
            .expect("origin leaf should be created");
        let acceptor =
            build_client_acceptor(&leaf_cert, &leaf_key, &alpn_protos).expect("acceptor");
        let acceptor = Arc::new(acceptor);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener should bind");
        let addr = listener.local_addr().expect("origin addr should resolve");

        let body = body.to_string();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let (stream, _peer) = match accept {
                            Ok(v) => v,
                            Err(err) => {
                                tracing::warn!(error=%err, "origin accept failed");
                                break;
                            }
                        };

                        let acceptor = acceptor.clone();
                        let body = body.clone();
                        tokio::spawn(async move {
                            let mut tls = match tokio_boring::accept(&acceptor, stream).await {
                                Ok(v) => v,
                                Err(err) => {
                                    tracing::warn!(error=%err, "origin TLS accept failed");
                                    return;
                                }
                            };

                            // Read and discard the request headers. If the server closes the
                            // TCP socket while unread client data is still pending, some
                            // platforms will abort the connection with RST, which makes the
                            // tests flaky.
                            let mut req_buf = Vec::with_capacity(1024);
                            let mut tmp = [0u8; 1024];
                            loop {
                                if req_buf.len() > 16 * 1024 {
                                    break;
                                }

                                let read_res = tokio::time::timeout(
                                    Duration::from_secs(2),
                                    tls.read(&mut tmp),
                                )
                                .await;
                                let n = match read_res {
                                    Ok(Ok(n)) => n,
                                    Ok(Err(_)) => break,
                                    Err(_) => break,
                                };
                                if n == 0 {
                                    break;
                                }
                                req_buf.extend_from_slice(&tmp[..n]);
                                if memchr::memmem::find(&req_buf, b"\r\n\r\n").is_some() {
                                    break;
                                }
                            }

                            let response = format!(
                                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}",
                                body.len()
                            );

                            let _ = tls.write_all(response.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        });
                    }
                }
            }
        });

        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
            task,
        }
    }

    async fn spawn_handshake_only(
        host: &str,
        ca: &TestCa,
        alpn_protos: Vec<String>,
    ) -> (Self, oneshot::Receiver<Option<Vec<u8>>>) {
        let (leaf_cert, leaf_key) = ca
            .manager
            .leaf_for_host(host)
            .await
            .expect("origin leaf should be created");
        let acceptor =
            build_client_acceptor(&leaf_cert, &leaf_key, &alpn_protos).expect("acceptor");
        let acceptor = Arc::new(acceptor);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener should bind");
        let addr = listener.local_addr().expect("origin addr should resolve");

        let (alpn_tx, alpn_rx) = oneshot::channel();
        let alpn_tx = Arc::new(Mutex::new(Some(alpn_tx)));

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let (stream, _peer) = match accept {
                            Ok(v) => v,
                            Err(err) => {
                                tracing::warn!(error=%err, "origin accept failed");
                                break;
                            }
                        };

                        let acceptor = acceptor.clone();
                        let alpn_tx = alpn_tx.clone();
                        tokio::spawn(async move {
                            let mut tls = match tokio_boring::accept(&acceptor, stream).await {
                                Ok(v) => v,
                                Err(err) => {
                                    tracing::warn!(error=%err, "origin TLS accept failed");
                                    return;
                                }
                            };

                            let selected = tls.ssl().selected_alpn_protocol().map(|v| v.to_vec());
                            if let Some(tx) = alpn_tx.lock().await.take() {
                                let _ = tx.send(selected);
                            }

                            let _ = tls.shutdown().await;
                        });
                    }
                }
            }
        });

        (
            Self {
                addr,
                shutdown_tx: Some(shutdown_tx),
                task,
            },
            alpn_rx,
        )
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for TestTlsOrigin {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.task.abort();
    }
}

fn build_tls_client_connector(ca_file: &str, alpn_protos: &[&str]) -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("client builder");
    builder
        .set_ca_file(ca_file)
        .expect("client CA should be set");
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_alpn_protos(&encode_alpn(alpn_protos))
        .expect("client ALPN should be set");
    builder.build()
}

fn encode_alpn(protos: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for proto in protos {
        out.push(proto.len() as u8);
        out.extend_from_slice(proto.as_bytes());
    }
    out
}

async fn open_connect_tunnel(
    proxy_addr: SocketAddr,
    authority: &str,
    extra_headers: &[(&str, &str)],
) -> TcpStream {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("client should connect to proxy");

    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    for (name, value) in extra_headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("CONNECT request should be written");

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .expect("CONNECT response should be read");
        assert!(n > 0, "proxy should send a CONNECT response");
        buf.extend_from_slice(&tmp[..n]);
        if memchr::memmem::find(&buf, b"\r\n\r\n").is_some() {
            break;
        }
    }

    let first_line_end =
        memchr::memmem::find(&buf, b"\r\n").expect("CONNECT response should have status line");
    let status_line = String::from_utf8_lossy(&buf[..first_line_end]);
    assert!(
        status_line.starts_with("HTTP/1.1 200 "),
        "expected 200 CONNECT response, got: {status_line:?}"
    );

    stream
}

fn profiles_for_tests() -> HashMap<String, crate::profile::UpstreamProfile> {
    use crate::profile::UpstreamProfile;

    let mut profiles = HashMap::new();
    profiles.insert(
        "chrome-143-macos-arm64".to_string(),
        UpstreamProfile::chrome_143_macos_arm64(),
    );
    profiles.insert(
        "firefox-145-macos-arm64".to_string(),
        UpstreamProfile::firefox_145_macos_arm64(),
    );
    profiles.insert(
        "safari-26.2-macos-arm64".to_string(),
        UpstreamProfile::safari_26_2_macos_arm64(),
    );
    profiles
}

#[tokio::test]
async fn passthrough_tunnels_tls_end_to_end() {
    let origin_ca = TestCa::new("e2e-origin-ca").await;
    let (origin_leaf, _origin_leaf_key) = origin_ca
        .manager
        .leaf_for_host("localhost")
        .await
        .expect("origin leaf should be created");

    let origin = TestTlsOrigin::spawn_http(
        "localhost",
        &origin_ca,
        vec!["http/1.1".to_string()],
        "passthrough-ok",
    )
    .await;

    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Passthrough,
    })
    .await;

    let authority = format!("localhost:{}", origin.addr().port());
    let tunnel = open_connect_tunnel(proxy.addr(), &authority, &[]).await;

    let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("client builder");
    builder
        .set_ca_file(&origin_ca.ca_cert_path_str())
        .expect("client CA should be set");
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_alpn_protos(&encode_alpn(&["http/1.1"]))
        .expect("ALPN should be set");
    let connector = builder.build();

    let mut cfg = connector.configure().expect("config");
    cfg.set_verify_hostname(true);
    let mut tls = tokio_boring::connect(cfg, "localhost", tunnel)
        .await
        .expect("TLS handshake should succeed");

    let peer_cert = tls
        .ssl()
        .peer_certificate()
        .expect("peer should provide a certificate");
    assert_eq!(
        peer_cert.to_der().expect("cert DER"),
        origin_leaf.to_der().expect("origin leaf DER"),
        "passthrough should preserve origin certificate"
    );

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request should be written");

    let mut resp = Vec::new();
    tls.read_to_end(&mut resp)
        .await
        .expect("response should be read");

    let resp = String::from_utf8_lossy(&resp);
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {resp:?}"
    );
    assert!(
        resp.ends_with("passthrough-ok"),
        "unexpected body: {resp:?}"
    );
}

#[tokio::test]
async fn mitm_terminates_client_tls_and_relays_http1() {
    use crate::mitm::MitmState;
    use crate::profile::{UpstreamProfiles, UpstreamVerification};

    let origin_ca = TestCa::new("e2e-origin-ca").await;
    let origin = TestTlsOrigin::spawn_http(
        "localhost",
        &origin_ca,
        vec!["http/1.1".to_string()],
        "mitm-ok",
    )
    .await;

    let proxy_ca = TestCa::new("e2e-proxy-ca").await;
    let (expected_proxy_leaf, _expected_proxy_key) = proxy_ca
        .manager
        .leaf_for_host("localhost")
        .await
        .expect("proxy leaf should be created");

    let profiles = profiles_for_tests();
    let upstream_profiles = UpstreamProfiles::new("chrome-143-macos-arm64".to_string(), profiles)
        .expect("profiles should be valid");

    let upstream_verification = UpstreamVerification {
        insecure_skip_verify: false,
        verify_hostname: true,
        ca_file: Some(origin_ca.ca_cert_path_str()),
    };
    upstream_profiles
        .connector_for(None, &upstream_verification)
        .await
        .expect("default connector should build");

    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Mitm(MitmState {
            ca: proxy_ca.manager.clone(),
            upstream_profiles,
            upstream_verification,
        }),
    })
    .await;

    let authority = format!("localhost:{}", origin.addr().port());
    let tunnel = open_connect_tunnel(proxy.addr(), &authority, &[]).await;

    let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("client builder");
    builder
        .set_ca_file(&proxy_ca.ca_cert_path_str())
        .expect("client CA should be set");
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_alpn_protos(&encode_alpn(&["http/1.1"]))
        .expect("ALPN should be set");
    let connector = builder.build();

    let mut cfg = connector.configure().expect("config");
    cfg.set_verify_hostname(true);
    let mut tls = tokio_boring::connect(cfg, "localhost", tunnel)
        .await
        .expect("TLS handshake should succeed");

    let peer_cert = tls
        .ssl()
        .peer_certificate()
        .expect("peer should provide a certificate");
    assert_eq!(
        peer_cert.to_der().expect("cert DER"),
        expected_proxy_leaf.to_der().expect("proxy leaf DER"),
        "MITM should present a proxy-minted leaf certificate"
    );

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request should be written");

    let mut resp = Vec::new();
    tls.read_to_end(&mut resp)
        .await
        .expect("response should be read");

    let resp = String::from_utf8_lossy(&resp);
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {resp:?}"
    );
    assert!(resp.ends_with("mitm-ok"), "unexpected body: {resp:?}");
}

#[tokio::test]
async fn mitm_selects_profile_per_request_via_connect_header() {
    use crate::http_connect::UPSTREAM_PROFILE_HEADER;
    use crate::mitm::MitmState;
    use crate::profile::{UpstreamProfiles, UpstreamVerification};

    let origin_ca = TestCa::new("e2e-origin-ca").await;
    let (origin, _origin_alpn_rx) =
        TestTlsOrigin::spawn_handshake_only("localhost", &origin_ca, vec!["http/1.1".to_string()])
            .await;

    let proxy_ca = TestCa::new("e2e-proxy-ca").await;
    let profiles = profiles_for_tests();
    let upstream_profiles = UpstreamProfiles::new("chrome-143-macos-arm64".to_string(), profiles)
        .expect("profiles should be valid");
    let upstream_verification = UpstreamVerification {
        insecure_skip_verify: false,
        verify_hostname: true,
        ca_file: Some(origin_ca.ca_cert_path_str()),
    };
    upstream_profiles
        .connector_for(None, &upstream_verification)
        .await
        .expect("default connector should build");

    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Mitm(MitmState {
            ca: proxy_ca.manager.clone(),
            upstream_profiles,
            upstream_verification,
        }),
    })
    .await;

    let authority = format!("localhost:{}", origin.addr().port());

    let connector = build_tls_client_connector(&proxy_ca.ca_cert_path_str(), &["h2", "http/1.1"]);

    {
        let tunnel = open_connect_tunnel(
            proxy.addr(),
            &authority,
            &[(UPSTREAM_PROFILE_HEADER, "chrome-143-macos-arm64")],
        )
        .await;

        let mut cfg = connector.configure().expect("config");
        cfg.set_verify_hostname(true);
        let tls = tokio_boring::connect(cfg, "localhost", tunnel)
            .await
            .expect("TLS handshake should succeed");

        assert_eq!(
            tls.ssl().selected_alpn_protocol(),
            Some(b"http/1.1".as_slice()),
            "chrome profile should negotiate http/1.1"
        );
    }

    {
        let tunnel = open_connect_tunnel(
            proxy.addr(),
            &authority,
            &[(UPSTREAM_PROFILE_HEADER, "firefox-145-macos-arm64")],
        )
        .await;

        let mut cfg = connector.configure().expect("config");
        cfg.set_verify_hostname(true);
        let tls = tokio_boring::connect(cfg, "localhost", tunnel)
            .await
            .expect("TLS handshake should succeed");

        assert_eq!(
            tls.ssl().selected_alpn_protocol(),
            Some(b"http/1.1".as_slice()),
            "firefox profile should negotiate http/1.1"
        );
    }
}

#[tokio::test]
async fn mitm_allows_insecure_upstream_for_self_signed_targets() {
    use crate::mitm::MitmState;
    use crate::profile::{UpstreamProfiles, UpstreamVerification};

    let origin_ca = TestCa::new("e2e-origin-ca").await;
    let origin = TestTlsOrigin::spawn_http(
        "localhost",
        &origin_ca,
        vec!["http/1.1".to_string()],
        "insecure-ok",
    )
    .await;

    let proxy_ca = TestCa::new("e2e-proxy-ca").await;

    let profiles = profiles_for_tests();

    let authority = format!("localhost:{}", origin.addr().port());

    let connector = build_tls_client_connector(&proxy_ca.ca_cert_path_str(), &["http/1.1"]);

    {
        let upstream_profiles =
            UpstreamProfiles::new("chrome-143-macos-arm64".to_string(), profiles.clone())
                .expect("profiles should be valid");
        let upstream_verification = UpstreamVerification::default();
        upstream_profiles
            .connector_for(None, &upstream_verification)
            .await
            .expect("default connector should build");

        let proxy = TestProxy::spawn(ProxySettings {
            mode: ProxyMode::Mitm(MitmState {
                ca: proxy_ca.manager.clone(),
                upstream_profiles,
                upstream_verification,
            }),
        })
        .await;

        let tunnel = open_connect_tunnel(proxy.addr(), &authority, &[]).await;
        let mut cfg = connector.configure().expect("config");
        cfg.set_verify_hostname(true);
        let mut tls = tokio_boring::connect(cfg, "localhost", tunnel)
            .await
            .expect("client TLS handshake should succeed");

        let write_res = tls
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await;

        let mut resp = Vec::new();
        let read_res = tls.read_to_end(&mut resp).await;

        assert!(
            write_res.is_err() || read_res.is_err() || !resp.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "expected upstream verification failure without ca_file/insecure, got response: {:?}",
            String::from_utf8_lossy(&resp),
        );
    }

    {
        let upstream_profiles =
            UpstreamProfiles::new("chrome-143-macos-arm64".to_string(), profiles.clone())
                .expect("profiles should be valid");
        let upstream_verification = UpstreamVerification {
            insecure_skip_verify: true,
            verify_hostname: true,
            ca_file: None,
        };
        upstream_profiles
            .connector_for(None, &upstream_verification)
            .await
            .expect("default connector should build");

        let proxy = TestProxy::spawn(ProxySettings {
            mode: ProxyMode::Mitm(MitmState {
                ca: proxy_ca.manager.clone(),
                upstream_profiles,
                upstream_verification,
            }),
        })
        .await;

        let tunnel = open_connect_tunnel(proxy.addr(), &authority, &[]).await;
        let mut cfg = connector.configure().expect("config");
        cfg.set_verify_hostname(true);
        let mut tls = tokio_boring::connect(cfg, "localhost", tunnel)
            .await
            .expect("client TLS handshake should succeed");

        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("request should be written");

        let mut resp = Vec::new();
        tls.read_to_end(&mut resp)
            .await
            .expect("response should be read");

        let resp = String::from_utf8_lossy(&resp);
        assert!(
            resp.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected response: {resp:?}"
        );
        assert!(resp.ends_with("insecure-ok"), "unexpected body: {resp:?}");
    }
}
