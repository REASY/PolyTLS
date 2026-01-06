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

pub struct TestProxy {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl TestProxy {
    pub async fn spawn(settings: ProxySettings) -> Self {
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

    pub fn addr(&self) -> SocketAddr {
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

pub struct TestCa {
    #[allow(dead_code)]
    pub dir: tempfile::TempDir,
    pub manager: Arc<crate::ca::CaManager>,
    pub ca_cert_path: PathBuf,
}

impl TestCa {
    pub async fn new(prefix: &str) -> Self {
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

    pub fn ca_cert_path_str(&self) -> String {
        self.ca_cert_path.to_string_lossy().to_string()
    }
}

pub struct TestTlsOrigin {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl TestTlsOrigin {
    pub async fn spawn_http(host: &str, ca: &TestCa, alpn_protos: Vec<String>, body: &str) -> Self {
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

    pub fn addr(&self) -> SocketAddr {
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

pub struct TestClient {
    proxy_addr: SocketAddr,
    ca_cert_path: Option<String>,
}

impl TestClient {
    pub fn new(proxy_addr: SocketAddr, ca_cert_path: Option<String>) -> Self {
        Self {
            proxy_addr,
            ca_cert_path,
        }
    }

    pub async fn connect_tunnel(
        &self,
        authority: &str,
        extra_headers: &[(&str, &str)],
    ) -> TcpStream {
        open_connect_tunnel(self.proxy_addr, authority, extra_headers).await
    }

    pub async fn connect_tls(
        &self,
        host: &str,
        tunnel: TcpStream,
        alpn: &[&str],
        verify_hostname: bool,
    ) -> tokio_boring::SslStream<TcpStream> {
        let ca_file = self
            .ca_cert_path
            .as_deref()
            .expect("TestClient needs a CA cert path for TLS tests");

        let connector = build_tls_client_connector(ca_file, alpn);
        let mut cfg = connector.configure().expect("config");
        cfg.set_verify_hostname(verify_hostname);
        tokio_boring::connect(cfg, host, tunnel)
            .await
            .expect("TLS handshake should succeed")
    }

    pub async fn get(
        &self,
        host: &str,
        port: u16,
        alpn: &[&str],
        extra_headers: &[(&str, &str)],
    ) -> Vec<u8> {
        let authority = format!("{}:{}", host, port);
        let tunnel = self.connect_tunnel(&authority, extra_headers).await;
        let mut tls = self.connect_tls(host, tunnel, alpn, true).await;

        tls.write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host
            )
            .as_bytes(),
        )
        .await
        .expect("request should be written");

        let mut resp = Vec::new();
        tls.read_to_end(&mut resp)
            .await
            .expect("response should be read");
        resp
    }
}

pub struct TestContext {
    #[allow(dead_code)]
    pub origin_ca: TestCa,
    #[allow(dead_code)]
    pub proxy_ca: TestCa,
    pub origin: TestTlsOrigin,
    pub proxy: TestProxy,
}

impl TestContext {
    pub async fn new_mitm(origin_body: &str) -> Self {
        let origin_ca = TestCa::new("e2e-origin-ca").await;
        let origin = TestTlsOrigin::spawn_http(
            "localhost",
            &origin_ca,
            vec!["h2".to_string(), "http/1.1".to_string()],
            origin_body,
        )
        .await;

        Self::from_origin(origin, origin_ca).await
    }

    pub async fn from_origin(origin: TestTlsOrigin, origin_ca: TestCa) -> Self {
        use crate::mitm::MitmState;
        use crate::profile::{UpstreamProfiles, UpstreamVerification};

        let proxy_ca = TestCa::new("e2e-proxy-ca").await;

        let profiles = profiles_for_tests();
        let upstream_profiles =
            UpstreamProfiles::new("chrome-143-macos-arm64".to_string(), profiles)
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

        Self {
            origin_ca,
            proxy_ca,
            origin,
            proxy,
        }
    }

    pub fn client(&self) -> TestClient {
        TestClient::new(self.proxy.addr(), Some(self.proxy_ca.ca_cert_path_str()))
    }

    pub fn origin_addr(&self) -> SocketAddr {
        self.origin.addr()
    }

    pub async fn new_passthrough(origin_body: &str) -> Self {
        let origin_ca = TestCa::new("e2e-origin-ca").await;
        let origin = TestTlsOrigin::spawn_http(
            "localhost",
            &origin_ca,
            vec!["h2".to_string(), "http/1.1".to_string()],
            origin_body,
        )
        .await;

        let proxy = TestProxy::spawn(ProxySettings {
            mode: ProxyMode::Passthrough,
        })
        .await;

        let proxy_ca = TestCa::new("e2e-proxy-ca-unused").await;

        Self {
            origin_ca,
            proxy_ca,
            origin,
            proxy,
        }
    }

    #[allow(dead_code)]
    pub fn client_passthrough(&self) -> TestClient {
        TestClient::new(self.proxy.addr(), Some(self.origin_ca.ca_cert_path_str()))
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

async fn send_raw_request(proxy_addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .expect("client should connect to proxy");
    stream
        .write_all(request)
        .await
        .expect("request should be written");

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let read_res = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut tmp)).await;
        let n = match read_res {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => panic!("response should be read: {err}"),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if memchr::memmem::find(&buf, b"\r\n\r\n").is_some() {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }

    buf
}

fn status_line(buf: &[u8]) -> String {
    let first_line_end = memchr::memmem::find(buf, b"\r\n").unwrap_or_else(|| {
        panic!(
            "response should have status line: {:?}",
            String::from_utf8_lossy(buf)
        )
    });
    String::from_utf8_lossy(&buf[..first_line_end]).to_string()
}

pub fn profiles_for_tests() -> HashMap<String, crate::profile::UpstreamProfile> {
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
    let ctx = TestContext::new_passthrough("passthrough-ok").await;
    let resp = ctx
        .client_passthrough()
        .get("localhost", ctx.origin_addr().port(), &["http/1.1"], &[])
        .await;

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
    let ctx = TestContext::new_mitm("mitm-ok").await;
    let resp = ctx
        .client()
        .get("localhost", ctx.origin_addr().port(), &["http/1.1"], &[])
        .await;

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

    let origin_ca = TestCa::new("e2e-origin-ca").await;
    let (origin, _origin_alpn_rx) =
        TestTlsOrigin::spawn_handshake_only("localhost", &origin_ca, vec!["http/1.1".to_string()])
            .await;

    let ctx = TestContext::from_origin(origin, origin_ca).await;

    {
        let tunnel = ctx
            .client()
            .connect_tunnel(
                &format!("localhost:{}", ctx.origin_addr().port()),
                &[(UPSTREAM_PROFILE_HEADER, "chrome-143-macos-arm64")],
            )
            .await;

        let tls = ctx
            .client()
            .connect_tls("localhost", tunnel, &["http/1.1"], true)
            .await;

        assert_eq!(
            tls.ssl().selected_alpn_protocol(),
            Some(b"http/1.1".as_slice()),
            "chrome profile should negotiate http/1.1"
        );
    }

    {
        let tunnel = ctx
            .client()
            .connect_tunnel(
                &format!("localhost:{}", ctx.origin_addr().port()),
                &[(UPSTREAM_PROFILE_HEADER, "firefox-145-macos-arm64")],
            )
            .await;

        let tls = ctx
            .client()
            .connect_tls("localhost", tunnel, &["http/1.1"], true)
            .await;

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

#[tokio::test]
async fn connect_rejects_unsupported_method_with_405() {
    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Passthrough,
    })
    .await;

    let resp = send_raw_request(
        proxy.addr(),
        b"GET example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    )
    .await;

    assert!(
        status_line(&resp).starts_with("HTTP/1.1 405 "),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}

#[tokio::test]
async fn connect_rejects_invalid_authority_with_400() {
    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Passthrough,
    })
    .await;

    let resp = send_raw_request(proxy.addr(), b"CONNECT example.com HTTP/1.1\r\n\r\n").await;

    assert!(
        status_line(&resp).starts_with("HTTP/1.1 400 "),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}

#[tokio::test]
async fn connect_rejects_too_large_request_with_431() {
    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Passthrough,
    })
    .await;

    let mut req = Vec::new();
    req.extend_from_slice(b"CONNECT example.com:443 HTTP/1.1\r\n");
    req.extend_from_slice(b"Host: example.com:443\r\n");
    req.extend_from_slice(b"X-Fill: ");
    req.extend_from_slice(&vec![b'a'; 20 * 1024]);

    let resp = send_raw_request(proxy.addr(), &req).await;

    assert!(
        status_line(&resp).starts_with("HTTP/1.1 431 "),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}

#[tokio::test]
async fn mitm_rejects_unknown_upstream_profile_with_400() {
    use crate::mitm::MitmState;
    use crate::profile::{UpstreamProfiles, UpstreamVerification};

    let proxy_ca = TestCa::new("e2e-proxy-ca").await;
    let profiles = profiles_for_tests();
    let upstream_profiles = UpstreamProfiles::new("chrome-143-macos-arm64".to_string(), profiles)
        .expect("profiles should be valid");
    let upstream_verification = UpstreamVerification::default();

    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Mitm(MitmState {
            ca: proxy_ca.manager.clone(),
            upstream_profiles,
            upstream_verification,
        }),
    })
    .await;

    let resp = send_raw_request(
        proxy.addr(),
        b"CONNECT example.com:443 HTTP/1.1\r\n\
Host: example.com:443\r\n\
X-PolyTLS-Upstream-Profile: definitely-not-a-profile\r\n\
\r\n",
    )
    .await;

    assert!(
        status_line(&resp).starts_with("HTTP/1.1 400 "),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}

#[tokio::test]
async fn passthrough_returns_502_when_upstream_connect_fails() {
    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Passthrough,
    })
    .await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temp port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let authority = format!("127.0.0.1:{port}");
    let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    let resp = send_raw_request(proxy.addr(), req.as_bytes()).await;

    assert!(
        status_line(&resp).starts_with("HTTP/1.1 502 "),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}

#[tokio::test]
async fn mitm_returns_502_when_upstream_connect_fails() {
    use crate::mitm::MitmState;
    use crate::profile::{UpstreamProfiles, UpstreamVerification};

    let proxy_ca = TestCa::new("e2e-proxy-ca").await;
    let profiles = profiles_for_tests();
    let upstream_profiles = UpstreamProfiles::new("chrome-143-macos-arm64".to_string(), profiles)
        .expect("profiles should be valid");
    let upstream_verification = UpstreamVerification::default();

    let proxy = TestProxy::spawn(ProxySettings {
        mode: ProxyMode::Mitm(MitmState {
            ca: proxy_ca.manager.clone(),
            upstream_profiles,
            upstream_verification,
        }),
    })
    .await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temp port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let authority = format!("127.0.0.1:{port}");
    let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    let resp = send_raw_request(proxy.addr(), req.as_bytes()).await;

    assert!(
        status_line(&resp).starts_with("HTTP/1.1 502 "),
        "unexpected response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}

#[tokio::test]
async fn mitm_allows_upstream_without_alpn_when_client_is_http1() {
    use crate::mitm::MitmState;
    use crate::profile::{UpstreamProfiles, UpstreamVerification};

    let origin_ca = TestCa::new("e2e-origin-ca").await;
    let origin = TestTlsOrigin::spawn_http(
        "localhost",
        &origin_ca,
        vec!["h2".to_string()],
        "no-alpn-ok",
    )
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
    let tunnel = open_connect_tunnel(proxy.addr(), &authority, &[]).await;

    let connector = build_tls_client_connector(&proxy_ca.ca_cert_path_str(), &["http/1.1"]);
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
    assert!(resp.ends_with("no-alpn-ok"), "unexpected body: {resp:?}");
}

#[tokio::test]
async fn mitm_rejects_clienthello_sni_mismatch() {
    let ctx = TestContext::new_mitm("sni-mismatch").await;
    let tunnel = ctx
        .client()
        .connect_tunnel(&format!("localhost:{}", ctx.origin_addr().port()), &[])
        .await;

    // We intentionally send a different SNI ("definitely-not-localhost") than the CONNECT authority ("localhost").
    // The proxy should detect this mismatch and abort the connection (usually during or after handshake).
    // Note: TestClient::connect_tls expects handshake to succeed, which it does (client-side),
    // but the subsequent I/O should fail or return an error/alert.
    let mut tls = ctx
        .client()
        .connect_tls(
            "definitely-not-localhost",
            tunnel,
            &["http/1.1"],
            false, // disable hostname verification
        )
        .await;

    let write_res = tls
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await;
    let mut resp = Vec::new();
    let read_res = tls.read_to_end(&mut resp).await;

    assert!(
        write_res.is_err() || read_res.is_err() || !resp.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "expected SNI mismatch to abort the tunnel, got response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}

#[tokio::test]
async fn mitm_rejects_alpn_mismatch_between_client_and_upstream() {
    use crate::http_connect::UPSTREAM_PROFILE_HEADER;
    use crate::mitm::MitmState;
    use crate::profile::{UpstreamProfile, UpstreamProfiles, UpstreamVerification};

    let origin_ca = TestCa::new("e2e-origin-ca").await;
    let origin = TestTlsOrigin::spawn_http(
        "localhost",
        &origin_ca,
        vec!["http/1.1".to_string()],
        "alpn-mismatch",
    )
    .await;

    let proxy_ca = TestCa::new("e2e-proxy-ca").await;

    let mut profiles = profiles_for_tests();
    let mut h2_profile = UpstreamProfile::chrome_143_macos_arm64();
    h2_profile.alpn_protos = vec!["h2".to_string()];
    profiles.insert("h2-only".to_string(), h2_profile);

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
    let tunnel = open_connect_tunnel(
        proxy.addr(),
        &authority,
        &[(UPSTREAM_PROFILE_HEADER, "h2-only")],
    )
    .await;

    let connector = build_tls_client_connector(&proxy_ca.ca_cert_path_str(), &["h2"]);
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
        "expected ALPN mismatch to abort the tunnel, got response: {:?}",
        String::from_utf8_lossy(&resp),
    );
}
