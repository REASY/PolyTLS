# TLS Fingerprint Modification Proxy - Technical Specification

## 1. Project Overview

### 1.1 Purpose
An explicit HTTP proxy (HTTP/1.1 `CONNECT`) with two data-plane modes:

- **Passthrough**: tunnels bytes end-to-end (client TLS terminates on the origin).
- **MITM**: terminates client TLS on the proxy and originates a new proxy→upstream TLS connection, with configurable outbound (proxy→upstream) ClientHello parameters (“upstream profiles”).

Current implementation entrypoints: [`src/main.rs`](../../src/main.rs#L94), [`src/proxy.rs`](../../src/proxy.rs#L46).

**Important**: This project is intended for systems and traffic you own or are explicitly authorized to test/inspect. It is not intended to bypass third‑party security controls or access restrictions.

### 1.2 Core Problem Statement
Many upstream services behave differently depending on TLS handshake details (cipher suites, extensions, ALPN, TLS 1.3 behaviors). In enterprise networks and lab environments, it is often necessary to reproduce specific TLS client behaviors (e.g., common browser handshakes) to:
- diagnose interoperability issues,
- validate monitoring and policy controls,
- run repeatable protocol experiments.

### 1.3 Key Constraints
- **Must** use TLS termination (not packet rewriting) due to cryptographic integrity requirements
- **Must** support dynamic certificate generation and management
- **Must** use BoringSSL (not rustls or OpenSSL) for ClientHello customization capabilities
- **Must** maintain full bidirectional traffic flow with minimal latency
- **MVP**: explicit proxy only (HTTP/1.1 `CONNECT`), no transparent/TProxy mode
- **Current**: L4 byte-relay (no L7 HTTP/2 translation/framing parsing); ALPN is profile-driven (Chrome/Firefox/Safari profiles advertise `h2`, default profile is `http/1.1`).
- **Future**: Full L7 HTTP/2 support (H2 frame model, SETTINGS fingerprinting, HPACK behavior, pseudo-header ordering, priority/prioritization).

### 1.4 OSI Scope & Fingerprinting Limits (Important)
This system is primarily a Layer 7 proxy (HTTP `CONNECT`) that performs Layer 6 TLS bridging. It will **inevitably change** characteristics outside of TLS, including:
- **Layer 4 (TCP) fingerprinting**: upstream SYN/SYN-ACK options, MSS, window scaling, initial congestion window behavior, pacing, etc. come from the proxy host/kernel, not the original client.
- **Layer 3 (IP) attributes**: source IP, TTL/hop-limit, path MTU discovery behavior, and routing are those of the proxy.

If your evaluation target correlates **TLS + TCP + HTTP** fingerprints, this proxy only controls the TLS and (optionally) HTTP aspects. Controlling TCP/IP fingerprints generally requires OS/kernel tuning or a different architecture and is out of scope for the MVP.

## 2. Architecture

### 2.1 System Diagram
```
MITM mode (terminates client TLS):

┌─────────┐  HTTP/1.1 CONNECT + TLS1 (terminated)  ┌─────────────┐   TLS2 (originated)    ┌──────────────┐
│ Client  │ ──────────────────────────────────────►│ MITM Proxy  │ ────────────────────►  │ Target Server│
│         │ ◄──────────────────────────────────────│             │ ◄────────────────────  │              │
└─────────┘            Decrypted / Relayed         └─────────────┘     Decrypted / Relayed└──────────────┘
                                 │
                                 └──────────────────────────────────┐
                                                                    │
                                      ┌─────────────────────────────┴─────────────────────────────┐
                                      │                 Certificate Authority (CA)                │
                                      │              (On-the-fly leaf cert generation)            │
                                      └───────────────────────────────────────────────────────────┘

Passthrough mode (tunnels TLS end-to-end):

┌─────────┐  HTTP/1.1 CONNECT + TLS (tunneled)  ┌─────────────┐   TCP relay         ┌──────────────┐
│ Client  │ ───────────────────────────────────►│ Proxy       │ ─────────────►      │ Target Server│
│         │ ◄───────────────────────────────────│             │ ◄────────────       │              │
└─────────┘          Encrypted / Relayed        └─────────────┘  Encrypted / Relayed└──────────────┘
```

### 2.2 Components

#### 2.2.1 Explicit Proxy Frontend (HTTP/1.1 CONNECT)
- Listens on a plain TCP port and implements HTTP/1.1 proxy semantics for `CONNECT host:port`
- Enforces request limits: max request bytes (16KiB) + max header count (64) ([`src/http_connect.rs`](../../src/http_connect.rs#L5))
- Enforces an upstream TCP connect timeout (30s) ([`src/proxy.rs`](../../src/proxy.rs#L12))
- Defines upstream target selection policy: `CONNECT` authority is the upstream destination; SNI mismatch is fail-closed in MITM mode ([`src/proxy.rs`](../../src/proxy.rs#L184), [`src/mitm.rs`](../../src/mitm.rs#L66))

#### 2.2.2 Certificate Authority (CA) Manager
- Loads an existing root CA from disk or generates a new RSA-2048 root CA on first run ([`src/ca.rs`](../../src/ca.rs#L40))
- Mints per-host RSA leaf certificates (CN+SAN=`host`) on demand for MITM mode ([`src/ca.rs`](../../src/ca.rs#L91))
- Caches leaf certs in memory with a TTL ([`src/ca.rs`](../../src/ca.rs#L91))

#### 2.2.3 TLS Termination Endpoint
- Accepts incoming client TLS connections
- Presents dynamically generated leaf certificates to clients in MITM mode ([`src/proxy.rs`](../../src/proxy.rs#L213))
- Enforces `SNI == CONNECT host` as a fail-closed policy (after handshake completion) ([`src/proxy.rs`](../../src/proxy.rs#L220), [`src/mitm.rs`](../../src/mitm.rs#L66))

**Note on SNI timing**: SNI is carried in the client `ClientHello` and is available during the handshake (and can be queried after handshake completion). However, certificate selection must occur **before** the server sends `ServerHello`. For the MVP, use the `CONNECT host:port` authority as the certificate name source-of-truth (then optionally enforce `SNI == CONNECT host` as a fail-closed policy).

#### 2.2.4 TLS Origination Endpoint
- Establishes new TLS connections to upstream servers
- Applies outbound ClientHello configuration based on a selected upstream profile ([`src/profile.rs`](../../src/profile.rs#L217))
- Optional (future): upstream connection reuse/pooling (requires L7-aware proxying)

#### 2.2.5 Configuration Manager
- Loads a TOML config file into [`Config`](../../src/config.rs#L4) (TOML-only; `.yaml` is not supported)
- Provides built-in upstream profiles (`chrome`, `firefox`, `safari`) and optional per-profile overrides from config ([`src/main.rs`](../../src/main.rs#L294), [`src/profile.rs`](../../src/profile.rs#L60))
- Selects upstream profile per request via `X-PolyTLS-Upstream-Profile` header on `CONNECT` ([`src/http_connect.rs`](../../src/http_connect.rs#L7), [`src/proxy.rs`](../../src/proxy.rs#L157))
- Does not implement hot reload (future)

#### 2.2.6 Traffic Relay
- Efficiently moves bytes between connections (no HTTP parsing/translation), using `tokio::io::copy_bidirectional` ([`src/proxy.rs`](../../src/proxy.rs#L7), [`src/proxy.rs`](../../src/proxy.rs#L259))
- Does not maintain an L7 connection model; connection metadata is currently emitted via logs only (future: structured per-connection state/metrics)
- Optional (future): traffic inspection hooks / L7-aware proxying

## 3. Technical Requirements

### 3.0 Proxy Mode Requirements (MVP: Explicit CONNECT)
- [x] Accept HTTP/1.1 `CONNECT host:port` and reply `200 Connection Established` before starting TLS termination in MITM mode ([`src/proxy.rs`](../../src/proxy.rs#L201))
- [x] Reject non-`CONNECT` methods with a clear HTTP error (`405 Method Not Allowed`) ([`src/http_connect.rs`](../../src/http_connect.rs#L70), [`src/proxy.rs`](../../src/proxy.rs#L279))
- [x] Upstream target selection: use `CONNECT` authority as the upstream destination; enforce SNI mismatch as a policy violation in MITM mode ([`src/proxy.rs`](../../src/proxy.rs#L184), [`src/proxy.rs`](../../src/proxy.rs#L220))
- [x] Enforce request limits: max request bytes (16KiB) + max header count (64) ([`src/http_connect.rs`](../../src/http_connect.rs#L5))
- [x] Enforce upstream TCP connect timeout (30s) ([`src/proxy.rs`](../../src/proxy.rs#L12))
- [ ] Idle timeouts for established tunnels (not implemented)
- [ ] `Proxy-Authorization` / ACLs (not implemented)
- [x] Correctly parse `host:port` where `host` may be a DNS name, IPv4 literal, or IPv6 literal in brackets (e.g. `CONNECT [2001:db8::1]:443`) ([`src/http_connect.rs`](../../src/http_connect.rs#L119))

### 3.1 TLS Fingerprint Customization Features

#### 3.1.1 Implemented (proxy→upstream) Modifications
- [x] **GREASE** via `set_grease_enabled` ([`src/profile.rs`](../../src/profile.rs#L221))
- [x] **Extension permutation** via `set_permute_extensions` (optional per profile) ([`src/profile.rs`](../../src/profile.rs#L223))
- [x] **ALPN list** (profile-driven) ([`src/profile.rs`](../../src/profile.rs#L224))
- [x] **Supported groups / named curves** via `set_curves_list` ([`src/profile.rs`](../../src/profile.rs#L262))
- [x] **TLS 1.2 cipher list** via `set_cipher_list` ([`src/profile.rs`](../../src/profile.rs#L240))
- [x] **Signature algorithms list** via `set_sigalgs_list` ([`src/profile.rs`](../../src/profile.rs#L246))
- [x] **OCSP stapling offer** via `enable_ocsp_stapling` ([`src/profile.rs`](../../src/profile.rs#L252))
- [x] **Signed Certificate Timestamps (SCT) offer** via `enable_signed_cert_timestamps` ([`src/profile.rs`](../../src/profile.rs#L256))
- [x] **Certificate compression** (`compress_certificate` extension) with zlib/brotli/zstd decompression support ([`src/compress.rs`](../../src/compress.rs#L54))
- [x] **TLS version bounds** via `set_min_proto_version` / `set_max_proto_version` ([`src/profile.rs`](../../src/profile.rs#L268))
- [x] **ECH GREASE toggle** applied per upstream connection ([`src/proxy.rs`](../../src/proxy.rs#L230))

**JA3/JA4 note**: Extension order is fingerprint-significant (JA3 is order-sensitive). If your goal is to reproduce a *specific* client fingerprint (e.g., "Chrome 120"), you generally want a deterministic extension order rather than random permutation.

#### 3.1.2 Not Implemented / Future Modifications
- [ ] **TLS 1.3 cipher suite list control** (only TLS 1.2 cipher list is configurable today)
- [ ] **Session ticket / resumption knobs**
- [ ] **Application Settings (ALPS) extension**
- [ ] **Custom extension injection / byte-for-byte ClientHello reproduction**
- [ ] **Record layer version manipulation**

### 3.2 Certificate Management

#### 3.2.1 Root CA Requirements
- [x] Generate an RSA 2048-bit root CA on first run and persist to disk ([`src/ca.rs`](../../src/ca.rs#L40))
- [x] Support custom CA import by providing existing `ca_key_path`/`ca_cert_path` ([`src/main.rs`](../../src/main.rs#L57))
- [x] Provide CA certificate export for client installation: the root CA certificate is a PEM file on disk (default `./ca/certificate.pem`) ([`src/main.rs`](../../src/main.rs#L61))
- [ ] Persist to disk with password protection / encrypted private key (not implemented; key is stored as unencrypted PKCS#8 PEM, chmod 0600 on Unix) ([`src/ca.rs`](../../src/ca.rs#L69))

#### 3.2.2 Leaf Certificate Generation
- [x] Generate certificates on-demand for each requested domain (`CONNECT` host), and present CN+SAN=`host` ([`src/ca.rs`](../../src/ca.rs#L91))
- [x] Implement leaf certificate caching with TTL (in-memory) ([`src/ca.rs`](../../src/ca.rs#L91))
- [ ] Multi-domain (multi-SAN) certificates (not implemented)
- [ ] OCSP response generation (not implemented)

### 3.3 Performance Requirements
- **Latency**: < 10ms additional latency for TLS handshake
- **Throughput**: Support ≥ 1000 concurrent connections
- **Memory**: Linear scaling with connection count
- **CPU**: Efficient certificate generation (pre-compute where possible)

### 3.4 Security Requirements
- [ ] Secure private key storage (encrypted at rest / HSM) (not implemented)
- [ ] Certificate transparency logging (optional)
- [x] Upstream TCP connect timeout (30s) ([`src/proxy.rs`](../../src/proxy.rs#L12))
- [ ] Rate limiting / connection limits (not implemented)
- [ ] Audit logging for all generated certificates
- [x] Upstream verification policy: verify by default; allow opt-out for controlled lab targets ([`src/profile.rs`](../../src/profile.rs#L190), [`src/main.rs`](../../src/main.rs#L236))
- [ ] Secure configuration management
- [x] Safer default listener binding: `127.0.0.1:8080` unless configured otherwise ([`src/main.rs`](../../src/main.rs#L109))
- [ ] Proxy authentication / ACLs (not implemented)
- [x] Safe defaults: avoid logging decrypted payloads; log only metadata and byte counts ([`src/proxy.rs`](../../src/proxy.rs#L174), [`src/proxy.rs`](../../src/proxy.rs#L262))

## 4. Implementation Details

### 4.1 Technology Stack

#### 4.1.1 Primary Dependencies
Authoritative dependencies live in [`Cargo.toml`](../../Cargo.toml#L1). Core crates in the current implementation:

- **Runtime / async IO**: `tokio`, `tokio-boring` ([`src/proxy.rs`](../../src/proxy.rs#L7))
- **TLS (BoringSSL bindings)**: `boring`, `boring-sys` ([`src/profile.rs`](../../src/profile.rs#L1))
- **HTTP/1.1 CONNECT parsing**: `httparse` ([`src/http_connect.rs`](../../src/http_connect.rs#L62))
- **Config**: `serde` + `toml` ([`src/config.rs`](../../src/config.rs#L1), [`src/main.rs`](../../src/main.rs#L152))
- **Tracing / telemetry**: `tracing` + OpenTelemetry OTLP (`opentelemetry-*`) ([`src/telemetry`](../../src/telemetry/logger.rs#L1))
- **Certificate compression decompressors**: `flate2` (zlib), `brotli`, `zstd` ([`src/compress.rs`](../../src/compress.rs#L88))

#### 4.1.2 BoringSSL Capability Notes (Reality Check)
BoringSSL exposes fewer knobs than "raw ClientHello crafting". For an MVP, focus on what is configurable via supported APIs:
- Generally feasible without patching: TLS min/max version, ALPN list, cipher suite lists (TLS 1.2 + TLS 1.3), supported groups list, GREASE enable/disable, extension permutation enable/disable.
- Version-dependent / library-limited: controlling the exact offered signature algorithms, OCSP/SCT offering behavior, certificate compression, and application settings.
- Typically requires patching/forking BoringSSL (or pinning to a very specific commit): arbitrary custom extension injection, byte-for-byte reproduction of a third-party ClientHello (including extension ordering/values beyond exposed config), and record-layer version "tricks".


### 4.2 Configuration Format

#### 4.2.1 Profile-Based Configuration
```toml
[profiles.default]
# Defaults are Chrome-like. You can override specific knobs below.
permute_extensions = true

[profiles."chrome-143-macos-arm64"]
permute_extensions = true

[profiles."firefox-145-macos-arm64"]
alpn_protos = ["h2", "http/1.1"]
permute_extensions = false

[profiles."safari-26.2-macos-arm64"]
alpn_protos = ["h2", "http/1.1"]
enable_ech_grease = false
cert_compression = ["zlib"]
# Optional knobs (examples):
# alpn_protos = ["h2", "http/1.1"]
# grease = true
# enable_ech_grease = true
# curves_list = "X25519MLKEM768:X25519:P-256:P-384"
# cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:..."
# sigalgs_list = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:..."
# enable_ocsp_stapling = true
# enable_signed_cert_timestamps = true
# cert_compression = ["zlib", "brotli", "zstd"]
# min_tls = "TLS1.2"
# max_tls = "TLS1.3"
```
#### 4.2.2 Proxy Configuration
```toml
[proxy]
mode = "explicit"

[proxy.mitm]
enabled = true # Set false for Phase 1 CONNECT-only tunnel development.

[proxy.listen]
# Explicit proxy listener (plain TCP speaking HTTP/1.1 CONNECT)
address = "127.0.0.1:8080" # Safe default: do not expose an unauthenticated proxy publicly.
backlog = 1024

[proxy.upstream]
# MVP: use CONNECT authority (host:port). Optional override for lab use-cases.
# default_upstream = "example.com:443"
# Default TLS profile name when the client does not provide a per-request override.
default_profile = "default"
# Additional PEM trust bundle for proxy→upstream TLS verification (optional).
# ca_file = "./path/to/upstream-ca.pem"
# Lab-only: disable upstream certificate verification (like curl -k).
insecure_skip_verify = false
# Lab-only: disable upstream hostname verification.
verify_hostname = true

[proxy.certificate]
ca_key_path = "./ca/private.key"
ca_cert_path = "./ca/certificate.pem"
cache_ttl = 3600 # seconds
```

Per-request profile selection:
- The client may include `X-PolyTLS-Upstream-Profile: <profile-name>` in the HTTP CONNECT request ([`src/http_connect.rs`](../../src/http_connect.rs#L7)).

Implementation notes:
- Config file format is TOML only (enforced by [`read_config`](../../src/main.rs#L152)); see [`config/example.toml`](../../config/example.toml#L1).
- Built-in profile names are created in [`init_default_profiles`](../../src/main.rs#L294); profile structs live in [`src/profile.rs`](../../src/profile.rs#L38).

### 4.3 API Design

#### 4.3.1 Control Plane API (Optional)
Not implemented in the current codebase (future enhancement).
```rust

#[derive(Clone)]
struct ProxyControl {
    // Profile management
    async fn add_profile(name: String, config: FingerprintProfile) -> Result<()>;
    async fn remove_profile(name: &str) -> Result<()>;
    async fn list_profiles() -> Result<Vec<ProfileInfo>>;
    
    // Certificate management
    async fn get_ca_certificate() -> Result<Vec<u8>>;
    async fn revoke_certificate(serial: &str) -> Result<()>;
    async fn list_certificates() -> Result<Vec<CertificateInfo>>;
    
    // Runtime statistics
    async fn get_stats() -> Result<ProxyStats>;
    async fn get_connection_info(conn_id: u64) -> Result<ConnectionInfo>;
}
```

#### 4.3.2 Data Plane

The data plane is implemented as a per-connection async task that performs:

1. Parse `CONNECT` (and optionally extract `X-PolyTLS-Upstream-Profile`) via [`read_connect_request`](../../src/http_connect.rs#L36).
2. Establish an upstream TCP connection with a timeout ([`src/proxy.rs`](../../src/proxy.rs#L115)).
3. Reply `HTTP/1.1 200 Connection Established` ([`src/proxy.rs`](../../src/proxy.rs#L272)).
4. Relay bytes bidirectionally using `tokio::io::copy_bidirectional` ([`src/proxy.rs`](../../src/proxy.rs#L134), [`src/proxy.rs`](../../src/proxy.rs#L259)).

Two modes differ only in what is relayed:

- **Passthrough**: raw `TcpStream` ↔ `TcpStream`, with `PrefixedStream` used to re-inject any bytes already read past the end of the CONNECT headers ([`src/prefixed_stream.rs`](../../src/prefixed_stream.rs#L5)).
- **MITM**: `tokio_boring::SslStream` ↔ `tokio_boring::SslStream` (TLS terminated on the proxy, then re-originated upstream), with SNI mismatch enforcement and ALPN compatibility enforcement (ALPN must match when present; if upstream omits ALPN, treat it as compatible with `http/1.1`) ([`src/proxy.rs`](../../src/proxy.rs#L213), [`src/proxy.rs`](../../src/proxy.rs#L237)).

The current code does not model a persistent `ProxyConnection` struct or store per-connection metadata beyond logs.

### 4.4 Error Handling

#### 4.4.1 Error Categories

1.  **Configuration Errors**: Invalid profiles, missing CA files

2.  **Certificate Errors**: Generation failures, validation failures

3.  **TLS Errors**: Handshake failures, unsupported parameters

4.  **Network Errors**: Connection refused, timeouts

5.  **Resource Errors**: File I/O, memory allocation


#### 4.4.2 Recovery Strategies

- **CONNECT request validation**: parse/validation failures map to HTTP errors (`405`/`431`/`400`) before sending `200` ([`src/proxy.rs`](../../src/proxy.rs#L279)).
- **Upstream connect failures**: map to `502`/`504` before sending `200` ([`src/proxy.rs`](../../src/proxy.rs#L116), [`src/proxy.rs`](../../src/proxy.rs#L185)).
- **TLS failures after `200`**: the tunnel is already established; clients observe EOF/connection reset (current behavior).
- **Certificate caching**: leaf certificates are cached with a TTL to avoid repeated generation ([`src/ca.rs`](../../src/ca.rs#L91)).
- [ ] Retry with fallback profile (not implemented)
- [ ] Circuit breaker/backoff for upstream failures (not implemented)


## 5. Implementation Status (Current)

Implemented:
- Explicit proxy (HTTP/1.1 `CONNECT`) with `Passthrough` and `MITM` modes ([`src/proxy.rs`](../../src/proxy.rs#L35))
- Root CA generation + per-host leaf minting with TTL cache ([`src/ca.rs`](../../src/ca.rs#L40))
- Upstream TLS profile selection (default + per-request header) ([`src/main.rs`](../../src/main.rs#L270), [`src/http_connect.rs`](../../src/http_connect.rs#L84))
- Upstream ClientHello knobs via BoringSSL (GREASE/permutation/ALPN/curves/cipher list/sigalgs/OCSP/SCT/cert compression) ([`src/profile.rs`](../../src/profile.rs#L217))
- OpenTelemetry/OTLP logging+metrics plumbing and graceful shutdown ([`src/telemetry/logger.rs`](../../src/telemetry/logger.rs#L1), [`src/main.rs`](../../src/main.rs#L132))
- **H2 Support**: L4 tunneling of HTTP/2 traffic via coordinated ALPN negotiation ([`src/proxy.rs`](../../src/proxy.rs)).

Not implemented yet (examples):
- Control plane API, hot-reload configuration, health/readiness endpoints ([`docs/specs/tls_mitm.md`](tls_mitm.md#L251))
- Transparent/TProxy mode (explicit mode only; enforced) ([`src/main.rs`](../../src/main.rs#L119))
- HTTP/2 translation/fingerprinting (SETTINGS/HPACK/etc); current relay is byte-only ([`src/proxy.rs`](../../src/proxy.rs#L259))


## 6. Testing Strategy

### 6.1 Unit Tests

-   Certificate generation and validation

-   Configuration parsing

-   Profile application logic


### 6.2 Integration Tests

-   End-to-end proxy functionality

-   TLS fingerprint verification using external tools

-   Performance under load


### 6.3 Fingerprint Verification Tests
```bash

# Sanity: HTTPS via explicit proxy (CONNECT)
$ curl -v -x http://127.0.0.1:8080 https://example.com/

# MITM mode: trust the proxy root CA (recommended) or use -k/--insecure (lab only)
$ curl --cacert ./ca/certificate.pem -v -x http://127.0.0.1:8080 https://example.com/

# Per-request upstream profile selection (CONNECT header)
$ curl --proxy-header "X-PolyTLS-Upstream-Profile: safari" --cacert ./ca/certificate.pem -v -x http://127.0.0.1:8080 https://example.com/

# OpenSSL via proxy (if supported by your OpenSSL build)
$ openssl s_client -proxy 127.0.0.1:8080 -connect example.com:443 -servername example.com </dev/null | grep -A 1 "Cipher"

# Outbound (proxy→upstream) ClientHello verification:
# capture traffic on the proxy host and compute JA3/JA4 from the pcap using your preferred tool.
# (The JA3/JA4 you care about for "profiles" is the outbound handshake, not the client→proxy handshake.)
```

## 7. Deployment Considerations

### 7.1 Containerization
The repository includes a production-style Docker build in [`docker/Dockerfile`](../../docker/Dockerfile#L1).

Operational notes:
- For MITM mode, clients must trust the proxy root CA (or use `--insecure` for lab-only testing). Persist the CA directory (`./ca`) across container restarts to keep a stable root CA.
- For proxy→upstream verification, the container needs system trust roots (`ca-certificates` is installed in the current Dockerfile).

### 7.2 Kubernetes Deployment

-   ConfigMap for fingerprint profiles

-   Secret for CA private key

-   Horizontal Pod Autoscaler based on connection count

-   NetworkPolicy for ingress/egress rules


### 7.3 Monitoring

- OpenTelemetry/OTLP logging and metrics are initialized from [`src/main.rs`](../../src/main.rs#L95) via [`src/telemetry`](../../src/telemetry/logger.rs#L1).
- No HTTP health/readiness endpoints are implemented (future enhancement).


## 8. Risk Mitigation

### 8.1 Technical Risks

-   **BoringSSL API instability**: Pin to specific BoringSSL version

-   **Certificate revocation**: Implement OCSP stapling where possible

-   **Performance bottlenecks**: Profile and optimize hot paths


### 8.2 Security Risks

-   **CA compromise**: Store private key in secure enclave/HSM

-   **Traffic inspection**: Clear data boundaries, no storage of decrypted content

-   **DoS attacks**: Rate limiting, connection limits, timeouts


### 8.3 Operational Risks

-   **Configuration drift**: Version control for configs, schema validation

-   **Certificate expiration**: Automated renewal, alerting


## 9. Future Enhancements

### 9.1 Short-term

- HTTP/2 **L7** proxying (frame parsing/forwarding, SETTINGS, HPACK, pseudo-header ordering, prioritization) (L4 tunneling is already supported)
- gRPC and Protocol Buffers inspection hooks
- GUI for configuration management


### 9.2 Medium-term

- QUIC and HTTP/3 support
- Machine learning for adaptive fingerprint selection
- Distributed deployment with shared state


### 9.3 Long-term

- Integration with service mesh (Istio, Linkerd)
- Hardware acceleration support
- Formal verification of cryptographic components


## 10. Success Criteria

### 10.1 Functional

-   Successfully proxies HTTPS traffic for major websites

-   Produces expected TLS handshake characteristics per configured profile in controlled verification tests

-   Generates valid certificates for arbitrary domains

-   Maintains < 5% performance overhead vs direct connection


### 10.2 Non-functional

-   Handles 10k concurrent connections on 4-core machine

-   Memory usage < 50MB base + 10KB per connection

-   99.9% availability in 30-day period

-   Zero critical security vulnerabilities in audit
