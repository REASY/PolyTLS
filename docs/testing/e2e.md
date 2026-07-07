# End-to-End (E2E) Proxy Tests

The proxy E2E tests are implemented as **ignored** unit tests (they bind local TCP listeners and do real TLS handshakes).

## Run

- Run all ignored tests:
  - `cargo test -- --ignored`
- Run only the proxy E2E tests:
  - `cargo test proxy::tests -- --ignored`
- Run a single test (example):
  - `cargo test passthrough_tunnels_tls_end_to_end -- --ignored --nocapture`

## What They Verify

- **Passthrough**: end-to-end TLS is between the client and the origin; the proxy just relays bytes.
- **MITM**: the client terminates TLS on the proxy (proxy-minted leaf cert), and the proxy opens a separate TLS connection upstream.
- **Profile selection**: `X-PolyTLS-Upstream-Profile` on HTTP `CONNECT` or the SOCKS5 username selects the per-request upstream profile.
- **SOCKS5 MITM identity**: domain targets can be MITM'd directly; IP targets with ClientHello SNI use SNI for the certificate/upstream TLS name while still dialing the IP; IP targets without ClientHello SNI fail closed.
- **Upstream SOCKS5 chaining**: HTTP CONNECT, SOCKS5 frontend, and MITM flows can dial the target through a configured upstream SOCKS5 proxy.
- **Insecure upstream**: `UpstreamVerification.insecure_skip_verify` allows connecting to upstream servers with self-signed/private-CA certs (lab use only).
