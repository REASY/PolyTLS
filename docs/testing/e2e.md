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
- **Profile selection**: `X-PolyTLS-Upstream-Profile` on `CONNECT` selects the per-request upstream profile (validated via ALPN negotiation).
- **Insecure upstream**: `UpstreamVerification.insecure_skip_verify` allows connecting to upstream servers with self-signed/private-CA certs (lab use only).

