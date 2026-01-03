# Sanitizers

PolyTLS can be run under Rust sanitizers (nightly) to catch memory bugs across Rust + FFI (e.g., BoringSSL callbacks).

## Memory testing notes

[`src/compress.rs`](../../src/compress.rs) includes unit tests for the BoringSSL zstd certificate decompression callback ([`raw_ssl_cert_decompress_zstd`](../../src/compress.rs#L143)) that exercise a matrix of pointer/length combinations plus a successful roundtrip.

### Scudo (Linux only)

On Linux, `cargo test` will use the `scudo` allocator for the unit-test binary (configured via a `target_os = "linux"` dev-dependency and `#[global_allocator]` in the test module).

On macOS, `scudo` currently fails to build (the bundled scudo-standalone in `scudo-sys` has no Darwin platform implementation), so the tests run with the default allocator instead.

Note: this only affects Rust allocations. The callback itself allocates output via BoringSSL (`CRYPTO_BUFFER_alloc` / `CRYPTO_BUFFER_free`), so to catch out-of-bounds writes in that buffer you’ll generally want a sanitizer (e.g., ASan) or a system-level hardened allocator that replaces `malloc`/`free`.

## Prerequisites

- Nightly toolchain: `rustup toolchain install nightly`

## Sanitized runs (Nightly)

You can run the proxy or tests with sanitizers (address, leak) using the provided script.

```bash
# Run with address sanitizer
./scripts/sanitized.sh address run -- --config config/example.toml

# Run tests with leak sanitizer
./scripts/sanitized.sh leak test
```