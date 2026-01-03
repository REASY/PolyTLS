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
- Optional (instrument std too): `rustup component add rust-src --toolchain nightly`

## Running tests under ASan / LSan / TSan

Use [`scripts/sanitizer-test.sh`](../../scripts/sanitizer-test.sh):

- AddressSanitizer (ASan): `bash scripts/sanitizer-test.sh asan`
- LeakSanitizer (LSan): `bash scripts/sanitizer-test.sh lsan`
- ThreadSanitizer (TSan): `bash scripts/sanitizer-test.sh tsan`

TSan requires rebuilding the standard library with the same sanitizer to avoid ABI-mismatch errors. [`scripts/sanitizer-test.sh`](../../scripts/sanitizer-test.sh) automatically enables `-Zbuild-std` for `tsan` (requires `rust-src`).

To run only the zstd callback tests:

`bash scripts/sanitizer-test.sh asan test raw_ssl_cert_decompress_zstd`

To also build an instrumented standard library:

`bash scripts/sanitizer-test.sh asan -Zbuild-std raw_ssl_cert_decompress_zstd`

## Running the proxy under ASan

`bash scripts/sanitizer-test.sh asan run -- --config config/example.toml`

## macOS note: "Interceptors are not working"

On Apple platforms, sanitizer runtimes strip `DYLD_INSERT_LIBRARIES` for child processes by default. This breaks `cargo test` with ASan when `rustc` later `dlopen`s ASan-instrumented proc-macro dylibs.

[`scripts/sanitizer-test.sh`](../../scripts/sanitizer-test.sh) sets `*SAN_OPTIONS=strip_env=0` so `DYLD_INSERT_LIBRARIES` stays active for `rustc` and the test binary.
