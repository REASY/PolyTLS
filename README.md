# PolyTLS

An explicit HTTP/1.1 `CONNECT` proxy that can run in:

- **Passthrough mode**: tunnels bytes (no TLS termination).
- **MITM mode**: terminates client TLS and originates a new upstream TLS connection using **BoringSSL** via `boring` + `tokio-boring`.

Docs: [docs/README.md](docs/README.md). Use this only on systems and traffic you own or are explicitly authorized to test.

## Build

```bash
cargo build
```

Building `boring-sys` (BoringSSL) requires a working C/C++ toolchain and CMake on your system.

## Build docker image

```console
APP_VERSION=$(cargo pkgid --manifest-path Cargo.toml | cut -d '@' -f2); docker build --platform linux/amd64 --build-arg BUILD_DATE="$(date +'%Y-%m-%dT%H:%M:%S%z')" \
    --build-arg COMMIT_SHA=$(git rev-parse HEAD) \
    --build-arg VERSION=$(cargo pkgid --manifest-path Cargo.toml | cut -d '@' -f2) \
    . -f docker/Dockerfile \
   -t polytls:$APP_VERSION
```

## Run

### Passthrough (default)

```bash
cargo run -- --listen 127.0.0.1:8080
curl -v -x http://127.0.0.1:8080 https://example.com/
```

### MITM mode (TOML config)

```bash
cargo run -- --config config/example.toml
```

Or without a config file:

```bash
cargo run -- --mode mitm --listen 127.0.0.1:8080
```

On first run in MITM mode, a root CA is created at `./ca/private.key` and `./ca/certificate.pem`.
Install `./ca/certificate.pem` into your **test client** trust store to avoid certificate warnings.

For a quick smoke test without installing the CA (not recommended for real testing), you can use:

```bash
curl -vk -x http://127.0.0.1:8080 https://example.com/
```

### Testing self-signed upstream servers (lab)

If the **upstream** TLS server uses a self-signed certificate or private CA, either add that CA to the proxy:

```bash
cargo run -- --config config/example.toml --upstream-ca-file ./path/to/upstream-ca.pem
```

Or disable proxy→upstream verification entirely (lab only):

```bash
cargo run -- --config config/example.toml --upstream-insecure-skip-verify
```

### Selecting an upstream TLS profile per request

In MITM mode, you can select which upstream TLS profile the proxy uses by adding a header to the HTTP `CONNECT` request:

```bash
curl --proxy-header 'X-PolyTLS-Upstream-Profile: chrome-143-macos-arm64' -x http://127.0.0.1:8080 https://example.com/
```

Other built-in profiles:
- `firefox-145-macos-arm64`
- `safari-26.2-macos-arm64`

Profiles can be defined in TOML under `[profiles]` (see [config/example.toml](config/example.toml)).
