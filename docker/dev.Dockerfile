FROM ubuntu:25.10

ARG COMMIT_SHA
ARG BUILD_DATE

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.92.0 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      build-essential cmake libclang-dev iputils-ping net-tools curl binutils python3 pkg-config \
      ca-certificates libdw-dev libssl-dev libsasl2-dev git unzip && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

# install toolchain
RUN set -eux; \
    rustArch='x86_64-unknown-linux-gnu' \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- --default-toolchain $RUST_VERSION -y; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;\
    rustup toolchain install stable; \
    rustup component add llvm-tools-preview rustfmt clippy; \
    cargo +stable install cargo-llvm-cov --locked;

ENTRYPOINT ["/bin/bash"]

LABEL \
    org.opencontainers.image.name="PolyTLS-dev" \
    org.opencontainers.image.description="Tokio-based explicit HTTP/1.1 CONNECT proxy with TLS passthrough or MITM (BoringSSL), configurable upstream TLS fingerprint profiles, and OpenTelemetry/OTLP telemetry." \
    org.opencontainers.image.url="https://github.com/REASY/polytls" \
    org.opencontainers.image.source="https://github.com/REASY/polytls.git" \
    org.opencontainers.image.licenses="MIT License" \
    org.opencontainers.image.authors="Artavazd Balaian <reasyu@gmail.com>" \
    org.opencontainers.image.base.name="ubuntu:25.10" \
    org.opencontainers.image.created="$BUILD_DATE" \
    org.opencontainers.image.revision="${COMMIT_SHA}"
