mod alpn;
mod ca;
mod compress;
mod config;
mod error;
mod http_connect;
mod mitm;
mod prefixed_stream;
mod profile;
mod proxy;
mod socks5;
mod telemetry;
mod tls_client_hello;
mod upstream;

use clap::Parser;
use clap::ValueEnum;
use opentelemetry::global;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::metadata::LevelFilter;
use tracing::{error, info};

use crate::ca::{CaConfig, CaManager};
use crate::config::Config;
use crate::error::Result;
use crate::mitm::MitmState;
use crate::profile::{
    DEFAULT_UPSTREAM_PROFILE, UpstreamProfile, UpstreamProfiles, UpstreamVerification,
};
use crate::proxy::{ProxyProtocol, ProxySettings};
use crate::socks5::UpstreamAuth;
use crate::telemetry::{init_meter_provider, init_otlp_logging};
use crate::upstream::{Socks5Proxy, UpstreamProxy};
use boring::ssl::SslVersion;
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(
    name = "polytls",
    version,
    about = "HTTP CONNECT/SOCKS5 proxy with optional TLS MITM (authorized use only)."
)]
struct Args {
    /// Listen address for the explicit proxy (HTTP/1.1 CONNECT over plain TCP).
    #[arg(long)]
    listen: Option<String>,

    /// Optional config file (TOML).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Proxy mode.
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,

    /// Frontend proxy protocol.
    #[arg(long, value_enum)]
    proxy_protocol: Option<ProxyProtocolArg>,

    /// Root CA private key path (PEM, PKCS#8 recommended).
    #[arg(long, default_value = "./ca/private.key")]
    ca_key_path: PathBuf,

    /// Root CA certificate path (PEM).
    #[arg(long, default_value = "./ca/certificate.pem")]
    ca_cert_path: PathBuf,

    /// Leaf cert cache TTL in seconds.
    #[arg(long, default_value_t = 3600)]
    leaf_ttl_secs: u64,

    /// Additional upstream CA bundle (PEM) for proxy→upstream TLS verification.
    #[arg(long)]
    upstream_ca_file: Option<PathBuf>,

    /// Disable proxy→upstream certificate verification (lab use only).
    #[arg(long)]
    upstream_insecure_skip_verify: bool,

    /// Disable proxy→upstream hostname verification (lab use only).
    #[arg(long)]
    upstream_no_verify_hostname: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum ModeArg {
    Passthrough,
    Mitm,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum ProxyProtocolArg {
    /// HTTP/1.1 CONNECT explicit proxy frontend.
    Explicit,
    /// HTTP/1.1 CONNECT explicit proxy frontend.
    HttpConnect,
    /// SOCKS5 CONNECT frontend.
    Socks5,
}

#[derive(Debug, Clone, Copy)]
enum ModeSelection {
    Passthrough,
    Mitm,
}

#[tokio::main]
async fn main() -> Result<()> {
    let logger_provider = init_otlp_logging(
        "PolyTLS",
        LevelFilter::INFO,
        &["waf_core", "waf_feature_sync"],
    )?;

    let meter_provider = init_meter_provider("PolyTLS", Duration::from_secs(5))?;
    global::set_meter_provider(meter_provider.clone());
    info!("Meter provider initialized");

    let args = Args::parse();
    let file_config = read_config(&args).await?;

    let listen = args
        .listen
        .clone()
        .or_else(|| file_config.as_ref().map(|c| c.proxy.listen.address.clone()))
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let listen_addr: SocketAddr = listen
        .parse()
        .map_err(|e| error::ErrorKind::Config(format!("invalid listen address: {e}")))?;

    let settings = init_proxy_settings(args, file_config).await?;

    let shutdown: CancellationToken = CancellationToken::new();
    let shutdown_task = set_shutdown_hook(shutdown.clone());

    let run_res = proxy::run(listen_addr, settings, shutdown.clone()).await;
    shutdown.cancel();
    let _ = shutdown_task.await;

    info!("Shutting down OTLP providers");
    let _ = logger_provider.shutdown().inspect_err(|err| {
        error!("Failed to shutdown OTLP log provider: {:?}", err);
    });
    let _ = meter_provider.shutdown().inspect_err(|err| {
        error!("Failed to shutdown OTLP meter provider: {:?}", err);
    });

    info!("Shutdown complete");

    run_res
}

async fn read_config(args: &Args) -> Result<Option<Config>> {
    read_config_with_env_source(args.config.as_deref(), None).await
}

async fn read_config_with_env_source(
    config_path: Option<&std::path::Path>,
    env_source: Option<HashMap<String, String>>,
) -> Result<Option<Config>> {
    let has_env = env_source
        .as_ref()
        .map(|env| env.keys().any(|key| key.starts_with("POLYTLS__")))
        .unwrap_or_else(|| std::env::vars().any(|(key, _)| key.starts_with("POLYTLS__")));

    if config_path.is_none() && !has_env {
        return Ok(None);
    }

    let mut builder = config_rs::Config::builder();

    if let Some(config_path) = config_path {
        match config_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref()
        {
            Some("toml") => {
                builder = builder.add_source(
                    config_rs::File::from(config_path)
                        .format(config_rs::FileFormat::Toml)
                        .required(true),
                );
            }
            x => {
                return Err(error::ErrorKind::Config(format!(
                    "unsupported config format {x:?} for {} (expected .toml)",
                    config_path.display()
                ))
                .into());
            }
        }
    }

    let env = config_rs::Environment::with_prefix("POLYTLS")
        .separator("__")
        .ignore_empty(true)
        .try_parsing(true);
    let env = if let Some(env_source) = env_source {
        env.source(Some(env_source))
    } else {
        env
    };

    builder = builder.add_source(env);

    builder
        .build()
        .and_then(|cfg| cfg.try_deserialize::<Config>())
        .map(Some)
        .map_err(|e| error::ErrorKind::Config(format!("failed to load config: {e}")).into())
}

async fn init_proxy_settings(args: Args, file_config: Option<Config>) -> Result<ProxySettings> {
    let protocol = if let Some(protocol) = args.proxy_protocol {
        proxy_protocol_from_arg(protocol)
    } else if let Some(mode) = file_config.as_ref().and_then(|c| c.proxy.mode.as_deref()) {
        parse_proxy_protocol(mode)?
    } else {
        ProxyProtocol::HttpConnect
    };

    let mode = args
        .mode
        .map(|m| match m {
            ModeArg::Passthrough => ModeSelection::Passthrough,
            ModeArg::Mitm => ModeSelection::Mitm,
        })
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|c| c.proxy.mitm.as_ref())
                .map(|m| {
                    if m.enabled {
                        ModeSelection::Mitm
                    } else {
                        ModeSelection::Passthrough
                    }
                })
        })
        .unwrap_or(ModeSelection::Passthrough);

    let upstream = init_upstream_proxy(file_config.as_ref())?;

    let settings = match mode {
        ModeSelection::Passthrough => ProxySettings {
            protocol,
            mode: proxy::ProxyMode::Passthrough,
            upstream,
        },
        ModeSelection::Mitm => {
            let (ca_key_path, ca_cert_path, leaf_ttl_secs) = file_config
                .as_ref()
                .and_then(|c| c.proxy.certificate.as_ref())
                .map(|cert| {
                    (
                        PathBuf::from(&cert.ca_key_path),
                        PathBuf::from(&cert.ca_cert_path),
                        cert.cache_ttl.unwrap_or(args.leaf_ttl_secs),
                    )
                })
                .unwrap_or((
                    args.ca_key_path.clone(),
                    args.ca_cert_path.clone(),
                    args.leaf_ttl_secs,
                ));

            let ca = CaManager::load_or_create(CaConfig {
                ca_key_path,
                ca_cert_path,
                leaf_ttl: Duration::from_secs(leaf_ttl_secs),
            })
            .await?;

            let mut upstream_verification = file_config
                .as_ref()
                .and_then(|c| c.proxy.upstream.as_ref())
                .map(|cfg| UpstreamVerification {
                    insecure_skip_verify: cfg.insecure_skip_verify.unwrap_or(false),
                    verify_hostname: cfg.verify_hostname.unwrap_or(true),
                    ca_file: cfg.ca_file.clone(),
                })
                .unwrap_or_default();

            if let Some(ca_file) = args.upstream_ca_file.as_ref() {
                upstream_verification.ca_file = Some(ca_file.to_string_lossy().to_string());
            }

            if args.upstream_insecure_skip_verify {
                upstream_verification.insecure_skip_verify = true;
                upstream_verification.verify_hostname = false;
            }

            if args.upstream_no_verify_hostname {
                upstream_verification.verify_hostname = false;
            }

            let mut profiles = init_default_profiles();

            let default_profile_base = UpstreamProfile::default();
            if let Some(extra_profiles) = file_config.as_ref().and_then(|c| c.profiles.as_ref()) {
                for (name, cfg) in extra_profiles {
                    let base = profiles.get(name).unwrap_or(&default_profile_base);
                    let profile = apply_upstream_profile_config(base, cfg)?;
                    profiles.insert(name.clone(), profile);
                }
            }

            let default_profile = file_config
                .as_ref()
                .and_then(|c| c.proxy.upstream.as_ref())
                .and_then(|u| u.default_profile.clone())
                .unwrap_or_else(|| DEFAULT_UPSTREAM_PROFILE.to_string());

            let upstream_profiles = UpstreamProfiles::new(default_profile, profiles)?;
            // Build the default connector eagerly to fail fast on misconfiguration.
            upstream_profiles
                .connector_for(None, &upstream_verification)
                .await?;

            ProxySettings {
                protocol,
                mode: proxy::ProxyMode::Mitm(MitmState {
                    ca: Arc::new(ca),
                    upstream_profiles,
                    upstream_verification,
                }),
                upstream,
            }
        }
    };
    Ok(settings)
}

fn proxy_protocol_from_arg(arg: ProxyProtocolArg) -> ProxyProtocol {
    match arg {
        ProxyProtocolArg::Explicit | ProxyProtocolArg::HttpConnect => ProxyProtocol::HttpConnect,
        ProxyProtocolArg::Socks5 => ProxyProtocol::Socks5,
    }
}

fn parse_proxy_protocol(input: &str) -> Result<ProxyProtocol> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "explicit" | "http-connect" | "http_connect" | "httpconnect" => {
            Ok(ProxyProtocol::HttpConnect)
        }
        "socks5" | "socks" => Ok(ProxyProtocol::Socks5),
        other => Err(error::ErrorKind::Config(format!(
            "unsupported proxy.mode={other:?} (expected \"explicit\" or \"socks5\")"
        ))
        .into()),
    }
}

fn init_upstream_proxy(file_config: Option<&Config>) -> Result<UpstreamProxy> {
    let Some(proxy) = file_config
        .and_then(|c| c.proxy.upstream.as_ref())
        .and_then(|u| u.proxy.as_ref())
    else {
        return Ok(UpstreamProxy::Direct);
    };

    parse_upstream_proxy_config(proxy)
}

fn parse_upstream_proxy_config(cfg: &config::UpstreamProxyConfig) -> Result<UpstreamProxy> {
    let protocol = cfg.protocol.trim().to_ascii_lowercase();
    match protocol.as_str() {
        "socks5" | "socks" => {
            let address = cfg.address.trim();
            if address.is_empty() {
                return Err(error::ErrorKind::Config(
                    "proxy.upstream.proxy.address must not be empty".to_string(),
                )
                .into());
            }

            let auth = match (&cfg.username, &cfg.password) {
                (Some(username), password) => {
                    let username = username.trim();
                    if username.is_empty() {
                        return Err(error::ErrorKind::Config(
                            "proxy.upstream.proxy.username must not be empty".to_string(),
                        )
                        .into());
                    }
                    Some(UpstreamAuth {
                        username: username.to_string(),
                        password: password.clone().unwrap_or_default(),
                    })
                }
                (None, Some(_)) => {
                    return Err(error::ErrorKind::Config(
                        "proxy.upstream.proxy.username is required when password is set"
                            .to_string(),
                    )
                    .into());
                }
                (None, None) => None,
            };

            Ok(UpstreamProxy::Socks5(Socks5Proxy {
                address: address.to_string(),
                auth,
            }))
        }
        other => Err(error::ErrorKind::Config(format!(
            "unsupported proxy.upstream.proxy.protocol={other:?} (expected \"socks5\")"
        ))
        .into()),
    }
}

fn init_default_profiles() -> HashMap<String, UpstreamProfile> {
    let mut profiles: HashMap<String, UpstreamProfile> = HashMap::new();
    let chrome_like = UpstreamProfile::default();
    profiles.insert("chrome".to_string(), chrome_like.clone());
    profiles.insert("chrome-143-macos-x86_64".to_string(), chrome_like.clone());
    profiles.insert("chrome-143-macos-arm64".to_string(), chrome_like);

    let firefox = UpstreamProfile::firefox_145_macos_arm64();
    profiles.insert(DEFAULT_UPSTREAM_PROFILE.to_string(), firefox.clone());
    profiles.insert("firefox".to_string(), firefox.clone());
    profiles.insert("firefox-145-macos-arm64".to_string(), firefox);

    let safari = UpstreamProfile::safari_26_2_macos_arm64();
    profiles.insert("safari".to_string(), safari.clone());
    profiles.insert("safari-26.2-macos-arm64".to_string(), safari);
    profiles
}

fn apply_upstream_profile_config(
    base: &UpstreamProfile,
    cfg: &config::UpstreamProfileConfig,
) -> Result<UpstreamProfile> {
    let mut profile = base.clone();

    if let Some(v) = cfg.alpn_protos.as_ref() {
        profile.alpn_protos = v.clone();
    }
    if let Some(v) = cfg.alps_use_new_codepoint {
        profile.alps_use_new_codepoint = v;
    }
    if let Some(v) = cfg.grease {
        profile.grease = v;
    }
    if let Some(v) = cfg.enable_ech_grease {
        profile.enable_ech_grease = v;
    }
    if let Some(v) = cfg.permute_extensions {
        profile.permute_extensions = v;
    }
    if let Some(v) = cfg.disable_session_ticket {
        profile.disable_session_ticket = v;
    }
    if let Some(v) = cfg.curves_list.as_ref() {
        profile.curves_list = Some(v.clone());
    }
    if let Some(v) = cfg.cipher_list.as_ref() {
        profile.cipher_list = Some(v.clone());
    }
    if let Some(v) = cfg.sigalgs_list.as_ref() {
        profile.sigalgs_list = Some(v.clone());
    }
    if let Some(v) = cfg.enable_ocsp_stapling {
        profile.enable_ocsp_stapling = v;
    }
    if let Some(v) = cfg.enable_signed_cert_timestamps {
        profile.enable_signed_cert_timestamps = v;
    }
    if let Some(v) = cfg.cert_compression.as_ref() {
        profile.cert_compression = compress::parse_cert_compression_list(v)?;
    }
    if let Some(v) = cfg.min_tls.as_deref() {
        profile.min_tls = Some(parse_tls_version(v)?);
    }
    if let Some(v) = cfg.max_tls.as_deref() {
        profile.max_tls = Some(parse_tls_version(v)?);
    }

    Ok(profile)
}

fn parse_tls_version(input: &str) -> Result<SslVersion> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "tls1" | "tls1.0" | "tlsv1.0" | "tls1_0" => Ok(SslVersion::TLS1),
        "tls1.1" | "tlsv1.1" | "tls1_1" => Ok(SslVersion::TLS1_1),
        "tls1.2" | "tlsv1.2" | "tls1_2" => Ok(SslVersion::TLS1_2),
        "tls1.3" | "tlsv1.3" | "tls1_3" => Ok(SslVersion::TLS1_3),
        other => Err(error::ErrorKind::Config(format!(
            "invalid TLS version {other:?} (expected TLS1.2, TLS1.3, ...)"
        ))
        .into()),
    }
}

fn set_shutdown_hook(shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal as unix_signal};

            let mut term = match unix_signal(SignalKind::terminate()) {
                Ok(sig) => sig,
                Err(err) => {
                    tracing::warn!(error=%err, "failed to install SIGTERM handler");
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = signal::ctrl_c() => {
                            tracing::info!("Ctrl+C received");
                            shutdown.cancel();
                            return;
                        }
                    }
                }
            };

            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = signal::ctrl_c() => tracing::info!("Ctrl+C received"),
                _ = term.recv() => tracing::info!("SIGTERM received"),
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = signal::ctrl_c() => tracing::info!("Ctrl+C received"),
            }
        }

        shutdown.cancel();
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::CertCompression;

    #[test]
    fn parse_tls_version_accepts_common_variants() {
        assert_eq!(parse_tls_version("TLS1").unwrap(), SslVersion::TLS1);
        assert_eq!(parse_tls_version("tls1.0").unwrap(), SslVersion::TLS1);
        assert_eq!(parse_tls_version("tlsv1.2").unwrap(), SslVersion::TLS1_2);
        assert_eq!(parse_tls_version("TLS1_3").unwrap(), SslVersion::TLS1_3);
    }

    #[test]
    fn parse_tls_version_rejects_unknown_values() {
        let err = parse_tls_version("ssl3").expect_err("invalid TLS version should error");
        match err.kind() {
            error::ErrorKind::Config(msg) => assert!(msg.contains("invalid TLS version")),
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn parse_proxy_protocol_accepts_explicit_and_socks5() {
        assert!(matches!(
            parse_proxy_protocol("explicit").unwrap(),
            ProxyProtocol::HttpConnect
        ));
        assert!(matches!(
            parse_proxy_protocol("http-connect").unwrap(),
            ProxyProtocol::HttpConnect
        ));
        assert!(matches!(
            parse_proxy_protocol("socks5").unwrap(),
            ProxyProtocol::Socks5
        ));
    }

    #[test]
    fn parse_upstream_proxy_config_accepts_socks5_auth() {
        let cfg = config::UpstreamProxyConfig {
            protocol: "socks5".to_string(),
            address: "127.0.0.1:9050".to_string(),
            username: Some("chain-user".to_string()),
            password: Some("chain-pass".to_string()),
        };

        let proxy = parse_upstream_proxy_config(&cfg).expect("upstream proxy should parse");

        let UpstreamProxy::Socks5(proxy) = proxy else {
            panic!("expected SOCKS5 upstream proxy");
        };
        assert_eq!(proxy.address, "127.0.0.1:9050");
        let auth = proxy.auth.expect("auth should be configured");
        assert_eq!(auth.username, "chain-user");
        assert_eq!(auth.password, "chain-pass");
    }

    #[test]
    fn parse_upstream_proxy_config_rejects_password_without_username() {
        let cfg = config::UpstreamProxyConfig {
            protocol: "socks5".to_string(),
            address: "127.0.0.1:9050".to_string(),
            username: None,
            password: Some("chain-pass".to_string()),
        };

        let err =
            parse_upstream_proxy_config(&cfg).expect_err("password without username should fail");
        match err.kind() {
            error::ErrorKind::Config(msg) => {
                assert!(msg.contains("username is required"));
            }
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn apply_upstream_profile_config_overrides_selected_fields() {
        let base = UpstreamProfile::chrome_143_macos_arm64();
        let cfg = config::UpstreamProfileConfig {
            alpn_protos: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            alps_use_new_codepoint: None,
            grease: Some(false),
            enable_ech_grease: None,
            permute_extensions: Some(false),
            disable_session_ticket: None,
            curves_list: None,
            cipher_list: None,
            sigalgs_list: None,
            enable_ocsp_stapling: None,
            enable_signed_cert_timestamps: None,
            cert_compression: Some(vec!["zlib".to_string(), "zstd".to_string()]),
            min_tls: Some("TLS1.3".to_string()),
            max_tls: Some("tls1.3".to_string()),
        };

        let out = apply_upstream_profile_config(&base, &cfg).expect("profile config should apply");

        assert_eq!(out.alpn_protos, vec!["h2", "http/1.1"]);
        assert!(!out.grease);
        assert!(!out.permute_extensions);
        assert_eq!(
            out.cert_compression,
            vec![CertCompression::Zlib, CertCompression::Zstd]
        );
        assert_eq!(out.min_tls, Some(SslVersion::TLS1_3));
        assert_eq!(out.max_tls, Some(SslVersion::TLS1_3));
        assert_eq!(
            out.enable_ocsp_stapling, base.enable_ocsp_stapling,
            "unset fields should inherit from base profile"
        );
    }

    #[test]
    fn init_default_profiles_contains_expected_aliases() {
        let profiles = init_default_profiles();

        for name in [
            DEFAULT_UPSTREAM_PROFILE,
            "chrome",
            "chrome-143-macos-x86_64",
            "chrome-143-macos-arm64",
            "firefox",
            "firefox-145-macos-arm64",
            "safari",
            "safari-26.2-macos-arm64",
        ] {
            assert!(
                profiles.contains_key(name),
                "missing profile alias {name:?}"
            );
        }

        let default_profile = profiles
            .get(DEFAULT_UPSTREAM_PROFILE)
            .expect("default profile");
        let firefox_profile = profiles.get("firefox").expect("firefox profile");
        assert_eq!(
            default_profile.cert_compression, firefox_profile.cert_compression,
            "default alias should match the Firefox profile"
        );

        assert!(
            firefox_profile
                .cert_compression
                .contains(&CertCompression::Zstd),
            "firefox profile should advertise zstd cert compression"
        );

        let safari_profile = profiles.get("safari").expect("safari profile");
        assert_eq!(
            safari_profile.cert_compression,
            vec![CertCompression::Zlib],
            "safari profile should advertise only zlib cert compression"
        );
    }

    #[tokio::test]
    async fn read_config_parses_toml() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[proxy]
mode = "explicit"

[proxy.listen]
address = "127.0.0.1:8080"
"#,
        )
        .expect("write config");

        let args = Args {
            listen: None,
            config: Some(path),
            mode: None,
            proxy_protocol: None,
            ca_key_path: PathBuf::from("ca.key"),
            ca_cert_path: PathBuf::from("ca.crt"),
            leaf_ttl_secs: 3600,
            upstream_ca_file: None,
            upstream_insecure_skip_verify: false,
            upstream_no_verify_hostname: false,
        };

        let cfg = read_config(&args)
            .await
            .expect("config should parse")
            .expect("config should be loaded");

        assert_eq!(cfg.proxy.listen.address, "127.0.0.1:8080");
        assert_eq!(cfg.proxy.mode.as_deref(), Some("explicit"));
    }

    #[tokio::test]
    async fn read_config_rejects_non_toml_extension() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "proxy: {}").expect("write config");

        let args = Args {
            listen: None,
            config: Some(path),
            mode: None,
            proxy_protocol: None,
            ca_key_path: PathBuf::from("ca.key"),
            ca_cert_path: PathBuf::from("ca.crt"),
            leaf_ttl_secs: 3600,
            upstream_ca_file: None,
            upstream_insecure_skip_verify: false,
            upstream_no_verify_hostname: false,
        };

        let err = read_config(&args)
            .await
            .expect_err("non-toml config should fail");
        match err.kind() {
            error::ErrorKind::Config(msg) => assert!(msg.contains("unsupported config format")),
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_config_returns_none_without_file_or_env() {
        let cfg = read_config_with_env_source(None, Some(HashMap::new()))
            .await
            .expect("empty config sources should not fail");

        assert!(cfg.is_none());
    }

    #[tokio::test]
    async fn read_config_applies_polytls_env_overrides() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[proxy]
mode = "explicit"

[proxy.listen]
address = "127.0.0.1:8080"

[proxy.upstream]
default_profile = "chrome-143-macos-arm64"
insecure_skip_verify = false
"#,
        )
        .expect("write config");

        let env = HashMap::from([
            ("POLYTLS__PROXY__MODE".to_string(), "socks5".to_string()),
            (
                "POLYTLS__PROXY__LISTEN__ADDRESS".to_string(),
                "127.0.0.1:1080".to_string(),
            ),
            (
                "POLYTLS__PROXY__UPSTREAM__DEFAULT_PROFILE".to_string(),
                "firefox-145-macos-arm64".to_string(),
            ),
            (
                "POLYTLS__PROXY__UPSTREAM__INSECURE_SKIP_VERIFY".to_string(),
                "true".to_string(),
            ),
            (
                "POLYTLS__PROXY__UPSTREAM__PROXY__PROTOCOL".to_string(),
                "socks5".to_string(),
            ),
            (
                "POLYTLS__PROXY__UPSTREAM__PROXY__ADDRESS".to_string(),
                "127.0.0.1:9050".to_string(),
            ),
            (
                "POLYTLS__PROXY__UPSTREAM__PROXY__USERNAME".to_string(),
                "chain-user".to_string(),
            ),
            (
                "POLYTLS__PROXY__UPSTREAM__PROXY__PASSWORD".to_string(),
                "chain-pass".to_string(),
            ),
        ]);

        let cfg = read_config_with_env_source(Some(&path), Some(env))
            .await
            .expect("config should parse")
            .expect("config should be loaded");

        assert_eq!(cfg.proxy.mode.as_deref(), Some("socks5"));
        assert_eq!(cfg.proxy.listen.address, "127.0.0.1:1080");
        let upstream = cfg.proxy.upstream.expect("upstream config");
        assert_eq!(
            upstream.default_profile.as_deref(),
            Some("firefox-145-macos-arm64")
        );
        assert_eq!(upstream.insecure_skip_verify, Some(true));
        let proxy = upstream.proxy.expect("upstream proxy config");
        assert_eq!(proxy.protocol, "socks5");
        assert_eq!(proxy.address, "127.0.0.1:9050");
        assert_eq!(proxy.username.as_deref(), Some("chain-user"));
        assert_eq!(proxy.password.as_deref(), Some("chain-pass"));
    }

    #[tokio::test]
    async fn shutdown_hook_exits_when_cancelled() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let task = set_shutdown_hook(shutdown);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("shutdown hook should complete")
            .expect("shutdown hook task should not panic");
    }
}
