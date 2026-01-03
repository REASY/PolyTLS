use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub profiles: Option<HashMap<String, UpstreamProfileConfig>>,
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub mode: Option<String>,
    pub listen: ListenConfig,
    pub mitm: Option<MitmConfig>,
    pub upstream: Option<UpstreamConfig>,
    pub certificate: Option<CertificateConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub address: String,
    #[allow(dead_code)]
    pub backlog: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CertificateConfig {
    pub ca_key_path: String,
    pub ca_cert_path: String,
    pub cache_ttl: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct MitmConfig {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    /// Optional override for lab use-cases.
    #[allow(dead_code)]
    pub default_upstream: Option<String>,
    /// Default upstream TLS profile name (when the client does not provide a per-request override).
    pub default_profile: Option<String>,
    /// Additional PEM trust bundle for proxy→upstream TLS verification.
    pub ca_file: Option<String>,
    /// Disables proxy→upstream certificate verification (lab use only).
    pub insecure_skip_verify: Option<bool>,
    /// Disables proxy→upstream hostname verification (lab use only).
    pub verify_hostname: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamProfileConfig {
    pub alpn_protos: Option<Vec<String>>,
    pub grease: Option<bool>,
    pub enable_ech_grease: Option<bool>,
    pub permute_extensions: Option<bool>,
    pub curves_list: Option<String>,
    pub cipher_list: Option<String>,
    pub sigalgs_list: Option<String>,
    pub enable_ocsp_stapling: Option<bool>,
    pub enable_signed_cert_timestamps: Option<bool>,
    /// Ordered list of certificate compression algorithms to advertise in TLS 1.3
    /// (`compress_certificate` extension).
    ///
    /// Supported values: `zlib`, `brotli`, `zstd`.
    pub cert_compression: Option<Vec<String>>,
    pub min_tls: Option<String>,
    pub max_tls: Option<String>,
}
