use crate::compress::{CertCompression, register_certificate_compression};
use crate::error::{ErrorKind, Result};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

const CHROME_CURVES_LIST: &str = "X25519MLKEM768:X25519:P-256:P-384";
const CHROME_SIGALGS_LIST: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
     ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
     rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const CHROME_TLS12_CIPHER_LIST: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
     ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
     ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
     ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
     AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
const FIREFOX_CURVES_LIST: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";
const FIREFOX_SIGALGS_LIST: &str = "rsa_pkcs1_sha256:ecdsa_secp256r1_sha256:rsa_pkcs1_sha384:ecdsa_secp384r1_sha384:\
     rsa_pkcs1_sha512:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:\
     rsa_pss_rsae_sha512:rsa_pkcs1_sha1:ecdsa_sha1";
const FIREFOX_TLS12_CIPHER_LIST: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
     ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
     ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
     ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:\
     ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
     AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
const SAFARI_CURVES_LIST: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";
const SAFARI_SIGALGS_LIST: &str = "rsa_pkcs1_sha256:ecdsa_secp256r1_sha256:rsa_pkcs1_sha384:ecdsa_secp384r1_sha384:\
     rsa_pkcs1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha1";
const SAFARI_TLS12_CIPHER_LIST: &str = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
     ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:\
     ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:\
     ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:\
     ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:\
     AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:\
     ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA";

#[derive(Clone, Debug)]
pub struct UpstreamProfile {
    pub alpn_protos: Vec<String>,
    pub grease: bool,
    pub enable_ech_grease: bool,
    pub permute_extensions: bool,
    pub curves_list: Option<String>,
    pub cipher_list: Option<String>,
    pub sigalgs_list: Option<String>,
    pub enable_ocsp_stapling: bool,
    pub enable_signed_cert_timestamps: bool,
    pub cert_compression: Vec<CertCompression>,
    pub min_tls: Option<SslVersion>,
    pub max_tls: Option<SslVersion>,
}

impl Default for UpstreamProfile {
    fn default() -> Self {
        Self::chrome_143_macos_arm64()
    }
}

impl UpstreamProfile {
    pub fn chrome_143_macos_arm64() -> Self {
        // https://github.com/chromium/chromium/blob/5b92a5a0fc3489f88b8d512004010475d4ae484a/net/socket/ssl_client_socket_impl.cc#L658
        Self {
            alpn_protos: vec!["h2".to_string(), "http/1.1".to_string()],
            grease: true,
            enable_ech_grease: true,
            permute_extensions: true,
            curves_list: Some(CHROME_CURVES_LIST.to_string()),
            cipher_list: Some(CHROME_TLS12_CIPHER_LIST.to_string()),
            sigalgs_list: Some(CHROME_SIGALGS_LIST.to_string()),
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            cert_compression: vec![CertCompression::Brotli],
            min_tls: Some(SslVersion::TLS1_2),
            max_tls: None,
        }
    }

    pub fn firefox_145_macos_arm64() -> Self {
        // https://github.com/mozilla-firefox/firefox/blob/b82cded8c5b732c2ea15b7871d14e13b5fadeffd/security/nss/lib/ssl/sslsock.c#L4255
        Self {
            alpn_protos: vec!["h2".to_string(), "http/1.1".to_string()],
            grease: false,
            enable_ech_grease: true,
            permute_extensions: false,
            curves_list: Some(FIREFOX_CURVES_LIST.to_string()),
            cipher_list: Some(FIREFOX_TLS12_CIPHER_LIST.to_string()),
            sigalgs_list: Some(FIREFOX_SIGALGS_LIST.to_string()),
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            cert_compression: vec![
                CertCompression::Zlib,
                CertCompression::Brotli,
                CertCompression::Zstd,
            ],
            min_tls: Some(SslVersion::TLS1_2),
            max_tls: None,
        }
    }

    pub fn safari_26_2_macos_arm64() -> Self {
        Self {
            alpn_protos: vec!["h2".to_string(), "http/1.1".to_string()],
            grease: true,
            enable_ech_grease: false,
            permute_extensions: false,
            curves_list: Some(SAFARI_CURVES_LIST.to_string()),
            cipher_list: Some(SAFARI_TLS12_CIPHER_LIST.to_string()),
            sigalgs_list: Some(SAFARI_SIGALGS_LIST.to_string()),
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            cert_compression: vec![CertCompression::Zlib],
            min_tls: Some(SslVersion::TLS1_2),
            max_tls: None,
        }
    }
}

pub const DEFAULT_UPSTREAM_PROFILE: &str = "default";

#[derive(Clone)]
pub struct UpstreamProfiles {
    default_profile: String,
    profiles: Arc<HashMap<String, UpstreamProfile>>,
    connectors: Arc<RwLock<HashMap<String, Arc<SslConnector>>>>,
}

impl UpstreamProfiles {
    pub fn new(
        default_profile: String,
        profiles: HashMap<String, UpstreamProfile>,
    ) -> Result<Self> {
        if !profiles.contains_key(default_profile.as_str()) {
            return Err(ErrorKind::Config(format!(
                "default upstream profile {default_profile:?} is not defined"
            ))
            .into());
        }
        Ok(Self {
            default_profile,
            profiles: Arc::new(profiles),
            connectors: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn default_profile_name(&self) -> &str {
        &self.default_profile
    }

    pub fn profile_exists(&self, name: &str) -> bool {
        self.profiles.contains_key(name)
    }

    pub fn profile(&self, name: &str) -> Option<UpstreamProfile> {
        self.profiles.get(name).cloned()
    }

    pub async fn connector_for(
        &self,
        requested_profile: Option<&str>,
        verification: &UpstreamVerification,
    ) -> Result<(String, Arc<SslConnector>)> {
        let requested_profile = requested_profile.map(str::trim).filter(|v| !v.is_empty());
        let profile_name = requested_profile.unwrap_or(self.default_profile_name());

        if !self.profile_exists(profile_name) {
            return Err(ErrorKind::UnknownUpstreamProfile(profile_name.to_string()).into());
        }

        if let Some(connector) = self.connectors.read().await.get(profile_name).cloned() {
            return Ok((profile_name.to_string(), connector));
        }

        let profile = self
            .profiles
            .get(profile_name)
            .expect("profile existence checked")
            .clone();
        let connector = Arc::new(build_upstream_connector(&profile, verification)?);

        let mut cache = self.connectors.write().await;
        let cached = cache
            .entry(profile_name.to_string())
            .or_insert_with(|| connector.clone());

        Ok((profile_name.to_string(), cached.clone()))
    }
}

#[derive(Clone, Debug)]
pub struct UpstreamVerification {
    pub insecure_skip_verify: bool,
    pub verify_hostname: bool,
    pub ca_file: Option<String>,
}

impl UpstreamVerification {
    pub fn effective_verify_hostname(&self) -> bool {
        if self.insecure_skip_verify {
            false
        } else {
            self.verify_hostname
        }
    }
}

impl Default for UpstreamVerification {
    fn default() -> Self {
        Self {
            insecure_skip_verify: false,
            verify_hostname: true,
            ca_file: None,
        }
    }
}

pub fn build_upstream_connector(
    profile: &UpstreamProfile,
    verification: &UpstreamVerification,
) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_grease_enabled(profile.grease);
    builder.set_permute_extensions(profile.permute_extensions);
    builder
        .set_alpn_protos(&encode_alpn_protos(&profile.alpn_protos)?)
        .map_err(|e| ErrorKind::Config(format!("failed to set ALPN protos: {e}")))?;

    if let Some(ca_file) = &verification.ca_file {
        builder
            .set_ca_file(ca_file)
            .map_err(|e| ErrorKind::Config(format!("failed to set CA file {ca_file:?}: {e}")))?;
    }

    builder.set_verify(if verification.insecure_skip_verify {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });

    if let Some(cipher_list) = &profile.cipher_list {
        builder
            .set_cipher_list(cipher_list)
            .map_err(|e| ErrorKind::Config(format!("failed to set cipher_list: {e}")))?;
    }

    if let Some(sigalgs_list) = &profile.sigalgs_list {
        builder
            .set_sigalgs_list(sigalgs_list)
            .map_err(|e| ErrorKind::Config(format!("failed to set sigalgs_list: {e}")))?;
    }

    if profile.enable_ocsp_stapling {
        builder.enable_ocsp_stapling();
    }

    if profile.enable_signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }

    register_certificate_compression(&mut builder, &profile.cert_compression)?;

    if let Some(curves) = &profile.curves_list {
        builder
            .set_curves_list(curves)
            .map_err(|e| ErrorKind::Config(format!("failed to set curves_list: {e}")))?;
    }

    builder
        .set_min_proto_version(profile.min_tls)
        .map_err(|e| ErrorKind::Config(format!("failed to set min TLS version: {e}")))?;
    builder
        .set_max_proto_version(profile.max_tls)
        .map_err(|e| ErrorKind::Config(format!("failed to set max TLS version: {e}")))?;

    Ok(builder.build())
}

pub(crate) fn validate_alpn_protos(protos: &[String]) -> Result<()> {
    if protos.is_empty() {
        return Err(ErrorKind::Config("alpn_protos must not be empty".to_string()).into());
    }
    for proto in protos {
        let bytes = proto.as_bytes();
        if bytes.is_empty() {
            return Err(ErrorKind::Config(
                "alpn_protos must not contain empty entries".to_string(),
            )
            .into());
        }
        if bytes.len() > u8::MAX as usize {
            return Err(ErrorKind::Config(format!(
                "alpn protocol {proto:?} is too long (max 255 bytes)"
            ))
            .into());
        }
    }
    Ok(())
}

pub fn encode_alpn_protos(protos: &[String]) -> Result<Vec<u8>> {
    validate_alpn_protos(protos)?;

    let mut out = Vec::new();
    for proto in protos {
        let bytes = proto.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_upstream_connector_default_profile_does_not_error() {
        let _ = build_upstream_connector(
            &UpstreamProfile::default(),
            &UpstreamVerification::default(),
        )
        .expect("upstream connector should build");
    }

    #[test]
    fn build_upstream_connector_chrome_profile_does_not_error() {
        let _ = build_upstream_connector(
            &UpstreamProfile::chrome_143_macos_arm64(),
            &UpstreamVerification::default(),
        )
        .expect("upstream connector should build");
    }

    #[test]
    fn build_upstream_connector_firefox_profile_does_not_error() {
        let _ = build_upstream_connector(
            &UpstreamProfile::firefox_145_macos_arm64(),
            &UpstreamVerification::default(),
        )
        .expect("upstream connector should build");
    }

    #[test]
    fn build_upstream_connector_safari_profile_does_not_error() {
        let _ = build_upstream_connector(
            &UpstreamProfile::safari_26_2_macos_arm64(),
            &UpstreamVerification::default(),
        )
        .expect("upstream connector should build");
    }

    #[test]
    fn build_upstream_connector_can_disable_certificate_verification() {
        let verification = UpstreamVerification {
            insecure_skip_verify: true,
            verify_hostname: true,
            ca_file: None,
        };

        let connector = build_upstream_connector(&UpstreamProfile::default(), &verification)
            .expect("upstream connector should build");

        assert_eq!(connector.context().verify_mode(), SslVerifyMode::NONE);
        assert_eq!(verification.effective_verify_hostname(), false);
    }

    #[tokio::test]
    async fn upstream_profiles_rejects_unknown_profile() {
        let mut profiles = HashMap::new();
        profiles.insert(
            DEFAULT_UPSTREAM_PROFILE.to_string(),
            UpstreamProfile::default(),
        );

        let upstream_profiles =
            UpstreamProfiles::new(DEFAULT_UPSTREAM_PROFILE.to_string(), profiles).unwrap();

        let err = upstream_profiles
            .connector_for(Some("does-not-exist"), &UpstreamVerification::default())
            .await
            .expect_err("unknown profile should error");

        assert!(matches!(err.kind(), ErrorKind::UnknownUpstreamProfile(_)));
    }
}
