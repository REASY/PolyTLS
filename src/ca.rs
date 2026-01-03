use crate::error::Result;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use boring::x509::{X509, X509NameBuilder};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct CaConfig {
    pub ca_key_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub leaf_ttl: Duration,
}

#[derive(Clone)]
pub struct CaManager {
    ca_key: PKey<Private>,
    ca_cert: X509,
    leaf_ttl: Duration,
    leaf_cache: Arc<Mutex<HashMap<String, CachedLeaf>>>,
}

#[derive(Clone)]
struct CachedLeaf {
    created_at: Instant,
    cert: X509,
    key: PKey<Private>,
}

impl CaManager {
    pub async fn load_or_create(config: CaConfig) -> Result<Self> {
        let ca_key_path = config.ca_key_path;
        let ca_cert_path = config.ca_cert_path;

        let (ca_key, ca_cert) = if ca_key_path.exists() && ca_cert_path.exists() {
            let key_pem = tokio::fs::read(&ca_key_path).await?;
            let cert_pem = tokio::fs::read(&ca_cert_path).await?;

            let key = PKey::private_key_from_pem(&key_pem)?;
            let cert = X509::from_pem(&cert_pem)?;
            (key, cert)
        } else {
            if let Some(parent) = ca_key_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            if let Some(parent) = ca_cert_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let (key, cert_pem, key_pem) = tokio::task::spawn_blocking(move || {
                let (key, cert) = generate_root_ca()?;
                let cert_pem = cert.to_pem()?;
                let key_pem = key.private_key_to_pem_pkcs8()?;
                Ok::<_, boring::error::ErrorStack>((key, cert_pem, key_pem))
            })
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))??;

            tokio::fs::write(&ca_key_path, &key_pem).await?;
            tokio::fs::write(&ca_cert_path, &cert_pem).await?;

            #[cfg(unix)]
            {
                use std::fs::Permissions;
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&ca_key_path, Permissions::from_mode(0o600)).await?;
            }

            let cert = X509::from_pem(&cert_pem)?;
            (key, cert)
        };

        Ok(Self {
            ca_key,
            ca_cert,
            leaf_ttl: config.leaf_ttl,
            leaf_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn leaf_for_host(&self, host: &str) -> Result<(X509, PKey<Private>)> {
        {
            let mut cache = self.leaf_cache.lock().await;
            if let Some(entry) = cache.get(host) {
                if entry.created_at.elapsed() < self.leaf_ttl {
                    return Ok((entry.cert.clone(), entry.key.clone()));
                }
            }

            // Clear stale entry before generating a new one.
            cache.remove(host);
        }

        let host_key = host.to_string();
        let host_for_cert = host_key.clone();
        let ca_cert = self.ca_cert.clone();
        let ca_key = self.ca_key.clone();
        let leaf = tokio::task::spawn_blocking(move || {
            generate_leaf_cert(&host_for_cert, &ca_cert, &ca_key)
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))??;

        let mut cache = self.leaf_cache.lock().await;
        cache.insert(
            host_key,
            CachedLeaf {
                created_at: Instant::now(),
                cert: leaf.0.clone(),
                key: leaf.1.clone(),
            },
        );

        Ok(leaf)
    }
}

fn generate_root_ca() -> std::result::Result<(PKey<Private>, X509), boring::error::ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "PolyTLS Root CA")?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;

    let serial = random_serial()?;
    builder.set_serial_number(&serial)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    // For self-signed roots, BoringSSL's AKI builder expects the issuer to already have an SKI.
    // Build+append SKI first, then build AKI.
    let ski = {
        let ctx = builder.x509v3_context(None, None);
        SubjectKeyIdentifier::new().build(&ctx)?
    };
    builder.append_extension(ski)?;

    let aki = {
        let ctx = builder.x509v3_context(None, None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&ctx)
            .or_else(|_| AuthorityKeyIdentifier::new().issuer(true).build(&ctx))?
    };
    builder.append_extension(aki)?;

    builder.sign(&key, MessageDigest::sha256())?;
    Ok((key, builder.build()))
}

fn generate_leaf_cert(
    host: &str,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
) -> std::result::Result<(X509, PKey<Private>), boring::error::ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", host)?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&key)?;

    let serial = random_serial()?;
    builder.set_serial_number(&serial)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(30)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;

    let ski = {
        let ctx = builder.x509v3_context(Some(ca_cert), None);
        SubjectKeyIdentifier::new().build(&ctx)?
    };
    builder.append_extension(ski)?;

    let aki = {
        let ctx = builder.x509v3_context(Some(ca_cert), None);
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&ctx)
            .or_else(|_| AuthorityKeyIdentifier::new().issuer(true).build(&ctx))?
    };
    builder.append_extension(aki)?;

    let san = {
        let ctx = builder.x509v3_context(Some(ca_cert), None);
        let mut san = SubjectAlternativeName::new();
        san.dns(host);
        san.build(&ctx)?
    };
    builder.append_extension(san)?;

    builder.sign(ca_key, MessageDigest::sha256())?;
    Ok((builder.build(), key))
}

fn random_serial() -> std::result::Result<boring::asn1::Asn1Integer, boring::error::ErrorStack> {
    let mut serial_bytes = [0u8; 16];
    boring::rand::rand_bytes(&mut serial_bytes)?;
    serial_bytes[0] &= 0x7f; // ensure positive
    let bn = BigNum::from_slice(&serial_bytes)?;
    bn.to_asn1_integer()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_and_leaf_does_not_error() {
        let (ca_key, ca_cert) = generate_root_ca().expect("root CA generation should succeed");
        let (_leaf_cert, _leaf_key) = generate_leaf_cert("example.com", &ca_cert, &ca_key)
            .expect("leaf generation should succeed");
    }
}
