use crate::ca::CaManager;
use crate::error::{ErrorKind, PolyTlsError, Result};
use crate::profile::{UpstreamProfiles, UpstreamVerification, validate_alpn_protos};
use boring::pkey::{PKey, Private};
use boring::ssl::{AlpnError, SslAcceptor, SslMethod};
use boring::x509::X509;
use std::sync::Arc;

#[derive(Clone)]
pub struct MitmState {
    pub ca: Arc<CaManager>,
    pub upstream_profiles: UpstreamProfiles,
    pub upstream_verification: UpstreamVerification,
}

pub fn build_client_acceptor(
    leaf_cert: &X509,
    leaf_key: &PKey<Private>,
    alpn_protos: &[String],
) -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_certificate(leaf_cert)?;
    builder.set_private_key(leaf_key)?;
    builder.check_private_key()?;

    validate_alpn_protos(alpn_protos)?;
    let server_protos = alpn_protos
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect::<Vec<_>>();

    builder.set_alpn_select_callback(move |_ssl, client_protos| {
        select_client_alpn(&server_protos, client_protos).ok_or(AlpnError::NOACK)
    });

    Ok(builder.build())
}

fn select_client_alpn<'a>(server_protos: &[Vec<u8>], client_protos: &'a [u8]) -> Option<&'a [u8]> {
    for server_proto in server_protos {
        if let Some(found) = find_alpn_proto(client_protos, server_proto) {
            return Some(found);
        }
    }
    None
}

fn find_alpn_proto<'a>(client_protos: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    let mut idx = 0;
    while idx < client_protos.len() {
        let len = *client_protos.get(idx)? as usize;
        idx += 1;
        let end = idx.checked_add(len)?;
        if end > client_protos.len() {
            return None;
        }
        let proto = &client_protos[idx..end];
        if proto == wanted {
            return Some(proto);
        }
        idx = end;
    }
    None
}

pub fn sni_mismatch(connect_host: &str, sni: Option<&str>) -> Option<PolyTlsError> {
    let sni = sni?;
    if sni.eq_ignore_ascii_case(connect_host) {
        return None;
    }
    Some(
        ErrorKind::TlsHandshake(format!(
            "SNI mismatch: CONNECT host={connect_host} ClientHello SNI={sni}"
        ))
        .into(),
    )
}
