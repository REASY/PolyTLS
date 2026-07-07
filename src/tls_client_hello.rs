use crate::error::{ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

const TLS_HANDSHAKE_RECORD: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;

pub struct PeekedClientHello {
    pub prefix: Vec<u8>,
    pub sni: Option<String>,
}

pub async fn peek_client_hello<S>(stream: &mut S) -> Result<PeekedClientHello>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];

    loop {
        if prefix.len() > MAX_CLIENT_HELLO_BYTES {
            return Err(ErrorKind::TlsHandshake("ClientHello is too large".to_string()).into());
        }

        match parse_sni_from_tls_records(&prefix)? {
            ParseState::Complete(sni) => {
                return Ok(PeekedClientHello { prefix, sni });
            }
            ParseState::NeedMore => {
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(ErrorKind::TlsHandshake(
                        "connection closed before ClientHello".to_string(),
                    )
                    .into());
                }
                prefix.extend_from_slice(&tmp[..n]);
            }
        }
    }
}

enum ParseState {
    NeedMore,
    Complete(Option<String>),
}

fn parse_sni_from_tls_records(buf: &[u8]) -> Result<ParseState> {
    let mut offset = 0;
    let mut handshake = Vec::new();

    while offset + 5 <= buf.len() {
        let content_type = buf[offset];
        if content_type != TLS_HANDSHAKE_RECORD {
            return Err(ErrorKind::TlsHandshake(format!(
                "expected TLS handshake record, got content type {content_type}"
            ))
            .into());
        }

        let record_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        let record_start = offset + 5;
        let record_end = record_start + record_len;
        if record_end > buf.len() {
            return Ok(ParseState::NeedMore);
        }

        handshake.extend_from_slice(&buf[record_start..record_end]);

        if handshake.len() >= 4 {
            if handshake[0] != CLIENT_HELLO {
                return Err(ErrorKind::TlsHandshake(format!(
                    "expected ClientHello handshake, got type {}",
                    handshake[0]
                ))
                .into());
            }

            let hello_len = read_u24(&handshake[1..4]);
            if handshake.len() >= hello_len + 4 {
                let sni = parse_client_hello_sni(&handshake[4..hello_len + 4])?;
                return Ok(ParseState::Complete(sni));
            }
        }

        offset = record_end;
    }

    Ok(ParseState::NeedMore)
}

fn parse_client_hello_sni(mut body: &[u8]) -> Result<Option<String>> {
    take(&mut body, 2)?; // legacy_version
    take(&mut body, 32)?; // random

    let session_id_len = read_u8(take(&mut body, 1)?)? as usize;
    take(&mut body, session_id_len)?;

    let cipher_suites_len = read_u16(take(&mut body, 2)?)? as usize;
    take(&mut body, cipher_suites_len)?;

    let compression_methods_len = read_u8(take(&mut body, 1)?)? as usize;
    take(&mut body, compression_methods_len)?;

    if body.is_empty() {
        return Ok(None);
    }

    let extensions_len = read_u16(take(&mut body, 2)?)? as usize;
    let mut extensions = take(&mut body, extensions_len)?;

    while !extensions.is_empty() {
        let extension_type = read_u16(take(&mut extensions, 2)?)?;
        let extension_len = read_u16(take(&mut extensions, 2)?)? as usize;
        let extension = take(&mut extensions, extension_len)?;

        if extension_type == 0 {
            return parse_server_name_extension(extension);
        }
    }

    Ok(None)
}

fn parse_server_name_extension(mut extension: &[u8]) -> Result<Option<String>> {
    let list_len = read_u16(take(&mut extension, 2)?)? as usize;
    let mut names = take(&mut extension, list_len)?;

    while !names.is_empty() {
        let name_type = read_u8(take(&mut names, 1)?)?;
        let name_len = read_u16(take(&mut names, 2)?)? as usize;
        let name = take(&mut names, name_len)?;

        if name_type == 0 {
            let sni = std::str::from_utf8(name)
                .map_err(|_| ErrorKind::TlsHandshake("ClientHello SNI is not UTF-8".to_string()))?
                .trim_end_matches('.');
            if sni.is_empty() {
                return Ok(None);
            }
            return Ok(Some(sni.to_string()));
        }
    }

    Ok(None)
}

fn take<'a>(buf: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if buf.len() < len {
        return Err(ErrorKind::TlsHandshake("truncated ClientHello".to_string()).into());
    }
    let (head, tail) = buf.split_at(len);
    *buf = tail;
    Ok(head)
}

fn read_u8(buf: &[u8]) -> Result<u8> {
    buf.first()
        .copied()
        .ok_or_else(|| ErrorKind::TlsHandshake("truncated u8".to_string()).into())
}

fn read_u16(buf: &[u8]) -> Result<u16> {
    if buf.len() != 2 {
        return Err(ErrorKind::TlsHandshake("truncated u16".to_string()).into());
    }
    Ok(u16::from_be_bytes([buf[0], buf[1]]))
}

fn read_u24(buf: &[u8]) -> usize {
    ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize)
}
