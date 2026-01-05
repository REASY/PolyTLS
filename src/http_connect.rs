use std::io;
use thiserror::Error;
use tokio::io::AsyncReadExt;

const MAX_HEADERS: usize = 64;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const UPSTREAM_PROFILE_HEADER: &str = "X-PolyTLS-Upstream-Profile";

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("HTTP parse error: {0}")]
    HttpParse(#[from] httparse::Error),

    #[error("unexpected EOF while reading CONNECT request (read {bytes_read} bytes)")]
    UnexpectedEof { bytes_read: usize },

    #[error("request too large")]
    RequestTooLarge,

    #[error("unsupported method: {0}")]
    UnsupportedMethod(String),

    #[error("invalid CONNECT authority: {0}")]
    InvalidAuthority(String),
}

#[derive(Debug)]
pub struct ConnectRequest {
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub profile: Option<String>,
    pub leftover: Vec<u8>,
}

pub async fn read_connect_request<S>(stream: &mut S) -> Result<ConnectRequest, ConnectError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    let header_end = loop {
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(ConnectError::RequestTooLarge);
        }

        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ConnectError::UnexpectedEof {
                bytes_read: buf.len(),
            });
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(end) = find_header_end(&buf) {
            break end;
        }
    };

    let leftover = buf[header_end..].to_vec();
    let header_bytes = &buf[..header_end];

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);

    let status = req.parse(header_bytes)?;
    if !status.is_complete() {
        return Err(ConnectError::InvalidAuthority("incomplete request".into()));
    }

    let method = req
        .method
        .ok_or_else(|| ConnectError::InvalidAuthority("missing method".into()))?;
    if method != "CONNECT" {
        return Err(ConnectError::UnsupportedMethod(method.to_string()));
    }

    let authority = req
        .path
        .ok_or_else(|| ConnectError::InvalidAuthority("missing request target".into()))?
        .to_string();

    let (host, port) = parse_connect_authority(&authority)?;

    let profile = match req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(UPSTREAM_PROFILE_HEADER))
    {
        None => None,
        Some(header) => {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| {
                    ConnectError::InvalidAuthority(format!(
                        "invalid {UPSTREAM_PROFILE_HEADER} header value"
                    ))
                })?
                .trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
    };

    Ok(ConnectRequest {
        authority,
        host,
        port,
        profile,
        leftover,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    memchr::memmem::find(buf, b"\r\n\r\n").map(|idx| idx + 4)
}

fn parse_connect_authority(authority: &str) -> Result<(String, u16), ConnectError> {
    if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| ConnectError::InvalidAuthority(authority.to_string()))?;
        let host = &authority[1..close];
        let rest = &authority[(close + 1)..];
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| ConnectError::InvalidAuthority(authority.to_string()))?;
        let port: u16 = port
            .parse()
            .map_err(|_| ConnectError::InvalidAuthority(authority.to_string()))?;
        return Ok((host.to_string(), port));
    }

    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| ConnectError::InvalidAuthority(authority.to_string()))?;

    if host.is_empty() || host.contains(':') {
        return Err(ConnectError::InvalidAuthority(authority.to_string()));
    }

    let port: u16 = port
        .parse()
        .map_err(|_| ConnectError::InvalidAuthority(authority.to_string()))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncRead;

    struct OneShotReader {
        bytes: Vec<u8>,
        pos: usize,
    }

    impl OneShotReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, pos: 0 }
        }
    }

    impl AsyncRead for OneShotReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.pos >= self.bytes.len() {
                return Poll::Ready(Ok(()));
            }

            let remaining = &self.bytes[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn read_connect_request_parses_upstream_profile_header() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"CONNECT example.com:443 HTTP/1.1\r\n\
Host: example.com:443\r\n\
X-PolyTLS-Upstream-Profile: chrome-143-macos-x86_64\r\n\
\r\n",
        );
        bytes.extend_from_slice(b"\x16\x03\x01\x00\x01");

        let mut reader = OneShotReader::new(bytes);
        let req = read_connect_request(&mut reader)
            .await
            .expect("request should parse");

        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert_eq!(req.profile.as_deref(), Some("chrome-143-macos-x86_64"));
        assert_eq!(req.leftover, b"\x16\x03\x01\x00\x01");
    }

    #[tokio::test]
    async fn read_connect_request_rejects_non_utf8_profile_header_value() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"CONNECT example.com:443 HTTP/1.1\r\n\
Host: example.com:443\r\n\
X-PolyTLS-Upstream-Profile: ",
        );
        bytes.extend_from_slice(&[0xff, 0xff, 0xff]);
        bytes.extend_from_slice(b"\r\n\r\n");

        let mut reader = OneShotReader::new(bytes);
        let err = read_connect_request(&mut reader)
            .await
            .expect_err("request should fail");

        match err {
            ConnectError::InvalidAuthority(msg) => {
                assert!(msg.contains(UPSTREAM_PROFILE_HEADER));
            }
            other => panic!("expected InvalidAuthority, got {other:?}"),
        }
    }
}
