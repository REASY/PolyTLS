use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    #[allow(dead_code)]
    pub fn inner(&self) -> &S {
        &self.inner
    }

    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn reads_prefix_then_inner() {
        let (inner, mut other) = duplex(64);
        other.write_all(b"world").await.expect("write");
        drop(other);

        let mut stream = PrefixedStream::new(b"hello".to_vec(), inner);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"helloworld");
    }

    #[tokio::test]
    async fn reads_prefix_in_chunks() {
        let (inner, mut other) = duplex(64);
        other.write_all(b"world").await.expect("write");
        drop(other);

        let mut stream = PrefixedStream::new(b"hello".to_vec(), inner);

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"he");

        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ll");

        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ow");

        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.expect("read rest");
        assert_eq!(rest, b"orld");
    }

    #[tokio::test]
    async fn writes_are_forwarded_to_inner() {
        let (inner, mut other) = duplex(64);
        let mut stream = PrefixedStream::new(Vec::new(), inner);

        stream.write_all(b"ping").await.expect("write");
        stream.shutdown().await.expect("shutdown");

        let mut buf = Vec::new();
        other.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, b"ping");
    }
}
