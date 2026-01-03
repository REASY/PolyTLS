use opentelemetry_otlp::ExporterBuildError;
use std::io;
use thiserror::Error;

use crate::http_connect::ConnectError;

pub type Result<T> = std::result::Result<T, PolyTlsError>;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct PolyTlsError(pub Box<ErrorKind>);

impl PolyTlsError {
    #[allow(dead_code)]
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    pub fn new(kind: ErrorKind) -> Self {
        PolyTlsError(Box::new(kind))
    }
}

#[derive(Error, Debug)]
pub enum ErrorKind {
    #[error("config error: {0}")]
    Config(String),

    #[error("unknown upstream profile: {0}")]
    UnknownUpstreamProfile(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("CONNECT error: {0}")]
    Connect(#[from] ConnectError),

    #[error("BoringSSL error: {0}")]
    Boring(#[from] boring::error::ErrorStack),

    #[error("TLS handshake error: {0}")]
    TlsHandshake(String),

    #[error("timeout")]
    Timeout,

    #[error("OtlpError: {0}")]
    OtlpError(#[from] ExporterBuildError),

    #[error("TracingSubscriberError: {0}")]
    TracingSubscriberError(String),
}

impl<E> From<E> for PolyTlsError
where
    ErrorKind: From<E>,
{
    fn from(err: E) -> Self {
        PolyTlsError(Box::new(ErrorKind::from(err)))
    }
}
