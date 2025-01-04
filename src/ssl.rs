use tokio_native_tls::{
    native_tls::{self},
    TlsConnector, TlsStream,
};
use tokio_util::either::Either;

use crate::stream::Stream;

pub type StreamTransporter = Either<Stream, TlsStream<Stream>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Do not use SSL/TLS.
    Disabled,
    /// Use SSL/TLS if the server supports it, but allow a connection without
    Preferred,
    /// Use SSL/TLS, fail if the server does not support it.
    Required,
    /// Use SSL/TLS, verify that the server certificate is issued by a trusted CA
    VerifyCa,
    /// Use SSL/TLS, verify the server certificate CA and matches the server's hostname
    VerifyFull,
}

#[derive(Debug)]
pub struct TlsOptions<'a> {
    pub mode: TlsMode,
    pub pem: Option<&'a [u8]>,
    pub key: Option<&'a [u8]>,
    pub root: Option<&'a [u8]>,
    pub domain: Option<&'a str>,
}

#[derive(Debug)]
pub enum TlsError {
    NativeTls(native_tls::Error),
    DomainRequired,
}

impl From<native_tls::Error> for TlsError {
    fn from(e: native_tls::Error) -> Self {
        TlsError::NativeTls(e)
    }
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::NativeTls(e) => write!(f, "{}", e),
            TlsError::DomainRequired => write!(f, "domain is required for tls full verification"),
        }
    }
}

impl std::error::Error for TlsError {}

impl Stream {
    pub async fn maybe_upgrade_tls<'a>(
        self,
        ssl_opts: &TlsOptions<'a>,
    ) -> Result<StreamTransporter, TlsError> {
        if ssl_opts.mode == TlsMode::Disabled {
            return Ok(Either::Left(self));
        }

        let mut connector = native_tls::TlsConnector::builder();

        connector.danger_accept_invalid_certs(matches!(
            ssl_opts.mode,
            TlsMode::Required | TlsMode::Preferred
        ));

        connector.danger_accept_invalid_hostnames(matches!(
            ssl_opts.mode,
            TlsMode::Required | TlsMode::Preferred | TlsMode::VerifyCa,
        ));

        if let (Some(pem), Some(key)) = (ssl_opts.pem, ssl_opts.key) {
            let cert = native_tls::Identity::from_pkcs8(pem, key)?;
            connector.identity(cert);
        }
        if let Some(ca) = ssl_opts.root {
            let ca = native_tls::Certificate::from_pem(ca)?;
            connector.add_root_certificate(ca);
        }

        let domain = if matches!(ssl_opts.mode, TlsMode::VerifyFull) {
            ssl_opts.domain.ok_or(TlsError::DomainRequired)?
        } else {
            ssl_opts.domain.unwrap_or("")
        };

        let connector = connector.build()?;
        let connector = TlsConnector::from(connector);

        match connector.connect(domain, self).await {
            Ok(stream) => Ok(Either::Right(stream)),
            Err(e) => Err(e.into()),
        }
    }
}
