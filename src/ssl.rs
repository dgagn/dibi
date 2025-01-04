use tokio_native_tls::{
    native_tls::{self},
    TlsConnector, TlsStream,
};
use tokio_util::either::Either;

use crate::stream::Stream;

pub type StreamTransporter = Either<Stream, TlsStream<Stream>>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Do not use SSL/TLS.
    #[default]
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

#[derive(Debug, Default)]
pub struct TlsOptions<'a> {
    pub mode: TlsMode,
    pub pem: Option<&'a [u8]>,
    pub key: Option<&'a [u8]>,
    pub root: Option<&'a [u8]>,
    pub domain: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error(transparent)]
    NativeTls(#[from] native_tls::Error),
    #[error("domain is required for tls full verification")]
    DomainRequired,
}

impl Stream {
    pub async fn maybe_upgrade_tls<'a>(
        self,
        ssl_opts: &TlsOptions<'a>,
    ) -> Result<StreamTransporter, TlsError> {
        let parts = Self::into_tls_parts(ssl_opts)?;

        if let Some((domain, connector)) = parts {
            let stream = connector.connect(domain, self).await?;
            Ok(Either::Right(stream))
        } else {
            Ok(Either::Left(self))
        }
    }

    pub async fn maybe_upgrade_from_parts(
        self,
        (domain, connector): (&str, TlsConnector),
    ) -> Result<StreamTransporter, TlsError> {
        let stream = connector.connect(domain, self).await?;
        Ok(Either::Right(stream))
    }

    pub fn into_tls_parts<'a>(
        ssl_opts: &TlsOptions<'a>,
    ) -> Result<Option<(&'a str, TlsConnector)>, TlsError> {
        if ssl_opts.mode == TlsMode::Disabled {
            return Ok(None);
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

        let connector = connector.build()?;
        let connector = TlsConnector::from(connector);

        let domain = if matches!(ssl_opts.mode, TlsMode::VerifyFull) {
            ssl_opts.domain.ok_or(TlsError::DomainRequired)?
        } else {
            ssl_opts.domain.unwrap_or("")
        };

        Ok(Some((domain, connector)))
    }
}
