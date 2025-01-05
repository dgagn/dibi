use std::future::Future;

use tokio_native_tls::{
    native_tls::{self},
    TlsConnector, TlsStream,
};
use tokio_util::{codec::Framed, either::Either};

use crate::{connection::FramedStream, stream::Stream};

pub type StreamTransporter = Either<Stream, TlsStream<Stream>>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Do not use SSL/TLS.
    #[default]
    Disable,
    /// Use SSL/TLS if the server supports it, but allow a connection without
    Prefer,
    /// Use SSL/TLS, fail if the server does not support it.
    Require,
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
    pub domain: &'a str,
}

impl<'a> Default for TlsOptions<'a> {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            domain: "localhost",
            pem: None,
            key: None,
            root: None,
        }
    }
}

pub trait UpgradeStream: Sized {
    fn maybe_upgrade_tls(
        self,
        parts: Option<(&str, TlsConnector)>,
    ) -> impl Future<Output = Result<Self, UpgradeError>>;
}

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tls(#[from] native_tls::Error),
}

impl UpgradeStream for FramedStream {
    async fn maybe_upgrade_tls(
        self,
        parts: Option<(&str, TlsConnector)>,
    ) -> Result<Self, UpgradeError> {
        if let Some((domain, connector)) = parts {
            let parts = self.into_parts();
            let (stream, codec) = (parts.io, parts.codec);
            let stream = match stream {
                Either::Left(stream) => stream,
                Either::Right(stream) => {
                    return Ok(Framed::new(Either::Right(stream), codec));
                }
            };

            let tls_stream = connector.connect(domain, stream).await?;

            let transporter = StreamTransporter::Right(tls_stream);
            Ok(Framed::new(transporter, codec))
        } else {
            Ok(self)
        }
    }
}

pub trait EitherExt {
    fn is_right(&self) -> bool;
    fn is_left(&self) -> bool;
}

impl EitherExt for StreamTransporter {
    fn is_right(&self) -> bool {
        matches!(self, Either::Right(_))
    }

    fn is_left(&self) -> bool {
        matches!(self, Either::Left(_))
    }
}

pub async fn into_tls_parts<'a>(
    ssl_opts: &TlsOptions<'a>,
) -> Result<Option<(&'a str, TlsConnector)>, native_tls::Error> {
    if ssl_opts.mode == TlsMode::Disable {
        return Ok(None);
    }

    let mut connector = native_tls::TlsConnector::builder();

    connector
        .danger_accept_invalid_certs(matches!(ssl_opts.mode, TlsMode::Require | TlsMode::Prefer));

    connector.danger_accept_invalid_hostnames(matches!(
        ssl_opts.mode,
        TlsMode::Require | TlsMode::Prefer | TlsMode::VerifyCa,
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

    Ok(Some((ssl_opts.domain, connector)))
}

impl Stream {
    pub async fn maybe_upgrade_tls<'a>(
        self,
        ssl_opts: &TlsOptions<'a>,
    ) -> Result<StreamTransporter, native_tls::Error> {
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
    ) -> Result<StreamTransporter, native_tls::Error> {
        let stream = connector.connect(domain, self).await?;
        Ok(Either::Right(stream))
    }

    pub fn into_tls_parts<'a>(
        ssl_opts: &TlsOptions<'a>,
    ) -> Result<Option<(&'a str, TlsConnector)>, native_tls::Error> {
        if ssl_opts.mode == TlsMode::Disable {
            return Ok(None);
        }

        let mut connector = native_tls::TlsConnector::builder();

        connector.danger_accept_invalid_certs(matches!(
            ssl_opts.mode,
            TlsMode::Require | TlsMode::Prefer
        ));

        connector.danger_accept_invalid_hostnames(matches!(
            ssl_opts.mode,
            TlsMode::Require | TlsMode::Prefer | TlsMode::VerifyCa,
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

        Ok(Some((ssl_opts.domain, connector)))
    }
}
