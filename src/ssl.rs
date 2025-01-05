use std::future::Future;

use tokio_native_tls::{
    native_tls::{self},
    TlsConnector,
};

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
