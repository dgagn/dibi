use tokio_native_tls::native_tls;

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
