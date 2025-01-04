use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, UnixStream},
};
use tokio_native_tls::{
    native_tls::{self},
    TlsConnector, TlsStream,
};
use tokio_util::either::Either;

use crate::ssl::{TlsError, TlsMode, TlsOptions};

#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            Stream::Unix(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            Stream::Unix(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(ref mut stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Stream::Unix(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Stream::Unix(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl From<TcpStream> for Stream {
    fn from(stream: TcpStream) -> Self {
        Stream::Tcp(stream)
    }
}

#[cfg(unix)]
impl From<UnixStream> for Stream {
    fn from(stream: UnixStream) -> Self {
        Stream::Unix(stream)
    }
}

impl Stream {
    pub async fn maybe_upgrade_tls<'a>(
        self,
        ssl_opts: &TlsOptions<'a>,
    ) -> Result<Either<Self, TlsStream<Self>>, TlsError> {
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
