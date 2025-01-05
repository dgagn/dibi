use tokio::net::{TcpStream, UnixStream};
use tokio_native_tls::native_tls;
use tokio_util::codec::Framed;

use crate::{
    codec::PacketCodec,
    my::{stream::StreamTransporter, MyStream},
    protocol::{
        client::{self, HandshakeResponse, SslPacket},
        plugin::{AuthType, AuthTypeError},
        server::{InitialHandshakeError, InitialHanshakePacket},
        Capability,
    },
    ssl::{into_tls_parts, TlsMode, TlsOptions, UpgradeStream},
    stream::{Stream, StreamType},
};

#[derive(Debug)]
pub struct Connection {
    stream: MyStream,
}

#[derive(Debug)]
pub struct ConnectionOption<'a> {
    pub host: &'a str,
    pub username: &'a str,
    pub password: &'a [u8],
    pub database: Option<&'a str>,
    pub stream_type: StreamType,
    pub tls: TlsOptions<'a>,
}

impl<'a> Default for ConnectionOption<'a> {
    fn default() -> Self {
        Self {
            host: "127.0.0.1:3306",
            username: "",
            password: &[],
            stream_type: StreamType::default(),
            tls: TlsOptions::default(),
            database: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("failed to perform initial handshake")]
    InitialHandshake(#[from] InitialHandshakeError),

    #[error("the server does not support tls")]
    TlsCapability,

    #[error("unsupported auth plugin {0}")]
    UnsupportedAuthPlugin(AuthType),

    #[error(transparent)]
    AuthPluginError(#[from] AuthTypeError),

    #[error(transparent)]
    UpgradeError(#[from] crate::ssl::UpgradeError),

    #[error(transparent)]
    Tls(#[from] native_tls::Error),
}

impl Connection {
    pub async fn connect<'a>(options: &'a ConnectionOption<'a>) -> Result<Self, ConnectionError> {
        let stream = match options.stream_type {
            StreamType::Tcp => Stream::Tcp(TcpStream::connect(options.host).await?),
            StreamType::Unix => Stream::Unix(UnixStream::connect(options.host).await?),
        };
        let stream = StreamTransporter::Left(stream);
        let codec = PacketCodec::new();
        let mut mystream = MyStream::new(Framed::new(stream, codec));

        let packet = mystream.recv().await?;
        let handshake: InitialHanshakePacket = packet.try_into()?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Received handshake packet");

        mystream.handshake_packet(handshake);

        if matches!(
            options.tls.mode,
            TlsMode::Require | TlsMode::VerifyCa | TlsMode::VerifyFull
        ) && !mystream.context().has_server_capability(Capability::SSL)
        {
            return Err(ConnectionError::TlsCapability);
        }

        let parts = into_tls_parts(&options.tls).await?;

        let stream = if parts.is_some() {
            #[cfg(feature = "tracing")]
            tracing::debug!("Sending TLS packet to server for upgrade");
            let context = mystream.context_mut();
            context.set_client_capability(Capability::SSL);
            let ssl_packet = SslPacket::new();
            mystream.send_packet(ssl_packet).await?;
            mystream
        } else {
            mystream
        };

        let mut stream = stream.maybe_upgrade_tls(parts).await?;

        let context = stream.context();
        let auth_type = context.auth_type();

        if !auth_type.supported() {
            return Err(ConnectionError::UnsupportedAuthPlugin(auth_type));
        }

        if auth_type.needs_ssl() && !context.has_client_capability(Capability::SSL) {
            return Err(ConnectionError::TlsCapability);
        }

        let password = auth_type.encrypt(options.password, context)?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Sending handshake response packet");

        let handshake = HandshakeResponse {
            username: options.username,
            password: &password,
            database: options.database,
        };

        stream.send_packet(handshake).await?;

        let packet = stream.recv_packet().await?;

        println!("{:?}", packet);

        Ok(Self { stream })
    }

    pub async fn ping(&mut self) -> Result<(), std::io::Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("Sending ping packet");
        let ping = client::Ping::new();
        self.stream.send_packet(ping).await?;
        let packet = self.stream.recv_packet().await?;
        println!("{:?}", packet);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper trait to assert Send and Sync
    trait AssertSendSync: Send + Sync {}
    impl<T: Send + Sync> AssertSendSync for T {}

    // Function to enforce the assertion at compile time
    fn assert_send_sync<T: AssertSendSync>() {}

    #[tokio::test]
    async fn test_send_sync() {
        let options = ConnectionOption::default();
        let _connection = Connection::connect(&options).await.unwrap();
        assert_send_sync::<Connection>();
    }
}
