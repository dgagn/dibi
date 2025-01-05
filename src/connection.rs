use futures::SinkExt;
use tokio::net::{TcpStream, UnixStream};
use tokio_native_tls::native_tls;
use tokio_stream::StreamExt;
use tokio_util::{codec::Framed, either::Either};

use crate::{
    codec::{PacketCodec, PacketFrame},
    context::Context,
    protocol::{
        client::{HandshakeResponse, SslPacket},
        plugin::{AuthType, AuthTypeError},
        server::{InitialHandshakeError, InitialHanshakePacket},
        Capability,
    },
    ssl::{StreamTransporter, TlsMode, TlsOptions},
    stream::{Stream, StreamType},
    EncodePacket,
};

#[derive(Debug)]
pub struct Connection {
    stream: Framed<StreamTransporter, PacketCodec>,
    context: Context,
    next_seq: u8,
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

    #[error("Failed to perform initial handshake")]
    InitialHandshake(#[from] InitialHandshakeError),

    #[error("The server does not support tls")]
    TlsCapability,

    #[error("The server requires tls for authentication")]
    PluginNeedsTls,

    #[error("Unsupported auth plugin {0}")]
    UnsupportedAuthPlugin(AuthType),

    #[error(transparent)]
    AuthPluginError(#[from] AuthTypeError),

    #[error(transparent)]
    Tls(#[from] native_tls::Error),
}

impl Connection {
    pub async fn connect<'a>(options: &'a ConnectionOption<'a>) -> Result<Self, ConnectionError> {
        let stream = match options.stream_type {
            StreamType::Tcp => Stream::Tcp(TcpStream::connect(options.host).await?),
            StreamType::Unix => Stream::Unix(UnixStream::connect(options.host).await?),
        };
        let codec = PacketCodec::new();
        let mut framed = Framed::new(stream, codec);

        let packet = framed
            .next()
            .await
            .ok_or(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))??;

        let mut next_seq = packet.seq().wrapping_add(1);
        let handshake: InitialHanshakePacket = packet.try_into()?;
        let mut context = Context::new(handshake);

        if matches!(
            options.tls.mode,
            TlsMode::Required | TlsMode::VerifyCa | TlsMode::VerifyFull
        ) && !context.has_server_capability(Capability::SSL)
        {
            return Err(ConnectionError::TlsCapability);
        }

        let parts = Stream::into_tls_parts(&options.tls)?;

        let mut stream = if let Some(parts) = parts {
            context.set_client_capability(Capability::SSL);
            let mut packet_frame = SslPacket::new().encode_packet(&context)?;
            packet_frame.set_seq(next_seq);
            framed.send(packet_frame).await?;
            next_seq = next_seq.wrapping_add(1);

            let framed_parts = framed.into_parts();
            let (stream, codec) = (framed_parts.io, framed_parts.codec);

            let stream = stream.maybe_upgrade_from_parts(parts).await?;

            Framed::new(stream, codec)
        } else {
            let framed_parts = framed.into_parts();
            let (stream, codec) = (framed_parts.io, framed_parts.codec);

            Framed::new(Either::Left(stream), codec)
        };

        let auth_type = context.auth_type();

        if !auth_type.supported() {
            return Err(ConnectionError::UnsupportedAuthPlugin(auth_type));
        }

        if auth_type.needs_ssl() && !context.has_client_capability(Capability::SSL) {
            return Err(ConnectionError::TlsCapability);
        }

        let password = auth_type.encrypt(options.password, &context)?;

        let handshake = HandshakeResponse {
            username: options.username,
            password: &password,
            database: options.database,
        };

        let mut response = handshake.encode_packet(&context)?;
        response.set_seq(next_seq);
        next_seq = next_seq.wrapping_add(1);
        stream.send(response).await?;

        let packet = stream
            .next()
            .await
            .ok_or(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))??;

        println!("{:?}", packet);

        Ok(Self {
            stream,
            context,
            next_seq,
        })
    }

    pub async fn send_packet<P>(&mut self, packet: P) -> Result<(), P::Error>
    where
        P: EncodePacket<PacketFrame>,
        P::Error: From<std::io::Error>,
    {
        let mut packet = packet.encode_packet(&self.context)?;
        packet.set_seq(self.next_seq);
        self.next_seq = self.next_seq.wrapping_add(1);
        self.stream.send(packet).await?;
        Ok(())
    }

    pub async fn recv_packet(&mut self) -> Result<PacketFrame, std::io::Error> {
        let packet = self
            .stream
            .next()
            .await
            .ok_or(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))??;
        self.next_seq = packet.seq().wrapping_add(1);
        Ok(packet)
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
