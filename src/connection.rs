use futures::SinkExt;
use tokio::net::{TcpStream, UnixStream};
use tokio_native_tls::native_tls;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::{
    codec::{PacketCodec, PacketFrame},
    context::Context,
    protocol::{
        client::{HandshakeResponse, SslPacket},
        plugin::{AuthType, AuthTypeError},
        server::{InitialHandshakeError, InitialHanshakePacket},
        Capability,
    },
    ssl::{into_tls_parts, StreamTransporter, TlsMode, TlsOptions, UpgradeStream},
    stream::{Stream, StreamType},
    EncodePacket,
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
    UpgradeError(#[from] crate::ssl::UpgradeError),

    #[error(transparent)]
    Tls(#[from] native_tls::Error),
}

pub type FramedStream = Framed<StreamTransporter, PacketCodec>;

#[derive(Debug)]
pub struct MyStream {
    stream: FramedStream,
    context: Context,
    sequence: u8,
}

impl MyStream {
    pub fn new(stream: FramedStream) -> Self {
        Self {
            stream,
            context: Context::default(),
            sequence: 0,
        }
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }

    pub fn handshake_packet(&mut self, packet: InitialHanshakePacket) {
        self.context.for_packet(packet);
    }

    pub async fn send_packet<P>(&mut self, packet: P) -> Result<(), std::io::Error>
    where
        P: EncodePacket<PacketFrame>,
        P::Error: Into<std::io::Error>,
    {
        let mut frame = packet.encode_packet(&self.context).map_err(Into::into)?;
        frame.seq = self.sequence;
        self.stream.send(frame).await?;
        self.sequence = self.sequence.wrapping_add(1);

        Ok(())
    }

    pub async fn recv_packet(&mut self) -> Result<PacketFrame, std::io::Error> {
        let packet = self
            .stream
            .next()
            .await
            .ok_or(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))??;
        self.sequence = packet.seq.wrapping_add(1);
        Ok(packet)
    }
}

impl UpgradeStream for MyStream {
    async fn maybe_upgrade_tls(
        self,
        parts: Option<(&str, tokio_native_tls::TlsConnector)>,
    ) -> Result<Self, crate::ssl::UpgradeError> {
        let stream = self.stream.maybe_upgrade_tls(parts).await?;
        Ok(Self {
            stream,
            context: self.context,
            sequence: self.sequence,
        })
    }
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

        let packet = mystream.recv_packet().await?;
        let handshake: InitialHanshakePacket = packet.try_into()?;
        mystream.handshake_packet(handshake);

        if matches!(
            options.tls.mode,
            TlsMode::Required | TlsMode::VerifyCa | TlsMode::VerifyFull
        ) && !mystream.context().has_server_capability(Capability::SSL)
        {
            return Err(ConnectionError::TlsCapability);
        }

        let parts = into_tls_parts(&options.tls).await?;

        let stream = if parts.is_some() {
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
        //let ping = client::Ping::new();
        //let packet = ping.encode_packet(&self.context)?;
        //self.stream.send(packet).await?;
        //let packet = self.recv_packet().await?;
        //println!("{:?}", packet);
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
