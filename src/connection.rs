use futures::SinkExt;
use tokio::net::{TcpStream, UnixStream};
use tokio_native_tls::native_tls::HandshakeError;
use tokio_stream::StreamExt;
use tokio_util::{codec::Framed, either::Either};

use crate::{
    codec::PacketCodec,
    context::Context,
    protocol::{
        client::{HandshakeResponse, SslPacket},
        server::InitialHanshakePacket,
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
    pub password: &'a str,
    pub stream_type: StreamType,
    pub tls: TlsOptions<'a>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Failed to perform initial handshake")]
    InitialHandshake(#[from] crate::protocol::server::InitialHandshakeError),

    #[error("The server does not support tls")]
    NoTls,

    #[error(transparent)]
    Tls(#[from] crate::ssl::TlsError),
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
            return Err(ConnectionError::NoTls);
        }

        let parts = Stream::into_tls_parts(&options.tls)?;

        let stream = if let Some(parts) = parts {
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

        let mut response = HandshakeResponse::from(options).encode_packet(&context)?;
        response.set_seq(next_seq);
        next_seq = next_seq.wrapping_add(1);

        // send handshake packet response

        Ok(Self {
            stream,
            context,
            next_seq,
        })
    }
}
