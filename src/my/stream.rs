use futures::SinkExt;
use tokio_native_tls::TlsStream;
use tokio_stream::StreamExt;
use tokio_util::{codec::Framed, either::Either};

use crate::{
    codec::{PacketCodec, PacketFrame},
    context::Context,
    protocol::server::InitialHanshakePacket,
    ssl::UpgradeStream,
    stream::Stream,
    EncodePacket,
};

pub type StreamTransporter = Either<Stream, TlsStream<Stream>>;
pub type FramedStream = Framed<StreamTransporter, PacketCodec>;

#[derive(Debug)]
pub struct MyStream {
    stream: FramedStream,
    context: Context,
}

impl MyStream {
    pub fn new(stream: FramedStream) -> Self {
        Self {
            stream,
            context: Context::default(),
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
        if packet.is_command_packet() {
            let codec_mut = self.stream.codec_mut();
            codec_mut.reset_sequence();
        }
        let frame = packet.encode_packet(&self.context).map_err(Into::into)?;
        self.stream.send(frame).await?;

        Ok(())
    }

    pub async fn recv(&mut self) -> Result<PacketFrame, std::io::Error> {
        self.stream
            .next()
            .await
            .ok_or(std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?
    }

    pub async fn recv_packet(&mut self) -> Result<PacketFrame, std::io::Error> {
        let packet = self.recv().await?;
        // parse ok err switch packet
        Ok(packet)
    }
}

impl UpgradeStream for MyStream {
    async fn maybe_upgrade_tls(
        self,
        parts: Option<(&str, tokio_native_tls::TlsConnector)>,
    ) -> Result<Self, crate::ssl::UpgradeError> {
        let stream = if let Some((domain, connector)) = parts {
            let parts = self.stream.into_parts();
            let (stream, codec) = (parts.io, parts.codec);
            let stream = match stream {
                Either::Left(stream) => stream,
                Either::Right(stream) => {
                    return Ok(MyStream::new(Framed::new(Either::Right(stream), codec)));
                }
            };

            let tls_stream = connector.connect(domain, stream).await?;

            let transporter = StreamTransporter::Right(tls_stream);
            Framed::new(transporter, codec)
        } else {
            self.stream
        };

        Ok(Self {
            stream,
            context: self.context,
        })
    }
}
