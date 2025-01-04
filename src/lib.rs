use bytes::Buf;
use codec::PacketFrame;
use context::Context;

mod codec;
pub mod connection;
pub mod context;
pub mod protocol;
pub mod ssl;
pub mod stream;

pub trait BytesExt {
    fn get_bytes_null(&mut self) -> Result<bytes::Bytes, std::io::Error>;
}

impl BytesExt for bytes::Bytes {
    fn get_bytes_null(&mut self) -> Result<bytes::Bytes, std::io::Error> {
        let end = self
            .iter()
            .position(|&b| b == 0)
            .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let bytes = self.split_to(end);
        self.advance(1);
        Ok(bytes)
    }
}

pub trait DecodePacket: Sized {
    type Error;

    fn decode_packet(packet: PacketFrame, context: &Context) -> Result<Self, Self::Error>;
}

pub trait EncodePacket<T> {
    type Error;

    fn encode_packet(self, context: &Context) -> Result<T, Self::Error>;
}

impl<U> EncodePacket<U> for PacketFrame
where
    U: DecodePacket,
{
    type Error = <U as DecodePacket>::Error;

    fn encode_packet(self, context: &Context) -> Result<U, Self::Error> {
        U::decode_packet(self, context)
    }
}
