use bytes::{BufMut, BytesMut};

use crate::{codec::PacketFrame, context::Context, EncodePacket};

#[derive(Debug, Default)]
pub struct SslPacket {
    _private: (),
}

impl SslPacket {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl SslPacket {
    pub fn size_hint(&self) -> usize {
        32
    }
}

impl EncodePacket<PacketFrame> for SslPacket {
    type Error = std::io::Error;

    fn encode_packet(self, context: &Context) -> Result<PacketFrame, Self::Error> {
        let mut bytes = BytesMut::with_capacity(self.size_hint());
        bytes.put_u32_le(context.client_capabilities().to_default());
        bytes.put_u32_le(context.max_packet_size());
        bytes.put_u8(context.client_collation());
        bytes.resize(bytes.len() + 19, 0);

        if context.is_maria_db() {
            bytes.put_u32_le(context.client_capabilities().to_extended())
        } else {
            bytes.put_u32_le(0);
        }

        Ok(PacketFrame::new(bytes.freeze()))
    }
}

pub struct HandshakeResponse {}

impl HandshakeResponse {
    pub fn size_hint(&self) -> usize {
        // 4 + 4 + 1 + 19 + 4 + username.len() + 1 +
        512
    }
}

impl EncodePacket<PacketFrame> for HandshakeResponse {
    type Error = std::io::Error;

    fn encode_packet(self, context: &Context) -> Result<PacketFrame, Self::Error> {
        let mut bytes = BytesMut::with_capacity(self.size_hint());

        Ok(PacketFrame::new(bytes.freeze()))
    }
}
