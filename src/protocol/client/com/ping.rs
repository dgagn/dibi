use bytes::{BufMut, BytesMut};

use crate::{codec::PacketFrame, context::Context, EncodePacket};

#[derive(Debug, Default)]
pub struct PingPacket {
    _private: (),
}

impl PingPacket {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl EncodePacket<PacketFrame> for PingPacket {
    type Error = std::io::Error;

    fn encode_packet(self, _context: &Context) -> Result<PacketFrame, Self::Error> {
        let mut bytes = BytesMut::with_capacity(1);
        bytes.put_u8(0x0E);
        Ok(PacketFrame::new(bytes.freeze()))
    }

    fn is_command_packet(&self) -> bool {
        true
    }
}
