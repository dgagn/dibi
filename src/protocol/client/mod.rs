use bytes::{BufMut, BytesMut};

use crate::{codec::PacketFrame, context::Context, BufMutExt, EncodePacket};

use super::Capability;

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

pub struct HandshakeResponse<'a> {
    pub(crate) username: &'a str,
    pub(crate) password: &'a [u8],
    pub(crate) database: Option<&'a str>,
}

impl<'a> HandshakeResponse<'a> {
    pub fn size_hint(&self) -> usize {
        // 4 + 4 + 1 + 19 + 4 + username.len() + 1 +
        512
    }
}

impl<'a> EncodePacket<PacketFrame> for HandshakeResponse<'a> {
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
        bytes.put_str_null_terminated(self.username);

        if context.has_server_capability(Capability::PLUGIN_AUTH_LENENC_CLIENT_DATA) {
            bytes.put_len_encoded_str(self.password);
        } else if context.has_server_capability(Capability::SECURE_CONNECTION) {
            let auth_len = self.password.len() as u8;
            bytes.put_u8(auth_len);
            bytes.put_slice(self.password);
        } else {
            bytes.put_str_null_terminated(self.password);
        }

        if let Some(database) = self.database {
            if context.has_server_capability(Capability::CONNECT_WITH_DB) {
                bytes.put_str_null_terminated(database);
            } else {
                bytes.put_u8(0);
            }
        }

        if context.has_server_capability(Capability::PLUGIN_AUTH) {
            let auth_type = context.auth_type();
            bytes.put_str_null_terminated(auth_type.name());
        }

        if context.has_client_capability(Capability::CONNECT_ATTRS) {
            // todo
        }

        if context.has_client_capability(Capability::CLIENT_ZSTD_COMPRESSION_ALGORITHM) {
            // todo
        }

        Ok(PacketFrame::new(bytes.freeze()))
    }
}

#[derive(Debug, Default)]
pub struct Ping {
    _private: (),
}

impl Ping {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl EncodePacket<PacketFrame> for Ping {
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
