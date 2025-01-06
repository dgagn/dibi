use bytes::{BufMut, BytesMut};

use crate::{codec::PacketFrame, context::Context, protocol::Capability, BufMutExt, EncodePacket};

pub struct HandshakeResponsePacket<'a> {
    pub(crate) username: &'a str,
    pub(crate) password: &'a [u8],
    pub(crate) database: Option<&'a str>,
}

impl<'a> HandshakeResponsePacket<'a> {
    pub fn size_hint(&self) -> usize {
        512
    }
}

impl<'a> EncodePacket<PacketFrame> for HandshakeResponsePacket<'a> {
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

        bytes.put_str_null_terminated(self.username.as_bytes());

        if context.has_server_capability(Capability::PLUGIN_AUTH_LENENC_CLIENT_DATA) {
            bytes.put_len_encoded_str(self.password);
        } else if context.has_server_capability(Capability::SECURE_CONNECTION) {
            let auth_len = self.password.len() as u8;
            bytes.put_u8(auth_len);
            bytes.put_slice(self.password);
        } else {
            bytes.put_str_null_terminated(self.password);
        }

        if context.has_server_capability(Capability::CONNECT_WITH_DB) {
            if let Some(database) = self.database {
                bytes.put_str_null_terminated(database);
            }
        }

        if context.has_server_capability(Capability::PLUGIN_AUTH) {
            let auth_type = context.auth_type();
            bytes.put_str_null_terminated(auth_type.name());
        }

        Ok(PacketFrame::new(bytes.freeze()))
    }
}
