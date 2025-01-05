use bytes::Buf;

use crate::{
    codec::PacketFrame,
    protocol::{plugin::AuthType, Capability, ServerStatus, ServerVersion},
    BytesExt,
};

#[derive(Debug)]
pub struct InitialHanshakePacket {
    pub server_version: ServerVersion,
    pub connection_id: u32,
    pub server_capabilities: Capability,
    pub default_collation: u8,
    pub status_flags: ServerStatus,
    pub auth_type: Option<AuthType>,
    pub is_maria_db: bool,
    pub seed: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum InitialHandshakeError {
    #[error("unsupported protocol version: {0}")]
    ProtocolVersion(u8),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    ParseVersion(#[from] crate::protocol::error::ParseVersionError),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    PluginParse(#[from] crate::protocol::error::PluginParseError),
}

impl TryFrom<PacketFrame> for InitialHanshakePacket {
    type Error = InitialHandshakeError;

    fn try_from(packet: PacketFrame) -> Result<Self, Self::Error> {
        let mut payload = packet.take_buffer();
        let protocol_version = payload.get_u8();
        if protocol_version != 0xa {
            return Err(InitialHandshakeError::ProtocolVersion(protocol_version));
        }

        let server_version = payload.get_bytes_null()?;
        let server_version = std::str::from_utf8(&server_version)?;
        let server_version = server_version.parse::<ServerVersion>()?;

        let connection_id = payload.get_u32_le();
        let seed_start = payload.split_to(8);
        payload.advance(1);

        let server_capabilities_lower = payload.get_u16_le();
        let mut server_capabilities = Capability::from_lower(server_capabilities_lower);
        let default_collation = payload.get_u8();
        let status_flags = ServerStatus::from_bits_truncate(payload.get_u16_le());
        let server_capabilities_upper = payload.get_u16_le();
        server_capabilities.upper(server_capabilities_upper);

        let has_plugin_auth = server_capabilities.contains(Capability::PLUGIN_AUTH);

        let seed_length = if has_plugin_auth {
            let seed_length = payload.get_u8();
            std::cmp::max(12, seed_length.saturating_sub(9))
        } else {
            payload.advance(1);
            0
        };

        payload.advance(6);

        let is_mysql = server_capabilities.contains(Capability::CLIENT_MYSQL);
        let is_maria_db = server_version.is_maria_db() && !is_mysql;
        if is_mysql {
            payload.advance(4);
        } else {
            let extended_capabilities = payload.get_u32_le();
            server_capabilities.extended(extended_capabilities);
        }

        let has_secure_connection = server_capabilities.contains(Capability::SECURE_CONNECTION);
        let size_hint = if has_secure_connection {
            seed_start.len() + seed_length as usize
        } else {
            seed_start.len()
        };
        let mut seed = Vec::with_capacity(size_hint);
        seed.extend_from_slice(seed_start.as_ref());

        if has_secure_connection {
            let seed_end = payload.split_to(seed_length as usize);
            seed.extend_from_slice(seed_end.as_ref());
            payload.advance(1);
        }

        let auth_type = if has_plugin_auth {
            let auth_type = payload.get_bytes_null()?;
            let auth_type: AuthType = std::str::from_utf8(&auth_type)?.parse()?;
            Some(auth_type)
        } else {
            None
        };

        Ok(Self {
            server_version,
            connection_id,
            server_capabilities,
            default_collation,
            status_flags,
            auth_type,
            is_maria_db,
            seed,
        })
    }
}
