use crate::{
    codec::MAX_PACKET_SIZE,
    protocol::{
        plugin::AuthType, server::InitialHanshakePacket, Capability, ServerStatus, ServerVersion,
    },
};

#[derive(Debug, Clone)]
pub struct Context {
    server_capabilities: Capability,
    client_capabilities: Capability,
    is_maria_db: bool,
    max_packet_size: u32,
    client_collation: u8,
    auth_type: Option<AuthType>,
    seed: Vec<u8>,
    server_version: ServerVersion,
    connection_id: u32,
    status_flags: ServerStatus,
}

impl Context {
    fn default_client_capabilities() -> Capability {
        Capability::IGNORE_SPACE
            | Capability::CLIENT_PROTOCOL_41
            | Capability::TRANSACTIONS
            | Capability::SECURE_CONNECTION
            | Capability::MULTI_RESULTS
            | Capability::PS_MULTI_RESULTS
            | Capability::PLUGIN_AUTH
            | Capability::CONNECT_ATTRS
            | Capability::PLUGIN_AUTH_LENENC_CLIENT_DATA
            | Capability::CLIENT_SESSION_TRACK
    }
}

impl Context {
    pub fn new(packet: InitialHanshakePacket) -> Self {
        let server_capabilities = packet.server_capabilities;
        let client_capabilities = Self::default_client_capabilities();

        Context {
            server_capabilities,
            client_capabilities,
            max_packet_size: MAX_PACKET_SIZE as u32,
            is_maria_db: packet.is_maria_db,
            client_collation: packet.default_collation,
            seed: packet.seed,
            auth_type: packet.auth_type,
            server_version: packet.server_version,
            connection_id: packet.connection_id,
            status_flags: packet.status_flags,
        }
    }
}

impl Context {
    #[inline]
    pub fn server_version(&self) -> &ServerVersion {
        &self.server_version
    }

    #[inline]
    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    #[inline]
    pub fn status_flags(&self) -> ServerStatus {
        self.status_flags
    }

    #[inline]
    pub fn auth_type(&self) -> Option<AuthType> {
        self.auth_type
    }

    #[inline]
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    #[inline]
    pub fn is_maria_db(&self) -> bool {
        self.is_maria_db
    }

    #[inline]
    pub fn set_client_capability(&mut self, capability: Capability) {
        self.client_capabilities.insert(capability);
    }

    #[inline]
    pub fn has_server_capability(&self, capability: Capability) -> bool {
        self.server_capabilities.contains(capability)
    }

    #[inline]
    pub fn has_client_capability(&self, capability: Capability) -> bool {
        self.client_capabilities.contains(capability)
    }

    #[inline]
    pub fn max_packet_size(&self) -> u32 {
        self.max_packet_size
    }

    #[inline]
    pub fn client_collation(&self) -> u8 {
        self.client_collation
    }

    #[inline]
    pub fn server_capabilities(&self) -> Capability {
        self.server_capabilities
    }

    #[inline]
    pub fn client_capabilities(&self) -> Capability {
        self.client_capabilities
    }
}
