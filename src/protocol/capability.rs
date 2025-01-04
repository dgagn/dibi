bitflags::bitflags! {
    // https://mariadb.com/kb/en/connection/#capabilities
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    pub struct Capability: u64 {
        const CLIENT_MYSQL = 1;
        const FOUND_ROWS = 2;
        const CONNECT_WITH_DB = 8;
        const COMPRESS = 32;
        const LOCAL_FILES = 128;
        const IGNORE_SPACE = 256;
        const CLIENT_PROTOCOL_41 = 1 << 9;
        const CLIENT_INTERACTIVE = 1 << 10;
        const SSL = 1 << 11;
        const TRANSACTIONS = 1 << 13;
        const SECURE_CONNECTION = 1 << 15;
        const MULTI_STATEMENTS = 1 << 16;
        const MULTI_RESULTS = 1 << 17;
        const PS_MULTI_RESULTS = 1 << 18;
        const PLUGIN_AUTH = 1 << 19;
        const CONNECT_ATTRS = 1 << 20;
        const PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21;
        const CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 1 << 22;
        const CLIENT_SESSION_TRACK = 1 << 23;
        const CLIENT_DEPRECATE_EOF = 1 << 24;
        const CLIENT_OPTIONAL_RESULTSET_METADATA = 1 << 25;
        const CLIENT_ZSTD_COMPRESSION_ALGORITHM = 1 << 26;
        const CLIENT_CAPABILITY_EXTENSION = 1 << 29;
        const CLIENT_SSL_VERIFY_SERVER_CERT = 1 << 30;
        const CLIENT_REMEMBER_OPTIONS = 1 << 31;
        // MariaDB specific capabilities
        const PROGRESS = 1 << 32;
        const COM_MULTI = 1 << 33;
        const STMT_BULK_OPERATIONS = 1 << 34;
        const EXTENDED_METADATA = 1 << 35;
        const CACHE_METADATA = 1 << 36;
        const BULK_UNIT_RESULTS = 1 << 37;
    }
}

impl Capability {
    pub fn from_lower(lower: u16) -> Capability {
        Capability::from_bits_truncate(lower as u64)
    }

    pub fn upper(&mut self, upper: u16) {
        *self |= Capability::from_bits_truncate((upper as u64) << 16);
    }

    pub fn extended(&mut self, extended: u32) {
        *self |= Capability::from_bits_truncate((extended as u64) << 32);
    }

    pub fn to_default(&self) -> u32 {
        self.bits() as u32
    }

    pub fn to_extended(&self) -> u32 {
        (self.bits() >> 32) as u32
    }
}
