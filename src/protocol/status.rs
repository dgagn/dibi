bitflags::bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    pub struct ServerStatus: u16 {
        const IN_TRANSACTION = 1;
        const AUTOCOMMIT = 2;
        const MORE_RESULTS_EXISTS = 8;
        const QUERY_NO_GOOD_INDEX_USED = 16;
        const QUERY_NO_INDEX_USED = 32;
        const CURSOR_EXISTS = 64;
        const LAST_ROW_SENT = 128;
        const DB_DROPPED = 1 << 8;
        const NO_BACKSLASH_ESCAPES = 1 << 9;
        const METADATA_CHANGED = 1 << 10;
        const QUERY_WAS_SLOW = 1 << 11;
        const PS_OUT_PARAMS = 1 << 12;
        const IN_TRANS_READONLY = 1 << 13;
        const SESSION_STATE_CHANGED = 1 << 14;
    }
}
