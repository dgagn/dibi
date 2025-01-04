bitflags::bitflags! {
    pub struct ConnectionState: u16 {
        const NETWORK_TIMEOUT = 1;
        const DATABASE = 2;
        const READ_ONLY = 4;
        const AUTO_COMMIT = 8;
        const TRANSACTION_ISOLATION = 16;
    }
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum StateChange {
    SystemVariables = 0,
    Schema = 1,
    #[allow(clippy::enum_variant_names)]
    StateChange = 2,
    GTIDs = 3,
    TransactionCharacteristics = 4,
    TransactionState = 5,
}

#[derive(Debug, thiserror::Error)]
#[error("Failed to parse state change recv {0}")]
pub struct ParseStateChangeError(u8);

impl TryFrom<u8> for StateChange {
    type Error = ParseStateChangeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StateChange::SystemVariables),
            1 => Ok(StateChange::Schema),
            2 => Ok(StateChange::StateChange),
            3 => Ok(StateChange::GTIDs),
            4 => Ok(StateChange::TransactionCharacteristics),
            5 => Ok(StateChange::TransactionState),
            _ => Err(ParseStateChangeError(value)),
        }
    }
}

impl From<StateChange> for u8 {
    fn from(value: StateChange) -> u8 {
        value as u8
    }
}
