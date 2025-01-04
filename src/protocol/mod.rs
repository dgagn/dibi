mod capability;
pub mod client;
pub mod plugin;
pub mod server;
mod state;
mod status;
mod version;

pub mod error {
    pub use super::plugin::PluginParseError;
    pub use super::state::ParseStateChangeError;
    pub use super::version::ParseVersionError;
}

pub use capability::Capability;
pub use state::ConnectionState;
pub use state::StateChange;
pub use status::ServerStatus;
pub use version::ServerVersion;
