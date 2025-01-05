use std::{fmt, str::FromStr};

use native::mysql_native_password;

use crate::context::Context;

pub mod native;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    #[default]
    Native,
    Clear,
    Sha256,
    CachedSha2,
    Parsec,
    Gssapi,
    Ed25519,
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthTypeError {}

impl AuthType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Native => "mysql_native_password",
            Self::Sha256 => "sha256_password",
            Self::CachedSha2 => "caching_sha2_password",
            Self::Clear => "mysql_clear_password",
            Self::Parsec => "parsec",
            Self::Gssapi => "auth_gssapi_client",
            Self::Ed25519 => "client_ed25519",
        }
    }

    pub fn needs_ssl(&self) -> bool {
        matches!(self, Self::Clear)
    }

    pub fn supported(&self) -> bool {
        matches!(self, Self::Native | Self::Clear)
    }

    pub fn encrypt(&self, password: &[u8], context: &Context) -> Result<Vec<u8>, AuthTypeError> {
        match self {
            Self::Native => Ok(mysql_native_password(password, context.seed()).to_vec()),
            Self::Clear => Ok(password.to_vec()),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to parse the auth plugin type from {0}")]
pub struct PluginParseError(String);

impl FromStr for AuthType {
    type Err = PluginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mysql_native_password" => Ok(Self::Native),
            "caching_sha2_password" => Ok(Self::CachedSha2),
            "sha256_password" => Ok(Self::Sha256),
            "mysql_clear_password" => Ok(Self::Clear),
            "parsec" => Ok(Self::Parsec),
            "auth_gssapi_client" => Ok(Self::Gssapi),
            _ => Err(PluginParseError(s.into())),
        }
    }
}
