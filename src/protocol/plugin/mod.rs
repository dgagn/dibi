use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    Native,
    Clear,
    Sha256,
    CachedSha2,
    Parsec,
    Gssapi,
}

impl AuthType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Native => "mysql_native_password",
            Self::Sha256 => "sha256_password",
            Self::CachedSha2 => "caching_sha2_password",
            Self::Clear => "mysql_clear_password",
            Self::Parsec => "parsec",
            Self::Gssapi => "auth_gssapi_client",
        }
    }

    pub fn needs_ssl(&self) -> bool {
        matches!(self, Self::Clear)
    }

    pub fn supported(&self) -> bool {
        matches!(self, Self::Native | Self::Clear)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Failed to parse the auth plugin type from {0}")]
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
