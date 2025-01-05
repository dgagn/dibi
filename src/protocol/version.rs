use std::{num::ParseIntError, str::FromStr};

const MARIADB_RPL_HACK_PREFIX: &str = "5.5.5-";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServerVersion {
    major: u16,
    minor: u16,
    patch: u16,
    is_maria_db: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseVersionError {
    #[error("could not parse a part of the version to u16")]
    ParseIntError(#[from] ParseIntError),

    #[error("could not parse the server version to major.minor.patch")]
    Parse,

    #[error("the parts of the version is not correct")]
    VersionParts,
}

impl ServerVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
            is_maria_db: false,
        }
    }

    pub fn major(&self) -> u16 {
        self.major
    }

    pub fn minor(&self) -> u16 {
        self.minor
    }

    pub fn patch(&self) -> u16 {
        self.patch
    }

    pub fn is_maria_db(&self) -> bool {
        self.is_maria_db
    }
}

impl FromStr for ServerVersion {
    type Err = ParseVersionError;

    fn from_str(mut version: &str) -> Result<Self, Self::Err> {
        let is_maria_db =
            version.starts_with(MARIADB_RPL_HACK_PREFIX) || version.contains("MariaDB");

        if let Some(stripped_version) = version.strip_prefix(MARIADB_RPL_HACK_PREFIX) {
            version = stripped_version;
        }

        let mut parts = version.split('.');
        let major = parts.next().ok_or(ParseVersionError::Parse)?.parse()?;
        let minor = parts.next().ok_or(ParseVersionError::Parse)?.parse()?;
        let mut suffix = parts.next().ok_or(ParseVersionError::Parse)?.split('-');
        let patch = suffix
            .next()
            .ok_or(ParseVersionError::VersionParts)?
            .parse()?;

        Ok(Self {
            major,
            minor,
            patch,
            is_maria_db,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mariadb_server_version_should_be_parsed() {
        let version = "5.5.5-10.4.17-MariaDB-1:10.4.17+maria~bionic";
        let server_version = version.parse::<ServerVersion>().unwrap();
        assert_eq!(server_version.major(), 10);
        assert_eq!(server_version.minor(), 4);
        assert_eq!(server_version.patch(), 17);
        assert!(server_version.is_maria_db());
    }

    #[test]
    fn mysql_server_version_should_be_parsed() {
        let version = "8.0.23";
        let server_version = version.parse::<ServerVersion>().unwrap();
        assert_eq!(server_version.major(), 8);
        assert_eq!(server_version.minor(), 0);
        assert_eq!(server_version.patch(), 23);
        assert!(!server_version.is_maria_db());
    }

    #[test]
    fn invalid_server_version_should_fail() {
        let version = "8.0";
        let server_version = version.parse::<ServerVersion>();
        assert!(server_version.is_err());
    }

    #[test]
    fn invalid_server_version_parts_should_fail() {
        let version = "hello.world.123";
        let server_version = version.parse::<ServerVersion>();
        assert!(server_version.is_err());
    }
}
