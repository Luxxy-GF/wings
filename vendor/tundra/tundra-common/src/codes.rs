#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StreamCode {
    AclDenied = 1,
    NoSuchServer = 2,
    DialFailed = 3,
    Unavailable = 4,
    Protocol = 5,
    PortNotRegistered = 6,
    DrainFailed = 7,
}

impl StreamCode {
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[inline]
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => StreamCode::AclDenied,
            2 => StreamCode::NoSuchServer,
            3 => StreamCode::DialFailed,
            4 => StreamCode::Unavailable,
            5 => StreamCode::Protocol,
            6 => StreamCode::PortNotRegistered,
            7 => StreamCode::DrainFailed,
            _ => return None,
        })
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::AclDenied => "acl_denied",
            Self::NoSuchServer => "no_such_server",
            Self::DialFailed => "dial_failed",
            Self::Unavailable => "unavailable",
            Self::Protocol => "protocol_error",
            Self::PortNotRegistered => "port_not_registered",
            Self::DrainFailed => "drain_failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CloseCode {
    Shutdown = 0,
    AuthFailed = 1,
    DuplicateConnection = 2,
    Revoked = 3,
    Protocol = 4,
    ReauthTimeout = 5,
    VersionMismatch = 6,
    Restarting = 7,
}

impl CloseCode {
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[inline]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::AuthFailed => "auth_failed",
            Self::DuplicateConnection => "duplicate_connection",
            Self::Revoked => "revoked",
            Self::Protocol => "protocol_error",
            Self::ReauthTimeout => "reauth_timeout",
            Self::VersionMismatch => "version_mismatch",
            Self::Restarting => "restarting",
        }
    }

    #[inline]
    pub fn reason(self) -> &'static [u8] {
        self.to_str().as_bytes()
    }
}

/// Glare resolution: the connection dialed by the lexicographically lower uuid survives.
/// Both ends evaluate this independently and must agree.
#[inline]
pub fn keep_outbound(local: &uuid::Uuid, remote: &uuid::Uuid) -> bool {
    local.as_bytes() < remote.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // StreamCode / CloseCode

    #[test]
    fn codes_roundtrip_through_the_wire_representation() {
        let stream = [
            StreamCode::AclDenied,
            StreamCode::NoSuchServer,
            StreamCode::DialFailed,
            StreamCode::Unavailable,
            StreamCode::Protocol,
            StreamCode::PortNotRegistered,
            StreamCode::DrainFailed,
        ];
        for c in stream {
            assert_eq!(StreamCode::from_u32(c.as_u32()), Some(c));
        }

        assert_eq!(StreamCode::from_u32(0), None);
        assert_eq!(StreamCode::from_u32(999), None);
    }

    // keep_outbound

    #[test]
    fn glare_resolution_agrees_from_both_sides() {
        let a = uuid::Uuid::parse_str("00000000-0000-0000-0000-00000000000a").unwrap();
        let b = uuid::Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").unwrap();

        assert!(keep_outbound(&a, &b));
        assert!(!keep_outbound(&b, &a));
    }

    #[test]
    fn glare_resolution_matches_string_ordering_for_arbitrary_pairs() {
        let ids: Vec<_> = (0..64).map(|_| uuid::Uuid::new_v4()).collect();
        for a in &ids {
            for b in &ids {
                if a == b {
                    continue;
                }

                assert_eq!(keep_outbound(a, b), a.to_string() < b.to_string());
                assert_ne!(keep_outbound(a, b), keep_outbound(b, a));
            }
        }
    }

    #[test]
    fn exactly_one_connection_survives_every_pairing() {
        let a = uuid::Uuid::from_u128(1);
        let b = uuid::Uuid::from_u128(2);

        assert!(keep_outbound(&a, &b));
        assert!(!keep_outbound(&b, &a));
    }
}
