/// RADIUS packet codes as defined in RFC 2865 Section 4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Code {
    /// Access-Request (1)
    AccessRequest = 1,
    /// Access-Accept (2)
    AccessAccept = 2,
    /// Access-Reject (3)
    AccessReject = 3,
    /// Accounting-Request (4) - RFC 2866
    AccountingRequest = 4,
    /// Accounting-Response (5) - RFC 2866
    AccountingResponse = 5,
    /// Access-Challenge (11)
    AccessChallenge = 11,
    /// Status-Server (12) - RFC 5997
    StatusServer = 12,
    /// Status-Client (13) - RFC 5997
    StatusClient = 13,
    /// Disconnect-Request (40) - RFC 5176. Server→NAS: terminate a session.
    DisconnectRequest = 40,
    /// Disconnect-ACK (41) - RFC 5176. NAS→server: session terminated.
    DisconnectAck = 41,
    /// Disconnect-NAK (42) - RFC 5176. NAS→server: could not terminate.
    DisconnectNak = 42,
    /// CoA-Request (43) - RFC 5176. Server→NAS: change authorization in place.
    CoaRequest = 43,
    /// CoA-ACK (44) - RFC 5176. NAS→server: authorization changed.
    CoaAck = 44,
    /// CoA-NAK (45) - RFC 5176. NAS→server: could not change authorization.
    CoaNak = 45,
}

impl Code {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Code::AccessRequest),
            2 => Some(Code::AccessAccept),
            3 => Some(Code::AccessReject),
            4 => Some(Code::AccountingRequest),
            5 => Some(Code::AccountingResponse),
            11 => Some(Code::AccessChallenge),
            12 => Some(Code::StatusServer),
            13 => Some(Code::StatusClient),
            40 => Some(Code::DisconnectRequest),
            41 => Some(Code::DisconnectAck),
            42 => Some(Code::DisconnectNak),
            43 => Some(Code::CoaRequest),
            44 => Some(Code::CoaAck),
            45 => Some(Code::CoaNak),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynauth_codes_round_trip() {
        for (code, value) in [
            (Code::DisconnectRequest, 40),
            (Code::DisconnectAck, 41),
            (Code::DisconnectNak, 42),
            (Code::CoaRequest, 43),
            (Code::CoaAck, 44),
            (Code::CoaNak, 45),
        ] {
            assert_eq!(code.as_u8(), value);
            assert_eq!(Code::from_u8(value), Some(code));
        }
        // Unassigned codes still decode to None.
        assert_eq!(Code::from_u8(46), None);
    }
}
