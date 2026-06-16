//! RFC 5176 Dynamic Authorization Extensions (CoA / Disconnect).
//!
//! The packet [`crate::Code`]s (Disconnect-Request/ACK/NAK 40-42, CoA-Request/
//! ACK/NAK 43-45) live with the other codes. The Request Authenticator for a
//! Disconnect-Request / CoA-Request is computed exactly like an Accounting-Request
//! (RFC 5176 §3.4 → RFC 2866): see
//! [`crate::auth::calculate_accounting_request_authenticator`]. This module adds
//! the [`ErrorCause`] values a NAS returns in a NAK's `Error-Cause` (101)
//! attribute.

/// `Error-Cause` (attribute 101) values, RFC 5176 §3.5. A NAS returns one in a
/// CoA-NAK / Disconnect-NAK to explain the failure; the originating server reads
/// it to decide how to react (e.g. stop retrying on `SessionContextNotFound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCause {
    /// 201 — session was already gone; its residual context was removed.
    ResidualSessionContextRemoved = 201,
    /// 202 — an EAP packet in the request was invalid and ignored.
    InvalidEapPacket = 202,
    /// 401 — an attribute in the request is not supported.
    UnsupportedAttribute = 401,
    /// 402 — a required attribute is missing.
    MissingAttribute = 402,
    /// 403 — the NAS identification in the request did not match this NAS.
    NasIdentificationMismatch = 403,
    /// 404 — the request was malformed or otherwise invalid.
    InvalidRequest = 404,
    /// 405 — the requested service is not supported.
    UnsupportedService = 405,
    /// 406 — an extension in the request is not supported.
    UnsupportedExtension = 406,
    /// 407 — an attribute carried an invalid value.
    InvalidAttributeValue = 407,
    /// 501 — administratively prohibited.
    AdministrativelyProhibited = 501,
    /// 502 — request could not be routed to the target (proxy).
    RequestNotRoutable = 502,
    /// 503 — no session matched the request's identifying attributes.
    SessionContextNotFound = 503,
    /// 504 — the matched session cannot be removed/changed.
    SessionContextNotRemovable = 504,
    /// 505 — a proxy hit an unspecified processing error.
    OtherProxyProcessingError = 505,
    /// 506 — resources to honor the request are unavailable.
    ResourcesUnavailable = 506,
    /// 507 — the request has been accepted and acted on.
    RequestInitiated = 507,
    /// 508 — selecting among multiple sessions is not supported.
    MultipleSessionSelectionUnsupported = 508,
}

impl ErrorCause {
    /// Parse a wire value into a known [`ErrorCause`], or `None` if unrecognized.
    #[must_use]
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            201 => Some(Self::ResidualSessionContextRemoved),
            202 => Some(Self::InvalidEapPacket),
            401 => Some(Self::UnsupportedAttribute),
            402 => Some(Self::MissingAttribute),
            403 => Some(Self::NasIdentificationMismatch),
            404 => Some(Self::InvalidRequest),
            405 => Some(Self::UnsupportedService),
            406 => Some(Self::UnsupportedExtension),
            407 => Some(Self::InvalidAttributeValue),
            501 => Some(Self::AdministrativelyProhibited),
            502 => Some(Self::RequestNotRoutable),
            503 => Some(Self::SessionContextNotFound),
            504 => Some(Self::SessionContextNotRemovable),
            505 => Some(Self::OtherProxyProcessingError),
            506 => Some(Self::ResourcesUnavailable),
            507 => Some(Self::RequestInitiated),
            508 => Some(Self::MultipleSessionSelectionUnsupported),
            _ => None,
        }
    }

    /// The wire value (a 4-byte integer in the `Error-Cause` attribute).
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_cause_round_trips() {
        for c in [
            ErrorCause::SessionContextNotFound,
            ErrorCause::MissingAttribute,
            ErrorCause::AdministrativelyProhibited,
            ErrorCause::RequestInitiated,
        ] {
            assert_eq!(ErrorCause::from_u32(c.as_u32()), Some(c));
        }
        assert_eq!(ErrorCause::SessionContextNotFound.as_u32(), 503);
        assert_eq!(ErrorCause::from_u32(9999), None);
    }
}
