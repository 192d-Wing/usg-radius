//! RADIUS Packet and Attribute Validation
//!
//! Provides validation functions for RADIUS packets and attributes according to RFC 2865.
//! Supports both strict (default, recommended) and lenient RFC compliance modes.
//!
//! ## Validation Modes
//!
//! - **Strict Mode** (default): Enforces full RFC 2865 compliance including:
//!   - Required attributes (User-Name, User-Password/CHAP-Password)
//!   - Enumerated value validation (Service-Type, Framed-Protocol, etc.)
//!   - Type-specific validation (string UTF-8, integer/IPv4 lengths)
//!   - Malformed packet rejection
//!
//! - **Lenient Mode**: Only enforces critical requirements:
//!   - Required attributes must be present
//!   - Type-specific validation (prevents parsing errors)
//!   - Allows invalid enumerated values for compatibility

use crate::attributes::{Attribute, AttributeType};
use crate::packet::{Code, Packet};

/// Validation mode for RADIUS packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Lenient validation - only enforces critical requirements.
    /// Use this mode for compatibility with non-compliant RADIUS clients.
    Lenient,
    /// Strict validation - enforces full RFC 2865 compliance (recommended).
    /// This is the default and recommended mode for security and standards compliance.
    Strict,
}

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub message: String,
    pub attribute_type: Option<u8>,
}

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        ValidationError {
            message: message.into(),
            attribute_type: None,
        }
    }

    pub fn with_attribute(message: impl Into<String>, attr_type: u8) -> Self {
        ValidationError {
            message: message.into(),
            attribute_type: Some(attr_type),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(attr_type) = self.attribute_type {
            write!(f, "Attribute {}: {}", attr_type, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a RADIUS packet
pub fn validate_packet(packet: &Packet, mode: ValidationMode) -> Result<(), ValidationError> {
    // Validate required attributes based on packet type
    match packet.code {
        Code::AccessRequest => validate_access_request(packet, mode)?,
        Code::AccessAccept => validate_access_accept(packet, mode)?,
        Code::AccessReject => validate_access_reject(packet, mode)?,
        Code::StatusServer => validate_status_server(packet, mode)?,
        Code::AccountingRequest => validate_accounting_request(packet, mode)?,
        Code::AccountingResponse => validate_accounting_response(packet, mode)?,
        _ => {
            // Other packet types not yet fully supported
            if mode == ValidationMode::Strict {
                return Err(ValidationError::new(format!(
                    "Unsupported packet type: {:?}",
                    packet.code
                )));
            }
        }
    }

    // Validate all attributes
    for attr in &packet.attributes {
        validate_attribute(attr, mode)?;
    }

    Ok(())
}

/// Validate Access-Request packet
fn validate_access_request(packet: &Packet, _mode: ValidationMode) -> Result<(), ValidationError> {
    // RFC 2865 Section 4.1: User-Name is REQUIRED
    if packet
        .find_attribute(AttributeType::UserName as u8)
        .is_none()
    {
        return Err(ValidationError::with_attribute(
            "User-Name attribute is required in Access-Request",
            AttributeType::UserName as u8,
        ));
    }

    // RFC 2865 §4.1 requires User-Password OR CHAP-Password — but RFC 3579 §3.1
    // (RADIUS+EAP) carves out an exception: when EAP-Message (attr 79) is
    // present, neither User-Password nor CHAP-Password may be included.
    let has_user_password = packet
        .find_attribute(AttributeType::UserPassword as u8)
        .is_some();
    let has_chap_password = packet
        .find_attribute(AttributeType::ChapPassword as u8)
        .is_some();
    let has_eap_message = packet
        .find_attribute(AttributeType::EapMessage as u8)
        .is_some();

    if has_eap_message {
        if has_user_password || has_chap_password {
            return Err(ValidationError::new(
                "EAP-Message is present; User-Password/CHAP-Password MUST NOT be included (RFC 3579 §3.1)",
            ));
        }
    } else {
        if !has_user_password && !has_chap_password {
            return Err(ValidationError::new(
                "Either User-Password, CHAP-Password, or EAP-Message is required in Access-Request",
            ));
        }
        if has_user_password && has_chap_password {
            return Err(ValidationError::new(
                "User-Password and CHAP-Password cannot both be present in Access-Request",
            ));
        }
    }

    // RFC 2865 Section 5.32 & 5.4: Either NAS-IP-Address or NAS-Identifier MUST be present
    let has_nas_ip = packet
        .find_attribute(AttributeType::NasIpAddress as u8)
        .is_some();
    let has_nas_identifier = packet
        .find_attribute(AttributeType::NasIdentifier as u8)
        .is_some();

    if !has_nas_ip && !has_nas_identifier {
        return Err(ValidationError::new(
            "Either NAS-IP-Address or NAS-Identifier is required in Access-Request (RFC 2865)",
        ));
    }

    Ok(())
}

/// Validate Access-Accept packet
fn validate_access_accept(_packet: &Packet, _mode: ValidationMode) -> Result<(), ValidationError> {
    // RFC 2865 Section 4.2: No required attributes
    Ok(())
}

/// Validate Access-Reject packet
fn validate_access_reject(_packet: &Packet, _mode: ValidationMode) -> Result<(), ValidationError> {
    // RFC 2865 Section 4.3: No required attributes
    Ok(())
}

/// Validate Status-Server packet
fn validate_status_server(_packet: &Packet, _mode: ValidationMode) -> Result<(), ValidationError> {
    // RFC 5997: No required attributes
    Ok(())
}

/// Validate Accounting-Request packet
fn validate_accounting_request(
    packet: &Packet,
    _mode: ValidationMode,
) -> Result<(), ValidationError> {
    // RFC 2866 Section 4.1: Acct-Status-Type is REQUIRED
    if packet
        .find_attribute(AttributeType::AcctStatusType as u8)
        .is_none()
    {
        return Err(ValidationError::with_attribute(
            "Acct-Status-Type attribute is required in Accounting-Request",
            AttributeType::AcctStatusType as u8,
        ));
    }

    Ok(())
}

/// Validate Accounting-Response packet
fn validate_accounting_response(
    _packet: &Packet,
    _mode: ValidationMode,
) -> Result<(), ValidationError> {
    // RFC 2866: Accounting-Response has no required attributes
    Ok(())
}

/// Validate an individual attribute
fn validate_attribute(attr: &Attribute, mode: ValidationMode) -> Result<(), ValidationError> {
    match attr.attr_type {
        // String attributes
        t if t == AttributeType::UserName as u8 => validate_string_attribute(attr)?,
        t if t == AttributeType::FilterId as u8 => validate_string_attribute(attr)?,
        t if t == AttributeType::ReplyMessage as u8 => validate_string_attribute(attr)?,
        t if t == AttributeType::CallbackNumber as u8 => validate_string_attribute(attr)?,
        t if t == AttributeType::CallbackId as u8 => validate_string_attribute(attr)?,
        t if t == AttributeType::CalledStationId as u8 => validate_string_attribute(attr)?,
        t if t == AttributeType::CallingStationId as u8 => validate_string_attribute(attr)?,
        t if t == AttributeType::NasIdentifier as u8 => validate_string_attribute(attr)?,

        // Integer attributes with enumerated values
        t if t == AttributeType::ServiceType as u8 => validate_service_type(attr, mode)?,
        t if t == AttributeType::FramedProtocol as u8 => validate_framed_protocol(attr, mode)?,
        t if t == AttributeType::FramedRouting as u8 => validate_framed_routing(attr, mode)?,
        t if t == AttributeType::FramedCompression as u8 => {
            validate_framed_compression(attr, mode)?
        }
        t if t == AttributeType::LoginService as u8 => validate_login_service(attr, mode)?,
        t if t == AttributeType::TerminationAction as u8 => {
            validate_termination_action(attr, mode)?
        }

        // Integer attributes (no enumeration, just validate format)
        t if t == AttributeType::NasPort as u8 => validate_integer_attribute(attr)?,
        t if t == AttributeType::SessionTimeout as u8 => validate_integer_attribute(attr)?,
        t if t == AttributeType::IdleTimeout as u8 => validate_integer_attribute(attr)?,
        t if t == AttributeType::LoginTcpPort as u8 => validate_integer_attribute(attr)?,
        t if t == AttributeType::FramedMtu as u8 => validate_integer_attribute(attr)?,

        // IPv4 address attributes
        t if t == AttributeType::NasIpAddress as u8 => validate_ipv4_attribute(attr)?,
        t if t == AttributeType::FramedIpAddress as u8 => validate_ipv4_attribute(attr)?,
        t if t == AttributeType::FramedIpNetmask as u8 => validate_ipv4_attribute(attr)?,
        t if t == AttributeType::LoginIpHost as u8 => validate_ipv4_attribute(attr)?,

        _ => {
            // Unknown or not validated attribute types are allowed in lenient mode
            if mode == ValidationMode::Strict {
                // In strict mode, we could validate all known types more thoroughly
            }
        }
    }

    Ok(())
}

/// Validate string attribute (must be valid UTF-8)
fn validate_string_attribute(attr: &Attribute) -> Result<(), ValidationError> {
    if attr.as_string().is_err() {
        return Err(ValidationError::with_attribute(
            "Invalid UTF-8 in string attribute",
            attr.attr_type,
        ));
    }
    Ok(())
}

/// Validate integer attribute (must be exactly 4 bytes)
fn validate_integer_attribute(attr: &Attribute) -> Result<(), ValidationError> {
    if attr.value.len() != 4 {
        return Err(ValidationError::with_attribute(
            format!(
                "Integer attribute must be 4 bytes, got {}",
                attr.value.len()
            ),
            attr.attr_type,
        ));
    }
    Ok(())
}

/// Validate IPv4 address attribute (must be exactly 4 bytes)
fn validate_ipv4_attribute(attr: &Attribute) -> Result<(), ValidationError> {
    if attr.value.len() != 4 {
        return Err(ValidationError::with_attribute(
            format!(
                "IPv4 address attribute must be 4 bytes, got {}",
                attr.value.len()
            ),
            attr.attr_type,
        ));
    }
    Ok(())
}

/// Validate Service-Type attribute (RFC 2865 Section 5.6)
fn validate_service_type(attr: &Attribute, mode: ValidationMode) -> Result<(), ValidationError> {
    validate_integer_attribute(attr)?;
    let value = attr.as_integer().unwrap();

    // RFC 2865 defines values 1-13
    let valid = matches!(
        value,
        1..=13 // 1 Login
               // 2 Framed
               // 3 Callback Login
               // 4 Callback Framed
               // 5 Outbound
               // 6 Administrative
               // 7 NAS Prompt
               // 8 Authenticate Only
               // 9 Callback NAS Prompt
               // 10 Call Check
               // 11 Callback Administrative
               // 12 Voice (RFC 2865 extension)
               // 13 Fax (RFC 2865 extension)
    );

    if !valid && mode == ValidationMode::Strict {
        return Err(ValidationError::with_attribute(
            format!("Invalid Service-Type value: {} (must be 1-13)", value),
            attr.attr_type,
        ));
    }

    Ok(())
}

/// Validate Framed-Protocol attribute (RFC 2865 Section 5.7)
fn validate_framed_protocol(attr: &Attribute, mode: ValidationMode) -> Result<(), ValidationError> {
    validate_integer_attribute(attr)?;
    let value = attr.as_integer().unwrap();

    // RFC 2865 defines values 1-7
    let valid = matches!(
        value,
        1..=7 // 1 PPP
              // 2 SLIP
              // 3 AppleTalk Remote Access Protocol (ARAP)
              // 4 Gandalf proprietary SingleLink/MultiLink protocol
              // 5 Xylogics proprietary IPX/SLIP
              // 6 X.75 Synchronous
              // 7 GPRS PDP Context
    );

    if !valid && mode == ValidationMode::Strict {
        return Err(ValidationError::with_attribute(
            format!("Invalid Framed-Protocol value: {} (must be 1-7)", value),
            attr.attr_type,
        ));
    }

    Ok(())
}

/// Validate Framed-Routing attribute (RFC 2865 Section 5.10)
fn validate_framed_routing(attr: &Attribute, mode: ValidationMode) -> Result<(), ValidationError> {
    validate_integer_attribute(attr)?;
    let value = attr.as_integer().unwrap();

    let valid = matches!(
        value,
        0..=3 // 0 None
              // 1 Send routing packets
              // 2 Listen for routing packets
              // 3 Send and Listen
    );

    if !valid && mode == ValidationMode::Strict {
        return Err(ValidationError::with_attribute(
            format!("Invalid Framed-Routing value: {} (must be 0-3)", value),
            attr.attr_type,
        ));
    }

    Ok(())
}

/// Validate Framed-Compression attribute (RFC 2865 Section 5.13)
fn validate_framed_compression(
    attr: &Attribute,
    mode: ValidationMode,
) -> Result<(), ValidationError> {
    validate_integer_attribute(attr)?;
    let value = attr.as_integer().unwrap();

    let valid = matches!(
        value,
        0..=3 // 0 None
              // 1 VJ TCP/IP header compression
              // 2 IPX header compression
              // 3 Stac-LZS compression
    );

    if !valid && mode == ValidationMode::Strict {
        return Err(ValidationError::with_attribute(
            format!("Invalid Framed-Compression value: {} (must be 0-3)", value),
            attr.attr_type,
        ));
    }

    Ok(())
}

/// Validate Login-Service attribute (RFC 2865 Section 5.15)
fn validate_login_service(attr: &Attribute, mode: ValidationMode) -> Result<(), ValidationError> {
    validate_integer_attribute(attr)?;
    let value = attr.as_integer().unwrap();

    let valid = matches!(
        value,
        0..=8 // 0 Telnet
              // 1 Rlogin
              // 2 TCP Clear
              // 3 PortMaster (proprietary)
              // 4 LAT
              // 5 X25-PAD
              // 6 X25-T3POS
              // 8 TCP Clear Quiet (suppresses any NAS-generated connect string)
    );

    if !valid && mode == ValidationMode::Strict {
        return Err(ValidationError::with_attribute(
            format!("Invalid Login-Service value: {}", value),
            attr.attr_type,
        ));
    }

    Ok(())
}

/// Validate Termination-Action attribute (RFC 2865 Section 5.29)
fn validate_termination_action(
    attr: &Attribute,
    mode: ValidationMode,
) -> Result<(), ValidationError> {
    validate_integer_attribute(attr)?;
    let value = attr.as_integer().unwrap();

    let valid = matches!(
        value,
        0 // Default
        | 1 // RADIUS-Request
    );

    if !valid && mode == ValidationMode::Strict {
        return Err(ValidationError::with_attribute(
            format!("Invalid Termination-Action value: {} (must be 0-1)", value),
            attr.attr_type,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_access_request_with_user_name() {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, "test").unwrap());
        packet.add_attribute(
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        );
        packet.add_attribute(
            Attribute::new(AttributeType::NasIpAddress as u8, vec![192, 168, 0, 1]).unwrap(),
        );

        assert!(validate_packet(&packet, ValidationMode::Lenient).is_ok());
        assert!(validate_packet(&packet, ValidationMode::Strict).is_ok());
    }

    #[test]
    fn test_validate_access_request_missing_user_name() {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        );

        let result = validate_packet(&packet, ValidationMode::Lenient);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("User-Name attribute is required")
        );
    }

    #[test]
    fn test_validate_access_request_missing_password() {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, "test").unwrap());

        let result = validate_packet(&packet, ValidationMode::Lenient);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("User-Password, CHAP-Password, or EAP-Message is required")
        );
    }

    #[test]
    fn test_validate_access_request_eap_message_no_password() {
        // RFC 3579 §3.1: EAP-Message satisfies the credential requirement;
        // User-Password / CHAP-Password MUST NOT be present.
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, "test").unwrap());
        packet.add_attribute(
            Attribute::new(AttributeType::EapMessage as u8, vec![0x02, 0x00, 0x00, 0x05, 0x01])
                .unwrap(),
        );
        packet.add_attribute(
            Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1]).unwrap(),
        );
        assert!(validate_packet(&packet, ValidationMode::Lenient).is_ok());
    }

    #[test]
    fn test_validate_access_request_eap_with_password_rejected() {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, "test").unwrap());
        packet.add_attribute(
            Attribute::new(AttributeType::EapMessage as u8, vec![0x02, 0x00, 0x00, 0x05, 0x01])
                .unwrap(),
        );
        packet.add_attribute(
            Attribute::new(AttributeType::NasIpAddress as u8, vec![127, 0, 0, 1]).unwrap(),
        );
        packet.add_attribute(
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        );
        let err = validate_packet(&packet, ValidationMode::Lenient).unwrap_err();
        assert!(err.message.contains("MUST NOT be included"));
    }

    #[test]
    fn test_validate_access_request_both_passwords() {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, "test").unwrap());
        packet.add_attribute(
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        );
        packet.add_attribute(
            Attribute::new(AttributeType::ChapPassword as u8, vec![0u8; 17]).unwrap(),
        );

        let result = validate_packet(&packet, ValidationMode::Lenient);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("cannot both be present")
        );
    }

    #[test]
    fn test_validate_service_type_valid() {
        let attr = Attribute::integer(AttributeType::ServiceType as u8, 2).unwrap(); // Framed
        assert!(validate_attribute(&attr, ValidationMode::Strict).is_ok());
    }

    #[test]
    fn test_validate_service_type_invalid_strict() {
        let attr = Attribute::integer(AttributeType::ServiceType as u8, 99).unwrap();
        assert!(validate_attribute(&attr, ValidationMode::Strict).is_err());
    }

    #[test]
    fn test_validate_service_type_invalid_lenient() {
        let attr = Attribute::integer(AttributeType::ServiceType as u8, 99).unwrap();
        // Lenient mode allows invalid enumerated values
        assert!(validate_attribute(&attr, ValidationMode::Lenient).is_ok());
    }

    #[test]
    fn test_validate_integer_wrong_length() {
        let attr = Attribute::new(AttributeType::SessionTimeout as u8, vec![1, 2, 3]).unwrap(); // Only 3 bytes
        assert!(validate_attribute(&attr, ValidationMode::Lenient).is_err());
    }

    #[test]
    fn test_validate_ipv4_wrong_length() {
        let attr = Attribute::new(AttributeType::NasIpAddress as u8, vec![1, 2, 3]).unwrap(); // Only 3 bytes
        assert!(validate_attribute(&attr, ValidationMode::Lenient).is_err());
    }

    #[test]
    fn test_validate_string_invalid_utf8() {
        let attr = Attribute::new(AttributeType::UserName as u8, vec![0xFF, 0xFE, 0xFD]).unwrap();
        assert!(validate_attribute(&attr, ValidationMode::Lenient).is_err());
    }
}
