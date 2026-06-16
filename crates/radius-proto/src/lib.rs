//! RADIUS Protocol Implementation
//!
//! This crate provides a complete implementation of the RADIUS protocol
//! as defined in RFC 2865, 2866, 2869, and 5997.
//!
//! # Features
//!
//! - Packet encoding and decoding
//! - All standard RADIUS attributes (Types 1-80+)
//! - MD5-based password encryption
//! - Request/Response Authenticator calculation
//! - Zero-copy packet parsing where possible
//!
//! # Example
//!
//! ```rust
//! use radius_proto::{Packet, Code, Attribute, AttributeType};
//! use radius_proto::auth::{generate_request_authenticator, encrypt_user_password};
//!
//! // Create an Access-Request packet
//! let req_auth = generate_request_authenticator();
//! let mut packet = Packet::new(Code::AccessRequest, 1, req_auth);
//!
//! // Add User-Name attribute
//! packet.add_attribute(
//!     Attribute::string(AttributeType::UserName as u8, "alice").unwrap()
//! );
//!
//! // Add encrypted User-Password
//! let encrypted_pwd = encrypt_user_password("password", b"secret", &req_auth);
//! packet.add_attribute(
//!     Attribute::new(AttributeType::UserPassword as u8, encrypted_pwd).unwrap()
//! );
//!
//! // Encode to bytes
//! let bytes = packet.encode().unwrap();
//! ```

pub mod accounting;
pub mod attributes;
pub mod auth;
pub mod chap;
pub mod dynauth;
pub mod eap;
pub mod message_auth;
pub mod packet;
#[cfg(feature = "revocation")]
pub mod revocation;
pub mod validation;

pub use accounting::{AccountingError, AcctAuthentic, AcctStatusType, AcctTerminateCause};
pub use attributes::{Attribute, AttributeType};
pub use auth::{
    calculate_accounting_request_authenticator, calculate_response_authenticator,
    decrypt_user_password, encrypt_user_password, generate_request_authenticator,
    verify_response_authenticator,
};
pub use chap::{
    ChapChallenge, ChapError, ChapResponse, compute_chap_response, verify_chap_response,
};
pub use dynauth::ErrorCause;
pub use eap::{
    EapCode, EapError, EapPacket, EapSession, EapSessionManager, EapState, EapType, SessionStats,
    add_eap_to_radius_packet, eap_from_radius_packet, eap_to_radius_attributes,
};
pub use message_auth::{calculate_message_authenticator, verify_message_authenticator};
pub use packet::{Code, Packet, PacketError};
pub use validation::{ValidationError, ValidationMode, validate_packet};
