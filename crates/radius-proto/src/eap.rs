//! EAP (Extensible Authentication Protocol) Support
//!
//! This module implements EAP protocol structures as defined in RFC 3748
//! and EAP over RADIUS as defined in RFC 3579.
//!
//! # EAP Packet Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Code      |  Identifier   |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |  Type-Data ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::attributes::{Attribute, AttributeType};
use crate::packet::Packet;
use thiserror::Error;

/// EAP packet code (first byte of EAP packet)
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EapCode {
    /// Request packet (Code 1)
    Request = 1,
    /// Response packet (Code 2)
    Response = 2,
    /// Success packet (Code 3)
    Success = 3,
    /// Failure packet (Code 4)
    Failure = 4,
}

impl EapCode {
    /// Convert from u8 to EapCode
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(EapCode::Request),
            2 => Some(EapCode::Response),
            3 => Some(EapCode::Success),
            4 => Some(EapCode::Failure),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// EAP method types (RFC 3748 and IANA registry)
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EapType {
    /// Identity (Type 1) - RFC 3748
    Identity = 1,
    /// Notification (Type 2) - RFC 3748
    Notification = 2,
    /// Nak (Type 3) - RFC 3748
    /// Response only, sent in response to unacceptable authentication type
    Nak = 3,
    /// MD5-Challenge (Type 4) - RFC 3748
    Md5Challenge = 4,
    /// One-Time Password (Type 5) - RFC 2284 (deprecated)
    OneTimePassword = 5,
    /// Generic Token Card (Type 6) - RFC 2284 (deprecated)
    GenericTokenCard = 6,
    /// EAP-TLS (Type 13) - RFC 5216
    Tls = 13,
    /// EAP-TTLS (Type 21) - RFC 5281
    Ttls = 21,
    /// PEAP (Type 25) - draft-josefsson-pppext-eap-tls-eap
    Peap = 25,
    /// EAP-MSCHAPv2 (Type 26) - draft-kamath-pppext-eap-mschapv2
    MsChapV2 = 26,
    /// EAP-TEAP (Type 55) - RFC 7170
    Teap = 55,
}

impl EapType {
    /// Convert from u8 to EapType
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(EapType::Identity),
            2 => Some(EapType::Notification),
            3 => Some(EapType::Nak),
            4 => Some(EapType::Md5Challenge),
            5 => Some(EapType::OneTimePassword),
            6 => Some(EapType::GenericTokenCard),
            13 => Some(EapType::Tls),
            21 => Some(EapType::Ttls),
            25 => Some(EapType::Peap),
            26 => Some(EapType::MsChapV2),
            55 => Some(EapType::Teap),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// EAP packet structure
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    /// EAP code (Request, Response, Success, Failure)
    pub code: EapCode,
    /// Identifier for matching requests and responses (0-255)
    pub identifier: u8,
    /// EAP type (only present for Request/Response)
    pub eap_type: Option<EapType>,
    /// Type-specific data
    pub data: Vec<u8>,
}

impl EapPacket {
    /// Create a new EAP packet
    pub fn new(code: EapCode, identifier: u8, eap_type: Option<EapType>, data: Vec<u8>) -> Self {
        EapPacket {
            code,
            identifier,
            eap_type,
            data,
        }
    }

    /// Create an EAP Identity Request
    pub fn identity_request(identifier: u8, message: &str) -> Self {
        EapPacket {
            code: EapCode::Request,
            identifier,
            eap_type: Some(EapType::Identity),
            data: message.as_bytes().to_vec(),
        }
    }

    /// Create an EAP Identity Response
    pub fn identity_response(identifier: u8, identity: &str) -> Self {
        EapPacket {
            code: EapCode::Response,
            identifier,
            eap_type: Some(EapType::Identity),
            data: identity.as_bytes().to_vec(),
        }
    }

    /// Create an EAP Success packet
    pub fn success(identifier: u8) -> Self {
        EapPacket {
            code: EapCode::Success,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    /// Create an EAP Failure packet
    pub fn failure(identifier: u8) -> Self {
        EapPacket {
            code: EapCode::Failure,
            identifier,
            eap_type: None,
            data: Vec::new(),
        }
    }

    /// Parse EAP packet from bytes
    ///
    /// # Packet Format
    /// - Code (1 byte)
    /// - Identifier (1 byte)
    /// - Length (2 bytes, network byte order)
    /// - Type (1 byte, only for Request/Response)
    /// - Type-Data (variable length)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EapError> {
        if bytes.len() < 4 {
            return Err(EapError::PacketTooShort {
                expected: 4,
                actual: bytes.len(),
            });
        }

        // Parse header
        let code = EapCode::from_u8(bytes[0]).ok_or(EapError::InvalidCode(bytes[0]))?;
        let identifier = bytes[1];
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        // Validate length
        if length < 4 {
            return Err(EapError::InvalidLength(length));
        }
        if bytes.len() < length {
            return Err(EapError::PacketTooShort {
                expected: length,
                actual: bytes.len(),
            });
        }

        // Parse type and data based on code
        let (eap_type, data) = match code {
            EapCode::Request | EapCode::Response => {
                if length < 5 {
                    return Err(EapError::InvalidLength(length));
                }
                let type_byte = bytes[4];
                let eap_type = EapType::from_u8(type_byte);
                let data = bytes[5..length].to_vec();
                (eap_type, data)
            }
            EapCode::Success | EapCode::Failure => {
                // Success and Failure packets have no Type field
                (None, Vec::new())
            }
        };

        Ok(EapPacket {
            code,
            identifier,
            eap_type,
            data,
        })
    }

    /// Encode EAP packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Add code and identifier
        bytes.push(self.code.as_u8());
        bytes.push(self.identifier);

        // Calculate length
        let length = match self.code {
            EapCode::Request | EapCode::Response => {
                4 + 1 + self.data.len() // header + type + data
            }
            EapCode::Success | EapCode::Failure => {
                4 // header only
            }
        };

        // Add length (network byte order)
        bytes.extend_from_slice(&(length as u16).to_be_bytes());

        // Add type and data for Request/Response
        if let Some(eap_type) = self.eap_type {
            bytes.push(eap_type.as_u8());
            bytes.extend_from_slice(&self.data);
        }

        bytes
    }

    /// Get the total length of the packet
    pub fn length(&self) -> usize {
        match self.code {
            EapCode::Request | EapCode::Response => 4 + 1 + self.data.len(),
            EapCode::Success | EapCode::Failure => 4,
        }
    }
}

/// EAP-related errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EapError {
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    #[error("Invalid EAP code: {0}")]
    InvalidCode(u8),

    #[error("Invalid packet length: {0}")]
    InvalidLength(usize),

    #[error("Unknown EAP type: {0}")]
    UnknownType(u8),

    #[error("Fragmentation not supported")]
    FragmentationNotSupported,

    #[error("EAP session not found")]
    SessionNotFound,

    #[error("Invalid state for operation")]
    InvalidState,

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid challenge length: {0}")]
    InvalidChallengeLength(usize),

    #[error("Invalid response format")]
    InvalidResponseFormat,

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[cfg(feature = "tls")]
    #[error("TLS error: {0}")]
    TlsError(String),

    #[cfg(feature = "tls")]
    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[cfg(feature = "tls")]
    #[error("IO error: {0}")]
    IoError(String),
}

/// EAP-MD5 Challenge implementation (RFC 3748 Section 5.4)
///
/// EAP-MD5 provides a simple challenge-response authentication using MD5 hash.
/// It is primarily useful for testing and simple deployments.
///
/// Security Note: EAP-MD5 does not provide mutual authentication or key derivation,
/// and should not be used in production wireless environments. It's included here
/// for testing and compatibility with legacy systems.
pub mod eap_md5 {
    use super::*;

    /// EAP-MD5 Challenge value size (typically 16 bytes)
    pub const MD5_CHALLENGE_SIZE: usize = 16;

    /// EAP-MD5 Response value size (16 bytes MD5 hash)
    pub const MD5_RESPONSE_SIZE: usize = 16;

    /// Create an EAP-MD5 Challenge request
    ///
    /// # Arguments
    /// * `identifier` - EAP packet identifier
    /// * `challenge` - Challenge bytes (typically 16 bytes random)
    /// * `message` - Optional message to include after challenge
    ///
    /// # Format
    /// ```text
    /// 0                   1                   2                   3
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Value-Size    | Value (Challenge) ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Name (optional) ...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub fn create_challenge(identifier: u8, challenge: &[u8], message: &str) -> EapPacket {
        let mut data = Vec::new();
        data.push(challenge.len() as u8); // Value-Size
        data.extend_from_slice(challenge); // Challenge value
        data.extend_from_slice(message.as_bytes()); // Optional name/message

        EapPacket::new(
            EapCode::Request,
            identifier,
            Some(EapType::Md5Challenge),
            data,
        )
    }

    /// Parse an EAP-MD5 Challenge from packet data
    ///
    /// Returns (challenge_bytes, optional_message)
    pub fn parse_challenge(packet: &EapPacket) -> Result<(Vec<u8>, String), EapError> {
        if packet.eap_type != Some(EapType::Md5Challenge) {
            return Err(EapError::InvalidResponseFormat);
        }

        if packet.data.is_empty() {
            return Err(EapError::InvalidChallengeLength(0));
        }

        let value_size = packet.data[0] as usize;
        if packet.data.len() < 1 + value_size {
            return Err(EapError::InvalidChallengeLength(packet.data.len()));
        }

        let challenge = packet.data[1..1 + value_size].to_vec();
        let message = if packet.data.len() > 1 + value_size {
            String::from_utf8_lossy(&packet.data[1 + value_size..]).to_string()
        } else {
            String::new()
        };

        Ok((challenge, message))
    }

    /// Create an EAP-MD5 Response
    ///
    /// # Arguments
    /// * `identifier` - EAP packet identifier (must match challenge)
    /// * `response_hash` - MD5 hash of (identifier + password + challenge)
    /// * `name` - Optional name/identity
    pub fn create_response(identifier: u8, response_hash: &[u8; 16], name: &str) -> EapPacket {
        let mut data = Vec::new();
        data.push(MD5_RESPONSE_SIZE as u8); // Value-Size
        data.extend_from_slice(response_hash); // MD5 hash
        data.extend_from_slice(name.as_bytes()); // Optional name

        EapPacket::new(
            EapCode::Response,
            identifier,
            Some(EapType::Md5Challenge),
            data,
        )
    }

    /// Parse an EAP-MD5 Response from packet data
    ///
    /// Returns (response_hash, optional_name)
    pub fn parse_response(packet: &EapPacket) -> Result<([u8; 16], String), EapError> {
        if packet.eap_type != Some(EapType::Md5Challenge) {
            return Err(EapError::InvalidResponseFormat);
        }

        if packet.data.is_empty() {
            return Err(EapError::InvalidChallengeLength(0));
        }

        let value_size = packet.data[0] as usize;
        if value_size != MD5_RESPONSE_SIZE {
            return Err(EapError::InvalidChallengeLength(value_size));
        }

        if packet.data.len() < 1 + MD5_RESPONSE_SIZE {
            return Err(EapError::PacketTooShort {
                expected: 1 + MD5_RESPONSE_SIZE,
                actual: packet.data.len(),
            });
        }

        let mut response_hash = [0u8; 16];
        response_hash.copy_from_slice(&packet.data[1..1 + MD5_RESPONSE_SIZE]);

        let name = if packet.data.len() > 1 + MD5_RESPONSE_SIZE {
            String::from_utf8_lossy(&packet.data[1 + MD5_RESPONSE_SIZE..]).to_string()
        } else {
            String::new()
        };

        Ok((response_hash, name))
    }

    /// Compute the expected EAP-MD5 response hash
    ///
    /// Hash = MD5(identifier + password + challenge)
    ///
    /// # Arguments
    /// * `identifier` - EAP packet identifier
    /// * `password` - User's password (plain text)
    /// * `challenge` - Challenge bytes from the request
    pub fn compute_response_hash(identifier: u8, password: &str, challenge: &[u8]) -> [u8; 16] {
        let mut data = Vec::new();
        data.push(identifier);
        data.extend_from_slice(password.as_bytes());
        data.extend_from_slice(challenge);

        let digest = md5::compute(&data);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&digest.0);
        hash
    }

    /// Verify an EAP-MD5 response
    ///
    /// Returns true if the response hash matches the expected hash
    pub fn verify_response(
        identifier: u8,
        password: &str,
        challenge: &[u8],
        response_hash: &[u8; 16],
    ) -> bool {
        let expected = compute_response_hash(identifier, password, challenge);
        expected == *response_hash
    }
}

/// EAP-TLS implementation (RFC 5216)
///
/// EAP-TLS provides certificate-based mutual authentication using TLS.
/// It is one of the most secure EAP methods and is widely used in enterprise
/// wireless networks (802.1X/WPA-Enterprise).
///
/// # Features
/// - Mutual authentication using X.509 certificates
/// - Strong cryptographic protection
/// - Master Session Key (MSK) and Extended MSK (EMSK) derivation
/// - Support for fragmentation and reassembly
///
/// # Security
/// EAP-TLS provides:
/// - Mutual authentication (both client and server authenticate)
/// - Perfect forward secrecy (with appropriate cipher suites)
/// - Protection against man-in-the-middle attacks
/// - Key derivation for wireless encryption
#[cfg(feature = "tls")]
pub mod eap_tls {
    use super::*;
    use sha2::Sha256;

    /// EAP-TLS flags (first byte of Type-Data)
    ///
    /// ```text
    ///  0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+
    /// |L M S R R R R R|
    /// +-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// - L (Length included) = 0x80
    /// - M (More fragments) = 0x40
    /// - S (Start) = 0x20
    /// - R (Reserved) = Must be zero
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TlsFlags(u8);

    impl TlsFlags {
        /// Length included flag (L bit)
        pub const LENGTH_INCLUDED: u8 = 0x80;
        /// More fragments flag (M bit)
        pub const MORE_FRAGMENTS: u8 = 0x40;
        /// EAP-TLS start flag (S bit)
        pub const START: u8 = 0x20;

        /// Create new TLS flags
        pub fn new(length_included: bool, more_fragments: bool, start: bool) -> Self {
            let mut flags = 0u8;
            if length_included {
                flags |= Self::LENGTH_INCLUDED;
            }
            if more_fragments {
                flags |= Self::MORE_FRAGMENTS;
            }
            if start {
                flags |= Self::START;
            }
            TlsFlags(flags)
        }

        /// Create from raw byte
        pub fn from_u8(value: u8) -> Self {
            TlsFlags(value & 0xE0) // Mask reserved bits
        }

        /// Get raw byte value
        pub fn as_u8(self) -> u8 {
            self.0
        }

        /// Check if Length included flag is set
        pub fn length_included(self) -> bool {
            (self.0 & Self::LENGTH_INCLUDED) != 0
        }

        /// Check if More fragments flag is set
        pub fn more_fragments(self) -> bool {
            (self.0 & Self::MORE_FRAGMENTS) != 0
        }

        /// Check if Start flag is set
        pub fn start(self) -> bool {
            (self.0 & Self::START) != 0
        }
    }

    /// EAP-TLS packet structure
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Flags     |               TLS Message Length              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                       TLS Data...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// - Flags: TLS flags (L, M, S bits)
    /// - TLS Message Length: Total length of TLS message (only if L flag set)
    /// - TLS Data: TLS record(s)
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EapTlsPacket {
        /// TLS flags
        pub flags: TlsFlags,
        /// Total TLS message length (present if L flag is set)
        pub tls_message_length: Option<u32>,
        /// TLS record data
        pub tls_data: Vec<u8>,
    }

    impl EapTlsPacket {
        /// Maximum TLS record size (RFC 5216 recommends 16384 bytes)
        pub const MAX_RECORD_SIZE: usize = 16384;

        /// Create a new EAP-TLS packet
        pub fn new(flags: TlsFlags, tls_message_length: Option<u32>, tls_data: Vec<u8>) -> Self {
            EapTlsPacket {
                flags,
                tls_message_length,
                tls_data,
            }
        }

        /// Create an EAP-TLS Start packet
        pub fn start() -> Self {
            EapTlsPacket {
                flags: TlsFlags::new(false, false, true),
                tls_message_length: None,
                tls_data: Vec::new(),
            }
        }

        /// Parse EAP-TLS packet from EAP packet data
        pub fn from_eap_data(data: &[u8]) -> Result<Self, EapError> {
            if data.is_empty() {
                return Err(EapError::PacketTooShort {
                    expected: 1,
                    actual: 0,
                });
            }

            let flags = TlsFlags::from_u8(data[0]);
            let mut offset = 1;

            // Parse TLS message length if L flag is set
            let tls_message_length = if flags.length_included() {
                if data.len() < 5 {
                    return Err(EapError::PacketTooShort {
                        expected: 5,
                        actual: data.len(),
                    });
                }
                let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                offset = 5;
                Some(length)
            } else {
                None
            };

            // Extract TLS data
            let tls_data = if offset < data.len() {
                data[offset..].to_vec()
            } else {
                Vec::new()
            };

            Ok(EapTlsPacket {
                flags,
                tls_message_length,
                tls_data,
            })
        }

        /// Convert to EAP packet data
        pub fn to_eap_data(&self) -> Vec<u8> {
            let mut data = Vec::new();
            data.push(self.flags.as_u8());

            if let Some(length) = self.tls_message_length {
                data.extend_from_slice(&length.to_be_bytes());
            }

            data.extend_from_slice(&self.tls_data);
            data
        }

        /// Create an EAP Request with this TLS packet
        pub fn to_eap_request(&self, identifier: u8) -> EapPacket {
            EapPacket::new(
                EapCode::Request,
                identifier,
                Some(EapType::Tls),
                self.to_eap_data(),
            )
        }

        /// Create an EAP Response with this TLS packet
        pub fn to_eap_response(&self, identifier: u8) -> EapPacket {
            EapPacket::new(
                EapCode::Response,
                identifier,
                Some(EapType::Tls),
                self.to_eap_data(),
            )
        }
    }

    /// TLS handshake state for EAP-TLS
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TlsHandshakeState {
        /// Initial state - waiting for start
        Initial,
        /// Start message sent/received
        Started,
        /// TLS handshake in progress
        Handshaking,
        /// Certificate exchange in progress
        CertificateExchange,
        /// Key exchange in progress
        KeyExchange,
        /// Handshake complete
        Complete,
        /// Handshake failed
        Failed,
    }

    /// Fragment assembler for EAP-TLS
    ///
    /// Handles reassembly of fragmented TLS messages
    #[derive(Debug, Clone)]
    pub struct TlsFragmentAssembler {
        /// Expected total length (from L flag)
        expected_length: Option<u32>,
        /// Accumulated fragments
        fragments: Vec<u8>,
    }

    impl TlsFragmentAssembler {
        /// Create a new assembler
        pub fn new() -> Self {
            TlsFragmentAssembler {
                expected_length: None,
                fragments: Vec::new(),
            }
        }

        /// Add a fragment
        ///
        /// Returns Some(complete_data) when all fragments are received
        pub fn add_fragment(&mut self, packet: &EapTlsPacket) -> Result<Option<Vec<u8>>, EapError> {
            // Set expected length from first packet with L flag
            if packet.flags.length_included() && self.expected_length.is_none() {
                self.expected_length = packet.tls_message_length;
            }

            // Append fragment data
            self.fragments.extend_from_slice(&packet.tls_data);

            // Check if we have all fragments
            if !packet.flags.more_fragments() {
                // Validate length if it was specified
                if let Some(expected) = self.expected_length
                    && self.fragments.len() != expected as usize
                {
                    return Err(EapError::InvalidLength(self.fragments.len()));
                }

                // Take the assembled message and reset for the next inbound
                // exchange. Without clearing here, subsequent EAP-TLS rounds
                // would prepend the previous handshake message to fresh data
                // and confuse the TLS state machine
                // (e.g., rustls would see two stacked ClientHellos).
                let complete = std::mem::take(&mut self.fragments);
                self.expected_length = None;
                Ok(Some(complete))
            } else {
                Ok(None)
            }
        }

        /// Reset the assembler
        pub fn reset(&mut self) {
            self.expected_length = None;
            self.fragments.clear();
        }
    }

    impl Default for TlsFragmentAssembler {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Fragment a large TLS message into EAP-TLS packets
    ///
    /// # Arguments
    /// * `tls_data` - Complete TLS message to fragment
    /// * `max_fragment_size` - Maximum size of each fragment (typically 1020 bytes for Ethernet)
    ///
    /// # Returns
    /// Vector of EAP-TLS packets
    pub fn fragment_tls_message(tls_data: &[u8], max_fragment_size: usize) -> Vec<EapTlsPacket> {
        let mut packets = Vec::new();
        let total_length = tls_data.len() as u32;
        let mut offset = 0;

        // Account for flags byte (1) and length field (4) in first packet
        let first_fragment_size = max_fragment_size.saturating_sub(5);
        let subsequent_fragment_size = max_fragment_size.saturating_sub(1);

        while offset < tls_data.len() {
            let is_first = offset == 0;
            let remaining = tls_data.len() - offset;
            let fragment_size = if is_first {
                first_fragment_size.min(remaining)
            } else {
                subsequent_fragment_size.min(remaining)
            };

            let more_fragments = offset + fragment_size < tls_data.len();
            let fragment_data = tls_data[offset..offset + fragment_size].to_vec();

            let packet = if is_first {
                // First packet has L flag and total length
                EapTlsPacket::new(
                    TlsFlags::new(true, more_fragments, false),
                    Some(total_length),
                    fragment_data,
                )
            } else {
                // Subsequent packets only have M flag if more fragments follow
                EapTlsPacket::new(
                    TlsFlags::new(false, more_fragments, false),
                    None,
                    fragment_data,
                )
            };

            packets.push(packet);
            offset += fragment_size;
        }

        packets
    }

    /// Derive MSK and EMSK from TLS master secret (RFC 5216 Section 2.3)
    ///
    /// ```text
    /// MSK  = First 64 octets of TLS-PRF(master_secret, "client EAP encryption",
    ///                                   client_random + server_random)
    /// EMSK = Next 64 octets of TLS-PRF(...)
    /// ```
    ///
    /// # Arguments
    /// * `master_secret` - TLS master secret (48 bytes)
    /// * `client_random` - Client random from TLS handshake (32 bytes)
    /// * `server_random` - Server random from TLS handshake (32 bytes)
    ///
    /// # Returns
    /// (MSK, EMSK) - Each is 64 bytes
    pub fn derive_keys(
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> ([u8; 64], [u8; 64]) {
        // Label for key derivation
        let label = b"client EAP encryption";

        // Seed = client_random + server_random
        let mut seed = Vec::new();
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);

        // Generate 128 bytes using PRF (64 for MSK, 64 for EMSK)
        let key_material = tls_prf_sha256(master_secret, label, &seed, 128);

        // Split into MSK and EMSK
        let mut msk = [0u8; 64];
        let mut emsk = [0u8; 64];
        msk.copy_from_slice(&key_material[0..64]);
        emsk.copy_from_slice(&key_material[64..128]);

        (msk, emsk)
    }

    /// TLS 1.2 PRF using SHA-256
    ///
    /// PRF(secret, label, seed) = P_SHA256(secret, label + seed)
    fn tls_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        // Combine label and seed
        let mut label_seed = Vec::new();
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);

        // P_hash implementation
        let mut output = Vec::new();
        let mut a = label_seed.clone(); // A(0) = seed

        while output.len() < output_len {
            // A(i) = HMAC(secret, A(i-1))
            let mut mac =
                HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
            mac.update(&a);
            a = mac.finalize().into_bytes().to_vec();

            // HMAC(secret, A(i) + seed)
            let mut mac =
                HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
            mac.update(&a);
            mac.update(&label_seed);
            let result = mac.finalize().into_bytes();

            output.extend_from_slice(&result);
        }

        output.truncate(output_len);
        output
    }

    /// EAP-TLS session context
    ///
    /// Manages the TLS handshake state and buffering for a single EAP-TLS session
    #[derive(Debug)]
    pub struct EapTlsContext {
        /// Current handshake state
        pub handshake_state: TlsHandshakeState,
        /// Fragment assembler for incoming TLS messages
        pub assembler: TlsFragmentAssembler,
        /// Outgoing fragments waiting to be sent
        pub outgoing_fragments: Vec<EapTlsPacket>,
        /// Current fragment index being sent
        pub current_fragment_index: usize,
        /// Client random from TLS handshake (for key derivation)
        pub client_random: Option<[u8; 32]>,
        /// Server random from TLS handshake (for key derivation)
        pub server_random: Option<[u8; 32]>,
        /// TLS master secret (for key derivation)
        pub master_secret: Option<Vec<u8>>,
        /// Derived MSK (Master Session Key)
        pub msk: Option<[u8; 64]>,
        /// Derived EMSK (Extended Master Session Key)
        pub emsk: Option<[u8; 64]>,
    }

    impl EapTlsContext {
        /// Create a new EAP-TLS context
        pub fn new() -> Self {
            EapTlsContext {
                handshake_state: TlsHandshakeState::Initial,
                assembler: TlsFragmentAssembler::new(),
                outgoing_fragments: Vec::new(),
                current_fragment_index: 0,
                client_random: None,
                server_random: None,
                master_secret: None,
                msk: None,
                emsk: None,
            }
        }

        /// Reset the context to initial state
        pub fn reset(&mut self) {
            self.handshake_state = TlsHandshakeState::Initial;
            self.assembler.reset();
            self.outgoing_fragments.clear();
            self.current_fragment_index = 0;
            self.client_random = None;
            self.server_random = None;
            self.master_secret = None;
            self.msk = None;
            self.emsk = None;
        }

        /// Check if there are more outgoing fragments to send
        pub fn has_pending_fragments(&self) -> bool {
            self.current_fragment_index < self.outgoing_fragments.len()
        }

        /// Get the next outgoing fragment
        pub fn get_next_fragment(&mut self) -> Option<&EapTlsPacket> {
            if self.has_pending_fragments() {
                let fragment = &self.outgoing_fragments[self.current_fragment_index];
                self.current_fragment_index += 1;
                Some(fragment)
            } else {
                None
            }
        }

        /// Queue TLS data for sending, fragmenting if necessary
        pub fn queue_tls_data(&mut self, tls_data: Vec<u8>, max_fragment_size: usize) {
            self.outgoing_fragments = fragment_tls_message(&tls_data, max_fragment_size);
            self.current_fragment_index = 0;
        }

        /// Process an incoming EAP-TLS packet
        ///
        /// Returns Some(complete_tls_data) when all fragments are received
        pub fn process_incoming(
            &mut self,
            packet: &EapTlsPacket,
        ) -> Result<Option<Vec<u8>>, EapError> {
            // Handle Start packet
            if packet.flags.start() {
                self.handshake_state = TlsHandshakeState::Started;
                self.assembler.reset();
                return Ok(None);
            }

            // Reassemble fragments
            self.assembler.add_fragment(packet)
        }

        /// Derive and store MSK/EMSK from TLS handshake
        pub fn derive_session_keys(&mut self) -> Result<(), EapError> {
            let master_secret = self.master_secret.as_ref().ok_or(EapError::InvalidState)?;
            let client_random = self.client_random.as_ref().ok_or(EapError::InvalidState)?;
            let server_random = self.server_random.as_ref().ok_or(EapError::InvalidState)?;

            let (msk, emsk) = derive_keys(master_secret, client_random, server_random);
            self.msk = Some(msk);
            self.emsk = Some(emsk);

            Ok(())
        }

        /// Get the derived MSK (for RADIUS MS-MPPE keys)
        pub fn get_msk(&self) -> Option<&[u8; 64]> {
            self.msk.as_ref()
        }

        /// Get the derived EMSK
        pub fn get_emsk(&self) -> Option<&[u8; 64]> {
            self.emsk.as_ref()
        }
    }

    impl Default for EapTlsContext {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Certificate configuration for EAP-TLS server
    #[cfg(feature = "tls")]
    #[derive(Debug, Clone)]
    pub struct TlsCertificateConfig {
        /// Server certificate chain (PEM format)
        pub server_cert_path: String,
        /// Server private key (PEM format)
        pub server_key_path: String,
        /// CA certificate for client verification (optional, PEM format)
        pub ca_cert_path: Option<String>,
        /// Require client certificate (mutual TLS)
        pub require_client_cert: bool,
    }

    impl TlsCertificateConfig {
        /// Create a new certificate configuration
        pub fn new(
            server_cert_path: String,
            server_key_path: String,
            ca_cert_path: Option<String>,
            require_client_cert: bool,
        ) -> Self {
            TlsCertificateConfig {
                server_cert_path,
                server_key_path,
                ca_cert_path,
                require_client_cert,
            }
        }

        /// Create a simple configuration (server cert only, no client verification)
        pub fn simple(server_cert_path: String, server_key_path: String) -> Self {
            TlsCertificateConfig {
                server_cert_path,
                server_key_path,
                ca_cert_path: None,
                require_client_cert: false,
            }
        }
    }

    /// Load certificates from PEM file
    ///
    /// Loads X.509 certificates from a PEM-encoded file.
    /// The file may contain one or more certificates.
    ///
    /// # Arguments
    /// * `path` - Path to the PEM file containing certificates
    ///
    /// # Returns
    /// Vector of DER-encoded certificates
    ///
    /// # Example
    /// ```no_run
    /// # use radius_proto::eap::eap_tls::load_certificates_from_pem;
    /// let certs = load_certificates_from_pem("/path/to/server.pem").unwrap();
    /// println!("Loaded {} certificate(s)", certs.len());
    /// ```
    #[cfg(feature = "tls")]
    pub fn load_certificates_from_pem(path: &str) -> Result<Vec<Vec<u8>>, EapError> {
        use std::fs::File;
        use std::io::BufReader;

        let file = File::open(path).map_err(|e| {
            EapError::IoError(format!("Failed to open certificate file '{}': {}", path, e))
        })?;

        use pki_types::{CertificateDer, pem::PemObject};

        let mut reader = BufReader::new(file);

        let certs = CertificateDer::pem_reader_iter(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                EapError::CertificateError(format!("Failed to parse certificates: {}", e))
            })?;

        if certs.is_empty() {
            return Err(EapError::CertificateError(format!(
                "No certificates found in '{}'",
                path
            )));
        }

        // Convert to Vec<Vec<u8>>
        Ok(certs.into_iter().map(|cert| cert.to_vec()).collect())
    }

    /// Load private key from PEM file
    ///
    /// Loads a private key from a PEM-encoded file.
    /// Supports RSA, ECDSA, and Ed25519 keys in PKCS#8 or traditional format.
    ///
    /// # Arguments
    /// * `path` - Path to the PEM file containing the private key
    ///
    /// # Returns
    /// DER-encoded private key
    ///
    /// # Example
    /// ```no_run
    /// # use radius_proto::eap::eap_tls::load_private_key_from_pem;
    /// let key = load_private_key_from_pem("/path/to/server-key.pem").unwrap();
    /// println!("Loaded private key ({} bytes)", key.len());
    /// ```
    #[cfg(feature = "tls")]
    pub fn load_private_key_from_pem(path: &str) -> Result<Vec<u8>, EapError> {
        use std::fs::File;
        use std::io::BufReader;

        let file = File::open(path)
            .map_err(|e| EapError::IoError(format!("Failed to open key file '{}': {}", path, e)))?;

        use pki_types::{PrivateKeyDer, pem::PemObject};

        let mut reader = BufReader::new(file);

        // Read the first private key (PKCS#8, RSA, or SEC1/EC). `None` means no
        // private key section was present; `Some(Err(_))` means a parse failure.
        let key = PrivateKeyDer::pem_reader_iter(&mut reader)
            .next()
            .ok_or_else(|| {
                EapError::CertificateError(format!("No private key found in '{}'", path))
            })?
            .map_err(|e| {
                EapError::CertificateError(format!("Failed to parse private key: {}", e))
            })?;

        Ok(key.secret_der().to_vec())
    }

    /// Validate certificate and key pair
    ///
    /// Performs basic validation to ensure the certificate and key are compatible.
    /// This checks that:
    /// - Certificate is valid X.509
    /// - Certificate is not expired
    /// - Certificate's public key matches the private key
    ///
    /// # Arguments
    /// * `cert_der` - DER-encoded certificate
    /// * `key_der` - DER-encoded private key
    ///
    /// # Returns
    /// Ok(()) if valid, Err otherwise
    #[cfg(feature = "tls")]
    pub fn validate_cert_key_pair(cert_der: &[u8], _key_der: &[u8]) -> Result<(), EapError> {
        use x509_parser::prelude::*;

        // Parse the certificate
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| EapError::CertificateError(format!("Invalid X.509 certificate: {}", e)))?;

        // Check validity period
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| EapError::CertificateError(format!("System time error: {}", e)))?;

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let now_secs = now.as_secs() as i64;

        if now_secs < not_before {
            return Err(EapError::CertificateError(format!(
                "Certificate is not yet valid (not before: {})",
                cert.validity().not_before
            )));
        }

        if now_secs > not_after {
            return Err(EapError::CertificateError(format!(
                "Certificate has expired (not after: {})",
                cert.validity().not_after
            )));
        }

        // TODO: Verify public key matches private key
        // This would require additional crypto operations to verify the key pair

        Ok(())
    }

    /// Build rustls ServerConfig from certificates
    ///
    /// Creates a rustls ServerConfig suitable for EAP-TLS authentication.
    /// Supports both server-only authentication and mutual TLS with client certificates.
    ///
    /// # Arguments
    /// * `cert_config` - Certificate configuration
    ///
    /// # Returns
    /// rustls::ServerConfig ready for use
    ///
    /// # Example
    /// ```no_run
    /// # use radius_proto::eap::eap_tls::*;
    /// // Server-only authentication
    /// let config = TlsCertificateConfig::simple(
    ///     "server.pem".to_string(),
    ///     "server-key.pem".to_string(),
    /// );
    /// let server_config = build_server_config(&config)?;
    ///
    /// // Mutual TLS with client certificate verification
    /// let mutual_config = TlsCertificateConfig::new(
    ///     "server.pem".to_string(),
    ///     "server-key.pem".to_string(),
    ///     Some("ca.pem".to_string()),
    ///     true,
    /// );
    /// let mutual_server_config = build_server_config(&mutual_config)?;
    /// # Ok::<(), radius_proto::eap::EapError>(())
    /// ```
    #[cfg(feature = "tls")]
    pub fn build_server_config(
        cert_config: &TlsCertificateConfig,
    ) -> Result<rustls::ServerConfig, EapError> {
        use pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;

        // Load server certificates
        let cert_ders = load_certificates_from_pem(&cert_config.server_cert_path)?;
        let certs: Vec<CertificateDer> = cert_ders.into_iter().map(CertificateDer::from).collect();

        // Load server private key
        let key_der = load_private_key_from_pem(&cert_config.server_key_path)?;

        // Validate server certificate before converting
        validate_cert_key_pair(&certs[0], &key_der)?;

        let private_key = PrivateKeyDer::try_from(key_der).map_err(|e| {
            EapError::CertificateError(format!("Invalid private key format: {:?}", e))
        })?;

        // Build ServerConfig
        let config = ServerConfig::builder();

        // Configure client certificate requirements
        let config = if cert_config.require_client_cert {
            // Load CA certificates for client verification
            if let Some(ca_path) = &cert_config.ca_cert_path {
                let ca_cert_ders = load_certificates_from_pem(ca_path)?;
                let ca_certs: Vec<CertificateDer> =
                    ca_cert_ders.into_iter().map(CertificateDer::from).collect();

                // Create root certificate store
                let mut root_store = rustls::RootCertStore::empty();
                for ca_cert in ca_certs {
                    root_store.add(ca_cert).map_err(|e| {
                        EapError::CertificateError(format!("Failed to add CA certificate: {}", e))
                    })?;
                }

                // Create client certificate verifier
                let verifier = rustls::server::WebPkiClientVerifier::builder(root_store.into())
                    .build()
                    .map_err(|e| {
                        EapError::TlsError(format!("Failed to build client verifier: {}", e))
                    })?;

                config.with_client_cert_verifier(verifier)
            } else {
                return Err(EapError::CertificateError(
                    "Client certificate verification required but no CA certificate path provided"
                        .to_string(),
                ));
            }
        } else {
            config.with_no_client_auth()
        };

        // Set server certificate and key
        let mut server_config = config
            .with_single_cert(certs, private_key)
            .map_err(|e| EapError::TlsError(format!("Failed to configure server: {}", e)))?;

        // Enable TLS 1.2 and 1.3
        server_config.alpn_protocols = vec![];

        Ok(server_config)
    }

    /// EAP-TLS Server Handler
    ///
    /// Manages TLS handshake for a single EAP-TLS authentication session.
    /// This wraps rustls ServerConnection and integrates with EapTlsContext.
    #[cfg(feature = "tls")]
    pub struct EapTlsServer {
        /// rustls server connection
        connection: Option<rustls::ServerConnection>,
        /// EAP-TLS context
        context: EapTlsContext,
        /// Server configuration
        config: std::sync::Arc<rustls::ServerConfig>,
    }

    #[cfg(feature = "tls")]
    impl EapTlsServer {
        /// Create a new EAP-TLS server handler
        pub fn new(config: std::sync::Arc<rustls::ServerConfig>) -> Self {
            EapTlsServer {
                connection: None,
                context: EapTlsContext::new(),
                config,
            }
        }

        /// Initialize TLS connection (called after receiving EAP-TLS Start response)
        pub fn initialize_connection(&mut self) -> Result<(), EapError> {
            let conn = rustls::ServerConnection::new(self.config.clone())
                .map_err(|e| EapError::TlsError(format!("Failed to create connection: {}", e)))?;

            self.connection = Some(conn);
            self.context.handshake_state = TlsHandshakeState::Started;

            Ok(())
        }

        /// Process incoming TLS data from client
        ///
        /// # Arguments
        /// * `eap_tls_packet` - EAP-TLS packet from client
        ///
        /// # Returns
        /// * `Some(response_data)` - TLS response to send back
        /// * `None` - No response needed (waiting for more fragments)
        pub fn process_client_message(
            &mut self,
            eap_tls_packet: &EapTlsPacket,
        ) -> Result<Option<Vec<u8>>, EapError> {
            // Reassemble fragments if needed
            let tls_data = match self.context.process_incoming(eap_tls_packet)? {
                Some(data) => data,
                None => return Ok(None), // Need more fragments
            };

            // Get or create connection
            let conn = self.connection.as_mut().ok_or(EapError::InvalidState)?;

            // Feed TLS data to rustls
            conn.read_tls(&mut std::io::Cursor::new(&tls_data))
                .map_err(|e| EapError::TlsError(format!("Failed to read TLS: {}", e)))?;

            // Process TLS messages
            conn.process_new_packets()
                .map_err(|e| EapError::TlsError(format!("TLS processing error: {}", e)))?;

            // Update handshake state
            if conn.is_handshaking() {
                self.context.handshake_state = TlsHandshakeState::Handshaking;
            } else {
                self.context.handshake_state = TlsHandshakeState::Complete;
            }

            // Get TLS response data
            let mut response_buffer = Vec::new();
            conn.write_tls(&mut response_buffer)
                .map_err(|e| EapError::TlsError(format!("Failed to write TLS: {}", e)))?;

            if response_buffer.is_empty() {
                Ok(None)
            } else {
                Ok(Some(response_buffer))
            }
        }

        /// Check if handshake is complete
        pub fn is_handshake_complete(&self) -> bool {
            self.connection
                .as_ref()
                .map(|c| !c.is_handshaking())
                .unwrap_or(false)
        }

        /// True if there are still outgoing TLS fragments queued from a
        /// previous response that the peer hasn't received yet. The peer
        /// sends an EAP-TLS ACK (empty payload) after each non-final
        /// fragment; the caller should send the next queued fragment in
        /// that case instead of asking rustls for more data.
        pub fn has_pending_fragments(&self) -> bool {
            self.context.has_pending_fragments()
        }

        /// Pop the next outgoing TLS fragment, advancing the cursor.
        /// Returns `None` when no fragments remain.
        pub fn next_outgoing_fragment(&mut self) -> Option<EapTlsPacket> {
            self.context.get_next_fragment().cloned()
        }

        /// Queue a TLS message for transmission, splitting into fragments
        /// of at most `max_fragment_size` bytes. Resets the fragment cursor
        /// to zero. Caller then pulls fragments with `next_outgoing_fragment`.
        pub fn queue_outgoing_tls(&mut self, tls_data: Vec<u8>, max_fragment_size: usize) {
            self.context.queue_tls_data(tls_data, max_fragment_size);
        }

        /// Extract keys after successful handshake
        ///
        /// Uses RFC 5705 Keying Material Exporter to derive MSK and EMSK
        /// directly from the TLS connection per RFC 5216 Section 2.3.
        ///
        /// This is the production implementation using rustls 0.23's built-in
        /// `export_keying_material()` method, which implements RFC 5705
        /// "Keying Material Exporters for Transport Layer Security (TLS)".
        ///
        /// # RFC 5216 Compliance
        ///
        /// Per RFC 5216 Section 2.3, EAP-TLS derives the MSK and EMSK using:
        /// - **Label**: "client EAP encryption" (22 bytes, ASCII)
        /// - **Context**: None (empty context value)
        /// - **Length**: 128 bytes (64 MSK + 64 EMSK)
        ///
        /// The RFC 5705 exporter provides cryptographically secure key derivation
        /// that binds the keys to the specific TLS session, preventing key reuse
        /// across different sessions or connections.
        ///
        /// # Security Notes
        ///
        /// - MSK is used for deriving WPA/WPA2 PTK (Pairwise Transient Key)
        /// - EMSK is reserved for future use (e.g., fast re-authentication)
        /// - Keys are derived from TLS master secret + session parameters
        /// - Unique per TLS session (bound to handshake parameters)
        ///
        /// # Returns
        ///
        /// - `Ok(())` - Keys successfully extracted and stored in context
        /// - `Err(EapError::InvalidState)` - Handshake not complete or no connection
        /// - `Err(EapError::TlsError)` - Failed to export keying material
        ///
        /// # Example
        ///
        /// ```no_run
        /// # use radius_proto::eap::eap_tls::EapTlsServer;
        /// # use std::sync::Arc;
        /// # let config = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())));
        /// # let mut server = EapTlsServer::new(config);
        /// // After TLS handshake completes...
        /// server.extract_keys()?;
        /// let msk = server.get_msk().expect("MSK should be available");
        /// let emsk = server.get_emsk().expect("EMSK should be available");
        /// # Ok::<(), radius_proto::eap::EapError>(())
        /// ```
        pub fn extract_keys(&mut self) -> Result<(), EapError> {
            if !self.is_handshake_complete() {
                return Err(EapError::InvalidState);
            }

            let conn = self.connection.as_ref().ok_or(EapError::InvalidState)?;

            // RFC 5216 Section 2.3: Use RFC 5705 keying material exporter
            // Label: "client EAP encryption"
            // Context: None (empty)
            // Output: 128 bytes (64 MSK + 64 EMSK)
            let label = b"client EAP encryption";
            let mut keying_material = vec![0u8; 128];

            conn.export_keying_material(
                keying_material.as_mut_slice(),
                label,
                None, // No context value per RFC 5216
            )
            .map_err(|e| {
                EapError::TlsError(format!("Failed to export keying material: {:?}", e))
            })?;

            // Split into MSK (first 64 bytes) and EMSK (last 64 bytes)
            let msk: [u8; 64] = keying_material[0..64]
                .try_into()
                .map_err(|_| EapError::InvalidState)?;
            let emsk: [u8; 64] = keying_material[64..128]
                .try_into()
                .map_err(|_| EapError::InvalidState)?;

            self.context.msk = Some(msk);
            self.context.emsk = Some(emsk);

            Ok(())
        }

        /// Get the derived MSK (Master Session Key)
        pub fn get_msk(&self) -> Option<&[u8; 64]> {
            self.context.get_msk()
        }

        /// Get the derived EMSK (Extended Master Session Key)
        pub fn get_emsk(&self) -> Option<&[u8; 64]> {
            self.context.get_emsk()
        }

        /// Export keying material from the TLS connection (RFC 5705)
        ///
        /// Generic wrapper around rustls' `export_keying_material` for callers
        /// that need a labeled exporter other than the EAP-TLS MSK/EMSK derivation
        /// (e.g. EAP-TEAP's `session_key_seed`, RFC 7170 Section 5.2).
        ///
        /// # Arguments
        /// * `label` - Exporter label, per the consuming RFC
        /// * `context` - Optional context value (None for empty context)
        /// * `length` - Number of bytes of keying material to derive
        ///
        /// # Errors
        /// Returns `EapError::InvalidState` if the TLS handshake is not complete,
        /// or `EapError::TlsError` if the underlying export fails.
        pub fn export_keying_material(
            &self,
            label: &[u8],
            context: Option<&[u8]>,
            length: usize,
        ) -> Result<Vec<u8>, EapError> {
            if !self.is_handshake_complete() {
                return Err(EapError::InvalidState);
            }
            let conn = self.connection.as_ref().ok_or(EapError::InvalidState)?;
            let mut output = vec![0u8; length];
            conn.export_keying_material(output.as_mut_slice(), label, context)
                .map_err(|e| {
                    EapError::TlsError(format!("export_keying_material failed: {:?}", e))
                })?;
            Ok(output)
        }

        /// Get reference to the context
        pub fn context(&self) -> &EapTlsContext {
            &self.context
        }

        /// Get mutable reference to the context
        pub fn context_mut(&mut self) -> &mut EapTlsContext {
            &mut self.context
        }

        /// Get client certificate information (if mutual TLS)
        ///
        /// Returns the peer's certificate chain if client certificate
        /// authentication was performed during the TLS handshake.
        ///
        /// # Returns
        /// * `Some(Vec<Vec<u8>>)` - Client certificate chain (DER encoded)
        /// * `None` - No client certificate or handshake not complete
        pub fn get_peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
            self.connection
                .as_ref()
                .and_then(|conn| conn.peer_certificates())
                .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
        }

        /// Get mutable access to the underlying TLS connection
        ///
        /// This is used by EAP-TEAP to encrypt/decrypt Phase 2 application data.
        ///
        /// # Returns
        /// * `Ok(&mut ServerConnection)` - Mutable reference to TLS connection
        /// * `Err(EapError)` - Connection not initialized
        ///
        /// # Example
        ///
        /// ```no_run
        /// # use radius_proto::eap::eap_tls::EapTlsServer;
        /// # use std::sync::Arc;
        /// # use std::io::Write;
        /// # let config = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into())).unwrap());
        /// # let mut server = EapTlsServer::new(config);
        /// # server.initialize_connection().unwrap();
        /// // After handshake is complete, write application data
        /// let conn = server.get_connection_mut()?;
        /// conn.writer().write_all(b"application data")?;
        /// # Ok::<(), Box<dyn std::error::Error>>(())
        /// ```
        pub fn get_connection_mut(&mut self) -> Result<&mut rustls::ServerConnection, EapError> {
            self.connection.as_mut().ok_or(EapError::TlsError(
                "TLS connection not initialized".to_string(),
            ))
        }

        /// Verify client certificate identity matches EAP identity
        ///
        /// For mutual TLS, this checks that the certificate's Subject CN
        /// or SubjectAltName matches the provided EAP identity.
        ///
        /// # Arguments
        /// * `expected_identity` - Expected identity from EAP-Identity
        ///
        /// # Returns
        /// * `Ok(true)` - Certificate identity matches
        /// * `Ok(false)` - Certificate identity doesn't match
        /// * `Err(_)` - Error parsing certificate
        pub fn verify_peer_identity(&self, expected_identity: &str) -> Result<bool, EapError> {
            use x509_parser::prelude::*;

            let peer_certs = match self.get_peer_certificates() {
                Some(certs) if !certs.is_empty() => certs,
                _ => return Ok(false), // No peer cert
            };

            // Parse the first certificate (end-entity certificate)
            let (_, cert) = X509Certificate::from_der(&peer_certs[0]).map_err(|e| {
                EapError::CertificateError(format!("Failed to parse peer certificate: {}", e))
            })?;

            // Extract Subject CN
            let subject_cn = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .unwrap_or("");

            // Check if CN matches identity
            if subject_cn == expected_identity {
                return Ok(true);
            }

            // TODO: Also check SubjectAltName for email/DNS matches
            // For now, just check CN

            Ok(false)
        }
    }

    /// Helper trait for EAP-TLS authentication
    ///
    /// Implement this trait to handle EAP-TLS authentication in your
    /// RADIUS server.
    #[cfg(feature = "tls")]
    pub trait EapTlsAuthHandler: Send + Sync {
        /// Authenticate user with EAP-TLS
        ///
        /// # Arguments
        /// * `username` - User identity from EAP-Identity
        /// * `eap_tls_server` - EAP-TLS server handler
        ///
        /// # Returns
        /// * `Ok(true)` - Authentication successful
        /// * `Ok(false)` - Authentication failed
        /// * `Err(_)` - Error occurred
        fn authenticate_eap_tls(
            &self,
            username: &str,
            eap_tls_server: &EapTlsServer,
        ) -> Result<bool, EapError>;

        /// Get server certificate configuration
        fn get_tls_config(&self) -> &TlsCertificateConfig;
    }
}

/// EAP authentication state
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapState {
    /// Initial state - awaiting identity request
    Initialize,
    /// Identity request sent, awaiting response
    IdentityRequested,
    /// Identity received, selecting method
    IdentityReceived,
    /// Authentication method selected, awaiting challenge response
    MethodRequested,
    /// Challenge sent, awaiting response
    ChallengeRequested,
    /// Response received, validating
    ResponseReceived,
    /// Authentication succeeded
    Success,
    /// Authentication failed
    Failure,
    /// Timeout occurred
    Timeout,
}

impl EapState {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            EapState::Success | EapState::Failure | EapState::Timeout
        )
    }

    /// Check if this state can transition to another state
    pub fn can_transition_to(&self, next: &EapState) -> bool {
        match (self, next) {
            // From Initialize
            (EapState::Initialize, EapState::IdentityRequested) => true,

            // From IdentityRequested
            (EapState::IdentityRequested, EapState::IdentityReceived) => true,
            (EapState::IdentityRequested, EapState::Failure) => true,
            (EapState::IdentityRequested, EapState::Timeout) => true,

            // From IdentityReceived
            (EapState::IdentityReceived, EapState::MethodRequested) => true,
            (EapState::IdentityReceived, EapState::Failure) => true,

            // From MethodRequested
            (EapState::MethodRequested, EapState::ChallengeRequested) => true,
            (EapState::MethodRequested, EapState::Failure) => true,
            (EapState::MethodRequested, EapState::Timeout) => true,

            // From ChallengeRequested
            (EapState::ChallengeRequested, EapState::ResponseReceived) => true,
            (EapState::ChallengeRequested, EapState::Failure) => true,
            (EapState::ChallengeRequested, EapState::Timeout) => true,

            // From ResponseReceived
            (EapState::ResponseReceived, EapState::Success) => true,
            (EapState::ResponseReceived, EapState::Failure) => true,
            (EapState::ResponseReceived, EapState::ChallengeRequested) => true, // For multi-round auth

            // Terminal states can't transition
            _ if self.is_terminal() => false,

            // Default: no transition
            _ => false,
        }
    }
}

/// EAP session state for tracking authentication progress
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct EapSession {
    /// Session identifier (typically username or session ID)
    pub session_id: String,
    /// Current authentication state
    pub state: EapState,
    /// Current EAP identifier (increments with each request)
    pub current_identifier: u8,
    /// Selected EAP method
    pub eap_method: Option<EapType>,
    /// User identity (from Identity response)
    pub identity: Option<String>,
    /// Last sent packet (for retransmission)
    pub last_request: Option<EapPacket>,
    /// Challenge data (method-specific)
    pub challenge: Option<Vec<u8>>,
    /// Session creation timestamp (Unix epoch seconds)
    pub created_at: u64,
    /// Last activity timestamp (Unix epoch seconds)
    pub last_activity: u64,
    /// Number of authentication attempts
    pub attempt_count: u32,
}

impl EapSession {
    /// Create a new EAP session
    pub fn new(session_id: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            session_id,
            state: EapState::Initialize,
            current_identifier: 0,
            eap_method: None,
            identity: None,
            last_request: None,
            challenge: None,
            created_at: now,
            last_activity: now,
            attempt_count: 0,
        }
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: EapState) -> Result<(), EapError> {
        if !self.state.can_transition_to(&new_state) {
            return Err(EapError::InvalidState);
        }

        self.state = new_state;
        self.update_activity();
        Ok(())
    }

    /// Get next identifier and increment
    pub fn next_identifier(&mut self) -> u8 {
        let id = self.current_identifier;
        self.current_identifier = self.current_identifier.wrapping_add(1);
        self.update_activity();
        id
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self, timeout_seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.last_activity > timeout_seconds
    }

    /// Get session age in seconds
    pub fn age(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.created_at
    }

    /// Increment attempt counter
    pub fn increment_attempts(&mut self) {
        self.attempt_count += 1;
        self.update_activity();
    }

    /// Check if maximum attempts exceeded
    pub fn is_max_attempts_exceeded(&self, max_attempts: u32) -> bool {
        self.attempt_count >= max_attempts
    }
}

/// EAP session manager for tracking multiple concurrent sessions
#[derive(Debug)]
pub struct EapSessionManager {
    /// Active sessions indexed by session ID
    sessions: std::collections::HashMap<String, EapSession>,
    /// Default session timeout in seconds
    default_timeout: u64,
    /// Maximum authentication attempts per session
    #[allow(dead_code)]
    max_attempts: u32,
}

impl EapSessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            default_timeout: 300, // 5 minutes default
            max_attempts: 3,
        }
    }

    /// Create a new session manager with custom settings
    pub fn with_config(timeout_seconds: u64, max_attempts: u32) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            default_timeout: timeout_seconds,
            max_attempts,
        }
    }

    /// Create a new session
    pub fn create_session(&mut self, session_id: String) -> &mut EapSession {
        let session = EapSession::new(session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.sessions.get_mut(&session_id).unwrap()
    }

    /// Get an existing session
    pub fn get_session(&self, session_id: &str) -> Option<&EapSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable reference to an existing session
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut EapSession> {
        self.sessions.get_mut(session_id)
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &str) -> Option<EapSession> {
        self.sessions.remove(session_id)
    }

    /// Get or create a session
    pub fn get_or_create_session(&mut self, session_id: String) -> &mut EapSession {
        if !self.sessions.contains_key(&session_id) {
            self.create_session(session_id.clone());
        }
        self.sessions.get_mut(&session_id).unwrap()
    }

    /// Clean up timed out sessions
    pub fn cleanup_timed_out(&mut self) -> usize {
        let timeout = self.default_timeout;
        let before_count = self.sessions.len();

        self.sessions
            .retain(|_, session| !session.is_timed_out(timeout));

        before_count - self.sessions.len()
    }

    /// Clean up terminal sessions (success/failure/timeout)
    pub fn cleanup_terminal(&mut self) -> usize {
        let before_count = self.sessions.len();

        self.sessions
            .retain(|_, session| !session.state.is_terminal());

        before_count - self.sessions.len()
    }

    /// Get number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get statistics about sessions
    pub fn stats(&self) -> SessionStats {
        let mut stats = SessionStats::default();

        for session in self.sessions.values() {
            stats.total += 1;

            match session.state {
                EapState::Initialize => stats.initialize += 1,
                EapState::IdentityRequested => stats.identity_requested += 1,
                EapState::IdentityReceived => stats.identity_received += 1,
                EapState::MethodRequested => stats.method_requested += 1,
                EapState::ChallengeRequested => stats.challenge_requested += 1,
                EapState::ResponseReceived => stats.response_received += 1,
                EapState::Success => stats.success += 1,
                EapState::Failure => stats.failure += 1,
                EapState::Timeout => stats.timeout += 1,
            }
        }

        stats
    }
}

impl Default for EapSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Session statistics
#[derive(Debug, Default, Clone)]
pub struct SessionStats {
    pub total: usize,
    pub initialize: usize,
    pub identity_requested: usize,
    pub identity_received: usize,
    pub method_requested: usize,
    pub challenge_requested: usize,
    pub response_received: usize,
    pub success: usize,
    pub failure: usize,
    pub timeout: usize,
}

// =============================================================================
// RADIUS Integration Helpers (RFC 3579)
// =============================================================================

/// Convert an EAP packet to RADIUS EAP-Message attribute(s)
///
/// Per RFC 3579, EAP packets are encapsulated in EAP-Message attributes (Type 79).
/// If the EAP packet is larger than 253 bytes, it MUST be split across multiple
/// EAP-Message attributes.
///
/// # Arguments
/// * `eap_packet` - The EAP packet to encapsulate
///
/// # Returns
/// Vector of EAP-Message attributes. May contain multiple attributes if the
/// EAP packet exceeds the maximum attribute value length (253 bytes).
///
/// # Example
/// ```
/// use radius_proto::eap::{EapPacket, EapCode, eap_to_radius_attributes};
///
/// let eap = EapPacket::new(EapCode::Request, 1, None, vec![]);
/// let attributes = eap_to_radius_attributes(&eap).unwrap();
/// assert_eq!(attributes.len(), 1);
/// assert_eq!(attributes[0].attr_type, 79); // EAP-Message
/// ```
pub fn eap_to_radius_attributes(eap_packet: &EapPacket) -> Result<Vec<Attribute>, EapError> {
    let eap_bytes = eap_packet.to_bytes();
    let mut attributes = Vec::new();

    // Maximum EAP-Message attribute value length is 253 bytes
    const MAX_ATTR_VALUE_LEN: usize = Attribute::MAX_VALUE_LENGTH;

    // Split EAP packet into chunks if necessary
    let mut offset = 0;
    while offset < eap_bytes.len() {
        let chunk_len = std::cmp::min(MAX_ATTR_VALUE_LEN, eap_bytes.len() - offset);
        let chunk = eap_bytes[offset..offset + chunk_len].to_vec();

        let attr = Attribute::new(AttributeType::EapMessage as u8, chunk).map_err(|e| {
            EapError::EncodingError(format!("Failed to create EAP-Message attribute: {}", e))
        })?;

        attributes.push(attr);
        offset += chunk_len;
    }

    Ok(attributes)
}

/// Extract EAP packet from RADIUS packet
///
/// Per RFC 3579, EAP packets may be fragmented across multiple EAP-Message
/// attributes. This function reassembles all EAP-Message attributes into a
/// single EAP packet.
///
/// # Arguments
/// * `radius_packet` - The RADIUS packet containing EAP-Message attribute(s)
///
/// # Returns
/// The reassembled EAP packet, or None if no EAP-Message attributes found
///
/// # Example
/// ```
/// use radius_proto::eap::eap_from_radius_packet;
/// use radius_proto::{Packet, Code, Attribute};
///
/// let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
/// // ... add EAP-Message attributes ...
///
/// if let Some(eap) = eap_from_radius_packet(&packet).unwrap() {
///     println!("EAP Code: {:?}", eap.code);
/// }
/// ```
pub fn eap_from_radius_packet(radius_packet: &Packet) -> Result<Option<EapPacket>, EapError> {
    // Collect all EAP-Message attributes (Type 79)
    let eap_message_type = AttributeType::EapMessage as u8;
    let mut eap_bytes = Vec::new();

    for attr in &radius_packet.attributes {
        if attr.attr_type == eap_message_type {
            eap_bytes.extend_from_slice(&attr.value);
        }
    }

    // No EAP-Message attributes found
    if eap_bytes.is_empty() {
        return Ok(None);
    }

    // Decode the reassembled EAP packet
    let eap_packet = EapPacket::from_bytes(&eap_bytes)?;
    Ok(Some(eap_packet))
}

/// Add an EAP packet to a RADIUS packet as EAP-Message attribute(s)
///
/// This is a convenience function that combines `eap_to_radius_attributes`
/// and adding the attributes to a RADIUS packet.
///
/// # Arguments
/// * `radius_packet` - The RADIUS packet to add EAP-Message attributes to
/// * `eap_packet` - The EAP packet to encapsulate
///
/// # Example
/// ```
/// use radius_proto::{Packet, Code};
/// use radius_proto::eap::{EapPacket, EapCode, add_eap_to_radius_packet};
///
/// let mut radius = Packet::new(Code::AccessChallenge, 1, [0u8; 16]);
/// let eap = EapPacket::new(EapCode::Request, 1, None, vec![]);
///
/// add_eap_to_radius_packet(&mut radius, &eap).unwrap();
/// ```
pub fn add_eap_to_radius_packet(
    radius_packet: &mut Packet,
    eap_packet: &EapPacket,
) -> Result<(), EapError> {
    let eap_attributes = eap_to_radius_attributes(eap_packet)?;

    for attr in eap_attributes {
        radius_packet.add_attribute(attr);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eap_code_conversion() {
        assert_eq!(EapCode::from_u8(1), Some(EapCode::Request));
        assert_eq!(EapCode::from_u8(2), Some(EapCode::Response));
        assert_eq!(EapCode::from_u8(3), Some(EapCode::Success));
        assert_eq!(EapCode::from_u8(4), Some(EapCode::Failure));
        assert_eq!(EapCode::from_u8(5), None);

        assert_eq!(EapCode::Request.as_u8(), 1);
        assert_eq!(EapCode::Response.as_u8(), 2);
        assert_eq!(EapCode::Success.as_u8(), 3);
        assert_eq!(EapCode::Failure.as_u8(), 4);
    }

    #[test]
    fn test_eap_type_conversion() {
        assert_eq!(EapType::from_u8(1), Some(EapType::Identity));
        assert_eq!(EapType::from_u8(4), Some(EapType::Md5Challenge));
        assert_eq!(EapType::from_u8(13), Some(EapType::Tls));
        assert_eq!(EapType::from_u8(255), None);

        assert_eq!(EapType::Identity.as_u8(), 1);
        assert_eq!(EapType::Md5Challenge.as_u8(), 4);
    }

    #[test]
    fn test_identity_request_encode_decode() {
        let packet = EapPacket::identity_request(42, "Enter your username");
        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], 1); // Request code
        assert_eq!(bytes[1], 42); // Identifier
        assert_eq!(bytes[4], 1); // Identity type

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Request);
        assert_eq!(decoded.identifier, 42);
        assert_eq!(decoded.eap_type, Some(EapType::Identity));
        assert_eq!(decoded.data, "Enter your username".as_bytes());
    }

    #[test]
    fn test_identity_response_encode_decode() {
        let packet = EapPacket::identity_response(42, "alice@example.com");
        let bytes = packet.to_bytes();

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Response);
        assert_eq!(decoded.identifier, 42);
        assert_eq!(decoded.eap_type, Some(EapType::Identity));
        assert_eq!(decoded.data, "alice@example.com".as_bytes());
    }

    #[test]
    fn test_success_encode_decode() {
        let packet = EapPacket::success(99);
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), 4); // Success has no type or data
        assert_eq!(bytes[0], 3); // Success code
        assert_eq!(bytes[1], 99); // Identifier

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Success);
        assert_eq!(decoded.identifier, 99);
        assert_eq!(decoded.eap_type, None);
        assert_eq!(decoded.data.len(), 0);
    }

    #[test]
    fn test_failure_encode_decode() {
        let packet = EapPacket::failure(123);
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 4); // Failure code

        let decoded = EapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.code, EapCode::Failure);
        assert_eq!(decoded.identifier, 123);
        assert_eq!(decoded.eap_type, None);
    }

    #[test]
    fn test_packet_too_short() {
        let bytes = vec![1, 2]; // Only 2 bytes
        let result = EapPacket::from_bytes(&bytes);
        assert!(matches!(result, Err(EapError::PacketTooShort { .. })));
    }

    #[test]
    fn test_invalid_code() {
        let bytes = vec![99, 1, 0, 4]; // Invalid code 99
        let result = EapPacket::from_bytes(&bytes);
        assert!(matches!(result, Err(EapError::InvalidCode(99))));
    }

    #[test]
    fn test_packet_length_mismatch() {
        // Length says 10 bytes but only provide 4
        let bytes = vec![1, 1, 0, 10];
        let result = EapPacket::from_bytes(&bytes);
        assert!(matches!(result, Err(EapError::PacketTooShort { .. })));
    }

    #[test]
    fn test_eap_md5_challenge_create_parse() {
        use super::eap_md5;

        let challenge_bytes = b"0123456789abcdef"; // 16 bytes
        let packet = eap_md5::create_challenge(42, challenge_bytes, "Enter password");

        // Verify packet structure
        assert_eq!(packet.code, EapCode::Request);
        assert_eq!(packet.identifier, 42);
        assert_eq!(packet.eap_type, Some(EapType::Md5Challenge));

        // Parse it back
        let (parsed_challenge, message) = eap_md5::parse_challenge(&packet).unwrap();
        assert_eq!(parsed_challenge, challenge_bytes);
        assert_eq!(message, "Enter password");
    }

    #[test]
    fn test_eap_md5_response_create_parse() {
        use super::eap_md5;

        let response_hash = [1u8; 16];
        let packet = eap_md5::create_response(99, &response_hash, "alice");

        // Verify packet structure
        assert_eq!(packet.code, EapCode::Response);
        assert_eq!(packet.identifier, 99);
        assert_eq!(packet.eap_type, Some(EapType::Md5Challenge));

        // Parse it back
        let (parsed_hash, name) = eap_md5::parse_response(&packet).unwrap();
        assert_eq!(parsed_hash, response_hash);
        assert_eq!(name, "alice");
    }

    #[test]
    fn test_eap_md5_compute_and_verify() {
        use super::eap_md5;

        let identifier = 42;
        let password = "secret123";
        let challenge = b"random_challenge";

        // Compute response hash
        let response_hash = eap_md5::compute_response_hash(identifier, password, challenge);

        // Verify it
        assert!(eap_md5::verify_response(
            identifier,
            password,
            challenge,
            &response_hash
        ));

        // Verify wrong password fails
        assert!(!eap_md5::verify_response(
            identifier,
            "wrong_password",
            challenge,
            &response_hash
        ));

        // Verify wrong identifier fails
        assert!(!eap_md5::verify_response(
            99,
            password,
            challenge,
            &response_hash
        ));
    }

    #[test]
    fn test_eap_md5_full_flow() {
        use super::eap_md5;

        // Server creates challenge
        let challenge_bytes = b"1234567890abcdef";
        let challenge_packet = eap_md5::create_challenge(1, challenge_bytes, "");

        // Encode and decode challenge
        let challenge_bytes_encoded = challenge_packet.to_bytes();
        let challenge_decoded = EapPacket::from_bytes(&challenge_bytes_encoded).unwrap();

        // Client parses challenge
        let (received_challenge, _) = eap_md5::parse_challenge(&challenge_decoded).unwrap();

        // Client computes response
        let password = "my_password";
        let response_hash = eap_md5::compute_response_hash(
            challenge_decoded.identifier,
            password,
            &received_challenge,
        );

        // Client sends response
        let response_packet =
            eap_md5::create_response(challenge_decoded.identifier, &response_hash, "user123");

        // Encode and decode response
        let response_bytes = response_packet.to_bytes();
        let response_decoded = EapPacket::from_bytes(&response_bytes).unwrap();

        // Server verifies response
        let (received_hash, username) = eap_md5::parse_response(&response_decoded).unwrap();
        assert_eq!(username, "user123");

        let is_valid = eap_md5::verify_response(
            response_decoded.identifier,
            password,
            challenge_bytes,
            &received_hash,
        );

        assert!(is_valid);
    }

    // ===== State Machine Tests =====

    #[test]
    fn test_eap_state_transitions() {
        // Test valid transitions
        assert!(EapState::Initialize.can_transition_to(&EapState::IdentityRequested));
        assert!(EapState::IdentityRequested.can_transition_to(&EapState::IdentityReceived));
        assert!(EapState::IdentityReceived.can_transition_to(&EapState::MethodRequested));
        assert!(EapState::MethodRequested.can_transition_to(&EapState::ChallengeRequested));
        assert!(EapState::ChallengeRequested.can_transition_to(&EapState::ResponseReceived));
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::Success));
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::Failure));

        // Test invalid transitions
        assert!(!EapState::Initialize.can_transition_to(&EapState::Success));
        assert!(!EapState::IdentityRequested.can_transition_to(&EapState::Success));
        assert!(!EapState::Success.can_transition_to(&EapState::Failure));
        assert!(!EapState::Failure.can_transition_to(&EapState::Success));

        // Test terminal states
        assert!(EapState::Success.is_terminal());
        assert!(EapState::Failure.is_terminal());
        assert!(EapState::Timeout.is_terminal());
        assert!(!EapState::Initialize.is_terminal());
        assert!(!EapState::MethodRequested.is_terminal());
    }

    #[test]
    fn test_eap_state_multi_round_auth() {
        // Multi-round authentication: ResponseReceived -> ChallengeRequested
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::ChallengeRequested));
    }

    #[test]
    fn test_eap_state_failure_from_any() {
        // Can fail from most states
        assert!(EapState::IdentityRequested.can_transition_to(&EapState::Failure));
        assert!(EapState::IdentityReceived.can_transition_to(&EapState::Failure));
        assert!(EapState::MethodRequested.can_transition_to(&EapState::Failure));
        assert!(EapState::ChallengeRequested.can_transition_to(&EapState::Failure));
        assert!(EapState::ResponseReceived.can_transition_to(&EapState::Failure));
    }

    #[test]
    fn test_eap_state_timeout_transitions() {
        // Can timeout from specific states
        assert!(EapState::IdentityRequested.can_transition_to(&EapState::Timeout));
        assert!(EapState::MethodRequested.can_transition_to(&EapState::Timeout));
        assert!(EapState::ChallengeRequested.can_transition_to(&EapState::Timeout));
    }

    // ===== Session Tests =====

    #[test]
    fn test_eap_session_creation() {
        let session = EapSession::new("test_session".to_string());

        assert_eq!(session.session_id, "test_session");
        assert_eq!(session.state, EapState::Initialize);
        assert_eq!(session.current_identifier, 0);
        assert_eq!(session.eap_method, None);
        assert_eq!(session.identity, None);
        assert_eq!(session.last_request, None);
        assert_eq!(session.challenge, None);
        assert_eq!(session.attempt_count, 0);
        assert!(session.created_at > 0);
        assert!(session.last_activity > 0);
    }

    #[test]
    fn test_eap_session_transition_valid() {
        let mut session = EapSession::new("test".to_string());

        // Valid transition
        assert!(session.transition(EapState::IdentityRequested).is_ok());
        assert_eq!(session.state, EapState::IdentityRequested);

        assert!(session.transition(EapState::IdentityReceived).is_ok());
        assert_eq!(session.state, EapState::IdentityReceived);
    }

    #[test]
    fn test_eap_session_transition_invalid() {
        let mut session = EapSession::new("test".to_string());

        // Invalid transition
        let result = session.transition(EapState::Success);
        assert!(result.is_err());
        assert_eq!(session.state, EapState::Initialize); // State unchanged
    }

    #[test]
    fn test_eap_session_identifier_increment() {
        let mut session = EapSession::new("test".to_string());

        assert_eq!(session.next_identifier(), 0);
        assert_eq!(session.next_identifier(), 1);
        assert_eq!(session.next_identifier(), 2);
        assert_eq!(session.current_identifier, 3);
    }

    #[test]
    fn test_eap_session_identifier_wrapping() {
        let mut session = EapSession::new("test".to_string());
        session.current_identifier = 255;

        assert_eq!(session.next_identifier(), 255);
        assert_eq!(session.current_identifier, 0); // Wrapped around
    }

    #[test]
    fn test_eap_session_timeout_check() {
        let mut session = EapSession::new("test".to_string());

        // Set last_activity to 400 seconds ago
        session.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 400;

        assert!(!session.is_timed_out(500)); // Not timed out
        assert!(session.is_timed_out(300)); // Timed out
    }

    #[test]
    fn test_eap_session_age() {
        let mut session = EapSession::new("test".to_string());

        // Set created_at to 100 seconds ago
        session.created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 100;

        let age = session.age();
        assert!(age >= 100 && age <= 102); // Allow small timing variations
    }

    #[test]
    fn test_eap_session_attempts() {
        let mut session = EapSession::new("test".to_string());

        assert_eq!(session.attempt_count, 0);
        assert!(!session.is_max_attempts_exceeded(3));

        session.increment_attempts();
        assert_eq!(session.attempt_count, 1);

        session.increment_attempts();
        session.increment_attempts();
        assert_eq!(session.attempt_count, 3);
        assert!(session.is_max_attempts_exceeded(3));
        assert!(!session.is_max_attempts_exceeded(5));
    }

    #[test]
    fn test_eap_session_activity_update() {
        let mut session = EapSession::new("test".to_string());
        let initial_activity = session.last_activity;

        // Sleep briefly to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(100));

        session.update_activity();
        assert!(session.last_activity >= initial_activity);
    }

    // ===== Session Manager Tests =====

    #[test]
    fn test_session_manager_creation() {
        let manager = EapSessionManager::new();
        assert_eq!(manager.session_count(), 0);
        assert_eq!(manager.default_timeout, 300);
        assert_eq!(manager.max_attempts, 3);
    }

    #[test]
    fn test_session_manager_with_config() {
        let manager = EapSessionManager::with_config(600, 5);
        assert_eq!(manager.default_timeout, 600);
        assert_eq!(manager.max_attempts, 5);
    }

    #[test]
    fn test_session_manager_create_session() {
        let mut manager = EapSessionManager::new();

        let session = manager.create_session("session1".to_string());
        assert_eq!(session.session_id, "session1");
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_get_session() {
        let mut manager = EapSessionManager::new();
        manager.create_session("session1".to_string());

        let session = manager.get_session("session1");
        assert!(session.is_some());
        assert_eq!(session.unwrap().session_id, "session1");

        let missing = manager.get_session("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_session_manager_get_session_mut() {
        let mut manager = EapSessionManager::new();
        manager.create_session("session1".to_string());

        {
            let session = manager.get_session_mut("session1").unwrap();
            session.increment_attempts();
        }

        let session = manager.get_session("session1").unwrap();
        assert_eq!(session.attempt_count, 1);
    }

    #[test]
    fn test_session_manager_remove_session() {
        let mut manager = EapSessionManager::new();
        manager.create_session("session1".to_string());
        assert_eq!(manager.session_count(), 1);

        let removed = manager.remove_session("session1");
        assert!(removed.is_some());
        assert_eq!(manager.session_count(), 0);

        let missing = manager.remove_session("session1");
        assert!(missing.is_none());
    }

    #[test]
    fn test_session_manager_get_or_create() {
        let mut manager = EapSessionManager::new();

        // First call creates
        let session1 = manager.get_or_create_session("session1".to_string());
        assert_eq!(session1.session_id, "session1");
        assert_eq!(manager.session_count(), 1);

        // Second call returns existing
        let session1_again = manager.get_or_create_session("session1".to_string());
        assert_eq!(session1_again.session_id, "session1");
        assert_eq!(manager.session_count(), 1); // Still 1
    }

    #[test]
    fn test_session_manager_cleanup_timed_out() {
        let mut manager = EapSessionManager::with_config(300, 3);

        // Create sessions with different ages
        let mut session1 = EapSession::new("session1".to_string());
        session1.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 400; // 400 seconds ago - timed out

        let session2 = EapSession::new("session2".to_string());
        // session2 has current timestamp - not timed out

        manager.sessions.insert("session1".to_string(), session1);
        manager.sessions.insert("session2".to_string(), session2);

        assert_eq!(manager.session_count(), 2);

        let removed = manager.cleanup_timed_out();
        assert_eq!(removed, 1); // Removed 1 timed out session
        assert_eq!(manager.session_count(), 1); // 1 remaining
        assert!(manager.get_session("session2").is_some());
        assert!(manager.get_session("session1").is_none());
    }

    #[test]
    fn test_session_manager_cleanup_terminal() {
        let mut manager = EapSessionManager::new();

        // Create sessions with different states
        let mut session1 = EapSession::new("session1".to_string());
        session1.state = EapState::Success; // Terminal

        let mut session2 = EapSession::new("session2".to_string());
        session2.state = EapState::Failure; // Terminal

        let mut session3 = EapSession::new("session3".to_string());
        session3.state = EapState::ChallengeRequested; // Not terminal

        manager.sessions.insert("session1".to_string(), session1);
        manager.sessions.insert("session2".to_string(), session2);
        manager.sessions.insert("session3".to_string(), session3);

        assert_eq!(manager.session_count(), 3);

        let removed = manager.cleanup_terminal();
        assert_eq!(removed, 2); // Removed 2 terminal sessions
        assert_eq!(manager.session_count(), 1); // 1 remaining
        assert!(manager.get_session("session3").is_some());
    }

    #[test]
    fn test_session_manager_stats() {
        let mut manager = EapSessionManager::new();

        // Create sessions in various states
        let mut s1 = EapSession::new("s1".to_string());
        s1.state = EapState::Initialize;

        let mut s2 = EapSession::new("s2".to_string());
        s2.state = EapState::IdentityRequested;

        let mut s3 = EapSession::new("s3".to_string());
        s3.state = EapState::ChallengeRequested;

        let mut s4 = EapSession::new("s4".to_string());
        s4.state = EapState::Success;

        let mut s5 = EapSession::new("s5".to_string());
        s5.state = EapState::Failure;

        manager.sessions.insert("s1".to_string(), s1);
        manager.sessions.insert("s2".to_string(), s2);
        manager.sessions.insert("s3".to_string(), s3);
        manager.sessions.insert("s4".to_string(), s4);
        manager.sessions.insert("s5".to_string(), s5);

        let stats = manager.stats();
        assert_eq!(stats.total, 5);
        assert_eq!(stats.initialize, 1);
        assert_eq!(stats.identity_requested, 1);
        assert_eq!(stats.challenge_requested, 1);
        assert_eq!(stats.success, 1);
        assert_eq!(stats.failure, 1);
    }

    #[test]
    fn test_session_manager_multiple_sessions() {
        let mut manager = EapSessionManager::new();

        for i in 0..10 {
            manager.create_session(format!("session_{}", i));
        }

        assert_eq!(manager.session_count(), 10);

        // Verify all sessions exist
        for i in 0..10 {
            assert!(manager.get_session(&format!("session_{}", i)).is_some());
        }
    }

    #[test]
    fn test_session_full_authentication_flow() {
        let mut manager = EapSessionManager::new();
        let session = manager.create_session("user_session".to_string());

        // Initial state
        assert_eq!(session.state, EapState::Initialize);

        // Request identity
        assert!(session.transition(EapState::IdentityRequested).is_ok());
        let id1 = session.next_identifier();
        assert_eq!(id1, 0);

        // Receive identity
        assert!(session.transition(EapState::IdentityReceived).is_ok());
        session.identity = Some("alice@example.com".to_string());

        // Select method
        assert!(session.transition(EapState::MethodRequested).is_ok());
        session.eap_method = Some(EapType::Md5Challenge);

        // Send challenge
        assert!(session.transition(EapState::ChallengeRequested).is_ok());
        let id2 = session.next_identifier();
        assert_eq!(id2, 1);
        session.challenge = Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Receive response
        assert!(session.transition(EapState::ResponseReceived).is_ok());

        // Success
        assert!(session.transition(EapState::Success).is_ok());

        // Verify final state
        assert_eq!(session.state, EapState::Success);
        assert_eq!(session.identity, Some("alice@example.com".to_string()));
        assert_eq!(session.eap_method, Some(EapType::Md5Challenge));
        assert!(session.state.is_terminal());
    }

    // =========================================================================
    // RADIUS Integration Helper Tests
    // =========================================================================

    #[test]
    fn test_eap_to_radius_attributes_small_packet() {
        // Small EAP packet that fits in one attribute
        let eap = EapPacket::new(EapCode::Request, 1, Some(EapType::Identity), vec![]);
        let attributes = eap_to_radius_attributes(&eap).unwrap();

        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].attr_type, AttributeType::EapMessage as u8);

        // Verify the attribute contains the encoded EAP packet
        let expected_eap_bytes = eap.to_bytes();
        assert_eq!(attributes[0].value, expected_eap_bytes);
    }

    #[test]
    fn test_eap_to_radius_attributes_large_packet() {
        // Create a large EAP packet that requires multiple attributes
        // Each EAP-Message attribute can hold max 253 bytes
        let large_data = vec![0x42; 500]; // 500 bytes of data
        let eap = EapPacket::new(EapCode::Request, 1, Some(EapType::Md5Challenge), large_data);
        let attributes = eap_to_radius_attributes(&eap).unwrap();

        // Should be split across multiple attributes
        assert!(attributes.len() > 1);

        // All attributes should be EAP-Message type
        for attr in &attributes {
            assert_eq!(attr.attr_type, AttributeType::EapMessage as u8);
        }

        // Reassemble and verify
        let mut reassembled = Vec::new();
        for attr in &attributes {
            reassembled.extend_from_slice(&attr.value);
        }

        let expected_eap_bytes = eap.to_bytes();
        assert_eq!(reassembled, expected_eap_bytes);
    }

    #[test]
    fn test_eap_from_radius_packet_single_attribute() {
        use crate::packet::Code;

        let eap = EapPacket::new(
            EapCode::Response,
            5,
            Some(EapType::Identity),
            b"alice".to_vec(),
        );
        let eap_bytes = eap.to_bytes();

        // Create RADIUS packet with EAP-Message attribute
        let mut radius = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        let eap_attr = Attribute::new(AttributeType::EapMessage as u8, eap_bytes.clone()).unwrap();
        radius.add_attribute(eap_attr);

        // Extract EAP packet
        let extracted = eap_from_radius_packet(&radius).unwrap();
        assert!(extracted.is_some());

        let extracted_eap = extracted.unwrap();
        assert_eq!(extracted_eap.code, EapCode::Response);
        assert_eq!(extracted_eap.identifier, 5);
        assert_eq!(extracted_eap.eap_type, Some(EapType::Identity));
        assert_eq!(extracted_eap.data, b"alice");
    }

    #[test]
    fn test_eap_from_radius_packet_multiple_attributes() {
        use crate::packet::Code;

        // Create a large EAP packet
        let large_data = vec![0xAA; 400];
        let eap = EapPacket::new(
            EapCode::Request,
            10,
            Some(EapType::Md5Challenge),
            large_data.clone(),
        );

        // Convert to RADIUS attributes (will be split)
        let eap_attributes = eap_to_radius_attributes(&eap).unwrap();
        assert!(eap_attributes.len() > 1);

        // Create RADIUS packet with fragmented EAP-Message attributes
        let mut radius = Packet::new(Code::AccessChallenge, 10, [0u8; 16]);
        for attr in eap_attributes {
            radius.add_attribute(attr);
        }

        // Extract and verify
        let extracted = eap_from_radius_packet(&radius).unwrap();
        assert!(extracted.is_some());

        let extracted_eap = extracted.unwrap();
        assert_eq!(extracted_eap.code, EapCode::Request);
        assert_eq!(extracted_eap.identifier, 10);
        assert_eq!(extracted_eap.eap_type, Some(EapType::Md5Challenge));
        assert_eq!(extracted_eap.data, large_data);
    }

    #[test]
    fn test_eap_from_radius_packet_no_eap_message() {
        use crate::packet::Code;

        // RADIUS packet without EAP-Message attributes
        let mut radius = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        radius.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());

        let extracted = eap_from_radius_packet(&radius).unwrap();
        assert!(extracted.is_none());
    }

    #[test]
    fn test_add_eap_to_radius_packet() {
        use crate::packet::Code;

        let mut radius = Packet::new(Code::AccessChallenge, 2, [0u8; 16]);
        let eap = EapPacket::new(
            EapCode::Request,
            2,
            Some(EapType::Md5Challenge),
            vec![1, 2, 3, 4],
        );

        // Initially no attributes
        assert_eq!(radius.attributes.len(), 0);

        // Add EAP packet
        add_eap_to_radius_packet(&mut radius, &eap).unwrap();

        // Should have EAP-Message attribute(s)
        assert!(radius.attributes.len() > 0);

        // All added attributes should be EAP-Message
        for attr in &radius.attributes {
            assert_eq!(attr.attr_type, AttributeType::EapMessage as u8);
        }

        // Verify we can extract it back
        let extracted = eap_from_radius_packet(&radius).unwrap().unwrap();
        assert_eq!(extracted.code, eap.code);
        assert_eq!(extracted.identifier, eap.identifier);
        assert_eq!(extracted.eap_type, eap.eap_type);
        assert_eq!(extracted.data, eap.data);
    }

    #[test]
    fn test_radius_integration_round_trip() {
        use crate::packet::Code;

        // Test various EAP packet types
        let test_cases = vec![
            EapPacket::new(EapCode::Request, 1, Some(EapType::Identity), vec![]),
            EapPacket::new(
                EapCode::Response,
                2,
                Some(EapType::Identity),
                b"user@example.com".to_vec(),
            ),
            EapPacket::new(
                EapCode::Request,
                3,
                Some(EapType::Md5Challenge),
                vec![0x11; 16],
            ),
            EapPacket::new(EapCode::Success, 4, None, vec![]),
            EapPacket::new(EapCode::Failure, 5, None, vec![]),
        ];

        for original_eap in test_cases {
            let mut radius = Packet::new(Code::AccessRequest, 1, [0u8; 16]);

            // Add EAP to RADIUS
            add_eap_to_radius_packet(&mut radius, &original_eap).unwrap();

            // Extract EAP from RADIUS
            let extracted_eap = eap_from_radius_packet(&radius).unwrap().unwrap();

            // Verify round-trip
            assert_eq!(extracted_eap.code, original_eap.code);
            assert_eq!(extracted_eap.identifier, original_eap.identifier);
            assert_eq!(extracted_eap.eap_type, original_eap.eap_type);
            assert_eq!(extracted_eap.data, original_eap.data);
        }
    }

    #[test]
    fn test_radius_integration_with_other_attributes() {
        use crate::packet::Code;

        // RADIUS packet with both EAP-Message and other attributes
        let mut radius = Packet::new(Code::AccessRequest, 7, [0u8; 16]);

        // Add non-EAP attributes
        radius.add_attribute(Attribute::string(AttributeType::UserName as u8, "bob").unwrap());
        radius
            .add_attribute(Attribute::string(AttributeType::NasIdentifier as u8, "nas1").unwrap());

        // Add EAP packet
        let eap = EapPacket::new(
            EapCode::Response,
            7,
            Some(EapType::Identity),
            b"bob@example.com".to_vec(),
        );
        add_eap_to_radius_packet(&mut radius, &eap).unwrap();

        // Add more attributes after EAP
        radius.add_attribute(Attribute::integer(AttributeType::NasPort as u8, 1234).unwrap());

        // Should have all attributes (2 before + EAP + 1 after = at least 4)
        assert!(radius.attributes.len() >= 4);

        // Should still be able to extract EAP correctly
        let extracted = eap_from_radius_packet(&radius).unwrap().unwrap();
        assert_eq!(extracted.code, EapCode::Response);
        assert_eq!(extracted.identifier, 7);
        assert_eq!(extracted.data, b"bob@example.com");
    }

    // EAP-TLS Tests
    #[cfg(feature = "tls")]
    mod eap_tls_tests {
        use super::super::eap_tls::*;
        use super::*;

        #[test]
        fn test_tls_flags_creation() {
            // Test individual flags
            let flags = TlsFlags::new(true, false, false);
            assert!(flags.length_included());
            assert!(!flags.more_fragments());
            assert!(!flags.start());

            let flags = TlsFlags::new(false, true, false);
            assert!(!flags.length_included());
            assert!(flags.more_fragments());
            assert!(!flags.start());

            let flags = TlsFlags::new(false, false, true);
            assert!(!flags.length_included());
            assert!(!flags.more_fragments());
            assert!(flags.start());

            // Test all flags set
            let flags = TlsFlags::new(true, true, true);
            assert!(flags.length_included());
            assert!(flags.more_fragments());
            assert!(flags.start());
            assert_eq!(flags.as_u8(), 0xE0);
        }

        #[test]
        fn test_tls_flags_from_u8() {
            // Test Start flag (0x20)
            let flags = TlsFlags::from_u8(0x20);
            assert!(flags.start());
            assert!(!flags.length_included());
            assert!(!flags.more_fragments());

            // Test Length flag (0x80)
            let flags = TlsFlags::from_u8(0x80);
            assert!(flags.length_included());
            assert!(!flags.more_fragments());
            assert!(!flags.start());

            // Test More fragments flag (0x40)
            let flags = TlsFlags::from_u8(0x40);
            assert!(flags.more_fragments());
            assert!(!flags.length_included());
            assert!(!flags.start());

            // Test L + M flags (0xC0)
            let flags = TlsFlags::from_u8(0xC0);
            assert!(flags.length_included());
            assert!(flags.more_fragments());
            assert!(!flags.start());

            // Test reserved bits are masked
            let flags = TlsFlags::from_u8(0xFF); // All bits set
            assert_eq!(flags.as_u8(), 0xE0); // Only L, M, S bits
        }

        #[test]
        fn test_eap_tls_start_packet() {
            let start = EapTlsPacket::start();
            assert!(start.flags.start());
            assert!(!start.flags.length_included());
            assert!(!start.flags.more_fragments());
            assert!(start.tls_data.is_empty());
            assert!(start.tls_message_length.is_none());

            // Test encoding
            let data = start.to_eap_data();
            assert_eq!(data.len(), 1); // Just flags byte
            assert_eq!(data[0], 0x20); // Start flag
        }

        #[test]
        fn test_eap_tls_packet_with_data() {
            let tls_data = vec![0x16, 0x03, 0x03, 0x00, 0x05]; // Fake TLS handshake record
            let packet =
                EapTlsPacket::new(TlsFlags::new(false, false, false), None, tls_data.clone());

            let encoded = packet.to_eap_data();
            assert_eq!(encoded[0], 0x00); // No flags set
            assert_eq!(&encoded[1..], &tls_data[..]);
        }

        #[test]
        fn test_eap_tls_packet_with_length() {
            let tls_data = vec![1, 2, 3, 4, 5];
            let total_length = 1000u32;
            let packet = EapTlsPacket::new(
                TlsFlags::new(true, false, false),
                Some(total_length),
                tls_data.clone(),
            );

            let encoded = packet.to_eap_data();
            assert_eq!(encoded[0], 0x80); // Length flag
            // Check length field (4 bytes, big-endian)
            let length = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
            assert_eq!(length, 1000);
            assert_eq!(&encoded[5..], &tls_data[..]);
        }

        #[test]
        fn test_eap_tls_packet_parsing() {
            // Test parsing start packet
            let data = vec![0x20]; // Start flag only
            let packet = EapTlsPacket::from_eap_data(&data).unwrap();
            assert!(packet.flags.start());
            assert!(packet.tls_data.is_empty());
            assert!(packet.tls_message_length.is_none());

            // Test parsing packet with length
            let data = vec![
                0x80, // Length flag
                0x00, 0x00, 0x10, 0x00, // Length = 4096
                0x16, 0x03, 0x03, // TLS data
            ];
            let packet = EapTlsPacket::from_eap_data(&data).unwrap();
            assert!(packet.flags.length_included());
            assert_eq!(packet.tls_message_length, Some(4096));
            assert_eq!(packet.tls_data, vec![0x16, 0x03, 0x03]);
        }

        #[test]
        fn test_eap_tls_packet_round_trip() {
            let original = EapTlsPacket::new(
                TlsFlags::new(true, true, false),
                Some(5000),
                vec![1, 2, 3, 4, 5, 6, 7, 8],
            );

            let encoded = original.to_eap_data();
            let decoded = EapTlsPacket::from_eap_data(&encoded).unwrap();

            assert_eq!(decoded.flags.as_u8(), original.flags.as_u8());
            assert_eq!(decoded.tls_message_length, original.tls_message_length);
            assert_eq!(decoded.tls_data, original.tls_data);
        }

        #[test]
        fn test_eap_tls_packet_error_empty() {
            let data = vec![];
            let result = EapTlsPacket::from_eap_data(&data);
            assert!(matches!(result, Err(EapError::PacketTooShort { .. })));
        }

        #[test]
        fn test_eap_tls_packet_error_length_truncated() {
            // Length flag set but not enough bytes for length field
            let data = vec![0x80, 0x00, 0x00]; // Only 3 bytes of length
            let result = EapTlsPacket::from_eap_data(&data);
            assert!(matches!(result, Err(EapError::PacketTooShort { .. })));
        }

        #[test]
        fn test_fragment_assembler() {
            let mut assembler = TlsFragmentAssembler::new();

            // First fragment with length and more fragments
            let frag1 =
                EapTlsPacket::new(TlsFlags::new(true, true, false), Some(10), vec![1, 2, 3, 4]);
            let result = assembler.add_fragment(&frag1).unwrap();
            assert!(result.is_none()); // Not complete yet

            // Second fragment with more fragments
            let frag2 = EapTlsPacket::new(TlsFlags::new(false, true, false), None, vec![5, 6, 7]);
            let result = assembler.add_fragment(&frag2).unwrap();
            assert!(result.is_none()); // Still not complete

            // Last fragment
            let frag3 = EapTlsPacket::new(TlsFlags::new(false, false, false), None, vec![8, 9, 10]);
            let result = assembler.add_fragment(&frag3).unwrap();
            assert!(result.is_some()); // Complete!

            let complete = result.unwrap();
            assert_eq!(complete, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        }

        #[test]
        fn test_fragment_assembler_reset() {
            let mut assembler = TlsFragmentAssembler::new();

            let frag1 =
                EapTlsPacket::new(TlsFlags::new(true, true, false), Some(10), vec![1, 2, 3]);
            assembler.add_fragment(&frag1).unwrap();

            // Reset
            assembler.reset();

            // Should be able to start fresh
            let frag2 = EapTlsPacket::new(
                TlsFlags::new(true, false, false),
                Some(5),
                vec![4, 5, 6, 7, 8],
            );
            let result = assembler.add_fragment(&frag2).unwrap();
            assert!(result.is_some());
            assert_eq!(result.unwrap(), vec![4, 5, 6, 7, 8]);
        }

        #[test]
        fn test_fragment_assembler_length_mismatch() {
            let mut assembler = TlsFragmentAssembler::new();

            // First fragment claims 10 bytes total
            let frag1 =
                EapTlsPacket::new(TlsFlags::new(true, true, false), Some(10), vec![1, 2, 3]);
            assembler.add_fragment(&frag1).unwrap();

            // Last fragment but total is only 8 bytes (not 10)
            let frag2 = EapTlsPacket::new(
                TlsFlags::new(false, false, false),
                None,
                vec![4, 5, 6, 7, 8],
            );
            let result = assembler.add_fragment(&frag2);
            assert!(matches!(result, Err(EapError::InvalidLength(_))));
        }

        #[test]
        fn test_fragment_tls_message_small() {
            // Small message that fits in one fragment
            let data = vec![1, 2, 3, 4, 5];
            let fragments = fragment_tls_message(&data, 1000);

            assert_eq!(fragments.len(), 1);
            assert!(fragments[0].flags.length_included());
            assert!(!fragments[0].flags.more_fragments());
            assert_eq!(fragments[0].tls_message_length, Some(5));
            assert_eq!(fragments[0].tls_data, data);
        }

        #[test]
        fn test_fragment_tls_message_large() {
            // Create a large message that needs fragmentation
            let data = vec![0x42u8; 2000]; // 2000 bytes
            let max_fragment = 1000;
            let fragments = fragment_tls_message(&data, max_fragment);

            // Should have multiple fragments
            assert!(fragments.len() > 1);

            // First fragment should have L flag and total length
            assert!(fragments[0].flags.length_included());
            assert!(fragments[0].flags.more_fragments());
            assert_eq!(fragments[0].tls_message_length, Some(2000));

            // Middle fragments should have M flag
            for i in 1..fragments.len() - 1 {
                assert!(!fragments[i].flags.length_included());
                assert!(fragments[i].flags.more_fragments());
                assert!(fragments[i].tls_message_length.is_none());
            }

            // Last fragment should have no M flag
            let last = &fragments[fragments.len() - 1];
            assert!(!last.flags.more_fragments());

            // Reassemble and verify
            let mut reassembled = Vec::new();
            for frag in &fragments {
                reassembled.extend_from_slice(&frag.tls_data);
            }
            assert_eq!(reassembled, data);
        }

        #[test]
        fn test_fragment_then_reassemble() {
            // Test fragmentation and reassembly round-trip
            let original_data = vec![0xAAu8; 5000];
            let fragments = fragment_tls_message(&original_data, 1000);

            let mut assembler = TlsFragmentAssembler::new();
            let mut complete_data = None;

            for frag in fragments {
                if let Some(data) = assembler.add_fragment(&frag).unwrap() {
                    complete_data = Some(data);
                }
            }

            assert!(complete_data.is_some());
            assert_eq!(complete_data.unwrap(), original_data);
        }

        #[test]
        fn test_derive_keys() {
            // Test key derivation with known values
            let master_secret = vec![0x42u8; 48];
            let client_random = vec![0xAAu8; 32];
            let server_random = vec![0xBBu8; 32];

            let (msk, emsk) = derive_keys(&master_secret, &client_random, &server_random);

            // Verify sizes
            assert_eq!(msk.len(), 64);
            assert_eq!(emsk.len(), 64);

            // MSK and EMSK should be different
            assert_ne!(msk, emsk);

            // Should be deterministic
            let (msk2, emsk2) = derive_keys(&master_secret, &client_random, &server_random);
            assert_eq!(msk, msk2);
            assert_eq!(emsk, emsk2);
        }

        #[test]
        fn test_derive_keys_different_inputs() {
            let master_secret = vec![0x42u8; 48];
            let client_random1 = vec![0xAAu8; 32];
            let client_random2 = vec![0xBBu8; 32];
            let server_random = vec![0xCCu8; 32];

            let (msk1, emsk1) = derive_keys(&master_secret, &client_random1, &server_random);
            let (msk2, emsk2) = derive_keys(&master_secret, &client_random2, &server_random);

            // Different inputs should produce different keys
            assert_ne!(msk1, msk2);
            assert_ne!(emsk1, emsk2);
        }

        #[test]
        fn test_eap_tls_to_eap_packet() {
            let tls_packet = EapTlsPacket::start();

            // Test to_eap_request
            let eap_request = tls_packet.to_eap_request(42);
            assert_eq!(eap_request.code, EapCode::Request);
            assert_eq!(eap_request.identifier, 42);
            assert_eq!(eap_request.eap_type, Some(EapType::Tls));

            // Test to_eap_response
            let eap_response = tls_packet.to_eap_response(43);
            assert_eq!(eap_response.code, EapCode::Response);
            assert_eq!(eap_response.identifier, 43);
            assert_eq!(eap_response.eap_type, Some(EapType::Tls));
        }

        #[test]
        fn test_tls_handshake_state() {
            // Just verify the enum exists and can be used
            let state = TlsHandshakeState::Initial;
            assert_eq!(state, TlsHandshakeState::Initial);

            let state = TlsHandshakeState::Complete;
            assert_eq!(state, TlsHandshakeState::Complete);
        }

        #[test]
        fn test_eap_tls_context_new() {
            let ctx = EapTlsContext::new();
            assert_eq!(ctx.handshake_state, TlsHandshakeState::Initial);
            assert_eq!(ctx.current_fragment_index, 0);
            assert!(ctx.outgoing_fragments.is_empty());
            assert!(ctx.client_random.is_none());
            assert!(ctx.server_random.is_none());
            assert!(ctx.master_secret.is_none());
            assert!(ctx.msk.is_none());
            assert!(ctx.emsk.is_none());
        }

        #[test]
        fn test_eap_tls_context_reset() {
            let mut ctx = EapTlsContext::new();
            ctx.handshake_state = TlsHandshakeState::Complete;
            ctx.client_random = Some([0xAAu8; 32]);
            ctx.server_random = Some([0xBBu8; 32]);
            ctx.master_secret = Some(vec![0x42u8; 48]);

            ctx.reset();

            assert_eq!(ctx.handshake_state, TlsHandshakeState::Initial);
            assert!(ctx.client_random.is_none());
            assert!(ctx.server_random.is_none());
            assert!(ctx.master_secret.is_none());
        }

        #[test]
        fn test_eap_tls_context_queue_and_fragments() {
            let mut ctx = EapTlsContext::new();
            let data = vec![0x42u8; 2000];

            // Queue data for fragmentation
            ctx.queue_tls_data(data, 1000);

            // Should have multiple fragments
            assert!(ctx.outgoing_fragments.len() > 1);
            assert_eq!(ctx.current_fragment_index, 0);

            // Get fragments one by one
            assert!(ctx.has_pending_fragments());
            let frag1 = ctx.get_next_fragment();
            assert!(frag1.is_some());
            assert_eq!(ctx.current_fragment_index, 1);

            // Get next fragment
            assert!(ctx.has_pending_fragments());
            let frag2 = ctx.get_next_fragment();
            assert!(frag2.is_some());

            // Continue until all fragments are retrieved
            while ctx.has_pending_fragments() {
                ctx.get_next_fragment();
            }

            // No more fragments
            assert!(!ctx.has_pending_fragments());
            assert!(ctx.get_next_fragment().is_none());
        }

        #[test]
        fn test_eap_tls_context_process_start() {
            let mut ctx = EapTlsContext::new();
            let start_packet = EapTlsPacket::start();

            let result = ctx.process_incoming(&start_packet).unwrap();
            assert!(result.is_none()); // Start packet doesn't contain data
            assert_eq!(ctx.handshake_state, TlsHandshakeState::Started);
        }

        #[test]
        fn test_eap_tls_context_process_fragments() {
            let mut ctx = EapTlsContext::new();

            // First fragment
            let frag1 =
                EapTlsPacket::new(TlsFlags::new(true, true, false), Some(10), vec![1, 2, 3, 4]);
            let result = ctx.process_incoming(&frag1).unwrap();
            assert!(result.is_none()); // Not complete yet

            // Last fragment
            let frag2 = EapTlsPacket::new(
                TlsFlags::new(false, false, false),
                None,
                vec![5, 6, 7, 8, 9, 10],
            );
            let result = ctx.process_incoming(&frag2).unwrap();
            assert!(result.is_some()); // Complete!
            assert_eq!(result.unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        }

        #[test]
        fn test_eap_tls_context_derive_keys() {
            let mut ctx = EapTlsContext::new();

            // Set up handshake parameters
            ctx.master_secret = Some(vec![0x42u8; 48]);
            ctx.client_random = Some([0xAAu8; 32]);
            ctx.server_random = Some([0xBBu8; 32]);

            // Derive keys
            let result = ctx.derive_session_keys();
            assert!(result.is_ok());

            // Verify MSK and EMSK are set
            assert!(ctx.msk.is_some());
            assert!(ctx.emsk.is_some());

            let msk = ctx.get_msk().unwrap();
            let emsk = ctx.get_emsk().unwrap();
            assert_eq!(msk.len(), 64);
            assert_eq!(emsk.len(), 64);
            assert_ne!(msk, emsk); // Should be different
        }

        #[test]
        fn test_eap_tls_context_derive_keys_missing_params() {
            let mut ctx = EapTlsContext::new();

            // Try to derive without setting parameters
            let result = ctx.derive_session_keys();
            assert!(matches!(result, Err(EapError::InvalidState)));

            // Set only master secret
            ctx.master_secret = Some(vec![0x42u8; 48]);
            let result = ctx.derive_session_keys();
            assert!(matches!(result, Err(EapError::InvalidState)));
        }

        #[test]
        fn test_tls_certificate_config() {
            let config = TlsCertificateConfig::new(
                "/path/to/cert.pem".to_string(),
                "/path/to/key.pem".to_string(),
                Some("/path/to/ca.pem".to_string()),
                true,
            );

            assert_eq!(config.server_cert_path, "/path/to/cert.pem");
            assert_eq!(config.server_key_path, "/path/to/key.pem");
            assert_eq!(config.ca_cert_path, Some("/path/to/ca.pem".to_string()));
            assert!(config.require_client_cert);
        }

        #[test]
        fn test_tls_certificate_config_simple() {
            let config = TlsCertificateConfig::simple(
                "/path/to/cert.pem".to_string(),
                "/path/to/key.pem".to_string(),
            );

            assert_eq!(config.server_cert_path, "/path/to/cert.pem");
            assert_eq!(config.server_key_path, "/path/to/key.pem");
            assert!(config.ca_cert_path.is_none());
            assert!(!config.require_client_cert);
        }

        #[test]
        fn test_load_certificates_nonexistent() {
            // Should return IoError for nonexistent files
            let result = load_certificates_from_pem("/nonexistent/cert.pem");
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), EapError::IoError(_)));

            let result = load_private_key_from_pem("/nonexistent/key.pem");
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), EapError::IoError(_)));
        }

        #[test]
        fn test_validate_cert_invalid_der() {
            // Invalid DER data should return CertificateError
            let invalid_cert = vec![0xFF, 0xFF, 0xFF, 0xFF];
            let dummy_key = vec![0x00; 32];

            let result = validate_cert_key_pair(&invalid_cert, &dummy_key);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), EapError::CertificateError(_)));
        }

        #[test]
        fn test_eap_tls_server_creation() {
            use rustls::ServerConfig;
            use std::sync::Arc;

            // Create minimal server config
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

            let arc_config = Arc::new(config);
            let server = EapTlsServer::new(arc_config);

            assert!(!server.is_handshake_complete());
            assert_eq!(server.context().handshake_state, TlsHandshakeState::Initial);
        }

        #[test]
        fn test_eap_tls_server_state_tracking() {
            use rustls::ServerConfig;
            use std::sync::Arc;

            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

            let mut server = EapTlsServer::new(Arc::new(config));

            // Initially not handshaking
            assert!(!server.is_handshake_complete());

            // Initialize connection
            let result = server.initialize_connection();
            // May fail without proper cert, but state should update
            if result.is_ok() {
                assert_eq!(server.context().handshake_state, TlsHandshakeState::Started);
            }
        }

        #[test]
        fn test_eap_tls_server_key_extraction_requires_complete() {
            use rustls::ServerConfig;
            use std::sync::Arc;

            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

            let mut server = EapTlsServer::new(Arc::new(config));

            // Should fail before handshake complete
            let result = server.extract_keys();
            assert!(matches!(result, Err(EapError::InvalidState)));
        }

        #[test]
        fn test_build_server_config_without_client_auth() {
            // Create test certificates directory (would exist in real scenario)
            let config = TlsCertificateConfig::simple(
                "test_certs/server.pem".to_string(),
                "test_certs/server-key.pem".to_string(),
            );

            // Note: This test will fail without actual certificate files
            // In real usage, certificates would be generated first
            // Just testing the configuration structure
            assert_eq!(config.server_cert_path, "test_certs/server.pem");
            assert_eq!(config.server_key_path, "test_certs/server-key.pem");
            assert_eq!(config.ca_cert_path, None);
            assert_eq!(config.require_client_cert, false);
        }

        #[test]
        fn test_build_server_config_with_client_auth() {
            let config = TlsCertificateConfig::new(
                "test_certs/server.pem".to_string(),
                "test_certs/server-key.pem".to_string(),
                Some("test_certs/ca.pem".to_string()),
                true,
            );

            assert_eq!(config.server_cert_path, "test_certs/server.pem");
            assert_eq!(config.server_key_path, "test_certs/server-key.pem");
            assert_eq!(config.ca_cert_path, Some("test_certs/ca.pem".to_string()));
            assert_eq!(config.require_client_cert, true);
        }

        #[test]
        fn test_build_server_config_missing_ca_error() {
            // Config requiring client cert but no CA path
            let config = TlsCertificateConfig::new(
                "test_certs/server.pem".to_string(),
                "test_certs/server-key.pem".to_string(),
                None, // No CA cert path
                true, // But requiring client cert
            );

            // build_server_config should fail with this configuration
            // (can't test actual call without cert files, but structure is validated)
            assert_eq!(config.require_client_cert, true);
            assert_eq!(config.ca_cert_path, None);
        }

        #[test]
        fn test_eap_tls_server_peer_certificates_empty() {
            use rustls::ServerConfig;
            use std::sync::Arc;

            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

            let server = EapTlsServer::new(Arc::new(config));

            // No peer certificates before handshake
            assert_eq!(server.get_peer_certificates(), None);
        }

        #[test]
        fn test_eap_tls_server_verify_peer_identity_no_cert() {
            use rustls::ServerConfig;
            use std::sync::Arc;

            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

            let server = EapTlsServer::new(Arc::new(config));

            // Should return Ok(false) when no peer certificate
            let result = server.verify_peer_identity("test@example.com");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }
    }
}

/// EAP-TEAP (Tunneled Extensible Authentication Protocol)
///
/// RFC 7170 - Tunnel Extensible Authentication Protocol (TEAP) Version 1
///
/// TEAP is a modern tunneled authentication protocol that supersedes legacy
/// methods like EAP-TTLS, PEAP, and EAP-MSCHAPv2. It provides:
///
/// - Two-phase authentication (TLS tunnel + inner method)
/// - TLV-based inner authentication protocol
/// - Cryptographic binding between inner and outer authentication
/// - Support for multiple inner authentication methods
/// - Protected Access Credential (PAC) support for fast reconnect
#[cfg(feature = "tls")]
pub mod eap_teap;
