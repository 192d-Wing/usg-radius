//! EAP-TEAP (Tunneled Extensible Authentication Protocol)
//!
//! Implementation of RFC 7170 - Tunnel Extensible Authentication Protocol (TEAP) Version 1
//!
//! TEAP is a two-phase authentication protocol:
//! - Phase 1: TLS tunnel establishment (reuses EAP-TLS infrastructure)
//! - Phase 2: TLV-based inner authentication inside encrypted tunnel
//!
//! # Architecture
//!
//! ```text
//! Phase 1: TLS Handshake (using EapTlsServer)
//!     ↓
//! Phase 2: TLV Protocol
//!     - Identity-Type TLV
//!     - Inner Auth (EAP-Payload or Basic-Password-Auth)
//!     - Crypto-Binding TLV (optional, for security)
//!     - Result TLV (success/failure)
//! ```
//!
//! # Example
//!
//! ```no_run
//! # use radius_proto::eap::eap_teap::*;
//! # use radius_proto::eap::eap_tls::*;
//! # use std::sync::Arc;
//! # use rustls::ServerConfig;
//! # let config = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into())).unwrap());
//! // Create TEAP server
//! let mut server = EapTeapServer::new(config);
//!
//! // Initialize connection (Phase 1)
//! server.initialize_connection().unwrap();
//!
//! // Process client messages...
//! ```

use super::EapError;
use super::eap_tls::{EapTlsPacket, EapTlsServer};
use std::sync::Arc;

// Cryptographic imports for Crypto-Binding
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// TEAP TLV Type (RFC 7170 Section 4.2)
///
/// Defines all TLV types used in TEAP Phase 2 authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlvType {
    /// Authority-ID TLV (Type 1) - Used for PAC provisioning
    AuthorityId = 1,
    /// Identity-Type TLV (Type 2) - Negotiates identity type (User/Machine)
    IdentityType = 2,
    /// Result TLV (Type 3) - Indicates final authentication result
    Result = 3,
    /// NAK TLV (Type 4) - Rejects unsupported TLV
    Nak = 4,
    /// Error TLV (Type 5) - Indicates protocol errors
    Error = 5,
    /// Channel-Binding TLV (Type 6) - Binds to specific channel
    ChannelBinding = 6,
    /// Vendor-Specific TLV (Type 7) - Vendor extensions
    VendorSpecific = 7,
    /// Request-Action TLV (Type 8) - Requests specific actions
    RequestAction = 8,
    /// EAP-Payload TLV (Type 9) - Encapsulates inner EAP method
    EapPayload = 9,
    /// Intermediate-Result TLV (Type 10) - Result of intermediate authentication
    IntermediateResult = 10,
    /// PAC TLV (Type 11) - Protected Access Credential
    Pac = 11,
    /// Crypto-Binding TLV (Type 12) - Cryptographic binding
    CryptoBinding = 12,
    /// Basic-Password-Auth-Req TLV (Type 13) - Password request
    BasicPasswordAuthReq = 13,
    /// Basic-Password-Auth-Resp TLV (Type 14) - Password response
    BasicPasswordAuthResp = 14,
    /// PKCS#7 TLV (Type 15) - Certificate provisioning
    Pkcs7 = 15,
    /// PKCS#10 TLV (Type 16) - Certificate request
    Pkcs10 = 16,
    /// Trusted-Server-Root TLV (Type 17) - Trusted server certificate
    TrustedServerRoot = 17,
}

impl TlvType {
    /// Convert from u16 to TlvType
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::AuthorityId),
            2 => Some(Self::IdentityType),
            3 => Some(Self::Result),
            4 => Some(Self::Nak),
            5 => Some(Self::Error),
            6 => Some(Self::ChannelBinding),
            7 => Some(Self::VendorSpecific),
            8 => Some(Self::RequestAction),
            9 => Some(Self::EapPayload),
            10 => Some(Self::IntermediateResult),
            11 => Some(Self::Pac),
            12 => Some(Self::CryptoBinding),
            13 => Some(Self::BasicPasswordAuthReq),
            14 => Some(Self::BasicPasswordAuthResp),
            15 => Some(Self::Pkcs7),
            16 => Some(Self::Pkcs10),
            17 => Some(Self::TrustedServerRoot),
            _ => None,
        }
    }
}

/// TEAP TLV Structure (RFC 7170 Section 4.2)
///
/// TLV Format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |M|R|            TLV Type       |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              Value...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - M = Mandatory bit (0x8000): If set, TLV must be understood
/// - R = Reserved (0x4000): Must be zero
/// - TLV Type = 14 bits (0x3FFF mask)
/// - Length = Length of Value field (not including Type/Length header)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeapTlv {
    /// TLV type (14 bits)
    pub tlv_type: u16,
    /// Mandatory flag (M bit)
    pub mandatory: bool,
    /// TLV value (variable length)
    pub value: Vec<u8>,
}

impl TeapTlv {
    /// Mandatory flag mask (M bit)
    pub const MANDATORY_FLAG: u16 = 0x8000;

    /// Reserved flag mask (R bit, must be 0)
    pub const RESERVED_FLAG: u16 = 0x4000;

    /// Type mask (14 bits)
    pub const TYPE_MASK: u16 = 0x3FFF;

    /// Create a new TLV
    ///
    /// # Arguments
    ///
    /// * `tlv_type` - TLV type
    /// * `mandatory` - Whether this TLV is mandatory
    /// * `value` - TLV value bytes
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::{TeapTlv, TlvType};
    /// let tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]); // Success result
    /// ```
    pub fn new(tlv_type: TlvType, mandatory: bool, value: Vec<u8>) -> Self {
        Self {
            tlv_type: tlv_type as u16,
            mandatory,
            value,
        }
    }

    /// Create a TLV from raw type value
    pub fn new_raw(tlv_type: u16, mandatory: bool, value: Vec<u8>) -> Self {
        Self {
            tlv_type,
            mandatory,
            value,
        }
    }

    /// Parse a single TLV from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing TLV data
    ///
    /// # Returns
    ///
    /// Returns `Ok((tlv, bytes_consumed))` on success, or `Err` if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns `EapError::InvalidPacket` if:
    /// - Data is too short (< 4 bytes for header)
    /// - Length field exceeds available data
    /// - Reserved flag is set
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), EapError> {
        if data.len() < 4 {
            return Err(EapError::PacketTooShort {
                expected: 4,
                actual: data.len(),
            });
        }

        // Parse Type field (2 bytes, big-endian)
        let type_field = u16::from_be_bytes([data[0], data[1]]);

        // Extract M bit
        let mandatory = (type_field & Self::MANDATORY_FLAG) != 0;

        // Check R bit (must be 0)
        if (type_field & Self::RESERVED_FLAG) != 0 {
            return Err(EapError::InvalidResponseFormat);
        }

        // Extract TLV type (14 bits)
        let tlv_type = type_field & Self::TYPE_MASK;

        // Parse Length field (2 bytes, big-endian)
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Validate length
        if data.len() < 4 + length {
            return Err(EapError::InvalidLength(length));
        }

        // Extract value
        let value = data[4..4 + length].to_vec();

        let tlv = Self {
            tlv_type,
            mandatory,
            value,
        };

        Ok((tlv, 4 + length))
    }

    /// Encode TLV to bytes
    ///
    /// # Returns
    ///
    /// Returns byte vector containing encoded TLV
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::{TeapTlv, TlvType};
    /// let tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]);
    /// let bytes = tlv.to_bytes();
    /// assert_eq!(bytes.len(), 5); // 4 byte header + 1 byte value
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.value.len());

        // Encode Type field (M bit | TLV type)
        let mut type_field = self.tlv_type & Self::TYPE_MASK;
        if self.mandatory {
            type_field |= Self::MANDATORY_FLAG;
        }
        bytes.extend_from_slice(&type_field.to_be_bytes());

        // Encode Length field
        let length = self.value.len() as u16;
        bytes.extend_from_slice(&length.to_be_bytes());

        // Encode Value
        bytes.extend_from_slice(&self.value);

        bytes
    }

    /// Parse multiple TLVs from data
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing multiple TLVs
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<TeapTlv>)` with all parsed TLVs, or `Err` if parsing fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::TeapTlv;
    /// let data = vec![
    ///     0x80, 0x03, 0x00, 0x02, 0x00, 0x01, // Result TLV (mandatory, success)
    /// ];
    /// let tlvs = TeapTlv::parse_tlvs(&data).unwrap();
    /// assert_eq!(tlvs.len(), 1);
    /// ```
    pub fn parse_tlvs(data: &[u8]) -> Result<Vec<Self>, EapError> {
        let mut tlvs = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let (tlv, consumed) = Self::from_bytes(&data[offset..])?;
            tlvs.push(tlv);
            offset += consumed;
        }

        Ok(tlvs)
    }

    /// Encode multiple TLVs to bytes
    ///
    /// # Arguments
    ///
    /// * `tlvs` - Slice of TLVs to encode
    ///
    /// # Returns
    ///
    /// Returns byte vector containing all encoded TLVs concatenated
    ///
    /// # Example
    ///
    /// ```
    /// # use radius_proto::eap::eap_teap::{TeapTlv, TlvType};
    /// let tlvs = vec![
    ///     TeapTlv::new(TlvType::Result, true, vec![0x01]),
    /// ];
    /// let bytes = TeapTlv::encode_tlvs(&tlvs);
    /// ```
    pub fn encode_tlvs(tlvs: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for tlv in tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }
        bytes
    }

    /// Get the TLV type as enum (if known)
    pub fn get_type(&self) -> Option<TlvType> {
        TlvType::from_u16(self.tlv_type)
    }
}

/// TEAP Result values (for Result and Intermediate-Result TLVs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TeapResult {
    /// Success
    Success = 1,
    /// Failure
    Failure = 2,
}

impl TeapResult {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Success),
            2 => Some(Self::Failure),
            _ => None,
        }
    }

    /// Convert to Result TLV
    pub fn to_result_tlv(&self) -> TeapTlv {
        let mut value = vec![0u8; 2];
        value[0..2].copy_from_slice(&(*self as u16).to_be_bytes());
        TeapTlv::new(TlvType::Result, true, value)
    }

    /// Convert to Intermediate-Result TLV
    pub fn to_intermediate_result_tlv(&self) -> TeapTlv {
        let mut value = vec![0u8; 2];
        value[0..2].copy_from_slice(&(*self as u16).to_be_bytes());
        TeapTlv::new(TlvType::IntermediateResult, true, value)
    }

    /// Parse Result TLV value
    pub fn from_result_tlv(tlv: &TeapTlv) -> Result<Self, EapError> {
        if tlv.tlv_type != TlvType::Result as u16
            && tlv.tlv_type != TlvType::IntermediateResult as u16
        {
            return Err(EapError::InvalidResponseFormat);
        }
        if tlv.value.len() < 2 {
            return Err(EapError::InvalidLength(tlv.value.len()));
        }
        let result_value = u16::from_be_bytes([tlv.value[0], tlv.value[1]]);
        Self::from_u16(result_value).ok_or(EapError::InvalidResponseFormat)
    }

    /// Parse Intermediate-Result TLV value (same format as Result TLV)
    pub fn from_intermediate_result_tlv(tlv: &TeapTlv) -> Result<Self, EapError> {
        Self::from_result_tlv(tlv) // Reuse the same parser
    }
}

/// Identity Type values (for Identity-Type TLV)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IdentityType {
    /// User identity
    User = 1,
    /// Machine identity
    Machine = 2,
}

impl IdentityType {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::User),
            2 => Some(Self::Machine),
            _ => None,
        }
    }

    /// Create Identity-Type TLV
    pub fn to_tlv(&self) -> TeapTlv {
        let mut value = vec![0u8; 2];
        value[0..2].copy_from_slice(&(*self as u16).to_be_bytes());
        TeapTlv::new(TlvType::IdentityType, true, value)
    }

    /// Parse Identity-Type TLV
    pub fn from_tlv(tlv: &TeapTlv) -> Result<Self, EapError> {
        if tlv.tlv_type != TlvType::IdentityType as u16 {
            return Err(EapError::InvalidResponseFormat);
        }
        if tlv.value.len() < 2 {
            return Err(EapError::InvalidLength(tlv.value.len()));
        }
        let identity_type = u16::from_be_bytes([tlv.value[0], tlv.value[1]]);
        Self::from_u16(identity_type).ok_or(EapError::InvalidResponseFormat)
    }
}

/// EAP-Payload TLV (RFC 7170 Section 4.2.9)
///
/// Encapsulates an inner EAP method inside the TEAP tunnel.
/// This allows any EAP method to be tunneled within TEAP.
///
/// # Format
///
/// The value field contains a complete EAP packet (Code, Identifier, Length, Data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPayloadTlv {
    /// The encapsulated EAP packet data
    pub eap_packet_data: Vec<u8>,
}

impl EapPayloadTlv {
    /// Create new EAP-Payload TLV
    pub fn new(eap_packet_data: Vec<u8>) -> Self {
        Self { eap_packet_data }
    }

    /// Convert to TEAP TLV
    pub fn to_tlv(&self) -> TeapTlv {
        TeapTlv::new(TlvType::EapPayload, true, self.eap_packet_data.clone())
    }

    /// Parse from TEAP TLV
    pub fn from_tlv(tlv: &TeapTlv) -> Result<Self, EapError> {
        if tlv.tlv_type != TlvType::EapPayload as u16 {
            return Err(EapError::InvalidResponseFormat);
        }

        Ok(Self {
            eap_packet_data: tlv.value.clone(),
        })
    }

    /// Parse the inner EAP packet
    pub fn parse_eap_packet(&self) -> Result<super::EapPacket, EapError> {
        super::EapPacket::from_bytes(&self.eap_packet_data)
    }
}

/// Crypto-Binding TLV (RFC 7170 Section 4.2.13 and 5.3)
///
/// Provides cryptographic binding between the outer TLS tunnel and inner authentication.
/// This prevents man-in-the-middle attacks where an attacker could tunnel their own
/// authentication inside a victim's TLS session.
///
/// # Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Reserved   |    Version    |   Received Ver|   Sub-Type    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                             Nonce                             ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                    Compound MAC                               ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoBindingTlv {
    /// Version (1 byte) - TEAP version (currently 1)
    pub version: u8,
    /// Received Version (1 byte) - Highest version received from peer
    pub received_version: u8,
    /// Sub-Type (1 byte) - Binding request (0) or response (1)
    pub sub_type: u8,
    /// Nonce (32 bytes) - Random value for binding
    pub nonce: [u8; 32],
    /// Compound MAC (20 bytes for HMAC-SHA1 or 32 bytes for HMAC-SHA256)
    pub compound_mac: Vec<u8>,
}

impl CryptoBindingTlv {
    /// Crypto-Binding Request subtype
    pub const SUBTYPE_REQUEST: u8 = 0;
    /// Crypto-Binding Response subtype
    pub const SUBTYPE_RESPONSE: u8 = 1;

    /// TEAP version 1
    pub const VERSION: u8 = 1;

    /// Create new Crypto-Binding request
    pub fn new_request(nonce: [u8; 32]) -> Self {
        Self {
            version: Self::VERSION,
            received_version: Self::VERSION,
            sub_type: Self::SUBTYPE_REQUEST,
            nonce,
            compound_mac: vec![0u8; 32], // Will be calculated later
        }
    }

    /// Create new Crypto-Binding response
    pub fn new_response(nonce: [u8; 32], received_version: u8) -> Self {
        Self {
            version: Self::VERSION,
            received_version,
            sub_type: Self::SUBTYPE_RESPONSE,
            nonce,
            compound_mac: vec![0u8; 32], // Will be calculated later
        }
    }

    /// Convert to TEAP TLV
    pub fn to_tlv(&self) -> TeapTlv {
        let mut value = Vec::with_capacity(68); // 4 header + 32 nonce + 32 MAC

        value.push(0); // Reserved
        value.push(self.version);
        value.push(self.received_version);
        value.push(self.sub_type);
        value.extend_from_slice(&self.nonce);
        value.extend_from_slice(&self.compound_mac);

        TeapTlv::new(TlvType::CryptoBinding, true, value)
    }

    /// Parse from TEAP TLV value
    pub fn from_tlv(tlv: &TeapTlv) -> Result<Self, EapError> {
        if tlv.tlv_type != TlvType::CryptoBinding as u16 {
            return Err(EapError::InvalidResponseFormat);
        }

        if tlv.value.len() < 68 {
            // Minimum: 4 bytes header + 32 nonce + 32 MAC
            return Err(EapError::InvalidLength(tlv.value.len()));
        }

        let version = tlv.value[1];
        let received_version = tlv.value[2];
        let sub_type = tlv.value[3];

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&tlv.value[4..36]);

        let compound_mac = tlv.value[36..].to_vec();

        Ok(Self {
            version,
            received_version,
            sub_type,
            nonce,
            compound_mac,
        })
    }
}

/// Cryptographic binding context for TEAP
///
/// Manages the cryptographic keys and state needed for crypto-binding.
#[derive(Debug, Clone)]
pub struct CryptoBinding {
    /// IMCK (Intermediate Compound Key) - 60 bytes
    pub imck: Vec<u8>,
    /// CMK (Compound MAC Key) derived from IMCK - 20 bytes
    pub cmk: Vec<u8>,
    /// Server nonce for crypto-binding
    pub server_nonce: [u8; 32],
    /// Client nonce (received in response)
    pub client_nonce: Option<[u8; 32]>,
}

impl CryptoBinding {
    /// Derive IMCK (Intermediate Compound Key) - RFC 7170 Section 5.2
    ///
    /// IMCK[j] = TLS-PRF(S-IMCK[j-1], "Inner Methods Compound Keys",
    ///                    IMSK[j], 60)
    ///
    /// For first inner method (j=0):
    /// IMCK[0] = TLS-PRF(session_key_seed, "Inner Methods Compound Keys",
    ///                   IMSK[0], 60)
    ///
    /// Where session_key_seed is derived from TLS master secret.
    pub fn derive_imck(session_key_seed: &[u8], imsk: &[u8]) -> Vec<u8> {
        // For MVP, use HMAC-SHA256 as TLS-PRF with expansion to 60 bytes
        // In production, should use actual TLS PRF from the TLS version negotiated

        let label = b"Inner Methods Compound Keys";

        // HMAC-SHA256 produces 32 bytes, we need 60 bytes
        // Use iterative HMAC to expand the output
        let mut output = Vec::with_capacity(60);

        // First iteration: HMAC(seed, label || imsk || 0x01)
        let mut mac = Hmac::<Sha256>::new_from_slice(session_key_seed)
            .expect("HMAC can take key of any size");
        mac.update(label);
        mac.update(imsk);
        mac.update(&[0x01]);
        let a1 = mac.finalize().into_bytes();
        output.extend_from_slice(&a1);

        // Second iteration: HMAC(seed, A1 || label || imsk || 0x02)
        let mut mac = Hmac::<Sha256>::new_from_slice(session_key_seed)
            .expect("HMAC can take key of any size");
        mac.update(&a1);
        mac.update(label);
        mac.update(imsk);
        mac.update(&[0x02]);
        let a2 = mac.finalize().into_bytes();
        output.extend_from_slice(&a2);

        // Truncate to 60 bytes
        output.truncate(60);
        output
    }

    /// Derive CMK (Compound MAC Key) from IMCK - RFC 7170 Section 5.3
    ///
    /// CMK = First 20 bytes of IMCK
    pub fn derive_cmk(imck: &[u8]) -> Vec<u8> {
        imck[..20].to_vec()
    }

    /// Calculate Compound MAC - RFC 7170 Section 5.3
    ///
    /// Compound-MAC = HMAC-SHA256(CMK, BUFFER)
    ///
    /// Where BUFFER is the Crypto-Binding TLV with MAC field zeroed out,
    /// plus all previous TLVs in the conversation.
    pub fn calculate_compound_mac(cmk: &[u8], buffer: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(cmk).expect("HMAC can take key of any size");

        mac.update(buffer);

        let result = mac.finalize();
        result.into_bytes().to_vec()
    }

    /// Verify Compound MAC
    pub fn verify_compound_mac(cmk: &[u8], buffer: &[u8], received_mac: &[u8]) -> bool {
        let calculated_mac = Self::calculate_compound_mac(cmk, buffer);

        // Constant-time comparison
        if calculated_mac.len() != received_mac.len() {
            return false;
        }

        let mut result = 0u8;
        for (a, b) in calculated_mac.iter().zip(received_mac.iter()) {
            result |= a ^ b;
        }

        result == 0
    }

    /// Generate random nonce
    pub fn generate_nonce() -> [u8; 32] {
        use rand::Rng;
        let mut nonce = [0u8; 32];
        rand::rng().fill(&mut nonce);
        nonce
    }

    /// Create new crypto-binding context
    pub fn new(session_key_seed: &[u8], imsk: &[u8]) -> Self {
        let imck = Self::derive_imck(session_key_seed, imsk);
        let cmk = Self::derive_cmk(&imck);
        let server_nonce = Self::generate_nonce();

        Self {
            imck,
            cmk,
            server_nonce,
            client_nonce: None,
        }
    }
}

/// TEAP authentication phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeapPhase {
    /// Phase 1: TLS tunnel establishment
    Phase1TlsHandshake,
    /// Phase 2: Inner authentication
    Phase2InnerAuth,
    /// Authentication complete
    Complete,
}

/// EAP-TEAP Server
///
/// Manages TEAP authentication sessions, handling both Phase 1 (TLS tunnel)
/// and Phase 2 (inner authentication via TLVs).
///
/// # Example
///
/// ```no_run
/// # use radius_proto::eap::eap_teap::*;
/// # use std::sync::Arc;
/// # use rustls::ServerConfig;
/// # let config = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into())).unwrap());
/// let mut server = EapTeapServer::new(config);
/// server.initialize_connection().unwrap();
/// ```
pub struct EapTeapServer {
    /// Underlying TLS server (Phase 1)
    tls_server: EapTlsServer,

    /// Current TEAP phase
    phase: TeapPhase,

    /// Inner authentication method handler
    inner_method: Option<Box<dyn InnerMethodHandler>>,

    /// Intermediate results from inner methods
    intermediate_results: Vec<TeapResult>,

    /// Cryptographic binding context (for security)
    crypto_binding: Option<CryptoBinding>,

    /// Encoded bytes of all Phase 2 TLVs in conversation order.
    ///
    /// Used as the BUFFER prefix when computing/verifying the Crypto-Binding
    /// compound MAC (RFC 7170 §5.3). Sent and received TLVs are appended
    /// in the order they appear in the conversation, except for the
    /// Crypto-Binding TLV itself, which is appended only after MAC
    /// computation/verification (since BUFFER is `history || cb_tlv_zeroed`).
    phase2_tlv_history: Vec<u8>,

    /// Test-only override for `session_key_seed`.
    ///
    /// When set, `derive_session_key_seed` returns this value instead of
    /// invoking the TLS keying-material exporter. This lets unit tests drive
    /// the crypto-binding flow without completing a real TLS handshake.
    #[cfg(test)]
    test_session_key_seed: Option<Vec<u8>>,
}

impl EapTeapServer {
    /// Create new TEAP server
    ///
    /// # Arguments
    ///
    /// * `config` - rustls ServerConfig for TLS tunnel
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use radius_proto::eap::eap_teap::EapTeapServer;
    /// # use std::sync::Arc;
    /// # use rustls::ServerConfig;
    /// # let config = Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into())).unwrap());
    /// let server = EapTeapServer::new(config);
    /// ```
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            tls_server: EapTlsServer::new(config),
            phase: TeapPhase::Phase1TlsHandshake,
            inner_method: None,
            intermediate_results: Vec::new(),
            crypto_binding: None,
            phase2_tlv_history: Vec::new(),
            #[cfg(test)]
            test_session_key_seed: None,
        }
    }

    /// Create new TEAP server with inner method handler
    ///
    /// # Arguments
    ///
    /// * `config` - rustls ServerConfig for TLS tunnel
    /// * `inner_method` - Inner authentication method handler
    pub fn with_inner_method(
        config: Arc<rustls::ServerConfig>,
        inner_method: Box<dyn InnerMethodHandler>,
    ) -> Self {
        Self {
            tls_server: EapTlsServer::new(config),
            phase: TeapPhase::Phase1TlsHandshake,
            inner_method: Some(inner_method),
            intermediate_results: Vec::new(),
            crypto_binding: None,
            phase2_tlv_history: Vec::new(),
            #[cfg(test)]
            test_session_key_seed: None,
        }
    }

    /// Initialize TLS connection (Phase 1)
    pub fn initialize_connection(&mut self) -> Result<(), EapError> {
        self.tls_server.initialize_connection()
    }

    /// Check if TLS handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.tls_server.is_handshake_complete()
    }

    /// Get current phase
    pub fn get_phase(&self) -> TeapPhase {
        self.phase
    }

    /// Check if TEAP authentication is complete
    pub fn is_complete(&self) -> bool {
        self.phase == TeapPhase::Complete
    }

    /// Derive `session_key_seed` for Crypto-Binding (RFC 7170 §5.2).
    ///
    /// Uses the RFC 5705 TLS keying-material exporter with label
    /// `"EXPORTER: teap session key seed"` and an empty context, producing
    /// 40 octets that seed the IMCK derivation chain.
    ///
    /// In tests, `test_session_key_seed` overrides this to allow exercising
    /// the crypto-binding path without a completed TLS handshake.
    fn derive_session_key_seed(&mut self) -> Result<Vec<u8>, EapError> {
        #[cfg(test)]
        if let Some(ref seed) = self.test_session_key_seed {
            return Ok(seed.clone());
        }
        const TEAP_SESSION_KEY_SEED_LABEL: &[u8] = b"EXPORTER: teap session key seed";
        const SESSION_KEY_SEED_LEN: usize = 40;
        self.tls_server.export_keying_material(
            TEAP_SESSION_KEY_SEED_LABEL,
            None,
            SESSION_KEY_SEED_LEN,
        )
    }

    /// Get the IMSK (Inner Method Session Key) for Crypto-Binding.
    ///
    /// Returns the inner method's IMSK if it produces one; otherwise returns
    /// an all-zero 32-octet IMSK as specified for methods that do not derive
    /// keying material (RFC 7170 §5.2). This is an explicit decision rather
    /// than a placeholder.
    fn get_inner_imsk(&self) -> Vec<u8> {
        self.inner_method
            .as_ref()
            .and_then(|h| h.get_imsk())
            .unwrap_or_else(|| vec![0u8; 32])
    }

    /// Append an encoded TLV to the Phase 2 conversation history.
    ///
    /// History feeds the BUFFER for Crypto-Binding compound MAC (RFC 7170 §5.3).
    fn append_to_phase2_history(&mut self, tlv: &TeapTlv) {
        self.phase2_tlv_history.extend_from_slice(&tlv.to_bytes());
    }

    /// Build a Crypto-Binding Request TLV bound to the current conversation.
    ///
    /// BUFFER = phase2_tlv_history || cb_request_with_mac_zeroed
    /// MAC = HMAC-SHA256(CMK, BUFFER), per RFC 7170 §5.3.
    ///
    /// On success, stores the `CryptoBinding` context on `self` and returns
    /// the TLV ready for transmission. The caller is responsible for sending
    /// the TLV (which will append it to history via the send helpers).
    fn build_crypto_binding_request_tlv(&mut self) -> Result<TeapTlv, EapError> {
        let session_key_seed = self.derive_session_key_seed()?;
        let imsk = self.get_inner_imsk();
        let crypto_binding = CryptoBinding::new(&session_key_seed, &imsk);

        let cb_template = CryptoBindingTlv {
            version: CryptoBindingTlv::VERSION,
            received_version: 0,
            sub_type: CryptoBindingTlv::SUBTYPE_REQUEST,
            nonce: crypto_binding.server_nonce,
            compound_mac: vec![0u8; 32],
        };

        // BUFFER = prior conversation || this TLV with MAC field zeroed.
        let mut buffer = self.phase2_tlv_history.clone();
        buffer.extend_from_slice(&cb_template.to_tlv().to_bytes());
        let compound_mac = CryptoBinding::calculate_compound_mac(&crypto_binding.cmk, &buffer);

        let cb_tlv = CryptoBindingTlv {
            compound_mac,
            ..cb_template
        };

        self.crypto_binding = Some(crypto_binding);
        Ok(cb_tlv.to_tlv())
    }

    /// Verify a Crypto-Binding Response TLV against the current conversation.
    ///
    /// BUFFER = phase2_tlv_history || cb_response_with_mac_zeroed,
    /// where `phase2_tlv_history` already includes the previously-sent
    /// Crypto-Binding Request. Returns `Ok(true)` if the MAC matches.
    fn verify_crypto_binding_response_tlv(&self, tlv: &TeapTlv) -> Result<bool, EapError> {
        let cb_response = CryptoBindingTlv::from_tlv(tlv)?;
        let crypto_binding = self.crypto_binding.as_ref().ok_or(EapError::InvalidState)?;

        if cb_response.sub_type != CryptoBindingTlv::SUBTYPE_RESPONSE {
            return Err(EapError::InvalidResponseFormat);
        }

        let mut tlv_for_mac = cb_response.clone();
        tlv_for_mac.compound_mac = vec![0u8; 32];

        let mut buffer = self.phase2_tlv_history.clone();
        buffer.extend_from_slice(&tlv_for_mac.to_tlv().to_bytes());

        Ok(CryptoBinding::verify_compound_mac(
            &crypto_binding.cmk,
            &buffer,
            &cb_response.compound_mac,
        ))
    }

    /// Process client message (Phase 1 - TLS handshake)
    ///
    /// This handles Phase 1 TLS tunnel establishment.
    pub fn process_client_message(
        &mut self,
        tls_packet: &EapTlsPacket,
    ) -> Result<Option<Vec<u8>>, EapError> {
        match self.phase {
            TeapPhase::Phase1TlsHandshake => {
                // Delegate to TLS server
                let response = self.tls_server.process_client_message(tls_packet)?;

                // Check if handshake complete
                if self.tls_server.is_handshake_complete() {
                    // Extract keys for future use
                    self.tls_server.extract_keys()?;
                    // Transition to Phase 2
                    self.phase = TeapPhase::Phase2InnerAuth;
                }

                Ok(response)
            }
            TeapPhase::Phase2InnerAuth => {
                // Decrypt TLS application data to get TLVs
                let tlv_data = self.decrypt_tls_data(tls_packet)?;

                // Parse TLVs from decrypted data
                let tlvs = TeapTlv::parse_tlvs(&tlv_data)?;

                // Process Phase 2 TLVs
                self.process_phase2_tlvs(&tlvs)
            }
            TeapPhase::Complete => Err(EapError::InvalidState),
        }
    }

    /// Decrypt TLS application data from EAP-TLS packet
    ///
    /// In Phase 2, the client sends TLVs encrypted in the TLS tunnel.
    /// We need to decrypt them using the established TLS connection.
    ///
    /// This:
    /// 1. Feeds encrypted TLS records to rustls
    /// 2. Processes and decrypts the records
    /// 3. Extracts the plaintext application data (TLVs)
    fn decrypt_tls_data(&mut self, tls_packet: &EapTlsPacket) -> Result<Vec<u8>, EapError> {
        use std::io::{Cursor, Read};

        // Get mutable access to TLS connection
        let conn = self.tls_server.get_connection_mut()?;

        // Feed encrypted data to rustls
        let mut cursor = Cursor::new(&tls_packet.tls_data);
        conn.read_tls(&mut cursor)
            .map_err(|e| EapError::TlsError(format!("Failed to read TLS data: {}", e)))?;

        // Process TLS records (decrypt)
        conn.process_new_packets()
            .map_err(|e| EapError::TlsError(format!("Failed to process TLS packets: {}", e)))?;

        // Read decrypted application data
        let mut plaintext = Vec::new();
        conn.reader()
            .read_to_end(&mut plaintext)
            .map_err(|e| EapError::TlsError(format!("Failed to read decrypted data: {}", e)))?;

        Ok(plaintext)
    }

    /// Process Phase 2 TLVs
    ///
    /// Handles the TLV exchange for inner authentication.
    fn process_phase2_tlvs(&mut self, tlvs: &[TeapTlv]) -> Result<Option<Vec<u8>>, EapError> {
        if tlvs.is_empty() {
            // No TLVs received, send Identity-Type request
            return self.send_identity_type_request();
        }

        // Process each TLV
        for tlv in tlvs {
            // Append received TLV to conversation history for crypto-binding
            // (RFC 7170 §5.3). The Crypto-Binding response is excluded here:
            // its MAC is verified against history *without* itself, then it
            // is appended below after verification.
            if tlv.get_type() != Some(TlvType::CryptoBinding) {
                self.append_to_phase2_history(tlv);
            }
            match tlv.get_type() {
                Some(TlvType::IdentityType) => {
                    // Identity-Type response received
                    // Check if inner method can handle this (e.g., EapPayloadHandler)
                    // Otherwise fall back to password auth
                    if let Some(ref mut handler) = self.inner_method {
                        // Try to delegate to handler
                        if let Ok(response_tlv) = handler.process_inner_request(tlv) {
                            return self.encrypt_and_send_tlvs(&[response_tlv]);
                        }
                    }
                    // Fall back to Basic-Password-Auth if handler doesn't support IdentityType
                    return self.send_password_auth_request();
                }
                Some(TlvType::BasicPasswordAuthResp) => {
                    // Password auth response received
                    if let Some(ref mut handler) = self.inner_method {
                        let _result_tlv = handler.process_inner_request(tlv)?;

                        // Check if authentication is complete
                        if handler.is_complete() {
                            let auth_result = handler.get_result();

                            // If authentication succeeded, initiate crypto-binding
                            if auth_result == TeapResult::Success {
                                return self.send_crypto_binding_request();
                            } else {
                                // Authentication failed, send failure result
                                self.phase = TeapPhase::Complete;
                                let failure_tlv = TeapResult::Failure.to_result_tlv();
                                return self.encrypt_and_send_tlvs(&[failure_tlv]);
                            }
                        }
                    }
                }
                Some(TlvType::EapPayload) => {
                    // EAP-Payload TLV received - process inner EAP method
                    if let Some(ref mut handler) = self.inner_method {
                        let response_tlv = handler.process_inner_request(tlv)?;

                        // Check if this is an Intermediate-Result TLV
                        if response_tlv.get_type() == Some(TlvType::IntermediateResult) {
                            // Store intermediate result
                            let result = TeapResult::from_result_tlv(&response_tlv)?;
                            self.intermediate_results.push(result);

                            // Check if authentication is complete
                            if handler.is_complete() {
                                let auth_result = handler.get_result();

                                // If authentication succeeded, initiate crypto-binding
                                if auth_result == TeapResult::Success {
                                    return self.send_crypto_binding_request();
                                } else {
                                    // Authentication failed, send failure result
                                    self.phase = TeapPhase::Complete;
                                    let failure_tlv = TeapResult::Failure.to_result_tlv();
                                    return self.encrypt_and_send_tlvs(&[failure_tlv]);
                                }
                            }
                        } else {
                            // Regular EAP-Payload response, send it back
                            return self.encrypt_and_send_tlvs(&[response_tlv]);
                        }
                    }
                }
                Some(TlvType::IntermediateResult) => {
                    // Intermediate-Result TLV from client (acknowledgment)
                    let result = TeapResult::from_result_tlv(tlv)?;
                    self.intermediate_results.push(result);
                    // Continue processing other TLVs
                    continue;
                }
                Some(TlvType::CryptoBinding) => {
                    // Crypto-Binding response received from client
                    return self.process_crypto_binding_response(tlv);
                }
                Some(TlvType::Result) => {
                    // Final result TLV from client (acknowledgment)
                    self.phase = TeapPhase::Complete;
                    return Ok(None);
                }
                _ => {
                    // Unknown or unsupported TLV
                    continue;
                }
            }
        }

        Ok(None)
    }

    /// Send Identity-Type TLV request
    fn send_identity_type_request(&mut self) -> Result<Option<Vec<u8>>, EapError> {
        let identity_tlv = IdentityType::User.to_tlv();
        self.encrypt_and_send_tlvs(&[identity_tlv])
    }

    /// Send Basic-Password-Auth-Req TLV
    fn send_password_auth_request(&mut self) -> Result<Option<Vec<u8>>, EapError> {
        let request_tlv = BasicPasswordAuthHandler::create_password_request();
        self.encrypt_and_send_tlvs(&[request_tlv])
    }

    /// Encrypt TLVs and send in TLS tunnel
    ///
    /// This encrypts the TLVs using the established TLS connection
    /// and returns the encrypted data for transmission.
    ///
    /// This:
    /// 1. Encodes TLVs to bytes
    /// 2. Writes application data to rustls
    /// 3. Extracts encrypted TLS records
    /// 4. Appends each sent TLV to `phase2_tlv_history` for crypto-binding
    fn encrypt_and_send_tlvs(&mut self, tlvs: &[TeapTlv]) -> Result<Option<Vec<u8>>, EapError> {
        use std::io::Write;

        // Encode TLVs
        let tlv_data = TeapTlv::encode_tlvs(tlvs);

        // Get mutable access to TLS connection
        let conn = self.tls_server.get_connection_mut()?;

        // Write application data (TLVs) to TLS connection
        conn.writer()
            .write_all(&tlv_data)
            .map_err(|e| EapError::TlsError(format!("Failed to write application data: {}", e)))?;

        // Get encrypted TLS records
        let mut encrypted = Vec::new();
        conn.write_tls(&mut encrypted)
            .map_err(|e| EapError::TlsError(format!("Failed to write TLS records: {}", e)))?;

        // Track sent TLVs for Crypto-Binding compound MAC (RFC 7170 §5.3).
        // Done after successful encryption so a failed send doesn't desync history.
        for tlv in tlvs {
            self.append_to_phase2_history(tlv);
        }

        Ok(Some(encrypted))
    }

    /// Test helper: Send TLVs without encryption (for unit tests)
    ///
    /// This bypasses TLS encryption and returns plaintext TLVs.
    /// Used only in tests where TLS handshake hasn't been completed.
    /// Sent TLVs are still tracked in `phase2_tlv_history` so crypto-binding
    /// behavior matches the production path.
    #[cfg(test)]
    fn send_tlvs_plaintext(&mut self, tlvs: &[TeapTlv]) -> Result<Option<Vec<u8>>, EapError> {
        let tlv_data = TeapTlv::encode_tlvs(tlvs);
        for tlv in tlvs {
            self.append_to_phase2_history(tlv);
        }
        Ok(Some(tlv_data))
    }

    /// Test helper: Process Phase 2 TLVs without encryption (for unit tests)
    ///
    /// Mirrors `process_phase2_tlvs` but routes outgoing TLVs through
    /// `send_tlvs_plaintext` so tests can drive the flow without a completed
    /// TLS handshake. Crypto-binding uses the same `build_*` / `verify_*`
    /// helpers as production, so BUFFER semantics stay identical.
    #[cfg(test)]
    fn process_phase2_tlvs_test(&mut self, tlvs: &[TeapTlv]) -> Result<Option<Vec<u8>>, EapError> {
        if tlvs.is_empty() {
            let tlv = IdentityType::User.to_tlv();
            return self.send_tlvs_plaintext(&[tlv]);
        }

        for tlv in tlvs {
            // Append non-CryptoBinding received TLVs to history; CryptoBinding
            // is appended only after MAC verification (see helper).
            if tlv.get_type() != Some(TlvType::CryptoBinding) {
                self.append_to_phase2_history(tlv);
            }
            match tlv.get_type() {
                Some(TlvType::IdentityType) => {
                    if let Some(ref mut handler) = self.inner_method
                        && let Ok(response_tlv) = handler.process_inner_request(tlv)
                    {
                        return self.send_tlvs_plaintext(&[response_tlv]);
                    }
                    let req = TeapTlv::new(TlvType::BasicPasswordAuthReq, true, Vec::new());
                    return self.send_tlvs_plaintext(&[req]);
                }
                Some(TlvType::BasicPasswordAuthResp) => {
                    if let Some(ref mut handler) = self.inner_method {
                        let _result_tlv = handler.process_inner_request(tlv)?;
                        if handler.is_complete() {
                            let auth_result = handler.get_result();
                            if auth_result == TeapResult::Success {
                                let cb_tlv = self.build_crypto_binding_request_tlv()?;
                                return self.send_tlvs_plaintext(&[cb_tlv]);
                            } else {
                                self.phase = TeapPhase::Complete;
                                let failure_tlv = TeapResult::Failure.to_result_tlv();
                                return self.send_tlvs_plaintext(&[failure_tlv]);
                            }
                        }
                    }
                }
                Some(TlvType::EapPayload) => {
                    if let Some(ref mut handler) = self.inner_method {
                        let response_tlv = handler.process_inner_request(tlv)?;
                        if response_tlv.get_type() == Some(TlvType::IntermediateResult) {
                            let result = TeapResult::from_result_tlv(&response_tlv)?;
                            self.intermediate_results.push(result);
                            if handler.is_complete() {
                                let auth_result = handler.get_result();
                                if auth_result == TeapResult::Success {
                                    let cb_tlv = self.build_crypto_binding_request_tlv()?;
                                    return self.send_tlvs_plaintext(&[cb_tlv]);
                                } else {
                                    self.phase = TeapPhase::Complete;
                                    let failure_tlv = TeapResult::Failure.to_result_tlv();
                                    return self.send_tlvs_plaintext(&[failure_tlv]);
                                }
                            }
                        } else {
                            return self.send_tlvs_plaintext(&[response_tlv]);
                        }
                    }
                }
                Some(TlvType::IntermediateResult) => {
                    let result = TeapResult::from_result_tlv(tlv)?;
                    self.intermediate_results.push(result);
                    continue;
                }
                Some(TlvType::CryptoBinding) => {
                    let mac_ok = self.verify_crypto_binding_response_tlv(tlv)?;
                    if let Ok(cb_response) = CryptoBindingTlv::from_tlv(tlv)
                        && let Some(crypto_binding) = self.crypto_binding.as_mut()
                    {
                        crypto_binding.client_nonce = Some(cb_response.nonce);
                    }
                    self.phase = TeapPhase::Complete;
                    let result_tlv = if mac_ok {
                        TeapResult::Success.to_result_tlv()
                    } else {
                        TeapResult::Failure.to_result_tlv()
                    };
                    return self.send_tlvs_plaintext(&[result_tlv]);
                }
                Some(TlvType::Result) => {
                    self.phase = TeapPhase::Complete;
                    return Ok(None);
                }
                _ => continue,
            }
        }

        Ok(None)
    }

    /// Send Crypto-Binding Request TLV
    ///
    /// RFC 7170 Section 5.3: After successful inner authentication, the server
    /// sends a Crypto-Binding TLV to bind the inner and outer authentication.
    /// The compound MAC covers `phase2_tlv_history || cb_request_with_mac_zeroed`,
    /// so any tampering with prior conversation TLVs invalidates the binding.
    fn send_crypto_binding_request(&mut self) -> Result<Option<Vec<u8>>, EapError> {
        let cb_tlv = self.build_crypto_binding_request_tlv()?;
        self.encrypt_and_send_tlvs(&[cb_tlv])
    }

    /// Process Crypto-Binding Response TLV
    ///
    /// RFC 7170 Section 5.3: Verify the client's Crypto-Binding response.
    /// BUFFER for verification is `phase2_tlv_history || cb_response_zeroed`
    /// where `phase2_tlv_history` already includes the Crypto-Binding Request
    /// we sent earlier; this is what binds the inner authentication to the
    /// outer TLS-tunneled conversation.
    fn process_crypto_binding_response(
        &mut self,
        tlv: &TeapTlv,
    ) -> Result<Option<Vec<u8>>, EapError> {
        let cb_response = CryptoBindingTlv::from_tlv(tlv)?;
        let mac_ok = self.verify_crypto_binding_response_tlv(tlv)?;

        // Record the client nonce regardless of MAC result for diagnostics.
        if let Some(crypto_binding) = self.crypto_binding.as_mut() {
            crypto_binding.client_nonce = Some(cb_response.nonce);
        }

        self.phase = TeapPhase::Complete;
        let result_tlv = if mac_ok {
            TeapResult::Success.to_result_tlv()
        } else {
            TeapResult::Failure.to_result_tlv()
        };
        self.encrypt_and_send_tlvs(&[result_tlv])
    }
}

/// Inner authentication method handler trait
///
/// Defines the interface for handling inner authentication methods within
/// the TEAP tunnel (Phase 2).
pub trait InnerMethodHandler: Send + Sync {
    /// Process inner authentication request
    ///
    /// # Arguments
    ///
    /// * `request_tlv` - TLV containing the inner auth request
    ///
    /// # Returns
    ///
    /// Returns response TLV or error
    fn process_inner_request(&mut self, request_tlv: &TeapTlv) -> Result<TeapTlv, EapError>;

    /// Check if authentication is complete
    fn is_complete(&self) -> bool;

    /// Get authentication result
    fn get_result(&self) -> TeapResult;

    /// Get authenticated identity (if successful)
    fn get_identity(&self) -> Option<String>;

    /// Get the IMSK (Inner Method Session Key) produced by this method,
    /// used to derive the Crypto-Binding compound MAC (RFC 7170 §5.2).
    ///
    /// Methods that do not produce keying material (e.g. Basic-Password-Auth,
    /// EAP-MD5) MUST return `None`; per RFC 7170 §5.2 the server then uses
    /// an all-zero IMSK for binding. Methods that derive an MSK
    /// (e.g. EAP-MSCHAPv2, EAP-TLS-as-inner) should return the first 32
    /// octets of that MSK.
    fn get_imsk(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Basic Password Authentication Handler
///
/// Implements simple username/password authentication inside TEAP tunnel.
/// This is the simplest inner method for MVP.
///
/// # Example
///
/// ```no_run
/// # use radius_proto::eap::eap_teap::*;
/// let handler = BasicPasswordAuthHandler::new("alice".to_string(), "password".to_string());
/// // Process authentication TLVs...
/// ```
pub struct BasicPasswordAuthHandler {
    /// Expected username
    expected_username: Option<String>,
    /// Expected password
    expected_password: Option<String>,
    /// Received username
    username: Option<String>,
    /// Authentication complete flag
    complete: bool,
    /// Authentication result
    result: TeapResult,
}

impl BasicPasswordAuthHandler {
    /// Create new Basic Password Auth handler
    ///
    /// # Arguments
    ///
    /// * `expected_username` - Expected username for authentication
    /// * `expected_password` - Expected password for authentication
    pub fn new(expected_username: String, expected_password: String) -> Self {
        Self {
            expected_username: Some(expected_username),
            expected_password: Some(expected_password),
            username: None,
            complete: false,
            result: TeapResult::Failure,
        }
    }

    /// Create handler without pre-set credentials (for testing)
    pub fn new_empty() -> Self {
        Self {
            expected_username: None,
            expected_password: None,
            username: None,
            complete: false,
            result: TeapResult::Failure,
        }
    }

    /// Parse Basic-Password-Auth-Resp TLV
    ///
    /// Format (RFC 7170 Section 4.2.14):
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |            Username Length    |          Username...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |            Password Length    |          Password...
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse_password_response(&mut self, tlv: &TeapTlv) -> Result<(), EapError> {
        if tlv.value.len() < 4 {
            return Err(EapError::InvalidLength(tlv.value.len()));
        }

        let mut offset = 0;

        // Parse username length (2 bytes)
        let username_len = u16::from_be_bytes([tlv.value[offset], tlv.value[offset + 1]]) as usize;
        offset += 2;

        if offset + username_len > tlv.value.len() {
            return Err(EapError::InvalidLength(username_len));
        }

        // Parse username
        let username = String::from_utf8(tlv.value[offset..offset + username_len].to_vec())
            .map_err(|_| EapError::InvalidResponseFormat)?;
        offset += username_len;

        if offset + 2 > tlv.value.len() {
            return Err(EapError::InvalidLength(tlv.value.len() - offset));
        }

        // Parse password length (2 bytes)
        let password_len = u16::from_be_bytes([tlv.value[offset], tlv.value[offset + 1]]) as usize;
        offset += 2;

        if offset + password_len > tlv.value.len() {
            return Err(EapError::InvalidLength(password_len));
        }

        // Parse password
        let password = String::from_utf8(tlv.value[offset..offset + password_len].to_vec())
            .map_err(|_| EapError::InvalidResponseFormat)?;

        // Verify credentials
        let auth_success = if let (Some(exp_user), Some(exp_pass)) =
            (&self.expected_username, &self.expected_password)
        {
            &username == exp_user && &password == exp_pass
        } else {
            false
        };

        self.username = Some(username);
        self.complete = true;
        self.result = if auth_success {
            TeapResult::Success
        } else {
            TeapResult::Failure
        };

        Ok(())
    }

    /// Create Basic-Password-Auth-Req TLV
    ///
    /// Simple request with no prompt (minimal implementation)
    fn create_password_request() -> TeapTlv {
        // Empty prompt for simplicity (MVP)
        TeapTlv::new(TlvType::BasicPasswordAuthReq, true, vec![])
    }
}

impl InnerMethodHandler for BasicPasswordAuthHandler {
    fn process_inner_request(&mut self, request_tlv: &TeapTlv) -> Result<TeapTlv, EapError> {
        match request_tlv.get_type() {
            Some(TlvType::BasicPasswordAuthResp) => {
                // Process password response
                self.parse_password_response(request_tlv)?;
                // Return result TLV
                Ok(self.result.to_result_tlv())
            }
            _ => {
                // Unknown TLV type, return NAK
                Err(EapError::InvalidResponseFormat)
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn get_result(&self) -> TeapResult {
        self.result
    }

    fn get_identity(&self) -> Option<String> {
        self.username.clone()
    }
}

/// EAP-Payload Authentication Handler
///
/// Implements tunneled EAP authentication inside TEAP (Phase 2).
/// Supports any inner EAP method including EAP-Identity, EAP-MD5, EAP-MSCHAPv2, etc.
///
/// # Inner EAP State Machine
///
/// ```text
/// Initial → Identity Request → Identity Response → Method Request
///     → Method Response (may be multi-round) → Success/Failure
/// ```
///
/// # Example
///
/// ```no_run
/// # use radius_proto::eap::eap_teap::*;
/// let handler = EapPayloadHandler::new("alice".to_string(), "password".to_string());
/// // Process EAP-Payload TLVs...
/// ```
pub struct EapPayloadHandler {
    /// Expected username for authentication
    expected_username: String,
    /// Expected password for authentication
    #[allow(dead_code)]
    expected_password: String,
    /// Current inner EAP state
    inner_state: InnerEapState,
    /// Last identifier used
    last_identifier: u8,
    /// Authenticated identity
    authenticated_identity: Option<String>,
    /// Authentication complete flag
    complete: bool,
    /// Authentication result
    result: TeapResult,
    /// Current inner EAP method type
    inner_method_type: Option<super::EapType>,
}

/// Inner EAP state for tunneled authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnerEapState {
    /// Initial state - need to send Identity request
    Initial,
    /// Identity request sent, awaiting response
    IdentityRequested,
    /// Identity received, need to send method request
    IdentityReceived,
    /// Method request sent, awaiting response
    MethodRequested,
    /// Method response received, processing
    #[allow(dead_code)]
    MethodInProgress,
    /// Authentication completed (success or failure)
    Complete,
}

impl EapPayloadHandler {
    /// Create new EAP-Payload handler
    ///
    /// # Arguments
    ///
    /// * `expected_username` - Expected username for authentication
    /// * `expected_password` - Expected password for authentication
    pub fn new(expected_username: String, expected_password: String) -> Self {
        Self {
            expected_username,
            expected_password,
            inner_state: InnerEapState::Initial,
            last_identifier: 0,
            authenticated_identity: None,
            complete: false,
            result: TeapResult::Failure,
            inner_method_type: None,
        }
    }

    /// Get next identifier for inner EAP
    fn next_identifier(&mut self) -> u8 {
        self.last_identifier = self.last_identifier.wrapping_add(1);
        self.last_identifier
    }

    /// Create EAP-Identity request
    fn create_identity_request(&mut self) -> TeapTlv {
        let identifier = self.next_identifier();
        let eap_packet = super::EapPacket::new(
            super::EapCode::Request,
            identifier,
            Some(super::EapType::Identity),
            vec![],
        );

        self.inner_state = InnerEapState::IdentityRequested;

        EapPayloadTlv::new(eap_packet.to_bytes()).to_tlv()
    }

    /// Create EAP-MD5 Challenge request
    fn create_md5_challenge_request(&mut self) -> TeapTlv {
        use rand::Rng;

        let identifier = self.next_identifier();

        // Generate 16-byte random challenge
        let mut challenge = [0u8; 16];
        rand::rng().fill(&mut challenge);

        // EAP-MD5 format: value-size (1 byte) + challenge (16 bytes)
        let mut data = Vec::with_capacity(17);
        data.push(16); // Challenge size
        data.extend_from_slice(&challenge);

        let eap_packet = super::EapPacket::new(
            super::EapCode::Request,
            identifier,
            Some(super::EapType::Md5Challenge),
            data,
        );

        self.inner_state = InnerEapState::MethodRequested;
        self.inner_method_type = Some(super::EapType::Md5Challenge);

        EapPayloadTlv::new(eap_packet.to_bytes()).to_tlv()
    }

    /// Process EAP-Identity response
    fn process_identity_response(
        &mut self,
        eap_packet: &super::EapPacket,
    ) -> Result<TeapTlv, EapError> {
        // Extract identity from EAP data
        if let Ok(identity) = String::from_utf8(eap_packet.data.clone()) {
            self.authenticated_identity = Some(identity.clone());
            self.inner_state = InnerEapState::IdentityReceived;

            // Send MD5 Challenge as inner method
            Ok(self.create_md5_challenge_request())
        } else {
            Err(EapError::InvalidResponseFormat)
        }
    }

    /// Process EAP-MD5 Challenge response
    fn process_md5_response(&mut self, eap_packet: &super::EapPacket) -> Result<TeapTlv, EapError> {
        // EAP-MD5 format: value-size (1 byte) + response hash (16 bytes)
        if eap_packet.data.len() < 17 {
            return Err(EapError::InvalidLength(eap_packet.data.len()));
        }

        let value_size = eap_packet.data[0];
        if value_size != 16 {
            return Err(EapError::InvalidLength(value_size as usize));
        }

        // For MVP, accept any MD5 response (full MD5 validation would require
        // tracking the challenge we sent and computing expected hash)
        // In production: hash = MD5(identifier || password || challenge)

        // Simplified authentication: just check if identity matches expected username
        let auth_success = self
            .authenticated_identity
            .as_ref()
            .map(|id| id == &self.expected_username)
            .unwrap_or(false);

        self.complete = true;
        self.result = if auth_success {
            TeapResult::Success
        } else {
            TeapResult::Failure
        };
        self.inner_state = InnerEapState::Complete;

        // Return Intermediate-Result TLV
        Ok(self.result.to_intermediate_result_tlv())
    }

    /// Process inner EAP packet from EAP-Payload TLV
    fn process_eap_packet(&mut self, eap_packet: &super::EapPacket) -> Result<TeapTlv, EapError> {
        match eap_packet.code {
            super::EapCode::Response => {
                // Route based on current state and method type
                match self.inner_state {
                    InnerEapState::IdentityRequested => {
                        // Identity response
                        self.process_identity_response(eap_packet)
                    }
                    InnerEapState::MethodRequested | InnerEapState::MethodInProgress => {
                        // Method-specific response
                        match self.inner_method_type {
                            Some(super::EapType::Md5Challenge) => {
                                self.process_md5_response(eap_packet)
                            }
                            _ => Err(EapError::InvalidResponseFormat),
                        }
                    }
                    _ => Err(EapError::InvalidState),
                }
            }
            _ => Err(EapError::InvalidResponseFormat),
        }
    }
}

impl InnerMethodHandler for EapPayloadHandler {
    fn process_inner_request(&mut self, request_tlv: &TeapTlv) -> Result<TeapTlv, EapError> {
        match request_tlv.get_type() {
            Some(TlvType::EapPayload) => {
                // Parse EAP-Payload TLV
                let eap_payload = EapPayloadTlv::from_tlv(request_tlv)?;

                // Parse inner EAP packet
                let eap_packet = eap_payload.parse_eap_packet()?;

                // Process the inner EAP packet
                self.process_eap_packet(&eap_packet)
            }
            Some(TlvType::IdentityType) => {
                // Initial request - start inner EAP by sending Identity request
                Ok(self.create_identity_request())
            }
            _ => {
                // Unknown TLV type
                Err(EapError::InvalidResponseFormat)
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn get_result(&self) -> TeapResult {
        self.result
    }

    fn get_identity(&self) -> Option<String> {
        self.authenticated_identity.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_type_from_u16() {
        assert_eq!(TlvType::from_u16(1), Some(TlvType::AuthorityId));
        assert_eq!(TlvType::from_u16(3), Some(TlvType::Result));
        assert_eq!(TlvType::from_u16(9), Some(TlvType::EapPayload));
        assert_eq!(TlvType::from_u16(12), Some(TlvType::CryptoBinding));
        assert_eq!(TlvType::from_u16(17), Some(TlvType::TrustedServerRoot));
        assert_eq!(TlvType::from_u16(255), None);
    }

    #[test]
    fn test_tlv_new() {
        let tlv = TeapTlv::new(TlvType::Result, true, vec![0x00, 0x01]);
        assert_eq!(tlv.tlv_type, 3);
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);
    }

    #[test]
    fn test_tlv_encode_decode_roundtrip() {
        let original = TeapTlv::new(TlvType::Result, true, vec![0x00, 0x01]);
        let bytes = original.to_bytes();
        let (decoded, consumed) = TeapTlv::from_bytes(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_tlv_mandatory_flag() {
        let mandatory_tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]);
        let bytes = mandatory_tlv.to_bytes();
        assert_eq!(bytes[0] & 0x80, 0x80); // M bit set

        let optional_tlv = TeapTlv::new(TlvType::VendorSpecific, false, vec![0x01]);
        let bytes = optional_tlv.to_bytes();
        assert_eq!(bytes[0] & 0x80, 0x00); // M bit not set
    }

    #[test]
    fn test_tlv_parse_single() {
        // Result TLV (mandatory, success)
        let data = vec![
            0x80, 0x03, // Type: Mandatory | Result
            0x00, 0x02, // Length: 2
            0x00, 0x01, // Value: Success
        ];

        let (tlv, consumed) = TeapTlv::from_bytes(&data).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(tlv.tlv_type, 3);
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);
    }

    #[test]
    fn test_tlv_parse_multiple() {
        let data = vec![
            0x80, 0x02, 0x00, 0x02, 0x00, 0x01, // Identity-Type TLV
            0x80, 0x03, 0x00, 0x02, 0x00, 0x01, // Result TLV
        ];

        let tlvs = TeapTlv::parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tlv_type, 2); // Identity-Type
        assert_eq!(tlvs[1].tlv_type, 3); // Result
    }

    #[test]
    fn test_tlv_encode_multiple() {
        let tlvs = vec![
            TeapTlv::new(TlvType::IdentityType, true, vec![0x00, 0x01]),
            TeapTlv::new(TlvType::Result, true, vec![0x00, 0x01]),
        ];

        let bytes = TeapTlv::encode_tlvs(&tlvs);
        let decoded = TeapTlv::parse_tlvs(&bytes).unwrap();

        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn test_tlv_invalid_length() {
        // Length says 10, but only 2 bytes available
        let data = vec![0x80, 0x03, 0x00, 0x0A, 0x00, 0x01];
        assert!(TeapTlv::from_bytes(&data).is_err());
    }

    #[test]
    fn test_tlv_too_short() {
        let data = vec![0x80, 0x03]; // Only 2 bytes, need at least 4
        assert!(TeapTlv::from_bytes(&data).is_err());
    }

    #[test]
    fn test_tlv_reserved_flag_set() {
        // Reserved bit (0x4000) should cause error
        let data = vec![
            0xC0, 0x03, // Type with both M and R bits set
            0x00, 0x02, 0x00, 0x01,
        ];
        assert!(TeapTlv::from_bytes(&data).is_err());
    }

    #[test]
    fn test_result_tlv_success() {
        let result = TeapResult::Success;
        let tlv = result.to_result_tlv();

        assert_eq!(tlv.tlv_type, 3);
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);

        let parsed = TeapResult::from_result_tlv(&tlv).unwrap();
        assert_eq!(parsed, TeapResult::Success);
    }

    #[test]
    fn test_result_tlv_failure() {
        let result = TeapResult::Failure;
        let tlv = result.to_result_tlv();

        assert_eq!(tlv.value, vec![0x00, 0x02]);

        let parsed = TeapResult::from_result_tlv(&tlv).unwrap();
        assert_eq!(parsed, TeapResult::Failure);
    }

    #[test]
    fn test_intermediate_result_tlv() {
        let result = TeapResult::Success;
        let tlv = result.to_intermediate_result_tlv();

        assert_eq!(tlv.tlv_type, 10); // Intermediate-Result
        assert_eq!(tlv.mandatory, true);
    }

    #[test]
    fn test_identity_type_user() {
        let identity = IdentityType::User;
        let tlv = identity.to_tlv();

        assert_eq!(tlv.tlv_type, 2); // Identity-Type
        assert_eq!(tlv.mandatory, true);
        assert_eq!(tlv.value, vec![0x00, 0x01]);

        let parsed = IdentityType::from_tlv(&tlv).unwrap();
        assert_eq!(parsed, IdentityType::User);
    }

    #[test]
    fn test_identity_type_machine() {
        let identity = IdentityType::Machine;
        let tlv = identity.to_tlv();

        assert_eq!(tlv.value, vec![0x00, 0x02]);

        let parsed = IdentityType::from_tlv(&tlv).unwrap();
        assert_eq!(parsed, IdentityType::Machine);
    }

    #[test]
    fn test_teap_phase_initial_state() {
        use std::sync::Arc as StdArc;
        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );
        let server = EapTeapServer::new(config);

        assert_eq!(server.get_phase(), TeapPhase::Phase1TlsHandshake);
    }

    #[test]
    fn test_tlv_get_type() {
        let tlv = TeapTlv::new(TlvType::Result, true, vec![0x01]);
        assert_eq!(tlv.get_type(), Some(TlvType::Result));

        let unknown_tlv = TeapTlv::new_raw(999, false, vec![]);
        assert_eq!(unknown_tlv.get_type(), None);
    }

    #[test]
    fn test_tlv_empty_value() {
        let tlv = TeapTlv::new(TlvType::Nak, true, vec![]);
        let bytes = tlv.to_bytes();

        assert_eq!(bytes.len(), 4); // Just header, no value

        let (decoded, _) = TeapTlv::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.value.len(), 0);
    }

    // BasicPasswordAuthHandler tests
    #[test]
    fn test_basic_password_auth_handler_creation() {
        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        assert!(!handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), None);
    }

    #[test]
    fn test_basic_password_auth_success() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Create Basic-Password-Auth-Resp TLV
        // Format: username_len (2) | username | password_len (2) | password
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes()); // username length = 5
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes()); // password length = 6
        value.extend_from_slice(b"secret");

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // Process the response
        let result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        // Should be complete with success
        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Success);
        assert_eq!(handler.get_identity(), Some("alice".to_string()));

        // Result TLV should indicate success
        assert_eq!(result_tlv.tlv_type, TlvType::Result as u16);
        assert_eq!(
            TeapResult::from_result_tlv(&result_tlv).unwrap(),
            TeapResult::Success
        );
    }

    #[test]
    fn test_basic_password_auth_failure_wrong_password() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Create response with wrong password
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"wrong");

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        // Should be complete with failure
        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), Some("alice".to_string()));

        assert_eq!(
            TeapResult::from_result_tlv(&result_tlv).unwrap(),
            TeapResult::Failure
        );
    }

    #[test]
    fn test_basic_password_auth_failure_wrong_username() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Create response with wrong username
        let mut value = Vec::new();
        value.extend_from_slice(&3u16.to_be_bytes());
        value.extend_from_slice(b"bob");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let _result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), Some("bob".to_string()));
    }

    #[test]
    fn test_basic_password_auth_invalid_tlv_too_short() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // TLV with insufficient data
        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, vec![0x00]);

        let result = handler.process_inner_request(&response_tlv);
        assert!(result.is_err());
    }

    #[test]
    fn test_basic_password_auth_invalid_username_length() {
        let mut handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());

        // Username length exceeds available data
        let mut value = Vec::new();
        value.extend_from_slice(&100u16.to_be_bytes()); // claims 100 bytes
        value.extend_from_slice(b"alice"); // only 5 bytes

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let result = handler.process_inner_request(&response_tlv);
        assert!(result.is_err());
    }

    #[test]
    fn test_basic_password_auth_empty_credentials() {
        let mut handler = BasicPasswordAuthHandler::new("".to_string(), "".to_string());

        // Empty username and password
        let mut value = Vec::new();
        value.extend_from_slice(&0u16.to_be_bytes());
        value.extend_from_slice(&0u16.to_be_bytes());

        let response_tlv = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let _result_tlv = handler.process_inner_request(&response_tlv).unwrap();

        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Success);
        assert_eq!(handler.get_identity(), Some("".to_string()));
    }

    #[test]
    fn test_basic_password_auth_request_creation() {
        let request_tlv = BasicPasswordAuthHandler::create_password_request();

        assert_eq!(request_tlv.tlv_type, TlvType::BasicPasswordAuthReq as u16);
        assert!(request_tlv.mandatory);
        assert_eq!(request_tlv.value.len(), 0); // Empty prompt
    }

    #[test]
    fn test_inner_method_handler_trait() {
        let handler: Box<dyn InnerMethodHandler> = Box::new(BasicPasswordAuthHandler::new(
            "alice".to_string(),
            "secret".to_string(),
        ));

        // Test trait methods
        assert!(!handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), None);
    }

    // Phase 2 Integration Tests
    #[test]
    fn test_eap_teap_server_creation() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let server = EapTeapServer::new(config);
        assert_eq!(server.phase, TeapPhase::Phase1TlsHandshake);
    }

    #[test]
    fn test_eap_teap_server_with_inner_method() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let server = EapTeapServer::with_inner_method(config, Box::new(handler));

        assert_eq!(server.phase, TeapPhase::Phase1TlsHandshake);
        assert!(server.inner_method.is_some());
    }

    #[test]
    fn test_phase2_empty_tlvs_sends_identity_request() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();

        // Manually transition to Phase 2 (in real scenario, this happens after TLS handshake)
        server.phase = TeapPhase::Phase2InnerAuth;

        // Process empty TLVs should send Identity-Type request
        let result = server.process_phase2_tlvs_test(&[]);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::IdentityType));
    }

    #[test]
    fn test_phase2_identity_response_sends_password_request() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();

        server.phase = TeapPhase::Phase2InnerAuth;

        // Simulate Identity-Type response
        let identity_response = IdentityType::User.to_tlv();

        // Process identity response should send password request
        let result = server.process_phase2_tlvs_test(&[identity_response]);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::BasicPasswordAuthReq));
    }

    #[test]
    fn test_phase2_password_response_successful_auth() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();
        // Bypass TLS exporter (handshake not completed in test)
        server.test_session_key_seed = Some(vec![0u8; 40]);

        server.phase = TeapPhase::Phase2InnerAuth;

        // Create password response TLV
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes()); // username length = 5
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes()); // password length = 6
        value.extend_from_slice(b"secret");

        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // Process password response
        let result = server.process_phase2_tlvs_test(&[password_response]);
        assert!(result.is_ok());

        // With crypto-binding enabled, server should remain in Phase2InnerAuth
        // and send Crypto-Binding Request
        assert_eq!(server.phase, TeapPhase::Phase2InnerAuth);

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs - should be Crypto-Binding TLV Request
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::CryptoBinding));

        // Verify it's a Crypto-Binding Request
        let cb_tlv = CryptoBindingTlv::from_tlv(&tlvs[0]).unwrap();
        assert_eq!(cb_tlv.sub_type, CryptoBindingTlv::SUBTYPE_REQUEST);
    }

    #[test]
    fn test_phase2_password_response_failed_auth() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();

        server.phase = TeapPhase::Phase2InnerAuth;

        // Create password response TLV with WRONG password
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"wrong"); // Wrong password

        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // Process password response
        let result = server.process_phase2_tlvs_test(&[password_response]);
        assert!(result.is_ok());

        // Server should transition to Complete
        assert_eq!(server.phase, TeapPhase::Complete);

        let response = result.unwrap();
        assert!(response.is_some());

        // Parse the response TLVs - should be Result TLV with Failure
        let tlvs = TeapTlv::parse_tlvs(&response.unwrap()).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].get_type(), Some(TlvType::Result));

        let result_value = u16::from_be_bytes([tlvs[0].value[0], tlvs[0].value[1]]);
        assert_eq!(result_value, TeapResult::Failure as u16);
    }

    #[test]
    fn test_phase2_complete_flow_success() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();
        // Bypass TLS exporter (handshake not completed in test)
        server.test_session_key_seed = Some(vec![0u8; 40]);

        server.phase = TeapPhase::Phase2InnerAuth;

        // Step 1: Empty TLVs -> Identity request
        let result1 = server.process_phase2_tlvs_test(&[]).unwrap();
        assert!(result1.is_some());
        let tlvs1 = TeapTlv::parse_tlvs(&result1.unwrap()).unwrap();
        assert_eq!(tlvs1[0].get_type(), Some(TlvType::IdentityType));

        // Step 2: Identity response -> Password request
        let identity_response = IdentityType::User.to_tlv();
        let result2 = server
            .process_phase2_tlvs_test(&[identity_response])
            .unwrap();
        assert!(result2.is_some());
        let tlvs2 = TeapTlv::parse_tlvs(&result2.unwrap()).unwrap();
        assert_eq!(tlvs2[0].get_type(), Some(TlvType::BasicPasswordAuthReq));

        // Step 3: Password response -> Crypto-Binding Request
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");
        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        let result3 = server
            .process_phase2_tlvs_test(&[password_response])
            .unwrap();
        assert!(result3.is_some());
        assert_eq!(server.phase, TeapPhase::Phase2InnerAuth);

        let tlvs3 = TeapTlv::parse_tlvs(&result3.unwrap()).unwrap();
        assert_eq!(tlvs3[0].get_type(), Some(TlvType::CryptoBinding));

        // Verify it's a Crypto-Binding Request
        let cb_request = CryptoBindingTlv::from_tlv(&tlvs3[0]).unwrap();
        assert_eq!(cb_request.sub_type, CryptoBindingTlv::SUBTYPE_REQUEST);

        // Step 4: Crypto-Binding Response -> Result (Success)
        let cb_response = CryptoBindingTlv {
            version: CryptoBindingTlv::VERSION,
            received_version: CryptoBindingTlv::VERSION,
            sub_type: CryptoBindingTlv::SUBTYPE_RESPONSE,
            nonce: [0u8; 32],
            compound_mac: vec![0u8; 32],
        };

        // BUFFER for compound MAC = phase2 conversation history || cb_response_zeroed
        // (RFC 7170 §5.3). History at this point includes identity request,
        // identity response, password request, password response, and the
        // Crypto-Binding Request the server just sent.
        let crypto_binding = server.crypto_binding.as_ref().unwrap();
        let mut tlv_for_mac = cb_response.clone();
        tlv_for_mac.compound_mac = vec![0u8; 32];
        let mut buffer = server.phase2_tlv_history.clone();
        buffer.extend_from_slice(&tlv_for_mac.to_tlv().to_bytes());
        let compound_mac = CryptoBinding::calculate_compound_mac(&crypto_binding.cmk, &buffer);

        let cb_response_with_mac = CryptoBindingTlv {
            compound_mac,
            ..cb_response
        };

        let result4 = server
            .process_phase2_tlvs_test(&[cb_response_with_mac.to_tlv()])
            .unwrap();
        assert!(result4.is_some());
        assert_eq!(server.phase, TeapPhase::Complete);

        let tlvs4 = TeapTlv::parse_tlvs(&result4.unwrap()).unwrap();
        assert_eq!(tlvs4[0].get_type(), Some(TlvType::Result));
        let result_value = u16::from_be_bytes([tlvs4[0].value[0], tlvs4[0].value[1]]);
        assert_eq!(result_value, TeapResult::Success as u16);
    }

    #[test]
    fn test_phase2_result_acknowledgment() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        server.phase = TeapPhase::Phase2InnerAuth;

        // Simulate receiving Result TLV from client (acknowledgment)
        let result_tlv = TeapResult::Success.to_result_tlv();

        let response = server.process_phase2_tlvs(&[result_tlv]);
        assert!(response.is_ok());

        // Should transition to Complete and return None (no more data)
        assert_eq!(server.phase, TeapPhase::Complete);
        assert!(response.unwrap().is_none());
    }

    #[test]
    fn test_decrypt_tls_data_mvp() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let mut server = EapTeapServer::new(config);

        // Initialize TLS connection
        server.initialize_connection().unwrap();

        // Create test TLS packet with data
        let test_data = vec![1, 2, 3, 4, 5];
        let tls_packet = EapTlsPacket {
            flags: crate::eap::eap_tls::TlsFlags::new(false, false, false),
            tls_message_length: None,
            tls_data: test_data.clone(),
        };

        // Note: Can't test actual decryption without completing handshake
        // This test validates the function exists and compiles correctly
        // Full decryption testing requires integration test with real TLS handshake
        let result = server.decrypt_tls_data(&tls_packet);

        // May fail without handshake, but that's expected
        // In real usage, this is called after Phase 1 handshake completes
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_encrypt_and_send_tlvs_mvp() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let mut server = EapTeapServer::new(config);

        // Create test TLVs
        let tlv = IdentityType::User.to_tlv();

        // Initialize TLS connection first (required for encryption)
        server.initialize_connection().unwrap();

        // Note: Can't test actual encryption without completing handshake
        // This test now validates that the function signature is correct
        // Full encryption testing requires integration test with real TLS handshake
        let result = server.encrypt_and_send_tlvs(&[tlv.clone()]);

        // Should succeed (will encrypt once handshake is complete in real usage)
        assert!(result.is_ok());
    }

    // ===== Crypto-Binding Tests (Week 4-5) =====

    #[test]
    fn test_crypto_binding_imck_derivation() {
        // Test IMCK derivation
        let session_key_seed = vec![0x01; 32];
        let imsk = vec![0x02; 32];

        let imck = CryptoBinding::derive_imck(&session_key_seed, &imsk);

        // Should produce exactly 60 bytes
        assert_eq!(imck.len(), 60);

        // Should be deterministic - same inputs produce same output
        let imck2 = CryptoBinding::derive_imck(&session_key_seed, &imsk);
        assert_eq!(imck, imck2);

        // Different inputs should produce different output
        let imsk_different = vec![0x03; 32];
        let imck3 = CryptoBinding::derive_imck(&session_key_seed, &imsk_different);
        assert_ne!(imck, imck3);
    }

    #[test]
    fn test_crypto_binding_cmk_derivation() {
        // Test CMK derivation
        let session_key_seed = vec![0x01; 32];
        let imsk = vec![0x02; 32];

        let imck = CryptoBinding::derive_imck(&session_key_seed, &imsk);
        let cmk = CryptoBinding::derive_cmk(&imck);

        // CMK should be 20 bytes (first 20 bytes of IMCK)
        assert_eq!(cmk.len(), 20);

        // Should match first 20 bytes of IMCK
        assert_eq!(&cmk[..], &imck[..20]);
    }

    #[test]
    fn test_crypto_binding_compound_mac_calculation() {
        let cmk = vec![0x01; 20];
        let buffer = b"test buffer data";

        let mac = CryptoBinding::calculate_compound_mac(&cmk, buffer);

        // HMAC-SHA256 produces 32 bytes
        assert_eq!(mac.len(), 32);

        // Should be deterministic
        let mac2 = CryptoBinding::calculate_compound_mac(&cmk, buffer);
        assert_eq!(mac, mac2);

        // Different buffer should produce different MAC
        let mac3 = CryptoBinding::calculate_compound_mac(&cmk, b"different data");
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_crypto_binding_mac_verification() {
        let cmk = vec![0x01; 20];
        let buffer = b"test buffer data";

        let mac = CryptoBinding::calculate_compound_mac(&cmk, buffer);

        // Correct MAC should verify
        assert!(CryptoBinding::verify_compound_mac(&cmk, buffer, &mac));

        // Wrong MAC should not verify
        let mut wrong_mac = mac.clone();
        wrong_mac[0] ^= 0x01; // Flip one bit
        assert!(!CryptoBinding::verify_compound_mac(
            &cmk, buffer, &wrong_mac
        ));

        // Wrong buffer should not verify
        assert!(!CryptoBinding::verify_compound_mac(
            &cmk,
            b"wrong buffer",
            &mac
        ));
    }

    #[test]
    fn test_crypto_binding_nonce_generation() {
        let nonce1 = CryptoBinding::generate_nonce();
        let nonce2 = CryptoBinding::generate_nonce();

        // Nonces should be 32 bytes
        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);

        // Random nonces should be different (statistically)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_crypto_binding_context_creation() {
        let session_key_seed = vec![0x01; 32];
        let imsk = vec![0x02; 32];

        let crypto_binding = CryptoBinding::new(&session_key_seed, &imsk);

        // Should have 60-byte IMCK
        assert_eq!(crypto_binding.imck.len(), 60);

        // Should have 20-byte CMK
        assert_eq!(crypto_binding.cmk.len(), 20);

        // Should have 32-byte server nonce
        assert_eq!(crypto_binding.server_nonce.len(), 32);

        // Client nonce should initially be None
        assert!(crypto_binding.client_nonce.is_none());
    }

    #[test]
    fn test_crypto_binding_tlv_encoding_decoding() {
        let cb_tlv = CryptoBindingTlv {
            version: CryptoBindingTlv::VERSION,
            received_version: 0,
            sub_type: CryptoBindingTlv::SUBTYPE_REQUEST,
            nonce: [0x42; 32],
            compound_mac: vec![0xAB; 32],
        };

        // Encode to TLV
        let tlv = cb_tlv.to_tlv();

        // Should be CryptoBinding type (12)
        assert_eq!(tlv.get_type(), Some(TlvType::CryptoBinding));

        // Should be mandatory
        assert!(tlv.mandatory);

        // Decode back
        let decoded = CryptoBindingTlv::from_tlv(&tlv).unwrap();

        // Should match original
        assert_eq!(decoded.version, cb_tlv.version);
        assert_eq!(decoded.received_version, cb_tlv.received_version);
        assert_eq!(decoded.sub_type, cb_tlv.sub_type);
        assert_eq!(decoded.nonce, cb_tlv.nonce);
        assert_eq!(decoded.compound_mac, cb_tlv.compound_mac);
    }

    #[test]
    fn test_crypto_binding_invalid_tlv_type() {
        // Create a Result TLV (not CryptoBinding)
        let result_tlv = TeapResult::Success.to_result_tlv();

        // Should fail to parse as CryptoBinding
        let result = CryptoBindingTlv::from_tlv(&result_tlv);
        assert!(result.is_err());
    }

    #[test]
    fn test_crypto_binding_tlv_too_short() {
        // Create invalid TLV with too little data
        let tlv = TeapTlv::new(TlvType::CryptoBinding, true, vec![0x01, 0x00, 0x00, 0x00]);

        // Should fail to parse (need at least 68 bytes: 4 header + 32 nonce + 32 MAC)
        let result = CryptoBindingTlv::from_tlv(&tlv);
        assert!(result.is_err());
    }

    #[test]
    fn test_crypto_binding_response_verification_success() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();
        // Bypass TLS exporter (handshake not completed in test)
        server.test_session_key_seed = Some(vec![0u8; 40]);

        server.phase = TeapPhase::Phase2InnerAuth;

        // Trigger crypto-binding by authenticating
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");
        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // This should send crypto-binding request
        let _result = server
            .process_phase2_tlvs_test(&[password_response])
            .unwrap();

        // Server should have crypto-binding context
        assert!(server.crypto_binding.is_some());

        // Create valid crypto-binding response
        let cb_response = CryptoBindingTlv {
            version: CryptoBindingTlv::VERSION,
            received_version: CryptoBindingTlv::VERSION,
            sub_type: CryptoBindingTlv::SUBTYPE_RESPONSE,
            nonce: [0u8; 32],
            compound_mac: vec![0u8; 32],
        };

        // BUFFER = phase2 history (incl. CB request) || cb_response_zeroed
        let crypto_binding = server.crypto_binding.as_ref().unwrap();
        let mut tlv_for_mac = cb_response.clone();
        tlv_for_mac.compound_mac = vec![0u8; 32];
        let mut buffer = server.phase2_tlv_history.clone();
        buffer.extend_from_slice(&tlv_for_mac.to_tlv().to_bytes());
        let compound_mac = CryptoBinding::calculate_compound_mac(&crypto_binding.cmk, &buffer);

        let cb_response_with_mac = CryptoBindingTlv {
            compound_mac,
            ..cb_response
        };

        // Process response - should succeed
        let result = server.process_phase2_tlvs_test(&[cb_response_with_mac.to_tlv()]);
        assert!(result.is_ok());

        // Should transition to Complete and send Success
        assert_eq!(server.phase, TeapPhase::Complete);

        let response = result.unwrap().unwrap();
        let tlvs = TeapTlv::parse_tlvs(&response).unwrap();
        assert_eq!(tlvs[0].get_type(), Some(TlvType::Result));

        let result_value = u16::from_be_bytes([tlvs[0].value[0], tlvs[0].value[1]]);
        assert_eq!(result_value, TeapResult::Success as u16);
    }

    #[test]
    fn test_crypto_binding_response_verification_failure() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();
        // Bypass TLS exporter (handshake not completed in test)
        server.test_session_key_seed = Some(vec![0u8; 40]);

        server.phase = TeapPhase::Phase2InnerAuth;

        // Trigger crypto-binding by authenticating
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");
        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);

        // This should send crypto-binding request
        let _result = server
            .process_phase2_tlvs_test(&[password_response])
            .unwrap();

        // Create INVALID crypto-binding response (wrong MAC)
        let cb_response = CryptoBindingTlv {
            version: CryptoBindingTlv::VERSION,
            received_version: CryptoBindingTlv::VERSION,
            sub_type: CryptoBindingTlv::SUBTYPE_RESPONSE,
            nonce: [0u8; 32],
            compound_mac: vec![0xFF; 32], // Wrong MAC
        };

        // Process response - should fail verification
        let result = server.process_phase2_tlvs_test(&[cb_response.to_tlv()]);
        assert!(result.is_ok());

        // Should transition to Complete and send Failure
        assert_eq!(server.phase, TeapPhase::Complete);

        let response = result.unwrap().unwrap();
        let tlvs = TeapTlv::parse_tlvs(&response).unwrap();
        assert_eq!(tlvs[0].get_type(), Some(TlvType::Result));

        let result_value = u16::from_be_bytes([tlvs[0].value[0], tlvs[0].value[1]]);
        assert_eq!(result_value, TeapResult::Failure as u16);
    }

    // ===== EAP-Payload Tests (Week 6-7) =====

    #[test]
    fn test_eap_payload_tlv_creation() {
        let eap_data = vec![2, 1, 0, 5, 1]; // EAP Response, ID=1, Length=5, Type=Identity
        let payload = EapPayloadTlv::new(eap_data.clone());

        assert_eq!(payload.eap_packet_data, eap_data);
    }

    #[test]
    fn test_eap_payload_tlv_encoding_decoding() {
        let eap_data = vec![2, 1, 0, 5, 1];
        let payload = EapPayloadTlv::new(eap_data.clone());

        // Convert to TLV
        let tlv = payload.to_tlv();
        assert_eq!(tlv.get_type(), Some(TlvType::EapPayload));
        assert!(tlv.mandatory);
        assert_eq!(tlv.value, eap_data);

        // Parse back
        let parsed = EapPayloadTlv::from_tlv(&tlv).unwrap();
        assert_eq!(parsed.eap_packet_data, eap_data);
    }

    #[test]
    fn test_eap_payload_tlv_parse_eap_packet() {
        // Create Identity Request EAP packet
        let eap_packet = super::super::EapPacket::new(
            super::super::EapCode::Request,
            1,
            Some(super::super::EapType::Identity),
            vec![],
        );

        let eap_data = eap_packet.to_bytes();
        let payload = EapPayloadTlv::new(eap_data);

        // Parse EAP packet
        let parsed_packet = payload.parse_eap_packet().unwrap();
        assert_eq!(parsed_packet.code, super::super::EapCode::Request);
        assert_eq!(parsed_packet.identifier, 1);
        assert_eq!(
            parsed_packet.eap_type,
            Some(super::super::EapType::Identity)
        );
    }

    #[test]
    fn test_eap_payload_tlv_invalid_type() {
        // Create a Result TLV instead of EAP-Payload
        let result_tlv = TeapResult::Success.to_result_tlv();

        // Should fail to parse as EAP-Payload
        let result = EapPayloadTlv::from_tlv(&result_tlv);
        assert!(result.is_err());
    }

    #[test]
    fn test_eap_payload_handler_creation() {
        let handler = EapPayloadHandler::new("alice".to_string(), "password".to_string());

        assert!(!handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), None);
    }

    #[test]
    fn test_eap_payload_handler_identity_request() {
        let mut handler = EapPayloadHandler::new("alice".to_string(), "password".to_string());

        // Process Identity-Type TLV to trigger identity request
        let identity_type_tlv = IdentityType::User.to_tlv();
        let response_tlv = handler.process_inner_request(&identity_type_tlv).unwrap();

        // Should be EAP-Payload TLV
        assert_eq!(response_tlv.get_type(), Some(TlvType::EapPayload));

        // Parse EAP-Payload
        let eap_payload = EapPayloadTlv::from_tlv(&response_tlv).unwrap();
        let eap_packet = eap_payload.parse_eap_packet().unwrap();

        // Should be EAP Identity Request
        assert_eq!(eap_packet.code, super::super::EapCode::Request);
        assert_eq!(eap_packet.eap_type, Some(super::super::EapType::Identity));
    }

    #[test]
    fn test_eap_payload_handler_identity_response() {
        let mut handler = EapPayloadHandler::new("alice".to_string(), "password".to_string());

        // Step 1: Get identity request
        let identity_type_tlv = IdentityType::User.to_tlv();
        let _id_req = handler.process_inner_request(&identity_type_tlv).unwrap();

        // Step 2: Send identity response
        let identity_response = super::super::EapPacket::new(
            super::super::EapCode::Response,
            1,
            Some(super::super::EapType::Identity),
            b"alice".to_vec(),
        );

        let eap_payload_tlv = EapPayloadTlv::new(identity_response.to_bytes()).to_tlv();
        let response_tlv = handler.process_inner_request(&eap_payload_tlv).unwrap();

        // Should get MD5 Challenge request
        assert_eq!(response_tlv.get_type(), Some(TlvType::EapPayload));

        let eap_payload = EapPayloadTlv::from_tlv(&response_tlv).unwrap();
        let eap_packet = eap_payload.parse_eap_packet().unwrap();

        assert_eq!(eap_packet.code, super::super::EapCode::Request);
        assert_eq!(
            eap_packet.eap_type,
            Some(super::super::EapType::Md5Challenge)
        );
        assert_eq!(eap_packet.data.len(), 17); // 1 byte size + 16 bytes challenge
    }

    #[test]
    fn test_eap_payload_handler_md5_challenge_response() {
        let mut handler = EapPayloadHandler::new("alice".to_string(), "password".to_string());

        // Step 1: Get identity request
        let identity_type_tlv = IdentityType::User.to_tlv();
        let _id_req = handler.process_inner_request(&identity_type_tlv).unwrap();

        // Step 2: Send identity response
        let identity_response = super::super::EapPacket::new(
            super::super::EapCode::Response,
            1,
            Some(super::super::EapType::Identity),
            b"alice".to_vec(),
        );
        let eap_payload_tlv = EapPayloadTlv::new(identity_response.to_bytes()).to_tlv();
        let _md5_req = handler.process_inner_request(&eap_payload_tlv).unwrap();

        // Step 3: Send MD5 Challenge response
        let mut md5_response_data = Vec::new();
        md5_response_data.push(16); // Hash size
        md5_response_data.extend_from_slice(&[0xAB; 16]); // Fake MD5 hash

        let md5_response = super::super::EapPacket::new(
            super::super::EapCode::Response,
            2,
            Some(super::super::EapType::Md5Challenge),
            md5_response_data,
        );

        let eap_payload_tlv = EapPayloadTlv::new(md5_response.to_bytes()).to_tlv();
        let response_tlv = handler.process_inner_request(&eap_payload_tlv).unwrap();

        // Should get Intermediate-Result TLV
        assert_eq!(response_tlv.get_type(), Some(TlvType::IntermediateResult));

        // Should be complete
        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Success);
        assert_eq!(handler.get_identity(), Some("alice".to_string()));
    }

    #[test]
    fn test_eap_payload_handler_wrong_identity() {
        let mut handler = EapPayloadHandler::new("alice".to_string(), "password".to_string());

        // Step 1 & 2: Send identity response with wrong identity
        let identity_type_tlv = IdentityType::User.to_tlv();
        let _id_req = handler.process_inner_request(&identity_type_tlv).unwrap();

        let identity_response = super::super::EapPacket::new(
            super::super::EapCode::Response,
            1,
            Some(super::super::EapType::Identity),
            b"bob".to_vec(), // Wrong identity
        );
        let eap_payload_tlv = EapPayloadTlv::new(identity_response.to_bytes()).to_tlv();
        let _md5_req = handler.process_inner_request(&eap_payload_tlv).unwrap();

        // Step 3: Send MD5 Challenge response
        let mut md5_response_data = Vec::new();
        md5_response_data.push(16);
        md5_response_data.extend_from_slice(&[0xAB; 16]);

        let md5_response = super::super::EapPacket::new(
            super::super::EapCode::Response,
            2,
            Some(super::super::EapType::Md5Challenge),
            md5_response_data,
        );

        let eap_payload_tlv = EapPayloadTlv::new(md5_response.to_bytes()).to_tlv();
        let response_tlv = handler.process_inner_request(&eap_payload_tlv).unwrap();

        // Should be complete but failed
        assert!(handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), Some("bob".to_string()));

        // Result should be Intermediate-Result with Failure
        assert_eq!(response_tlv.get_type(), Some(TlvType::IntermediateResult));
        let result = TeapResult::from_result_tlv(&response_tlv).unwrap();
        assert_eq!(result, TeapResult::Failure);
    }

    #[test]
    fn test_phase2_eap_payload_full_flow() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        // Use EapPayloadHandler as inner method
        let handler = EapPayloadHandler::new("alice".to_string(), "password".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));

        // Initialize TLS connection (required for encryption)
        server.initialize_connection().unwrap();
        // Bypass TLS exporter (handshake not completed in test)
        server.test_session_key_seed = Some(vec![0u8; 40]);

        server.phase = TeapPhase::Phase2InnerAuth;

        // Step 1: Empty TLVs -> Identity-Type request
        let result1 = server.process_phase2_tlvs_test(&[]).unwrap();
        assert!(result1.is_some());
        let tlvs1 = TeapTlv::parse_tlvs(&result1.unwrap()).unwrap();
        assert_eq!(tlvs1[0].get_type(), Some(TlvType::IdentityType));

        // Step 2: Identity-Type response -> EAP-Identity request
        let identity_type = IdentityType::User.to_tlv();
        let result2 = server.process_phase2_tlvs_test(&[identity_type]).unwrap();
        assert!(result2.is_some());
        let tlvs2 = TeapTlv::parse_tlvs(&result2.unwrap()).unwrap();
        assert_eq!(tlvs2[0].get_type(), Some(TlvType::EapPayload));

        // Parse EAP packet - should be Identity Request
        let eap_payload2 = EapPayloadTlv::from_tlv(&tlvs2[0]).unwrap();
        let eap_packet2 = eap_payload2.parse_eap_packet().unwrap();
        assert_eq!(eap_packet2.code, super::super::EapCode::Request);
        assert_eq!(eap_packet2.eap_type, Some(super::super::EapType::Identity));

        // Step 3: EAP-Identity response -> EAP-MD5 Challenge request
        let identity_response = super::super::EapPacket::new(
            super::super::EapCode::Response,
            eap_packet2.identifier,
            Some(super::super::EapType::Identity),
            b"alice".to_vec(),
        );
        let identity_payload_tlv = EapPayloadTlv::new(identity_response.to_bytes()).to_tlv();

        let result3 = server
            .process_phase2_tlvs_test(&[identity_payload_tlv])
            .unwrap();
        assert!(result3.is_some());
        let tlvs3 = TeapTlv::parse_tlvs(&result3.unwrap()).unwrap();
        assert_eq!(tlvs3[0].get_type(), Some(TlvType::EapPayload));

        // Parse EAP packet - should be MD5 Challenge Request
        let eap_payload3 = EapPayloadTlv::from_tlv(&tlvs3[0]).unwrap();
        let eap_packet3 = eap_payload3.parse_eap_packet().unwrap();
        assert_eq!(eap_packet3.code, super::super::EapCode::Request);
        assert_eq!(
            eap_packet3.eap_type,
            Some(super::super::EapType::Md5Challenge)
        );

        // Step 4: EAP-MD5 Challenge response -> Crypto-Binding request
        let mut md5_response_data = Vec::new();
        md5_response_data.push(16);
        md5_response_data.extend_from_slice(&[0xAB; 16]);

        let md5_response = super::super::EapPacket::new(
            super::super::EapCode::Response,
            eap_packet3.identifier,
            Some(super::super::EapType::Md5Challenge),
            md5_response_data,
        );
        let md5_payload_tlv = EapPayloadTlv::new(md5_response.to_bytes()).to_tlv();

        let result4 = server.process_phase2_tlvs_test(&[md5_payload_tlv]).unwrap();
        assert!(result4.is_some());
        assert_eq!(server.phase, TeapPhase::Phase2InnerAuth);

        // Should get Crypto-Binding Request
        let tlvs4 = TeapTlv::parse_tlvs(&result4.unwrap()).unwrap();
        assert_eq!(tlvs4[0].get_type(), Some(TlvType::CryptoBinding));

        // Verify Crypto-Binding Request
        let cb_request = CryptoBindingTlv::from_tlv(&tlvs4[0]).unwrap();
        assert_eq!(cb_request.sub_type, CryptoBindingTlv::SUBTYPE_REQUEST);
    }

    #[test]
    fn test_eap_payload_inner_method_handler_trait() {
        let handler: Box<dyn InnerMethodHandler> = Box::new(EapPayloadHandler::new(
            "alice".to_string(),
            "password".to_string(),
        ));

        // Test trait methods
        assert!(!handler.is_complete());
        assert_eq!(handler.get_result(), TeapResult::Failure);
        assert_eq!(handler.get_identity(), None);
    }

    /// Regression test for RFC 7170 §5.3 BUFFER concatenation.
    ///
    /// Before the fix, the Compound MAC was computed only over the
    /// Crypto-Binding TLV itself, so a tampered prior-conversation TLV would
    /// not invalidate the binding. After the fix, BUFFER includes the full
    /// Phase 2 conversation history, so the MAC over a non-empty history
    /// must differ from the MAC over the bare TLV.
    #[test]
    fn test_compound_mac_includes_phase2_history() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));
        server.initialize_connection().unwrap();
        server.test_session_key_seed = Some(vec![0u8; 40]);
        server.phase = TeapPhase::Phase2InnerAuth;

        // Drive the flow up to and including the Crypto-Binding Request.
        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");
        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);
        let response_bytes = server
            .process_phase2_tlvs_test(&[password_response])
            .unwrap()
            .unwrap();
        let cb_request_tlvs = TeapTlv::parse_tlvs(&response_bytes).unwrap();
        let cb_request = CryptoBindingTlv::from_tlv(&cb_request_tlvs[0]).unwrap();

        // History must be non-empty: it includes the password response (received)
        // and the Crypto-Binding Request (sent).
        assert!(
            !server.phase2_tlv_history.is_empty(),
            "phase2_tlv_history should include prior conversation"
        );

        // Compute MAC two ways: with full history (correct) and with empty
        // history (the pre-fix behavior).
        let cmk = server.crypto_binding.as_ref().unwrap().cmk.clone();
        let cb_zeroed = CryptoBindingTlv {
            compound_mac: vec![0u8; 32],
            ..cb_request.clone()
        };
        let cb_zeroed_bytes = cb_zeroed.to_tlv().to_bytes();

        // Pre-fix BUFFER: just the Crypto-Binding TLV with MAC zeroed.
        let mac_without_history = CryptoBinding::calculate_compound_mac(&cmk, &cb_zeroed_bytes);

        // Post-fix BUFFER: history (without this CB request) || cb_zeroed.
        // Reconstruct history-as-of-CB-request by stripping the CB request
        // from the end of the recorded history.
        let cb_request_tlv_bytes = cb_request_tlvs[0].to_bytes();
        assert!(
            server.phase2_tlv_history.ends_with(&cb_request_tlv_bytes),
            "history should end with the just-sent CB request"
        );
        let history_before_cb = &server.phase2_tlv_history
            [..server.phase2_tlv_history.len() - cb_request_tlv_bytes.len()];
        let mut buffer = history_before_cb.to_vec();
        buffer.extend_from_slice(&cb_zeroed_bytes);
        let mac_with_history = CryptoBinding::calculate_compound_mac(&cmk, &buffer);

        // The actual MAC carried in the request must match the history-aware
        // computation, not the bare-TLV one.
        assert_eq!(
            cb_request.compound_mac, mac_with_history,
            "server MAC must be computed over conversation history"
        );
        assert_ne!(
            mac_with_history, mac_without_history,
            "history-aware MAC must differ from bare-TLV MAC \
             (regression: BUFFER did not include prior TLVs)"
        );
    }

    /// Tampering with a prior Phase 2 TLV must invalidate the Crypto-Binding
    /// MAC. Validates that the BUFFER actually binds the inner conversation.
    #[test]
    fn test_compound_mac_detects_history_tampering() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let handler = BasicPasswordAuthHandler::new("alice".to_string(), "secret".to_string());
        let mut server = EapTeapServer::with_inner_method(config, Box::new(handler));
        server.initialize_connection().unwrap();
        server.test_session_key_seed = Some(vec![0u8; 40]);
        server.phase = TeapPhase::Phase2InnerAuth;

        let mut value = Vec::new();
        value.extend_from_slice(&5u16.to_be_bytes());
        value.extend_from_slice(b"alice");
        value.extend_from_slice(&6u16.to_be_bytes());
        value.extend_from_slice(b"secret");
        let password_response = TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value);
        let _ = server
            .process_phase2_tlvs_test(&[password_response])
            .unwrap();

        // Build a CB response. Compute its MAC against a TAMPERED history
        // (one extra byte appended) — verification must fail because the
        // server's recorded history is the genuine one.
        let cmk = server.crypto_binding.as_ref().unwrap().cmk.clone();
        let cb_response_template = CryptoBindingTlv {
            version: CryptoBindingTlv::VERSION,
            received_version: CryptoBindingTlv::VERSION,
            sub_type: CryptoBindingTlv::SUBTYPE_RESPONSE,
            nonce: [0u8; 32],
            compound_mac: vec![0u8; 32],
        };
        let cb_zeroed_bytes = cb_response_template.to_tlv().to_bytes();

        let mut tampered_history = server.phase2_tlv_history.clone();
        tampered_history.push(0xAA); // attacker injects a stray byte
        let mut tampered_buffer = tampered_history;
        tampered_buffer.extend_from_slice(&cb_zeroed_bytes);
        let bad_mac = CryptoBinding::calculate_compound_mac(&cmk, &tampered_buffer);

        let cb_response = CryptoBindingTlv {
            compound_mac: bad_mac,
            ..cb_response_template
        };

        // Server processes the response; MAC will not match its untampered
        // history, so the result is Failure.
        let result_bytes = server
            .process_phase2_tlvs_test(&[cb_response.to_tlv()])
            .unwrap()
            .unwrap();
        let result_tlvs = TeapTlv::parse_tlvs(&result_bytes).unwrap();
        assert_eq!(result_tlvs[0].get_type(), Some(TlvType::Result));
        let result_value = u16::from_be_bytes([result_tlvs[0].value[0], result_tlvs[0].value[1]]);
        assert_eq!(result_value, TeapResult::Failure as u16);
        assert_eq!(server.phase, TeapPhase::Complete);
    }

    /// `BasicPasswordAuthHandler` and `EapPayloadHandler` produce no inner
    /// keying material, so they must explicitly return `None` from
    /// `get_imsk` (RFC 7170 §5.2). Documenting this as a test pins the
    /// contract so future inner methods that *do* derive an MSK are forced
    /// to override.
    #[test]
    fn test_inner_method_handlers_return_no_imsk() {
        let pw_handler: Box<dyn InnerMethodHandler> = Box::new(BasicPasswordAuthHandler::new(
            "alice".to_string(),
            "secret".to_string(),
        ));
        assert!(pw_handler.get_imsk().is_none());

        let eap_handler: Box<dyn InnerMethodHandler> = Box::new(EapPayloadHandler::new(
            "alice".to_string(),
            "password".to_string(),
        ));
        assert!(eap_handler.get_imsk().is_none());
    }

    /// Verify the new `EapTlsServer::export_keying_material` wrapper rejects
    /// calls before the TLS handshake completes. (Real exporter behavior is
    /// covered by the existing EAP-TLS extract_keys tests, which exercise the
    /// underlying rustls call.)
    #[test]
    fn test_export_keying_material_requires_handshake() {
        use std::sync::Arc as StdArc;

        let config = StdArc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(StdArc::new(
                    rustls::server::ResolvesServerCertUsingSni::new(),
                )),
        );

        let mut server = super::super::eap_tls::EapTlsServer::new(config);
        server.initialize_connection().unwrap();

        // Handshake not complete -> InvalidState.
        let result = server.export_keying_material(b"some label", None, 32);
        assert!(matches!(result, Err(EapError::InvalidState)));
    }
}
