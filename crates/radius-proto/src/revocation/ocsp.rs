//! OCSP (Online Certificate Status Protocol) Support - RFC 6960
//!
//! This module implements OCSP request building, response parsing, and validation
//! for real-time certificate revocation checking.
//!
//! # OCSP Protocol Overview
//!
//! OCSP provides a lightweight alternative to CRLs by allowing clients to query
//! the revocation status of individual certificates in real-time.
//!
//! ## Request/Response Flow:
//!
//! 1. **Build Request**: Create OCSPRequest with certificate serial number and issuer
//! 2. **HTTP POST**: Send DER-encoded request to OCSP responder URL
//! 3. **Parse Response**: Decode DER-encoded OCSPResponse
//! 4. **Validate**: Check signature, nonce, and certificate status
//! 5. **Cache**: Store validated response with TTL
//!
//! ## ASN.1 Structures (RFC 6960):
//!
//! ```asn1
//! OCSPRequest ::= SEQUENCE {
//!     tbsRequest      TBSRequest,
//!     optionalSignature   [0] EXPLICIT Signature OPTIONAL
//! }
//!
//! TBSRequest ::= SEQUENCE {
//!     version             [0] EXPLICIT Version DEFAULT v1,
//!     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
//!     requestList         SEQUENCE OF Request,
//!     requestExtensions   [2] EXPLICIT Extensions OPTIONAL
//! }
//!
//! Request ::= SEQUENCE {
//!     reqCert             CertID,
//!     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
//! }
//!
//! CertID ::= SEQUENCE {
//!     hashAlgorithm       AlgorithmIdentifier,
//!     issuerNameHash      OCTET STRING,
//!     issuerKeyHash       OCTET STRING,
//!     serialNumber        INTEGER
//! }
//!
//! OCSPResponse ::= SEQUENCE {
//!     responseStatus      OCSPResponseStatus,
//!     responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL
//! }
//!
//! BasicOCSPResponse ::= SEQUENCE {
//!     tbsResponseData     ResponseData,
//!     signatureAlgorithm  AlgorithmIdentifier,
//!     signature           BIT STRING,
//!     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
//! }
//!
//! SingleResponse ::= SEQUENCE {
//!     certID              CertID,
//!     certStatus          CertStatus,
//!     thisUpdate          GeneralizedTime,
//!     nextUpdate          [0] EXPLICIT GeneralizedTime OPTIONAL,
//!     singleExtensions    [1] EXPLICIT Extensions OPTIONAL
//! }
//!
//! CertStatus ::= CHOICE {
//!     good                [0] IMPLICIT NULL,
//!     revoked             [1] IMPLICIT RevokedInfo,
//!     unknown             [2] IMPLICIT UnknownInfo
//! }
//! ```
//!
//! # Implementation Strategy
//!
//! For Phase 1 (MVP), we'll use the `x509-parser` crate which already has some
//! OCSP support. For full control in Phase 2, we may migrate to `der` crate.
//!
//! **Dependencies**:
//! - `x509-parser`: OCSP response parsing (already in workspace)
//! - `sha2`: SHA-256/SHA-1 hashing for CertID
//! - `reqwest`: HTTP POST to OCSP responder (already in workspace)
//!
//! **Not needed** (x509-parser handles):
//! - Manual ASN.1 DER encoding/decoding
//! - Certificate parsing

use crate::revocation::error::RevocationError;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;

/// OCSP response status (RFC 6960 Section 2.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseStatus {
    /// Response has valid confirmations
    Successful = 0,
    /// Illegal confirmation request
    MalformedRequest = 1,
    /// Internal error in issuer
    InternalError = 2,
    /// Try again later
    TryLater = 3,
    /// Must sign the request
    SigRequired = 5,
    /// Request unauthorized
    Unauthorized = 6,
}

impl OcspResponseStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Successful),
            1 => Some(Self::MalformedRequest),
            2 => Some(Self::InternalError),
            3 => Some(Self::TryLater),
            5 => Some(Self::SigRequired),
            6 => Some(Self::Unauthorized),
            _ => None,
        }
    }
}

/// Certificate status in OCSP response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateStatus {
    /// Certificate is not revoked
    Good,
    /// Certificate has been revoked
    Revoked {
        /// Revocation time
        revocation_time: SystemTime,
        /// Revocation reason (if present)
        reason: Option<u8>,
    },
    /// Certificate status is unknown
    Unknown,
}

/// OCSP request builder
///
/// Builds a minimal unsigned OCSP request for a single certificate.
/// For production use, this will be extended to support:
/// - Request signing (optional)
/// - Nonce extension (replay protection)
/// - Multiple certificates in one request
pub struct OcspRequestBuilder {
    /// Certificate serial number to check
    serial_number: Vec<u8>,
    /// Issuer name hash (SHA-256)
    issuer_name_hash: Vec<u8>,
    /// Issuer public key hash (SHA-256)
    issuer_key_hash: Vec<u8>,
    /// Optional nonce for replay protection
    nonce: Option<Vec<u8>>,
}

impl OcspRequestBuilder {
    /// Create a new OCSP request builder
    ///
    /// # Arguments
    /// * `cert` - The certificate to check (DER-encoded)
    /// * `issuer` - The issuer certificate (DER-encoded)
    ///
    /// Extracts:
    /// - Certificate serial number
    /// - Issuer DN (for name hash)
    /// - Issuer public key (for key hash)
    pub fn new(cert: &[u8], issuer: &[u8]) -> Result<Self, RevocationError> {
        // Parse the certificate to check
        let (_, cert_parsed) = parse_x509_certificate(cert).map_err(|e| {
            RevocationError::ParseError(format!("Failed to parse certificate: {}", e))
        })?;

        // Parse the issuer certificate
        let (_, issuer_parsed) = parse_x509_certificate(issuer).map_err(|e| {
            RevocationError::ParseError(format!("Failed to parse issuer certificate: {}", e))
        })?;

        // Extract serial number from the certificate
        let serial_number = cert_parsed.serial.to_bytes_be();

        // Extract issuer distinguished name (raw DER)
        let issuer_dn_der = issuer_parsed.subject().as_raw();
        let issuer_name_hash = Self::hash_issuer_name(issuer_dn_der);

        // Extract issuer public key (the raw BIT STRING value without tag/length)
        let issuer_pubkey = &issuer_parsed.public_key().subject_public_key.data;
        let issuer_key_hash = Self::hash_issuer_key(issuer_pubkey);

        Ok(Self {
            serial_number,
            issuer_name_hash,
            issuer_key_hash,
            nonce: None,
        })
    }

    /// Add a nonce for replay protection
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Build the OCSP request as DER-encoded bytes
    ///
    /// This constructs the ASN.1 OCSPRequest structure and encodes it to DER.
    ///
    /// Structure (RFC 6960):
    /// ```asn1
    /// OCSPRequest ::= SEQUENCE {
    ///     tbsRequest      TBSRequest,
    ///     optionalSignature   [0] EXPLICIT Signature OPTIONAL
    /// }
    /// ```
    ///
    /// For MVP, we build unsigned requests (no optionalSignature).
    pub fn build(&self) -> Result<Vec<u8>, RevocationError> {
        // Build the request from inside out:
        // 1. CertID (identifies the certificate)
        // 2. Request (wraps CertID)
        // 3. TBSRequest (contains Request list + optional extensions)
        // 4. OCSPRequest (wraps TBSRequest)

        let cert_id = self.build_cert_id();
        let request = self.build_request(&cert_id);
        let tbs_request = self.build_tbs_request(&request)?;
        let ocsp_request = self.build_ocsp_request(&tbs_request);

        Ok(ocsp_request)
    }

    /// Build CertID structure
    ///
    /// ```asn1
    /// CertID ::= SEQUENCE {
    ///     hashAlgorithm       AlgorithmIdentifier,
    ///     issuerNameHash      OCTET STRING,
    ///     issuerKeyHash       OCTET STRING,
    ///     serialNumber        INTEGER
    /// }
    /// ```
    fn build_cert_id(&self) -> Vec<u8> {
        let mut cert_id = Vec::new();

        // hashAlgorithm: AlgorithmIdentifier for SHA-256
        // SEQUENCE { OID 2.16.840.1.101.3.4.2.1 (SHA-256), NULL }
        let mut hash_algo_content = Vec::new();
        hash_algo_content.extend_from_slice(&der_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1])); // SHA-256 OID
        hash_algo_content.extend_from_slice(&der_null());
        let hash_algo = der_sequence(&hash_algo_content);
        cert_id.extend_from_slice(&hash_algo);

        // issuerNameHash: OCTET STRING
        cert_id.extend_from_slice(&der_octet_string(&self.issuer_name_hash));

        // issuerKeyHash: OCTET STRING
        cert_id.extend_from_slice(&der_octet_string(&self.issuer_key_hash));

        // serialNumber: INTEGER
        cert_id.extend_from_slice(&der_integer(&self.serial_number));

        // Wrap in SEQUENCE
        der_sequence(&cert_id)
    }

    /// Build Request structure
    ///
    /// ```asn1
    /// Request ::= SEQUENCE {
    ///     reqCert             CertID,
    ///     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
    /// }
    /// ```
    fn build_request(&self, cert_id: &[u8]) -> Vec<u8> {
        // For MVP: no singleRequestExtensions
        // Just wrap the CertID in a SEQUENCE
        der_sequence(cert_id)
    }

    /// Build TBSRequest structure
    ///
    /// ```asn1
    /// TBSRequest ::= SEQUENCE {
    ///     version             [0] EXPLICIT Version DEFAULT v1,
    ///     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
    ///     requestList         SEQUENCE OF Request,
    ///     requestExtensions   [2] EXPLICIT Extensions OPTIONAL
    /// }
    /// ```
    fn build_tbs_request(&self, request: &[u8]) -> Result<Vec<u8>, RevocationError> {
        let mut tbs = Vec::new();

        // version: omitted (default v1)

        // requestorName: omitted (optional)

        // requestList: SEQUENCE OF Request (we have one request)
        let request_list = der_sequence(request);
        tbs.extend_from_slice(&request_list);

        // requestExtensions: [2] EXPLICIT Extensions (for nonce if present)
        if let Some(ref nonce_value) = self.nonce {
            let nonce_ext = self.build_nonce_extension(nonce_value);
            // Context-specific tag [2] EXPLICIT
            tbs.extend_from_slice(&der_explicit_context(2, &nonce_ext));
        }

        Ok(der_sequence(&tbs))
    }

    /// Build nonce extension
    ///
    /// ```asn1
    /// Extensions ::= SEQUENCE OF Extension
    /// Extension ::= SEQUENCE {
    ///     extnID      OBJECT IDENTIFIER,
    ///     critical    BOOLEAN DEFAULT FALSE,
    ///     extnValue   OCTET STRING
    /// }
    /// ```
    fn build_nonce_extension(&self, nonce: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();

        // extnID: OCSP Nonce OID 1.3.6.1.5.5.7.48.1.2
        ext.extend_from_slice(&der_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 2]));

        // critical: omitted (default FALSE)

        // extnValue: OCTET STRING containing nonce (itself an OCTET STRING)
        let nonce_value = der_octet_string(nonce);
        ext.extend_from_slice(&der_octet_string(&nonce_value));

        // Wrap extension in SEQUENCE
        let extension = der_sequence(&ext);

        // Wrap in SEQUENCE OF (even though we have only one)
        der_sequence(&extension)
    }

    /// Build final OCSPRequest structure
    ///
    /// ```asn1
    /// OCSPRequest ::= SEQUENCE {
    ///     tbsRequest      TBSRequest,
    ///     optionalSignature   [0] EXPLICIT Signature OPTIONAL
    /// }
    /// ```
    fn build_ocsp_request(&self, tbs_request: &[u8]) -> Vec<u8> {
        // For MVP: unsigned request (no optionalSignature)
        // Just wrap TBSRequest in a SEQUENCE
        der_sequence(tbs_request)
    }

    /// Compute SHA-256 hash of issuer name
    fn hash_issuer_name(issuer_dn: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(issuer_dn);
        hasher.finalize().to_vec()
    }

    /// Compute SHA-256 hash of issuer public key
    fn hash_issuer_key(issuer_pubkey: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(issuer_pubkey);
        hasher.finalize().to_vec()
    }
}

// ============================================================================
// DER Encoding Helpers
// ============================================================================

/// Encode a SEQUENCE
fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_tlv(0x30, contents)
}

/// Encode an OCTET STRING
fn der_octet_string(contents: &[u8]) -> Vec<u8> {
    der_tlv(0x04, contents)
}

/// Encode an INTEGER
fn der_integer(value: &[u8]) -> Vec<u8> {
    // Handle negative numbers by adding padding if high bit is set
    let mut int_value = value.to_vec();
    if let Some(&first_byte) = int_value.first()
        && first_byte & 0x80 != 0
    {
        int_value.insert(0, 0x00);
    }
    der_tlv(0x02, &int_value)
}

/// Encode an OBJECT IDENTIFIER
fn der_oid(components: &[u64]) -> Vec<u8> {
    if components.len() < 2 {
        return der_tlv(0x06, &[]);
    }

    let mut encoded = Vec::new();

    // First two components are encoded as 40*v1 + v2
    encoded.push((40 * components[0] + components[1]) as u8);

    // Remaining components use base-128 encoding
    for &component in &components[2..] {
        let bytes = encode_base128(component);
        encoded.extend_from_slice(&bytes);
    }

    der_tlv(0x06, &encoded)
}

/// Encode NULL
fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Encode context-specific explicit tag
fn der_explicit_context(tag: u8, contents: &[u8]) -> Vec<u8> {
    // Context-specific, constructed, tag number
    let tag_byte = 0xA0 | tag;
    der_tlv(tag_byte, contents)
}

/// Encode Tag-Length-Value
fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    result.extend_from_slice(&der_length(contents.len()));
    result.extend_from_slice(contents);
    result
}

/// Encode DER length
fn der_length(length: usize) -> Vec<u8> {
    if length < 128 {
        // Short form: single byte
        vec![length as u8]
    } else {
        // Long form: first byte has high bit set and indicates number of length bytes
        let mut length_bytes = Vec::new();
        let mut len = length;
        while len > 0 {
            length_bytes.insert(0, (len & 0xFF) as u8);
            len >>= 8;
        }
        let mut result = vec![0x80 | length_bytes.len() as u8];
        result.extend_from_slice(&length_bytes);
        result
    }
}

/// Encode value in base-128 (for OID components)
fn encode_base128(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }

    let mut result = Vec::new();
    let mut first = true;

    while value > 0 || first {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;

        if !first {
            byte |= 0x80; // Set high bit on all but last byte
        }

        result.insert(0, byte);
        first = false;
    }

    result
}

/// Parsed OCSP response
///
/// Contains the decoded and validated OCSP response data.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// Response status
    pub status: OcspResponseStatus,
    /// Certificate status (if response was successful)
    pub cert_status: Option<CertificateStatus>,
    /// When this response was produced
    pub produced_at: SystemTime,
    /// When this status was last updated
    pub this_update: SystemTime,
    /// When this status will be updated next (optional)
    pub next_update: Option<SystemTime>,
    /// Response nonce (if present)
    pub nonce: Option<Vec<u8>>,
    /// Raw response bytes (for caching)
    pub raw_bytes: Vec<u8>,
}

impl OcspResponse {
    /// Parse an OCSP response from DER-encoded bytes
    ///
    /// # Arguments
    /// * `der_bytes` - DER-encoded OCSP response
    ///
    /// # Returns
    /// Parsed OCSP response or error
    ///
    /// This implementation uses x509-parser's OCSP support to parse BasicOCSPResponse.
    pub fn parse(der_bytes: &[u8]) -> Result<Self, RevocationError> {
        // Parse the outer OCSPResponse structure
        // OCSPResponse ::= SEQUENCE {
        //     responseStatus  OCSPResponseStatus,
        //     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
        // }

        let (_rem, ocsp_resp_seq) = der_parser::parse_der(der_bytes).map_err(|e| {
            RevocationError::ParseError(format!("Failed to parse OCSP response: {:?}", e))
        })?;

        let ocsp_resp_seq = ocsp_resp_seq.as_sequence().map_err(|_| {
            RevocationError::ParseError("OCSP response is not a SEQUENCE".to_string())
        })?;

        if ocsp_resp_seq.is_empty() {
            return Err(RevocationError::ParseError(
                "OCSP response SEQUENCE is empty".to_string(),
            ));
        }

        // Extract responseStatus (ENUMERATED)
        let status_int = ocsp_resp_seq[0]
            .as_u32()
            .map_err(|_| RevocationError::ParseError("Invalid responseStatus".to_string()))?;

        let status = OcspResponseStatus::from_u8(status_int as u8).ok_or_else(|| {
            RevocationError::ParseError(format!("Unknown OCSP response status: {}", status_int))
        })?;

        // If status is not Successful, return early with no cert status
        if status != OcspResponseStatus::Successful {
            return Ok(Self {
                status,
                cert_status: None,
                produced_at: SystemTime::now(), // Placeholder
                this_update: SystemTime::now(),
                next_update: None,
                nonce: None,
                raw_bytes: der_bytes.to_vec(),
            });
        }

        // Parse responseBytes [0] EXPLICIT ResponseBytes
        if ocsp_resp_seq.len() < 2 {
            return Err(RevocationError::ParseError(
                "OCSP response missing responseBytes".to_string(),
            ));
        }

        // responseBytes is [0] EXPLICIT, so it's a tagged structure
        let response_bytes = &ocsp_resp_seq[1];

        // Extract the content (should be a SEQUENCE)
        let response_bytes_seq = response_bytes.as_sequence().map_err(|_| {
            RevocationError::ParseError("responseBytes is not a SEQUENCE".to_string())
        })?;

        if response_bytes_seq.len() < 2 {
            return Err(RevocationError::ParseError(
                "responseBytes SEQUENCE too short".to_string(),
            ));
        }

        // responseType is an OID (should be BasicOCSPResponse: 1.3.6.1.5.5.7.48.1.1)
        let response_type = response_bytes_seq[0]
            .as_oid()
            .map_err(|_| RevocationError::ParseError("Invalid responseType OID".to_string()))?;

        let basic_ocsp_oid = oid!(1.3.6.1.5.5.7.48.1.1);
        if *response_type != basic_ocsp_oid {
            return Err(RevocationError::ParseError(format!(
                "Unsupported OCSP response type: {}",
                response_type
            )));
        }

        // response is an OCTET STRING containing DER-encoded BasicOCSPResponse
        let basic_resp_bytes = response_bytes_seq[1]
            .as_slice()
            .map_err(|_| RevocationError::ParseError("Invalid response bytes".to_string()))?;

        // Parse BasicOCSPResponse from the OCTET STRING
        let (_, basic_resp_der) = der_parser::parse_der(basic_resp_bytes).map_err(|e| {
            RevocationError::ParseError(format!("Failed to parse BasicOCSPResponse: {:?}", e))
        })?;

        let basic_resp_seq = basic_resp_der.as_sequence().map_err(|_| {
            RevocationError::ParseError("BasicOCSPResponse is not a SEQUENCE".to_string())
        })?;

        if basic_resp_seq.len() < 3 {
            return Err(RevocationError::ParseError(
                "BasicOCSPResponse SEQUENCE too short".to_string(),
            ));
        }

        // Extract tbsResponseData (SEQUENCE)
        let tbs_response_data = basic_resp_seq[0].as_sequence().map_err(|_| {
            RevocationError::ParseError("tbsResponseData is not a SEQUENCE".to_string())
        })?;

        // Parse ResponseData
        // ResponseData ::= SEQUENCE {
        //     version             [0] EXPLICIT Version DEFAULT v1,
        //     responderID         ResponderID,
        //     producedAt          GeneralizedTime,
        //     responses           SEQUENCE OF SingleResponse,
        //     responseExtensions  [1] EXPLICIT Extensions OPTIONAL
        // }

        let mut idx = 0;

        // Check for optional version [0]
        if tbs_response_data[idx].header.tag().0 == 0xA0 {
            idx += 1; // Skip version
        }

        // responderID (skip for now)
        idx += 1;

        // producedAt (GeneralizedTime)
        let produced_at_str = tbs_response_data[idx]
            .as_str()
            .map_err(|_| RevocationError::ParseError("Invalid producedAt".to_string()))?;
        let produced_at = parse_generalized_time(produced_at_str)?;
        idx += 1;

        // responses SEQUENCE OF SingleResponse
        let responses = tbs_response_data[idx]
            .as_sequence()
            .map_err(|_| RevocationError::ParseError("responses is not a SEQUENCE".to_string()))?;

        if responses.is_empty() {
            return Err(RevocationError::ParseError(
                "No SingleResponse in OCSP response".to_string(),
            ));
        }

        // Parse first SingleResponse
        let single_resp = responses[0].as_sequence().map_err(|_| {
            RevocationError::ParseError("SingleResponse is not a SEQUENCE".to_string())
        })?;

        if single_resp.len() < 3 {
            return Err(RevocationError::ParseError(
                "SingleResponse SEQUENCE too short".to_string(),
            ));
        }

        // certID (skip for now - we trust the responder)
        // certStatus (CHOICE)
        let cert_status_der = &single_resp[1];
        let cert_status = parse_cert_status(cert_status_der)?;

        // thisUpdate (GeneralizedTime)
        let this_update_str = single_resp[2]
            .as_str()
            .map_err(|_| RevocationError::ParseError("Invalid thisUpdate".to_string()))?;
        let this_update = parse_generalized_time(this_update_str)?;

        // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
        let mut next_update = None;
        if single_resp.len() > 3
            && single_resp[3].header.tag().0 == 0xA0
            && let Ok(seq) = single_resp[3].as_sequence()
            && let Some(next_update_str) = seq.first().and_then(|item| item.as_str().ok())
        {
            next_update = Some(parse_generalized_time(next_update_str)?);
        }

        // Extract nonce from responseExtensions if present
        let mut nonce = None;
        if tbs_response_data.len() > idx + 1
            && tbs_response_data[idx + 1].header.tag().0 == 0xA1
            && let Ok(exts_seq) = tbs_response_data[idx + 1].as_sequence()
        {
            nonce = extract_nonce_from_extensions(exts_seq)?;
        }

        Ok(Self {
            status,
            cert_status: Some(cert_status),
            produced_at,
            this_update,
            next_update,
            nonce,
            raw_bytes: der_bytes.to_vec(),
        })
    }

    /// Verify the signature on this OCSP response
    ///
    /// # Arguments
    /// * `issuer_cert` - The issuer certificate (to verify signature)
    ///
    /// # Returns
    /// Ok(()) if signature is valid, Err otherwise
    pub fn verify_signature(&self, _issuer_cert: &[u8]) -> Result<(), RevocationError> {
        // TODO: Implement signature verification
        // For now, return placeholder
        todo!("OCSP signature verification - Phase 2")
    }

    /// Check if this response is still fresh (not expired)
    pub fn is_fresh(&self) -> bool {
        let now = SystemTime::now();

        // Must be after thisUpdate
        if now < self.this_update {
            return false;
        }

        // If nextUpdate is present, must be before it
        if let Some(next_update) = self.next_update
            && now >= next_update
        {
            return false;
        }

        true
    }

    /// Get the TTL for caching this response
    ///
    /// Returns the time until nextUpdate, or a default TTL if nextUpdate is missing
    pub fn cache_ttl(&self) -> Duration {
        if let Some(next_update) = self.next_update
            && let Ok(duration) = next_update.duration_since(SystemTime::now())
        {
            return duration;
        }

        // Default: cache for 1 hour if no nextUpdate
        Duration::from_secs(3600)
    }

    /// Check if the certificate is revoked according to this response
    pub fn is_revoked(&self) -> bool {
        matches!(self.cert_status, Some(CertificateStatus::Revoked { .. }))
    }
}

// ============================================================================
// OCSP Response Parsing Helpers
// ============================================================================

/// Parse CertStatus from DER object
///
/// ```asn1
/// CertStatus ::= CHOICE {
///     good        [0] IMPLICIT NULL,
///     revoked     [1] IMPLICIT RevokedInfo,
///     unknown     [2] IMPLICIT UnknownInfo
/// }
/// ```
fn parse_cert_status(
    der: &der_parser::der::DerObject,
) -> Result<CertificateStatus, RevocationError> {
    // Context-specific tags use the pattern: tag class (0b10) + tag number
    // [0] = 0x80, [1] = 0x81, [2] = 0x82
    match der.header.tag().0 {
        // [0] IMPLICIT NULL - good
        0x80 => Ok(CertificateStatus::Good),

        // [1] IMPLICIT RevokedInfo - revoked
        0x81 => {
            // RevokedInfo ::= SEQUENCE {
            //     revocationTime  GeneralizedTime,
            //     revocationReason [0] EXPLICIT CRLReason OPTIONAL
            // }
            let revoked_seq = der.as_sequence().map_err(|_| {
                RevocationError::ParseError("RevokedInfo is not a SEQUENCE".to_string())
            })?;

            if revoked_seq.is_empty() {
                return Err(RevocationError::ParseError(
                    "RevokedInfo SEQUENCE is empty".to_string(),
                ));
            }

            let revocation_time_str = revoked_seq[0]
                .as_str()
                .map_err(|_| RevocationError::ParseError("Invalid revocationTime".to_string()))?;
            let revocation_time = parse_generalized_time(revocation_time_str)?;

            // Optional revocation reason
            let reason = if revoked_seq.len() > 1 {
                if let Ok(reason_int) = revoked_seq[1].as_u32() {
                    Some(reason_int as u8)
                } else {
                    None
                }
            } else {
                None
            };

            Ok(CertificateStatus::Revoked {
                revocation_time,
                reason,
            })
        }

        // [2] IMPLICIT UnknownInfo - unknown
        0x82 => Ok(CertificateStatus::Unknown),

        _ => Err(RevocationError::ParseError(format!(
            "Unknown CertStatus tag: {:?}",
            der.header.tag()
        ))),
    }
}

/// Parse ASN.1 GeneralizedTime to SystemTime
///
/// GeneralizedTime format: YYYYMMDDHHMMSSZ
fn parse_generalized_time(time_str: &str) -> Result<SystemTime, RevocationError> {
    use chrono::{DateTime, Utc};

    // Parse the GeneralizedTime string
    // Format: YYYYMMDDHHMMSS[.fff]Z or YYYYMMDDHHMMSS[.fff]+0000
    let datetime = DateTime::parse_from_str(time_str, "%Y%m%d%H%M%SZ")
        .or_else(|_| DateTime::parse_from_str(time_str, "%Y%m%d%H%M%S%.fZ"))
        .map_err(|e| {
            RevocationError::ParseError(format!(
                "Failed to parse GeneralizedTime '{}': {}",
                time_str, e
            ))
        })?;

    let utc_datetime: DateTime<Utc> = datetime.into();

    Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(utc_datetime.timestamp() as u64))
}

/// Extract nonce from OCSP response extensions
///
/// Returns Some(nonce_value) if nonce extension is found, None otherwise
fn extract_nonce_from_extensions(
    extensions_seq: &[der_parser::der::DerObject],
) -> Result<Option<Vec<u8>>, RevocationError> {
    // Nonce extension OID: 1.3.6.1.5.5.7.48.1.2
    let nonce_oid = oid!(1.3.6.1.5.5.7.48.1.2);

    for ext_der in extensions_seq {
        // Each extension is a SEQUENCE
        let ext_seq = ext_der
            .as_sequence()
            .map_err(|_| RevocationError::ParseError("Extension is not a SEQUENCE".to_string()))?;

        if ext_seq.len() < 2 {
            continue;
        }

        // extnID (OID)
        let extn_id = ext_seq[0]
            .as_oid()
            .map_err(|_| RevocationError::ParseError("Invalid extension OID".to_string()))?;

        if *extn_id == nonce_oid {
            // extnValue is an OCTET STRING containing the nonce
            // The nonce itself is also an OCTET STRING inside
            let extn_value_bytes =
                ext_seq.last().unwrap().as_slice().map_err(|_| {
                    RevocationError::ParseError("Invalid extension value".to_string())
                })?;

            // Parse the inner OCTET STRING
            let (_, nonce_der) = der_parser::parse_der(extn_value_bytes).map_err(|e| {
                RevocationError::ParseError(format!("Failed to parse nonce value: {:?}", e))
            })?;

            let nonce_value = nonce_der.as_slice().map_err(|_| {
                RevocationError::ParseError("Nonce value is not an OCTET STRING".to_string())
            })?;

            return Ok(Some(nonce_value.to_vec()));
        }
    }

    Ok(None)
}

/// OCSP client for querying responders
///
/// Handles HTTP POST requests to OCSP responders and response parsing.
#[derive(Debug)]
pub struct OcspClient {
    /// HTTP client (reused for connection pooling)
    http_client: reqwest::blocking::Client,
}

impl OcspClient {
    /// Create a new OCSP client
    ///
    /// # Arguments
    /// * `timeout` - HTTP request timeout in seconds
    pub fn new(timeout: u64) -> Result<Self, RevocationError> {
        super::ensure_default_crypto_provider();
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .map_err(|e| {
                RevocationError::HttpError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { http_client })
    }

    /// Query an OCSP responder
    ///
    /// # Arguments
    /// * `url` - OCSP responder URL
    /// * `request` - DER-encoded OCSP request
    /// * `max_response_size` - Maximum allowed response size in bytes
    ///
    /// # Returns
    /// DER-encoded OCSP response or error
    pub fn query(
        &self,
        url: &str,
        request: &[u8],
        max_response_size: usize,
    ) -> Result<Vec<u8>, RevocationError> {
        // Send HTTP POST request
        let response = self
            .http_client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request.to_vec())
            .send()
            .map_err(|e| RevocationError::HttpError(format!("OCSP HTTP request failed: {}", e)))?;

        // Check HTTP status code
        if !response.status().is_success() {
            return Err(RevocationError::HttpError(format!(
                "OCSP responder returned HTTP {}",
                response.status()
            )));
        }

        // Check Content-Type header
        if let Some(content_type) = response.headers().get("Content-Type")
            && let Ok(ct_str) = content_type.to_str()
            && !ct_str.contains("application/ocsp-response")
        {
            return Err(RevocationError::HttpError(format!(
                "Unexpected Content-Type: {}",
                ct_str
            )));
        }

        // Read response body with size limit
        let bytes = response.bytes().map_err(|e| {
            RevocationError::HttpError(format!("Failed to read OCSP response body: {}", e))
        })?;

        if bytes.len() > max_response_size {
            return Err(RevocationError::HttpError(format!(
                "OCSP response too large: {} bytes (max: {})",
                bytes.len(),
                max_response_size
            )));
        }

        Ok(bytes.to_vec())
    }

    /// Extract OCSP responder URL from a certificate
    ///
    /// Parses the Authority Information Access extension to find OCSP URL.
    ///
    /// # Arguments
    /// * `cert` - DER-encoded certificate
    ///
    /// # Returns
    /// OCSP responder URL or error if not found
    pub fn extract_ocsp_url(cert: &[u8]) -> Result<String, RevocationError> {
        // Parse certificate
        let (_, cert_parsed) = parse_x509_certificate(cert).map_err(|e| {
            RevocationError::ParseError(format!("Failed to parse certificate: {}", e))
        })?;

        // Find Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1)
        let aia_oid = oid!(1.3.6.1.5.5.7.1.1);

        for ext in cert_parsed.extensions() {
            if ext.oid == aia_oid {
                // Parse AIA extension value
                // The extension value is a SEQUENCE OF AccessDescription
                // AccessDescription ::= SEQUENCE {
                //     accessMethod    OBJECT IDENTIFIER,
                //     accessLocation  GeneralName
                // }
                // OCSP access method OID is 1.3.6.1.5.5.7.48.1

                // Use x509-parser's parsing
                use x509_parser::extensions::{GeneralName, ParsedExtension};

                if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                    let ocsp_oid = oid!(1.3.6.1.5.5.7.48.1);

                    for access_desc in aia.accessdescs.iter() {
                        if access_desc.access_method == ocsp_oid {
                            // Extract URL from GeneralName
                            if let GeneralName::URI(uri) = &access_desc.access_location {
                                return Ok(uri.to_string());
                            }
                        }
                    }
                }
            }
        }

        Err(RevocationError::ParseError(
            "No OCSP URL found in certificate AIA extension".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_response_status_conversion() {
        assert_eq!(
            OcspResponseStatus::from_u8(0),
            Some(OcspResponseStatus::Successful)
        );
        assert_eq!(
            OcspResponseStatus::from_u8(1),
            Some(OcspResponseStatus::MalformedRequest)
        );
        assert_eq!(OcspResponseStatus::from_u8(99), None);
    }

    #[test]
    fn test_certificate_status_equality() {
        let good1 = CertificateStatus::Good;
        let good2 = CertificateStatus::Good;
        assert_eq!(good1, good2);

        let unknown1 = CertificateStatus::Unknown;
        let unknown2 = CertificateStatus::Unknown;
        assert_eq!(unknown1, unknown2);
    }

    // TODO: Add more tests once implementation is complete
    // - OCSP request building
    // - OCSP response parsing
    // - Signature verification
    // - Nonce validation
    // - Freshness checking
}
