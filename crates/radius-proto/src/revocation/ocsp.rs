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
//! 4. **Validate**: Match the CertID, verify the signature and the signer's
//!    authorization (RFC 6960 §3.2, §4.2.2.2), check the nonce and freshness
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
//! # Implementation
//!
//! Requests are encoded and responses decoded with a small DER reader so the
//! exact `tbsResponseData` bytes the responder signed are available for
//! signature verification, which uses the rustls `CryptoProvider`'s
//! signature algorithms (aws-lc-rs). Certificates are parsed with
//! `x509-parser`; CertID hashes use SHA-256 (`sha2`).

use crate::revocation::error::RevocationError;
use crate::revocation::signature::{
    SignedData, TAG_ENUMERATED, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID,
    TAG_SEQUENCE, Tlv, expect_tlv, has_ocsp_nocheck, integer_magnitude, is_issued_by, read_tlv,
    split_signed, verify_signed_data,
};
use rustls::crypto::WebPkiSupportedAlgorithms;
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

    /// The CertID this request asks about; a response is only accepted for
    /// a SingleResponse with exactly this CertID.
    pub fn cert_id(&self) -> CertId {
        CertId {
            hash_algorithm: SHA256_OID.to_vec(),
            issuer_name_hash: self.issuer_name_hash.clone(),
            issuer_key_hash: self.issuer_key_hash.clone(),
            serial_number: integer_magnitude(&self.serial_number).to_vec(),
        }
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

/// CertID (RFC 6960 §4.1.1): which certificate a request or a SingleResponse
/// is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertId {
    /// hashAlgorithm OID (DER contents octets); parameters are ignored
    pub hash_algorithm: Vec<u8>,
    /// Hash of the issuer's DER subject Name
    pub issuer_name_hash: Vec<u8>,
    /// Hash of the issuer's subjectPublicKey BIT STRING value
    pub issuer_key_hash: Vec<u8>,
    /// Serial number, minimal big-endian magnitude
    pub serial_number: Vec<u8>,
}

/// DER contents of the id-sha256 OID (2.16.840.1.101.3.4.2.1).
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

impl CertId {
    /// Parse a DER CertID SEQUENCE.
    fn parse(tlv: &Tlv<'_>) -> Result<Self, RevocationError> {
        if tlv.tag != TAG_SEQUENCE {
            return Err(parse_err("CertID is not a SEQUENCE"));
        }
        let (alg, rest) = expect_tlv(tlv.content, TAG_SEQUENCE)?;
        let (oid, _params) = expect_tlv(alg.content, TAG_OID)?;
        let (name_hash, rest) = expect_tlv(rest, TAG_OCTET_STRING)?;
        let (key_hash, rest) = expect_tlv(rest, TAG_OCTET_STRING)?;
        let (serial, rest) = expect_tlv(rest, TAG_INTEGER)?;
        if !rest.is_empty() {
            return Err(parse_err("trailing data in CertID"));
        }
        Ok(Self {
            hash_algorithm: oid.content.to_vec(),
            issuer_name_hash: name_hash.content.to_vec(),
            issuer_key_hash: key_hash.content.to_vec(),
            serial_number: integer_magnitude(serial.content).to_vec(),
        })
    }

    /// Bytes that identify this CertID as a cache key.
    pub fn cache_key(&self) -> Vec<u8> {
        let mut key = self.issuer_key_hash.clone();
        key.extend_from_slice(&self.issuer_name_hash);
        key.extend_from_slice(&self.serial_number);
        key
    }
}

/// ResponderID (RFC 6960 §4.2.1)
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResponderId {
    /// byName: DER Name of the signer
    ByName(Vec<u8>),
    /// byKey: SHA-1 hash of the signer's public key
    ByKey(Vec<u8>),
}

/// One SingleResponse (RFC 6960 §4.2.1)
#[derive(Debug, Clone)]
struct SingleResponse {
    cert_id: CertId,
    status: CertificateStatus,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
}

/// A parsed BasicOCSPResponse, kept in the form the signature covers.
#[derive(Debug, Clone)]
struct BasicOcspResponse {
    /// DER of tbsResponseData (what the signature covers)
    tbs: Vec<u8>,
    /// signatureAlgorithm AlgorithmIdentifier contents
    signature_algorithm: Vec<u8>,
    /// Signature octets
    signature: Vec<u8>,
    /// Certificates the responder included (DER)
    certs: Vec<Vec<u8>>,
    responder_id: ResponderId,
    produced_at: SystemTime,
    responses: Vec<SingleResponse>,
    nonce: Option<Vec<u8>>,
}

/// id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1), DER contents
const OCSP_BASIC_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2), DER contents
const OCSP_NONCE_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

/// Certificate extensions understood for a delegated responder certificate:
/// basicConstraints, keyUsage, extendedKeyUsage, subjectAltName,
/// id-pkix-ocsp-nocheck (plus the key identifiers, never critical anyway).
const RESPONDER_KNOWN_EXTENSIONS: &[&str] = &[
    "2.5.29.19",
    "2.5.29.15",
    "2.5.29.37",
    "2.5.29.17",
    "2.5.29.14",
    "2.5.29.35",
    "1.3.6.1.5.5.7.48.1.5",
];

/// Leeway for a responder clock slightly ahead of ours on thisUpdate.
const THIS_UPDATE_LEEWAY: Duration = Duration::from_secs(300);

fn parse_err(what: &str) -> RevocationError {
    RevocationError::ParseError(format!("OCSP response: {what}"))
}

/// Parse the outer OCSPResponse; returns the status and, when successful,
/// the BasicOCSPResponse DER.
fn parse_outer(der: &[u8]) -> Result<(OcspResponseStatus, Option<&[u8]>), RevocationError> {
    // OCSPResponse ::= SEQUENCE {
    //     responseStatus  OCSPResponseStatus,
    //     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }
    let (outer, rest) = expect_tlv(der, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(parse_err("trailing data"));
    }
    let (status, rest) = expect_tlv(outer.content, TAG_ENUMERATED)?;
    let status = match status.content {
        [value] => OcspResponseStatus::from_u8(*value)
            .ok_or_else(|| parse_err(&format!("unknown responseStatus {value}")))?,
        _ => return Err(parse_err("responseStatus")),
    };
    if status != OcspResponseStatus::Successful {
        return Ok((status, None));
    }

    // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
    let (explicit, rest) =
        expect_tlv(rest, 0xA0).map_err(|_| parse_err("missing responseBytes"))?;
    let (response_bytes, inner_rest) = expect_tlv(explicit.content, TAG_SEQUENCE)?;
    let (response_type, bytes_rest) = expect_tlv(response_bytes.content, TAG_OID)?;
    if response_type.content != OCSP_BASIC_OID {
        return Err(parse_err("responseType is not id-pkix-ocsp-basic"));
    }
    let (response, after) = expect_tlv(bytes_rest, TAG_OCTET_STRING)?;
    if !rest.is_empty() || !inner_rest.is_empty() || !after.is_empty() {
        return Err(parse_err("trailing data in responseBytes"));
    }
    Ok((status, Some(response.content)))
}

impl BasicOcspResponse {
    fn parse(der: &[u8]) -> Result<Self, RevocationError> {
        // BasicOCSPResponse ::= SEQUENCE {
        //     tbsResponseData ResponseData, signatureAlgorithm AlgorithmIdentifier,
        //     signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
        let signed = split_signed(der)?;
        let mut certs = Vec::new();
        if !signed.trailing.is_empty() {
            let (explicit, rest) = expect_tlv(signed.trailing, 0xA0)?;
            if !rest.is_empty() {
                return Err(parse_err("trailing data after certs"));
            }
            let (seq, after) = expect_tlv(explicit.content, TAG_SEQUENCE)?;
            if !after.is_empty() {
                return Err(parse_err("trailing data in certs"));
            }
            let mut rest = seq.content;
            while !rest.is_empty() {
                let (cert, next) = expect_tlv(rest, TAG_SEQUENCE)?;
                certs.push(cert.raw.to_vec());
                rest = next;
            }
        }

        // ResponseData ::= SEQUENCE {
        //     version [0] EXPLICIT Version DEFAULT v1, responderID ResponderID,
        //     producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse,
        //     responseExtensions [1] EXPLICIT Extensions OPTIONAL }
        let (tbs, _) = expect_tlv(signed.tbs, TAG_SEQUENCE)?;
        let (mut item, mut rest) = read_tlv(tbs.content)?;
        if item.tag == 0xA0 {
            // DER omits the DEFAULT v1; tolerate an explicit v1 (it is inside
            // the signed data), refuse any other version.
            let (version, after) = expect_tlv(item.content, TAG_INTEGER)?;
            if version.content != [0] || !after.is_empty() {
                return Err(parse_err("unsupported ResponseData version"));
            }
            (item, rest) = read_tlv(rest)?;
        }
        let (responder_id, after) = match item.tag {
            0xA1 => {
                let (name, after) = expect_tlv(item.content, TAG_SEQUENCE)?;
                (ResponderId::ByName(name.raw.to_vec()), after)
            }
            0xA2 => {
                let (hash, after) = expect_tlv(item.content, TAG_OCTET_STRING)?;
                (ResponderId::ByKey(hash.content.to_vec()), after)
            }
            _ => return Err(parse_err("responderID")),
        };
        if !after.is_empty() {
            return Err(parse_err("trailing data in responderID"));
        }
        let (produced_at, rest) = expect_tlv(rest, TAG_GENERALIZED_TIME)?;
        let produced_at = parse_generalized_time_der(produced_at.content)?;
        let (responses_seq, rest) = expect_tlv(rest, TAG_SEQUENCE)?;

        let mut nonce = None;
        if !rest.is_empty() {
            let (exts, rest) = expect_tlv(rest, 0xA1)?;
            if !rest.is_empty() {
                return Err(parse_err("trailing data in ResponseData"));
            }
            nonce = parse_extensions(exts.content, true)?;
        }

        let mut responses = Vec::new();
        let mut rest = responses_seq.content;
        while !rest.is_empty() {
            let (single, next) = expect_tlv(rest, TAG_SEQUENCE)?;
            responses.push(parse_single_response(single.content)?);
            rest = next;
        }
        if responses.is_empty() {
            return Err(parse_err("no SingleResponse"));
        }

        Ok(Self {
            tbs: signed.tbs.to_vec(),
            signature_algorithm: signed.algorithm.to_vec(),
            signature: signed.signature.to_vec(),
            certs,
            responder_id,
            produced_at,
            responses,
            nonce,
        })
    }

    fn signed_data(&self) -> SignedData<'_> {
        SignedData {
            tbs: &self.tbs,
            algorithm: &self.signature_algorithm,
            signature: &self.signature,
            trailing: &[],
        }
    }

    /// Does the ResponderID name `cert`? byKey is a SHA-1 hash this crate
    /// does not compute; the signature check decides for it.
    fn responder_id_names(&self, cert: &X509Certificate<'_>) -> bool {
        match &self.responder_id {
            ResponderId::ByName(name) => name.as_slice() == cert.subject().as_raw(),
            ResponderId::ByKey(hash) => hash.len() == 20,
        }
    }

    /// Establish who signed the response and that they may (RFC 6960 §3.2
    /// items 2–4, §4.2.2.2): the CA that issued the certificate in question,
    /// or a delegated responder whose certificate that CA issued directly and
    /// which carries id-kp-OCSPSigning.
    fn authorize_signer(
        &self,
        issuer_der: &[u8],
        algorithms: &WebPkiSupportedAlgorithms,
        now: SystemTime,
    ) -> Result<ResponderAuthorization, RevocationError> {
        let (_, issuer) = parse_x509_certificate(issuer_der).map_err(|e| {
            RevocationError::CertificateError(format!("Failed to parse issuer certificate: {e}"))
        })?;
        let signed = self.signed_data();

        // 1. Signed by the issuing CA itself.
        if self.responder_id_names(&issuer)
            && verify_signed_data(algorithms, issuer.public_key().raw, &signed).is_ok()
        {
            return Ok(ResponderAuthorization::Issuer);
        }

        // 2. Signed by a delegated responder certificate from `certs`.
        let now_asn1 = ASN1Time::from_timestamp(unix_secs(now))
            .map_err(|_| RevocationError::OcspError("time out of range".to_string()))?;
        // `certs` is outside the signed data, so a certificate that made the
        // signature but is not authorized (an expired copy, say) only
        // disqualifies itself; the first such reason is reported if none
        // qualifies.
        let mut disqualified: Option<RevocationError> = None;
        for cert_der in &self.certs {
            let Ok((_, responder)) = parse_x509_certificate(cert_der) else {
                continue;
            };
            if !self.responder_id_names(&responder)
                || verify_signed_data(algorithms, responder.public_key().raw, &signed).is_err()
            {
                continue;
            }
            // This certificate's key made the signature; is it authorized?
            match delegated_responder_problem(
                &responder, cert_der, issuer_der, algorithms, now_asn1,
            ) {
                None => {
                    return Ok(ResponderAuthorization::Delegated {
                        certificate: cert_der.clone(),
                        nocheck: has_ocsp_nocheck(&responder),
                    });
                }
                Some(why) => {
                    disqualified.get_or_insert(RevocationError::InvalidSignature(why));
                }
            }
        }

        Err(disqualified.unwrap_or_else(|| {
            RevocationError::InvalidSignature(
                "OCSP response is not signed by the issuing CA or an authorized responder"
                    .to_string(),
            )
        }))
    }
}

/// Why a certificate whose key signed an OCSP response may not answer for
/// `issuer_der`'s certificates (RFC 6960 §4.2.2.2), or `None` if it may.
fn delegated_responder_problem(
    responder: &X509Certificate<'_>,
    responder_der: &[u8],
    issuer_der: &[u8],
    algorithms: &WebPkiSupportedAlgorithms,
    now: ASN1Time,
) -> Option<String> {
    if !is_issued_by(algorithms, responder_der, issuer_der) {
        return Some(
            "OCSP responder certificate is not issued by the certificate's CA".to_string(),
        );
    }
    match responder.extended_key_usage() {
        Ok(Some(eku)) if eku.value.ocsp_signing => {}
        _ => return Some("OCSP responder certificate lacks id-kp-OCSPSigning".to_string()),
    }
    // RFC 5280 §4.2: a critical extension this code does not process (one
    // that might restrict the responder) disqualifies it.
    if let Some(ext) = responder.extensions().iter().find(|ext| {
        ext.critical && !RESPONDER_KNOWN_EXTENSIONS.contains(&ext.oid.to_id_string().as_str())
    }) {
        return Some(format!(
            "OCSP responder certificate has unrecognized critical extension {}",
            ext.oid
        ));
    }
    match responder.key_usage() {
        Ok(Some(ku)) if !ku.value.digital_signature() && !ku.value.non_repudiation() => {
            return Some("OCSP responder keyUsage does not permit signing".to_string());
        }
        Ok(_) => {}
        Err(_) => return Some("OCSP responder keyUsage is malformed".to_string()),
    }
    if !responder.validity().is_valid_at(now) {
        return Some("OCSP responder certificate is outside its validity period".to_string());
    }
    None
}

/// Parse one SingleResponse's contents.
fn parse_single_response(content: &[u8]) -> Result<SingleResponse, RevocationError> {
    // SingleResponse ::= SEQUENCE {
    //     certID CertID, certStatus CertStatus, thisUpdate GeneralizedTime,
    //     nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL,
    //     singleExtensions [1] EXPLICIT Extensions OPTIONAL }
    let (cert_id, rest) = read_tlv(content)?;
    let cert_id = CertId::parse(&cert_id)?;
    let (status, rest) = read_tlv(rest)?;
    let status = parse_cert_status(&status)?;
    let (this_update, mut rest) = expect_tlv(rest, TAG_GENERALIZED_TIME)?;
    let this_update = parse_generalized_time_der(this_update.content)?;
    let mut next_update = None;
    if let Ok((item, next)) = read_tlv(rest)
        && item.tag == 0xA0
    {
        let (time, after) = expect_tlv(item.content, TAG_GENERALIZED_TIME)?;
        if !after.is_empty() {
            return Err(parse_err("trailing data in nextUpdate"));
        }
        next_update = Some(parse_generalized_time_der(time.content)?);
        rest = next;
    }
    if !rest.is_empty() {
        let (exts, rest) = expect_tlv(rest, 0xA1)?;
        if !rest.is_empty() {
            return Err(parse_err("trailing data in SingleResponse"));
        }
        parse_extensions(exts.content, false)?;
    }
    Ok(SingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
    })
}

/// Walk an Extensions SEQUENCE: reject unrecognized critical extensions and
/// return the nonce (RFC 8954 §2.1) when `allow_nonce`.
fn parse_extensions(
    explicit: &[u8],
    allow_nonce: bool,
) -> Result<Option<Vec<u8>>, RevocationError> {
    let (seq, after) = expect_tlv(explicit, TAG_SEQUENCE)?;
    if !after.is_empty() {
        return Err(parse_err("trailing data after Extensions"));
    }
    let mut nonce = None;
    let mut rest = seq.content;
    while !rest.is_empty() {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
        let (ext, next) = expect_tlv(rest, TAG_SEQUENCE)?;
        rest = next;
        let (oid, ext_rest) = expect_tlv(ext.content, TAG_OID)?;
        let (mut item, mut ext_rest) = read_tlv(ext_rest)?;
        let mut critical = false;
        if item.tag == 0x01 {
            // DER: TRUE is 0xFF and DEFAULT FALSE is omitted (X.690 §11.1,
            // §11.5). An explicit FALSE (0x00, seen from older responders)
            // is harmless; anything else is malformed, not "not critical".
            critical = match item.content {
                [0xFF] => true,
                [0x00] => false,
                _ => return Err(parse_err("extension critical flag is not a DER BOOLEAN")),
            };
            (item, ext_rest) = read_tlv(ext_rest)?;
        }
        if item.tag != TAG_OCTET_STRING || !ext_rest.is_empty() {
            return Err(parse_err("malformed extension"));
        }
        if allow_nonce && oid.content == OCSP_NONCE_OID {
            // extnValue is exactly one OCTET STRING holding the nonce
            let (inner, after) = expect_tlv(item.content, TAG_OCTET_STRING)?;
            if !after.is_empty() || inner.content.is_empty() || nonce.is_some() {
                return Err(parse_err("malformed or repeated nonce extension"));
            }
            nonce = Some(inner.content.to_vec());
        } else if critical {
            return Err(parse_err("unrecognized critical extension"));
        }
    }
    Ok(nonce)
}

/// Parsed OCSP response
///
/// Contains the decoded OCSP response data. A response obtained through
/// [`OcspResponse::parse_verified`] describes the requested certificate and
/// carries a signature checked per RFC 6960 §3.2; one from
/// [`OcspResponse::parse`] is unverified.
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

/// Who signed an OCSP response, as established by
/// [`OcspResponse::parse_verified`] (RFC 6960 §4.2.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderAuthorization {
    /// The CA that issued the certificate in question
    Issuer,
    /// A delegated responder certificate issued directly by that CA, with
    /// id-kp-OCSPSigning
    Delegated {
        /// The responder certificate (DER)
        certificate: Vec<u8>,
        /// The responder certificate carries id-pkix-ocsp-nocheck, so its
        /// own revocation status is not checked (RFC 6960 §4.2.2.2.1)
        nocheck: bool,
    },
}

impl OcspResponse {
    /// Parse an OCSP response from DER-encoded bytes **without** verifying
    /// its signature or matching it to a request.
    ///
    /// The status fields describe the first SingleResponse. Use
    /// [`OcspResponse::parse_verified`] for anything that decides access.
    pub fn parse(der_bytes: &[u8]) -> Result<Self, RevocationError> {
        let (status, basic) = parse_outer(der_bytes)?;
        let Some(basic) = basic else {
            return Ok(Self::unsuccessful(status, der_bytes));
        };
        let basic = BasicOcspResponse::parse(basic)?;
        let single = basic.responses[0].clone();
        Ok(Self::from_single(status, &basic, single, der_bytes))
    }

    /// Parse an OCSP response and verify it answers `request` (RFC 6960 §3.2):
    ///
    /// 1. the response is successful and of type id-pkix-ocsp-basic;
    /// 2. a SingleResponse carries exactly the requested CertID;
    /// 3. the signature verifies and the signer is the issuing CA
    ///    (`issuer_der`) or a delegated responder it authorized (§4.2.2.2);
    /// 4. thisUpdate is not in the future (with a small leeway) and
    ///    nextUpdate, when present, has not passed; without nextUpdate,
    ///    thisUpdate is at most `max_age` old (§3.2 item 5, "sufficiently
    ///    recent"), so a recorded response cannot be replayed indefinitely.
    ///
    /// Returns the response for the requested certificate and how its signer
    /// was authorized; a delegated responder without id-pkix-ocsp-nocheck
    /// still needs its own revocation status checked by the caller.
    pub fn parse_verified(
        der_bytes: &[u8],
        request: &CertId,
        issuer_der: &[u8],
        algorithms: &WebPkiSupportedAlgorithms,
        now: SystemTime,
        max_age: Duration,
    ) -> Result<(Self, ResponderAuthorization), RevocationError> {
        let (status, basic) = parse_outer(der_bytes)?;
        let Some(basic) = basic else {
            // Error responses are unsigned (RFC 6960 §2.3); never trust them
            // for anything but "no answer".
            return Err(RevocationError::OcspError(format!(
                "OCSP responder returned error status: {status:?}"
            )));
        };
        let basic = BasicOcspResponse::parse(basic)?;

        let single = basic
            .responses
            .iter()
            .find(|single| single.cert_id == *request)
            .cloned()
            .ok_or_else(|| {
                RevocationError::OcspError(
                    "OCSP response has no SingleResponse for the requested CertID".to_string(),
                )
            })?;

        let authorization = basic.authorize_signer(issuer_der, algorithms, now)?;

        let response = Self::from_single(status, &basic, single, der_bytes);
        if !response.is_fresh_at(now) {
            return Err(RevocationError::OcspError(
                "OCSP response is not current (thisUpdate/nextUpdate)".to_string(),
            ));
        }
        if !response.is_within_max_age(now, max_age) {
            return Err(RevocationError::OcspError(format!(
                "OCSP response has no nextUpdate and its thisUpdate is older than {} s",
                max_age.as_secs()
            )));
        }
        Ok((response, authorization))
    }

    fn unsuccessful(status: OcspResponseStatus, der_bytes: &[u8]) -> Self {
        Self {
            status,
            cert_status: None,
            produced_at: SystemTime::now(), // Placeholder
            this_update: SystemTime::now(),
            next_update: None,
            nonce: None,
            raw_bytes: der_bytes.to_vec(),
        }
    }

    fn from_single(
        status: OcspResponseStatus,
        basic: &BasicOcspResponse,
        single: SingleResponse,
        der_bytes: &[u8],
    ) -> Self {
        Self {
            status,
            cert_status: Some(single.status),
            produced_at: basic.produced_at,
            this_update: single.this_update,
            next_update: single.next_update,
            nonce: basic.nonce.clone(),
            raw_bytes: der_bytes.to_vec(),
        }
    }

    /// Without nextUpdate, is thisUpdate at most `max_age` before `now`
    /// (RFC 6960 §3.2 item 5)? Always true when nextUpdate is present (that
    /// bound is checked by [`OcspResponse::is_fresh_at`]).
    pub fn is_within_max_age(&self, now: SystemTime, max_age: Duration) -> bool {
        self.next_update.is_some()
            || self
                .this_update
                .checked_add(max_age)
                .is_none_or(|limit| now <= limit)
    }

    /// Check if this response is still fresh (not expired)
    pub fn is_fresh(&self) -> bool {
        self.is_fresh_at(SystemTime::now())
    }

    /// Is the response current at `now`? thisUpdate may be up to five
    /// minutes ahead of `now` (responder clock skew); nextUpdate, when
    /// present, must be later than `now`.
    pub fn is_fresh_at(&self, now: SystemTime) -> bool {
        if now + THIS_UPDATE_LEEWAY < self.this_update {
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

/// Parse CertStatus
///
/// ```asn1
/// CertStatus ::= CHOICE {
///     good        [0] IMPLICIT NULL,
///     revoked     [1] IMPLICIT RevokedInfo,
///     unknown     [2] IMPLICIT UnknownInfo
/// }
/// ```
fn parse_cert_status(tlv: &Tlv<'_>) -> Result<CertificateStatus, RevocationError> {
    match tlv.tag {
        // [0] IMPLICIT NULL (primitive, empty)
        0x80 if tlv.content.is_empty() => Ok(CertificateStatus::Good),

        // [1] IMPLICIT RevokedInfo (constructed: a SEQUENCE's contents)
        0xA1 => {
            // RevokedInfo ::= SEQUENCE {
            //     revocationTime  GeneralizedTime,
            //     revocationReason [0] EXPLICIT CRLReason OPTIONAL
            // }
            let (time, rest) = expect_tlv(tlv.content, TAG_GENERALIZED_TIME)?;
            let revocation_time = parse_generalized_time_der(time.content)?;
            let reason = if rest.is_empty() {
                None
            } else {
                let (explicit, after) = expect_tlv(rest, 0xA0)?;
                let (reason, inner) = expect_tlv(explicit.content, TAG_ENUMERATED)?;
                match (reason.content, after.is_empty() && inner.is_empty()) {
                    ([reason], true) => Some(*reason),
                    _ => return Err(parse_err("revocationReason")),
                }
            };
            Ok(CertificateStatus::Revoked {
                revocation_time,
                reason,
            })
        }

        // [2] IMPLICIT UnknownInfo (NULL, primitive, empty)
        0x82 if tlv.content.is_empty() => Ok(CertificateStatus::Unknown),

        other => Err(parse_err(&format!("unknown CertStatus tag {other:#04x}"))),
    }
}

/// Parse the contents of a DER GeneralizedTime (`YYYYMMDDHHMMSS[.f]Z`,
/// RFC 5280 §4.1.2.5.2) to SystemTime.
fn parse_generalized_time_der(content: &[u8]) -> Result<SystemTime, RevocationError> {
    let text = std::str::from_utf8(content).map_err(|_| parse_err("GeneralizedTime"))?;
    parse_generalized_time(text)
}

/// Parse ASN.1 GeneralizedTime to SystemTime
///
/// GeneralizedTime format: YYYYMMDDHHMMSS[.fff]Z
fn parse_generalized_time(time_str: &str) -> Result<SystemTime, RevocationError> {
    use chrono::NaiveDateTime;

    let naive = time_str
        .strip_suffix('Z')
        .and_then(|t| {
            NaiveDateTime::parse_from_str(t, "%Y%m%d%H%M%S")
                .or_else(|_| NaiveDateTime::parse_from_str(t, "%Y%m%d%H%M%S%.f"))
                .ok()
        })
        .ok_or_else(|| {
            RevocationError::ParseError(format!("Failed to parse GeneralizedTime '{time_str}'"))
        })?;
    let secs = u64::try_from(naive.and_utc().timestamp())
        .map_err(|_| RevocationError::ParseError("GeneralizedTime before 1970".to_string()))?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

/// Seconds since the Unix epoch (0 for earlier times).
fn unix_secs(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
            // No redirects: a 307/308 would replay the request to wherever
            // the party on the path points it.
            .redirect(reqwest::redirect::Policy::none())
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

        // Read at most max_response_size + 1 bytes, whatever Content-Length says.
        let too_large = || {
            RevocationError::HttpError(format!(
                "OCSP response larger than {max_response_size} bytes"
            ))
        };
        if response
            .content_length()
            .is_some_and(|len| len > max_response_size as u64)
        {
            return Err(too_large());
        }
        super::fetch::read_body_limited(response, max_response_size)?.ok_or_else(too_large)
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

    // --- Known-answer tests against OpenSSL (tests/fixtures/ocsp/gen.sh) ---

    use crate::revocation::signature::default_algorithms;

    const KAT_CA: &[u8] = include_bytes!("../../tests/fixtures/ocsp/ca.der");
    const KAT_LEAF: &[u8] = include_bytes!("../../tests/fixtures/ocsp/leaf.der");
    const KAT_RESPONDER: &[u8] = include_bytes!("../../tests/fixtures/ocsp/responder.der");
    const KAT_REQUEST: &[u8] = include_bytes!("../../tests/fixtures/ocsp/req.der");
    const KAT_CA_GOOD: &[u8] = include_bytes!("../../tests/fixtures/ocsp/resp-ca-good.der");
    const KAT_CA_REVOKED: &[u8] = include_bytes!("../../tests/fixtures/ocsp/resp-ca-revoked.der");
    const KAT_DELEGATED_GOOD: &[u8] =
        include_bytes!("../../tests/fixtures/ocsp/resp-delegated-good.der");

    fn kat_cert_id() -> CertId {
        OcspRequestBuilder::new(KAT_LEAF, KAT_CA).unwrap().cert_id()
    }

    fn kat_verify(
        response: &[u8],
    ) -> Result<(OcspResponse, ResponderAuthorization), RevocationError> {
        OcspResponse::parse_verified(
            response,
            &kat_cert_id(),
            KAT_CA,
            &default_algorithms(),
            SystemTime::now(),
            Duration::from_secs(3600),
        )
    }

    #[test]
    fn openssl_request_matches_ours_byte_for_byte() {
        // `openssl ocsp -sha256 -no_nonce`: SHA-256 CertID over the issuer's
        // subject DER and subjectPublicKey, serial 00A5C3 (sign padding).
        let ours = OcspRequestBuilder::new(KAT_LEAF, KAT_CA)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(hex::encode(ours), hex::encode(KAT_REQUEST));
        assert_eq!(kat_cert_id().serial_number, vec![0xA5, 0xC3]);
    }

    #[test]
    fn openssl_response_signed_by_the_ca() {
        let (response, authorization) = kat_verify(KAT_CA_GOOD).unwrap();
        assert_eq!(authorization, ResponderAuthorization::Issuer);
        assert_eq!(response.cert_status, Some(CertificateStatus::Good));
        assert!(response.next_update.is_some());
        assert!(response.nonce.is_none());
    }

    #[test]
    fn openssl_response_signed_by_a_delegated_responder() {
        let (response, authorization) = kat_verify(KAT_DELEGATED_GOOD).unwrap();
        assert_eq!(
            authorization,
            ResponderAuthorization::Delegated {
                certificate: KAT_RESPONDER.to_vec(),
                nocheck: true,
            }
        );
        assert_eq!(response.cert_status, Some(CertificateStatus::Good));
    }

    #[test]
    fn openssl_revoked_response() {
        let (response, _) = kat_verify(KAT_CA_REVOKED).unwrap();
        match response.cert_status {
            Some(CertificateStatus::Revoked { reason, .. }) => assert_eq!(reason, Some(1)),
            other => panic!("expected revoked, got {other:?}"),
        }
    }

    #[test]
    fn openssl_response_with_one_flipped_signature_bit_is_rejected() {
        // Locate the signature octets inside the response and flip one bit of
        // the ECDSA `r` value.
        let (_, basic) = parse_outer(KAT_CA_GOOD).unwrap();
        let signature = split_signed(basic.unwrap()).unwrap().signature;
        let offset = signature.as_ptr() as usize - KAT_CA_GOOD.as_ptr() as usize;
        let mut tampered = KAT_CA_GOOD.to_vec();
        tampered[offset + 10] ^= 0x01;
        assert!(matches!(
            kat_verify(&tampered),
            Err(RevocationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn openssl_response_checked_against_the_wrong_issuer_is_rejected() {
        // The responder certificate is not a CA; using it as "issuer" must not
        // let the CA-signed response through.
        let result = OcspResponse::parse_verified(
            KAT_CA_GOOD,
            &kat_cert_id(),
            KAT_RESPONDER,
            &default_algorithms(),
            SystemTime::now(),
            Duration::from_secs(3600),
        );
        assert!(result.is_err());
    }

    #[test]
    fn unverified_parse_reads_the_first_single_response() {
        let response = OcspResponse::parse(KAT_CA_REVOKED).unwrap();
        assert!(response.is_revoked());
    }

    #[test]
    fn error_status_is_never_verified() {
        // OCSPResponse { responseStatus tryLater }
        let try_later = [0x30, 0x03, 0x0A, 0x01, 0x03];
        assert_eq!(
            OcspResponse::parse(&try_later).unwrap().status,
            OcspResponseStatus::TryLater
        );
        assert!(matches!(
            OcspResponse::parse_verified(
                &try_later,
                &kat_cert_id(),
                KAT_CA,
                &default_algorithms(),
                SystemTime::now(),
                Duration::from_secs(3600)
            ),
            Err(RevocationError::OcspError(_))
        ));
    }

    const KAT_RSA_CA: &[u8] = include_bytes!("../../tests/fixtures/ocsp/rsa-ca.der");
    const KAT_RSA_LEAF: &[u8] = include_bytes!("../../tests/fixtures/ocsp/rsa-leaf.der");
    const KAT_RSA_REVOKED: &[u8] = include_bytes!("../../tests/fixtures/ocsp/resp-rsa-revoked.der");
    const KAT_RSA_PSS_REVOKED: &[u8] =
        include_bytes!("../../tests/fixtures/ocsp/resp-rsa-pss-revoked.der");

    #[test]
    fn openssl_rsa_pkcs1_and_pss_responses_verify() {
        let cert_id = OcspRequestBuilder::new(KAT_RSA_LEAF, KAT_RSA_CA)
            .unwrap()
            .cert_id();
        for (name, response) in [("PKCS#1", KAT_RSA_REVOKED), ("PSS", KAT_RSA_PSS_REVOKED)] {
            let (parsed, authorization) = OcspResponse::parse_verified(
                response,
                &cert_id,
                KAT_RSA_CA,
                &default_algorithms(),
                SystemTime::now(),
                Duration::from_secs(3600),
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(authorization, ResponderAuthorization::Issuer, "{name}");
            assert!(parsed.is_revoked(), "{name}");
        }
    }

    #[test]
    fn generalized_time_parses_with_and_without_fraction() {
        let t = parse_generalized_time("20260101000000Z").unwrap();
        assert_eq!(unix_secs(t), 1_767_225_600);
        let t = parse_generalized_time("20260101000000.5Z").unwrap();
        assert_eq!(unix_secs(t), 1_767_225_600);
        assert!(parse_generalized_time("20260101000000").is_err());
    }
}
