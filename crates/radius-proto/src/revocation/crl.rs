//! CRL parsing and validation
//!
//! This module handles parsing of Certificate Revocation Lists (RFC 5280)
//! and checking if certificates are revoked.
//!
//! # Overview
//!
//! A Certificate Revocation List (CRL) is a signed list of revoked certificates
//! published by a Certificate Authority. This module:
//!
//! - Parses DER-encoded CRLs using x509-parser
//! - Verifies CRL signatures against the issuing CA (RFC 5280 §6.3.3)
//! - Validates CRL timestamps and extracts the CRL number
//! - Provides O(1) serial number lookup via HashSet
//! - Checks CRL freshness (thisUpdate/nextUpdate)
//!
//! # Example
//!
//! (`ignore`: this module is crate-private; the example is illustrative)
//! ```ignore
//! use radius_proto::revocation::crl::CrlInfo;
//! use chrono::Utc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let crl_der = std::fs::read("crl.der")?;
//! # let ca_der: Vec<u8> = Vec::new();
//! # let algorithms = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
//! // Parse, then verify the signature with the issuing CA's certificate
//! let crl = CrlInfo::parse_and_verify(&crl_der, &ca_der, &algorithms)?;
//!
//! // Validate CRL is current
//! crl.validate_current(Utc::now())?;
//!
//! // Check if certificate is revoked
//! let serial = vec![0x01, 0x02, 0x03];
//! if crl.is_revoked(&serial) {
//!     println!("Certificate is revoked!");
//! }
//! # Ok(())
//! # }
//! ```

use super::error::RevocationError;
use super::signature::{split_signed, verify_signed_data};
use rustls::crypto::WebPkiSupportedAlgorithms;
use std::collections::HashSet;
use x509_parser::num_bigint::BigUint;
use x509_parser::prelude::*;

/// CRL extensions (RFC 5280 §5.2) this module understands.
const OID_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const OID_ISSUER_ALT_NAME: &str = "2.5.29.18";
const OID_CRL_NUMBER: &str = "2.5.29.20";
const OID_DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const OID_ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
const OID_FRESHEST_CRL: &str = "2.5.29.46";
/// CRL entry extensions (RFC 5280 §5.3) this module understands.
const OID_REASON_CODE: &str = "2.5.29.21";
const OID_INVALIDITY_DATE: &str = "2.5.29.24";

/// Parsed CRL information
///
/// Contains all relevant information extracted from a CRL for efficient
/// revocation checking.
#[derive(Debug, Clone)]
pub struct CrlInfo {
    /// CRL issuer distinguished name (for messages)
    pub issuer: String,

    /// CRL issuer Name, DER as encoded in the CRL (for matching)
    pub issuer_raw: Vec<u8>,

    /// CRL thisUpdate time (when this CRL was issued)
    pub this_update: chrono::DateTime<chrono::Utc>,

    /// CRL nextUpdate time (when next CRL will be issued, optional per RFC 5280)
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,

    /// Set of revoked certificate serial numbers (for O(1) lookup)
    pub revoked_serials: HashSet<Vec<u8>>,

    /// Signature algorithm OID (informational)
    #[allow(dead_code)]
    pub signature_algorithm: String,

    /// CRL number (RFC 5280 §5.2.3), used to refuse a CRL older than one
    /// already accepted for the same issuer
    pub crl_number: Option<BigUint>,

    /// DER SubjectPublicKeyInfo of the key the CRL signature was verified
    /// with; `None` until [`CrlInfo::verify_signature`] succeeds. A CRL is
    /// only consulted for a certificate whose issuer holds this key.
    pub verified_with: Option<Vec<u8>>,
}

impl CrlInfo {
    /// Parse a CRL from DER-encoded bytes
    ///
    /// This function:
    /// 1. Parses the DER-encoded CRL structure
    /// 2. Extracts issuer, validity period, CRL number and signature info
    /// 3. Builds a HashSet of revoked certificate serial numbers
    /// 4. Rejects CRLs this module cannot process correctly: a
    ///    TBSCertList.signature that differs from the outer
    ///    signatureAlgorithm (RFC 5280 §5.1.1.2), delta CRLs, CRLs scoped by
    ///    an Issuing Distribution Point, and any unrecognized critical CRL or
    ///    CRL entry extension (RFC 5280 §5.2, §5.3)
    ///
    /// The result is **unverified** (`verified_with` is `None`); call
    /// [`CrlInfo::verify_signature`] with the issuing CA before trusting it.
    pub fn parse_der(crl_der: &[u8]) -> Result<Self, RevocationError> {
        // Parse the CRL using x509-parser
        let (_, crl) = parse_x509_crl(crl_der)
            .map_err(|e| RevocationError::ParseError(format!("Failed to parse CRL DER: {}", e)))?;

        // RFC 5280 §5.1.1.2: signatureAlgorithm MUST equal TBSCertList.signature.
        if crl.signature_algorithm != crl.tbs_cert_list.signature {
            return Err(RevocationError::ParseError(
                "CRL signatureAlgorithm differs from TBSCertList.signature".to_string(),
            ));
        }

        for ext in crl.extensions() {
            match ext.oid.to_id_string().as_str() {
                OID_AUTHORITY_KEY_IDENTIFIER
                | OID_ISSUER_ALT_NAME
                | OID_CRL_NUMBER
                | OID_FRESHEST_CRL => {}
                OID_DELTA_CRL_INDICATOR => {
                    return Err(RevocationError::ParseError(
                        "delta CRLs are not supported".to_string(),
                    ));
                }
                OID_ISSUING_DISTRIBUTION_POINT => {
                    return Err(RevocationError::ParseError(
                        "CRLs with an Issuing Distribution Point (partitioned or indirect CRLs) \
                         are not supported"
                            .to_string(),
                    ));
                }
                other if ext.critical => {
                    return Err(RevocationError::ParseError(format!(
                        "unrecognized critical CRL extension {other}"
                    )));
                }
                _ => {}
            }
        }

        // Extract issuer
        let issuer = crl.issuer().to_string();
        let issuer_raw = crl.issuer().as_raw().to_vec();

        // Extract thisUpdate (required)
        let this_update = asn1_time_to_chrono(&crl.last_update()).ok_or_else(|| {
            RevocationError::ParseError("Invalid thisUpdate time in CRL".to_string())
        })?;

        // nextUpdate: OPTIONAL in the ASN.1, but conforming CRL issuers MUST
        // include it (RFC 5280 §5.1.2.5); `validate_current` refuses a CRL
        // without one. A value that does not convert is malformed, not absent.
        let next_update = match crl.next_update() {
            Some(t) => Some(asn1_time_to_chrono(&t).ok_or_else(|| {
                RevocationError::ParseError("Invalid nextUpdate time in CRL".to_string())
            })?),
            None => None,
        };

        // Extract signature algorithm
        let signature_algorithm = crl.signature_algorithm.algorithm.to_id_string();

        // RFC 5280 §5.2.3 CRL number
        let crl_number = crl.crl_number().cloned();

        // Build HashSet of revoked serial numbers
        let mut revoked_serials = HashSet::new();

        for revoked_cert in crl.iter_revoked_certificates() {
            // RFC 5280 §5.3: an unrecognized critical entry extension (for
            // example certificateIssuer, which makes the CRL indirect) means
            // the CRL cannot be used.
            if let Some(ext) = revoked_cert.extensions().iter().find(|ext| {
                ext.critical
                    && !matches!(
                        ext.oid.to_id_string().as_str(),
                        OID_REASON_CODE | OID_INVALIDITY_DATE
                    )
            }) {
                return Err(RevocationError::ParseError(format!(
                    "unrecognized critical CRL entry extension {}",
                    ext.oid
                )));
            }
            // Minimal big-endian magnitude, the same form `X509Certificate::serial`
            // (a `BigUint`) yields, so a serial with its top bit set (DER pads it
            // with a leading 0x00) still matches the certificate's serial.
            revoked_serials.insert(revoked_cert.user_certificate.to_bytes_be());
        }

        Ok(CrlInfo {
            issuer,
            issuer_raw,
            this_update,
            next_update,
            revoked_serials,
            signature_algorithm,
            crl_number,
            verified_with: None,
        })
    }

    /// Verify the CRL signature against the certificate of its issuer
    /// (RFC 5280 §6.3.3 (f)–(g)).
    ///
    /// `crl_der` must be the DER this `CrlInfo` was parsed from and
    /// `issuer_der` a certificate the caller already trusts (a trust anchor or
    /// a certificate chained to one). Checks, in order:
    ///
    /// 1. the CRL issuer Name equals the certificate's subject Name;
    /// 2. if the certificate has a keyUsage extension, it asserts cRLSign
    ///    (RFC 5280 §4.2.1.3);
    /// 3. the signature verifies with the certificate's public key under the
    ///    CRL's signatureAlgorithm.
    ///
    /// On success `verified_with` records the key.
    pub fn verify_signature(
        &mut self,
        crl_der: &[u8],
        issuer_der: &[u8],
        algorithms: &WebPkiSupportedAlgorithms,
    ) -> Result<(), RevocationError> {
        self.verified_with = Some(self.check_signature(crl_der, issuer_der, algorithms)?);
        Ok(())
    }

    /// [`CrlInfo::verify_signature`] without recording the result; returns
    /// the DER SubjectPublicKeyInfo the signature verified with.
    pub(crate) fn check_signature(
        &self,
        crl_der: &[u8],
        issuer_der: &[u8],
        algorithms: &WebPkiSupportedAlgorithms,
    ) -> Result<Vec<u8>, RevocationError> {
        let (_, issuer) = parse_x509_certificate(issuer_der).map_err(|e| {
            RevocationError::CertificateError(format!("Failed to parse CRL issuer: {}", e))
        })?;

        if issuer.subject().as_raw() != self.issuer_raw.as_slice() {
            return Err(RevocationError::InvalidSignature(format!(
                "CRL issuer {} is not the certificate issuer {}",
                self.issuer,
                issuer.subject()
            )));
        }

        match issuer.key_usage() {
            Ok(Some(ku)) if !ku.value.crl_sign() => {
                return Err(RevocationError::InvalidSignature(format!(
                    "keyUsage of {} does not permit cRLSign",
                    issuer.subject()
                )));
            }
            Ok(_) => {}
            Err(e) => {
                return Err(RevocationError::CertificateError(format!(
                    "keyUsage of CRL issuer: {e}"
                )));
            }
        }

        let signed = split_signed(crl_der)?;
        if !signed.trailing.is_empty() {
            return Err(RevocationError::ParseError(
                "unexpected data after CRL signature".to_string(),
            ));
        }
        let spki = issuer.public_key().raw;
        verify_signed_data(algorithms, spki, &signed).map_err(|e| match e {
            RevocationError::InvalidSignature(why) => {
                RevocationError::InvalidSignature(format!("CRL from {}: {why}", self.issuer))
            }
            other => other,
        })?;
        Ok(spki.to_vec())
    }

    /// Parse a DER CRL and verify its signature with `issuer_der`.
    pub fn parse_and_verify(
        crl_der: &[u8],
        issuer_der: &[u8],
        algorithms: &WebPkiSupportedAlgorithms,
    ) -> Result<Self, RevocationError> {
        let mut crl = Self::parse_der(crl_der)?;
        crl.verify_signature(crl_der, issuer_der, algorithms)?;
        Ok(crl)
    }

    /// Was the signature verified with the key in `spki_der`?
    pub fn is_verified_by(&self, spki_der: &[u8]) -> bool {
        self.verified_with.as_deref() == Some(spki_der)
    }

    /// Check if a certificate serial number is revoked
    ///
    /// Uses HashSet for O(1) lookup performance.
    ///
    /// # Arguments
    ///
    /// * `serial` - Certificate serial number bytes
    ///
    /// # Returns
    ///
    /// * `true` - Certificate is revoked
    /// * `false` - Certificate is not revoked (or not in this CRL)
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked_serials.contains(serial)
    }

    /// Validate CRL is current (not expired and not future-dated)
    ///
    /// Checks:
    /// 1. `thisUpdate` <= `now` (CRL is not future-dated)
    /// 2. `nextUpdate` is present and > `now` (CRL is not expired)
    ///
    /// nextUpdate is OPTIONAL in the ASN.1, but conforming CRL issuers MUST
    /// include it (RFC 5280 §5.1.2.5). A CRL without one would be current
    /// forever, so a recorded old CRL could be replayed indefinitely (the
    /// crlNumber floor does not survive a restart); it is refused instead.
    ///
    /// # Arguments
    ///
    /// * `now` - Current time for validation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - CRL is current
    /// * `Err(RevocationError::CrlExpired)` - CRL has expired
    /// * `Err(RevocationError::CrlNotYetValid)` - CRL is future-dated
    pub fn validate_current(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), RevocationError> {
        // Check thisUpdate <= now
        if self.this_update > now {
            return Err(RevocationError::CrlNotYetValid(
                self.this_update.to_rfc3339(),
            ));
        }

        // Check nextUpdate > now
        match self.next_update {
            Some(next_update) if next_update <= now => {
                return Err(RevocationError::CrlExpired(next_update.to_rfc3339()));
            }
            Some(_) => {}
            None => {
                return Err(RevocationError::CrlExpired(
                    "absent (RFC 5280 §5.1.2.5 requires nextUpdate)".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Get the number of revoked certificates in this CRL
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn revoked_count(&self) -> usize {
        self.revoked_serials.len()
    }

    /// Check if CRL has any revoked certificates
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.revoked_serials.is_empty()
    }
}

/// DER of a CRL given as PEM (detected by its armor) or DER.
pub(crate) fn crl_der_from_bytes(bytes: &[u8]) -> Result<Vec<u8>, RevocationError> {
    if bytes.starts_with(b"-----BEGIN") {
        let (_, pem) = x509_parser::pem::parse_x509_pem(bytes)
            .map_err(|e| RevocationError::ParseError(format!("Failed to parse CRL PEM: {}", e)))?;
        Ok(pem.contents)
    } else {
        Ok(bytes.to_vec())
    }
}

/// Convert ASN.1 time to chrono DateTime
///
/// Handles both UTCTime and GeneralizedTime formats.
fn asn1_time_to_chrono(asn1_time: &ASN1Time) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;

    // x509-parser returns seconds since UNIX epoch
    let timestamp = asn1_time.timestamp();
    chrono::Utc.timestamp_opt(timestamp, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_crl_info_is_revoked() {
        let mut revoked_serials = HashSet::new();
        revoked_serials.insert(vec![0x01, 0x02, 0x03]);
        revoked_serials.insert(vec![0xAA, 0xBB, 0xCC]);

        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            issuer_raw: Vec::new(),
            this_update: Utc::now(),
            next_update: Some(Utc::now() + chrono::Duration::days(7)),
            revoked_serials,
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(BigUint::from(42u32)),
            verified_with: None,
        };

        // Test revoked certificate
        assert!(crl.is_revoked(&[0x01, 0x02, 0x03]));
        assert!(crl.is_revoked(&[0xAA, 0xBB, 0xCC]));

        // Test non-revoked certificate
        assert!(!crl.is_revoked(&[0xFF, 0xFF, 0xFF]));
        assert!(!crl.is_revoked(&[]));
    }

    #[test]
    fn test_crl_info_validate_current() {
        let now = Utc::now();

        // Valid CRL (current)
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            issuer_raw: Vec::new(),
            this_update: now - chrono::Duration::hours(1),
            next_update: Some(now + chrono::Duration::days(7)),
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(BigUint::from(1u32)),
            verified_with: None,
        };
        assert!(crl.validate_current(now).is_ok());
    }

    #[test]
    fn test_crl_info_validate_expired() {
        let now = Utc::now();

        // Expired CRL
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            issuer_raw: Vec::new(),
            this_update: now - chrono::Duration::days(30),
            next_update: Some(now - chrono::Duration::days(1)), // Expired
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(BigUint::from(1u32)),
            verified_with: None,
        };

        let result = crl.validate_current(now);
        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::CrlExpired(_))));
    }

    #[test]
    fn test_crl_info_validate_future() {
        let now = Utc::now();

        // Future-dated CRL (thisUpdate in future)
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            issuer_raw: Vec::new(),
            this_update: now + chrono::Duration::hours(1), // Future
            next_update: Some(now + chrono::Duration::days(7)),
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(BigUint::from(1u32)),
            verified_with: None,
        };

        let result = crl.validate_current(now);
        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::CrlNotYetValid(_))));
    }

    #[test]
    fn test_crl_info_without_next_update_is_refused() {
        let now = Utc::now();

        // CRL without nextUpdate: refused (RFC 5280 §5.1.2.5)
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            issuer_raw: Vec::new(),
            this_update: now - chrono::Duration::hours(1),
            next_update: None, // No expiry
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(BigUint::from(1u32)),
            verified_with: None,
        };

        assert!(matches!(
            crl.validate_current(now),
            Err(RevocationError::CrlExpired(_))
        ));
    }

    #[test]
    fn test_crl_info_revoked_count() {
        let mut revoked_serials = HashSet::new();
        revoked_serials.insert(vec![0x01]);
        revoked_serials.insert(vec![0x02]);
        revoked_serials.insert(vec![0x03]);

        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            issuer_raw: Vec::new(),
            this_update: Utc::now(),
            next_update: None,
            revoked_serials,
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: None,
            verified_with: None,
        };

        assert_eq!(crl.revoked_count(), 3);
        assert!(!crl.is_empty());
    }

    #[test]
    fn test_crl_info_empty() {
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            issuer_raw: Vec::new(),
            this_update: Utc::now(),
            next_update: None,
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: None,
            verified_with: None,
        };

        assert_eq!(crl.revoked_count(), 0);
        assert!(crl.is_empty());
    }

    #[test]
    fn test_asn1_time_conversion() {
        // Test that ASN.1 time conversion works
        // In real tests, we'd create actual ASN1Time objects
        let now = Utc::now();
        let timestamp = now.timestamp();

        // Verify round-trip conversion
        let converted = chrono::Utc.timestamp_opt(timestamp, 0).single();
        assert!(converted.is_some());
    }

    // Known answers: OpenSSL-signed RSA CRLs (tests/fixtures/ocsp/gen.sh),
    // PKCS#1 v1.5 and PSS, each revoking serial 5A5A of the RSA KAT leaf.
    const RSA_CA: &[u8] = include_bytes!("../../tests/fixtures/ocsp/rsa-ca.der");
    const ECDSA_CA: &[u8] = include_bytes!("../../tests/fixtures/ocsp/ca.der");
    const RSA_CRL: &[u8] = include_bytes!("../../tests/fixtures/ocsp/crl-rsa.der");
    const RSA_PSS_CRL: &[u8] = include_bytes!("../../tests/fixtures/ocsp/crl-rsa-pss.der");

    #[test]
    fn openssl_rsa_crls_verify_and_list_the_serial() {
        let algorithms = crate::revocation::signature::default_algorithms();
        for (name, der, number) in [("PKCS#1", RSA_CRL, 1u32), ("PSS", RSA_PSS_CRL, 2)] {
            let crl = CrlInfo::parse_and_verify(der, RSA_CA, &algorithms)
                .unwrap_or_else(|e| panic!("{name}: {}", e.kind()));
            assert!(crl.is_revoked(&[0x5A, 0x5A]), "{name}");
            assert_eq!(crl.crl_number, Some(BigUint::from(number)), "{name}");
            crl.validate_current(Utc::now()).unwrap();
        }
    }

    #[test]
    fn openssl_rsa_crl_does_not_verify_with_another_ca() {
        let algorithms = crate::revocation::signature::default_algorithms();
        let mut crl = CrlInfo::parse_der(RSA_CRL).unwrap();
        // Different issuer Name: refused before any signature math.
        assert!(matches!(
            crl.verify_signature(RSA_CRL, ECDSA_CA, &algorithms),
            Err(RevocationError::InvalidSignature(_))
        ));
        assert!(crl.verified_with.is_none());
    }
}
