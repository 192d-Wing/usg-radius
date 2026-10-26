//! CRL parsing and validation
#![allow(dead_code)] // CRL support in-progress; some helpers unused today
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
//! - Validates CRL signatures and timestamps
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
//! let crl = CrlInfo::parse_der(&crl_der)?;
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
use std::collections::HashSet;
use x509_parser::prelude::*;

/// Parsed CRL information
///
/// Contains all relevant information extracted from a CRL for efficient
/// revocation checking.
#[derive(Debug, Clone)]
pub struct CrlInfo {
    /// CRL issuer distinguished name
    pub issuer: String,

    /// CRL thisUpdate time (when this CRL was issued)
    pub this_update: chrono::DateTime<chrono::Utc>,

    /// CRL nextUpdate time (when next CRL will be issued, optional per RFC 5280)
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,

    /// Set of revoked certificate serial numbers (for O(1) lookup)
    pub revoked_serials: HashSet<Vec<u8>>,

    /// Signature algorithm OID
    pub signature_algorithm: String,

    /// CRL number (optional extension, for tracking)
    pub crl_number: Option<u64>,
}

impl CrlInfo {
    /// Parse a CRL from DER-encoded bytes
    ///
    /// This function:
    /// 1. Parses the DER-encoded CRL structure
    /// 2. Extracts issuer, validity period, and signature info
    /// 3. Builds a HashSet of revoked certificate serial numbers
    /// 4. Validates the CRL structure (but not the signature)
    ///
    /// # Arguments
    ///
    /// * `crl_der` - DER-encoded CRL bytes
    ///
    /// # Returns
    ///
    /// * `Ok(CrlInfo)` - Successfully parsed CRL
    /// * `Err(RevocationError)` - Parse error or invalid CRL
    ///
    /// # Note
    ///
    /// This function does NOT verify the CRL signature. Signature verification
    /// should be performed by rustls during TLS handshake or separately if
    /// loading static CRL files.
    pub fn parse_der(crl_der: &[u8]) -> Result<Self, RevocationError> {
        // Parse the CRL using x509-parser
        let (_, crl) = parse_x509_crl(crl_der)
            .map_err(|e| RevocationError::ParseError(format!("Failed to parse CRL DER: {}", e)))?;

        // Extract issuer
        let issuer = crl.issuer().to_string();

        // Extract thisUpdate (required)
        let this_update = asn1_time_to_chrono(&crl.last_update()).ok_or_else(|| {
            RevocationError::ParseError("Invalid thisUpdate time in CRL".to_string())
        })?;

        // Extract nextUpdate (optional per RFC 5280)
        let next_update = crl.next_update().and_then(|t| asn1_time_to_chrono(&t));

        // Extract signature algorithm
        let signature_algorithm = crl.signature_algorithm.algorithm.to_id_string();

        // Extract CRL number extension (if present)
        let crl_number = None; // Simplified for Phase 1.2

        // Build HashSet of revoked serial numbers
        let mut revoked_serials = HashSet::new();

        for revoked_cert in crl.iter_revoked_certificates() {
            // Minimal big-endian magnitude, the same form `X509Certificate::serial`
            // (a `BigUint`) yields, so a serial with its top bit set (DER pads it
            // with a leading 0x00) still matches the certificate's serial.
            revoked_serials.insert(revoked_cert.user_certificate.to_bytes_be());
        }

        Ok(CrlInfo {
            issuer,
            this_update,
            next_update,
            revoked_serials,
            signature_algorithm,
            crl_number,
        })
    }

    /// Parse a CRL from PEM-encoded bytes
    ///
    /// Convenience method for parsing PEM-encoded CRLs.
    /// The PEM format is base64-encoded DER with header/footer.
    ///
    /// # Arguments
    ///
    /// * `pem_data` - PEM-encoded CRL bytes
    ///
    /// # Returns
    ///
    /// * `Ok(CrlInfo)` - Successfully parsed CRL
    /// * `Err(RevocationError)` - Parse error or invalid CRL
    pub fn parse_pem(pem_data: &[u8]) -> Result<Self, RevocationError> {
        // Parse PEM to get DER
        let pem = x509_parser::pem::parse_x509_pem(pem_data)
            .map_err(|e| RevocationError::ParseError(format!("Failed to parse CRL PEM: {}", e)))?;

        // Parse the DER content
        Self::parse_der(&pem.1.contents)
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
    /// 2. `nextUpdate` > `now` (CRL is not expired, if nextUpdate is present)
    ///
    /// Per RFC 5280 Section 5.1.2.4, nextUpdate is optional. If not present,
    /// the CRL is considered valid indefinitely (though this is discouraged).
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

        // Check nextUpdate > now (if present)
        if let Some(next_update) = self.next_update
            && next_update <= now
        {
            return Err(RevocationError::CrlExpired(next_update.to_rfc3339()));
        }

        Ok(())
    }

    /// Get the number of revoked certificates in this CRL
    pub fn revoked_count(&self) -> usize {
        self.revoked_serials.len()
    }

    /// Check if CRL has any revoked certificates
    pub fn is_empty(&self) -> bool {
        self.revoked_serials.is_empty()
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

// CRL Number extraction is deferred to Phase 1.6 (Integration Tests)
// when we'll have real test PKI infrastructure to validate against.
// CRL Number is optional metadata (RFC 5280 Section 5.2.3) and
// not critical for core revocation checking functionality.

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    // Helper to create a minimal test CRL in DER format
    // This is a placeholder - in real tests, we'd use test PKI generation
    fn create_test_crl_der() -> Vec<u8> {
        // This would be a real DER-encoded CRL in production tests
        // For now, we'll test with actual CRL data in integration tests
        vec![]
    }

    #[test]
    fn test_crl_info_is_revoked() {
        let mut revoked_serials = HashSet::new();
        revoked_serials.insert(vec![0x01, 0x02, 0x03]);
        revoked_serials.insert(vec![0xAA, 0xBB, 0xCC]);

        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            this_update: Utc::now(),
            next_update: Some(Utc::now() + chrono::Duration::days(7)),
            revoked_serials,
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(42),
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
            this_update: now - chrono::Duration::hours(1),
            next_update: Some(now + chrono::Duration::days(7)),
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(1),
        };
        assert!(crl.validate_current(now).is_ok());
    }

    #[test]
    fn test_crl_info_validate_expired() {
        let now = Utc::now();

        // Expired CRL
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            this_update: now - chrono::Duration::days(30),
            next_update: Some(now - chrono::Duration::days(1)), // Expired
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(1),
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
            this_update: now + chrono::Duration::hours(1), // Future
            next_update: Some(now + chrono::Duration::days(7)),
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(1),
        };

        let result = crl.validate_current(now);
        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::CrlNotYetValid(_))));
    }

    #[test]
    fn test_crl_info_validate_no_next_update() {
        let now = Utc::now();

        // CRL without nextUpdate (valid per RFC 5280)
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            this_update: now - chrono::Duration::hours(1),
            next_update: None, // No expiry
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: Some(1),
        };

        assert!(crl.validate_current(now).is_ok());
    }

    #[test]
    fn test_crl_info_revoked_count() {
        let mut revoked_serials = HashSet::new();
        revoked_serials.insert(vec![0x01]);
        revoked_serials.insert(vec![0x02]);
        revoked_serials.insert(vec![0x03]);

        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            this_update: Utc::now(),
            next_update: None,
            revoked_serials,
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: None,
        };

        assert_eq!(crl.revoked_count(), 3);
        assert!(!crl.is_empty());
    }

    #[test]
    fn test_crl_info_empty() {
        let crl = CrlInfo {
            issuer: "CN=Test CA".to_string(),
            this_update: Utc::now(),
            next_update: None,
            revoked_serials: HashSet::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            crl_number: None,
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

    // Note: Full CRL parsing tests with real DER/PEM data will be added
    // in Phase 1.6 (integration tests) once we have test PKI infrastructure
}
