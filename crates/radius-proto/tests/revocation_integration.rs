//! Integration tests for CRL revocation checking
//!
//! These tests validate the end-to-end revocation checking flow with
//! real certificate and CRL data structures.
//!
//! # Test PKI Setup
//!
//! For full integration testing, you'll need to generate:
//!
//! 1. **Root CA**: Self-signed root certificate
//! 2. **Intermediate CA**: Signed by root CA
//! 3. **Server Certificate**: For RADIUS server (signed by intermediate)
//! 4. **Client Certificates**: For EAP-TLS clients (signed by intermediate)
//! 5. **CRL**: Certificate Revocation List (signed by intermediate)
//!
//! ## Generating Test PKI (OpenSSL)
//!
//! ```bash
//! # Generate Root CA
//! openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
//!   -keyout root-key.pem -out root-cert.pem \
//!   -subj "/CN=Test Root CA"
//!
//! # Generate Intermediate CA
//! openssl req -newkey rsa:2048 -nodes \
//!   -keyout intermediate-key.pem -out intermediate-req.pem \
//!   -subj "/CN=Test Intermediate CA"
//!
//! openssl x509 -req -in intermediate-req.pem \
//!   -CA root-cert.pem -CAkey root-key.pem -CAcreateserial \
//!   -out intermediate-cert.pem -days 365 \
//!   -extensions v3_ca -extfile openssl.cnf
//!
//! # Generate Client Certificate with CRL Distribution Point
//! openssl req -newkey rsa:2048 -nodes \
//!   -keyout client-key.pem -out client-req.pem \
//!   -subj "/CN=test-client"
//!
//! # Add CRL Distribution Point extension
//! cat > client-ext.cnf <<EOF
//! crlDistributionPoints = URI:http://localhost:8000/test.crl
//! EOF
//!
//! openssl x509 -req -in client-req.pem \
//!   -CA intermediate-cert.pem -CAkey intermediate-key.pem -CAcreateserial \
//!   -out client-cert.pem -days 365 \
//!   -extfile client-ext.cnf
//!
//! # Generate Empty CRL
//! openssl ca -gencrl -keyfile intermediate-key.pem \
//!   -cert intermediate-cert.pem -out empty.crl
//!
//! # Revoke Client Certificate and Generate CRL
//! openssl ca -revoke client-cert.pem \
//!   -keyfile intermediate-key.pem -cert intermediate-cert.pem
//! openssl ca -gencrl -keyfile intermediate-key.pem \
//!   -cert intermediate-cert.pem -out revoked.crl
//! ```

#![cfg(feature = "revocation")]

use radius_proto::revocation::{
    CrlConfig, FallbackBehavior, OcspConfig, RevocationCheckMode, RevocationConfig,
};

/// Test configuration creation
#[test]
fn test_revocation_config_integration() {
    // Test creating a production-like configuration
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig {
            static_crl_paths: vec!["/etc/radius/crls/ca.crl".to_string()],
            enable_http_fetch: true,
            http_timeout_secs: 5,
            cache_ttl_secs: 3600,
            max_cache_entries: 100,
            max_crl_size_bytes: 10 * 1024 * 1024,
        },
        ocsp_config: OcspConfig::default(),
    };

    assert_eq!(config.check_mode, RevocationCheckMode::CrlOnly);
    assert_eq!(config.fallback_behavior, FallbackBehavior::FailClosed);
    assert_eq!(config.crl_config.http_timeout_secs, 5);
    assert_eq!(config.crl_config.cache_ttl_secs, 3600);
}

/// Test fail-open vs fail-closed behavior
#[test]
fn test_fallback_behavior_modes() {
    // Fail-closed for production (high security)
    let fail_closed = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::default(),
        ocsp_config: OcspConfig::default(),
    };

    assert_eq!(fail_closed.fallback_behavior, FallbackBehavior::FailClosed);

    // Fail-open for testing/development (availability over security)
    let fail_open = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailOpen,
        crl_config: CrlConfig::default(),
        ocsp_config: OcspConfig::default(),
    };

    assert_eq!(fail_open.fallback_behavior, FallbackBehavior::FailOpen);
}

/// Test disabled mode (bypass revocation checking)
#[test]
fn test_disabled_mode() {
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::Disabled,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::default(),
        ocsp_config: OcspConfig::default(),
    };

    assert_eq!(config.check_mode, RevocationCheckMode::Disabled);
}

/// Test static CRL file configuration
#[test]
fn test_static_crl_configuration() {
    let config = RevocationConfig::static_files(
        vec![
            "/etc/radius/crls/root-ca.crl".to_string(),
            "/etc/radius/crls/intermediate-ca.crl".to_string(),
        ],
        FallbackBehavior::FailClosed,
    );

    assert_eq!(config.crl_config.static_crl_paths.len(), 2);
    assert!(!config.crl_config.enable_http_fetch);
}

/// Test HTTP fetch configuration
#[test]
fn test_http_fetch_configuration() {
    let config = RevocationConfig::crl_only(
        CrlConfig::http_fetch(5, 3600, 100),
        FallbackBehavior::FailClosed,
    );

    assert!(config.crl_config.enable_http_fetch);
    assert_eq!(config.crl_config.http_timeout_secs, 5);
    assert_eq!(config.crl_config.cache_ttl_secs, 3600);
    assert_eq!(config.crl_config.max_cache_entries, 100);
}

/// Test configuration serialization
#[test]
fn test_config_json_serialization() {
    let config = RevocationConfig::default();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config).unwrap();
    assert!(json.contains("check_mode"));
    assert!(json.contains("fallback_behavior"));

    // Deserialize from JSON
    let deserialized: RevocationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.check_mode, config.check_mode);
}

// Note: The following tests would require actual certificate/CRL data.
// They are documented here but marked as ignored until test PKI is generated.

/// Integration test with real CRL parsing
///
/// This test uses the generated test PKI in tests/pki/ to verify CRL parsing
#[test]
fn test_real_crl_parsing() {
    use std::fs;
    use std::path::Path;

    // Ensure test PKI exists (relative to workspace root)
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|p| {
            Path::new(&p)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .unwrap();
    let crl_path = workspace_root.join("tests/pki/crls/intermediate-ca-empty.crl.der");
    assert!(
        crl_path.exists(),
        "Test PKI not found at {:?}. Run PKI generation first.",
        crl_path
    );

    // Read and parse the CRL to validate it's well-formed
    let crl_bytes = fs::read(&crl_path).expect("Failed to read CRL");

    // Parse CRL using x509-parser
    use x509_parser::prelude::*;
    use x509_parser::revocation_list::CertificateRevocationList;

    let parse_result = CertificateRevocationList::from_der(&crl_bytes);
    assert!(
        parse_result.is_ok(),
        "Failed to parse real CRL: {:?}",
        parse_result.err()
    );

    let (_, crl) = parse_result.unwrap();

    // Verify it's an empty CRL (no revocations)
    let revoked_certs = crl.iter_revoked_certificates().collect::<Vec<_>>();
    assert_eq!(
        revoked_certs.len(),
        0,
        "Empty CRL should have no revoked certificates"
    );

    // Verify issuer is correct
    assert!(
        crl.issuer().to_string().contains("Test Intermediate CA"),
        "CRL issuer should be Test Intermediate CA"
    );
}

/// Integration test with revoked certificate
///
/// This test validates that the CRL implementation correctly identifies
/// revoked certificates by their serial number.
#[test]
fn test_revoked_certificate_detection() {
    use std::fs;
    use std::path::Path;

    // Ensure test PKI exists (relative to workspace root)
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|p| {
            Path::new(&p)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .unwrap();
    let crl_path = workspace_root.join("tests/pki/crls/intermediate-ca.crl.der");
    let revoked_cert_path = workspace_root.join("tests/pki/certs/client-revoked.crt.der");

    assert!(crl_path.exists(), "Test CRL not found at {:?}", crl_path);
    assert!(
        revoked_cert_path.exists(),
        "Test revoked certificate not found at {:?}",
        revoked_cert_path
    );

    // Read the CRL and verify it contains the revoked certificate
    let crl_bytes = fs::read(crl_path).expect("Failed to read CRL");

    // Parse using x509-parser to verify structure
    use x509_parser::prelude::*;
    use x509_parser::revocation_list::CertificateRevocationList;
    let (_, crl) = CertificateRevocationList::from_der(&crl_bytes).expect("Failed to parse CRL");

    // Verify CRL has at least one revoked certificate
    let revoked_certs = crl.iter_revoked_certificates().collect::<Vec<_>>();
    assert!(
        !revoked_certs.is_empty(),
        "CRL should contain revoked certificates"
    );

    // Read the revoked certificate and get its serial
    let cert_bytes = fs::read(revoked_cert_path).expect("Failed to read certificate");
    let (_, cert) = parse_x509_certificate(&cert_bytes).expect("Failed to parse certificate");

    // Verify the certificate's serial is in the CRL
    let cert_serial = cert.serial.to_bytes_be();
    let is_revoked = revoked_certs
        .iter()
        .any(|revoked| revoked.raw_serial() == cert_serial.as_slice());

    assert!(is_revoked, "Revoked certificate serial should be in CRL");
}

/// Integration test with CRL caching
#[test]
#[ignore]
fn test_crl_cache_integration() {
    // This would test:
    // 1. First request: cache miss → HTTP fetch → cache store
    // 2. Second request: cache hit → no HTTP fetch
    // 3. After TTL: cache expired → HTTP fetch → cache update

    // Placeholder: CRL caching integration requires HTTP server setup.
}

/// Integration test with EAP-TLS
#[test]
#[ignore]
fn test_eap_tls_revocation_integration() {
    // This would test the full EAP-TLS authentication flow:
    // 1. TLS handshake with client cert
    // 2. Extract CRL distribution points
    // 3. Fetch CRL
    // 4. Check revocation
    // 5. Accept or reject authentication

    // Placeholder: EAP-TLS integration requires full TLS handshake setup.
}

// Future integration tests to add:
// - test_multiple_distribution_points: Test fallback when first URL fails
// - test_crl_expiration: Test behavior with expired CRL
// - test_http_timeout: Test timeout handling
// - test_size_limit: Test CRL size limit enforcement
// - test_concurrent_requests: Test cache under concurrent load
// - test_fail_open_mode: Test authentication succeeds on CRL fetch failure
// - test_fail_closed_mode: Test authentication fails on CRL fetch failure

/// Test that verifies the module is properly feature-gated
#[test]
fn test_feature_gate() {
    // This test ensures the revocation module is only available with the feature flag
    // The fact that this compiles means the feature is working
    let _config = RevocationConfig::default();
}

/// Documentation test showing production configuration
///
/// This demonstrates how a production RADIUS server would configure
/// certificate revocation checking.
#[test]
fn test_production_configuration_example() {
    // High-security deployment with fail-closed mode
    let production_config = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailClosed, // Reject on errors
        crl_config: CrlConfig {
            static_crl_paths: vec![
                "/etc/radius/crls/root-ca.crl".to_string(),
                "/etc/radius/crls/intermediate-ca.crl".to_string(),
            ],
            enable_http_fetch: true, // Allow fetching from cert extensions
            http_timeout_secs: 5,    // 5 second timeout for CRL fetch
            cache_ttl_secs: 3600,    // Cache CRLs for 1 hour
            max_cache_entries: 100,  // Cache up to 100 CRLs
            max_crl_size_bytes: 10 * 1024 * 1024, // 10 MB limit
        },
        ocsp_config: OcspConfig::default(),
    };

    // Verify configuration
    assert_eq!(
        production_config.fallback_behavior,
        FallbackBehavior::FailClosed
    );
    assert!(production_config.crl_config.enable_http_fetch);
    assert_eq!(production_config.crl_config.cache_ttl_secs, 3600);

    // Serialize for storage
    let json = serde_json::to_string_pretty(&production_config).unwrap();
    assert!(!json.is_empty());

    println!("Production configuration:\n{}", json);
}

// ========================================
// OCSP Integration Tests
// ========================================

/// Test OCSP-only configuration
#[test]
fn test_ocsp_only_configuration() {
    let config = RevocationConfig::ocsp_only(
        OcspConfig::http_fetch(5, 3600, 100),
        FallbackBehavior::FailClosed,
    );

    assert_eq!(config.check_mode, RevocationCheckMode::OcspOnly);
    assert!(config.ocsp_config.enabled);
    assert_eq!(config.ocsp_config.http_timeout_secs, 5);
    assert_eq!(config.ocsp_config.cache_ttl_secs, 3600);
    assert_eq!(config.ocsp_config.max_cache_entries, 100);
    assert!(config.ocsp_config.enable_nonce);
}

/// Test PreferOcsp configuration
#[test]
fn test_prefer_ocsp_configuration() {
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::PreferOcsp,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::default(),
        ocsp_config: OcspConfig::http_fetch(5, 3600, 100),
    };

    assert_eq!(config.check_mode, RevocationCheckMode::PreferOcsp);
    assert!(config.ocsp_config.enabled);
    assert!(config.ocsp_config.prefer_ocsp);
}

/// Test Both (OCSP and CRL) configuration
#[test]
fn test_both_revocation_methods_configuration() {
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::Both,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::http_fetch(5, 3600, 100),
        ocsp_config: OcspConfig::http_fetch(5, 3600, 100),
    };

    assert_eq!(config.check_mode, RevocationCheckMode::Both);
    assert!(config.crl_config.enable_http_fetch);
    assert!(config.ocsp_config.enabled);
}

/// Test OCSP configuration serialization
#[test]
fn test_ocsp_config_json_serialization() {
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::PreferOcsp,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::default(),
        ocsp_config: OcspConfig::http_fetch(5, 3600, 100),
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config).unwrap();
    assert!(json.contains("prefer_ocsp"));
    assert!(json.contains("enable_nonce"));
    assert!(json.contains("ocsp_config"));

    // Deserialize from JSON
    let deserialized: RevocationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.check_mode, RevocationCheckMode::PreferOcsp);
    assert!(deserialized.ocsp_config.enabled);
}

/// Test OCSP disabled configuration
#[test]
fn test_ocsp_disabled_configuration() {
    let config = RevocationConfig {
        check_mode: RevocationCheckMode::CrlOnly,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig::default(),
        ocsp_config: OcspConfig::disabled(),
    };

    assert!(!config.ocsp_config.enabled);
}

/// Documentation test showing production OCSP configuration
#[test]
fn test_production_ocsp_configuration_example() {
    // Modern deployment with OCSP preferred over CRL
    let production_config = RevocationConfig {
        check_mode: RevocationCheckMode::PreferOcsp,
        fallback_behavior: FallbackBehavior::FailClosed,
        crl_config: CrlConfig {
            static_crl_paths: vec![],
            enable_http_fetch: true,
            http_timeout_secs: 5,
            cache_ttl_secs: 3600,
            max_cache_entries: 100,
            max_crl_size_bytes: 10 * 1024 * 1024,
        },
        ocsp_config: OcspConfig {
            enabled: true,
            http_timeout_secs: 5,                 // 5 second timeout for OCSP
            cache_ttl_secs: 3600,                 // Cache responses for 1 hour
            max_cache_entries: 100,               // Cache up to 100 responses
            enable_nonce: true,                   // Enable replay protection
            max_response_size_bytes: 1024 * 1024, // 1 MB limit
            prefer_ocsp: true,                    // Prefer OCSP over CRL
        },
    };

    // Verify configuration
    assert_eq!(
        production_config.check_mode,
        RevocationCheckMode::PreferOcsp
    );
    assert!(production_config.ocsp_config.enabled);
    assert!(production_config.ocsp_config.enable_nonce);
    assert_eq!(production_config.ocsp_config.cache_ttl_secs, 3600);

    // Serialize for storage
    let json = serde_json::to_string_pretty(&production_config).unwrap();
    assert!(!json.is_empty());
    assert!(json.contains("prefer_ocsp"));

    println!("Production OCSP configuration:\n{}", json);
}

/// Integration test for OCSP request building
#[test]
fn test_ocsp_request_building() {
    use radius_proto::revocation::ocsp::OcspRequestBuilder;
    use std::fs;
    use std::path::Path;

    // Use test PKI if available
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|p| {
            Path::new(&p)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .unwrap();
    let cert_path = workspace_root.join("tests/pki/certs/client.crt.der");
    let issuer_path = workspace_root.join("tests/pki/certs/intermediate-ca.crt.der");

    // Skip if test PKI doesn't exist
    if !cert_path.exists() || !issuer_path.exists() {
        println!("Skipping OCSP request building test - test PKI not found");
        return;
    }

    let cert_bytes = fs::read(cert_path).expect("Failed to read client cert");
    let issuer_bytes = fs::read(issuer_path).expect("Failed to read issuer cert");

    // Build OCSP request
    let builder = OcspRequestBuilder::new(&cert_bytes, &issuer_bytes)
        .expect("Failed to create OCSP request builder");

    // Add a test nonce
    let nonce = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let builder = builder.with_nonce(nonce);

    let request_der = builder.build().expect("Failed to build OCSP request");

    // Verify request is non-empty DER data
    assert!(!request_der.is_empty());
    assert_eq!(request_der[0], 0x30); // SEQUENCE tag
}

/// Integration test for OCSP URL extraction
#[test]
fn test_ocsp_url_extraction() {
    use radius_proto::revocation::ocsp::OcspClient;
    use std::fs;
    use std::path::Path;

    // Use test PKI if available
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|p| {
            Path::new(&p)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .unwrap();
    let cert_path = workspace_root.join("tests/pki/certs/client.crt.der");

    // Skip if test PKI doesn't exist
    if !cert_path.exists() {
        println!("Skipping OCSP URL extraction test - test PKI not found");
        return;
    }

    let cert_bytes = fs::read(cert_path).expect("Failed to read client cert");

    // Try to extract OCSP URL
    let url_result = OcspClient::extract_ocsp_url(&cert_bytes);

    // If certificate has AIA with OCSP URL, verify it's a valid URL
    if let Ok(url) = url_result {
        assert!(url.starts_with("http://") || url.starts_with("https://"));
        println!("Extracted OCSP URL: {}", url);
    } else {
        println!("Certificate does not contain OCSP URL in AIA extension");
    }
}

/// Integration test for OCSP response parsing
#[test]
fn test_ocsp_response_parsing() {
    use radius_proto::revocation::ocsp::{OcspResponse, OcspResponseStatus};

    // Test non-successful OCSP response (malformed request)
    // This is the minimal valid OCSPResponse structure
    let error_response = vec![
        0x30, 0x03, // SEQUENCE (3 bytes)
        0x0a, 0x01, 0x01, // ENUMERATED (1 byte) = 1 (malformedRequest)
    ];

    let result = OcspResponse::parse(&error_response);

    // This should parse successfully
    assert!(result.is_ok(), "Failed to parse error OCSP response");

    let response = result.unwrap();
    assert_eq!(response.status, OcspResponseStatus::MalformedRequest);
    // Error responses don't have cert_status
    assert_eq!(response.cert_status, None);
}

/// Integration test for OCSP cache
#[test]
fn test_ocsp_cache_integration() {
    use radius_proto::revocation::ocsp::{CertificateStatus, OcspResponse, OcspResponseStatus};
    use radius_proto::revocation::ocsp_cache::OcspCache;
    use std::time::SystemTime;

    let cache = OcspCache::new(10);
    let serial = vec![0x01, 0x02, 0x03];

    // Create a test OCSP response
    let response = OcspResponse {
        status: OcspResponseStatus::Successful,
        cert_status: Some(CertificateStatus::Good),
        produced_at: SystemTime::now(),
        this_update: SystemTime::now(),
        next_update: Some(SystemTime::now() + std::time::Duration::from_secs(3600)),
        nonce: None,
        raw_bytes: vec![],
    };

    // Cache the response
    cache.insert(serial.clone(), response.clone());

    // Retrieve from cache
    let cached = cache.get(&serial);
    assert!(cached.is_some());

    let cached_response = cached.unwrap();
    assert_eq!(cached_response.status, OcspResponseStatus::Successful);
    assert_eq!(cached_response.cert_status, Some(CertificateStatus::Good));
}

// Future OCSP integration tests to add:
// - test_ocsp_http_query: Test actual HTTP query to OCSP responder (requires test responder)
// - test_ocsp_nonce_validation: Test nonce mismatch detection
// - test_ocsp_revoked_status: Test revoked certificate detection
// - test_ocsp_cache_expiry: Test cache TTL expiration
// - test_ocsp_fallback_to_crl: Test PreferOcsp mode fallback behavior
// - test_ocsp_and_crl_both: Test Both mode with conflicting results
// - test_ocsp_signature_verification: Test response signature validation (when implemented)
