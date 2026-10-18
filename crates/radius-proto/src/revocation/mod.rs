//! Certificate Revocation Checking (CRL/OCSP)
//!
//! This module provides production-grade certificate revocation checking for EAP-TLS
//! mutual authentication. It supports:
//!
//! - **CRL (Certificate Revocation Lists)**: RFC 5280
//! - **OCSP (Online Certificate Status Protocol)**: RFC 6960 (planned for v0.7.0)
//!
//! # Features
//!
//! - **CRL Parsing & Validation**: Full DER/PEM parsing with `thisUpdate`/`nextUpdate` validation
//! - **HTTP Fetching**: Automatic CRL download from certificate distribution points
//! - **Thread-Safe Caching**: TTL-based caching with LRU eviction using DashMap
//! - **Fail-Open/Fail-Closed**: Configurable error handling policy
//! - **Static CRL Files**: Support for pre-loaded CRL files (air-gapped environments)
//! - **rustls Integration**: Custom `ClientCertVerifier` for seamless TLS integration
//! - **O(1) Revocation Lookup**: HashSet-based serial number checking
//!
//! # Quick Start
//!
//! ## Basic Usage (HTTP CRL Fetching)
//!
//! ```no_run
//! use radius_proto::revocation::{RevocationConfig, CrlConfig, FallbackBehavior};
//! use radius_proto::revocation::RevocationCheckingVerifier;
//! use rustls::ServerConfig;
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create revocation configuration
//! let crl_config = CrlConfig::http_fetch(
//!     5,      // 5 second HTTP timeout
//!     3600,   // 1 hour cache TTL
//!     100,    // Max 100 cached CRLs
//! );
//!
//! let config = RevocationConfig::crl_only(
//!     crl_config,
//!     FallbackBehavior::FailClosed,  // Reject on CRL fetch failure (secure default)
//! );
//!
//! // 2. Create verifier with revocation checking
//! let verifier = RevocationCheckingVerifier::new(config)?;
//!
//! // 3. Build rustls ServerConfig with custom verifier
//! // (ServerConfig setup omitted for brevity - see examples/eap_tls_server.rs)
//! # Ok(())
//! # }
//! ```
//!
//! ## Static CRL Files (Air-Gapped Environments)
//!
//! ```no_run
//! use radius_proto::revocation::{RevocationConfig, FallbackBehavior};
//!
//! let config = RevocationConfig::static_files(
//!     vec![
//!         "/etc/radius/crls/root-ca.crl".to_string(),
//!         "/etc/radius/crls/intermediate-ca.crl".to_string(),
//!     ],
//!     FallbackBehavior::FailClosed,
//! );
//! ```
//!
//! ## Disabled Mode (Development/Testing)
//!
//! ```
//! use radius_proto::revocation::RevocationConfig;
//!
//! let config = RevocationConfig::disabled();
//! ```
//!
//! # Configuration Guide
//!
//! ## Fail-Open vs Fail-Closed
//!
//! Choose the error handling policy based on your security requirements:
//!
//! | Mode | Behavior | Use Case | Security Impact |
//! |------|----------|----------|-----------------|
//! | **Fail-Closed** | Reject auth on CRL fetch failure | Production high-security | ✅ Maximum security, may impact availability |
//! | **Fail-Open** | Allow auth on CRL fetch failure | Development, low-security | ⚠️ Reduced security, maximum availability |
//!
//! **Recommendation**: Use `FailClosed` for production unless you have specific availability requirements.
//!
//! ```no_run
//! use radius_proto::revocation::{RevocationConfig, CrlConfig, FallbackBehavior};
//!
//! // Production: Fail-Closed (reject on errors)
//! let production = RevocationConfig::crl_only(
//!     CrlConfig::default(),
//!     FallbackBehavior::FailClosed,
//! );
//!
//! // Development: Fail-Open (allow on errors)
//! let development = RevocationConfig::crl_only(
//!     CrlConfig::default(),
//!     FallbackBehavior::FailOpen,
//! );
//! ```
//!
//! ## Cache TTL Tuning
//!
//! Choose cache TTL based on your CRL update frequency:
//!
//! - **Short TTL (300-900s)**: For CAs that update CRLs frequently
//! - **Medium TTL (3600s)**: Default, suitable for most deployments
//! - **Long TTL (7200-86400s)**: For stable environments with infrequent CRL updates
//!
//! **Note**: TTL should be **less than** the CRL's `nextUpdate` interval to avoid using stale CRLs.
//!
//! ```no_run
//! use radius_proto::revocation::CrlConfig;
//!
//! // High-frequency CRL updates (every 15 minutes)
//! let config = CrlConfig::http_fetch(
//!     5,    // 5 second timeout
//!     600,  // 10 minute cache TTL (less than 15 min update interval)
//!     100,
//! );
//! ```
//!
//! ## HTTP Timeout Settings
//!
//! Choose timeout based on network conditions and RADIUS request latency requirements:
//!
//! - **Short timeout (1-3s)**: Low-latency networks, strict RADIUS timeout requirements
//! - **Medium timeout (5s)**: Default, suitable for most deployments
//! - **Long timeout (10s)**: Slow networks, unreliable CRL distribution points
//!
//! **RADIUS Consideration**: EAP-TLS authentication must complete within the RADIUS request timeout
//! (typically 30-60 seconds). Factor in multiple round-trips for TLS handshake + CRL fetching.
//!
//! # Security Best Practices
//!
//! ## 1. Use HTTPS for CRL Distribution Points
//!
//! **Always** use HTTPS URLs in certificate CRL Distribution Points extensions:
//!
//! ```text
//! ✅ GOOD: https://ca.example.com/crl.der
//! ❌ BAD:  http://ca.example.com/crl.der  (vulnerable to MITM)
//! ```
//!
//! HTTP CRLs are vulnerable to man-in-the-middle attacks where an attacker could
//! serve a modified CRL to avoid revocation detection.
//!
//! ## 2. Enforce CRL Freshness
//!
//! The implementation automatically validates:
//! - `thisUpdate <= current_time` (CRL is active)
//! - `nextUpdate >= current_time` (CRL has not expired)
//!
//! Expired CRLs are rejected in Fail-Closed mode.
//!
//! ## 3. Set Appropriate Size Limits
//!
//! Protect against memory exhaustion attacks:
//!
//! ```no_run
//! use radius_proto::revocation::CrlConfig;
//!
//! let config = CrlConfig {
//!     max_crl_size_bytes: 10 * 1024 * 1024,  // 10 MB default
//!     ..CrlConfig::default()
//! };
//! ```
//!
//! Typical CRL sizes:
//! - Small CA: 10-100 KB
//! - Medium CA: 100 KB - 1 MB
//! - Large CA: 1-10 MB
//! - Very Large CA: 10+ MB (may require custom limit)
//!
//! ## 4. Monitor CRL Cache Hit Rate
//!
//! In production, monitor cache performance to tune TTL:
//!
//! ```no_run
//! # use radius_proto::revocation::RevocationCheckingVerifier;
//! # fn example(verifier: &RevocationCheckingVerifier) {
//! // Cache statistics (future API - not yet implemented)
//! // let (total, expired) = verifier.cache_stats();
//! // println!("Cache: {} entries, {} expired", total, expired);
//! # }
//! ```
//!
//! ## 5. Regular CRL Updates for Static Files
//!
//! If using static CRL files, ensure automated updates:
//!
//! ```bash
//! # Example cron job (daily at 2 AM)
//! 0 2 * * * curl -o /etc/radius/crls/ca.crl https://ca.example.com/ca.crl
//! ```
//!
//! # Performance Characteristics
//!
//! - **CRL Parsing**: O(n) where n = number of revoked certificates
//! - **Serial Lookup**: O(1) using HashSet
//! - **Cache Lookup**: O(1) using DashMap
//! - **Cache Eviction**: O(k) where k = cache size (only when cache is full)
//! - **HTTP Fetch**: Depends on network latency + CRL size
//!
//! ## Memory Usage
//!
//! - **Per CRL**: ~(revoked_count * 32 bytes) + metadata (~200 bytes)
//! - **Cache**: max_cache_entries * avg_crl_size
//! - **Example**: 100 cached CRLs with 1000 revocations each ≈ 3-5 MB
//!
//! ## Latency Impact
//!
//! | Scenario | Latency |
//! |----------|---------|
//! | Cache hit | < 1 ms |
//! | Cache miss (HTTP fetch) | network_latency + parse_time (5-50 ms typical) |
//! | First connection | TLS handshake + CRL fetch (~100-500 ms) |
//! | Subsequent connections | TLS handshake + cache hit (~50-100 ms) |
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   EAP-TLS TLS Handshake                      │
//! │                    (rustls ServerConfig)                     │
//! └──────────────────────┬───────────────────────────────────────┘
//!                        │
//!                        ▼
//! ┌──────────────────────────────────────────────────────────────┐
//! │           RevocationCheckingVerifier                         │
//! │   (implements rustls::ClientCertVerifier)                    │
//! ├──────────────────────────────────────────────────────────────┤
//! │  1. WebPkiClientVerifier (standard TLS validation)           │
//! │  2. Extract CRL distribution points from cert                │
//! │  3. Check cache for CRL                                      │
//! │  4. If miss: HTTP fetch → parse → validate → cache           │
//! │  5. Check if cert serial is in revoked set                   │
//! │  6. Apply fail-open/fail-closed policy on errors             │
//! └──────────────────────────────────────────────────────────────┘
//!         │                    │                    │
//!         ▼                    ▼                    ▼
//! ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
//! │  CrlCache   │    │  CrlFetcher  │    │    CrlInfo      │
//! │  (DashMap)  │    │  (reqwest)   │    │  (x509-parser)  │
//! └─────────────┘    └──────────────┘    └─────────────────┘
//! ```
//!
//! # Error Handling
//!
//! The module defines comprehensive error types in [`RevocationError`]:
//!
//! - **`CertificateRevoked`**: Certificate is in CRL (auth rejected)
//! - **`FetchError`**: HTTP fetch failed (fail-open/closed applies)
//! - **`ParseError`**: CRL parsing failed (fail-open/closed applies)
//! - **`CrlExpired`**: CRL `nextUpdate` has passed (fail-open/closed applies)
//! - **`HttpTimeout`**: HTTP request timed out (fail-open/closed applies)
//! - **`CrlTooLarge`**: CRL exceeds size limit (fail-open/closed applies)
//!
//! # Phase 1: CRL Support (v0.6.0) ✅ Complete
//!
//! Current implementation focuses on CRL checking only. OCSP support will be
//! added in Phase 2 (v0.7.0).
//!
//! ## Implementation Status
//!
//! - ✅ Phase 1.1: Core types and configuration
//! - ✅ Phase 1.2: CRL parsing and validation
//! - ✅ Phase 1.3: CRL caching with TTL
//! - ✅ Phase 1.4: CRL HTTP fetching
//! - ✅ Phase 1.5: EAP-TLS integration (custom verifier)
//! - ✅ Phase 1.6: Integration tests
//! - ✅ Phase 1.7: Documentation
//!
//! ## Future Roadmap (Phase 2)
//!
//! - OCSP support (RFC 6960)
//! - OCSP stapling
//! - Hybrid CRL + OCSP modes
//! - Delta CRL support
//! - CRL signing chain validation

pub mod config;
pub mod error;

// CRL, caching, fetching, and verification modules
#[cfg(feature = "revocation")]
pub(crate) mod cache;
#[cfg(feature = "revocation")]
pub(crate) mod crl;
#[cfg(feature = "revocation")]
pub(crate) mod fetch;
#[cfg(feature = "revocation")]
pub mod ocsp;
#[cfg(feature = "revocation")]
pub mod ocsp_cache;
#[cfg(feature = "revocation")]
pub mod verifier;

// Re-export public types
pub use config::{CrlConfig, FallbackBehavior, OcspConfig, RevocationCheckMode, RevocationConfig};
pub use error::RevocationError;

#[cfg(feature = "revocation")]
pub use verifier::RevocationCheckingVerifier;

/// Module version for tracking implementation progress
pub const VERSION: &str = "0.6.0 (Phase 1: CRL Support Complete)";

/// Ensure a process-level rustls [`CryptoProvider`](rustls::crypto::CryptoProvider)
/// is installed before `reqwest` builds a TLS client.
///
/// `reqwest` is built with `rustls-tls-webpki-roots-no-provider`, so it uses
/// whatever default provider the process has and panics if there is none. The
/// EAP-TLS code installs `aws-lc-rs` implicitly through `ServerConfig::builder()`,
/// but the revocation fetchers may run before any TLS server config is built,
/// so install the same provider explicitly here. A concurrent install by another
/// thread is not an error.
pub(crate) fn ensure_default_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_config_creation() {
        let config = RevocationConfig::default();
        assert_eq!(config.check_mode, RevocationCheckMode::Disabled);
    }
}
