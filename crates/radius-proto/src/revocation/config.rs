//! Configuration types for certificate revocation checking
//!
//! This module defines configuration structures for CRL and OCSP checking.

use serde::{Deserialize, Serialize};

/// Certificate revocation checking configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationConfig {
    /// Revocation check mode (CRL only, OCSP only, both, etc.)
    pub check_mode: RevocationCheckMode,

    /// Behavior when revocation check fails (network error, timeout, etc.)
    pub fallback_behavior: FallbackBehavior,

    /// CRL-specific configuration
    pub crl_config: CrlConfig,

    /// OCSP-specific configuration
    #[serde(default)]
    pub ocsp_config: OcspConfig,
}

impl RevocationConfig {
    /// Create a new revocation configuration with CRL checking only
    pub fn crl_only(crl_config: CrlConfig, fallback_behavior: FallbackBehavior) -> Self {
        Self {
            check_mode: RevocationCheckMode::CrlOnly,
            fallback_behavior,
            crl_config,
            ocsp_config: OcspConfig::default(),
        }
    }

    /// Create a new revocation configuration with OCSP checking only
    pub fn ocsp_only(ocsp_config: OcspConfig, fallback_behavior: FallbackBehavior) -> Self {
        Self {
            check_mode: RevocationCheckMode::OcspOnly,
            fallback_behavior,
            crl_config: CrlConfig::default(),
            ocsp_config,
        }
    }

    /// Create configuration for static CRL files (no HTTP fetching)
    pub fn static_files(crl_paths: Vec<String>, fallback_behavior: FallbackBehavior) -> Self {
        Self {
            check_mode: RevocationCheckMode::CrlOnly,
            fallback_behavior,
            crl_config: CrlConfig {
                static_crl_paths: crl_paths,
                enable_http_fetch: false,
                ..CrlConfig::default()
            },
            ocsp_config: OcspConfig::default(),
        }
    }

    /// Create a disabled revocation configuration
    pub fn disabled() -> Self {
        Self {
            check_mode: RevocationCheckMode::Disabled,
            fallback_behavior: FallbackBehavior::FailOpen,
            crl_config: CrlConfig::default(),
            ocsp_config: OcspConfig::default(),
        }
    }
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Revocation check mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RevocationCheckMode {
    /// CRL checking only
    CrlOnly,

    /// OCSP checking only (not yet implemented)
    #[allow(dead_code)]
    OcspOnly,

    /// Check both CRL and OCSP (not yet implemented)
    #[allow(dead_code)]
    Both,

    /// Prefer OCSP, fallback to CRL (not yet implemented)
    #[allow(dead_code)]
    PreferOcsp,

    /// Disabled - no revocation checking
    Disabled,
}

/// Fallback behavior when revocation check fails
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FallbackBehavior {
    /// Allow authentication on revocation check failure
    /// (e.g., network timeout, CRL unavailable)
    ///
    /// **Security Note**: This reduces security but improves availability.
    /// Recommended for development/testing only.
    FailOpen,

    /// Reject authentication on revocation check failure
    ///
    /// **Security Note**: This maximizes security but may impact availability
    /// if CRL distribution points are unreachable.
    /// Recommended for production high-security environments.
    FailClosed,
}

/// CRL-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrlConfig {
    /// Static CRL file paths to preload (PEM or DER format)
    ///
    /// These CRLs are loaded at startup and cached.
    /// Useful for air-gapped environments or guaranteed availability.
    #[serde(default)]
    pub static_crl_paths: Vec<String>,

    /// Enable HTTP fetching of CRLs from distribution points
    ///
    /// When enabled, CRLs will be fetched from URLs in the certificate's
    /// CRL Distribution Points extension.
    #[serde(default = "default_true")]
    pub enable_http_fetch: bool,

    /// HTTP request timeout in seconds
    #[serde(default = "default_http_timeout")]
    pub http_timeout_secs: u64,

    /// CRL cache TTL (time-to-live) in seconds
    ///
    /// Cached CRLs are reused until this TTL expires.
    /// Should be less than the typical CRL nextUpdate interval.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Maximum number of CRLs to cache
    ///
    /// Oldest entries are evicted when limit is reached.
    #[serde(default = "default_max_cache_entries")]
    pub max_cache_entries: usize,

    /// Maximum CRL size in bytes (default 10 MB)
    ///
    /// Protects against memory exhaustion from malicious/large CRLs.
    #[serde(default = "default_max_crl_size")]
    pub max_crl_size_bytes: usize,
}

impl CrlConfig {
    /// Create a new CRL configuration with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a CRL configuration with static file paths only (no HTTP)
    pub fn static_files(crl_paths: Vec<String>) -> Self {
        Self {
            static_crl_paths: crl_paths,
            enable_http_fetch: false,
            ..Default::default()
        }
    }

    /// Create a CRL configuration with HTTP fetching enabled
    pub fn http_fetch(
        http_timeout_secs: u64,
        cache_ttl_secs: u64,
        max_cache_entries: usize,
    ) -> Self {
        Self {
            static_crl_paths: vec![],
            enable_http_fetch: true,
            http_timeout_secs,
            cache_ttl_secs,
            max_cache_entries,
            max_crl_size_bytes: default_max_crl_size(),
        }
    }
}

impl Default for CrlConfig {
    fn default() -> Self {
        Self {
            static_crl_paths: vec![],
            enable_http_fetch: true,
            http_timeout_secs: default_http_timeout(),
            cache_ttl_secs: default_cache_ttl(),
            max_cache_entries: default_max_cache_entries(),
            max_crl_size_bytes: default_max_crl_size(),
        }
    }
}

// Default value functions for serde

fn default_true() -> bool {
    true
}

fn default_http_timeout() -> u64 {
    5 // 5 seconds
}

fn default_cache_ttl() -> u64 {
    3600 // 1 hour
}

fn default_max_cache_entries() -> usize {
    100
}

fn default_max_crl_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}

/// OCSP-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OcspConfig {
    /// Enable OCSP checking
    #[serde(default)]
    pub enabled: bool,

    /// HTTP request timeout in seconds
    #[serde(default = "default_http_timeout")]
    pub http_timeout_secs: u64,

    /// OCSP response cache TTL (time-to-live) in seconds
    ///
    /// Cached responses are reused until this TTL expires or nextUpdate is reached.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Maximum number of OCSP responses to cache
    #[serde(default = "default_max_cache_entries")]
    pub max_cache_entries: usize,

    /// Enable nonce extension for replay protection (RFC 8954)
    ///
    /// Recommended for production use.
    #[serde(default = "default_true")]
    pub enable_nonce: bool,

    /// Maximum OCSP response size in bytes (default 1 MB)
    ///
    /// Protects against memory exhaustion from malicious/large responses.
    #[serde(default = "default_max_ocsp_response_size")]
    pub max_response_size_bytes: usize,

    /// Prefer OCSP over CRL when both are available
    ///
    /// Only relevant when check_mode is Both or PreferOcsp.
    #[serde(default = "default_true")]
    pub prefer_ocsp: bool,
}

impl OcspConfig {
    /// Create a new OCSP configuration with HTTP fetching enabled
    pub fn http_fetch(
        http_timeout_secs: u64,
        cache_ttl_secs: u64,
        max_cache_entries: usize,
    ) -> Self {
        Self {
            enabled: true,
            http_timeout_secs,
            cache_ttl_secs,
            max_cache_entries,
            enable_nonce: true,
            max_response_size_bytes: default_max_ocsp_response_size(),
            prefer_ocsp: true,
        }
    }

    /// Create a disabled OCSP configuration
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            http_timeout_secs: default_http_timeout(),
            cache_ttl_secs: default_cache_ttl(),
            max_cache_entries: default_max_cache_entries(),
            enable_nonce: true,
            max_response_size_bytes: default_max_ocsp_response_size(),
            prefer_ocsp: true,
        }
    }
}

fn default_max_ocsp_response_size() -> usize {
    1024 * 1024 // 1 MB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_config_default() {
        let config = RevocationConfig::default();
        assert_eq!(config.check_mode, RevocationCheckMode::Disabled);
        assert_eq!(config.fallback_behavior, FallbackBehavior::FailOpen);
    }

    #[test]
    fn test_revocation_config_crl_only() {
        let crl_config = CrlConfig::default();
        let config = RevocationConfig::crl_only(crl_config, FallbackBehavior::FailClosed);

        assert_eq!(config.check_mode, RevocationCheckMode::CrlOnly);
        assert_eq!(config.fallback_behavior, FallbackBehavior::FailClosed);
    }

    #[test]
    fn test_crl_config_default() {
        let config = CrlConfig::default();
        assert_eq!(config.static_crl_paths.len(), 0);
        assert!(config.enable_http_fetch);
        assert_eq!(config.http_timeout_secs, 5);
        assert_eq!(config.cache_ttl_secs, 3600);
        assert_eq!(config.max_cache_entries, 100);
        assert_eq!(config.max_crl_size_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn test_crl_config_static_files() {
        let paths = vec![
            "/path/to/crl1.pem".to_string(),
            "/path/to/crl2.pem".to_string(),
        ];
        let config = CrlConfig::static_files(paths.clone());

        assert_eq!(config.static_crl_paths, paths);
        assert!(!config.enable_http_fetch);
    }

    #[test]
    fn test_crl_config_http_fetch() {
        let config = CrlConfig::http_fetch(10, 7200, 200);

        assert!(config.enable_http_fetch);
        assert_eq!(config.http_timeout_secs, 10);
        assert_eq!(config.cache_ttl_secs, 7200);
        assert_eq!(config.max_cache_entries, 200);
    }

    #[test]
    fn test_fallback_behavior_serialization() {
        let fail_open = FallbackBehavior::FailOpen;
        let json = serde_json::to_string(&fail_open).unwrap();
        assert_eq!(json, "\"fail_open\"");

        let fail_closed = FallbackBehavior::FailClosed;
        let json = serde_json::to_string(&fail_closed).unwrap();
        assert_eq!(json, "\"fail_closed\"");
    }

    #[test]
    fn test_check_mode_serialization() {
        let mode = RevocationCheckMode::CrlOnly;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"crl_only\"");

        let mode = RevocationCheckMode::Disabled;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"disabled\"");
    }

    #[test]
    fn test_revocation_config_serialization() {
        let config = RevocationConfig::crl_only(CrlConfig::default(), FallbackBehavior::FailClosed);

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RevocationConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }
}
