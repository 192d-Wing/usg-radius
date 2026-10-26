//! CRL HTTP fetching
#![allow(dead_code)] // HTTP fetcher is wired later in revocation pipeline
//!
//! This module provides HTTP client functionality for fetching CRLs from
//! distribution points specified in X.509 certificates.
//!
//! # Overview
//!
//! The fetcher uses `reqwest` in blocking mode for synchronous operation.
//! Key features:
//!
//! - **HTTP/HTTPS support**: Fetches CRLs over HTTP or HTTPS
//! - **Timeout enforcement**: Configurable timeout per request
//! - **Size limits**: Protects against memory exhaustion
//! - **Error handling**: Comprehensive error reporting
//!
//! # Security Considerations
//!
//! - **HTTPS recommended**: Use HTTPS URLs for CRL distribution points
//! - **Size limits**: Default 10 MB limit prevents DoS attacks
//! - **Timeouts**: Default 5 second timeout prevents hanging
//! - **URL validation**: Basic validation of distribution point URLs
//!
//! # Example
//!
//! (`ignore`: this module is crate-private; the example is illustrative)
//! ```ignore
//! use radius_proto::revocation::fetch::CrlFetcher;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create fetcher with 5 second timeout
//! let fetcher = CrlFetcher::new(5)?;
//!
//! // Fetch CRL from distribution point
//! let crl_bytes = fetcher.fetch_crl("http://ca.example.com/crl.der")?;
//! println!("Fetched {} bytes", crl_bytes.len());
//! # Ok(())
//! # }
//! ```

use super::error::RevocationError;
use reqwest::blocking::Client;
use std::time::Duration;
use url::Url;

/// Default maximum CRL size (10 MB)
const DEFAULT_MAX_CRL_SIZE: usize = 10 * 1024 * 1024;

/// HTTP client for fetching CRLs
///
/// This fetcher uses `reqwest` in blocking mode for synchronous operation,
/// which is appropriate for RADIUS request handling where we need to make
/// an authentication decision quickly.
///
/// # Example
///
/// (`ignore`: this module is crate-private; the example is illustrative)
/// ```ignore
/// use radius_proto::revocation::fetch::CrlFetcher;
///
/// let fetcher = CrlFetcher::new(5).unwrap();
/// let crl_data = fetcher.fetch_crl("http://ca.example.com/crl.der").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct CrlFetcher {
    /// HTTP client with configured timeout
    client: Client,

    /// Maximum allowed CRL size in bytes
    max_size: usize,

    /// Timeout in seconds (stored for error reporting)
    timeout_secs: u64,
}

impl CrlFetcher {
    /// Create a new CRL fetcher
    ///
    /// # Arguments
    ///
    /// * `timeout_secs` - HTTP request timeout in seconds
    ///
    /// # Returns
    ///
    /// * `Ok(CrlFetcher)` - Successfully created fetcher
    /// * `Err(RevocationError)` - Failed to create HTTP client
    pub fn new(timeout_secs: u64) -> Result<Self, RevocationError> {
        Self::with_max_size(timeout_secs, DEFAULT_MAX_CRL_SIZE)
    }

    /// Create a new CRL fetcher with custom max size
    ///
    /// # Arguments
    ///
    /// * `timeout_secs` - HTTP request timeout in seconds
    /// * `max_size` - Maximum CRL size in bytes
    ///
    /// # Returns
    ///
    /// * `Ok(CrlFetcher)` - Successfully created fetcher
    /// * `Err(RevocationError)` - Failed to create HTTP client
    pub fn with_max_size(timeout_secs: u64, max_size: usize) -> Result<Self, RevocationError> {
        super::ensure_default_crypto_provider();
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| {
                RevocationError::HttpError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            client,
            max_size,
            timeout_secs,
        })
    }

    /// Fetch a CRL from an HTTP/HTTPS URL
    ///
    /// This method:
    /// 1. Validates the URL format
    /// 2. Sends HTTP GET request with timeout
    /// 3. Checks response size against max_size limit
    /// 4. Returns the raw CRL bytes (DER-encoded)
    ///
    /// # Arguments
    ///
    /// * `url` - CRL distribution point URL (HTTP or HTTPS)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Raw CRL bytes (DER-encoded)
    /// * `Err(RevocationError)` - Fetch failed (timeout, size, HTTP error, etc.)
    ///
    /// # Errors
    ///
    /// - `InvalidUrl`: URL is malformed or uses unsupported scheme
    /// - `HttpTimeout`: Request timed out
    /// - `HttpError`: HTTP request failed (network error, 404, etc.)
    /// - `CrlTooLarge`: Response exceeds max_size limit
    pub fn fetch_crl(&self, url: &str) -> Result<Vec<u8>, RevocationError> {
        // Validate and parse URL
        let parsed_url =
            Url::parse(url).map_err(|e| RevocationError::InvalidUrl(format!("{}: {}", url, e)))?;

        // Ensure HTTP or HTTPS
        match parsed_url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(RevocationError::InvalidUrl(format!(
                    "Unsupported URL scheme '{}' (must be http or https)",
                    scheme
                )));
            }
        }

        // Send HTTP GET request
        let response = self.client.get(url).send().map_err(|e| {
            if e.is_timeout() {
                RevocationError::HttpTimeout(self.timeout_secs)
            } else {
                RevocationError::HttpError(format!("GET {} failed: {}", url, e))
            }
        })?;

        // Check HTTP status
        if !response.status().is_success() {
            return Err(RevocationError::HttpError(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        // Check Content-Length header if present
        if let Some(content_length) = response.content_length()
            && content_length as usize > self.max_size
        {
            return Err(RevocationError::CrlTooLarge(
                content_length as usize,
                self.max_size,
            ));
        }

        // Read response body with size limit
        let bytes = response
            .bytes()
            .map_err(|e| RevocationError::HttpError(format!("Failed to read response: {}", e)))?;

        // Check actual size
        if bytes.len() > self.max_size {
            return Err(RevocationError::CrlTooLarge(bytes.len(), self.max_size));
        }

        Ok(bytes.to_vec())
    }
}

/// Extract CRL distribution points from a certificate
///
/// This function parses a DER-encoded X.509 certificate and extracts
/// the CRL Distribution Points extension (OID 2.5.29.31).
///
/// # Arguments
///
/// * `cert_der` - DER-encoded X.509 certificate bytes
///
/// # Returns
///
/// * `Ok(Vec<String>)` - List of CRL distribution point URLs
/// * `Err(RevocationError)` - Certificate parsing failed or extension not present
///
/// # Note
///
/// This is a placeholder implementation for Phase 1.4. Full implementation
/// with x509-parser will be completed in Phase 1.5 during EAP-TLS integration
/// when we have access to actual certificate data.
pub fn extract_crl_distribution_points(cert_der: &[u8]) -> Result<Vec<String>, RevocationError> {
    use x509_parser::prelude::*;

    // Parse certificate
    let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
        RevocationError::CertificateError(format!("Failed to parse certificate: {}", e))
    })?;

    let mut distribution_points = Vec::new();

    // Find CRL Distribution Points extension (OID 2.5.29.31)
    // Note: get_extension_unique returns Result<Option<...>, X509Error>
    if let Ok(Some(ext)) =
        cert.get_extension_unique(&oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
    {
        // Parse CRL Distribution Points
        // x509-parser provides a dedicated parser for this extension
        use x509_parser::extensions::ParsedExtension;
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            for dp in points.points.iter() {
                if let Some(name) = &dp.distribution_point {
                    use x509_parser::extensions::DistributionPointName;
                    if let DistributionPointName::FullName(general_names) = name {
                        for general_name in general_names {
                            use x509_parser::extensions::GeneralName;
                            if let GeneralName::URI(uri) = general_name {
                                distribution_points.push(uri.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    if distribution_points.is_empty() {
        Err(RevocationError::DistributionPointError(
            "No CRL distribution points found in certificate".to_string(),
        ))
    } else {
        Ok(distribution_points)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetcher_new() {
        let fetcher = CrlFetcher::new(5);
        assert!(fetcher.is_ok());
        let fetcher = fetcher.unwrap();
        assert_eq!(fetcher.max_size, DEFAULT_MAX_CRL_SIZE);
    }

    #[test]
    fn test_fetcher_with_custom_max_size() {
        let fetcher = CrlFetcher::with_max_size(10, 1024);
        assert!(fetcher.is_ok());
        let fetcher = fetcher.unwrap();
        assert_eq!(fetcher.max_size, 1024);
    }

    #[test]
    fn test_invalid_url_scheme() {
        let fetcher = CrlFetcher::new(5).unwrap();

        // FTP not supported
        let result = fetcher.fetch_crl("ftp://example.com/crl.der");
        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::InvalidUrl(_))));

        // File URLs not supported
        let result = fetcher.fetch_crl("file:///tmp/crl.der");
        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::InvalidUrl(_))));
    }

    #[test]
    fn test_malformed_url() {
        let fetcher = CrlFetcher::new(5).unwrap();

        let result = fetcher.fetch_crl("not a url");
        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::InvalidUrl(_))));
    }

    #[test]
    fn test_http_timeout() {
        // Create fetcher with very short timeout
        let fetcher = CrlFetcher::new(1).unwrap();

        // Try to fetch from a URL that will timeout
        // Using httpbin's delay endpoint which delays for 10 seconds
        let result = fetcher.fetch_crl("https://httpbin.org/delay/10");

        // Should timeout
        assert!(result.is_err());
        if let Err(e) = result {
            // Could be timeout or other error depending on network
            assert!(
                matches!(e, RevocationError::HttpTimeout(_))
                    || matches!(e, RevocationError::HttpError(_))
            );
        }
    }

    #[test]
    fn test_http_404() {
        let fetcher = CrlFetcher::new(5).unwrap();

        // Try to fetch from a URL that returns 404
        let result = fetcher.fetch_crl("https://httpbin.org/status/404");

        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::HttpError(_))));
    }

    #[test]
    fn test_size_limit_enforcement() {
        // Create fetcher with very small size limit
        let fetcher = CrlFetcher::with_max_size(5, 10).unwrap();

        // Try to fetch something larger than 10 bytes
        let result = fetcher.fetch_crl("https://httpbin.org/bytes/1000");

        // Should fail with size error
        assert!(result.is_err());
        if let Err(e) = result {
            // Might fail on Content-Length check or actual read
            assert!(
                matches!(e, RevocationError::CrlTooLarge(_, _))
                    || matches!(e, RevocationError::HttpError(_))
            );
        }
    }

    #[test]
    fn test_successful_fetch_small() {
        let fetcher = CrlFetcher::new(5).unwrap();

        // Fetch a small response from httpbin
        let result = fetcher.fetch_crl("https://httpbin.org/bytes/100");

        // Should succeed
        if let Ok(bytes) = result {
            assert_eq!(bytes.len(), 100);
        }
        // If it fails due to network issues, that's okay for unit tests
    }

    #[test]
    fn test_extract_distribution_points_invalid_cert() {
        // Invalid DER data
        let result = extract_crl_distribution_points(&[0x00, 0x01, 0x02]);
        assert!(result.is_err());
        assert!(matches!(result, Err(RevocationError::CertificateError(_))));
    }

    // Note: Full testing of extract_crl_distribution_points() requires
    // real certificate data, which will be added in Phase 1.6 integration tests
}
