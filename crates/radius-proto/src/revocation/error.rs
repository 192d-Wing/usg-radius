//! Revocation-specific error types
//!
//! This module defines error types for certificate revocation checking (CRL/OCSP).

/// Errors that can occur during certificate revocation checking
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// Failed to fetch CRL from distribution point
    #[error("CRL fetch failed: {0}")]
    FetchError(String),

    /// Failed to parse CRL data
    #[error("CRL parse error: {0}")]
    ParseError(String),

    /// Certificate has been revoked
    #[error("Certificate revoked: serial={0}")]
    CertificateRevoked(String),

    /// A CRL, OCSP response or certificate signature did not verify, or was
    /// made by a key that is not authorized to make it (RFC 5280 §6.3.3,
    /// RFC 6960 §3.2)
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),

    /// Linking the peer's chain to the configured issuers exceeded the
    /// work budget (signature verifications, path extensions or paths); the
    /// peer controls the intermediates, so this rejects regardless of the
    /// fail policy
    #[error("certification path building budget exceeded: {0}")]
    PathBudgetExceeded(String),

    /// A CRL is older (lower crlNumber) than one already accepted for the
    /// same issuer (RFC 5280 §5.2.3)
    #[error("stale CRL: {0}")]
    StaleCrl(String),

    /// CRL has expired (nextUpdate < current time)
    #[error("CRL expired: nextUpdate={0}")]
    CrlExpired(String),

    /// CRL is not yet valid (thisUpdate > current time)
    #[error("CRL not yet valid: thisUpdate={0}")]
    CrlNotYetValid(String),

    /// HTTP request failed
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// HTTP timeout
    #[error("HTTP request timed out after {0}s")]
    HttpTimeout(u64),

    /// Invalid URL in CRL distribution point
    #[error("Invalid CRL distribution point URL: {0}")]
    InvalidUrl(String),

    /// CRL exceeds maximum allowed size
    #[error("CRL size {0} bytes exceeds maximum {1} bytes")]
    CrlTooLarge(usize, usize),

    /// Failed to extract CRL distribution points from certificate
    #[error("Failed to extract CRL distribution points: {0}")]
    DistributionPointError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Certificate parsing error
    #[error("Certificate parsing error: {0}")]
    CertificateError(String),

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// OCSP error
    #[error("OCSP error: {0}")]
    OcspError(String),
}

impl RevocationError {
    /// The variant's name, without its message: for logs and test failures
    /// that must not echo certificate- or response-derived text.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::FetchError(_) => "FetchError",
            Self::ParseError(_) => "ParseError",
            Self::CertificateRevoked(_) => "CertificateRevoked",
            Self::InvalidSignature(_) => "InvalidSignature",
            Self::PathBudgetExceeded(_) => "PathBudgetExceeded",
            Self::StaleCrl(_) => "StaleCrl",
            Self::CrlExpired(_) => "CrlExpired",
            Self::CrlNotYetValid(_) => "CrlNotYetValid",
            Self::HttpError(_) => "HttpError",
            Self::HttpTimeout(_) => "HttpTimeout",
            Self::InvalidUrl(_) => "InvalidUrl",
            Self::CrlTooLarge(_, _) => "CrlTooLarge",
            Self::DistributionPointError(_) => "DistributionPointError",
            Self::IoError(_) => "IoError",
            Self::CertificateError(_) => "CertificateError",
            Self::CacheError(_) => "CacheError",
            Self::ConfigError(_) => "ConfigError",
            Self::OcspError(_) => "OcspError",
        }
    }
}

impl From<RevocationError> for crate::eap::EapError {
    fn from(err: RevocationError) -> Self {
        crate::eap::EapError::TlsError(format!("Revocation check failed: {}", err))
    }
}
