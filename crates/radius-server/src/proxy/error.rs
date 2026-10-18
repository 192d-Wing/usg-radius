//! Proxy error types

use std::net::AddrParseError;
use thiserror::Error;

/// Proxy operation errors
#[derive(Error, Debug)]
pub enum ProxyError {
    /// IO error during network operations
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// RADIUS packet encoding/decoding error
    #[error("Packet error: {0}")]
    Packet(#[from] radius_proto::PacketError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Home server not found
    #[error("Home server not found: {0}")]
    HomeServerNotFound(String),

    /// No home servers available in pool
    #[error("No home servers available in pool: {0}")]
    NoServersAvailable(String),

    /// Proxy cache full (too many outstanding requests)
    #[error("Proxy cache full: {0} outstanding requests")]
    CacheFull(usize),

    /// Request correlation failed (Proxy-State not found)
    #[error("Request correlation failed: Proxy-State not found")]
    CorrelationFailed,

    /// Proxy loop detected (too many Proxy-State attributes)
    #[error("Proxy loop detected: {0} Proxy-State attributes (limit: {1})")]
    ProxyLoop(usize, usize),

    /// Request timeout
    #[error("Request timeout after {0}s")]
    Timeout(u64),

    /// Max retries exceeded
    #[error("Max retries exceeded: {0} retries")]
    MaxRetriesExceeded(u8),

    /// Invalid response authenticator from home server
    #[error("Invalid response authenticator from home server")]
    InvalidResponseAuthenticator,

    /// User-Password from the NAS could not be decrypted under the client secret
    #[error("User-Password from NAS could not be decrypted under the client secret: {0}")]
    InvalidUserPassword(String),

    /// Address parse error
    #[error("Address parse error: {0}")]
    AddressParse(#[from] AddrParseError),

    /// Realm not found
    #[error("Realm not found: {0}")]
    RealmNotFound(String),

    /// Invalid realm pattern
    #[error("Invalid realm pattern: {0}")]
    InvalidRealmPattern(String),
}

/// Result type for proxy operations
pub type ProxyResult<T> = Result<T, ProxyError>;
