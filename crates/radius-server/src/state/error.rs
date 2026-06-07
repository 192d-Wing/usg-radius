//! Error types for state backend operations

use std::fmt;

/// Errors that can occur during state backend operations
#[derive(Debug)]
pub enum StateError {
    /// Connection error (backend unreachable)
    ConnectionError(String),

    /// Command timeout
    Timeout(String),

    /// Serialization/deserialization error
    SerializationError(String),

    /// Invalid key or value
    InvalidInput(String),

    /// Backend-specific error
    BackendError(String),

    /// Configuration error
    ConfigError(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            StateError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            StateError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            StateError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            StateError::BackendError(msg) => write!(f, "Backend error: {}", msg),
            StateError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for StateError {}

impl From<std::io::Error> for StateError {
    fn from(err: std::io::Error) -> Self {
        StateError::BackendError(format!("IO error: {}", err))
    }
}

impl From<serde_json::Error> for StateError {
    fn from(err: serde_json::Error) -> Self {
        StateError::SerializationError(format!("JSON error: {}", err))
    }
}
