//! Shared state backend abstraction
//!
//! This module provides a pluggable state backend system for storing session
//! and cache data. The server is stateless and scaled via Kubernetes
//! ReplicaSets, so only an in-memory backend is provided.
//!
//! # Architecture
//!
//! The state backend system uses a trait-based abstraction that allows
//! switching between different storage implementations:
//!
//! - **MemoryStateBackend**: Local in-memory storage (default)
//!
//! # Usage
//!
//! ```rust
//! use radius_server::state::StateConfig;
//!
//! // Default: In-memory
//! let config = StateConfig::default();
//! ```

pub mod config;
pub mod error;
pub mod memory;
pub mod session_manager;

pub use config::{StateBackendType, StateConfig};
pub use error::StateError;
pub use memory::MemoryStateBackend;
pub use session_manager::{CacheStats, SharedSessionManager};

use async_trait::async_trait;
use std::time::Duration;

/// State backend trait for pluggable storage implementations
///
/// This trait defines the interface for storing and retrieving session
/// and cache data. Implementations must be thread-safe and support
/// asynchronous operations.
///
/// # Implementations
///
/// - `MemoryStateBackend`: In-memory HashMap-based storage
///
/// # Key Design
///
/// Keys should follow a hierarchical naming scheme:
///
/// ```text
/// {prefix}:{type}:{identifier}
///
/// Examples:
/// - usg-radius:eap_session:abc123
/// - usg-radius:accounting:session-456
/// - usg-radius:req_cache:fingerprint-789
/// - usg-radius:ratelimit:192.168.1.100
/// ```
#[async_trait]
pub trait StateBackend: Send + Sync {
    /// Get a value by key
    ///
    /// Returns `Ok(Some(value))` if the key exists and hasn't expired.
    /// Returns `Ok(None)` if the key doesn't exist or has expired.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StateError>;

    /// Set a value with optional TTL (time-to-live)
    ///
    /// If `ttl` is `None`, the value never expires (for in-memory backend).
    async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<(), StateError>;

    /// Delete a key
    ///
    /// Returns `Ok(())` regardless of whether the key existed.
    async fn delete(&self, key: &str) -> Result<(), StateError>;

    /// Check if a key exists
    ///
    /// Returns `true` if the key exists and hasn't expired.
    async fn exists(&self, key: &str) -> Result<bool, StateError>;

    /// Get all keys matching a pattern (glob-style)
    ///
    /// Pattern syntax:
    /// - `*` matches any sequence of characters
    /// - `?` matches any single character
    /// - `[abc]` matches any character in the set
    ///
    /// Example: `"session:*"` matches all session keys
    ///
    /// **Warning**: This operation can be slow on large datasets.
    /// Use sparingly, primarily for debugging or admin operations.
    async fn keys(&self, pattern: &str) -> Result<Vec<String>, StateError>;

    /// Atomic SET if Not eXists (SET NX)
    ///
    /// Sets the key to value only if it doesn't already exist.
    /// Returns `true` if the key was set, `false` if it already existed.
    ///
    /// Used for distributed locking and request deduplication.
    async fn set_nx(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool, StateError>;

    /// Atomic increment
    ///
    /// Increments the integer value stored at key by 1.
    /// If the key doesn't exist, it's set to 0 before incrementing.
    /// Returns the new value after increment.
    ///
    /// Used for rate limiting and counters.
    async fn incr(&self, key: &str) -> Result<i64, StateError>;

    /// Set expiration on an existing key
    ///
    /// Returns `true` if the timeout was set, `false` if key doesn't exist.
    async fn expire(&self, key: &str, ttl: Duration) -> Result<bool, StateError>;

    /// Health check / connectivity test
    ///
    /// Verifies the backend is reachable and functional.
    /// For in-memory backend, always returns `Ok(())`.
    async fn ping(&self) -> Result<(), StateError>;
}
