//! RADIUS Server Implementation
//!
//! This crate provides a production-ready RADIUS server built on top of
//! the `radius-proto` protocol implementation.
//!
//! # Features
//!
//! - Async I/O with Tokio
//! - Pluggable authentication handlers
//! - JSON configuration
//! - User and client management
//! - Logging and monitoring
//! - Strict RFC 2865 compliance validation (default)
//! - JSON audit logging
//! - Rate limiting and DoS protection
//! - Request deduplication (replay attack prevention)
//! - Per-client IP validation and secrets
//!
//! # Example
//!
//! ```rust,no_run
//! use radius_server::{RadiusServer, ServerConfig, SimpleAuthHandler};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create auth handler
//!     let mut handler = SimpleAuthHandler::new();
//!     handler.add_user("alice", "password");
//!
//!     // Create server (supports both IPv4 and IPv6)
//!     // Use "0.0.0.0:1812" for IPv4 or "[::]:1812" for IPv6
//!     let config = ServerConfig::new(
//!         "0.0.0.0:1812".parse()?,
//!         b"secret",
//!         Arc::new(handler)
//!     );
//!
//!     let server = RadiusServer::new(config).await?;
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod accounting;
pub mod audit;
pub mod buffer_pool;
pub mod cache;
pub mod config;
pub mod eap_auth;
pub mod health;
pub mod ldap_auth;
pub mod metrics;
pub mod mgmt;
pub mod policy;
pub mod policy_enforce;
pub mod postgres_auth;
pub mod proxy;
pub mod ratelimit;
pub mod server;
pub mod state;

pub use accounting::{AccountingHandler, AccountingResult, Session, SimpleAccountingHandler};
pub use audit::{AuditEntry, AuditEventType, AuditLogger};
pub use cache::{RequestCache, RequestFingerprint};
pub use config::{Client, Config, ConfigError, User};
pub use eap_auth::EapAuthHandler;
pub use ldap_auth::{LdapAuthHandler, LdapConfig, LdapError};
pub use policy::{
    AuthzProfile, Condition, Decision, Dictionary, Effect, Operator, PolicyConfig, PolicySet,
    ReplyAttribute, RequestContext, Rule, dictionary,
};
pub use postgres_auth::{PostgresAuthHandler, PostgresConfig, PostgresError};
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use server::{
    AuthHandler, AuthResult, RadiusServer, ServerConfig, ServerError, SimpleAuthHandler,
};

// Observability exports (health + metrics HTTP servers)
#[cfg(feature = "observability")]
pub use health::{HealthCheckState, HealthStatus, create_health_server, start_health_server};
#[cfg(feature = "observability")]
pub use metrics::{MetricsState, PrometheusMetrics, create_metrics_server, start_metrics_server};
#[cfg(feature = "observability")]
pub use mgmt::{MgmtState, create_mgmt_server, start_mgmt_server};
