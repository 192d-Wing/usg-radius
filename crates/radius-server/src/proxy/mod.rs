//! RADIUS Proxy Module
//!
//! This module implements RADIUS proxy functionality as specified in RFC 2865.
//! It provides request forwarding, realm-based routing, load balancing, and failover.
//!
//! # Architecture
//!
//! The proxy consists of several key components:
//!
//! - [`ProxyHandler`] - Core request forwarding and response routing logic
//! - [`Router`] - Realm-based routing engine for determining target servers
//! - [`HomeServer`] - Upstream server configuration and state tracking
//! - [`HomeServerPool`] - Server groups with load balancing strategies
//! - [`ProxyCache`] - Request/response correlation via Proxy-State attributes
//! - [`RetryManager`] - Timeout detection and retry orchestration
//!
//! # Example
//!
//! ```rust,ignore
//! use radius_server::proxy::{ProxyConfig, ProxyHandler};
//!
//! // Configure proxy with realm-based routing
//! let config = ProxyConfig {
//!     enabled: true,
//!     cache_ttl: 30,
//!     max_outstanding: 1000,
//!     pools: vec![/* ... */],
//!     realms: vec![/* ... */],
//!     // ...
//! };
//!
//! // Create proxy handler
//! let handler = ProxyHandler::new(config).await?;
//!
//! // Forward a request
//! let decision = router.route_request(&request);
//! match decision {
//!     RoutingDecision::Proxy { home_server, .. } => {
//!         handler.forward_request(request, source, home_server).await?;
//!     }
//!     RoutingDecision::Local => {
//!         // Authenticate locally
//!     }
//!     RoutingDecision::Reject => {
//!         // Send Access-Reject
//!     }
//! }
//! ```

pub mod cache;
pub mod error;
pub mod handler;
pub mod health;
pub mod home_server;
pub mod pool;
#[cfg(feature = "tls")]
pub mod radsec_client;
pub mod realm;
pub mod retry;
pub mod router;
pub mod stats;

pub use cache::{ProxyCache, ProxyCacheEntry, ProxyStateKey};
pub use error::ProxyError;
pub use handler::ProxyHandler;
pub use health::{HealthCheckConfig, HealthChecker};
pub use home_server::{
    HomeServer, HomeServerConfig, HomeServerState, HomeServerStats, HomeServerTlsConfig,
    HomeServerTransport,
};
pub use pool::{HomeServerPool, HomeServerPoolConfig, LoadBalanceStrategy};
pub use realm::{Realm, RealmConfig, RealmMatchConfig, RealmMatcher};
pub use retry::{RetryConfig, RetryManager};
pub use router::{Router, RoutingDecision};
pub use stats::{PoolStatSnapshot, ProxyStats, ServerHealthStats, ServerStatSnapshot};

use serde::{Deserialize, Serialize};

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Enable proxy functionality
    #[serde(default)]
    pub enabled: bool,

    /// Request cache TTL in seconds (for correlation tracking)
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,

    /// Maximum outstanding proxied requests
    #[serde(default = "default_max_outstanding")]
    pub max_outstanding: usize,

    /// Proxy timeout in seconds (before retry/failover)
    #[serde(default = "default_proxy_timeout")]
    pub proxy_timeout: u64,

    /// Home server pools
    #[serde(default)]
    pub pools: Vec<HomeServerPoolConfig>,

    /// Realm routing rules
    #[serde(default)]
    pub realms: Vec<RealmConfig>,

    /// Default realm for unmatched requests
    /// "local" = authenticate locally
    /// pool name = proxy to that pool
    #[serde(default)]
    pub default_realm: Option<String>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: HealthCheckConfig,

    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,
}

fn default_cache_ttl() -> u64 {
    30 // 30 seconds
}

fn default_max_outstanding() -> usize {
    1000
}

fn default_proxy_timeout() -> u64 {
    30 // 30 seconds
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: false,
            cache_ttl: default_cache_ttl(),
            max_outstanding: default_max_outstanding(),
            proxy_timeout: default_proxy_timeout(),
            pools: vec![],
            realms: vec![],
            default_realm: Some("local".to_string()),
            health_check: HealthCheckConfig::default(),
            retry: RetryConfig::default(),
        }
    }
}

impl ProxyConfig {
    /// Validate proxy configuration
    pub fn validate(&self) -> Result<(), ProxyError> {
        if !self.enabled {
            return Ok(());
        }

        // Validate pools
        if self.pools.is_empty() {
            return Err(ProxyError::Configuration(
                "Proxy enabled but no pools configured".to_string(),
            ));
        }

        for pool in &self.pools {
            pool.validate()?;
        }

        // Validate realms reference valid pools
        for realm in &self.realms {
            if !self.pools.iter().any(|p| p.name == realm.pool) {
                return Err(ProxyError::Configuration(format!(
                    "Realm '{}' references unknown pool '{}'",
                    realm.name, realm.pool
                )));
            }
        }

        // Validate default realm
        if let Some(ref default_realm) = self.default_realm
            && default_realm != "local"
            && !self.pools.iter().any(|p| &p.name == default_realm)
        {
            return Err(ProxyError::Configuration(format!(
                "Default realm '{}' is not 'local' and does not reference a valid pool",
                default_realm
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.cache_ttl, 30);
        assert_eq!(config.max_outstanding, 1000);
        assert_eq!(config.proxy_timeout, 30);
        assert_eq!(config.default_realm, Some("local".to_string()));
    }

    #[test]
    fn test_proxy_config_validation_disabled() {
        let config = ProxyConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_proxy_config_validation_no_pools() {
        let config = ProxyConfig {
            enabled: true,
            pools: vec![],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
