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

        // RFC 6613 §2.6 (via RFC 6614 §2.3 item 1): a RADIUS/TCP connection
        // MUST be watched by the RFC 3539 §3.4 application-layer watchdog,
        // with Status-Server as the watchdog message. The Status-Server
        // probe *is* that watchdog for a RadSec link, so a RadSec home server
        // without probes is a configuration error, not a quiet degradation.
        if !self.health_check.enabled {
            let radsec_server = self
                .pools
                .iter()
                .flat_map(|p| p.servers.iter().map(move |s| (p, s)))
                .find(|(_, s)| s.transport == HomeServerTransport::Radsec);
            if let Some((pool, server)) = radsec_server {
                return Err(ProxyError::Configuration(format!(
                    "pool '{}' home server '{}': RadSec home servers require \
                     health_check.enabled: the Status-Server probe is the RFC 6613 §2.6 \
                     watchdog (RFC 3539 §3.4) of the connection",
                    pool.name,
                    server.name.as_deref().unwrap_or(&server.address)
                )));
            }
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

    /// A pool with one RadSec home server and one UDP home server.
    fn mixed_pool() -> HomeServerPoolConfig {
        HomeServerPoolConfig {
            name: "home".to_string(),
            strategy: Default::default(),
            servers: vec![
                HomeServerConfig::udp("10.0.0.1:1812", "home-secret"),
                HomeServerConfig {
                    name: Some("home-radsec".to_string()),
                    ..HomeServerConfig::radsec(
                        "10.0.0.2:2083",
                        HomeServerTlsConfig {
                            ca_path: "/etc/radius/home-ca.pem".to_string(),
                            cert_path: "/etc/radius/proxy.pem".to_string(),
                            key_path: "/etc/radius/proxy.key".to_string(),
                            server_name: "home.test".to_string(),
                            revocation: None,
                        },
                    )
                },
            ],
        }
    }

    #[test]
    fn radsec_home_server_requires_health_checks() {
        // RFC 6613 §2.6: the Status-Server probe is the mandatory watchdog of
        // a RADIUS/TCP connection, so a RadSec home server with
        // health_check.enabled = false is a configuration error, named.
        let config = ProxyConfig {
            enabled: true,
            pools: vec![mixed_pool()],
            health_check: HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("health_check.enabled"), "{err}");
        assert!(err.contains("home-radsec"), "{err}");
        assert!(err.contains("RFC 6613"), "{err}");

        // A UDP-only pool may still run without probes.
        let mut udp_only = mixed_pool();
        udp_only.servers.truncate(1);
        let config = ProxyConfig {
            enabled: true,
            pools: vec![udp_only],
            health_check: HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        // With probes on, the RadSec server is accepted (given the `tls`
        // feature; without it `HomeServerConfig::validate` refuses it).
        let config = ProxyConfig {
            enabled: true,
            pools: vec![mixed_pool()],
            ..Default::default()
        };
        assert_eq!(config.validate().is_ok(), cfg!(feature = "tls"));
    }
}
