//! Home server pools and load balancing
//!
//! This module implements server pools with multiple load balancing strategies:
//! - Round-robin: Distribute requests evenly across servers
//! - Least-outstanding: Send to server with fewest pending requests
//! - Failover: Primary server with fallback to backups
//! - Random: Random server selection

use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::home_server::{HomeServer, HomeServerConfig};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Load balancing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Round-robin selection
    #[default]
    RoundRobin,
    /// Select server with fewest outstanding requests
    LeastOutstanding,
    /// Failover (primary + backups)
    Failover,
    /// Random selection
    Random,
}

/// Home server pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeServerPoolConfig {
    /// Pool name
    pub name: String,
    /// Load balancing strategy
    #[serde(default)]
    pub strategy: LoadBalanceStrategy,
    /// Servers in this pool
    pub servers: Vec<HomeServerConfig>,
}

impl HomeServerPoolConfig {
    /// Validate configuration
    pub fn validate(&self) -> ProxyResult<()> {
        if self.name.is_empty() {
            return Err(ProxyError::Configuration(
                "Pool name cannot be empty".to_string(),
            ));
        }

        if self.servers.is_empty() {
            return Err(ProxyError::Configuration(format!(
                "Pool '{}' has no servers configured",
                self.name
            )));
        }

        for server in &self.servers {
            server.validate()?;
        }

        Ok(())
    }
}

/// Home server pool
pub struct HomeServerPool {
    /// Pool name
    pub name: String,
    /// Servers in this pool
    pub servers: Vec<Arc<HomeServer>>,
    /// Load balancing strategy
    pub strategy: LoadBalanceStrategy,
    /// Round-robin counter (used for round-robin strategy)
    round_robin_counter: AtomicUsize,
}

impl HomeServerPool {
    /// Create a new pool from configuration
    pub fn new(config: HomeServerPoolConfig) -> ProxyResult<Self> {
        config.validate()?;

        // Create HomeServer instances from configuration
        let servers: Result<Vec<_>, _> = config
            .servers
            .into_iter()
            .map(|server_config| HomeServer::new(server_config).map(Arc::new))
            .collect();

        let servers = servers?;

        if servers.is_empty() {
            return Err(ProxyError::Configuration(format!(
                "Pool '{}' has no servers after initialization",
                config.name
            )));
        }

        Ok(HomeServerPool {
            name: config.name,
            servers,
            strategy: config.strategy,
            round_robin_counter: AtomicUsize::new(0),
        })
    }

    /// Select next server based on configured strategy
    ///
    /// Returns None if no servers are available or all servers are at capacity.
    pub fn select_server(&self) -> Option<Arc<HomeServer>> {
        match self.strategy {
            LoadBalanceStrategy::RoundRobin => self.select_round_robin(),
            LoadBalanceStrategy::LeastOutstanding => self.select_least_outstanding(),
            LoadBalanceStrategy::Failover => self.select_failover(),
            LoadBalanceStrategy::Random => self.select_random(),
        }
    }

    /// Round-robin selection: distribute requests evenly across all available servers
    fn select_round_robin(&self) -> Option<Arc<HomeServer>> {
        let available_servers: Vec<_> = self
            .servers
            .iter()
            .filter(|s| s.is_available() && s.has_capacity())
            .collect();

        if available_servers.is_empty() {
            return None;
        }

        // Increment counter and use modulo to wrap around
        let counter = self.round_robin_counter.fetch_add(1, Ordering::Relaxed);
        let index = counter % available_servers.len();

        Some(Arc::clone(available_servers[index]))
    }

    /// Least-outstanding selection: choose server with fewest pending requests
    fn select_least_outstanding(&self) -> Option<Arc<HomeServer>> {
        self.servers
            .iter()
            .filter(|s| s.is_available() && s.has_capacity())
            .min_by_key(|s| s.stats().outstanding())
            .map(Arc::clone)
    }

    /// Failover selection: use first server, fall back to others if unavailable
    fn select_failover(&self) -> Option<Arc<HomeServer>> {
        // Try each server in order until we find one that's available
        self.servers
            .iter()
            .find(|s| s.is_available() && s.has_capacity())
            .map(Arc::clone)
    }

    /// Random selection: randomly choose from available servers
    fn select_random(&self) -> Option<Arc<HomeServer>> {
        let available_servers: Vec<_> = self
            .servers
            .iter()
            .filter(|s| s.is_available() && s.has_capacity())
            .collect();

        if available_servers.is_empty() {
            return None;
        }

        // Randomly select an index
        let index = rand::rng().random_range(0..available_servers.len());
        Some(Arc::clone(available_servers[index]))
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let total_servers = self.servers.len();
        let available_servers = self.servers.iter().filter(|s| s.is_available()).count();
        let servers_with_capacity = self
            .servers
            .iter()
            .filter(|s| s.is_available() && s.has_capacity())
            .count();
        let total_requests: u64 = self.servers.iter().map(|s| s.stats().requests_sent()).sum();
        let total_responses: u64 = self
            .servers
            .iter()
            .map(|s| s.stats().responses_received())
            .sum();
        let total_outstanding: u64 = self.servers.iter().map(|s| s.stats().outstanding()).sum();

        PoolStats {
            total_servers,
            available_servers,
            servers_with_capacity,
            total_requests,
            total_responses,
            total_outstanding,
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total number of servers in pool
    pub total_servers: usize,
    /// Number of available servers (not dead/unavailable)
    pub available_servers: usize,
    /// Number of servers with capacity for more requests
    pub servers_with_capacity: usize,
    /// Total requests sent to pool
    pub total_requests: u64,
    /// Total responses received from pool
    pub total_responses: u64,
    /// Total outstanding requests across all servers
    pub total_outstanding: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_pool_config(
        name: &str,
        num_servers: usize,
        strategy: LoadBalanceStrategy,
    ) -> HomeServerPoolConfig {
        let servers = (0..num_servers)
            .map(|i| HomeServerConfig {
                name: Some(format!("Server{}", i)),
                ..HomeServerConfig::udp(format!("127.0.0.1:180{}", i), format!("secret{}", i))
            })
            .collect();

        HomeServerPoolConfig {
            name: name.to_string(),
            strategy,
            servers,
        }
    }

    #[test]
    fn test_pool_creation() {
        let config = create_test_pool_config("test_pool", 3, LoadBalanceStrategy::RoundRobin);
        let pool = HomeServerPool::new(config).unwrap();

        assert_eq!(pool.name, "test_pool");
        assert_eq!(pool.servers.len(), 3);
        assert_eq!(pool.strategy, LoadBalanceStrategy::RoundRobin);
    }

    #[test]
    fn test_pool_config_validation_empty_name() {
        let config = HomeServerPoolConfig {
            name: "".to_string(),
            strategy: LoadBalanceStrategy::RoundRobin,
            servers: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_pool_config_validation_no_servers() {
        let config = HomeServerPoolConfig {
            name: "test".to_string(),
            strategy: LoadBalanceStrategy::RoundRobin,
            servers: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_round_robin_selection() {
        let config = create_test_pool_config("test_pool", 3, LoadBalanceStrategy::RoundRobin);
        let pool = HomeServerPool::new(config).unwrap();

        // Select servers multiple times and verify round-robin behavior
        let selections: Vec<_> = (0..9)
            .filter_map(|_| pool.select_server().map(|s| s.name.clone()))
            .collect();

        // Should cycle through all 3 servers
        assert_eq!(selections.len(), 9);
        // Pattern should repeat: Server0, Server1, Server2, Server0, Server1, Server2, ...
        for (i, selection) in selections.iter().enumerate() {
            let expected = format!("Server{}", i % 3);
            assert_eq!(*selection, expected);
        }
    }

    #[test]
    fn test_least_outstanding_selection() {
        let config = create_test_pool_config("test_pool", 3, LoadBalanceStrategy::LeastOutstanding);
        let pool = HomeServerPool::new(config).unwrap();

        // All servers start with 0 outstanding, should select first
        let server1 = pool.select_server().unwrap();
        assert_eq!(server1.name, "Server0");

        // Simulate request sent to server0
        server1.stats().record_request();

        // Next selection should prefer server with 0 outstanding (Server1 or Server2)
        let server2 = pool.select_server().unwrap();
        assert!(server2.name == "Server1" || server2.name == "Server2");
    }

    #[test]
    fn test_failover_selection() {
        let config = create_test_pool_config("test_pool", 3, LoadBalanceStrategy::Failover);
        let pool = HomeServerPool::new(config).unwrap();

        // Failover always selects first available server
        for _ in 0..5 {
            let server = pool.select_server().unwrap();
            assert_eq!(server.name, "Server0");
        }
    }

    #[test]
    fn test_random_selection() {
        let config = create_test_pool_config("test_pool", 3, LoadBalanceStrategy::Random);
        let pool = HomeServerPool::new(config).unwrap();

        // Select many times and verify all servers are eventually selected
        let mut selected_servers = std::collections::HashSet::new();
        for _ in 0..20 {
            if let Some(server) = pool.select_server() {
                selected_servers.insert(server.name.clone());
            }
        }

        // With 20 selections from 3 servers, we should hit all servers
        assert_eq!(selected_servers.len(), 3);
    }

    #[test]
    fn test_pool_stats() {
        let config = create_test_pool_config("test_pool", 3, LoadBalanceStrategy::RoundRobin);
        let pool = HomeServerPool::new(config).unwrap();

        let stats = pool.stats();
        assert_eq!(stats.total_servers, 3);
        assert_eq!(stats.available_servers, 3);
        assert_eq!(stats.servers_with_capacity, 3);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_responses, 0);
        assert_eq!(stats.total_outstanding, 0);
    }

    #[test]
    fn test_load_balance_strategy_default() {
        assert_eq!(
            LoadBalanceStrategy::default(),
            LoadBalanceStrategy::RoundRobin
        );
    }
}
