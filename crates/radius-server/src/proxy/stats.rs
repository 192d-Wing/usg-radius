//! Proxy statistics aggregation and export
//!
//! This module provides structures for collecting and exporting statistics
//! from all proxy components (pools, servers, health checks, cache).

use crate::proxy::home_server::{HomeServer, HomeServerState};
use crate::proxy::pool::HomeServerPool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Aggregate proxy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
    /// Statistics for each pool
    pub pools: Vec<PoolStatSnapshot>,
    /// Total requests across all pools
    pub total_requests: u64,
    /// Total responses across all pools
    pub total_responses: u64,
    /// Total outstanding requests across all pools
    pub total_outstanding: u64,
    /// Total timeouts across all servers
    pub total_timeouts: u64,
}

/// Snapshot of pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStatSnapshot {
    /// Pool name
    pub name: String,
    /// Load balancing strategy
    pub strategy: String,
    /// Total servers in pool
    pub total_servers: usize,
    /// Available servers (Up state)
    pub available_servers: usize,
    /// Servers with capacity
    pub servers_with_capacity: usize,
    /// Total requests to this pool
    pub total_requests: u64,
    /// Total responses from this pool
    pub total_responses: u64,
    /// Total outstanding requests in this pool
    pub total_outstanding: u64,
    /// Statistics for each server in the pool
    pub servers: Vec<ServerStatSnapshot>,
}

/// Snapshot of individual server statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatSnapshot {
    /// Server name
    pub name: String,
    /// Server address
    pub address: String,
    /// Current server state
    pub state: String,
    /// Requests sent to this server
    pub requests_sent: u64,
    /// Responses received from this server
    pub responses_received: u64,
    /// Timeouts from this server
    pub timeouts: u64,
    /// Outstanding requests to this server
    pub outstanding: u64,
    /// Time since last response (seconds)
    pub time_since_last_response: Option<u64>,
    /// Health check statistics
    pub health: ServerHealthStats,
}

/// Health check statistics for a server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHealthStats {
    /// Total health checks performed
    pub total_checks: u64,
    /// Total successful health checks
    pub total_successes: u64,
    /// Total failed health checks
    pub total_failures: u64,
    /// Consecutive failures
    pub consecutive_failures: u64,
    /// Consecutive successes
    pub consecutive_successes: u64,
}

impl ProxyStats {
    /// Collect statistics from all pools
    pub fn collect(pools: &[Arc<HomeServerPool>]) -> Self {
        let mut pool_snapshots = Vec::new();
        let mut total_requests = 0;
        let mut total_responses = 0;
        let mut total_outstanding = 0;
        let mut total_timeouts = 0;

        for pool in pools {
            let pool_stats = pool.stats();

            // Collect server statistics
            let mut server_snapshots = Vec::new();
            for server in &pool.servers {
                let server_snapshot = ServerStatSnapshot::from_server(server);
                total_timeouts += server_snapshot.timeouts;
                server_snapshots.push(server_snapshot);
            }

            total_requests += pool_stats.total_requests;
            total_responses += pool_stats.total_responses;
            total_outstanding += pool_stats.total_outstanding;

            pool_snapshots.push(PoolStatSnapshot {
                name: pool.name.clone(),
                strategy: format!("{:?}", pool.strategy),
                total_servers: pool_stats.total_servers,
                available_servers: pool_stats.available_servers,
                servers_with_capacity: pool_stats.servers_with_capacity,
                total_requests: pool_stats.total_requests,
                total_responses: pool_stats.total_responses,
                total_outstanding: pool_stats.total_outstanding,
                servers: server_snapshots,
            });
        }

        ProxyStats {
            pools: pool_snapshots,
            total_requests,
            total_responses,
            total_outstanding,
            total_timeouts,
        }
    }

    /// Export statistics as JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl ServerStatSnapshot {
    /// Create a snapshot from a HomeServer
    fn from_server(server: &Arc<HomeServer>) -> Self {
        let stats = server.stats();
        let health_stats = server.health_stats();

        let state_str = match server.state() {
            HomeServerState::Up => "Up",
            HomeServerState::Down => "Down",
            HomeServerState::Dead => "Dead",
        };

        ServerStatSnapshot {
            name: server.name.clone(),
            address: server.address.to_string(),
            state: state_str.to_string(),
            requests_sent: stats.requests_sent(),
            responses_received: stats.responses_received(),
            timeouts: stats.timeouts(),
            outstanding: stats.outstanding(),
            time_since_last_response: stats.time_since_last_response().map(|d| d.as_secs()),
            health: ServerHealthStats {
                total_checks: health_stats.total_checks(),
                total_successes: health_stats.total_successes(),
                total_failures: health_stats.total_failures(),
                consecutive_failures: health_stats.consecutive_failures(),
                consecutive_successes: health_stats.consecutive_successes(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::home_server::HomeServerConfig;
    use crate::proxy::pool::{HomeServerPoolConfig, LoadBalanceStrategy};

    #[test]
    fn test_proxy_stats_collection() {
        let pool_config = HomeServerPoolConfig {
            name: "test_pool".to_string(),
            strategy: LoadBalanceStrategy::RoundRobin,
            servers: vec![
                HomeServerConfig {
                    name: Some("server1".to_string()),
                    ..HomeServerConfig::udp("127.0.0.1:1812", "secret1")
                },
                HomeServerConfig {
                    name: Some("server2".to_string()),
                    ..HomeServerConfig::udp("127.0.0.1:1813", "secret2")
                },
            ],
        };

        let pool = Arc::new(HomeServerPool::new(pool_config).unwrap());
        let pools = vec![pool];

        let stats = ProxyStats::collect(&pools);

        assert_eq!(stats.pools.len(), 1);
        assert_eq!(stats.pools[0].name, "test_pool");
        assert_eq!(stats.pools[0].servers.len(), 2);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_responses, 0);
    }

    #[test]
    fn test_proxy_stats_json_export() {
        let pool_config = HomeServerPoolConfig {
            name: "test_pool".to_string(),
            strategy: LoadBalanceStrategy::Failover,
            servers: vec![HomeServerConfig {
                name: Some("test_server".to_string()),
                ..HomeServerConfig::udp("127.0.0.1:1812", "secret")
            }],
        };

        let pool = Arc::new(HomeServerPool::new(pool_config).unwrap());
        let stats = ProxyStats::collect(&[pool]);

        let json = stats.to_json().unwrap();
        assert!(json.contains("test_pool"));
        assert!(json.contains("test_server"));
        assert!(json.contains("Failover"));
    }
}
