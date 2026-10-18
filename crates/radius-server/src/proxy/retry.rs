//! Retry and timeout handling
//!
//! This module implements retry logic and timeout detection for proxy requests.
//!
//! ## Retry Strategy
//! - Detects timed-out requests by scanning ProxyCache
//! - Retries with same server or fails over to different server
//! - Sends Access-Reject to NAS after max retries exhausted
//!
//! ## Timeout Monitoring
//! - Background task periodically scans for timed-out requests
//! - Configurable scan interval (default: every 5 seconds)
//! - Removes expired entries and triggers retries

use crate::proxy::cache::{ProxyCache, ProxyCacheEntry};
use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::handler::ProxyHandler;
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::auth::calculate_response_authenticator;
use radius_proto::{Code, Packet};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, info, warn};

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    /// Retry interval in seconds (how often to check for timeouts)
    #[serde(default = "default_retry_interval")]
    pub retry_interval: u64,
    /// Failover to different server on timeout
    #[serde(default = "default_failover_on_timeout")]
    pub failover_on_timeout: bool,
}

fn default_max_retries() -> u8 {
    3
}

fn default_retry_interval() -> u64 {
    5
}

fn default_failover_on_timeout() -> bool {
    true
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max_retries: default_max_retries(),
            retry_interval: default_retry_interval(),
            failover_on_timeout: default_failover_on_timeout(),
        }
    }
}

/// Retry manager for timeout and retry orchestration
pub struct RetryManager {
    /// Proxy cache for finding timed-out requests
    cache: Arc<ProxyCache>,
    /// Proxy handler for re-forwarding requests
    handler: Arc<ProxyHandler>,
    /// Retry configuration
    config: RetryConfig,
    /// Request timeout duration
    timeout: Duration,
    /// Running flag for background task
    running: Arc<AtomicBool>,
    /// Socket for sending reject responses
    socket: Arc<UdpSocket>,
}

impl RetryManager {
    /// Create a new retry manager
    pub fn new(
        cache: Arc<ProxyCache>,
        handler: Arc<ProxyHandler>,
        config: RetryConfig,
        timeout: Duration,
    ) -> Self {
        let socket = handler.socket();

        RetryManager {
            cache,
            handler,
            config,
            timeout,
            running: Arc::new(AtomicBool::new(false)),
            socket,
        }
    }

    /// Start background retry/timeout monitoring task
    ///
    /// This task periodically scans the cache for timed-out requests
    /// and either retries them or sends Access-Reject if max retries exceeded.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(&self.cache);
        let handler = Arc::clone(&self.handler);
        let socket = Arc::clone(&self.socket);
        let config = self.config.clone();
        let timeout = self.timeout;
        let running = Arc::clone(&self.running);

        running.store(true, Ordering::Relaxed);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(config.retry_interval));

            info!(
                retry_interval = config.retry_interval,
                max_retries = config.max_retries,
                failover_on_timeout = config.failover_on_timeout,
                timeout_secs = timeout.as_secs(),
                "Retry manager started"
            );

            while running.load(Ordering::Relaxed) {
                interval.tick().await;

                // Get all timed-out entries
                let timed_out = cache.get_timed_out(timeout);

                debug!(
                    timed_out_count = timed_out.len(),
                    "Checking for timed-out requests"
                );

                for entry in timed_out {
                    if let Err(e) =
                        Self::handle_timeout(&cache, &handler, &socket, &config, entry).await
                    {
                        warn!(error = %e, "Failed to handle timeout");
                    }
                }
            }

            info!("Retry manager stopped");
        })
    }

    /// Stop the background retry task
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Handle a timed-out request
    async fn handle_timeout(
        cache: &Arc<ProxyCache>,
        _handler: &Arc<ProxyHandler>,
        socket: &Arc<UdpSocket>,
        config: &RetryConfig,
        mut entry: ProxyCacheEntry,
    ) -> ProxyResult<()> {
        // Check if max retries exceeded
        if entry.retry_count >= config.max_retries {
            warn!(
                nas = %entry.original_source,
                identifier = entry.original_request.identifier,
                retry_count = entry.retry_count,
                max_retries = config.max_retries,
                "Max retries exceeded, sending Access-Reject"
            );

            // Send Access-Reject to NAS
            Self::send_reject(socket, &entry).await?;

            // Remove from cache
            cache.remove(&entry.proxy_state);

            // Record timeout in home server stats
            entry.home_server.stats().record_timeout();

            return Ok(());
        }

        // Increment retry count
        entry.retry_count += 1;

        info!(
            nas = %entry.original_source,
            identifier = entry.original_request.identifier,
            retry_count = entry.retry_count,
            home_server = %entry.home_server.name,
            "Retrying timed-out request"
        );

        // Determine if we should failover to a different server
        let home_server = if config.failover_on_timeout {
            // Try to select a different server from the pool
            // For now, use the same server (pool selection would need pool reference)
            // This is a limitation - full failover requires Router integration
            entry.home_server.clone()
        } else {
            entry.home_server.clone()
        };

        // Record timeout for old server
        entry.home_server.stats().record_timeout();

        // Re-forward the request (keeping the same Proxy-State)
        // Note: The original Proxy-State is already in the packet
        let request_data = entry.original_request.encode()?;
        socket.send_to(&request_data, home_server.address).await?;

        // Update entry with new home server and timestamp
        entry.home_server = home_server.clone();
        entry.sent_at = std::time::Instant::now();

        // Re-insert into cache
        cache.insert(entry)?;

        // Record new request
        home_server.stats().record_request();

        Ok(())
    }

    /// Send Access-Reject to NAS
    async fn send_reject(socket: &Arc<UdpSocket>, entry: &ProxyCacheEntry) -> ProxyResult<()> {
        let mut reject = Packet::new(
            Code::AccessReject,
            entry.original_request.identifier,
            entry.original_request.authenticator,
        );

        // Add Reply-Message explaining timeout
        reject.add_attribute(
            Attribute::string(
                AttributeType::ReplyMessage as u8,
                "Request timed out after maximum retries",
            )
            .map_err(|e| {
                ProxyError::Configuration(format!("Failed to create Reply-Message: {}", e))
            })?,
        );

        // Calculate response authenticator (use empty secret for reject from proxy)
        let response_auth = calculate_response_authenticator(
            &reject,
            &entry.original_request.authenticator,
            b"", // Empty secret - reject from proxy itself
        );
        reject.authenticator = response_auth;

        // Send to NAS
        let reject_data = reject.encode()?;
        socket.send_to(&reject_data, entry.original_source).await?;

        info!(
            nas = %entry.original_source,
            identifier = entry.original_request.identifier,
            "Sent Access-Reject due to timeout"
        );

        Ok(())
    }
}

impl Drop for RetryManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RetryConfig {
        RetryConfig {
            max_retries: 2,
            retry_interval: 1, // 1 second for faster tests
            failover_on_timeout: true,
        }
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_interval, 5);
        assert!(config.failover_on_timeout);
    }

    #[test]
    fn test_retry_config_serialization() {
        let config = create_test_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RetryConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.max_retries, config.max_retries);
        assert_eq!(deserialized.retry_interval, config.retry_interval);
        assert_eq!(deserialized.failover_on_timeout, config.failover_on_timeout);
    }

    #[tokio::test]
    async fn test_retry_manager_creation() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(30), 100));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let config = create_test_config();
        let timeout = Duration::from_secs(30);

        let manager = RetryManager::new(cache, Arc::new(handler), config, timeout);
        assert_eq!(manager.config.max_retries, 2);
        assert_eq!(manager.config.retry_interval, 1);
        assert_eq!(manager.timeout, timeout);
    }

    #[tokio::test]
    async fn test_retry_manager_start_stop() {
        let cache = Arc::new(ProxyCache::new(Duration::from_secs(30), 100));
        let handler = ProxyHandler::new(cache.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let config = create_test_config();
        let timeout = Duration::from_secs(30);

        let manager = RetryManager::new(cache, Arc::new(handler), config, timeout);

        // Start background task
        let handle = manager.start();
        assert!(manager.running.load(Ordering::Relaxed));

        // Give it a moment to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop it
        manager.stop();
        assert!(!manager.running.load(Ordering::Relaxed));

        // Wait for task to finish
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}
