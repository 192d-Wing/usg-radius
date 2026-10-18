//! Health checking for home servers
//!
//! This module implements health checks using Status-Server requests (RFC 5997).
//! Health checks run in the background and automatically mark servers as up/down
//! based on their responsiveness.

use crate::proxy::home_server::{HomeServer, HomeServerState};
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::{Code, Packet};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, info, warn};

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checking
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Health check interval in seconds
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Health check timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Number of consecutive failures before marking server down
    #[serde(default = "default_failures_before_down")]
    pub failures_before_down: u8,
    /// Number of consecutive successes before marking server up (when down)
    #[serde(default = "default_successes_before_up")]
    pub successes_before_up: u8,
}

fn default_enabled() -> bool {
    true
}

fn default_interval() -> u64 {
    30 // Check every 30 seconds
}

fn default_timeout() -> u64 {
    10 // 10 second timeout
}

fn default_failures_before_down() -> u8 {
    3 // 3 consecutive failures
}

fn default_successes_before_up() -> u8 {
    2 // 2 consecutive successes to recover
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        HealthCheckConfig {
            enabled: default_enabled(),
            interval: default_interval(),
            timeout: default_timeout(),
            failures_before_down: default_failures_before_down(),
            successes_before_up: default_successes_before_up(),
        }
    }
}

/// Health check statistics for a single server
#[derive(Debug)]
pub struct HealthCheckStats {
    /// Total health checks performed
    total_checks: AtomicU64,
    /// Total successful health checks
    total_successes: AtomicU64,
    /// Total failed health checks
    total_failures: AtomicU64,
    /// Consecutive failures
    consecutive_failures: AtomicU64,
    /// Consecutive successes
    consecutive_successes: AtomicU64,
}

impl HealthCheckStats {
    pub fn new() -> Self {
        HealthCheckStats {
            total_checks: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
        }
    }

    /// Record a successful health check
    fn record_success(&self) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        self.total_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    /// Record a failed health check
    fn record_failure(&self) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
    }

    /// Get total checks performed
    pub fn total_checks(&self) -> u64 {
        self.total_checks.load(Ordering::Relaxed)
    }

    /// Get total successful checks
    pub fn total_successes(&self) -> u64 {
        self.total_successes.load(Ordering::Relaxed)
    }

    /// Get total failed checks
    pub fn total_failures(&self) -> u64 {
        self.total_failures.load(Ordering::Relaxed)
    }

    /// Get consecutive failures
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Get consecutive successes
    pub fn consecutive_successes(&self) -> u64 {
        self.consecutive_successes.load(Ordering::Relaxed)
    }
}

impl Default for HealthCheckStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Health checker for home servers
pub struct HealthChecker {
    /// Health check configuration
    config: HealthCheckConfig,
    /// Socket for sending Status-Server requests
    socket: Arc<UdpSocket>,
    /// Running flag for background task
    running: Arc<AtomicBool>,
}

impl HealthChecker {
    /// Create a new health checker
    pub async fn new(
        config: HealthCheckConfig,
        bind_addr: std::net::SocketAddr,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;

        Ok(HealthChecker {
            config,
            socket: Arc::new(socket),
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start background health checking task
    ///
    /// This task periodically sends Status-Server requests to all servers
    /// and updates their health state based on responses.
    pub fn start(&self, servers: Vec<Arc<HomeServer>>) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let socket = Arc::clone(&self.socket);
        let running = Arc::clone(&self.running);

        running.store(true, Ordering::Relaxed);

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(config.interval));

            info!(
                interval_secs = config.interval,
                timeout_secs = config.timeout,
                failures_before_down = config.failures_before_down,
                successes_before_up = config.successes_before_up,
                server_count = servers.len(),
                "Health checker started"
            );

            while running.load(Ordering::Relaxed) {
                interval.tick().await;

                debug!(server_count = servers.len(), "Running health checks");

                // Check all servers concurrently
                let mut check_tasks = vec![];
                for server in &servers {
                    let server = Arc::clone(server);
                    let socket = Arc::clone(&socket);
                    let timeout = Duration::from_secs(config.timeout);
                    let task = tokio::spawn(async move {
                        Self::check_server_health(server, socket, timeout).await
                    });
                    check_tasks.push(task);
                }

                // Wait for all checks to complete
                for task in check_tasks {
                    let _ = task.await;
                }

                // Update server states based on consecutive failures/successes
                for server in &servers {
                    Self::update_server_state(
                        server,
                        config.failures_before_down,
                        config.successes_before_up,
                    );
                }
            }

            info!("Health checker stopped");
        })
    }

    /// Stop the background health checking task
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check health of a single server using Status-Server request
    async fn check_server_health(
        server: Arc<HomeServer>,
        socket: Arc<UdpSocket>,
        timeout: Duration,
    ) {
        // Get or create health stats for this server
        let stats = server.health_stats();

        // Create Status-Server packet (RFC 5997)
        let mut request = Packet::new(Code::StatusServer, 1, [0u8; 16]);

        // Add Message-Authenticator (required for Status-Server)
        request.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16])
                .expect("Failed to create Message-Authenticator"),
        );

        // Encode the request
        let request_data = match request.encode() {
            Ok(data) => data,
            Err(e) => {
                warn!(
                    server = %server.name,
                    error = %e,
                    "Failed to encode Status-Server request"
                );
                stats.record_failure();
                return;
            }
        };

        // Send Status-Server request with timeout
        let send_result = socket.send_to(&request_data, server.address).await;
        if let Err(e) = send_result {
            warn!(
                server = %server.name,
                error = %e,
                "Failed to send Status-Server request"
            );
            stats.record_failure();
            return;
        }

        // Wait for response with timeout
        let mut buf = vec![0u8; 4096];
        let recv_result = time::timeout(timeout, socket.recv_from(&mut buf)).await;

        match recv_result {
            Ok(Ok((len, addr))) => {
                // Verify response is from the expected server
                if addr != server.address {
                    warn!(
                        server = %server.name,
                        expected = %server.address,
                        actual = %addr,
                        "Status-Server response from unexpected address"
                    );
                    stats.record_failure();
                    return;
                }

                // Decode the response
                match Packet::decode(&buf[..len]) {
                    Ok(response) => {
                        // Status-Server response should be Access-Accept (RFC 5997)
                        if response.code == Code::AccessAccept {
                            debug!(
                                server = %server.name,
                                "Status-Server check successful"
                            );
                            stats.record_success();
                        } else {
                            warn!(
                                server = %server.name,
                                code = ?response.code,
                                "Unexpected Status-Server response code"
                            );
                            stats.record_failure();
                        }
                    }
                    Err(e) => {
                        warn!(
                            server = %server.name,
                            error = %e,
                            "Failed to decode Status-Server response"
                        );
                        stats.record_failure();
                    }
                }
            }
            Ok(Err(e)) => {
                warn!(
                    server = %server.name,
                    error = %e,
                    "Error receiving Status-Server response"
                );
                stats.record_failure();
            }
            Err(_) => {
                warn!(
                    server = %server.name,
                    timeout_secs = timeout.as_secs(),
                    "Status-Server request timed out"
                );
                stats.record_failure();
            }
        }
    }

    /// Update server state based on consecutive failures/successes
    fn update_server_state(
        server: &Arc<HomeServer>,
        failures_before_down: u8,
        successes_before_up: u8,
    ) {
        let stats = server.health_stats();
        let consecutive_failures = stats.consecutive_failures();
        let consecutive_successes = stats.consecutive_successes();
        let current_state = server.state();

        match current_state {
            HomeServerState::Up => {
                // Mark down if too many consecutive failures
                if consecutive_failures >= failures_before_down as u64 {
                    warn!(
                        server = %server.name,
                        consecutive_failures = consecutive_failures,
                        "Marking server as DOWN due to health check failures"
                    );
                    server.mark_down();
                }
            }
            HomeServerState::Down => {
                // Mark up if enough consecutive successes
                if consecutive_successes >= successes_before_up as u64 {
                    info!(
                        server = %server.name,
                        consecutive_successes = consecutive_successes,
                        "Marking server as UP - health checks successful"
                    );
                    server.mark_up();
                }
            }
            HomeServerState::Dead => {
                // Dead servers can recover too
                if consecutive_successes >= successes_before_up as u64 {
                    info!(
                        server = %server.name,
                        consecutive_successes = consecutive_successes,
                        "Server recovered from DEAD state"
                    );
                    server.mark_up();
                }
            }
        }
    }
}

impl Drop for HealthChecker {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::home_server::HomeServerConfig;

    fn create_test_config() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            interval: 1, // 1 second for faster tests
            timeout: 1,
            failures_before_down: 2,
            successes_before_up: 2,
        }
    }

    #[test]
    fn test_health_check_config_defaults() {
        let config = HealthCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval, 30);
        assert_eq!(config.timeout, 10);
        assert_eq!(config.failures_before_down, 3);
        assert_eq!(config.successes_before_up, 2);
    }

    #[test]
    fn test_health_check_stats() {
        let stats = HealthCheckStats::new();

        assert_eq!(stats.total_checks(), 0);
        assert_eq!(stats.total_successes(), 0);
        assert_eq!(stats.total_failures(), 0);
        assert_eq!(stats.consecutive_failures(), 0);
        assert_eq!(stats.consecutive_successes(), 0);

        // Record success
        stats.record_success();
        assert_eq!(stats.total_checks(), 1);
        assert_eq!(stats.total_successes(), 1);
        assert_eq!(stats.consecutive_successes(), 1);
        assert_eq!(stats.consecutive_failures(), 0);

        // Record another success
        stats.record_success();
        assert_eq!(stats.total_checks(), 2);
        assert_eq!(stats.total_successes(), 2);
        assert_eq!(stats.consecutive_successes(), 2);

        // Record failure - resets consecutive successes
        stats.record_failure();
        assert_eq!(stats.total_checks(), 3);
        assert_eq!(stats.total_failures(), 1);
        assert_eq!(stats.consecutive_failures(), 1);
        assert_eq!(stats.consecutive_successes(), 0);
    }

    #[tokio::test]
    async fn test_health_checker_creation() {
        let config = create_test_config();
        let checker = HealthChecker::new(config, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(checker.config.interval, 1);
        assert_eq!(checker.config.timeout, 1);
        assert!(!checker.running.load(Ordering::Relaxed));
    }

    #[test]
    fn test_update_server_state_mark_down() {
        let config = HomeServerConfig {
            address: "127.0.0.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: Some("test_server".to_string()),
        };

        let server = Arc::new(HomeServer::new(config).unwrap());
        let stats = server.health_stats();

        // Server starts as Up
        assert_eq!(server.state(), HomeServerState::Up);

        // Record failures
        stats.record_failure();
        stats.record_failure();

        // Update state - should mark down
        HealthChecker::update_server_state(&server, 2, 2);
        assert_eq!(server.state(), HomeServerState::Down);
    }

    #[test]
    fn test_update_server_state_recover() {
        let config = HomeServerConfig {
            address: "127.0.0.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: Some("test_server".to_string()),
        };

        let server = Arc::new(HomeServer::new(config).unwrap());
        let stats = server.health_stats();

        // Mark server down
        server.mark_down();
        assert_eq!(server.state(), HomeServerState::Down);

        // Record successes
        stats.record_success();
        stats.record_success();

        // Update state - should mark up
        HealthChecker::update_server_state(&server, 2, 2);
        assert_eq!(server.state(), HomeServerState::Up);
    }

    #[tokio::test]
    async fn test_health_checker_start_stop() {
        let config = create_test_config();
        let checker = HealthChecker::new(config, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Create a test server
        let server_config = HomeServerConfig {
            address: "127.0.0.1:1812".to_string(),
            secret: "test_secret".to_string(),
            timeout: 30,
            max_outstanding: 100,
            name: Some("test_server".to_string()),
        };
        let server = Arc::new(HomeServer::new(server_config).unwrap());

        // Start health checking
        let handle = checker.start(vec![server]);
        assert!(checker.running.load(Ordering::Relaxed));

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop it
        checker.stop();
        assert!(!checker.running.load(Ordering::Relaxed));

        // Wait for task to finish
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}
