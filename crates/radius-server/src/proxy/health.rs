//! Health checking for home servers
//!
//! This module implements health checks using Status-Server requests (RFC 5997).
//! Health checks run in the background and automatically mark servers as up/down
//! based on their responsiveness.
//!
//! Each probe is a conformant RFC 5997 client: random Request Authenticator
//! (§3), a Message-Authenticator under the home server's secret (§4.1), and the
//! reply's Response Authenticator verified before the probe counts (§4.4).
//! Either Access-Accept or Accounting-Response marks the server alive (§4.2).

use crate::proxy::home_server::{HomeServer, HomeServerState};
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::auth::{generate_request_authenticator, verify_response_authenticator};
use radius_proto::{Code, Packet, calculate_message_authenticator};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
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
    /// `ip:0` template each probe binds its own ephemeral socket from. One
    /// socket per probe keeps concurrent probes from reading each other's
    /// replies (and failing both).
    probe_bind_addr: SocketAddr,
    /// Running flag for background task
    running: Arc<AtomicBool>,
}

impl HealthChecker {
    /// Create a new health checker. `bind_addr` is the local address (normally
    /// `0.0.0.0:0` or `[::]:0`) probes bind their per-probe sockets to.
    pub fn new(config: HealthCheckConfig, bind_addr: SocketAddr) -> Self {
        HealthChecker {
            config,
            probe_bind_addr: bind_addr,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start background health checking task
    ///
    /// This task periodically sends Status-Server requests to all servers
    /// and updates their health state based on responses.
    pub fn start(&self, servers: Vec<Arc<HomeServer>>) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let probe_bind_addr = self.probe_bind_addr;
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
                    let timeout = Duration::from_secs(config.timeout);
                    let task = tokio::spawn(async move {
                        Self::check_server_health(server, probe_bind_addr, timeout).await
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

    /// Check health of a single server using Status-Server request (RFC 5997).
    ///
    /// The probe binds its own ephemeral socket at `probe_bind_addr`, sends a
    /// Status-Server with a random Request Authenticator and Identifier and a
    /// Message-Authenticator under the server's secret, and counts the probe as
    /// a success only when a datagram from the server's address carries the
    /// same Identifier, Code 2 or 5, and a Response Authenticator that verifies
    /// under that secret. Anything else — including a reply from the right
    /// address that fails verification — is a failed probe, the same as a
    /// timeout; a stray or forged datagram can never make a server look up.
    async fn check_server_health(
        server: Arc<HomeServer>,
        probe_bind_addr: SocketAddr,
        timeout: Duration,
    ) {
        // Get or create health stats for this server
        let stats = server.health_stats();

        let socket = match UdpSocket::bind(probe_bind_addr).await {
            Ok(socket) => socket,
            Err(e) => {
                warn!(
                    server = %server.name,
                    error = %e,
                    "Failed to bind a socket for the Status-Server probe"
                );
                stats.record_failure();
                return;
            }
        };

        // RFC 5997 §3: random Request Authenticator; the Identifier is random
        // too so a stale reply from an earlier probe cannot match.
        let request_auth = generate_request_authenticator();
        let identifier: u8 = rand::rng().random();
        let mut request = Packet::new(Code::StatusServer, identifier, request_auth);

        // RFC 5997 §4.1: the request MUST carry a Message-Authenticator,
        // HMAC-MD5 under the home server's secret over the packet with the
        // attribute value zeroed (RFC 2869 §5.14).
        let zeroed_ma =
            match Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]) {
                Ok(attr) => attr,
                Err(e) => {
                    warn!(
                        server = %server.name,
                        error = %e,
                        "Failed to build the Status-Server Message-Authenticator"
                    );
                    stats.record_failure();
                    return;
                }
            };
        request.add_attribute(zeroed_ma);
        let request_data = match request.encode() {
            Ok(bytes) => {
                let mac = calculate_message_authenticator(&bytes, server.secret());
                if let Some(ma) = request
                    .attributes
                    .iter_mut()
                    .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
                {
                    ma.value = mac.to_vec();
                }
                request.encode()
            }
            Err(e) => Err(e),
        };
        let request_data = match request_data {
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
        if let Err(e) = socket.send_to(&request_data, server.address).await {
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
                let response = match Packet::decode(&buf[..len]) {
                    Ok(response) => response,
                    Err(e) => {
                        warn!(
                            server = %server.name,
                            error = %e,
                            "Failed to decode Status-Server response"
                        );
                        stats.record_failure();
                        return;
                    }
                };

                if response.identifier != identifier {
                    warn!(
                        server = %server.name,
                        expected = identifier,
                        actual = response.identifier,
                        "Status-Server response with the wrong Identifier"
                    );
                    stats.record_failure();
                    return;
                }

                // RFC 5997 §4.2: Access-Accept from an authentication port,
                // Accounting-Response from an accounting port.
                if !matches!(response.code, Code::AccessAccept | Code::AccountingResponse) {
                    warn!(
                        server = %server.name,
                        code = ?response.code,
                        "Unexpected Status-Server response code"
                    );
                    stats.record_failure();
                    return;
                }

                // RFC 5997 §4.4 / RFC 2865 §3: a reply whose Response
                // Authenticator does not verify under the secret is discarded.
                if !verify_response_authenticator(&response, &request_auth, server.secret()) {
                    warn!(
                        server = %server.name,
                        code = ?response.code,
                        "Status-Server response failed the Response Authenticator check"
                    );
                    stats.record_failure();
                    return;
                }

                debug!(
                    server = %server.name,
                    code = ?response.code,
                    "Status-Server check successful"
                );
                stats.record_success();
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
        let checker = HealthChecker::new(config, "127.0.0.1:0".parse().unwrap());

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
        let checker = HealthChecker::new(config, "127.0.0.1:0".parse().unwrap());

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

    // --- The probe as an RFC 5997 client, against a verifying fake home server ---

    use radius_proto::auth::calculate_response_authenticator;
    use radius_proto::verify_message_authenticator;

    const HOME_SECRET: &[u8] = b"home-secret";

    fn home_server_at(addr: SocketAddr, secret: &[u8]) -> Arc<HomeServer> {
        Arc::new(
            HomeServer::new(HomeServerConfig {
                address: addr.to_string(),
                secret: String::from_utf8(secret.to_vec()).unwrap(),
                timeout: 5,
                max_outstanding: 10,
                name: Some(format!("home-{}", addr.port())),
            })
            .unwrap(),
        )
    }

    /// What a conformant home server does with a probe: decode, require a
    /// non-zero Request Authenticator and a valid Message-Authenticator under
    /// `secret` (RFC 5997 §4.1), and hand back the decoded request. Returns
    /// `None` (no reply) when the probe fails those checks.
    fn verify_probe(bytes: &[u8], secret: &[u8]) -> Option<Packet> {
        let request = Packet::decode(bytes).ok()?;
        if request.code != Code::StatusServer || request.authenticator == [0u8; 16] {
            return None;
        }
        let mut offset = 20;
        let mut ma_offset = None;
        for attr in &request.attributes {
            if attr.attr_type == AttributeType::MessageAuthenticator as u8 {
                ma_offset = Some(offset + 2);
                break;
            }
            offset += 2 + attr.value.len();
        }
        if !verify_message_authenticator(bytes, secret, ma_offset?) {
            return None;
        }
        Some(request)
    }

    /// A signed reply to `request`: Response Authenticator under `secret`
    /// (RFC 2865 §3) and a Message-Authenticator (RFC 5997 §4.1).
    fn signed_reply(request: &Packet, code: Code, identifier: u8, secret: &[u8]) -> Vec<u8> {
        let mut reply = Packet::new(code, identifier, request.authenticator);
        reply.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        let mac = calculate_message_authenticator(&reply.encode().unwrap(), secret);
        reply
            .attributes
            .iter_mut()
            .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
            .unwrap()
            .value = mac.to_vec();
        reply.authenticator =
            calculate_response_authenticator(&reply, &request.authenticator, secret);
        reply.encode().unwrap()
    }

    /// Fake home server: answers one probe with `respond(request)` (or nothing
    /// when `respond` returns `None`), after `delay`.
    fn spawn_fake_home(
        delay: Duration,
        respond: impl FnOnce(&Packet) -> Option<Vec<u8>> + Send + 'static,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let sock = UdpSocket::from_std(sock).unwrap();
            let mut buf = vec![0u8; 4096];
            let (len, from) = sock.recv_from(&mut buf).await.unwrap();
            let Some(request) = verify_probe(&buf[..len], HOME_SECRET) else {
                return; // RFC 5997 §4.1: silent discard
            };
            if let Some(reply) = respond(&request) {
                tokio::time::sleep(delay).await;
                sock.send_to(&reply, from).await.unwrap();
            }
        });
        (addr, handle)
    }

    const PROBE_BIND: &str = "127.0.0.1:0";
    const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

    async fn probe(server: &Arc<HomeServer>) {
        HealthChecker::check_server_health(
            Arc::clone(server),
            PROBE_BIND.parse().unwrap(),
            PROBE_TIMEOUT,
        )
        .await;
    }

    #[tokio::test]
    async fn probe_is_accepted_by_a_verifying_home_server() {
        let (addr, home) = spawn_fake_home(Duration::ZERO, |req| {
            Some(signed_reply(
                req,
                Code::AccessAccept,
                req.identifier,
                HOME_SECRET,
            ))
        });
        let server = home_server_at(addr, HOME_SECRET);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_successes(), 1);
        assert_eq!(server.health_stats().consecutive_failures(), 0);
    }

    #[tokio::test]
    async fn probe_accepts_accounting_response() {
        let (addr, home) = spawn_fake_home(Duration::ZERO, |req| {
            Some(signed_reply(
                req,
                Code::AccountingResponse,
                req.identifier,
                HOME_SECRET,
            ))
        });
        let server = home_server_at(addr, HOME_SECRET);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(
            server.health_stats().consecutive_successes(),
            1,
            "RFC 5997 §4.2: Accounting-Response from an accounting port is alive"
        );
    }

    #[tokio::test]
    async fn probe_rejects_bad_response_authenticator() {
        let (addr, home) = spawn_fake_home(Duration::ZERO, |req| {
            Some(signed_reply(
                req,
                Code::AccessAccept,
                req.identifier,
                b"not-the-home-secret",
            ))
        });
        let server = home_server_at(addr, HOME_SECRET);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().consecutive_successes(), 0);
    }

    #[tokio::test]
    async fn probe_rejects_wrong_identifier_and_wrong_source() {
        // Wrong Identifier, otherwise perfectly signed.
        let (addr, home) = spawn_fake_home(Duration::ZERO, |req| {
            Some(signed_reply(
                req,
                Code::AccessAccept,
                req.identifier.wrapping_add(1),
                HOME_SECRET,
            ))
        });
        let server = home_server_at(addr, HOME_SECRET);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);

        // Right reply, wrong source socket.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let addr = sock.local_addr().unwrap();
        let home = tokio::spawn(async move {
            let sock = UdpSocket::from_std(sock).unwrap();
            let mut buf = vec![0u8; 4096];
            let (len, from) = sock.recv_from(&mut buf).await.unwrap();
            let request = verify_probe(&buf[..len], HOME_SECRET).expect("probe is conformant");
            let reply = signed_reply(
                &request,
                Code::AccessAccept,
                request.identifier,
                HOME_SECRET,
            );
            let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            other.send_to(&reply, from).await.unwrap();
        });
        let server = home_server_at(addr, HOME_SECRET);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().consecutive_successes(), 0);
    }

    /// Two probes in flight at once each get their own reply. On the old
    /// shared socket the fast server's reply reached whichever task was
    /// waiting, and both probes failed.
    #[tokio::test]
    async fn concurrent_probes_do_not_cross() {
        let (addr_a, home_a) = spawn_fake_home(Duration::from_millis(100), |req| {
            Some(signed_reply(
                req,
                Code::AccessAccept,
                req.identifier,
                HOME_SECRET,
            ))
        });
        let (addr_b, home_b) = spawn_fake_home(Duration::ZERO, |req| {
            Some(signed_reply(
                req,
                Code::AccessAccept,
                req.identifier,
                HOME_SECRET,
            ))
        });
        let server_a = home_server_at(addr_a, HOME_SECRET);
        let server_b = home_server_at(addr_b, HOME_SECRET);
        tokio::join!(probe(&server_a), probe(&server_b));
        home_a.await.unwrap();
        home_b.await.unwrap();
        assert_eq!(server_a.health_stats().consecutive_successes(), 1);
        assert_eq!(server_b.health_stats().consecutive_successes(), 1);
    }

    #[tokio::test]
    async fn probe_times_out_without_reply() {
        // A bound socket nobody reads from: the probe gets no datagram back.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = home_server_at(silent.local_addr().unwrap(), HOME_SECRET);
        HealthChecker::check_server_health(
            Arc::clone(&server),
            PROBE_BIND.parse().unwrap(),
            Duration::from_millis(300),
        )
        .await;
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().total_checks(), 1);
    }
}
