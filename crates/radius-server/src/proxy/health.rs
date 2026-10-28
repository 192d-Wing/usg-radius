//! Health checking for home servers
//!
//! This module implements health checks using Status-Server requests (RFC 5997).
//! Health checks run in the background and automatically mark servers as up/down
//! based on their responsiveness.
//!
//! Each probe is a conformant RFC 5997 client: random Request Authenticator
//! (§3), a Message-Authenticator under the home server's secret (§4.1), and the
//! reply's Response Authenticator (§4.4) and — when present — its
//! Message-Authenticator (RFC 2869 §5.14 / RFC 3579 §3.2) verified before the
//! probe counts. Access-Accept or Accounting-Response (§4.2), or an
//! authenticated Access-Reject (which §4.2 permits as the reply), marks the
//! server alive; Access-Challenge is NOT RECOMMENDED there and is not accepted.
//! A datagram that fails any check is discarded and the probe keeps waiting
//! until its deadline, so a stray datagram cannot fail a healthy server.

use crate::proxy::home_server::{HomeServer, HomeServerState};
use crate::server::{MessageAuthenticatorCheck, check_message_authenticator};
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
    /// same Identifier, Code 2, 3 or 5, a Response Authenticator that verifies
    /// under that secret and, if present, a Message-Authenticator that does
    /// too. Anything else — including a reply from the right address that
    /// fails verification — is discarded and the probe keeps waiting; only the
    /// deadline (or a socket error) fails it. A stray or forged datagram can
    /// therefore neither make a server look up nor make a healthy one look down.
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

        // Wait for a verified reply until the deadline. RFC 5997 §4.4 /
        // RFC 2865 §3: a datagram that fails any check is silently discarded
        // and the client keeps waiting, so one stray or forged datagram cannot
        // fail an otherwise healthy probe; only the deadline does. A socket
        // error still ends the probe (bounded work, no busy loop).
        let mut buf = vec![0u8; 4096];
        let wait = time::timeout(timeout, async {
            loop {
                let (len, addr) = socket.recv_from(&mut buf).await?;
                if let Some(code) =
                    Self::verify_probe_reply(&server, &buf[..len], addr, identifier, &request_auth)
                {
                    return Ok::<Code, std::io::Error>(code);
                }
            }
        })
        .await;

        match wait {
            Ok(Ok(code)) => {
                debug!(
                    server = %server.name,
                    code = ?code,
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

    /// Every check a probe reply must pass before `server` counts as alive.
    /// Returns the reply code on success; on any failure logs at `debug!`
    /// (naming the check — never the secret or the MAC bytes) and returns
    /// `None` so the caller keeps waiting for the real reply.
    fn verify_probe_reply(
        server: &HomeServer,
        bytes: &[u8],
        from: SocketAddr,
        identifier: u8,
        request_auth: &[u8; 16],
    ) -> Option<Code> {
        // Source check. On a dual-stack probe socket an IPv4 home server's
        // reply arrives from a v4-mapped address (RFC 4291 §2.5.5.2), so both
        // sides are compared in canonical form.
        if !same_peer(from, server.address) {
            debug!(
                server = %server.name,
                expected = %server.address,
                actual = %from,
                "Ignoring Status-Server reply from an unexpected address"
            );
            return None;
        }

        let response = match Packet::decode(bytes) {
            Ok(response) => response,
            Err(e) => {
                debug!(
                    server = %server.name,
                    error = %e,
                    "Ignoring undecodable datagram on the probe socket"
                );
                return None;
            }
        };

        if response.identifier != identifier {
            debug!(
                server = %server.name,
                expected = identifier,
                actual = response.identifier,
                "Ignoring Status-Server reply with the wrong Identifier"
            );
            return None;
        }

        // RFC 5997 §4.2: Access-Accept from an authentication port,
        // Accounting-Response from an accounting port; an Access-Reject "MAY be
        // used" and, once authenticated, still proves the server is up.
        // Access-Challenge is NOT RECOMMENDED there and is not accepted.
        if !matches!(
            response.code,
            Code::AccessAccept | Code::AccessReject | Code::AccountingResponse
        ) {
            debug!(
                server = %server.name,
                code = ?response.code,
                "Ignoring Status-Server reply with an unexpected code"
            );
            return None;
        }

        // RFC 5997 §4.4 / RFC 2865 §3: a reply whose Response Authenticator
        // does not verify under the secret is discarded.
        if !verify_response_authenticator(&response, request_auth, server.secret()) {
            debug!(
                server = %server.name,
                code = ?response.code,
                "Ignoring Status-Server reply that failed the Response Authenticator check"
            );
            return None;
        }

        // RFC 2869 §5.14 / RFC 3579 §3.2: a client receiving a reply that
        // carries a Message-Authenticator MUST verify it (HMAC-MD5 with the
        // Request Authenticator in the header) and silently discard the packet
        // on mismatch. A reply without one is accepted: RFC 5997 §5 lists the
        // attribute as 0-1 on Access-Accept / Accounting-Response.
        match check_message_authenticator(&response, request_auth, server.secret()) {
            Ok(MessageAuthenticatorCheck::Valid) | Ok(MessageAuthenticatorCheck::Absent) => {
                Some(response.code)
            }
            Ok(MessageAuthenticatorCheck::Invalid) => {
                debug!(
                    server = %server.name,
                    code = ?response.code,
                    "Ignoring Status-Server reply that failed the Message-Authenticator check"
                );
                None
            }
            Err(e) => {
                debug!(
                    server = %server.name,
                    error = %e,
                    "Ignoring Status-Server reply that could not be re-encoded"
                );
                None
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

/// Whether a reply from `actual` came from `expected`. An IPv4-mapped IPv6
/// source (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2) — what a `[::]` probe socket
/// sees from an IPv4 home server — is compared as its IPv4 address.
fn same_peer(actual: SocketAddr, expected: SocketAddr) -> bool {
    actual.port() == expected.port() && actual.ip().to_canonical() == expected.ip().to_canonical()
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

    /// A fresh shared secret per test, built at runtime (never a literal, so
    /// CodeQL does not read it as a hard-coded key) and hex-encoded so it is
    /// also a valid `HomeServerConfig.secret`. The `HomeServer` under test and
    /// the fake home server both key with `secret.as_bytes()` of one value.
    fn home_secret() -> String {
        use rand::RngExt;
        hex::encode(rand::rng().random::<[u8; 16]>())
    }

    fn home_server_at(addr: SocketAddr, secret: &str) -> Arc<HomeServer> {
        Arc::new(
            HomeServer::new(HomeServerConfig {
                address: addr.to_string(),
                secret: secret.to_string(),
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

    /// Fake home server keyed with `secret`: answers one probe with
    /// `respond(request, secret_bytes)` (or nothing when `respond` returns
    /// `None`), after `delay`.
    fn spawn_fake_home(
        secret: &str,
        delay: Duration,
        respond: impl FnOnce(&Packet, &[u8]) -> Option<Vec<u8>> + Send + 'static,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let addr = sock.local_addr().unwrap();
        let secret = secret.to_string();
        let handle = tokio::spawn(async move {
            let sock = UdpSocket::from_std(sock).unwrap();
            let mut buf = vec![0u8; 4096];
            let (len, from) = sock.recv_from(&mut buf).await.unwrap();
            let Some(request) = verify_probe(&buf[..len], secret.as_bytes()) else {
                return; // RFC 5997 §4.1: silent discard
            };
            if let Some(reply) = respond(&request, secret.as_bytes()) {
                tokio::time::sleep(delay).await;
                sock.send_to(&reply, from).await.unwrap();
            }
        });
        (addr, handle)
    }

    /// A reply whose Response Authenticator verifies but whose
    /// Message-Authenticator does not (the MA is garbage, the RA is computed
    /// over it): what a peer with a broken MA computation would send.
    fn reply_with_bad_message_authenticator(
        request: &Packet,
        code: Code,
        identifier: u8,
        secret: &[u8],
    ) -> Vec<u8> {
        let mut reply = Packet::new(code, identifier, request.authenticator);
        let mut wrong = calculate_message_authenticator(&reply.encode().unwrap(), secret);
        wrong[0] ^= 0x01;
        reply.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, wrong.to_vec()).unwrap(),
        );
        reply.authenticator =
            calculate_response_authenticator(&reply, &request.authenticator, secret);
        reply.encode().unwrap()
    }

    const PROBE_BIND: &str = "127.0.0.1:0";
    const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
    /// For probes expected to fail: the probe now waits out its whole deadline
    /// after discarding a bad datagram, so keep that short.
    const NEGATIVE_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

    async fn probe_with(server: &Arc<HomeServer>, timeout: Duration) {
        HealthChecker::check_server_health(
            Arc::clone(server),
            PROBE_BIND.parse().unwrap(),
            timeout,
        )
        .await;
    }

    async fn probe(server: &Arc<HomeServer>) {
        probe_with(server, PROBE_TIMEOUT).await;
    }

    async fn probe_expecting_failure(server: &Arc<HomeServer>) {
        probe_with(server, NEGATIVE_PROBE_TIMEOUT).await;
    }

    #[tokio::test]
    async fn probe_is_accepted_by_a_verifying_home_server() {
        let secret = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, |req, key| {
            Some(signed_reply(req, Code::AccessAccept, req.identifier, key))
        });
        let server = home_server_at(addr, &secret);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_successes(), 1);
        assert_eq!(server.health_stats().consecutive_failures(), 0);
    }

    #[tokio::test]
    async fn probe_accepts_accounting_response() {
        let secret = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, |req, key| {
            Some(signed_reply(
                req,
                Code::AccountingResponse,
                req.identifier,
                key,
            ))
        });
        let server = home_server_at(addr, &secret);
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
        let secret = home_secret();
        let other = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, move |req, _| {
            Some(signed_reply(
                req,
                Code::AccessAccept,
                req.identifier,
                other.as_bytes(),
            ))
        });
        let server = home_server_at(addr, &secret);
        probe_expecting_failure(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().consecutive_successes(), 0);
    }

    #[tokio::test]
    async fn probe_rejects_wrong_identifier_and_wrong_source() {
        // Wrong Identifier, otherwise perfectly signed.
        let secret = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, |req, key| {
            Some(signed_reply(
                req,
                Code::AccessAccept,
                req.identifier.wrapping_add(1),
                key,
            ))
        });
        let server = home_server_at(addr, &secret);
        probe_expecting_failure(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);

        // Right reply, wrong source socket.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let addr = sock.local_addr().unwrap();
        let key = secret.clone();
        let home = tokio::spawn(async move {
            let sock = UdpSocket::from_std(sock).unwrap();
            let mut buf = vec![0u8; 4096];
            let (len, from) = sock.recv_from(&mut buf).await.unwrap();
            let request = verify_probe(&buf[..len], key.as_bytes()).expect("probe is conformant");
            let reply = signed_reply(
                &request,
                Code::AccessAccept,
                request.identifier,
                key.as_bytes(),
            );
            let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            other.send_to(&reply, from).await.unwrap();
        });
        let server = home_server_at(addr, &secret);
        probe_expecting_failure(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().consecutive_successes(), 0);
    }

    /// Two probes in flight at once each get their own reply. On the old
    /// shared socket the fast server's reply reached whichever task was
    /// waiting, and both probes failed.
    #[tokio::test]
    async fn concurrent_probes_do_not_cross() {
        let secret = home_secret();
        let (addr_a, home_a) = spawn_fake_home(&secret, Duration::from_millis(100), |req, key| {
            Some(signed_reply(req, Code::AccessAccept, req.identifier, key))
        });
        let (addr_b, home_b) = spawn_fake_home(&secret, Duration::ZERO, |req, key| {
            Some(signed_reply(req, Code::AccessAccept, req.identifier, key))
        });
        let server_a = home_server_at(addr_a, &secret);
        let server_b = home_server_at(addr_b, &secret);
        tokio::join!(probe(&server_a), probe(&server_b));
        home_a.await.unwrap();
        home_b.await.unwrap();
        assert_eq!(server_a.health_stats().consecutive_successes(), 1);
        assert_eq!(server_b.health_stats().consecutive_successes(), 1);
    }

    #[tokio::test]
    async fn probe_times_out_without_reply() {
        // A bound socket nobody reads from: the probe gets no datagram back.
        let secret = home_secret();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = home_server_at(silent.local_addr().unwrap(), &secret);
        HealthChecker::check_server_health(
            Arc::clone(&server),
            PROBE_BIND.parse().unwrap(),
            Duration::from_millis(300),
        )
        .await;
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().total_checks(), 1);
    }

    #[tokio::test]
    async fn probe_accepts_authenticated_access_reject() {
        // RFC 5997 §4.2: "An Access-Reject response MAY be used." A server
        // that answers with an authenticated Access-Reject is alive.
        let secret = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, |req, key| {
            Some(signed_reply(req, Code::AccessReject, req.identifier, key))
        });
        let server = home_server_at(addr, &secret);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_successes(), 1);
        assert_eq!(server.health_stats().consecutive_failures(), 0);
    }

    #[tokio::test]
    async fn probe_rejects_access_reject_with_bad_response_authenticator() {
        // Access-Reject counts only once authenticated: the same reply signed
        // under the wrong secret is a failed probe.
        let secret = home_secret();
        let other = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, move |req, _| {
            Some(signed_reply(
                req,
                Code::AccessReject,
                req.identifier,
                other.as_bytes(),
            ))
        });
        let server = home_server_at(addr, &secret);
        probe_expecting_failure(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().consecutive_successes(), 0);
    }

    #[tokio::test]
    async fn probe_rejects_access_challenge() {
        // RFC 5997 §4.2: Access-Challenge is NOT RECOMMENDED as the reply and
        // is not accepted, however well it is signed.
        let secret = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, |req, key| {
            Some(signed_reply(
                req,
                Code::AccessChallenge,
                req.identifier,
                key,
            ))
        });
        let server = home_server_at(addr, &secret);
        probe_expecting_failure(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().consecutive_successes(), 0);
    }

    #[tokio::test]
    async fn probe_rejects_bad_message_authenticator() {
        // RFC 2869 §5.14 / RFC 3579 §3.2: a reply whose Response Authenticator
        // verifies but whose Message-Authenticator does not is discarded, so a
        // peer with a broken MA computation is not marked alive.
        let secret = home_secret();
        for code in [Code::AccessAccept, Code::AccountingResponse] {
            let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, move |req, key| {
                Some(reply_with_bad_message_authenticator(
                    req,
                    code,
                    req.identifier,
                    key,
                ))
            });
            let server = home_server_at(addr, &secret);
            probe_expecting_failure(&server).await;
            home.await.unwrap();
            assert_eq!(server.health_stats().consecutive_failures(), 1, "{code:?}");
            assert_eq!(server.health_stats().consecutive_successes(), 0, "{code:?}");
        }
    }

    #[tokio::test]
    async fn probe_accepts_reply_without_message_authenticator() {
        // RFC 5997 §5 lists Message-Authenticator as 0-1 on the reply: a home
        // server that signs only the Response Authenticator is still alive.
        let secret = home_secret();
        let (addr, home) = spawn_fake_home(&secret, Duration::ZERO, |req, key| {
            let mut reply = Packet::new(Code::AccessAccept, req.identifier, req.authenticator);
            reply.authenticator = calculate_response_authenticator(&reply, &req.authenticator, key);
            Some(reply.encode().unwrap())
        });
        let server = home_server_at(addr, &secret);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_successes(), 1);
    }

    #[tokio::test]
    async fn probe_rejects_undecodable_reply() {
        // A datagram from the right address that is not a RADIUS packet at
        // all (below the 20-octet minimum) is ignored; with nothing else
        // arriving the probe fails on its deadline, not with a crash and not
        // with a success.
        let secret = home_secret();
        let (addr, home) =
            spawn_fake_home(&secret, Duration::ZERO, |_, _| Some(vec![0x02, 0x00, 0x00]));
        let server = home_server_at(addr, &secret);
        probe_expecting_failure(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_failures(), 1);
        assert_eq!(server.health_stats().consecutive_successes(), 0);
    }

    #[tokio::test]
    async fn stray_datagrams_do_not_fail_a_probe_the_real_reply_answers() {
        // RFC 5997 §4.4 / RFC 2865 §3: the client discards what does not
        // verify and keeps waiting. Three bad datagrams from the home server's
        // own address — garbage, a wrong Identifier, a wrong secret — arrive
        // before the genuine reply; the probe still succeeds.
        let secret = home_secret();
        let other = home_secret();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let addr = sock.local_addr().unwrap();
        let key = secret.clone();
        let home = tokio::spawn(async move {
            let sock = UdpSocket::from_std(sock).unwrap();
            let mut buf = vec![0u8; 4096];
            let (len, from) = sock.recv_from(&mut buf).await.unwrap();
            let request = verify_probe(&buf[..len], key.as_bytes()).expect("probe is conformant");
            let id = request.identifier;
            sock.send_to(&[0x02, 0x00, 0x00], from).await.unwrap();
            sock.send_to(
                &signed_reply(
                    &request,
                    Code::AccessAccept,
                    id.wrapping_add(1),
                    key.as_bytes(),
                ),
                from,
            )
            .await
            .unwrap();
            sock.send_to(
                &signed_reply(&request, Code::AccessAccept, id, other.as_bytes()),
                from,
            )
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            sock.send_to(
                &signed_reply(&request, Code::AccessAccept, id, key.as_bytes()),
                from,
            )
            .await
            .unwrap();
        });
        let server = home_server_at(addr, &secret);
        probe(&server).await;
        home.await.unwrap();
        assert_eq!(server.health_stats().consecutive_successes(), 1);
        assert_eq!(server.health_stats().consecutive_failures(), 0);
    }

    #[test]
    fn same_peer_canonicalises_v4_mapped_sources() {
        // RFC 4291 §2.5.5.2: what a `[::]` probe socket reports for an IPv4
        // home server's reply must match the configured IPv4 address.
        let home: SocketAddr = "10.77.0.10:1812".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:10.77.0.10]:1812".parse().unwrap();
        assert!(same_peer(home, home));
        assert!(same_peer(mapped, home));
        assert!(same_peer(home, mapped));
        assert!(!same_peer(
            "[::ffff:10.77.0.11]:1812".parse().unwrap(),
            home
        ));
        assert!(!same_peer("10.77.0.10:1813".parse().unwrap(), home));
        assert!(!same_peer("[::1]:1812".parse().unwrap(), home));
    }
}
