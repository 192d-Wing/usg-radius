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
//!
//! A `transport = "radsec"` home server is probed over its RadSec link with
//! the same packet and the same reply checks; the TLS peer authentication
//! stands in for the source-address check. There the probe is also the
//! **application-layer watchdog** RFC 6613 §2.4/§2.6 require for RADIUS over
//! TCP (RFC 3539 §3.4 algorithm, Status-Server as the watchdog message, RFC
//! 5997 §4.3): the probe's Identifier is one the connection has free when it
//! is sent, a reply that fails the Response Authenticator or
//! Message-Authenticator check closes the connection (RFC 6613 §2.6.4), and
//! two consecutive unanswered probes on the same connection close it too (RFC
//! 3539 §3.4: not before that connection's watchdog timer has expired twice),
//! after which the link reconnects with backoff. Config validation therefore
//! refuses a RadSec home server with `health_check.enabled = false`.

use crate::proxy::error::ProxyResult;
use crate::proxy::home_server::{HomeServer, HomeServerState, HomeServerTransport};
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
    /// Enable health checking. Required (`true`) when any home server uses
    /// `transport = "radsec"`: the Status-Server probe is the RFC 6613 §2.6
    /// watchdog of the connection.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Health check interval in seconds. For a RadSec home server keep it
    /// below the home server's TLS idle timeout (FreeRADIUS `idle_timeout`,
    /// 30 s in its template): the probe is what keeps the connection warm, and
    /// an idle close costs the next request a `retry_interval` of latency.
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
    /// Watchdog misses on the RadSec link, counted per connection — RFC 3539
    /// §3.4 closes a connection only once *its own* timer has expired twice:
    /// `(connection generation of the last miss, misses in a row on it)`.
    watchdog_misses: std::sync::Mutex<(u64, u64)>,
}

impl HealthCheckStats {
    pub fn new() -> Self {
        HealthCheckStats {
            total_checks: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            watchdog_misses: std::sync::Mutex::new((0, 0)),
        }
    }

    /// Record a successful health check
    fn record_success(&self) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        self.total_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        // A verified reply restarts the watchdog: misses must be consecutive.
        self.watchdog_misses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1 = 0;
    }

    /// Record an unanswered Status-Server probe on link connection
    /// `generation` and return how many misses in a row that connection now
    /// has. A miss on a different connection from the last one starts the
    /// count again, so misses while the link was down or on a connection that
    /// has since been replaced never count against the current one (RFC 3539
    /// §3.4). The per-server `consecutive_failures` is recorded separately
    /// and keeps driving the pool's Up/Down decision.
    fn record_watchdog_miss(&self, generation: u64) -> u64 {
        let mut misses = self
            .watchdog_misses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if misses.0 != generation {
            *misses = (generation, 0);
        }
        misses.1 += 1;
        misses.1
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
    /// Over UDP the probe binds its own ephemeral socket at `probe_bind_addr`,
    /// sends a Status-Server with a random Request Authenticator and
    /// Identifier and a Message-Authenticator under the server's secret, and
    /// counts the probe as a success only when a datagram from the server's
    /// address carries the same Identifier, Code 2, 3 or 5, a Response
    /// Authenticator that verifies under that secret and, if present, a
    /// Message-Authenticator that does too. Anything else — including a reply
    /// from the right address that fails verification — is discarded and the
    /// probe keeps waiting; only the deadline (or a socket error) fails it. A
    /// stray or forged datagram can therefore neither make a server look up
    /// nor make a healthy one look down.
    ///
    /// Over RadSec the same packet goes down the server's link and the same
    /// checks apply to what comes back on it (see [`Self::probe_over_link`]).
    async fn check_server_health(
        server: Arc<HomeServer>,
        probe_bind_addr: SocketAddr,
        timeout: Duration,
    ) {
        match server.transport() {
            HomeServerTransport::Udp => {
                Self::probe_over_udp(server, probe_bind_addr, timeout).await
            }
            HomeServerTransport::Radsec => {
                #[cfg(feature = "tls")]
                match server.link() {
                    Some(link) => {
                        // The watchdog decision — two misses on the same
                        // connection close it (RFC 3539 §3.4) — is taken in
                        // there, where the probe knows which connection it
                        // went out on.
                        Self::probe_over_link(Arc::clone(&server), link, timeout).await;
                    }
                    None => {
                        warn!(
                            server = %server.name,
                            "Status-Server probe: RadSec home server has no link attached"
                        );
                        server.health_stats().record_failure();
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    // Unreachable after config validation.
                    warn!(
                        server = %server.name,
                        "Status-Server probe: RadSec home server in a binary without `tls`"
                    );
                    server.health_stats().record_failure();
                }
            }
        }
    }

    /// The UDP probe described on [`Self::check_server_health`].
    async fn probe_over_udp(
        server: Arc<HomeServer>,
        probe_bind_addr: SocketAddr,
        timeout: Duration,
    ) {
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

        let (request_data, identifier, request_auth) = match build_probe(server.secret()) {
            Ok(probe) => probe,
            Err(e) => {
                warn!(
                    server = %server.name,
                    error = %e,
                    "Failed to build Status-Server request"
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

    /// The probe over a RadSec link — the RFC 6613 §2.6 watchdog message
    /// (RFC 3539 §3.4, RFC 5997 §4.3). Its Identifier is one the connection
    /// has free when the probe is sent (RFC 6613 §2.6: one Identifier per
    /// connection is reserved for the watchdog, so the probe never goes out
    /// under an Identifier a forwarded request holds; a request forwarded
    /// *later* may still carry the probe's Identifier because NAS Identifiers
    /// are not rewritten — replies are told apart by Proxy-State presence and
    /// verified by Request Authenticator, so only the home server's duplicate
    /// detection can notice). When every Identifier is taken the probe is
    /// skipped and **not** counted: nothing was sent, so nothing was learnt
    /// about the peer. The probe registers for its Identifier **before**
    /// sending so a fast reply cannot be missed. A link that is down fails the
    /// probe at once (nothing to wait for); a link lost while waiting fails it
    /// as soon as the link task says so. A reply with the wrong Identifier or
    /// an unexpected code is discarded and the probe keeps waiting, as over
    /// UDP; a reply that fails the Response Authenticator or
    /// Message-Authenticator check fails the probe **and closes the
    /// connection** (RFC 6613 §2.6.4). An unanswered probe is a watchdog miss
    /// on the connection it went out on; the second miss in a row on the
    /// same connection closes it (RFC 3539 §3.4). There is no source-address
    /// check: the TLS peer is the authenticated home server.
    #[cfg(feature = "tls")]
    async fn probe_over_link(
        server: Arc<HomeServer>,
        link: &crate::proxy::radsec_client::RadsecLinkHandle,
        timeout: Duration,
    ) {
        let stats = server.health_stats();

        let Some(identifier) = link.free_identifier() else {
            // Not a watchdog miss and not a health-check failure: no probe was
            // sent, so this is no evidence about the peer. Counting it would
            // let a burst of unanswered forwarded requests (256 distinct
            // Identifiers within `identifier_ttl`) reset a healthy
            // connection; the TTL bounds how long the skip can last.
            warn!(
                server = %server.name,
                in_flight = link.in_flight(),
                "Status-Server probe skipped: every Identifier on the RadSec connection is in \
                 flight (RFC 6613 §2.6.5); not counted as a watchdog miss"
            );
            return;
        };
        let request_auth = generate_request_authenticator();
        let request_data = match build_probe_with(server.secret(), identifier, request_auth) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(
                    server = %server.name,
                    error = %e,
                    "Failed to build Status-Server request"
                );
                stats.record_failure();
                return;
            }
        };

        let mut replies = match link.register_probe(identifier) {
            Ok(replies) => replies,
            Err(e) => {
                warn!(
                    server = %server.name,
                    error = %e,
                    "Status-Server probe not registered on the RadSec link"
                );
                stats.record_failure();
                return;
            }
        };
        // The connection this probe goes out on: a miss is counted against it
        // and a reset for it is dropped once the link has moved on.
        let generation = link.connections();
        if let Err(e) = link.send(request_data) {
            warn!(
                server = %server.name,
                error = %e.into_proxy_error(&server.name),
                "Failed to send Status-Server request over the RadSec link"
            );
            stats.record_failure();
            return;
        }

        enum Outcome {
            Verified(Code),
            LinkLost,
            /// RFC 6613 §2.6.4: the reply failed an authenticator check.
            PeerFault(ProbeReject),
        }
        let wait = time::timeout(timeout, async {
            loop {
                let Some(reply) = replies.recv().await else {
                    return Outcome::LinkLost;
                };
                match verify_probe_packet(&server, &reply, identifier, &request_auth) {
                    Ok(code) => return Outcome::Verified(code),
                    Err(reject) if reject.closes_connection() => {
                        return Outcome::PeerFault(reject);
                    }
                    Err(_) => {} // wrong Identifier / code: not ours, keep waiting
                }
            }
        })
        .await;

        match wait {
            Ok(Outcome::Verified(code)) => {
                debug!(
                    server = %server.name,
                    code = ?code,
                    "Status-Server check successful"
                );
                stats.record_success();
            }
            Ok(Outcome::LinkLost) => {
                warn!(
                    server = %server.name,
                    "RadSec link lost while waiting for the Status-Server response"
                );
                stats.record_failure();
            }
            Ok(Outcome::PeerFault(reject)) => {
                warn!(
                    server = %server.name,
                    check = %reject,
                    "Status-Server reply failed verification; closing the RadSec connection \
                     (RFC 6613 §2.6.4)"
                );
                link.reset(
                    generation,
                    &format!("Status-Server reply failed the {reject} check (RFC 6613 §2.6.4)"),
                );
                stats.record_failure();
            }
            Err(_) => {
                let misses = stats.record_watchdog_miss(generation);
                warn!(
                    server = %server.name,
                    timeout_secs = timeout.as_secs(),
                    misses_on_connection = misses,
                    "Status-Server request timed out"
                );
                stats.record_failure();
                // RFC 3539 §3.4 (via RFC 6613 §2.6): the connection is closed
                // and re-established once *its* watchdog timer has expired
                // twice without a response — never after a single miss, and
                // never for misses on a previous connection. A reset on a
                // link that is already down is a no-op.
                if misses >= 2 {
                    link.reset(
                        generation,
                        "watchdog: two Status-Server probes unanswered (RFC 3539 §3.4)",
                    );
                }
            }
        }
    }

    /// Every check a UDP probe reply must pass before `server` counts as
    /// alive: the source address, then everything in [`verify_probe_packet`].
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

        // Over UDP every failure is a silent discard (RFC 5997 §4.4).
        verify_probe_packet(server, &response, identifier, request_auth).ok()
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

/// Build one RFC 5997 Status-Server probe keyed with `secret`: random Request
/// Authenticator (§3) and random Identifier (so a stale reply from an earlier
/// probe cannot match), and the Message-Authenticator §4.1 requires. Returns
/// the encoded packet, its Identifier and its Request Authenticator.
fn build_probe(secret: &[u8]) -> ProxyResult<(Vec<u8>, u8, [u8; 16])> {
    let request_auth = generate_request_authenticator();
    let identifier: u8 = rand::rng().random();
    let bytes = build_probe_with(secret, identifier, request_auth)?;
    Ok((bytes, identifier, request_auth))
}

/// [`build_probe`] with the Identifier and Request Authenticator given, so
/// the packet can be pinned against an independently computed vector.
///
/// RFC 5997 §4.1: the request MUST carry a Message-Authenticator, HMAC-MD5
/// under the home server's secret over the packet with the attribute value
/// zeroed (RFC 2869 §5.14). Over RadSec `secret` is the fixed `"radsec"`
/// (RFC 6614 §2.3 item 4).
fn build_probe_with(secret: &[u8], identifier: u8, request_auth: [u8; 16]) -> ProxyResult<Vec<u8>> {
    let mut request = Packet::new(Code::StatusServer, identifier, request_auth);
    request.add_attribute(Attribute::new(
        AttributeType::MessageAuthenticator as u8,
        vec![0u8; 16],
    )?);
    let mac = calculate_message_authenticator(&request.encode()?, secret);
    if let Some(ma) = request
        .attributes
        .iter_mut()
        .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
    {
        ma.value = mac.to_vec();
    }
    Ok(request.encode()?)
}

/// Which check of [`verify_probe_packet`] a reply failed. Never carries the
/// secret or MAC bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeReject {
    /// Not the Identifier of the outstanding probe (another request's reply,
    /// or a stale one).
    Identifier,
    /// A code RFC 5997 §4.2 does not allow as the reply to a Status-Server.
    Code,
    /// RFC 5997 §4.4 / RFC 2865 §3: Response Authenticator does not verify.
    ResponseAuthenticator,
    /// RFC 2869 §5.14 / RFC 3579 §3.2: Message-Authenticator does not verify.
    MessageAuthenticator,
    /// The packet could not be re-encoded for the Message-Authenticator check.
    Encode,
}

impl ProbeReject {
    /// Whether RFC 6613 §2.6.4 requires a TCP connection carrying this reply
    /// to be closed: a failed Response Authenticator or Message-Authenticator
    /// does; a reply "matching no request" (wrong Identifier or code) may be
    /// discarded with the connection kept.
    #[cfg(feature = "tls")]
    fn closes_connection(self) -> bool {
        matches!(
            self,
            Self::ResponseAuthenticator | Self::MessageAuthenticator
        )
    }
}

impl std::fmt::Display for ProbeReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Identifier => "Identifier",
            Self::Code => "Code",
            Self::ResponseAuthenticator => "Response Authenticator",
            Self::MessageAuthenticator => "Message-Authenticator",
            Self::Encode => "re-encode",
        })
    }
}

/// Every check a decoded probe reply must pass before `server` counts as
/// alive, whatever transport it arrived on: Identifier, Code, Response
/// Authenticator (RFC 5997 §4.4) and, when present, Message-Authenticator.
/// Returns the reply code on success; on any failure logs at `debug!` (naming
/// the check — never the secret or the MAC bytes) and returns which check
/// failed, so the RadSec probe can tell a stray reply (discard, RFC 6613
/// §2.6.4 "MAY") from a peer fault (close the connection, "MUST").
fn verify_probe_packet(
    server: &HomeServer,
    response: &Packet,
    identifier: u8,
    request_auth: &[u8; 16],
) -> Result<Code, ProbeReject> {
    if response.identifier != identifier {
        debug!(
            server = %server.name,
            expected = identifier,
            actual = response.identifier,
            "Ignoring Status-Server reply with the wrong Identifier"
        );
        return Err(ProbeReject::Identifier);
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
        return Err(ProbeReject::Code);
    }

    // RFC 5997 §4.4 / RFC 2865 §3: a reply whose Response Authenticator
    // does not verify under the secret is discarded.
    if !verify_response_authenticator(response, request_auth, server.secret()) {
        debug!(
            server = %server.name,
            code = ?response.code,
            "Ignoring Status-Server reply that failed the Response Authenticator check"
        );
        return Err(ProbeReject::ResponseAuthenticator);
    }

    // RFC 2869 §5.14 / RFC 3579 §3.2: a client receiving a reply that
    // carries a Message-Authenticator MUST verify it (HMAC-MD5 with the
    // Request Authenticator in the header) and silently discard the packet
    // on mismatch. A reply without one is accepted: RFC 5997 §5 lists the
    // attribute as 0-1 on Access-Accept / Accounting-Response.
    match check_message_authenticator(response, request_auth, server.secret()) {
        Ok(MessageAuthenticatorCheck::Valid) | Ok(MessageAuthenticatorCheck::Absent) => {
            Ok(response.code)
        }
        Ok(MessageAuthenticatorCheck::Invalid) => {
            debug!(
                server = %server.name,
                code = ?response.code,
                "Ignoring Status-Server reply that failed the Message-Authenticator check"
            );
            Err(ProbeReject::MessageAuthenticator)
        }
        Err(e) => {
            debug!(
                server = %server.name,
                error = %e,
                "Ignoring Status-Server reply that could not be re-encoded"
            );
            Err(ProbeReject::Encode)
        }
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
            name: Some("test_server".to_string()),
            ..HomeServerConfig::udp("127.0.0.1:1812", "test_secret")
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
            name: Some("test_server".to_string()),
            ..HomeServerConfig::udp("127.0.0.1:1812", "test_secret")
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
            name: Some("test_server".to_string()),
            ..HomeServerConfig::udp("127.0.0.1:1812", "test_secret")
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
                timeout: 5,
                max_outstanding: 10,
                name: Some(format!("home-{}", addr.port())),
                ..HomeServerConfig::udp(addr.to_string(), secret)
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

    // --- Known-answer vector: the probe as sent over a RadSec link -----------

    // Generated by tests/vectors/radsec_status_server_vector.py, an independent
    // implementation written from RFC 5997 §3/§4.1, RFC 2869 §5.14 and
    // RFC 6614 §2.3 (Python standard library only, self-checked against the
    // RFC 2202 HMAC-MD5 test case 2). Inputs: secret "radsec", Identifier
    // 0x5a, Request Authenticator a0 a1 .. af.
    const KAT_IDENTIFIER: u8 = 0x5a;
    const KAT_REQUEST_AUTHENTICATOR: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
    const KAT_MESSAGE_AUTHENTICATOR: &str = "87a91107160f1ca1f12ec3304cbe2752";
    const KAT_PACKET: &str =
        "0c5a0026a0a1a2a3a4a5a6a7a8a9aaabacadaeaf501287a91107160f1ca1f12ec3304cbe2752";

    #[test]
    fn status_server_probe_matches_the_radsec_known_answer_vector() {
        // RFC 6614 §2.3 fixed hop secret; a public constant, not a credential.
        let secret = crate::radsec_frame::RADSEC_SECRET;
        let mut request_auth = [0u8; 16];
        request_auth.copy_from_slice(&hex::decode(KAT_REQUEST_AUTHENTICATOR).unwrap());

        let packet = build_probe_with(secret, KAT_IDENTIFIER, request_auth).unwrap();
        assert_eq!(hex::encode(&packet), KAT_PACKET);
        assert_eq!(packet.len(), 38);
        assert_eq!(packet[0], Code::StatusServer as u8);
        assert_eq!(packet[1], KAT_IDENTIFIER);
        assert_eq!(&packet[4..20], &request_auth);
        assert_eq!(packet[20], AttributeType::MessageAuthenticator as u8);
        assert_eq!(packet[21], 18);
        assert_eq!(hex::encode(&packet[22..]), KAT_MESSAGE_AUTHENTICATOR);

        // And the home server's view: the MAC verifies under "radsec" only.
        assert!(verify_message_authenticator(&packet, secret, 22));
        assert!(!verify_message_authenticator(
            &packet,
            home_secret().as_bytes(),
            22
        ));
    }

    #[test]
    fn build_probe_randomises_identifier_and_request_authenticator() {
        let secret = home_secret();
        let (a, id_a, auth_a) = build_probe(secret.as_bytes()).unwrap();
        let (b, id_b, auth_b) = build_probe(secret.as_bytes()).unwrap();
        assert_ne!(auth_a, auth_b, "RFC 5997 §3: random Request Authenticator");
        assert_ne!((id_a, auth_a), (id_b, auth_b));
        assert_eq!(a[1], id_a);
        assert_eq!(b[1], id_b);
        // Both are conformant probes a home server accepts.
        assert!(verify_probe(&a, secret.as_bytes()).is_some());
        assert!(verify_probe(&b, secret.as_bytes()).is_some());
    }

    // --- verify_probe_packet: the transport-independent reply checks ---------

    fn kat_server(secret: &str) -> Arc<HomeServer> {
        home_server_at("127.0.0.1:1812".parse().unwrap(), secret)
    }

    fn probe_request(secret: &str) -> (Packet, u8, [u8; 16]) {
        let (bytes, id, auth) = build_probe(secret.as_bytes()).unwrap();
        (Packet::decode(&bytes).unwrap(), id, auth)
    }

    #[test]
    fn verify_probe_packet_accepts_each_permitted_code() {
        let secret = home_secret();
        let server = kat_server(&secret);
        let (req, id, auth) = probe_request(&secret);
        for code in [
            Code::AccessAccept,
            Code::AccessReject,
            Code::AccountingResponse,
        ] {
            let reply = Packet::decode(&signed_reply(&req, code, id, secret.as_bytes())).unwrap();
            assert_eq!(verify_probe_packet(&server, &reply, id, &auth), Ok(code));
        }
    }

    #[test]
    fn verify_probe_packet_rejects_identifier_code_authenticator_and_mac_failures() {
        let secret = home_secret();
        let other = home_secret();
        let server = kat_server(&secret);
        let (req, id, auth) = probe_request(&secret);

        // Wrong Identifier: not our reply, keep the connection (RFC 6613
        // §2.6.4 "MAY" for a response matching no request).
        let reply = Packet::decode(&signed_reply(
            &req,
            Code::AccessAccept,
            id.wrapping_add(1),
            secret.as_bytes(),
        ))
        .unwrap();
        let reject = verify_probe_packet(&server, &reply, id, &auth).unwrap_err();
        assert_eq!(reject, ProbeReject::Identifier);
        #[cfg(feature = "tls")]
        assert!(!reject.closes_connection());

        // Access-Challenge is not accepted (RFC 5997 §4.2).
        let reply = Packet::decode(&signed_reply(
            &req,
            Code::AccessChallenge,
            id,
            secret.as_bytes(),
        ))
        .unwrap();
        let reject = verify_probe_packet(&server, &reply, id, &auth).unwrap_err();
        assert_eq!(reject, ProbeReject::Code);
        #[cfg(feature = "tls")]
        assert!(!reject.closes_connection());

        // Wrong secret ⇒ Response Authenticator fails: a TCP connection
        // carrying this MUST be closed (RFC 6613 §2.6.4).
        let reply = Packet::decode(&signed_reply(
            &req,
            Code::AccessAccept,
            id,
            other.as_bytes(),
        ))
        .unwrap();
        let reject = verify_probe_packet(&server, &reply, id, &auth).unwrap_err();
        assert_eq!(reject, ProbeReject::ResponseAuthenticator);
        #[cfg(feature = "tls")]
        assert!(reject.closes_connection());

        // Good Response Authenticator, bad Message-Authenticator: likewise.
        let reply = Packet::decode(&reply_with_bad_message_authenticator(
            &req,
            Code::AccessAccept,
            id,
            secret.as_bytes(),
        ))
        .unwrap();
        let reject = verify_probe_packet(&server, &reply, id, &auth).unwrap_err();
        assert_eq!(reject, ProbeReject::MessageAuthenticator);
        #[cfg(feature = "tls")]
        assert!(reject.closes_connection());

        // Wrong Request Authenticator on our side ⇒ nothing verifies.
        let reply = Packet::decode(&signed_reply(
            &req,
            Code::AccessAccept,
            id,
            secret.as_bytes(),
        ))
        .unwrap();
        assert_eq!(
            verify_probe_packet(&server, &reply, id, &[0u8; 16]),
            Err(ProbeReject::ResponseAuthenticator)
        );
    }

    // --- The probe over a RadSec link: the RFC 6613 §2.6 watchdog ---------------

    #[cfg(feature = "tls")]
    mod over_link {
        use super::*;
        use crate::proxy::home_server::HomeServerTlsConfig;
        use crate::proxy::radsec_client::{LinkParams, RadsecLinkHandle, spawn_link};
        use crate::radsec_frame::RADSEC_SECRET;
        use crate::test_pki::{
            FakeAction, TestPaths, gen_chain, lenient_server_config, spawn_fake_tls_home,
            spawn_radsec_home,
        };
        use std::time::Instant;

        fn radsec_home_server(addr: SocketAddr, paths: &TestPaths) -> Arc<HomeServer> {
            Arc::new(
                HomeServer::new(HomeServerConfig {
                    name: Some(format!("home-radsec-{}", addr.port())),
                    timeout: 2,
                    max_outstanding: 255,
                    ..HomeServerConfig::radsec(
                        addr.to_string(),
                        HomeServerTlsConfig {
                            ca_path: paths.ca.clone(),
                            cert_path: paths.client_cert.clone(),
                            key_path: paths.client_key.clone(),
                            server_name: "localhost".to_string(),
                            revocation: None,
                        },
                    )
                })
                .unwrap(),
            )
        }

        fn fast() -> LinkParams {
            LinkParams {
                connect_timeout: Duration::from_secs(2),
                write_timeout: Duration::from_secs(2),
                initial_backoff: Duration::from_millis(40),
                max_backoff: Duration::from_millis(160),
                stable_after: Duration::from_secs(10),
                identifier_ttl: Duration::from_secs(60),
            }
        }

        /// Spawn and attach the link, waiting for it to come up.
        async fn attach_connected_link(hs: &Arc<HomeServer>) -> RadsecLinkHandle {
            let (tx, _rx) = tokio::sync::mpsc::channel(4);
            let link = spawn_link(Arc::clone(hs), tx, fast()).unwrap();
            hs.attach_link(link.clone());
            wait_for(|| link.is_connected(), Duration::from_secs(5)).await;
            assert!(hs.is_connected(), "link did not come up");
            link
        }

        async fn wait_for(mut cond: impl FnMut() -> bool, max: Duration) {
            let deadline = Instant::now() + max;
            while !cond() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        /// What a conformant home server answers a Status-Server over the
        /// link with: Access-Accept, same Identifier, signed under "radsec".
        fn probe_reply(request: &Packet) -> Vec<u8> {
            signed_reply(
                request,
                Code::AccessAccept,
                request.identifier,
                RADSEC_SECRET,
            )
        }

        #[tokio::test]
        async fn probe_over_the_link_against_the_real_listener_succeeds() {
            let chain = gen_chain();
            let (addr, _registry, paths) =
                spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
            let server = radsec_home_server(addr, &paths);
            let _link = attach_connected_link(&server).await;

            probe(&server).await;
            assert_eq!(server.health_stats().consecutive_successes(), 1);
            assert_eq!(server.health_stats().consecutive_failures(), 0);
            assert_eq!(server.secret(), RADSEC_SECRET);
        }

        #[tokio::test]
        async fn probe_on_a_down_link_fails_immediately() {
            // Nothing listens: the link never comes up and the probe does not
            // wait out its deadline.
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let addr = {
                let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                probe.local_addr().unwrap()
            };
            let server = radsec_home_server(addr, &paths);
            let (tx, _rx) = tokio::sync::mpsc::channel(4);
            let link = spawn_link(Arc::clone(&server), tx, fast()).unwrap();
            server.attach_link(link);
            tokio::time::sleep(Duration::from_millis(50)).await;

            let started = Instant::now();
            probe_with(&server, Duration::from_secs(5)).await;
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{:?}",
                started.elapsed()
            );
            assert_eq!(server.health_stats().consecutive_failures(), 1);
            assert_eq!(server.health_stats().consecutive_successes(), 0);
        }

        #[tokio::test]
        async fn probe_without_an_attached_link_is_a_failure() {
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let server = radsec_home_server("127.0.0.1:12083".parse().unwrap(), &paths);
            probe_with(&server, Duration::from_secs(5)).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);
        }

        #[tokio::test]
        async fn stray_frames_do_not_fail_a_probe_the_real_reply_answers() {
            // RFC 5997 §4.4: the fake home answers each probe first with a
            // correctly signed reply under the wrong Identifier, then a
            // correctly signed Access-Challenge (not a permitted code), then
            // the genuine reply. Neither stray is "ours" (RFC 6613 §2.6.4 lets
            // a response matching no request be discarded), so the connection
            // is kept and the probe succeeds.
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let addr = spawn_fake_tls_home(&chain, move |_, request| {
                let id = request.identifier;
                FakeAction::Reply(vec![
                    signed_reply(
                        request,
                        Code::AccessAccept,
                        id.wrapping_add(1),
                        RADSEC_SECRET,
                    ),
                    signed_reply(request, Code::AccessChallenge, id, RADSEC_SECRET),
                    probe_reply(request),
                ])
            })
            .await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            probe(&server).await;
            assert_eq!(server.health_stats().consecutive_successes(), 1);
            assert_eq!(server.health_stats().consecutive_failures(), 0);
            assert_eq!(link.connections(), 1, "stray replies keep the connection");
        }

        #[tokio::test]
        async fn probe_over_the_link_rejects_a_reply_under_the_wrong_secret_and_closes_the_connection()
         {
            // RFC 6613 §2.6.4: a reply whose Response Authenticator fails
            // validation MUST close the connection; the link reconnects.
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let other = home_secret();
            let addr = spawn_fake_tls_home(&chain, move |_, request| {
                FakeAction::Reply(vec![signed_reply(
                    request,
                    Code::AccessAccept,
                    request.identifier,
                    other.as_bytes(),
                )])
            })
            .await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);
            assert_eq!(server.health_stats().consecutive_successes(), 0);
            wait_for(
                || link.connections() == 2 && link.is_connected(),
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(
                link.connections(),
                2,
                "a failed Response Authenticator must close the connection"
            );
        }

        #[tokio::test]
        async fn probe_over_the_link_rejects_a_reply_with_a_bad_message_authenticator_and_closes_the_connection()
         {
            // RFC 5997 §4.4 / RFC 3579 §3.2: the Response Authenticator verifies
            // under "radsec" but the Message-Authenticator does not. The TLS
            // peer is authenticated; the RADIUS-layer check still applies, the
            // probe fails and (RFC 6613 §2.6.4) the connection is closed.
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let addr = spawn_fake_tls_home(&chain, |_, request| {
                FakeAction::Reply(vec![reply_with_bad_message_authenticator(
                    request,
                    Code::AccessAccept,
                    request.identifier,
                    RADSEC_SECRET,
                )])
            })
            .await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);
            assert_eq!(server.health_stats().consecutive_successes(), 0);
            wait_for(
                || link.connections() == 2 && link.is_connected(),
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(
                link.connections(),
                2,
                "a failed Message-Authenticator must close the connection"
            );
        }

        #[tokio::test]
        async fn two_unanswered_probes_close_the_connection_one_does_not() {
            // RFC 6613 §2.6 → RFC 3539 §3.4: the connection is torn down and
            // re-established only once the watchdog has expired twice without
            // a response. The fake home accepts connections and never answers
            // a probe (a half-dead peer: no FIN, no RST).
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let addr = spawn_fake_tls_home(&chain, |_, _| FakeAction::Reply(vec![])).await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                link.connections(),
                1,
                "one miss must not close the connection"
            );
            assert!(link.is_connected());

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 2);
            wait_for(
                || link.connections() == 2 && link.is_connected(),
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(
                link.connections(),
                2,
                "the second miss closes the connection and the link reconnects"
            );
        }

        #[tokio::test]
        async fn probe_identifier_avoids_identifiers_in_flight_on_the_link() {
            // RFC 6613 §2.6: one Identifier of the connection's 256 is
            // reserved for the watchdog. With Identifiers 0..=254 in flight
            // (unanswered forwarded requests), every probe must go out as 255.
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let probe_ids: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
            let seen = Arc::clone(&probe_ids);
            let addr = spawn_fake_tls_home(&chain, move |_, request| {
                if request.code == Code::StatusServer {
                    seen.lock().unwrap().push(request.identifier);
                    FakeAction::Reply(vec![probe_reply(request)])
                } else {
                    FakeAction::Reply(vec![]) // never answered: stays in flight
                }
            })
            .await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            for id in 0..=254u8 {
                let request =
                    Packet::new(Code::AccessRequest, id, generate_request_authenticator());
                link.send(request.encode().unwrap()).unwrap();
            }
            // Let the link task drain the outbound queue (the test runtime is
            // single-threaded; the queue holds exactly `max_outstanding`).
            tokio::time::sleep(Duration::from_millis(200)).await;
            for _ in 0..3 {
                probe(&server).await;
            }
            assert_eq!(server.health_stats().consecutive_successes(), 3);
            assert_eq!(*probe_ids.lock().unwrap(), vec![255, 255, 255]);

            // With the whole space taken the probe is skipped rather than
            // colliding with a forwarded request — and a skipped probe is no
            // evidence about the peer: not a failure, not a watchdog miss, no
            // reset, the connection is kept (SEC-007).
            let request = Packet::new(Code::AccessRequest, 255, generate_request_authenticator());
            link.send(request.encode().unwrap()).unwrap();
            assert_eq!(link.in_flight(), 256);
            let checks_before = server.health_stats().total_checks();
            probe_expecting_failure(&server).await;
            probe_expecting_failure(&server).await;
            assert_eq!(probe_ids.lock().unwrap().len(), 3, "no probe was sent");
            assert_eq!(server.health_stats().consecutive_failures(), 0);
            assert_eq!(server.health_stats().consecutive_successes(), 3);
            assert_eq!(
                server.health_stats().total_checks(),
                checks_before,
                "a skipped probe is not a check"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                link.connections(),
                1,
                "two skipped probes must not reset the connection"
            );
            assert!(link.is_connected());
        }

        #[tokio::test]
        async fn watchdog_misses_are_counted_per_connection() {
            // RFC 3539 §3.4: a connection is closed only once *its own*
            // watchdog timer has expired twice. A miss on connection 1 and
            // then a miss on connection 2 is one miss per connection — no
            // reset, although the server's consecutive-failure count (which
            // drives Up/Down) is 2. The second miss on connection 2 closes it.
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let addr = spawn_fake_tls_home(&chain, |_, _| FakeAction::Reply(vec![])).await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);
            assert_eq!(link.connections(), 1);

            // Connection 1 is replaced for another reason (say a peer fault).
            link.reset(1, "test");
            wait_for(
                || link.connections() == 2 && link.is_connected(),
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(link.connections(), 2);

            probe_expecting_failure(&server).await;
            assert_eq!(
                server.health_stats().consecutive_failures(),
                2,
                "the per-server count keeps growing"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                link.connections(),
                2,
                "one miss on connection 2 must not close it"
            );
            assert!(link.is_connected());

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 3);
            wait_for(
                || link.connections() == 3 && link.is_connected(),
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(
                link.connections(),
                3,
                "the second miss on connection 2 closes it"
            );
        }

        #[tokio::test]
        async fn a_verified_reply_restarts_the_watchdog_miss_count() {
            // Miss, verified reply, miss: the misses are not consecutive, so
            // the connection is kept; the next miss is the second in a row and
            // closes it (RFC 3539 §3.4).
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let answer = Arc::new(AtomicBool::new(false));
            let answering = Arc::clone(&answer);
            let addr = spawn_fake_tls_home(&chain, move |_, request| {
                if request.code == Code::StatusServer && answering.load(Ordering::SeqCst) {
                    FakeAction::Reply(vec![probe_reply(request)])
                } else {
                    FakeAction::Reply(vec![])
                }
            })
            .await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);

            answer.store(true, Ordering::SeqCst);
            probe(&server).await;
            assert_eq!(server.health_stats().consecutive_successes(), 1);
            assert_eq!(server.health_stats().consecutive_failures(), 0);

            answer.store(false, Ordering::SeqCst);
            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                link.connections(),
                1,
                "a miss after a verified reply is the first miss again"
            );
            assert!(link.is_connected());

            probe_expecting_failure(&server).await;
            wait_for(
                || link.connections() == 2 && link.is_connected(),
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(link.connections(), 2, "two misses in a row close it");
        }

        #[tokio::test]
        async fn probe_over_the_link_rejects_an_access_challenge() {
            // RFC 5997 §4.2: only Access-Accept / Access-Reject (or
            // Accounting-Response) answer a Status-Server; a correctly signed
            // Access-Challenge is not a healthy reply.
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let addr = spawn_fake_tls_home(&chain, |_, request| {
                FakeAction::Reply(vec![signed_reply(
                    request,
                    Code::AccessChallenge,
                    request.identifier,
                    RADSEC_SECRET,
                )])
            })
            .await;
            let server = radsec_home_server(addr, &paths);
            let link = attach_connected_link(&server).await;

            probe_expecting_failure(&server).await;
            assert_eq!(server.health_stats().consecutive_failures(), 1);
            assert_eq!(server.health_stats().consecutive_successes(), 0);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                link.connections(),
                1,
                "an unexpected code is a discard, not a connection fault"
            );
        }

        #[tokio::test]
        async fn probe_fails_when_the_link_drops_while_waiting() {
            let chain = gen_chain();
            let paths = chain.write_to_tempdir();
            let addr = spawn_fake_tls_home(&chain, |_, _| FakeAction::Close).await;
            let server = radsec_home_server(addr, &paths);
            let _link = attach_connected_link(&server).await;

            let started = Instant::now();
            probe_with(&server, Duration::from_secs(5)).await;
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "a lost link must fail the probe before its deadline"
            );
            assert_eq!(server.health_stats().consecutive_failures(), 1);
        }
    }
}
