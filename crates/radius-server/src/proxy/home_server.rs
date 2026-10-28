//! Home server (upstream RADIUS server) configuration and state tracking

use crate::config::RevocationConfig;
use crate::proxy::error::{ProxyError, ProxyResult};
use crate::proxy::health::HealthCheckStats;
use crate::radsec_frame::RADSEC_SECRET;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(feature = "tls")]
use crate::proxy::radsec_client::RadsecLinkHandle;
#[cfg(feature = "tls")]
use std::sync::OnceLock;

/// How the proxy reaches a home server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HomeServerTransport {
    /// RADIUS over UDP (RFC 2865) with the server's own shared secret.
    #[default]
    Udp,
    /// RADIUS over TLS 1.3 (RFC 6614 RadSec): one persistent, mutually
    /// authenticated connection; the hop secret is the fixed `"radsec"`
    /// (RFC 6614 §2.3) and the real authentication is the certificate exchange.
    Radsec,
}

impl std::fmt::Display for HomeServerTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Radsec => "radsec",
        })
    }
}

/// TLS client settings for a `transport = "radsec"` home server. Paths only;
/// the key is read when the link is built and never held here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeServerTlsConfig {
    /// CA bundle (PEM) the home server's certificate must chain to.
    pub ca_path: String,
    /// Our client certificate chain (PEM, leaf first), presented to the home
    /// server (RFC 6614 §2.3 item 2: mutual authentication is REQUIRED).
    pub cert_path: String,
    /// Our client private key (PEM).
    pub key_path: String,
    /// Name the home server's certificate must be valid for (DNS name or IP
    /// literal); also sent as SNI. RFC 6614 §2.3 item 3: certificate
    /// validation MUST follow RFC 5280 and check the expected DNS name.
    pub server_name: String,
    /// CRL/OCSP revocation checking of the home server's certificate; the same
    /// block as `eap.tls.revocation` and `radsec.revocation`. Omitted ⇒ chain
    /// validation only. Needs a binary built with the `revocation` feature.
    #[serde(default)]
    pub revocation: Option<RevocationConfig>,
}

impl HomeServerTlsConfig {
    /// Validate the block; `at` names it in errors.
    pub fn validate(&self, at: &str) -> ProxyResult<()> {
        let invalid = |msg: String| ProxyError::Configuration(format!("{at}: {msg}"));

        for (field, value) in [
            ("ca_path", &self.ca_path),
            ("cert_path", &self.cert_path),
            ("key_path", &self.key_path),
        ] {
            if value.trim().is_empty() {
                return Err(invalid(format!("{field} cannot be empty")));
            }
        }
        if self.server_name.trim().is_empty() {
            return Err(invalid("server_name cannot be empty".to_string()));
        }
        // A name rustls cannot represent can never match a certificate.
        #[cfg(feature = "tls")]
        if rustls::pki_types::ServerName::try_from(self.server_name.as_str()).is_err() {
            return Err(invalid(format!(
                "server_name {:?} is neither a DNS name nor an IP address",
                self.server_name
            )));
        }
        if let Some(rev) = &self.revocation {
            rev.validate(&format!("{at}.revocation"))
                .map_err(|e| ProxyError::Configuration(e.to_string()))?;
        }
        Ok(())
    }
}

/// Home server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeServerConfig {
    /// Server address (host:port)
    pub address: String,

    /// Shared secret for this server. Required for `transport = "udp"`; must
    /// be absent for `transport = "radsec"`, whose hop secret is the fixed
    /// `"radsec"` (RFC 6614 §2.3).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret: String,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Maximum outstanding requests to this server
    #[serde(default = "default_max_outstanding")]
    pub max_outstanding: usize,

    /// Optional server name/description
    #[serde(default)]
    pub name: Option<String>,

    /// Transport to the home server. Default `udp`.
    #[serde(default)]
    pub transport: HomeServerTransport,

    /// TLS client settings; required for and only used with `transport = "radsec"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<HomeServerTlsConfig>,
}

fn default_timeout() -> u64 {
    30
}

fn default_max_outstanding() -> usize {
    100
}

impl Default for HomeServerConfig {
    fn default() -> Self {
        HomeServerConfig {
            address: String::new(),
            secret: String::new(),
            timeout: default_timeout(),
            max_outstanding: default_max_outstanding(),
            name: None,
            transport: HomeServerTransport::Udp,
            tls: None,
        }
    }
}

impl HomeServerConfig {
    /// A UDP home server with the given shared secret and default limits.
    pub fn udp(address: impl Into<String>, secret: impl Into<String>) -> Self {
        HomeServerConfig {
            address: address.into(),
            secret: secret.into(),
            ..Self::default()
        }
    }

    /// A RadSec home server (RFC 6614) with the given TLS client settings and
    /// default limits. The hop secret is the fixed `"radsec"`.
    pub fn radsec(address: impl Into<String>, tls: HomeServerTlsConfig) -> Self {
        HomeServerConfig {
            address: address.into(),
            transport: HomeServerTransport::Radsec,
            tls: Some(tls),
            ..Self::default()
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> ProxyResult<()> {
        // Parse address to validate format
        let _: SocketAddr = self
            .address
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                ProxyError::Configuration(format!(
                    "Invalid home server address '{}': {}",
                    self.address, e
                ))
            })?;

        if self.timeout == 0 {
            return Err(ProxyError::Configuration(
                "Home server timeout cannot be 0".to_string(),
            ));
        }

        let label = self.name.as_deref().unwrap_or(&self.address);
        match self.transport {
            HomeServerTransport::Udp => {
                if self.secret.is_empty() {
                    return Err(ProxyError::Configuration(
                        "Home server secret cannot be empty".to_string(),
                    ));
                }
                if self.tls.is_some() {
                    return Err(ProxyError::Configuration(format!(
                        "Home server '{label}': tls is only used with transport = \"radsec\""
                    )));
                }
            }
            HomeServerTransport::Radsec => {
                // RFC 6613 §2.6.5: no more than 256 requests outstanding on
                // one TCP connection, and RFC 6613 §2.6 reserves one
                // Identifier of the connection's 256 for the watchdog
                // (Status-Server), so at most 255 forwarded requests may be
                // in flight on the link. `max_outstanding` is also the depth
                // of the link's outbound queue.
                if self.max_outstanding > 255 {
                    return Err(ProxyError::Configuration(format!(
                        "Home server '{label}': max_outstanding {} exceeds 255; one RadSec \
                         connection carries at most 256 outstanding requests with one \
                         Identifier reserved for the Status-Server watchdog \
                         (RFC 6613 §2.6, §2.6.5)",
                        self.max_outstanding
                    )));
                }
                // Fail closed: a config that asks for RadSec must not start a
                // binary that would have to reach the home server some other way.
                if !cfg!(feature = "tls") {
                    return Err(ProxyError::Configuration(format!(
                        "Home server '{label}': transport = \"radsec\" requires a binary built \
                         with the `tls` feature"
                    )));
                }
                // RFC 6614 §2.3: the shared secret on a RadSec hop is the fixed
                // string "radsec"; a configured one would be silently ignored,
                // so it is an error instead.
                if !self.secret.is_empty() {
                    return Err(ProxyError::Configuration(format!(
                        "Home server '{label}': secret must not be set with transport = \
                         \"radsec\" (RFC 6614 §2.3 fixes the hop secret to \"radsec\")"
                    )));
                }
                let tls = self.tls.as_ref().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Home server '{label}': transport = \"radsec\" requires a tls block \
                         (ca_path, cert_path, key_path, server_name)"
                    ))
                })?;
                tls.validate(&format!("Home server '{label}' tls"))?;
            }
        }

        Ok(())
    }
}

/// Home server state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HomeServerState {
    /// Server is operational and accepting requests
    #[default]
    Up,
    /// Server is down (health checks failing)
    Down,
    /// Server is permanently unavailable (requires manual intervention)
    Dead,
}

/// Home server statistics
#[derive(Debug)]
pub struct HomeServerStats {
    /// Total requests sent to this server
    pub requests_sent: AtomicU64,
    /// Total responses received from this server
    pub responses_received: AtomicU64,
    /// Total timeouts from this server
    pub timeouts: AtomicU64,
    /// Total requests currently in flight
    pub outstanding: AtomicU64,
    /// Last response timestamp
    pub last_response: RwLock<Option<Instant>>,
}

impl Default for HomeServerStats {
    fn default() -> Self {
        HomeServerStats {
            requests_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            outstanding: AtomicU64::new(0),
            last_response: RwLock::new(None),
        }
    }
}

impl HomeServerStats {
    /// Record a request sent
    pub fn record_request(&self) {
        self.requests_sent.fetch_add(1, Ordering::Relaxed);
        self.outstanding.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a response received
    pub fn record_response(&self) {
        self.responses_received.fetch_add(1, Ordering::Relaxed);
        self.release_outstanding();
        *self.last_response.write().unwrap() = Some(Instant::now());
    }

    /// Record a timeout
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
        self.release_outstanding();
    }

    /// One request fewer in flight. Saturating: a response or timeout without
    /// a matching `record_request` must never wrap the gauge to `u64::MAX`
    /// (which would make `has_capacity` false forever).
    fn release_outstanding(&self) {
        let mut current = self.outstanding.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self.outstanding.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Get current outstanding request count
    pub fn outstanding(&self) -> u64 {
        self.outstanding.load(Ordering::Relaxed)
    }

    /// Get total requests sent
    pub fn requests_sent(&self) -> u64 {
        self.requests_sent.load(Ordering::Relaxed)
    }

    /// Get total responses received
    pub fn responses_received(&self) -> u64 {
        self.responses_received.load(Ordering::Relaxed)
    }

    /// Get total timeouts
    pub fn timeouts(&self) -> u64 {
        self.timeouts.load(Ordering::Relaxed)
    }

    /// Get time since last response
    pub fn time_since_last_response(&self) -> Option<Duration> {
        self.last_response.read().unwrap().map(|t| t.elapsed())
    }
}

/// Home server (upstream RADIUS server)
pub struct HomeServer {
    /// Server name (for logging)
    pub name: String,
    /// Server socket address
    pub address: SocketAddr,
    /// Shared secret for this server: the configured one over UDP, the fixed
    /// `"radsec"` (RFC 6614 §2.3) over RadSec.
    pub secret: Vec<u8>,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum outstanding requests
    pub max_outstanding: usize,
    /// Transport to this server
    transport: HomeServerTransport,
    /// TLS client settings (RadSec only)
    tls: Option<HomeServerTlsConfig>,
    /// The RadSec link once the server has started it (RadSec only).
    #[cfg(feature = "tls")]
    link: OnceLock<RadsecLinkHandle>,
    /// Current server state
    state: Arc<RwLock<HomeServerState>>,
    /// Server statistics
    stats: Arc<HomeServerStats>,
    /// Health check statistics
    health_stats: Arc<HealthCheckStats>,
}

impl HomeServer {
    /// Create a new home server from configuration
    pub fn new(config: HomeServerConfig) -> ProxyResult<Self> {
        config.validate()?;

        let address: SocketAddr = config.address.parse()?;
        let name = config.name.unwrap_or_else(|| config.address.clone());
        let secret = match config.transport {
            HomeServerTransport::Udp => config.secret.into_bytes(),
            // RFC 6614 §2.3: fixed shared secret on a RadSec hop.
            HomeServerTransport::Radsec => RADSEC_SECRET.to_vec(),
        };

        Ok(HomeServer {
            name,
            address,
            secret,
            timeout: Duration::from_secs(config.timeout),
            max_outstanding: config.max_outstanding,
            transport: config.transport,
            tls: config.tls,
            #[cfg(feature = "tls")]
            link: OnceLock::new(),
            state: Arc::new(RwLock::new(HomeServerState::Up)),
            stats: Arc::new(HomeServerStats::default()),
            health_stats: Arc::new(HealthCheckStats::new()),
        })
    }

    /// Get current state
    pub fn state(&self) -> HomeServerState {
        *self.state.read().unwrap()
    }

    /// Set server state
    pub fn set_state(&self, new_state: HomeServerState) {
        *self.state.write().unwrap() = new_state;
    }

    /// Check if server is available for requests
    pub fn is_available(&self) -> bool {
        matches!(self.state(), HomeServerState::Up)
    }

    /// Check if server has capacity for more requests
    pub fn has_capacity(&self) -> bool {
        self.stats.outstanding() < self.max_outstanding as u64
    }

    /// Get server statistics
    pub fn stats(&self) -> &HomeServerStats {
        &self.stats
    }

    /// Get shared secret
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Transport to this server.
    pub fn transport(&self) -> HomeServerTransport {
        self.transport
    }

    /// TLS client settings (RadSec servers only).
    pub fn tls_config(&self) -> Option<&HomeServerTlsConfig> {
        self.tls.as_ref()
    }

    /// Attach the RadSec link that reaches this server. Called once by the
    /// server at startup; a second call is ignored (the first link stays).
    #[cfg(feature = "tls")]
    pub fn attach_link(&self, link: RadsecLinkHandle) {
        let _ = self.link.set(link);
    }

    /// The RadSec link to this server, once attached.
    #[cfg(feature = "tls")]
    pub fn link(&self) -> Option<&RadsecLinkHandle> {
        self.link.get()
    }

    /// The link's connection generation (`RadsecLinkHandle::connections()`)
    /// a request sent now goes out on, for `ProxyCacheEntry::sent_on_connection`
    /// (RFC 6613 §2.6.1). `None` for UDP and for a RadSec server with no link.
    pub fn link_generation(&self) -> Option<u64> {
        #[cfg(feature = "tls")]
        {
            self.link.get().map(RadsecLinkHandle::connections)
        }
        #[cfg(not(feature = "tls"))]
        {
            None
        }
    }

    /// Whether the transport to this server is currently usable: always for
    /// UDP (connectionless), the link state for RadSec.
    pub fn is_connected(&self) -> bool {
        match self.transport {
            HomeServerTransport::Udp => true,
            HomeServerTransport::Radsec => {
                #[cfg(feature = "tls")]
                {
                    self.link.get().is_some_and(RadsecLinkHandle::is_connected)
                }
                #[cfg(not(feature = "tls"))]
                {
                    false
                }
            }
        }
    }

    /// Get health check statistics
    pub fn health_stats(&self) -> &HealthCheckStats {
        &self.health_stats
    }

    /// Mark server as down
    pub fn mark_down(&self) {
        *self.state.write().unwrap() = HomeServerState::Down;
    }

    /// Mark server as up
    pub fn mark_up(&self) {
        *self.state.write().unwrap() = HomeServerState::Up;
    }

    /// Mark server as dead (requires manual intervention)
    pub fn mark_dead(&self) {
        *self.state.write().unwrap() = HomeServerState::Dead;
    }
}

impl std::fmt::Debug for HomeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeServer")
            .field("name", &self.name)
            .field("address", &self.address)
            .field("transport", &self.transport)
            .field("state", &self.state())
            .field("outstanding", &self.stats.outstanding())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn udp_config() -> HomeServerConfig {
        HomeServerConfig {
            name: Some("Test Server".to_string()),
            ..HomeServerConfig::udp("192.168.1.1:1812", "test_secret")
        }
    }

    fn tls_block() -> HomeServerTlsConfig {
        HomeServerTlsConfig {
            ca_path: "/etc/radius/home-ca.pem".to_string(),
            cert_path: "/etc/radius/proxy.pem".to_string(),
            key_path: "/etc/radius/proxy.key".to_string(),
            server_name: "home.example.test".to_string(),
            revocation: None,
        }
    }

    fn radsec_config() -> HomeServerConfig {
        HomeServerConfig {
            name: Some("home-radsec".to_string()),
            ..HomeServerConfig::radsec("192.168.1.1:2083", tls_block())
        }
    }

    #[test]
    fn test_home_server_config_validation() {
        assert!(udp_config().validate().is_ok());
    }

    #[test]
    fn test_home_server_config_invalid_address() {
        let config = HomeServerConfig::udp("invalid_address", "test_secret");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_home_server_config_empty_secret() {
        let config = HomeServerConfig::udp("192.168.1.1:1812", "");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_home_server_config_zero_timeout() {
        let config = HomeServerConfig {
            timeout: 0,
            ..udp_config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_home_server_creation() {
        let server = HomeServer::new(udp_config()).unwrap();
        assert_eq!(server.name, "Test Server");
        assert_eq!(server.address.to_string(), "192.168.1.1:1812");
        assert_eq!(server.secret, b"test_secret");
        assert_eq!(server.transport(), HomeServerTransport::Udp);
        assert!(server.tls_config().is_none());
        assert!(server.is_connected(), "UDP is connectionless");
        assert!(server.is_available());
        assert!(server.has_capacity());
    }

    #[test]
    fn test_home_server_state_transitions() {
        let server = HomeServer::new(udp_config()).unwrap();
        assert_eq!(server.state(), HomeServerState::Up);
        assert!(server.is_available());

        server.set_state(HomeServerState::Down);
        assert_eq!(server.state(), HomeServerState::Down);
        assert!(!server.is_available());

        server.set_state(HomeServerState::Dead);
        assert_eq!(server.state(), HomeServerState::Dead);
        assert!(!server.is_available());

        server.set_state(HomeServerState::Up);
        assert_eq!(server.state(), HomeServerState::Up);
        assert!(server.is_available());
    }

    #[test]
    fn test_home_server_stats() {
        let server = HomeServer::new(udp_config()).unwrap();
        let stats = server.stats();

        // Initial state
        assert_eq!(stats.requests_sent(), 0);
        assert_eq!(stats.responses_received(), 0);
        assert_eq!(stats.timeouts(), 0);
        assert_eq!(stats.outstanding(), 0);

        // Record request
        stats.record_request();
        assert_eq!(stats.requests_sent(), 1);
        assert_eq!(stats.outstanding(), 1);

        // Record response
        stats.record_response();
        assert_eq!(stats.responses_received(), 1);
        assert_eq!(stats.outstanding(), 0);
        assert!(stats.time_since_last_response().is_some());

        // Record timeout
        stats.record_request();
        stats.record_timeout();
        assert_eq!(stats.timeouts(), 1);
        assert_eq!(stats.outstanding(), 0);
    }

    #[test]
    fn outstanding_never_wraps_below_zero() {
        // A timeout or response without a prior record_request (the old
        // forward_request failure path) must not turn the gauge into u64::MAX
        // and starve the server of capacity.
        let server = HomeServer::new(udp_config()).unwrap();
        server.stats().record_timeout();
        assert_eq!(server.stats().outstanding(), 0);
        server.stats().record_response();
        assert_eq!(server.stats().outstanding(), 0);
        assert!(server.has_capacity());
    }

    #[test]
    fn test_home_server_capacity() {
        let config = HomeServerConfig {
            max_outstanding: 2,
            ..udp_config()
        };

        let server = HomeServer::new(config).unwrap();
        assert!(server.has_capacity());

        // Fill capacity
        server.stats().record_request();
        assert!(server.has_capacity());

        server.stats().record_request();
        assert!(!server.has_capacity());

        // Free up capacity
        server.stats().record_response();
        assert!(server.has_capacity());
    }

    // --- transport = "radsec" ---------------------------------------------

    #[test]
    fn default_transport_is_udp_when_the_key_is_absent() {
        // The pre-RadSec JSON shape still parses to a UDP home server.
        let json = r#"{"address":"10.0.0.1:1812","secret":"s3cret","name":"legacy"}"#;
        let config: HomeServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.transport, HomeServerTransport::Udp);
        assert!(config.tls.is_none());
        assert_eq!(config.timeout, 30);
        assert_eq!(config.max_outstanding, 100);
        config.validate().unwrap();
    }

    #[test]
    fn radsec_server_round_trips_through_serde() {
        let config = HomeServerConfig {
            tls: Some(HomeServerTlsConfig {
                revocation: Some(RevocationConfig::default()),
                ..tls_block()
            }),
            ..radsec_config()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"transport\":\"radsec\""));
        assert!(
            !json.contains("\"secret\""),
            "an empty secret is not serialized"
        );
        let back: HomeServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.transport, HomeServerTransport::Radsec);
        assert_eq!(back.tls, config.tls);
        assert_eq!(back.address, config.address);
        assert!(back.secret.is_empty());

        // And the JSON shape operators write.
        let json = r#"{
            "address": "10.0.0.1:2083",
            "transport": "radsec",
            "tls": {
                "ca_path": "/certs/ca.crt",
                "cert_path": "/certs/proxy.crt",
                "key_path": "/certs/proxy.key",
                "server_name": "home.example.test"
            }
        }"#;
        let config: HomeServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.transport, HomeServerTransport::Radsec);
        assert_eq!(
            config.tls.as_ref().unwrap().server_name,
            "home.example.test"
        );
        assert!(config.tls.as_ref().unwrap().revocation.is_none());
    }

    #[test]
    fn unknown_transport_is_rejected() {
        let json = r#"{"address":"10.0.0.1:1812","secret":"x","transport":"dtls"}"#;
        assert!(serde_json::from_str::<HomeServerConfig>(json).is_err());
    }

    #[test]
    fn radsec_requires_a_tls_block() {
        let config = HomeServerConfig {
            tls: None,
            ..radsec_config()
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("tls"), "{err}");
    }

    #[test]
    fn udp_rejects_a_tls_block() {
        let config = HomeServerConfig {
            tls: Some(tls_block()),
            ..udp_config()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("only used with transport"),
            "{err}"
        );
    }

    #[test]
    fn radsec_rejects_max_outstanding_above_255() {
        // RFC 6613 §2.6.5: at most 256 outstanding on one connection, one
        // Identifier of which RFC 6613 §2.6 reserves for the watchdog.
        let config = HomeServerConfig {
            max_outstanding: 256,
            ..radsec_config()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("max_outstanding 256"), "{err}");
        assert!(err.contains("RFC 6613"), "{err}");

        let config = HomeServerConfig {
            max_outstanding: 255,
            ..radsec_config()
        };
        assert_eq!(config.validate().is_ok(), cfg!(feature = "tls"));

        // UDP is not bound by it.
        let config = HomeServerConfig {
            max_outstanding: 1000,
            ..udp_config()
        };
        config.validate().unwrap();
    }

    #[test]
    fn radsec_rejects_a_configured_secret() {
        // RFC 6614 §2.3 item 4: the hop secret is fixed; a configured one is a mistake.
        let config = HomeServerConfig {
            secret: "not-radsec".to_string(),
            ..radsec_config()
        };
        let err = config.validate().unwrap_err();
        // Without `tls` the feature check fails first (fail closed either way).
        let expected = if cfg!(feature = "tls") {
            "secret must not be set"
        } else {
            "`tls` feature"
        };
        assert!(err.to_string().contains(expected), "{err}");
    }

    #[test]
    fn tls_block_rejects_blank_paths() {
        for field in ["ca_path", "cert_path", "key_path"] {
            let mut tls = tls_block();
            match field {
                "ca_path" => tls.ca_path = "  ".to_string(),
                "cert_path" => tls.cert_path = String::new(),
                _ => tls.key_path = String::new(),
            }
            let err = tls.validate("t").unwrap_err();
            assert!(err.to_string().contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn tls_block_rejects_empty_or_malformed_server_name() {
        let mut tls = tls_block();
        tls.server_name = String::new();
        assert!(tls.validate("t").is_err());

        tls.server_name = "   ".to_string();
        assert!(tls.validate("t").is_err());

        // Under `tls` the name must be a DNS name or IP literal (SNI /
        // certificate matching); a URL is neither.
        #[cfg(feature = "tls")]
        {
            tls.server_name = "https://home.example.test/".to_string();
            let err = tls.validate("t").unwrap_err();
            assert!(err.to_string().contains("server_name"), "{err}");

            tls.server_name = "10.0.0.1".to_string();
            tls.validate("t")
                .expect("IP literal is a valid server name");
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn radsec_home_server_uses_the_fixed_secret() {
        let server = HomeServer::new(radsec_config()).unwrap();
        assert_eq!(server.secret(), b"radsec");
        assert_eq!(server.transport(), HomeServerTransport::Radsec);
        assert_eq!(server.tls_config(), Some(&tls_block()));
        assert!(
            !server.is_connected(),
            "no link attached yet ⇒ not connected"
        );
        assert!(server.link().is_none());
        let dbg = format!("{server:?}");
        assert!(dbg.contains("transport: Radsec"), "{dbg}");
        assert!(
            !dbg.contains("secret"),
            "Debug never prints the secret: {dbg}"
        );
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn radsec_is_rejected_without_the_tls_feature() {
        let err = radsec_config().validate().unwrap_err();
        assert!(err.to_string().contains("`tls` feature"), "{err}");
        assert!(HomeServer::new(radsec_config()).is_err());
    }

    #[cfg(feature = "revocation")]
    #[test]
    fn tls_revocation_block_is_validated() {
        use crate::config::CrlSettings;

        // crl.fetch = false and no static files ⇒ no CRL source at all.
        let config = HomeServerConfig {
            tls: Some(HomeServerTlsConfig {
                revocation: Some(RevocationConfig {
                    crl: CrlSettings {
                        fetch: false,
                        static_files: vec![],
                        ..CrlSettings::default()
                    },
                    ..RevocationConfig::default()
                }),
                ..tls_block()
            }),
            ..radsec_config()
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("revocation"), "{err}");

        // The default block (CRL fetch on) is fine.
        let config = HomeServerConfig {
            tls: Some(HomeServerTlsConfig {
                revocation: Some(RevocationConfig::default()),
                ..tls_block()
            }),
            ..radsec_config()
        };
        config.validate().unwrap();
    }

    #[cfg(all(feature = "tls", not(feature = "revocation")))]
    #[test]
    fn tls_revocation_block_without_the_feature_is_rejected() {
        let config = HomeServerConfig {
            tls: Some(HomeServerTlsConfig {
                revocation: Some(RevocationConfig::default()),
                ..tls_block()
            }),
            ..radsec_config()
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("revocation"), "{err}");
    }
}
