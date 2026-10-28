use crate::accounting::AccountingHandler;
use crate::audit::{AuditEntry, AuditEventType, AuditLogger};
use crate::buffer_pool::BufferPool;
use crate::cache::{RequestCache, RequestFingerprint};
use crate::config::{AccountingPort, AccountingPortMode, Config};
use crate::proxy::ProxyConfig;
use crate::proxy::handler::ProxyHandler;
use crate::proxy::pool::HomeServerPool;
use crate::proxy::realm::Realm;
use crate::proxy::retry::RetryManager;
use crate::proxy::router::{Router, RoutingDecision};
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use radius_proto::accounting::{AccountingError, AcctStatusType};
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::auth::{
    calculate_accounting_request_authenticator, calculate_response_authenticator,
    decrypt_user_password,
};
use radius_proto::{
    ChapChallenge, ChapResponse, Code, MppeKeys, Packet, PacketError, ValidationMode,
    validate_packet, verify_chap_response,
};
use radius_proto::{calculate_message_authenticator, verify_message_authenticator};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Copy every Proxy-State attribute from `request` into `response`,
/// preserving their relative order (RFC 2865 §5.33).
///
/// "If a Proxy-State attribute was added to the access-request, it MUST be
/// copied unmodified to the response packet." Order is preserved by
/// iterating `request.attributes` in sequence and pushing each match onto
/// `response`, which appends in order.
fn copy_proxy_state(request: &Packet, response: &mut Packet) {
    for attr in request.attributes.iter() {
        if attr.attr_type == AttributeType::ProxyState as u8 {
            response.add_attribute(attr.clone());
        }
    }
}

/// Which listener a request arrived on. Decides which codes are admitted
/// (RFC 2866 §2) and which code answers Status-Server (RFC 5997 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortRole {
    /// UDP authentication socket (`listen_port`).
    Auth,
    /// UDP accounting socket (`accounting_port`).
    Accounting,
    /// RadSec connection: every code on one stream (RFC 6614 §2.5).
    Any,
}

impl PortRole {
    /// Whether a packet with `code` belongs on this listener.
    /// `accounting_on_auth` is
    /// `AccountingPort::accepts_accounting_on_auth_socket()` — true only in
    /// the legacy single-socket (`"shared"`) mode.
    fn admits(self, code: Code, accounting_on_auth: bool) -> bool {
        match (self, code) {
            (PortRole::Any, _) => true,
            // RFC 2866 §2: accounting has its own port; Code 4 on the
            // authentication socket is a misconfigured NAS unless "shared".
            (PortRole::Auth, Code::AccountingRequest) => accounting_on_auth,
            // RFC 2866 §2: nothing but accounting (and Status-Server, RFC 5997
            // §2) belongs on the accounting port.
            (PortRole::Accounting, Code::AccessRequest) => false,
            // Status-Server is accepted everywhere; other codes fall through
            // to the existing "Unsupported" dispatch arm.
            _ => true,
        }
    }

    /// RFC 5997 §4.2: Status-Server is answered with Access-Accept on the
    /// authentication port and Accounting-Response on the accounting port.
    fn status_server_reply_code(self) -> Code {
        match self {
            PortRole::Accounting => Code::AccountingResponse,
            PortRole::Auth | PortRole::Any => Code::AccessAccept,
        }
    }
}

/// Outcome of checking a request's Message-Authenticator against a secret.
enum MessageAuthenticatorCheck {
    /// The request carries no Message-Authenticator attribute.
    Absent,
    /// Present and verified under the secret.
    Valid,
    /// Present but the HMAC-MD5 does not match (or the value is malformed).
    Invalid,
}

/// RFC 2869 §5.14: re-encode `request`, locate the first Message-Authenticator
/// value (header 20 octets + 2 per attribute header + preceding values) and
/// verify it with the shared secret. The offset walk uses the decoded
/// attributes and the canonical re-encoding, so the two always agree.
fn check_message_authenticator(
    request: &Packet,
    secret: &[u8],
) -> Result<MessageAuthenticatorCheck, PacketError> {
    // Packet structure: Code (1) + ID (1) + Length (2) + Authenticator (16) + Attributes
    let mut offset = 20;
    let mut msg_auth_offset = None;
    for attr in &request.attributes {
        if attr.attr_type == AttributeType::MessageAuthenticator as u8 {
            // Attribute structure: Type (1) + Length (1) + Value
            msg_auth_offset = Some(offset + 2);
            break;
        }
        offset += 2 + attr.value.len();
    }
    let Some(offset) = msg_auth_offset else {
        return Ok(MessageAuthenticatorCheck::Absent);
    };
    let packet_bytes = request.encode()?;
    if verify_message_authenticator(&packet_bytes, secret, offset) {
        Ok(MessageAuthenticatorCheck::Valid)
    } else {
        Ok(MessageAuthenticatorCheck::Invalid)
    }
}

/// Sign `response` with a Message-Authenticator. Computed per RFC 2869 §5.14:
/// HMAC-MD5 over the full packet bytes with the Authenticator field set to the
/// *request* Authenticator and the Message-Authenticator attribute value set to
/// all zeros.
///
/// Appends a zeroed Message-Authenticator attribute if none exists, computes
/// the HMAC, and patches the value in place. Must be called BEFORE
/// calculate_response_authenticator so that Response-Authenticator covers the
/// final MA bytes.
fn add_message_authenticator(
    response: &mut Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> Result<(), PacketError> {
    let already_has_ma = response
        .attributes
        .iter()
        .any(|a| a.attr_type == AttributeType::MessageAuthenticator as u8);
    if !already_has_ma {
        response.add_attribute(radius_proto::Attribute::new(
            AttributeType::MessageAuthenticator as u8,
            vec![0u8; 16],
        )?);
    }

    // Build the HMAC input: same as on-wire bytes but with Authenticator =
    // request.authenticator. Packet::encode() writes self.authenticator, so
    // swap it in temporarily.
    let original_auth = response.authenticator;
    response.authenticator = *request_authenticator;
    let packet_bytes = response.encode()?;
    response.authenticator = original_auth;

    let mac = calculate_message_authenticator(&packet_bytes, secret);

    // Patch the MA attribute value (it's the last one we added, but search to be
    // safe in case caller already added other attrs after it).
    if let Some(ma_attr) = response
        .attributes
        .iter_mut()
        .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
    {
        ma_attr.value = mac.to_vec();
    }
    Ok(())
}

/// RFC 3579 §3.2: every Access-Accept / Access-Challenge / Access-Reject that
/// carries an EAP-Message attribute MUST also include a valid
/// Message-Authenticator. Gate around [`add_message_authenticator`]: a reply
/// without EAP-Message is left unchanged.
fn add_message_authenticator_if_eap(
    response: &mut Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> Result<(), PacketError> {
    let has_eap = response
        .attributes
        .iter()
        .any(|a| a.attr_type == AttributeType::EapMessage as u8);
    if !has_eap {
        return Ok(());
    }
    add_message_authenticator(response, request_authenticator, secret)
}

/// RADIUS attribute numbers that may appear at most once in a reply. When a policy
/// returns one of these, it must REPLACE any value already added by the auth
/// handler (e.g. a default Session-Timeout) rather than appending a duplicate —
/// duplicates of single-valued attributes have undefined behavior at the NAS.
/// Multi-valued attributes (Filter-Id, Class, Reply-Message) are intentionally
/// absent so they accumulate.
const SINGLE_VALUED_REPLY_ATTRS: &[u8] = &[
    AttributeType::SessionTimeout as u8,
    AttributeType::IdleTimeout as u8,
    AttributeType::TerminationAction as u8,
    64, // Tunnel-Type        (we only ever return one tunnel group)
    65, // Tunnel-Medium-Type
    81, // Tunnel-Private-Group-ID
];

/// Add a policy-derived reply attribute, replacing any prior value for the
/// single-valued types so the policy result wins over auth-handler defaults.
fn add_policy_reply_attribute(response: &mut Packet, attr: Attribute) {
    if SINGLE_VALUED_REPLY_ATTRS.contains(&attr.attr_type) {
        response
            .attributes
            .retain(|a| a.attr_type != attr.attr_type);
    }
    response.add_attribute(attr);
}

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Invalid client")]
    InvalidClient,
    #[error("Duplicate request")]
    DuplicateRequest,
    #[error("Rate limit exceeded")]
    RateLimited,
    #[error("Accounting error: {0}")]
    Accounting(#[from] AccountingError),
}

/// Authentication result for multi-round authentication
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication succeeded.
    ///
    /// `attributes` are added to the Access-Accept verbatim, on top of any
    /// the AuthHandler returns from `get_accept_attributes`. EAP methods
    /// use this to attach the EAP-Success EAP-Message (RFC 3748 §4.2);
    /// for PAP/CHAP success pass an empty Vec.
    ///
    /// `msk` is the EAP Master Session Key (RFC 3748 §7.10, ≥ 64 octets) of a
    /// key-deriving EAP method. When present, the Access-Accept builder
    /// encrypts it into MS-MPPE-Recv-Key (MSK[0..32]) and MS-MPPE-Send-Key
    /// (MSK[32..64]) per RFC 2548 §2.4, using the shared secret in force for
    /// the transport (per-client for UDP, `"radsec"` for RadSec) and the
    /// Request Authenticator — neither of which the handler needs to know.
    /// `None` for methods without key material (PAP/CHAP).
    Accept {
        attributes: Vec<Attribute>,
        msk: Option<Vec<u8>>,
    },
    /// Authentication failed
    Reject,
    /// Server needs more information (Access-Challenge)
    Challenge {
        /// Challenge message to display to user
        message: Option<String>,
        /// State to include in challenge response
        state: Vec<u8>,
        /// Additional attributes to include in challenge
        attributes: Vec<Attribute>,
    },
}

impl AuthResult {
    /// Shorthand for `AuthResult::Accept { attributes: vec![], msk: None }` —
    /// use when the response carries no protocol-specific attributes or key
    /// material (typical PAP/CHAP).
    pub fn accept() -> Self {
        AuthResult::Accept {
            attributes: Vec::new(),
            msk: None,
        }
    }
}

/// Authentication handler trait
///
/// Implement this trait to provide custom authentication logic.
pub trait AuthHandler: Send + Sync {
    /// Authenticate a user with username and password (PAP)
    ///
    /// Returns true if authentication succeeds, false otherwise.
    fn authenticate(&self, username: &str, password: &str) -> bool;

    /// Authenticate a user with CHAP challenge-response
    ///
    /// Returns true if authentication succeeds, false otherwise.
    /// Default implementation retrieves password and verifies CHAP response.
    fn authenticate_chap(
        &self,
        username: &str,
        chap_response: &ChapResponse,
        challenge: &ChapChallenge,
    ) -> bool {
        // Default implementation: get password and verify CHAP
        if let Some(password) = self.get_user_password(username) {
            verify_chap_response(chap_response, &password, challenge)
        } else {
            false
        }
    }

    /// Get user's plaintext password (for CHAP verification)
    ///
    /// Returns None if user doesn't exist or password retrieval is not supported.
    /// This is needed for CHAP authentication since the server must compute
    /// the expected response using the plaintext password.
    fn get_user_password(&self, _username: &str) -> Option<String> {
        None // Default: not supported
    }

    /// Multi-round authentication with challenge-response support
    ///
    /// This method is called when a request may require Access-Challenge.
    /// The default implementation calls authenticate() and returns Accept/Reject.
    ///
    /// # Arguments
    /// * `username` - The username from the request
    /// * `password` - The password from the request (if present)
    /// * `state` - The State attribute from the request (if this is a challenge response)
    ///
    /// # Returns
    /// AuthResult indicating Accept, Reject, or Challenge
    fn authenticate_with_challenge(
        &self,
        username: &str,
        password: Option<&str>,
        _state: Option<&[u8]>,
    ) -> AuthResult {
        // Default implementation: simple PAP authentication
        if let Some(pwd) = password {
            if self.authenticate(username, pwd) {
                AuthResult::accept()
            } else {
                AuthResult::Reject
            }
        } else {
            AuthResult::Reject
        }
    }

    /// Multi-round authentication with full request packet access
    ///
    /// This method provides access to the full RADIUS request packet, enabling
    /// authentication methods like EAP that need access to protocol-specific attributes.
    ///
    /// The default implementation extracts username, password, and state, then calls
    /// authenticate_with_challenge() for backward compatibility.
    ///
    /// # Arguments
    /// * `request` - The full RADIUS Access-Request packet
    /// * `secret` - The shared secret for this client
    ///
    /// # Returns
    /// AuthResult indicating Accept, Reject, or Challenge
    fn authenticate_request(&self, request: &Packet, secret: &[u8]) -> AuthResult {
        // Extract username
        let username = request
            .find_attribute(AttributeType::UserName as u8)
            .and_then(|attr| attr.as_string().ok())
            .unwrap_or_default();

        // Extract password (if PAP)
        let password = request
            .find_attribute(AttributeType::UserPassword as u8)
            .and_then(|attr| {
                decrypt_user_password(&attr.value, secret, &request.authenticator).ok()
            });

        // Extract state
        let state = request
            .find_attribute(AttributeType::State as u8)
            .map(|attr| attr.value.as_slice());

        // Delegate to authenticate_with_challenge for backward compatibility
        self.authenticate_with_challenge(&username, password.as_deref(), state)
    }

    /// Get additional attributes to include in Access-Accept response
    fn get_accept_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![]
    }

    /// Get additional attributes to include in Access-Reject response
    fn get_reject_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![Attribute::string(AttributeType::ReplyMessage as u8, "Authentication failed").unwrap()]
    }

    /// Get additional attributes to include in Access-Challenge response
    fn get_challenge_attributes(&self, _username: &str) -> Vec<Attribute> {
        vec![]
    }
}

/// Simple in-memory authentication handler for testing
pub struct SimpleAuthHandler {
    users: std::collections::HashMap<String, String>,
}

impl Default for SimpleAuthHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleAuthHandler {
    pub fn new() -> Self {
        SimpleAuthHandler {
            users: std::collections::HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }
}

impl AuthHandler for SimpleAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }

    fn get_user_password(&self, username: &str) -> Option<String> {
        self.users.get(username).cloned()
    }
}

/// RADIUS Server configuration
pub struct ServerConfig {
    /// Bind address for the server
    pub bind_addr: SocketAddr,
    /// Where Accounting-Request is accepted over UDP (RFC 2866 §2): a dedicated
    /// socket on `bind_addr.ip():<port>`, the authentication socket
    /// (`"shared"`), or nowhere (`"disabled"`).
    pub accounting_port: AccountingPort,
    /// Shared secret for authenticating clients (used if no client config provided)
    pub secret: Vec<u8>,
    /// Authentication handler
    pub auth_handler: Arc<dyn AuthHandler>,
    /// Accounting handler (optional)
    pub accounting_handler: Option<Arc<dyn AccountingHandler>>,
    /// Optional full configuration with client validation
    pub config: Option<Arc<Config>>,
    /// Request deduplication cache
    pub request_cache: Arc<RequestCache>,
    /// Rate limiter
    pub rate_limiter: Arc<RateLimiter>,
    /// Audit logger
    pub audit_logger: Arc<AuditLogger>,
    /// Buffer pool for memory optimization
    pub buffer_pool: Arc<BufferPool>,
    /// Proxy router (optional)
    pub router: Option<Arc<Router>>,
    /// Proxy handler (optional)
    pub proxy_handler: Option<Arc<ProxyHandler>>,
    /// Retry manager (optional)
    pub retry_manager: Option<Arc<RetryManager>>,
    /// Health checker (optional)
    pub health_checker: Option<Arc<crate::proxy::health::HealthChecker>>,
    /// Authorization policy, shared (and live-editable) with the management API.
    /// When present AND it has at least one policy set, it is enforced on
    /// Access-Accept (Phase 2b); otherwise the reply is unchanged.
    pub policy: Option<Arc<std::sync::RwLock<crate::policy::PolicyConfig>>>,
}

impl ServerConfig {
    pub fn new(
        bind_addr: SocketAddr,
        secret: impl Into<Vec<u8>>,
        auth_handler: Arc<dyn AuthHandler>,
    ) -> Self {
        // Default cache: 60 second TTL, 10000 max entries
        let request_cache = Arc::new(RequestCache::new(Duration::from_secs(60), 10000));

        // Default rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));

        // No audit logging by default
        let audit_logger = Arc::new(AuditLogger::new(None).unwrap());

        // Buffer pool: 4096 byte buffers, max 1000 pooled (reuse for UDP packets)
        let buffer_pool = BufferPool::new(4096, 1000);

        ServerConfig {
            bind_addr,
            // The library constructor keeps its single-socket contract:
            // Accounting-Request is accepted on the one bound socket.
            accounting_port: AccountingPort::Named(AccountingPortMode::Shared),
            secret: secret.into(),
            auth_handler,
            accounting_handler: None,
            config: None,
            request_cache,
            rate_limiter,
            audit_logger,
            buffer_pool,
            router: None,
            proxy_handler: None,
            retry_manager: None,
            health_checker: None,
            policy: None,
        }
    }

    /// Set the accounting handler
    pub fn with_accounting_handler(
        mut self,
        accounting_handler: Arc<dyn AccountingHandler>,
    ) -> Self {
        self.accounting_handler = Some(accounting_handler);
        self
    }

    /// Attach a shared (live-editable) authorization policy to enforce on accept.
    pub fn with_policy(
        mut self,
        policy: Arc<std::sync::RwLock<crate::policy::PolicyConfig>>,
    ) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Create server config from a full Config object
    pub fn from_config(
        config: Config,
        auth_handler: Arc<dyn AuthHandler>,
    ) -> Result<Self, ServerError> {
        let bind_addr = config.socket_addr().map_err(|e| {
            ServerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        let secret = config.secret.clone().into_bytes();

        // Create cache with configured TTL and max entries
        let ttl = Duration::from_secs(config.request_cache_ttl.unwrap_or(60));
        let max_entries = config.request_cache_max_entries.unwrap_or(10000);
        let request_cache = Arc::new(RequestCache::new(ttl, max_entries));

        // Create rate limiter with configured limits
        let rate_limit_config = RateLimitConfig {
            per_client_rps: config.rate_limit_per_client_rps.unwrap_or(100),
            per_client_burst: config.rate_limit_per_client_burst.unwrap_or(200),
            global_rps: config.rate_limit_global_rps.unwrap_or(1000),
            global_burst: config.rate_limit_global_burst.unwrap_or(2000),
            max_concurrent_connections: config.max_concurrent_connections.unwrap_or(100),
            max_bandwidth_bps: config.max_bandwidth_bps.unwrap_or(1_000_000), // 1 MB/s default
        };
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config));

        // Create audit logger if configured
        let audit_logger = Arc::new(AuditLogger::new(config.audit_log_path.clone())?);

        // Buffer pool: 4096 byte buffers, max 1000 pooled (reuse for UDP packets)
        let buffer_pool = BufferPool::new(4096, 1000);

        // Initialize proxy components if configured
        let (router, proxy_handler, retry_manager) = if let Some(ref proxy_config) = config.proxy {
            if proxy_config.enabled {
                // We'll need to create these components during RadiusServer::new()
                // because they need the socket, so we pass None here
                (None, None, None)
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        Ok(ServerConfig {
            bind_addr,
            accounting_port: config.accounting_port,
            secret,
            auth_handler,
            accounting_handler: None,
            config: Some(Arc::new(config)),
            request_cache,
            rate_limiter,
            audit_logger,
            buffer_pool,
            router,
            proxy_handler,
            retry_manager,
            health_checker: None,
            policy: None,
        })
    }

    /// Get the appropriate shared secret for a client IP address
    fn get_secret_for_client(&self, source_ip: std::net::IpAddr) -> &[u8] {
        if let Some(ref config) = self.config {
            config.get_secret_for_client(source_ip)
        } else {
            &self.secret
        }
    }

    /// Check if a client is authorized
    fn is_client_authorized(&self, source_ip: std::net::IpAddr) -> bool {
        // If no config is provided, allow all clients (backward compatibility)
        if let Some(ref config) = self.config {
            // If clients list is empty, allow all (backward compatibility)
            if config.clients.is_empty() {
                return true;
            }
            // Check if client is in the authorized list
            config.find_client(source_ip).is_some()
        } else {
            true
        }
    }
}

/// RADIUS Server
pub struct RadiusServer {
    config: Arc<ServerConfig>,
    /// UDP authentication socket (`listen_port`).
    socket: Arc<UdpSocket>,
    /// Dedicated UDP accounting socket (RFC 2866 §2), when `accounting_port`
    /// names one.
    accounting_socket: Option<Arc<UdpSocket>>,
    /// Home servers for health checking (if proxy is enabled)
    home_servers: Vec<Arc<crate::proxy::home_server::HomeServer>>,
    /// Home server pools (if proxy is enabled)
    pools: Vec<Arc<crate::proxy::pool::HomeServerPool>>,
}

impl RadiusServer {
    /// Create a new RADIUS server
    pub async fn new(mut config: ServerConfig) -> Result<Self, ServerError> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        let socket = Arc::new(socket);
        info!("RADIUS server listening on {}", config.bind_addr);

        // RFC 2866 §2: accounting has its own UDP port. Same IP as the
        // authentication socket, so dual-stack (`::`) and the v4-mapped source
        // canonicalisation in `handle_request` apply to both. A bind failure
        // (including a port clash with the auth socket in a non-validated
        // config) is fatal: the server does not start half-listening.
        let accounting_socket = match config.accounting_port.dedicated() {
            Some(port) => {
                let acct_addr = SocketAddr::new(config.bind_addr.ip(), port);
                let acct = UdpSocket::bind(acct_addr).await?;
                info!("RADIUS accounting listening on {}", acct_addr);
                Some(Arc::new(acct))
            }
            None => None,
        };

        let mut home_servers = Vec::new();
        let mut pools = Vec::new();

        // Initialize proxy components if enabled
        if let Some(ref full_config) = config.config
            && let Some(ref proxy_config) = full_config.proxy
            && proxy_config.enabled
        {
            info!("Initializing RADIUS proxy");

            // Create proxy components
            let (router, proxy_handler, retry_manager, health_checker, servers, server_pools) =
                Self::initialize_proxy(proxy_config, Arc::clone(&socket)).await?;

            config.router = Some(Arc::new(router));
            config.proxy_handler = Some(proxy_handler);
            config.retry_manager = Some(Arc::new(retry_manager));
            config.health_checker = health_checker.map(Arc::new);
            home_servers = servers;
            pools = server_pools;

            info!("RADIUS proxy initialized");
        }

        Ok(RadiusServer {
            config: Arc::new(config),
            socket,
            accounting_socket,
            home_servers,
            pools,
        })
    }

    /// Initialize proxy components from configuration
    async fn initialize_proxy(
        proxy_config: &ProxyConfig,
        socket: Arc<UdpSocket>,
    ) -> Result<
        (
            Router,
            Arc<ProxyHandler>,
            RetryManager,
            Option<crate::proxy::health::HealthChecker>,
            Vec<Arc<crate::proxy::home_server::HomeServer>>,
            Vec<Arc<crate::proxy::pool::HomeServerPool>>,
        ),
        ServerError,
    > {
        use crate::proxy::cache::ProxyCache;
        use crate::proxy::health::HealthChecker;

        // Create home server pools
        let mut pools = std::collections::HashMap::new();
        for pool_config in &proxy_config.pools {
            let pool = HomeServerPool::new(pool_config.clone()).map_err(|e| {
                ServerError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Failed to create pool '{}': {}", pool_config.name, e),
                ))
            })?;
            pools.insert(pool_config.name.clone(), Arc::new(pool));
        }

        // Create realms
        let mut realms = Vec::new();
        for realm_config in &proxy_config.realms {
            let pool = pools
                .get(&realm_config.pool)
                .ok_or_else(|| {
                    ServerError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Realm '{}' references unknown pool '{}'",
                            realm_config.name, realm_config.pool
                        ),
                    ))
                })?
                .clone();

            let realm = Realm::new(realm_config.clone(), pool).map_err(|e| {
                ServerError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Failed to create realm '{}': {}", realm_config.name, e),
                ))
            })?;
            realms.push(realm);
        }

        // Create router
        let router = Router::new(realms, proxy_config.default_realm.clone());

        // Create proxy cache
        let cache_ttl = Duration::from_secs(proxy_config.cache_ttl);
        let proxy_cache = Arc::new(ProxyCache::new(cache_ttl, proxy_config.max_outstanding));

        // Create the proxy handler. Home servers are reached through a socket of
        // its own on an ephemeral port (binding the listener's address again
        // would fail with EADDRINUSE), and home-server responses are read from
        // that socket by `listen_for_proxy_responses`. Replies to NASes go out
        // through the listening socket, so they come from the address:port the
        // NAS sent to. One handler serves both the request path and the retry
        // manager so retransmissions keep the same source port.
        let upstream_bind_addr: SocketAddr = match socket.local_addr()? {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let proxy_handler = Arc::new(
            ProxyHandler::new(Arc::clone(&proxy_cache), upstream_bind_addr)
                .await
                .map_err(|e| {
                    ServerError::Io(std::io::Error::other(format!(
                        "Failed to create proxy handler: {}",
                        e
                    )))
                })?
                .with_nas_socket(Arc::clone(&socket)),
        );

        // Create retry manager
        let retry_timeout = Duration::from_secs(proxy_config.proxy_timeout);
        let retry_manager = RetryManager::new(
            Arc::clone(&proxy_cache),
            Arc::clone(&proxy_handler),
            proxy_config.retry.clone(),
            retry_timeout,
        );

        // Collect all home servers and pools from all pools
        let mut all_servers = Vec::new();
        let mut all_pools = Vec::new();
        for pool in pools.values() {
            all_pools.push(Arc::clone(pool));
            for server in &pool.servers {
                all_servers.push(Arc::clone(server));
            }
        }

        // Create health checker if enabled
        let health_checker = if proxy_config.health_check.enabled {
            if !all_servers.is_empty() {
                // Each probe binds its own socket on an ephemeral port of this
                // address family (see `HealthChecker::check_server_health`).
                let health_bind_addr = match socket.local_addr()? {
                    std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                    std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
                };

                let checker =
                    HealthChecker::new(proxy_config.health_check.clone(), health_bind_addr);

                info!(
                    server_count = all_servers.len(),
                    interval = proxy_config.health_check.interval,
                    "Health checker created"
                );

                Some(checker)
            } else {
                warn!("Health checking enabled but no servers found in pools");
                None
            }
        } else {
            None
        };

        Ok((
            router,
            proxy_handler,
            retry_manager,
            health_checker,
            all_servers,
            all_pools,
        ))
    }

    /// Get the local address the server is listening on
    ///
    /// This is useful for testing when binding to port 0 (OS-assigned port)
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        self.socket.local_addr().map_err(ServerError::from)
    }

    /// Get the local address of the dedicated accounting socket, or `None`
    /// when `accounting_port` is `"shared"` or `"disabled"`.
    pub fn accounting_local_addr(&self) -> Result<Option<std::net::SocketAddr>, ServerError> {
        self.accounting_socket
            .as_ref()
            .map(|s| s.local_addr().map_err(ServerError::from))
            .transpose()
    }

    /// Get proxy statistics snapshot
    ///
    /// Returns aggregated statistics from all pools and servers if proxy is enabled.
    /// Returns None if proxy is not enabled.
    pub fn get_proxy_stats(&self) -> Option<crate::proxy::stats::ProxyStats> {
        if self.pools.is_empty() {
            None
        } else {
            Some(crate::proxy::stats::ProxyStats::collect(&self.pools))
        }
    }

    /// Start the server and handle incoming requests
    pub async fn run(&self) -> Result<(), ServerError> {
        // Start retry manager if proxy is enabled
        let _retry_task = self
            .config
            .retry_manager
            .as_ref()
            .map(|retry_manager| retry_manager.start());

        // Start health checker if proxy is enabled
        let _health_task = self
            .config
            .health_checker
            .as_ref()
            .and_then(|health_checker| {
                if !self.home_servers.is_empty() {
                    info!(
                        "Starting health checker for {} home servers",
                        self.home_servers.len()
                    );
                    Some(health_checker.start(self.home_servers.clone()))
                } else {
                    None
                }
            });

        // Start response listener task if proxy is enabled
        let _response_task = if let Some(ref proxy_handler) = self.config.proxy_handler {
            let handler = Arc::clone(proxy_handler);
            let socket = handler.socket();
            let buffer_pool = Arc::clone(&self.config.buffer_pool);
            Some(tokio::spawn(async move {
                Self::listen_for_proxy_responses(handler, socket, buffer_pool).await;
            }))
        } else {
            None
        };

        // Serve the authentication socket and, when bound, the accounting
        // socket (RFC 2866 §2) from this one task: each future only receives
        // and spawns, and the first socket error ends `run` as before.
        let auth = Self::serve_socket(
            Arc::clone(&self.socket),
            PortRole::Auth,
            Arc::clone(&self.config),
        );
        match &self.accounting_socket {
            Some(acct) => {
                let acct = Self::serve_socket(
                    Arc::clone(acct),
                    PortRole::Accounting,
                    Arc::clone(&self.config),
                );
                tokio::try_join!(auth, acct)?;
            }
            None => auth.await?,
        }
        Ok(())
    }

    /// Receive loop for one UDP listener: every datagram is handed to
    /// `handle_request` with the socket it arrived on (so the reply leaves from
    /// the same port) and that socket's `role`.
    async fn serve_socket(
        socket: Arc<UdpSocket>,
        role: PortRole,
        config: Arc<ServerConfig>,
    ) -> Result<(), ServerError> {
        loop {
            // Acquire a buffer from the pool
            let mut pooled_buf = config.buffer_pool.acquire().await;

            // Receive packet into pooled buffer
            let (len, addr) = socket.recv_from(pooled_buf.as_mut()).await?;

            // Copy the received data (only the received bytes, not the full buffer)
            let data = pooled_buf.as_ref()[..len].to_vec();

            // Buffer is automatically returned to pool when pooled_buf is dropped

            // Spawn a task to handle this request
            let config = Arc::clone(&config);
            let socket = Arc::clone(&socket);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_request(data, addr, role, config, socket).await {
                    debug!("Error handling request from {}: {}", addr, e);
                }
            });
        }
    }

    /// Listen for responses from home servers
    async fn listen_for_proxy_responses(
        proxy_handler: Arc<ProxyHandler>,
        socket: Arc<UdpSocket>,
        buffer_pool: Arc<BufferPool>,
    ) {
        info!("Proxy response listener started");

        loop {
            // Acquire a buffer from the pool
            let mut pooled_buf = buffer_pool.acquire().await;

            match socket.recv_from(pooled_buf.as_mut()).await {
                Ok((len, addr)) => {
                    // Copy the received data (only the received bytes)
                    let data = pooled_buf.as_ref()[..len].to_vec();
                    // Buffer is automatically returned to pool when pooled_buf is dropped
                    let handler = Arc::clone(&proxy_handler);

                    // Spawn task to handle response
                    tokio::spawn(async move {
                        // Decode the packet first
                        match Packet::decode(&data) {
                            Ok(response) => {
                                if let Err(e) = handler.handle_response(response, addr).await {
                                    debug!("Error handling proxy response from {}: {}", addr, e);
                                }
                            }
                            Err(e) => {
                                warn!("Failed to decode proxy response from {}: {}", addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("Error receiving proxy response: {}", e);
                    // Continue listening even after errors
                }
            }
        }
    }

    /// Handle a single RADIUS request received on `socket`, which plays `role`.
    async fn handle_request(
        data: Vec<u8>,
        addr: SocketAddr,
        role: PortRole,
        config: Arc<ServerConfig>,
        socket: Arc<UdpSocket>,
    ) -> Result<(), ServerError> {
        // Normalize IPv4-mapped IPv6 sources (`::ffff:a.b.c.d`) to plain IPv4. When
        // the server binds dual-stack (`[::]`), IPv4 datagrams arrive with a
        // v4-mapped source address; without this, IPv4 client/secret CIDRs (e.g.
        // `10.0.0.0/8`) never match and every IPv4 NAS is rejected as unauthorized.
        // Canonicalizing here keeps the whole pipeline — authorization, secret
        // selection, rate limiting, dedup, and audit logs — consistent.
        let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());

        // Check rate limit FIRST (before any expensive operations)
        if !config.rate_limiter.check_rate_limit(addr.ip()).await {
            let request_id = if data.len() >= 2 { data[1] } else { 0 };
            warn!(
                client_ip = %addr.ip(),
                request_id = request_id,
                "Rate limit exceeded"
            );

            // Audit log rate limit event
            config
                .audit_logger
                .log(
                    AuditEntry::new(AuditEventType::RateLimitExceeded)
                        .with_client_ip(addr.ip())
                        .with_request_id(request_id),
                )
                .await;

            return Err(ServerError::RateLimited);
        }

        // RFC 2865 Section 3: Validate source IP address
        if !config.is_client_authorized(addr.ip()) {
            let request_id = if data.len() >= 2 { data[1] } else { 0 };
            warn!(
                client_ip = %addr.ip(),
                request_id = request_id,
                "Rejected request from unauthorized client"
            );

            // Audit log unauthorized client event
            config
                .audit_logger
                .log(
                    AuditEntry::new(AuditEventType::UnauthorizedClient)
                        .with_client_ip(addr.ip())
                        .with_request_id(request_id),
                )
                .await;

            return Err(ServerError::InvalidClient);
        }

        // Resolve the shared secret from the source IP (UDP transport) and run the
        // transport-agnostic processing pipeline, then send any response back over
        // UDP. RadSec calls `process_request` directly with the fixed "radsec"
        // secret and writes the response over its TLS stream.
        let secret = config.get_secret_for_client(addr.ip()).to_vec();
        if let Some(response_data) =
            Self::process_request(&data, addr, &secret, role, &config).await?
        {
            socket.send_to(&response_data, addr).await?;
        }

        Ok(())
    }

    /// Transport-agnostic RADIUS request pipeline: decode, validate, replay-check,
    /// dispatch by packet type, and encode the response. Returns the response
    /// bytes to send (or `None` for request types that warrant no reply).
    ///
    /// `secret` is the shared secret to use for Response/Message-Authenticator
    /// computation — the per-client secret for UDP, or the fixed `"radsec"` for
    /// RadSec (RFC 6614 §2.3). `source` is the peer address, used for policy
    /// conditions (NAS-IP), logging, replay fingerprinting, and as the
    /// destination of a proxied response. `role` is the listener the packet
    /// arrived on: it gates which codes are admitted (RFC 2866 §2) and which
    /// code answers Status-Server (RFC 5997 §4.2); RadSec passes
    /// `PortRole::Any` (RFC 6614 §2.5).
    pub(crate) async fn process_request(
        data: &[u8],
        source: SocketAddr,
        secret: &[u8],
        role: PortRole,
        config: &Arc<ServerConfig>,
    ) -> Result<Option<Vec<u8>>, ServerError> {
        let source_ip = source.ip();
        // Decode the packet
        let request = Packet::decode(data)?;

        // Validate the packet
        let validation_mode = if config
            .config
            .as_ref()
            .map(|c| c.strict_rfc_compliance)
            .unwrap_or(false)
        {
            ValidationMode::Strict
        } else {
            ValidationMode::Lenient
        };

        if let Err(e) = validate_packet(&request, validation_mode) {
            warn!(
                client_ip = %source_ip,
                request_id = request.identifier,
                error = %e,
                "Rejected malformed packet"
            );
            return Err(ServerError::Validation(e.to_string()));
        }

        // RFC 2866 §2: a code that does not belong on this listener is
        // discarded silently, before the duplicate cache so the discard path
        // leaves no state behind.
        if !role.admits(
            request.code,
            config.accounting_port.accepts_accounting_on_auth_socket(),
        ) {
            warn!(
                client_ip = %source_ip,
                request_id = request.identifier,
                packet_type = ?request.code,
                port_role = ?role,
                "Discarded packet: code not accepted on this port (RFC 2866 §2)"
            );
            return Ok(None);
        }

        // Check for duplicate request (replay attack prevention)
        let fingerprint =
            RequestFingerprint::new(source_ip, request.identifier, &request.authenticator);
        if config
            .request_cache
            .is_duplicate(fingerprint, request.authenticator)
        {
            warn!(
                client_ip = %source_ip,
                request_id = request.identifier,
                "Rejected duplicate request"
            );

            // Audit log duplicate request event
            config
                .audit_logger
                .log(
                    AuditEntry::new(AuditEventType::DuplicateRequest)
                        .with_client_ip(source_ip)
                        .with_request_id(request.identifier),
                )
                .await;

            return Err(ServerError::DuplicateRequest);
        }

        debug!(
            packet_type = ?request.code,
            client_ip = %source_ip,
            request_id = request.identifier,
            "Received RADIUS packet"
        );

        // Handle based on packet type
        let response = match request.code {
            Code::AccessRequest => {
                Self::handle_access_request(&request, config, source, secret).await?
            }
            Code::AccountingRequest => {
                Self::handle_accounting_request(&request, config, source_ip, secret).await?
            }
            Code::StatusServer => {
                match Self::handle_status_server(&request, source_ip, secret, role)? {
                    Some(response) => response,
                    // RFC 5997 §4.1: silent discard, nothing on the wire.
                    None => return Ok(None),
                }
            }
            _ => {
                warn!(packet_type = ?request.code, "Unsupported packet type");
                return Ok(None);
            }
        };

        // Encode the response
        let response_data = response.encode()?;

        debug!(
            response_type = ?response.code,
            client_ip = %source_ip,
            request_id = response.identifier,
            "Encoded RADIUS response"
        );

        Ok(Some(response_data))
    }

    /// Handle Access-Request packet
    async fn handle_access_request(
        request: &Packet,
        config: &ServerConfig,
        source: SocketAddr,
        secret: &[u8],
    ) -> Result<Packet, ServerError> {
        let source_ip = source.ip();
        // Check if proxy routing is enabled
        if let (Some(router), Some(proxy_handler)) = (&config.router, &config.proxy_handler) {
            // Route the request
            let routing_decision = router.route_request(request);

            match routing_decision {
                RoutingDecision::Proxy {
                    home_server,
                    stripped_username,
                } => {
                    // Proxy the request
                    debug!(
                        home_server = %home_server.name,
                        "Proxying request to home server"
                    );

                    // Modify request if realm should be stripped
                    let mut forwarded_request = request.clone();
                    if let Some(stripped) = stripped_username {
                        // Replace User-Name attribute with stripped version
                        forwarded_request
                            .attributes
                            .retain(|attr| attr.attr_type != AttributeType::UserName as u8);
                        forwarded_request.add_attribute(
                            Attribute::string(AttributeType::UserName as u8, &stripped)
                                .map_err(|_| ServerError::AuthFailed)?,
                        );
                    }

                    // Forward to the home server using the resolved shared secret
                    // (per-client for UDP, "radsec" for RadSec).
                    let secret = secret.to_vec();

                    // Forward the request. The NAS's full address (IP *and*
                    // port) is what the relayed response is sent back to.
                    proxy_handler
                        .forward_request(forwarded_request, source, home_server, secret)
                        .await
                        .map_err(|e| {
                            warn!("Proxy forwarding failed: {}", e);
                            ServerError::Io(std::io::Error::other(format!(
                                "Proxy forwarding failed: {}",
                                e
                            )))
                        })?;

                    // Return empty response - actual response will come from proxy handler
                    // We'll handle this differently - for now, return a reject as placeholder
                    // In a real implementation, we'd need a different approach
                    // For now, we'll just continue to local auth which will handle the response
                    // This needs architectural refinement - the proxy response is async
                    return Err(ServerError::Io(std::io::Error::other(
                        "Request forwarded to proxy - response will be sent asynchronously",
                    )));
                }
                RoutingDecision::Reject => {
                    // Reject immediately
                    warn!("Routing decision: Reject");
                    return Err(ServerError::AuthFailed);
                }
                RoutingDecision::Local => {
                    // Continue with local authentication
                    debug!("Routing decision: Local authentication");
                }
            }
        }

        // `secret` is provided by the caller (per-client for UDP, "radsec" for
        // RadSec) and used for the Response/Message-Authenticator below.

        // Extract username
        let username = request
            .find_attribute(AttributeType::UserName as u8)
            .and_then(|attr| attr.as_string().ok())
            .ok_or(ServerError::AuthFailed)?;

        info!(
            username = %username,
            client_ip = %source_ip,
            request_id = request.identifier,
            "Authentication request received"
        );

        // RFC 2865 Section 5.32: Validate NAS-Identifier or NAS-IP-Address presence
        let has_nas_ip = request
            .find_attribute(AttributeType::NasIpAddress as u8)
            .is_some();
        let nas_identifier = request
            .find_attribute(AttributeType::NasIdentifier as u8)
            .and_then(|attr| attr.as_string().ok());

        if !has_nas_ip && nas_identifier.is_none() {
            warn!(
                client_ip = %source_ip,
                request_id = request.identifier,
                "Access-Request missing both NAS-IP-Address and NAS-Identifier"
            );
            return Err(ServerError::Validation(
                "Access-Request MUST contain either NAS-IP-Address or NAS-Identifier (RFC 2865)"
                    .to_string(),
            ));
        }

        // Validate NAS-Identifier if client has one configured
        if let Some(client_config) = config
            .config
            .as_ref()
            .and_then(|c| c.find_client(source_ip))
            && let Some(expected_nas_id) = &client_config.nas_identifier
        {
            match &nas_identifier {
                Some(actual_nas_id) => {
                    if actual_nas_id != expected_nas_id {
                        warn!(
                            client_ip = %source_ip,
                            request_id = request.identifier,
                            expected = %expected_nas_id,
                            actual = %actual_nas_id,
                            "NAS-Identifier mismatch"
                        );
                        return Err(ServerError::Validation(format!(
                            "NAS-Identifier mismatch: expected '{}', got '{}'",
                            expected_nas_id, actual_nas_id
                        )));
                    }
                }
                None => {
                    warn!(
                        client_ip = %source_ip,
                        request_id = request.identifier,
                        expected = %expected_nas_id,
                        "Missing required NAS-Identifier"
                    );
                    return Err(ServerError::Validation(format!(
                        "Missing required NAS-Identifier: expected '{}'",
                        expected_nas_id
                    )));
                }
            }
        }

        // RFC 3579 §3.2 / RFC 5080 / "Blast-RADIUS" (CVE-2024-3596): an
        // Access-Request that carries EAP-Message MUST also carry a valid
        // Message-Authenticator. Verify it whenever present, and reject an
        // EAP-bearing request that omits it — otherwise an attacker could strip
        // the attribute to defeat the integrity check.
        match check_message_authenticator(request, secret)? {
            MessageAuthenticatorCheck::Valid => {
                debug!(
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Message-Authenticator validated successfully"
                );
            }
            MessageAuthenticatorCheck::Invalid => {
                warn!(
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Invalid Message-Authenticator"
                );
                return Err(ServerError::Validation(
                    "Invalid Message-Authenticator".to_string(),
                ));
            }
            MessageAuthenticatorCheck::Absent => {
                if request
                    .find_attribute(AttributeType::EapMessage as u8)
                    .is_some()
                {
                    warn!(
                        client_ip = %source_ip,
                        request_id = request.identifier,
                        "Rejected EAP Access-Request without required Message-Authenticator (RFC 3579 / Blast-RADIUS)"
                    );
                    return Err(ServerError::Validation(
                        "EAP Access-Request missing required Message-Authenticator".to_string(),
                    ));
                }
            }
        }

        // Audit log authentication attempt
        let client_name = config
            .config
            .as_ref()
            .and_then(|c| c.find_client(source_ip))
            .and_then(|client| client.name.clone());

        config
            .audit_logger
            .log(
                AuditEntry::new(AuditEventType::AuthAttempt)
                    .with_username(&username)
                    .with_client_ip(source_ip)
                    .with_request_id(request.identifier)
                    .with_client_name(client_name.unwrap_or_else(|| "unknown".to_string())),
            )
            .await;

        // Determine authentication method and get result
        let auth_result = if let Some(chap_password_attr) =
            request.find_attribute(AttributeType::ChapPassword as u8)
        {
            // CHAP authentication - always returns Accept or Reject (no challenge)
            debug!(
                username = %username,
                "Using CHAP authentication"
            );

            // Parse CHAP-Password attribute (17 bytes: 1 byte ident + 16 bytes response)
            let chap_response =
                ChapResponse::from_bytes(&chap_password_attr.value).map_err(|e| {
                    warn!(username = %username, error = %e, "Invalid CHAP-Password attribute");
                    ServerError::AuthFailed
                })?;

            // Get CHAP challenge (from CHAP-Challenge attribute or Request Authenticator)
            let challenge = if let Some(chap_challenge_attr) =
                request.find_attribute(AttributeType::ChapChallenge as u8)
            {
                ChapChallenge::new(chap_challenge_attr.value.clone())
            } else {
                ChapChallenge::from_authenticator(&request.authenticator)
            };

            // Verify CHAP response using the auth handler
            if config
                .auth_handler
                .authenticate_chap(&username, &chap_response, &challenge)
            {
                AuthResult::accept()
            } else {
                AuthResult::Reject
            }
        } else {
            // Use new authenticate_request method which has access to full packet
            // This enables EAP and other protocol-specific authentication
            debug!(
                username = %username,
                "Using authenticate_request for flexible authentication"
            );

            config.auth_handler.authenticate_request(request, secret)
        };

        // Handle authentication result
        match auth_result {
            AuthResult::Accept {
                attributes: extra_attrs,
                msk,
            } => {
                info!(
                    username = %username,
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Authentication successful"
                );

                // Audit log authentication success
                let client_name = config
                    .config
                    .as_ref()
                    .and_then(|c| c.find_client(source_ip))
                    .and_then(|client| client.name.clone());

                config
                    .audit_logger
                    .log(
                        AuditEntry::new(AuditEventType::AuthSuccess)
                            .with_username(&username)
                            .with_client_ip(source_ip)
                            .with_request_id(request.identifier)
                            .with_client_name(
                                client_name.clone().unwrap_or_else(|| "unknown".to_string()),
                            ),
                    )
                    .await;

                // Create Access-Accept response
                let mut response = Packet::new(Code::AccessAccept, request.identifier, [0u8; 16]);

                // Add attributes from auth handler
                for attr in config.auth_handler.get_accept_attributes(&username) {
                    response.add_attribute(attr);
                }

                // Plus any extra attributes the AuthResult carries
                // (e.g., EAP-Success EAP-Message from an EAP handler).
                for attr in extra_attrs {
                    response.add_attribute(attr);
                }

                // RFC 2548 §2.4: hand the EAP MSK to the NAS as MS-MPPE-Recv-Key /
                // MS-MPPE-Send-Key. The keys are encrypted under this request's
                // authenticator and the transport's shared secret, so this is
                // the one place with everything needed. A key-deriving method
                // whose keys cannot be encoded must not yield a usable
                // session — fail the request rather than send a keyless Accept
                // that would strand the supplicant in the 4-way handshake.
                if let Some(msk) = msk {
                    let attrs = MppeKeys::from_msk(&msk)
                        .and_then(|keys| keys.to_attributes(secret, &request.authenticator))
                        .map_err(|e| {
                            error!(
                                username = %username,
                                error = %e,
                                "Failed to encode MS-MPPE keys for Access-Accept"
                            );
                            ServerError::AuthFailed
                        })?;
                    for attr in attrs {
                        response.add_attribute(attr);
                    }
                }

                // Phase 2b: enforce the authorization policy. Only active when a
                // policy with at least one policy set is loaded; otherwise the
                // accept is unchanged. A poisoned lock is recovered (read-only use)
                // rather than panicking the request handler.
                if let Some(policy_lock) = config.policy.as_ref() {
                    // Evaluate under the lock in a tight scope that yields an OWNED
                    // Decision, so the non-Send RwLockReadGuard is dropped before the
                    // audit `.await` below (the future must stay Send).
                    let decision = {
                        let guard = policy_lock
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if guard.policy_sets.is_empty() {
                            None
                        } else {
                            let ctx = crate::policy_enforce::request_context(request, &username);
                            Some(guard.evaluate(&ctx))
                        }
                    };
                    if let Some(decision) = decision {
                        match decision.effect {
                            crate::policy::Effect::Reject => {
                                warn!(
                                    username = %username,
                                    reason = %decision.reason,
                                    "Authorization policy denied access"
                                );

                                // Audit the authorization denial. Authentication
                                // itself succeeded (logged above), so this is a
                                // distinct AuthFailure carrying the policy reason —
                                // without it, the audit trail shows only the success
                                // and the access reject is invisible.
                                config
                                    .audit_logger
                                    .log(
                                        AuditEntry::new(AuditEventType::AuthFailure)
                                            .with_username(&username)
                                            .with_client_ip(source_ip)
                                            .with_request_id(request.identifier)
                                            .with_client_name(
                                                client_name
                                                    .clone()
                                                    .unwrap_or_else(|| "unknown".to_string()),
                                            )
                                            .with_details(format!(
                                                "authorization policy denied: {}",
                                                decision.reason
                                            )),
                                    )
                                    .await;

                                // Build the reject, preserving EAP semantics: if this
                                // was an EAP conversation the reject MUST carry an
                                // EAP-Failure EAP-Message (RFC 3579 §2.6.3), else the
                                // supplicant sees a malformed/again-Success state. The
                                // Message-Authenticator is added below for any reply
                                // that ends up carrying EAP-Message.
                                response =
                                    Packet::new(Code::AccessReject, request.identifier, [0u8; 16]);
                                if let Some(eap_id) = request
                                    .find_attribute(AttributeType::EapMessage as u8)
                                    .and_then(|a| a.value.get(1).copied())
                                {
                                    let failure =
                                        radius_proto::eap::EapPacket::failure(eap_id).to_bytes();
                                    if let Ok(a) =
                                        Attribute::new(AttributeType::EapMessage as u8, failure)
                                    {
                                        response.add_attribute(a);
                                    }
                                }
                                if let Some(msg) = decision.reply_message
                                    && let Ok(a) =
                                        Attribute::string(AttributeType::ReplyMessage as u8, msg)
                                {
                                    response.add_attribute(a);
                                }
                            }
                            crate::policy::Effect::Accept => {
                                for ra in &decision.attributes {
                                    match crate::policy_enforce::reply_attribute(ra) {
                                        Some(a) => add_policy_reply_attribute(&mut response, a),
                                        None => tracing::debug!(
                                            attribute = %ra.name,
                                            "policy reply attribute not encodable; skipped"
                                        ),
                                    }
                                }
                                if let Some(msg) = &decision.reply_message
                                    && let Ok(a) = Attribute::string(
                                        AttributeType::ReplyMessage as u8,
                                        msg.clone(),
                                    )
                                {
                                    response.add_attribute(a);
                                }
                            }
                        }
                    }
                }

                copy_proxy_state(request, &mut response);

                // RFC 3579 §3.2: add Message-Authenticator if response carries
                // EAP-Message. Must happen BEFORE Response-Authenticator so the
                // latter covers the final MA bytes.
                add_message_authenticator_if_eap(&mut response, &request.authenticator, secret)
                    .map_err(|_| ServerError::AuthFailed)?;

                // Calculate and set Response Authenticator using client-specific secret
                let response_auth =
                    calculate_response_authenticator(&response, &request.authenticator, secret);
                response.authenticator = response_auth;

                Ok(response)
            }
            AuthResult::Challenge {
                message,
                state,
                attributes,
            } => {
                info!(
                    username = %username,
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Sending Access-Challenge"
                );

                // Create Access-Challenge response
                let mut response =
                    Packet::new(Code::AccessChallenge, request.identifier, [0u8; 16]);

                // Add State attribute (required for Access-Challenge)
                response.add_attribute(
                    Attribute::new(AttributeType::State as u8, state)
                        .map_err(|_| ServerError::AuthFailed)?,
                );

                // Add Reply-Message if provided
                if let Some(msg) = message {
                    response.add_attribute(
                        Attribute::string(AttributeType::ReplyMessage as u8, &msg)
                            .map_err(|_| ServerError::AuthFailed)?,
                    );
                }

                // Add additional attributes
                for attr in attributes {
                    response.add_attribute(attr);
                }

                // Add attributes from auth handler
                for attr in config.auth_handler.get_challenge_attributes(&username) {
                    response.add_attribute(attr);
                }

                copy_proxy_state(request, &mut response);

                // RFC 3579 §3.2: add Message-Authenticator if response carries
                // EAP-Message. Must happen BEFORE Response-Authenticator so the
                // latter covers the final MA bytes.
                add_message_authenticator_if_eap(&mut response, &request.authenticator, secret)
                    .map_err(|_| ServerError::AuthFailed)?;

                // Calculate and set Response Authenticator using client-specific secret
                let response_auth =
                    calculate_response_authenticator(&response, &request.authenticator, secret);
                response.authenticator = response_auth;

                Ok(response)
            }
            AuthResult::Reject => {
                warn!(
                    username = %username,
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Authentication failed"
                );

                // Audit log authentication failure
                let client_name = config
                    .config
                    .as_ref()
                    .and_then(|c| c.find_client(source_ip))
                    .and_then(|client| client.name.clone());

                config
                    .audit_logger
                    .log(
                        AuditEntry::new(AuditEventType::AuthFailure)
                            .with_username(&username)
                            .with_client_ip(source_ip)
                            .with_request_id(request.identifier)
                            .with_client_name(client_name.unwrap_or_else(|| "unknown".to_string()))
                            .with_details("Invalid credentials"),
                    )
                    .await;

                // Create Access-Reject response
                let mut response = Packet::new(Code::AccessReject, request.identifier, [0u8; 16]);

                // RFC 3579 §2.6.3: an Access-Reject that ends an EAP conversation
                // carries an EAP-Failure EAP-Message (Identifier = the peer's last
                // EAP-Response), so the supplicant terminates the method cleanly
                // instead of retrying or waiting for a timeout. The method may
                // fail deep inside the TLS handshake (bad chain, revoked
                // certificate), where the handler only returns `Reject`, so the
                // EAP-Failure is attached here for every EAP reject.
                if let Some(eap_id) = request
                    .find_attribute(AttributeType::EapMessage as u8)
                    .and_then(|a| a.value.get(1).copied())
                    && let Ok(a) = Attribute::new(
                        AttributeType::EapMessage as u8,
                        radius_proto::eap::EapPacket::failure(eap_id).to_bytes(),
                    )
                {
                    response.add_attribute(a);
                }

                // Add attributes from auth handler
                for attr in config.auth_handler.get_reject_attributes(&username) {
                    response.add_attribute(attr);
                }

                copy_proxy_state(request, &mut response);

                // RFC 3579 §3.2: add Message-Authenticator if response carries
                // EAP-Message. Must happen BEFORE Response-Authenticator so the
                // latter covers the final MA bytes.
                add_message_authenticator_if_eap(&mut response, &request.authenticator, secret)
                    .map_err(|_| ServerError::AuthFailed)?;

                // Calculate and set Response Authenticator using client-specific secret
                let response_auth =
                    calculate_response_authenticator(&response, &request.authenticator, secret);
                response.authenticator = response_auth;

                Ok(response)
            }
        }
    }

    /// Handle Accounting-Request packet (RFC 2866)
    async fn handle_accounting_request(
        request: &Packet,
        config: &ServerConfig,
        source_ip: std::net::IpAddr,
        secret: &[u8],
    ) -> Result<Packet, ServerError> {
        // Check if accounting is enabled
        let accounting_handler = config
            .accounting_handler
            .as_ref()
            .ok_or_else(|| ServerError::Validation("Accounting not enabled".to_string()))?;

        // `secret` is provided by the caller (per-client for UDP, "radsec" for RadSec).

        // Validate Request Authenticator (RFC 2866 Section 3)
        // The Request Authenticator must be MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
        // We need to create a copy of the packet with authenticator set to zeros for validation
        let mut validation_packet = request.clone();
        validation_packet.authenticator = [0u8; 16];
        let expected_auth = calculate_accounting_request_authenticator(&validation_packet, secret);

        if request.authenticator != expected_auth {
            warn!(
                client_ip = %source_ip,
                request_id = request.identifier,
                "Invalid Request Authenticator in Accounting-Request"
            );
            return Err(ServerError::Validation(
                "Invalid Request Authenticator".to_string(),
            ));
        }

        // Extract Acct-Status-Type (required)
        let status_type_attr = request
            .find_attribute(AttributeType::AcctStatusType as u8)
            .ok_or_else(|| {
                warn!(
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Missing Acct-Status-Type attribute"
                );
                ServerError::Validation("Missing Acct-Status-Type attribute".to_string())
            })?;

        if status_type_attr.value.len() < 4 {
            return Err(ServerError::Validation(
                "Invalid Acct-Status-Type attribute".to_string(),
            ));
        }

        let status_type_value = u32::from_be_bytes([
            status_type_attr.value[0],
            status_type_attr.value[1],
            status_type_attr.value[2],
            status_type_attr.value[3],
        ]);

        let status_type = AcctStatusType::from_u32(status_type_value).ok_or_else(|| {
            warn!(
                client_ip = %source_ip,
                request_id = request.identifier,
                status_type = status_type_value,
                "Invalid Acct-Status-Type value"
            );
            ServerError::Validation(format!("Invalid Acct-Status-Type: {}", status_type_value))
        })?;

        debug!(
            client_ip = %source_ip,
            request_id = request.identifier,
            status_type = ?status_type,
            "Accounting request received"
        );

        // Handle based on status type
        let result = if status_type.is_session_status() {
            // Session-related accounting (Start, Stop, Interim-Update)
            // Extract session ID and username (required for session accounting)
            let session_id = request
                .find_attribute(AttributeType::AcctSessionId as u8)
                .and_then(|attr| attr.as_string().ok())
                .ok_or_else(|| {
                    ServerError::Validation("Missing Acct-Session-Id attribute".to_string())
                })?;

            let username = request
                .find_attribute(AttributeType::UserName as u8)
                .and_then(|attr| attr.as_string().ok())
                .ok_or_else(|| {
                    ServerError::Validation("Missing User-Name attribute".to_string())
                })?;

            info!(
                username = %username,
                session_id = %session_id,
                client_ip = %source_ip,
                request_id = request.identifier,
                status_type = ?status_type,
                "Processing accounting request"
            );

            // Route to appropriate handler method
            match status_type {
                AcctStatusType::Start => {
                    accounting_handler
                        .handle_start(&session_id, &username, source_ip, request)
                        .await?
                }
                AcctStatusType::Stop => {
                    accounting_handler
                        .handle_stop(&session_id, &username, source_ip, request)
                        .await?
                }
                AcctStatusType::InterimUpdate => {
                    accounting_handler
                        .handle_interim_update(&session_id, &username, source_ip, request)
                        .await?
                }
                _ => unreachable!(), // is_session_status() guarantees these three
            }
        } else {
            // NAS-related accounting (Accounting-On, Accounting-Off)
            info!(
                client_ip = %source_ip,
                request_id = request.identifier,
                status_type = ?status_type,
                "Processing NAS accounting request"
            );

            match status_type {
                AcctStatusType::AccountingOn => {
                    accounting_handler
                        .handle_accounting_on(source_ip, request)
                        .await?
                }
                AcctStatusType::AccountingOff => {
                    accounting_handler
                        .handle_accounting_off(source_ip, request)
                        .await?
                }
                _ => unreachable!(), // is_nas_status() guarantees these two
            }
        };

        // Check result
        match result {
            crate::accounting::AccountingResult::Success => {
                info!(
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    status_type = ?status_type,
                    "Accounting request successful"
                );
            }
            crate::accounting::AccountingResult::Failure(reason) => {
                warn!(
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    status_type = ?status_type,
                    reason = %reason,
                    "Accounting request failed"
                );
            }
        }

        // Create Accounting-Response (always success per RFC 2866)
        let mut response = Packet::new(Code::AccountingResponse, request.identifier, [0u8; 16]);

        copy_proxy_state(request, &mut response);

        // Calculate and set Response Authenticator using client-specific secret
        let response_auth =
            calculate_response_authenticator(&response, &request.authenticator, secret);
        response.authenticator = response_auth;

        Ok(response)
    }

    /// Handle Status-Server packet (RFC 5997).
    ///
    /// Returns `Ok(None)` when the request must be silently discarded
    /// (RFC 5997 §4.1: Message-Authenticator absent or invalid), otherwise the
    /// reply the role calls for (§4.2): Access-Accept on the authentication
    /// port and over RadSec, Accounting-Response on the accounting port. The
    /// proxy answers for itself and never forwards (§4.3) because this runs
    /// before any routing.
    fn handle_status_server(
        request: &Packet,
        source_ip: std::net::IpAddr,
        secret: &[u8],
        role: PortRole,
    ) -> Result<Option<Packet>, ServerError> {
        debug!(
            client_ip = %source_ip,
            request_id = request.identifier,
            port_role = ?role,
            "Status-Server request received"
        );

        // RFC 5997 §4.1: the request MUST contain a Message-Authenticator, the
        // server MUST validate it, and a packet failing the check MUST be
        // silently discarded. `secret` is the hop's secret (per-client for
        // UDP, "radsec" for RadSec).
        match check_message_authenticator(request, secret)? {
            MessageAuthenticatorCheck::Valid => {}
            MessageAuthenticatorCheck::Absent => {
                warn!(
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Discarded Status-Server without Message-Authenticator (RFC 5997 §4.1)"
                );
                return Ok(None);
            }
            MessageAuthenticatorCheck::Invalid => {
                warn!(
                    client_ip = %source_ip,
                    request_id = request.identifier,
                    "Discarded Status-Server with invalid Message-Authenticator (RFC 5997 §4.1)"
                );
                return Ok(None);
            }
        }

        // RFC 5997 §4.2: the reply code follows the port the request came in on.
        let mut response = Packet::new(
            role.status_server_reply_code(),
            request.identifier,
            [0u8; 16],
        );

        // RFC 5997 §4.1 / RFC 2865 §5.33: Proxy-State is echoed unmodified.
        copy_proxy_state(request, &mut response);

        // RFC 5997 §4.1: the reply MUST contain a Message-Authenticator. Added
        // before the Response Authenticator so the latter covers the MA bytes.
        add_message_authenticator(&mut response, &request.authenticator, secret)?;

        // RFC 2865 §3 / RFC 2866 §3: Response Authenticator over the final
        // attribute bytes, keyed by the hop secret.
        response.authenticator =
            calculate_response_authenticator(&response, &request.authenticator, secret);

        Ok(Some(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Proxy: socket layout and end-to-end relay ---

    /// A proxy config with one home server at `home` for realm `home.test`.
    fn proxy_config(home: SocketAddr, listen_port: u16) -> Config {
        use crate::proxy::ProxyConfig;
        use crate::proxy::health::HealthCheckConfig;
        use crate::proxy::home_server::HomeServerConfig;
        use crate::proxy::pool::HomeServerPoolConfig;
        use crate::proxy::realm::{RealmConfig, RealmMatchConfig};

        Config {
            listen_address: "127.0.0.1".to_string(),
            listen_port,
            // No second socket: both proxy tests would otherwise race for
            // 127.0.0.1:1813.
            accounting_port: AccountingPort::Named(AccountingPortMode::Disabled),
            clients: vec![crate::config::Client {
                address: "127.0.0.1/32".to_string(),
                secret: "nas-secret".to_string(),
                name: Some("test-nas".to_string()),
                enabled: true,
                nas_identifier: None,
            }],
            proxy: Some(ProxyConfig {
                enabled: true,
                pools: vec![HomeServerPoolConfig {
                    name: "home".to_string(),
                    strategy: Default::default(),
                    servers: vec![HomeServerConfig {
                        address: home.to_string(),
                        secret: "home-secret".to_string(),
                        timeout: 5,
                        max_outstanding: 10,
                        name: Some("home".to_string()),
                    }],
                }],
                realms: vec![RealmConfig {
                    name: "home".to_string(),
                    match_config: RealmMatchConfig {
                        match_type: "suffix".to_string(),
                        pattern: "home.test".to_string(),
                    },
                    pool: "home".to_string(),
                    strip_realm: false,
                }],
                health_check: HealthCheckConfig {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Config::default()
        }
    }

    async fn proxy_server(config: Config) -> Result<RadiusServer, ServerError> {
        let handler = Arc::new(SimpleAuthHandler::new());
        RadiusServer::new(ServerConfig::from_config(config, handler)?).await
    }

    /// Enabling the proxy used to bind a second socket on the listener's own
    /// address, which fails with EADDRINUSE on any real (non-zero) port.
    #[tokio::test]
    async fn proxy_enabled_server_starts_on_a_fixed_port() {
        let home: SocketAddr = "127.0.0.1:1812".parse().unwrap();
        // Pick a free port the way a config file would name one.
        let port = {
            let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap().port()
        };

        let server = proxy_server(proxy_config(home, port))
            .await
            .expect("server with proxy enabled must start on a fixed port");

        assert_eq!(server.local_addr().unwrap().port(), port);
        let upstream = server
            .config
            .proxy_handler
            .as_ref()
            .expect("proxy handler")
            .socket()
            .local_addr()
            .unwrap();
        assert_ne!(
            upstream.port(),
            port,
            "home-server socket must not share the listener's port"
        );
    }

    /// NAS -> proxy -> (fake) home server -> proxy -> NAS, over real sockets:
    /// the request leg is re-keyed for the home secret, and the relayed Accept
    /// reaches the NAS's own port from the proxy's listening address, signed
    /// with the NAS secret.
    #[tokio::test]
    async fn proxy_relays_home_server_response_to_the_nas() {
        use radius_proto::auth::{
            calculate_response_authenticator, decrypt_user_password, encrypt_user_password,
            generate_request_authenticator, verify_response_authenticator,
        };

        let home = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = proxy_server(proxy_config(home.local_addr().unwrap(), 0))
            .await
            .unwrap();
        let proxy_addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.run().await });

        // The NAS: an Access-Request for a realm the proxy routes.
        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request_auth = generate_request_authenticator();
        // Built at runtime, not a literal, so CodeQL does not read it as a
        // hard-coded credential; the value itself is irrelevant to the test.
        let password: String = ('a'..='p').collect();
        let mut request = Packet::new(Code::AccessRequest, 42, request_auth);
        request.add_attribute(
            Attribute::string(AttributeType::UserName as u8, "alice@home.test").unwrap(),
        );
        request.add_attribute(
            Attribute::new(
                AttributeType::UserPassword as u8,
                encrypt_user_password(&password, b"nas-secret", &request_auth),
            )
            .unwrap(),
        );
        request
            .add_attribute(Attribute::string(AttributeType::NasIdentifier as u8, "nas").unwrap());
        nas.send_to(&request.encode().unwrap(), proxy_addr)
            .await
            .unwrap();

        // The home server sees the request re-keyed for its secret, from the
        // proxy's dedicated upstream socket (not the listener).
        let mut buf = vec![0u8; 4096];
        let (len, upstream) =
            tokio::time::timeout(Duration::from_secs(5), home.recv_from(&mut buf))
                .await
                .expect("home server must receive the forwarded request")
                .unwrap();
        assert_ne!(upstream.port(), proxy_addr.port());
        let forwarded = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(forwarded.identifier, 42);
        assert_eq!(forwarded.authenticator, request_auth);
        let pw = forwarded
            .find_attribute(AttributeType::UserPassword as u8)
            .expect("User-Password forwarded");
        assert_eq!(
            decrypt_user_password(&pw.value, b"home-secret", &request_auth).unwrap(),
            password
        );
        let proxy_state = forwarded
            .find_attribute(AttributeType::ProxyState as u8)
            .expect("Proxy-State appended")
            .clone();

        // Home server answers, echoing Proxy-State, signed with its secret.
        let mut accept = Packet::new(Code::AccessAccept, 42, [0u8; 16]);
        accept.add_attribute(
            Attribute::string(AttributeType::ReplyMessage as u8, "welcome").unwrap(),
        );
        accept.add_attribute(proxy_state);
        accept.authenticator =
            calculate_response_authenticator(&accept, &request_auth, b"home-secret");
        home.send_to(&accept.encode().unwrap(), upstream)
            .await
            .unwrap();

        // The NAS gets it back from the address it sent to, re-signed for it.
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), nas.recv_from(&mut buf))
            .await
            .expect("NAS must receive the relayed Accept")
            .unwrap();
        assert_eq!(from, proxy_addr, "reply must come from the listener socket");
        let relayed = Packet::decode(&buf[..len]).unwrap();
        assert_eq!(relayed.code, Code::AccessAccept);
        assert_eq!(relayed.identifier, 42);
        assert!(verify_response_authenticator(
            &relayed,
            &request_auth,
            b"nas-secret"
        ));
        assert!(
            relayed
                .find_attribute(AttributeType::ProxyState as u8)
                .is_none()
        );
        assert_eq!(
            relayed
                .find_attribute(AttributeType::ReplyMessage as u8)
                .unwrap()
                .as_string()
                .unwrap(),
            "welcome"
        );
    }

    #[test]
    fn test_simple_auth_handler() {
        let mut handler = SimpleAuthHandler::new();
        handler.add_user("testuser", "testpass");

        assert!(handler.authenticate("testuser", "testpass"));
        assert!(!handler.authenticate("testuser", "wrongpass"));
        assert!(!handler.authenticate("wronguser", "testpass"));
    }

    // --- V-3: Message-Authenticator requirement on EAP Access-Requests ---

    fn msgauth_test_config() -> Arc<ServerConfig> {
        // Lenient validation so the packet-level validator doesn't pre-empt the
        // handler's Message-Authenticator check we're exercising.
        let config = Config {
            strict_rfc_compliance: false,
            ..Config::default()
        };
        let handler = Arc::new(SimpleAuthHandler::new());
        Arc::new(ServerConfig::from_config(config, handler).unwrap())
    }

    fn access_request_bytes(attrs: Vec<Attribute>) -> Vec<u8> {
        let mut p = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        // RFC 2865 requires a NAS identifier on Access-Requests; add one so the
        // packet validator passes and we reach the handler's checks.
        p.add_attribute(Attribute::string(AttributeType::NasIdentifier as u8, "test-nas").unwrap());
        for a in attrs {
            p.add_attribute(a);
        }
        p.encode().unwrap()
    }

    async fn process(data: &[u8]) -> Result<Option<Vec<u8>>, ServerError> {
        let cfg = msgauth_test_config();
        RadiusServer::process_request(
            data,
            "10.0.0.1:1812".parse().unwrap(),
            b"s3cret",
            PortRole::Auth,
            &cfg,
        )
        .await
    }

    fn eap_identity_attr() -> Attribute {
        // EAP-Response/Identity: code=2, id=1, len=6, type=1, data='a'.
        Attribute::new(AttributeType::EapMessage as u8, vec![2, 1, 0, 6, 1, b'a']).unwrap()
    }

    #[tokio::test]
    async fn eap_access_request_without_message_authenticator_is_rejected() {
        let data = access_request_bytes(vec![
            Attribute::string(AttributeType::UserName as u8, "alice").unwrap(),
            eap_identity_attr(),
        ]);
        match process(&data).await {
            Err(ServerError::Validation(m)) => {
                assert!(
                    m.contains("missing required Message-Authenticator"),
                    "unexpected error: {m}"
                );
            }
            other => panic!("expected Validation rejection, got {other:?}"),
        }
    }

    /// Encode an Access-Request with a valid Message-Authenticator over `attrs`
    /// under `secret`.
    fn signed_access_request_bytes(attrs: Vec<Attribute>, secret: &[u8]) -> Vec<u8> {
        let mut attrs = attrs;
        attrs.push(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        let mut bytes = access_request_bytes(attrs);
        let ma = calculate_message_authenticator(&bytes, secret);
        // Replace the zeroed Message-Authenticator value in place.
        let needle = [
            &[AttributeType::MessageAuthenticator as u8, 18][..],
            &[0u8; 16],
        ]
        .concat();
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .expect("zeroed Message-Authenticator present");
        bytes[pos + 2..pos + 18].copy_from_slice(&ma);
        bytes
    }

    #[tokio::test]
    async fn eap_access_reject_carries_eap_failure() {
        use rand::RngExt;
        // A handler that cannot authenticate the EAP peer (the PAP handler
        // knows no `alice`) ends the conversation with Access-Reject; RFC 3579
        // §2.6.3 requires that reject to carry EAP-Failure with the peer's
        // last EAP Identifier, signed by a Message-Authenticator.
        // A fresh random shared secret: the test only needs both sides to agree.
        let secret: Vec<u8> = rand::rng().random::<[u8; 16]>().to_vec();
        let data = signed_access_request_bytes(
            vec![
                Attribute::string(AttributeType::UserName as u8, "alice").unwrap(),
                eap_identity_attr(),
            ],
            &secret,
        );
        let cfg = msgauth_test_config();
        let reply = RadiusServer::process_request(
            &data,
            "10.0.0.1:1812".parse().unwrap(),
            &secret,
            PortRole::Auth,
            &cfg,
        )
        .await
        .expect("reject is a normal reply")
        .expect("a reply is sent");
        let reply = Packet::decode(&reply).unwrap();
        assert_eq!(reply.code, Code::AccessReject);
        let eap = reply
            .find_attribute(AttributeType::EapMessage as u8)
            .expect("EAP Access-Reject must carry EAP-Message");
        // EAP-Failure: code 4, identifier 1 (the EAP-Response/Identity's), length 4.
        assert_eq!(eap.value, vec![4, 1, 0, 4]);
        assert!(
            reply
                .find_attribute(AttributeType::MessageAuthenticator as u8)
                .is_some(),
            "a reply carrying EAP-Message needs a Message-Authenticator"
        );
    }

    #[tokio::test]
    async fn eap_access_request_with_invalid_message_authenticator_is_rejected() {
        let data = access_request_bytes(vec![
            Attribute::string(AttributeType::UserName as u8, "alice").unwrap(),
            eap_identity_attr(),
            // All-zero Message-Authenticator can't match the real HMAC.
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        ]);
        match process(&data).await {
            Err(ServerError::Validation(m)) => {
                assert!(
                    m.contains("Invalid Message-Authenticator"),
                    "unexpected error: {m}"
                );
            }
            other => panic!("expected Validation rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_eap_access_request_without_message_authenticator_is_not_rejected_for_it() {
        // A PAP request (no EAP-Message) must NOT be forced to carry a
        // Message-Authenticator — the requirement is scoped to EAP.
        let data = access_request_bytes(vec![
            Attribute::string(AttributeType::UserName as u8, "nobody").unwrap(),
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        ]);
        // Unknown user → AuthFailed, but never the EAP/Message-Authenticator error.
        // Any non-Validation outcome is fine for this scoping check.
        if let Err(ServerError::Validation(m)) = process(&data).await {
            assert!(
                !m.contains("Message-Authenticator"),
                "non-EAP request wrongly rejected for Message-Authenticator: {m}"
            );
        }
    }

    // --- Status-Server (RFC 5997) and per-port admission (RFC 2866 §2) ---

    use crate::accounting::SimpleAccountingHandler;
    use radius_proto::auth::{
        calculate_accounting_request_authenticator, generate_request_authenticator,
        verify_response_authenticator,
    };

    /// A pipeline config with the given `accounting_port` and an accounting
    /// handler, so Accounting-Request reaches the handler.
    fn pipeline_config(accounting_port: AccountingPort) -> Arc<ServerConfig> {
        let config = Config {
            strict_rfc_compliance: false,
            accounting_port,
            ..Config::default()
        };
        let handler = Arc::new(SimpleAuthHandler::new());
        Arc::new(
            ServerConfig::from_config(config, handler)
                .unwrap()
                .with_accounting_handler(Arc::new(SimpleAccountingHandler::new())),
        )
    }

    const NAS: &str = "10.0.0.1:1812";

    /// Encode a Status-Server with a random Request Authenticator and a valid
    /// Message-Authenticator under `secret`; returns the bytes and the Request
    /// Authenticator the reply must be verified against.
    fn signed_status_server_bytes(
        id: u8,
        secret: &[u8],
        extra_attrs: Vec<Attribute>,
    ) -> (Vec<u8>, [u8; 16]) {
        let request_auth = generate_request_authenticator();
        let mut p = Packet::new(Code::StatusServer, id, request_auth);
        for a in extra_attrs {
            p.add_attribute(a);
        }
        p.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        let mut bytes = p.encode().unwrap();
        let ma = calculate_message_authenticator(&bytes, secret);
        let needle = [
            &[AttributeType::MessageAuthenticator as u8, 18][..],
            &[0u8; 16],
        ]
        .concat();
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .expect("zeroed Message-Authenticator present");
        bytes[pos + 2..pos + 18].copy_from_slice(&ma);
        (bytes, request_auth)
    }

    /// The `handler.rs::message_authenticator_valid` check: zero the MA, set
    /// Authenticator := request authenticator, recompute, compare.
    fn reply_message_authenticator_valid(
        reply: &Packet,
        request_auth: &[u8; 16],
        secret: &[u8],
    ) -> bool {
        let Some(received) = reply
            .find_attribute(AttributeType::MessageAuthenticator as u8)
            .map(|a| a.value.clone())
        else {
            return false;
        };
        let mut zeroed = reply.clone();
        zeroed.authenticator = *request_auth;
        for ma in zeroed
            .attributes
            .iter_mut()
            .filter(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
        {
            ma.value = vec![0u8; 16];
        }
        calculate_message_authenticator(&zeroed.encode().unwrap(), secret).to_vec() == received
    }

    /// Decode a Status-Server reply and check everything RFC 5997 §4.1/§4.2
    /// require of it: code, Identifier, Response Authenticator,
    /// Message-Authenticator, and no State / EAP-Message.
    fn assert_status_reply(
        bytes: &[u8],
        expected_code: Code,
        id: u8,
        request_auth: &[u8; 16],
        secret: &[u8],
    ) -> Packet {
        let reply = Packet::decode(bytes).unwrap();
        assert_eq!(reply.code, expected_code);
        assert_eq!(reply.identifier, id);
        assert!(
            verify_response_authenticator(&reply, request_auth, secret),
            "Response Authenticator must verify under the hop secret"
        );
        assert!(
            reply_message_authenticator_valid(&reply, request_auth, secret),
            "reply MUST carry a valid Message-Authenticator (RFC 5997 §4.1)"
        );
        assert!(reply.find_attribute(AttributeType::State as u8).is_none());
        assert!(
            reply
                .find_attribute(AttributeType::EapMessage as u8)
                .is_none()
        );
        reply
    }

    /// An Accounting-Request Start with its RFC 2866 §3 Request Authenticator.
    fn accounting_start_bytes(id: u8, secret: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut p = Packet::new(Code::AccountingRequest, id, [0u8; 16]);
        p.add_attribute(
            Attribute::new(
                AttributeType::AcctStatusType as u8,
                (AcctStatusType::Start as u32).to_be_bytes().to_vec(),
            )
            .unwrap(),
        );
        p.add_attribute(
            Attribute::string(AttributeType::AcctSessionId as u8, "sess-0001").unwrap(),
        );
        p.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
        p.add_attribute(Attribute::string(AttributeType::NasIdentifier as u8, "test-nas").unwrap());
        let request_auth = calculate_accounting_request_authenticator(&p, secret);
        p.authenticator = request_auth;
        (p.encode().unwrap(), request_auth)
    }

    async fn process_as(
        data: &[u8],
        secret: &[u8],
        role: PortRole,
        cfg: &Arc<ServerConfig>,
    ) -> Result<Option<Vec<u8>>, ServerError> {
        RadiusServer::process_request(data, NAS.parse().unwrap(), secret, role, cfg).await
    }

    fn random_secret() -> Vec<u8> {
        use rand::RngExt;
        rand::rng().random::<[u8; 16]>().to_vec()
    }

    #[tokio::test]
    async fn status_server_without_message_authenticator_is_discarded() {
        let secret = random_secret();
        let cfg = pipeline_config(AccountingPort::default());
        let p = Packet::new(Code::StatusServer, 7, generate_request_authenticator());
        let out = process_as(&p.encode().unwrap(), &secret, PortRole::Auth, &cfg)
            .await
            .unwrap();
        assert!(out.is_none(), "RFC 5997 §4.1: silent discard");
    }

    #[tokio::test]
    async fn status_server_with_invalid_message_authenticator_is_discarded() {
        let secret = random_secret();
        let cfg = pipeline_config(AccountingPort::default());

        // All-zero Message-Authenticator cannot match the HMAC.
        let mut p = Packet::new(Code::StatusServer, 8, generate_request_authenticator());
        p.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        let out = process_as(&p.encode().unwrap(), &secret, PortRole::Auth, &cfg)
            .await
            .unwrap();
        assert!(out.is_none());

        // Correctly signed, but under a different secret.
        let other = random_secret();
        let (bytes, _) = signed_status_server_bytes(9, &other, vec![]);
        let out = process_as(&bytes, &secret, PortRole::Auth, &cfg)
            .await
            .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn status_server_on_auth_port_answers_access_accept() {
        let secret = random_secret();
        let cfg = pipeline_config(AccountingPort::default());
        let (bytes, request_auth) = signed_status_server_bytes(10, &secret, vec![]);
        let out = process_as(&bytes, &secret, PortRole::Auth, &cfg)
            .await
            .unwrap()
            .expect("a valid Status-Server is answered");
        assert_status_reply(&out, Code::AccessAccept, 10, &request_auth, &secret);
    }

    #[tokio::test]
    async fn status_server_on_accounting_port_answers_accounting_response() {
        let secret = random_secret();
        let cfg = pipeline_config(AccountingPort::default());
        let (bytes, request_auth) = signed_status_server_bytes(11, &secret, vec![]);
        let out = process_as(&bytes, &secret, PortRole::Accounting, &cfg)
            .await
            .unwrap()
            .expect("a valid Status-Server is answered");
        assert_status_reply(&out, Code::AccountingResponse, 11, &request_auth, &secret);
    }

    #[tokio::test]
    async fn status_server_echoes_proxy_state() {
        let secret = random_secret();
        let cfg = pipeline_config(AccountingPort::default());
        let ps1 = Attribute::new(AttributeType::ProxyState as u8, b"hop-one".to_vec()).unwrap();
        let ps2 = Attribute::new(AttributeType::ProxyState as u8, b"hop-two".to_vec()).unwrap();
        let (bytes, request_auth) =
            signed_status_server_bytes(12, &secret, vec![ps1.clone(), ps2.clone()]);
        let out = process_as(&bytes, &secret, PortRole::Auth, &cfg)
            .await
            .unwrap()
            .unwrap();
        let reply = assert_status_reply(&out, Code::AccessAccept, 12, &request_auth, &secret);
        let echoed: Vec<&Attribute> = reply
            .attributes
            .iter()
            .filter(|a| a.attr_type == AttributeType::ProxyState as u8)
            .collect();
        assert_eq!(echoed.len(), 2, "both Proxy-State echoed (RFC 2865 §5.33)");
        assert_eq!(echoed[0].value, ps1.value);
        assert_eq!(echoed[1].value, ps2.value);
    }

    #[tokio::test]
    async fn status_server_over_radsec_answers_access_accept() {
        let cfg = pipeline_config(AccountingPort::default());
        let (bytes, request_auth) = signed_status_server_bytes(13, b"radsec", vec![]);
        let out = process_as(&bytes, b"radsec", PortRole::Any, &cfg)
            .await
            .unwrap()
            .unwrap();
        assert_status_reply(&out, Code::AccessAccept, 13, &request_auth, b"radsec");
    }

    #[tokio::test]
    async fn access_request_on_accounting_port_is_discarded() {
        let secret = random_secret();
        let cfg = pipeline_config(AccountingPort::default());
        let data = access_request_bytes(vec![
            Attribute::string(AttributeType::UserName as u8, "nobody").unwrap(),
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        ]);
        let out = process_as(&data, &secret, PortRole::Accounting, &cfg)
            .await
            .unwrap();
        assert!(
            out.is_none(),
            "RFC 2866 §2: no Access-Request on the accounting port"
        );
    }

    #[tokio::test]
    async fn accounting_request_on_accounting_port_answers_accounting_response() {
        let secret = random_secret();
        let cfg = pipeline_config(AccountingPort::default());
        let (bytes, request_auth) = accounting_start_bytes(20, &secret);
        let out = process_as(&bytes, &secret, PortRole::Accounting, &cfg)
            .await
            .unwrap()
            .expect("Accounting-Request is answered");
        let reply = Packet::decode(&out).unwrap();
        assert_eq!(reply.code, Code::AccountingResponse);
        assert_eq!(reply.identifier, 20);
        assert!(verify_response_authenticator(
            &reply,
            &request_auth,
            &secret
        ));
    }

    #[tokio::test]
    async fn accounting_request_on_auth_port_is_discarded_unless_shared() {
        let secret = random_secret();
        let (bytes, request_auth) = accounting_start_bytes(21, &secret);

        // Dedicated accounting socket: Code 4 on the auth socket is discarded.
        let cfg = pipeline_config(AccountingPort::Dedicated(1813));
        assert!(
            process_as(&bytes, &secret, PortRole::Auth, &cfg)
                .await
                .unwrap()
                .is_none()
        );

        // Shared (legacy single socket): answered.
        let cfg = pipeline_config(AccountingPort::Named(AccountingPortMode::Shared));
        let out = process_as(&bytes, &secret, PortRole::Auth, &cfg)
            .await
            .unwrap()
            .expect("shared mode answers accounting on the auth socket");
        let reply = Packet::decode(&out).unwrap();
        assert_eq!(reply.code, Code::AccountingResponse);
        assert!(verify_response_authenticator(
            &reply,
            &request_auth,
            &secret
        ));

        // Disabled: no UDP accounting anywhere.
        let cfg = pipeline_config(AccountingPort::Named(AccountingPortMode::Disabled));
        assert!(
            process_as(&bytes, &secret, PortRole::Auth, &cfg)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn radsec_role_admits_every_code() {
        let cfg = pipeline_config(AccountingPort::Named(AccountingPortMode::Disabled));

        // Access-Request reaches authentication (unknown user → a reject, or
        // at least not the admission discard).
        let data = access_request_bytes(vec![
            Attribute::string(AttributeType::UserName as u8, "nobody").unwrap(),
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        ]);
        match process_as(&data, b"radsec", PortRole::Any, &cfg).await {
            Ok(None) => panic!("RadSec must not discard Access-Request by admission"),
            Ok(Some(bytes)) => {
                assert_eq!(Packet::decode(&bytes).unwrap().code, Code::AccessReject)
            }
            Err(_) => {} // AuthFailed for the unknown user is also "handled"
        }

        // Accounting-Request is handled even though UDP accounting is disabled.
        let (bytes, request_auth) = accounting_start_bytes(22, b"radsec");
        let out = process_as(&bytes, b"radsec", PortRole::Any, &cfg)
            .await
            .unwrap()
            .expect("RadSec carries accounting (RFC 6614 §2.5)");
        let reply = Packet::decode(&out).unwrap();
        assert_eq!(reply.code, Code::AccountingResponse);
        assert!(verify_response_authenticator(
            &reply,
            &request_auth,
            b"radsec"
        ));
    }

    // --- Real sockets: two listeners, routing by port ---

    fn dual_socket_config(accounting_port: AccountingPort) -> Config {
        Config {
            listen_address: "127.0.0.1".to_string(),
            listen_port: 0,
            accounting_port,
            clients: vec![crate::config::Client {
                address: "127.0.0.1/32".to_string(),
                secret: "nas-secret".to_string(),
                name: Some("test-nas".to_string()),
                enabled: true,
                nas_identifier: None,
            }],
            strict_rfc_compliance: false,
            ..Config::default()
        }
    }

    async fn dual_socket_server(config: Config) -> RadiusServer {
        let handler = Arc::new(SimpleAuthHandler::new());
        let server_config = ServerConfig::from_config(config, handler)
            .unwrap()
            .with_accounting_handler(Arc::new(SimpleAccountingHandler::new()));
        RadiusServer::new(server_config).await.unwrap()
    }

    async fn recv_reply(sock: &UdpSocket, wait: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => Some((buf[..len].to_vec(), from)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn dual_sockets_route_by_port() {
        let server = dual_socket_server(dual_socket_config(AccountingPort::Dedicated(0))).await;
        let auth_addr = server.local_addr().unwrap();
        let acct_addr = server
            .accounting_local_addr()
            .unwrap()
            .expect("a dedicated accounting socket is bound");
        assert_ne!(auth_addr, acct_addr);
        tokio::spawn(async move { server.run().await });

        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let secret = b"nas-secret";
        let long = Duration::from_secs(5);
        let short = Duration::from_millis(500);

        // Accounting-Request → accounting socket ⇒ Accounting-Response from it.
        let (bytes, request_auth) = accounting_start_bytes(30, secret);
        nas.send_to(&bytes, acct_addr).await.unwrap();
        let (reply, from) = recv_reply(&nas, long)
            .await
            .expect("Accounting-Response from the accounting socket");
        assert_eq!(from, acct_addr, "reply leaves from the accounting port");
        let reply = Packet::decode(&reply).unwrap();
        assert_eq!(reply.code, Code::AccountingResponse);
        assert_eq!(reply.identifier, 30);
        assert!(verify_response_authenticator(&reply, &request_auth, secret));

        // Same kind of request (new id) → auth socket ⇒ silence (RFC 2866 §2).
        let (bytes, _) = accounting_start_bytes(31, secret);
        nas.send_to(&bytes, auth_addr).await.unwrap();
        assert!(
            recv_reply(&nas, short).await.is_none(),
            "Accounting-Request on the auth socket is discarded"
        );

        // Status-Server → accounting socket ⇒ Accounting-Response (RFC 5997 §4.2).
        let (bytes, request_auth) = signed_status_server_bytes(32, secret, vec![]);
        nas.send_to(&bytes, acct_addr).await.unwrap();
        let (reply, from) = recv_reply(&nas, long)
            .await
            .expect("Status-Server answered");
        assert_eq!(from, acct_addr);
        assert_status_reply(&reply, Code::AccountingResponse, 32, &request_auth, secret);

        // Status-Server → auth socket ⇒ Access-Accept.
        let (bytes, request_auth) = signed_status_server_bytes(33, secret, vec![]);
        nas.send_to(&bytes, auth_addr).await.unwrap();
        let (reply, from) = recv_reply(&nas, long)
            .await
            .expect("Status-Server answered");
        assert_eq!(from, auth_addr);
        assert_status_reply(&reply, Code::AccessAccept, 33, &request_auth, secret);

        // Access-Request → accounting socket ⇒ silence.
        let data = access_request_bytes(vec![
            Attribute::string(AttributeType::UserName as u8, "nobody").unwrap(),
            Attribute::new(AttributeType::UserPassword as u8, vec![0u8; 16]).unwrap(),
        ]);
        nas.send_to(&data, acct_addr).await.unwrap();
        assert!(
            recv_reply(&nas, short).await.is_none(),
            "Access-Request on the accounting socket is discarded"
        );
    }

    #[tokio::test]
    async fn shared_mode_binds_one_socket() {
        let server = dual_socket_server(dual_socket_config(AccountingPort::Named(
            AccountingPortMode::Shared,
        )))
        .await;
        let auth_addr = server.local_addr().unwrap();
        assert!(server.accounting_local_addr().unwrap().is_none());
        tokio::spawn(async move { server.run().await });

        let nas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let secret = b"nas-secret";
        let (bytes, request_auth) = accounting_start_bytes(40, secret);
        nas.send_to(&bytes, auth_addr).await.unwrap();
        let (reply, from) = recv_reply(&nas, Duration::from_secs(5))
            .await
            .expect("shared mode answers accounting on the auth socket");
        assert_eq!(from, auth_addr);
        let reply = Packet::decode(&reply).unwrap();
        assert_eq!(reply.code, Code::AccountingResponse);
        assert!(verify_response_authenticator(&reply, &request_auth, secret));
    }
}
