use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
}

/// Expand environment variables in a string
///
/// Supports syntax: ${VAR_NAME} or $VAR_NAME
/// Returns error if variable is not found
fn expand_env_vars(s: &str) -> Result<String, ConfigError> {
    let mut result = s.to_string();

    // Match ${VAR_NAME} pattern
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = env::var(var_name)
                .map_err(|_| ConfigError::EnvVarNotFound(var_name.to_string()))?;
            result.replace_range(start..start + end + 1, &value);
        } else {
            break;
        }
    }

    Ok(result)
}

/// User configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    /// Client IP address or network (supports CIDR notation)
    pub address: String,
    /// Shared secret for this client
    pub secret: String,
    /// Optional client name/description
    #[serde(default)]
    pub name: Option<String>,
    /// Enable/disable this client
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Expected NAS-Identifier for this client (if specified, will be validated)
    #[serde(default)]
    pub nas_identifier: Option<String>,
}

fn default_enabled() -> bool {
    true
}

impl Client {
    /// Parse the client address as an IP network
    pub fn parse_network(&self) -> Result<IpNetwork, ConfigError> {
        // Try to parse as CIDR notation first
        if let Ok(network) = self.address.parse::<IpNetwork>() {
            return Ok(network);
        }

        // Try to parse as a single IP address
        if let Ok(ip) = self.address.parse::<IpAddr>() {
            // Convert to /32 (IPv4) or /128 (IPv6) network
            return Ok(IpNetwork::from(ip));
        }

        Err(ConfigError::Invalid(format!(
            "Invalid client address: {}",
            self.address
        )))
    }

    /// Check if a source IP address matches this client
    pub fn matches(&self, source_ip: IpAddr) -> Result<bool, ConfigError> {
        let network = self.parse_network()?;
        Ok(network.contains(source_ip))
    }

    /// Get the shared secret for this client
    pub fn get_secret(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server listen address
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Server listen port
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// Default shared secret (used if client doesn't specify one)
    #[serde(default = "default_secret")]
    pub secret: String,

    /// List of authorized clients
    #[serde(default)]
    pub clients: Vec<Client>,

    /// List of users for authentication
    #[serde(default)]
    pub users: Vec<User>,

    /// Enable verbose logging (deprecated: use log_level instead)
    #[serde(default)]
    pub verbose: bool,

    /// Log level: "trace", "debug", "info", "warn", "error" (default: "info")
    #[serde(default)]
    pub log_level: Option<String>,

    /// Audit log file path (JSON format, optional)
    #[serde(default)]
    pub audit_log_path: Option<String>,

    /// Accounting log file path (JSON Lines format, optional)
    /// When specified, enables file-based accounting with one JSON record per line.
    /// Example: "/var/log/radius/accounting.jsonl"
    #[serde(default)]
    pub accounting_log_path: Option<String>,

    /// PostgreSQL database URL for accounting (optional)
    /// When specified, enables PostgreSQL-based accounting storage.
    /// Example: "postgresql://user:password@localhost/radius"
    #[serde(default)]
    pub accounting_database_url: Option<String>,

    /// Accounting data retention period in days (optional)
    /// When specified, accounting records older than this will be deleted.
    /// Applies to both file-based and database accounting.
    /// Example: 90 (keep 90 days of history)
    #[serde(default)]
    pub accounting_retention_days: Option<u32>,

    /// Strict RFC 2865 compliance mode (default: true)
    /// When enabled, enforces strict validation of attribute values and types.
    /// Set to false for lenient mode if compatibility with non-compliant clients is needed.
    #[serde(default = "default_strict_rfc_compliance")]
    pub strict_rfc_compliance: bool,

    /// Request cache TTL in seconds (default: 60)
    #[serde(default)]
    pub request_cache_ttl: Option<u64>,

    /// Maximum number of cached requests (default: 10000)
    #[serde(default)]
    pub request_cache_max_entries: Option<usize>,

    /// Rate limit: requests per second per client (default: 100, 0 = unlimited)
    #[serde(default)]
    pub rate_limit_per_client_rps: Option<u32>,

    /// Rate limit: burst capacity per client (default: 200)
    #[serde(default)]
    pub rate_limit_per_client_burst: Option<u32>,

    /// Rate limit: requests per second globally (default: 1000, 0 = unlimited)
    #[serde(default)]
    pub rate_limit_global_rps: Option<u32>,

    /// Rate limit: global burst capacity (default: 2000)
    #[serde(default)]
    pub rate_limit_global_burst: Option<u32>,

    /// Maximum concurrent connections per client (default: 100, 0 = unlimited)
    #[serde(default)]
    pub max_concurrent_connections: Option<u32>,

    /// Maximum bandwidth per client in bytes per second (default: 1000000 = 1 MB/s, 0 = unlimited)
    #[serde(default)]
    pub max_bandwidth_bps: Option<u64>,

    /// LDAP configuration for LDAP/AD authentication
    #[serde(default)]
    pub ldap: Option<crate::ldap_auth::LdapConfig>,

    /// PostgreSQL configuration for database-backed authentication
    #[serde(default)]
    pub postgres: Option<crate::postgres_auth::PostgresConfig>,

    /// Proxy configuration for RADIUS proxying
    #[serde(default)]
    pub proxy: Option<crate::proxy::ProxyConfig>,

    /// EAP / EAP-TLS / EAP-TEAP configuration. When set, the server uses
    /// EapAuthHandler instead of the plain SimpleAuthHandler.
    #[serde(default)]
    pub eap: Option<EapConfig>,

    /// Management API security (mTLS + IAM-style ABAC access policy). When unset,
    /// the management API stays open (today's behavior) and logs a warning.
    #[serde(default)]
    pub mgmt: Option<MgmtConfig>,

    /// RADIUS transport. Per the authenticator SERVER-CONTRACT (G-1) the locked
    /// transport is RadSec (RADIUS over TLS 1.3, ML-KEM-1024-only); plain UDP is a
    /// transitional, non-FIPS fallback that must be opted into explicitly.
    #[serde(default)]
    pub transport: Transport,

    /// RadSec listener settings. Required when `transport = "radsec"`.
    #[serde(default)]
    pub radsec: Option<RadSecConfig>,
}

/// RADIUS transport selector (SERVER-CONTRACT §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// RadSec: RADIUS over mutually-authenticated TLS 1.3 with ML-KEM-1024-only
    /// key exchange (RFC 6614, FIPS 203). The locked, FIPS-posture transport.
    #[default]
    Radsec,
    /// Plain UDP/1812+1813 with a per-client shared secret. **Not FIPS-approved**
    /// and spoofable; permitted only for development against legacy NASes. The
    /// daemon logs a prominent warning when this is selected.
    UdpInsecure,
}

/// RadSec listener configuration (RFC 6614). The listener terminates TLS 1.3 with
/// the ML-KEM-1024-only FIPS provider and requires a client certificate (mTLS):
/// the NAS client-cert identity replaces UDP's spoofable shared-secret + source-IP
/// trust. Inside the tunnel the payload is standard RADIUS, using the fixed
/// shared secret `"radsec"` for the Authenticator/Message-Authenticator math.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadSecConfig {
    /// Listen address (default `::`, dual-stack).
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    /// Listen port (default 2083, the RadSec IANA port).
    #[serde(default = "default_radsec_port")]
    pub listen_port: u16,
    /// Server certificate chain (PEM, leaf first) presented to the NAS.
    pub cert_path: String,
    /// Server private key (PEM).
    pub key_path: String,
    /// CA bundle used to verify NAS client certificates (PEM). Always required —
    /// RadSec is mutually authenticated.
    pub client_ca_path: String,
    /// CRL/OCSP revocation checking of NAS client certificates. Omitted ⇒ chain
    /// validation only. Needs a binary built with the `revocation` feature.
    #[serde(default)]
    pub revocation: Option<RevocationConfig>,
}

/// Management API security configuration. Enforcement is *opt-in*: when an
/// `access_policy_file` is configured the IAM-style policy is applied (default
/// deny); when `tls` is configured the listener serves HTTPS and, if
/// `client_ca_path` is present, requires + verifies client certificates (mTLS).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MgmtConfig {
    /// TLS for the management listener. When omitted the listener is plain HTTP.
    #[serde(default)]
    pub tls: Option<MgmtTlsConfig>,
    /// Path to the IAM-style access policy JSON. When set, authorization is enforced.
    #[serde(default)]
    pub access_policy_file: Option<String>,
    /// Trust `X-Auth-Request-*` identity headers (forwarded by oauth2-proxy via the
    /// BFF) when building the ABAC principal. Headers are only honored when the peer
    /// was authenticated by mTLS, OR when this is explicitly true without mTLS.
    #[serde(default = "default_true")]
    pub trust_forwarded_identity: bool,
}

/// TLS certificate paths for the management API listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MgmtTlsConfig {
    pub cert_path: String,
    pub key_path: String,
    /// CA bundle used to verify client certificates. Present ⇒ mTLS (client cert
    /// required); absent ⇒ server-only TLS.
    #[serde(default)]
    pub client_ca_path: Option<String>,
}

/// EAP configuration block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EapConfig {
    /// TLS certificate configuration for EAP-TLS, and for the EAP-TEAP
    /// tunnel unless `teap_tls` is set.
    pub tls: EapTlsConfig,
    /// TLS configuration of the EAP-TEAP Phase 1 tunnel (RFC 9930 §3.2) when
    /// it differs from `tls`: typically the same certificate without
    /// `require_client_cert`, so that TEAP peers authenticate with the inner
    /// Basic-Password-Auth method instead of a client certificate. Omitted ⇒
    /// TEAP uses `tls`.
    #[serde(default)]
    pub teap_tls: Option<EapTlsConfig>,
    /// Enable EAP-TLS (Type 13). Default: false.
    #[serde(default)]
    pub enable_tls: bool,
    /// Enable EAP-TEAP (Type 55, RFC 9930). Default: true.
    #[serde(default = "default_true")]
    pub enable_teap: bool,
    /// Seconds an EAP conversation may sit without a packet from the peer
    /// before its state (EAP session plus TLS/TEAP context) is evicted.
    /// Default 120. An evicted conversation fails closed: the next packet
    /// carrying its State is rejected.
    #[serde(default = "default_eap_session_idle_timeout_secs")]
    pub session_idle_timeout_secs: u64,
    /// Maximum number of live EAP conversations. When reached, the least
    /// recently used one is evicted to make room. Default 4096, which bounds
    /// the EAP state to a few hundred MiB in the worst case under the default
    /// rate limits.
    #[serde(default = "default_eap_max_sessions")]
    pub max_sessions: usize,
}

fn default_eap_session_idle_timeout_secs() -> u64 {
    radius_proto::eap::EapSessionManager::DEFAULT_IDLE_TIMEOUT_SECS
}

fn default_eap_max_sessions() -> usize {
    radius_proto::eap::EapSessionManager::DEFAULT_MAX_SESSIONS
}

/// TLS certificate paths for EAP-TLS / EAP-TEAP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EapTlsConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub ca_path: Option<String>,
    #[serde(default)]
    pub require_client_cert: bool,
    /// CRL/OCSP revocation checking of supplicant certificates. Requires
    /// `require_client_cert` and `ca_path`. Omitted ⇒ chain validation only.
    /// Needs a binary built with the `revocation` feature.
    #[serde(default)]
    pub revocation: Option<RevocationConfig>,
}

/// Certificate revocation checking for peer certificates (EAP-TLS supplicants
/// under `eap.tls.revocation`, RadSec NAS clients under `radsec.revocation`).
///
/// Revocation is checked at TLS handshake time, after the certificate chain
/// has been validated against the CA bundle. Fetches block the handshake for
/// at most the configured timeout; prefer static CRL files (or short timeouts)
/// where the RADIUS client's own timeout is tight.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationConfig {
    /// Which sources to consult. Default `crl_only`.
    #[serde(default)]
    pub mode: RevocationMode,
    /// What to do when the status cannot be determined (CRL/OCSP unreachable,
    /// stale, unparseable, or no source covers the certificate). Default
    /// `fail_closed`: reject the client. A positive "revoked" answer always
    /// rejects, whatever this is set to.
    #[serde(default)]
    pub on_error: RevocationFailurePolicy,
    /// CRL settings (used by `crl_only`, `prefer_ocsp` and `both`).
    #[serde(default)]
    pub crl: CrlSettings,
    /// OCSP settings (used by `ocsp_only`, `prefer_ocsp` and `both`).
    #[serde(default)]
    pub ocsp: OcspSettings,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            mode: RevocationMode::CrlOnly,
            on_error: RevocationFailurePolicy::FailClosed,
            crl: CrlSettings::default(),
            ocsp: OcspSettings::default(),
        }
    }
}

/// Revocation sources to consult.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMode {
    /// CRLs only: static files first, then the certificate's CRL Distribution
    /// Points when `crl.fetch` is on.
    #[default]
    CrlOnly,
    /// OCSP only, against the responder in the certificate's Authority
    /// Information Access extension.
    OcspOnly,
    /// OCSP first; CRL when OCSP cannot answer.
    PreferOcsp,
    /// Both OCSP and CRL; revoked by either ⇒ rejected.
    Both,
}

impl RevocationMode {
    /// Whether this mode consults CRLs.
    pub fn uses_crl(self) -> bool {
        matches!(self, Self::CrlOnly | Self::PreferOcsp | Self::Both)
    }

    /// Whether this mode consults OCSP.
    pub fn uses_ocsp(self) -> bool {
        matches!(self, Self::OcspOnly | Self::PreferOcsp | Self::Both)
    }
}

/// What to do when revocation status cannot be determined.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RevocationFailurePolicy {
    /// Reject the client (secure default).
    #[default]
    FailClosed,
    /// Accept the client and log a warning. Availability over security; only
    /// for environments that accept the exposure.
    FailOpen,
}

/// CRL source, fetch and cache settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrlSettings {
    /// CRL files (PEM or DER) loaded at startup and matched to certificates
    /// by issuer. Suits air-gapped deployments; refresh them (and restart)
    /// before `nextUpdate` or the check fails per `on_error`.
    #[serde(default)]
    pub static_files: Vec<String>,
    /// Fetch CRLs over HTTP(S) from the certificate's CRL Distribution Points
    /// when no current static CRL covers its issuer. Default true.
    #[serde(default = "default_true")]
    pub fetch: bool,
    /// HTTP timeout per fetch, seconds. Default 5.
    #[serde(default = "default_revocation_timeout_secs")]
    pub fetch_timeout_secs: u64,
    /// How long a fetched CRL is reused, seconds (also bounded by its
    /// `nextUpdate`). Default 3600.
    #[serde(default = "default_revocation_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Maximum number of fetched CRLs kept in memory. Default 100.
    #[serde(default = "default_revocation_cache_entries")]
    pub max_cache_entries: usize,
    /// Largest CRL accepted from a distribution point, bytes. Default 10 MiB.
    #[serde(default = "default_crl_max_size_bytes")]
    pub max_size_bytes: usize,
}

impl Default for CrlSettings {
    fn default() -> Self {
        Self {
            static_files: Vec::new(),
            fetch: true,
            fetch_timeout_secs: default_revocation_timeout_secs(),
            cache_ttl_secs: default_revocation_cache_ttl_secs(),
            max_cache_entries: default_revocation_cache_entries(),
            max_size_bytes: default_crl_max_size_bytes(),
        }
    }
}

/// OCSP fetch and cache settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OcspSettings {
    /// HTTP timeout per responder query, seconds. Default 5.
    #[serde(default = "default_revocation_timeout_secs")]
    pub fetch_timeout_secs: u64,
    /// Upper bound on how long a response is reused, seconds (also bounded by
    /// its `nextUpdate`). Default 3600.
    #[serde(default = "default_revocation_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Maximum number of responses kept in memory. Default 100.
    #[serde(default = "default_revocation_cache_entries")]
    pub max_cache_entries: usize,
    /// Send an RFC 8954 nonce and require the responder to echo it. Default
    /// true.
    #[serde(default = "default_true")]
    pub nonce: bool,
    /// Largest OCSP response accepted, bytes. Default 1 MiB.
    #[serde(default = "default_ocsp_max_response_bytes")]
    pub max_response_size_bytes: usize,
}

impl Default for OcspSettings {
    fn default() -> Self {
        Self {
            fetch_timeout_secs: default_revocation_timeout_secs(),
            cache_ttl_secs: default_revocation_cache_ttl_secs(),
            max_cache_entries: default_revocation_cache_entries(),
            nonce: true,
            max_response_size_bytes: default_ocsp_max_response_bytes(),
        }
    }
}

impl RevocationConfig {
    /// Validate the block; `at` names it in errors (`eap.tls.revocation`,
    /// `radsec.revocation`).
    ///
    /// Without the `revocation` cargo feature any block is an error: a config
    /// that asks for revocation checking must not start a binary that cannot
    /// enforce it.
    #[cfg(not(feature = "revocation"))]
    pub fn validate(&self, at: &str) -> Result<(), ConfigError> {
        Err(ConfigError::Invalid(format!(
            "{at}: this binary was built without the `revocation` feature, so revocation \
             checking cannot be enforced; rebuild with `--features revocation` or remove \
             the block"
        )))
    }

    /// Validate the block; `at` names it in errors (`eap.tls.revocation`,
    /// `radsec.revocation`).
    #[cfg(feature = "revocation")]
    pub fn validate(&self, at: &str) -> Result<(), ConfigError> {
        let invalid = |msg: &str| ConfigError::Invalid(format!("{at}: {msg}"));

        if self.mode.uses_crl() {
            if !self.crl.fetch && self.crl.static_files.is_empty() {
                return Err(invalid(
                    "crl.fetch is false and crl.static_files is empty: no CRL source \
                     (mode uses CRLs)",
                ));
            }
            if self.crl.static_files.iter().any(|p| p.trim().is_empty()) {
                return Err(invalid("crl.static_files contains an empty path"));
            }
            if self.crl.fetch_timeout_secs == 0 {
                return Err(invalid("crl.fetch_timeout_secs must be > 0"));
            }
            if self.crl.cache_ttl_secs == 0 {
                return Err(invalid("crl.cache_ttl_secs must be > 0"));
            }
            if self.crl.max_cache_entries == 0 {
                return Err(invalid("crl.max_cache_entries must be > 0"));
            }
            if self.crl.max_size_bytes == 0 {
                return Err(invalid("crl.max_size_bytes must be > 0"));
            }
        }
        if self.mode.uses_ocsp() {
            if self.ocsp.fetch_timeout_secs == 0 {
                return Err(invalid("ocsp.fetch_timeout_secs must be > 0"));
            }
            if self.ocsp.cache_ttl_secs == 0 {
                return Err(invalid("ocsp.cache_ttl_secs must be > 0"));
            }
            if self.ocsp.max_cache_entries == 0 {
                return Err(invalid("ocsp.max_cache_entries must be > 0"));
            }
            if self.ocsp.max_response_size_bytes == 0 {
                return Err(invalid("ocsp.max_response_size_bytes must be > 0"));
            }
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn default_revocation_timeout_secs() -> u64 {
    5
}

fn default_revocation_cache_ttl_secs() -> u64 {
    3600
}

fn default_revocation_cache_entries() -> usize {
    100
}

fn default_crl_max_size_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_ocsp_max_response_bytes() -> usize {
    1024 * 1024
}

fn default_listen_address() -> String {
    "::".to_string() // IPv6 unspecified - accepts both IPv6 and IPv4-mapped IPv6 on most systems
}

fn default_listen_port() -> u16 {
    1812 // Standard RADIUS authentication port
}

fn default_radsec_port() -> u16 {
    2083 // RadSec (RADIUS over TLS), IANA-assigned
}

fn default_secret() -> String {
    "testing123".to_string()
}

fn default_strict_rfc_compliance() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_address: default_listen_address(),
            listen_port: default_listen_port(),
            secret: default_secret(),
            clients: vec![],
            users: vec![],
            verbose: false,
            log_level: None,
            audit_log_path: None,
            accounting_log_path: None,
            accounting_database_url: None,
            accounting_retention_days: None,
            strict_rfc_compliance: true,
            request_cache_ttl: None,
            request_cache_max_entries: None,
            rate_limit_per_client_rps: None,
            rate_limit_per_client_burst: None,
            rate_limit_global_rps: None,
            rate_limit_global_burst: None,
            max_concurrent_connections: None,
            max_bandwidth_bps: None,
            ldap: None,
            postgres: None,
            proxy: None,
            eap: None,
            mgmt: None,
            // The in-code Default is the legacy UDP dev object (secret + port
            // 1812 above), so it stays udp-insecure. Config *files* default to
            // RadSec via the field's `#[serde(default)]` (SERVER-CONTRACT §1).
            transport: Transport::UdpInsecure,
            radsec: None,
        }
    }
}

impl Config {
    /// Load configuration from a JSON file
    ///
    /// Supports environment variable expansion in secret fields using ${VAR_NAME} syntax.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&contents)?;

        // Expand environment variables in secrets
        config.secret = expand_env_vars(&config.secret)?;
        for client in &mut config.clients {
            client.secret = expand_env_vars(&client.secret)?;
        }

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a JSON file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }

    /// Get socket address for binding
    pub fn socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        let addr: IpAddr = self.listen_address.parse().map_err(|_| {
            ConfigError::Invalid(format!("Invalid IP address: {}", self.listen_address))
        })?;
        Ok(SocketAddr::new(addr, self.listen_port))
    }

    /// Find a client by source IP address
    ///
    /// Returns the first enabled client that matches the source IP.
    /// Returns None if no matching client is found or if the clients list is empty.
    pub fn find_client(&self, source_ip: IpAddr) -> Option<&Client> {
        // Canonicalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4 so a v4
        // client CIDR matches a source received over a dual-stack (`[::]`) socket.
        let source_ip = source_ip.to_canonical();
        for client in &self.clients {
            if !client.enabled {
                continue;
            }
            if let Ok(true) = client.matches(source_ip) {
                return Some(client);
            }
        }
        None
    }

    /// Get the shared secret for a source IP
    ///
    /// Returns the client-specific secret if a matching client is found,
    /// otherwise returns the default shared secret.
    pub fn get_secret_for_client(&self, source_ip: IpAddr) -> &[u8] {
        self.find_client(source_ip)
            .map(|client| client.get_secret())
            .unwrap_or_else(|| self.secret.as_bytes())
    }

    /// Validate configuration
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate listen address
        let _: IpAddr = self.listen_address.parse().map_err(|_| {
            ConfigError::Invalid(format!("Invalid listen address: {}", self.listen_address))
        })?;

        // Validate port
        if self.listen_port == 0 {
            return Err(ConfigError::Invalid("Port cannot be 0".to_string()));
        }

        // Validate secret is not empty
        if self.secret.is_empty() {
            return Err(ConfigError::Invalid("Secret cannot be empty".to_string()));
        }

        // Validate clients
        for client in &self.clients {
            if client.secret.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "Client {} has empty secret",
                    client.address
                )));
            }
            // Validate that address can be parsed
            client.parse_network()?;
        }

        // Validate users
        for user in &self.users {
            if user.username.is_empty() {
                return Err(ConfigError::Invalid("User has empty username".to_string()));
            }
        }

        // EAP session bounds: zero would evict every conversation at once.
        if let Some(eap) = &self.eap {
            if eap.session_idle_timeout_secs == 0 {
                return Err(ConfigError::Invalid(
                    "eap.session_idle_timeout_secs must be at least 1".to_string(),
                ));
            }
            if eap.max_sessions == 0 {
                return Err(ConfigError::Invalid(
                    "eap.max_sessions must be at least 1".to_string(),
                ));
            }
        }

        // Revocation checking is only meaningful for verified client certificates.
        if let Some(eap) = &self.eap {
            let blocks = [("eap.tls", &eap.tls)]
                .into_iter()
                .chain(eap.teap_tls.as_ref().map(|t| ("eap.teap_tls", t)));
            for (at, tls) in blocks {
                if let Some(rev) = &tls.revocation {
                    if !tls.require_client_cert || tls.ca_path.is_none() {
                        return Err(ConfigError::Invalid(format!(
                            "{at}.revocation requires {at}.require_client_cert = true and \
                             {at}.ca_path (there is no client certificate to check otherwise)"
                        )));
                    }
                    rev.validate(&format!("{at}.revocation"))?;
                }
            }
        }
        if let Some(radsec) = &self.radsec
            && let Some(rev) = &radsec.revocation
        {
            rev.validate("radsec.revocation")?;
        }

        // Validate management API security config.
        if let Some(mgmt) = &self.mgmt {
            if let Some(tls) = &mgmt.tls
                && (tls.cert_path.is_empty() || tls.key_path.is_empty())
            {
                return Err(ConfigError::Invalid(
                    "mgmt.tls requires both cert_path and key_path".to_string(),
                ));
            }
            // Enforcing authorization while accepting unauthenticated, spoofable
            // identity headers is a foot-gun — warn loudly but don't hard-fail
            // (the operator may terminate mTLS at a trusted mesh).
            let mtls = mgmt
                .tls
                .as_ref()
                .map(|t| t.client_ca_path.is_some())
                .unwrap_or(false);
            if mgmt.access_policy_file.is_some() && !mtls && mgmt.trust_forwarded_identity {
                tracing::warn!(
                    "mgmt.access_policy_file is set without mTLS (client_ca_path) but \
                     trust_forwarded_identity=true: identity headers are spoofable without \
                     a verified client certificate"
                );
            }
        }

        Ok(())
    }

    /// Create an example configuration file
    pub fn example() -> Self {
        Config {
            listen_address: "::".to_string(),
            listen_port: 1812,
            secret: "testing123".to_string(),
            clients: vec![
                Client {
                    address: "192.168.1.0/24".to_string(),
                    secret: "client_secret_1".to_string(),
                    name: Some("Internal Network".to_string()),
                    enabled: true,
                    nas_identifier: None,
                },
                Client {
                    address: "10.0.0.1".to_string(),
                    secret: "client_secret_2".to_string(),
                    name: Some("VPN Gateway".to_string()),
                    enabled: true,
                    nas_identifier: Some("vpn-gateway.example.com".to_string()),
                },
                Client {
                    address: "2001:db8::/32".to_string(),
                    secret: "client_secret_3".to_string(),
                    name: Some("IPv6 Network".to_string()),
                    enabled: true,
                    nas_identifier: None,
                },
                Client {
                    address: "::1".to_string(),
                    secret: "client_secret_4".to_string(),
                    name: Some("IPv6 Localhost".to_string()),
                    enabled: true,
                    nas_identifier: None,
                },
            ],
            users: vec![
                User {
                    username: "admin".to_string(),
                    password: "admin123".to_string(),
                    attributes: HashMap::new(),
                },
                User {
                    username: "user1".to_string(),
                    password: "password1".to_string(),
                    attributes: HashMap::new(),
                },
            ],
            verbose: false,
            log_level: Some("info".to_string()),
            audit_log_path: Some("/var/log/radius/audit.log".to_string()),
            accounting_log_path: Some("/var/log/radius/accounting.jsonl".to_string()),
            accounting_database_url: Some(
                "postgresql://radius:password@localhost/radius".to_string(),
            ),
            accounting_retention_days: Some(90),
            strict_rfc_compliance: true,
            request_cache_ttl: Some(60),
            request_cache_max_entries: Some(10000),
            rate_limit_per_client_rps: Some(100),
            rate_limit_per_client_burst: Some(200),
            rate_limit_global_rps: Some(1000),
            rate_limit_global_burst: Some(2000),
            max_concurrent_connections: Some(100),
            max_bandwidth_bps: Some(1_000_000), // 1 MB/s
            ldap: None,
            postgres: None,
            proxy: None,
            eap: None,
            mgmt: None,
            // Example ships udp-insecure so it runs out of the box for dev; the
            // `radsec` block below shows the production transport (just flip
            // `transport` to "radsec" once the certs exist).
            transport: Transport::UdpInsecure,
            radsec: Some(RadSecConfig {
                listen_address: "::".to_string(),
                listen_port: 2083,
                cert_path: "/etc/radius/radsec/server.pem".to_string(),
                key_path: "/etc/radius/radsec/server.key".to_string(),
                client_ca_path: "/etc/radius/radsec/nas-ca.pem".to_string(),
                revocation: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen_port, 1812);
        assert!(!config.secret.is_empty());
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.secret = "".to_string();
        assert!(config.validate().is_err());
    }

    /// Minimal config with an EAP-TLS block carrying the given `revocation` JSON
    /// (or none when `None`).
    fn eap_config_json(revocation: Option<&str>, require_client_cert: bool) -> String {
        let rev = revocation
            .map(|r| format!(", \"revocation\": {r}"))
            .unwrap_or_default();
        format!(
            r#"{{
                "secret": "s3cret",
                "eap": {{
                    "enable_tls": true,
                    "enable_teap": false,
                    "tls": {{
                        "cert_path": "/certs/server.crt",
                        "key_path": "/certs/server.key",
                        "ca_path": "/certs/ca.crt",
                        "require_client_cert": {require_client_cert}{rev}
                    }}
                }}
            }}"#
        )
    }

    #[test]
    fn revocation_block_is_optional_and_absent_by_default() {
        let config: Config = serde_json::from_str(&eap_config_json(None, true)).unwrap();
        assert!(config.eap.as_ref().unwrap().tls.revocation.is_none());
        assert!(config.validate().is_ok());

        let radsec: RadSecConfig =
            serde_json::from_str(r#"{"cert_path": "c", "key_path": "k", "client_ca_path": "ca"}"#)
                .unwrap();
        assert!(radsec.revocation.is_none());
    }

    #[test]
    fn eap_session_limits_default_and_reject_zero() {
        let config: Config = serde_json::from_str(&eap_config_json(None, true)).unwrap();
        let eap = config.eap.as_ref().unwrap();
        assert_eq!(
            eap.session_idle_timeout_secs,
            radius_proto::eap::EapSessionManager::DEFAULT_IDLE_TIMEOUT_SECS
        );
        assert_eq!(
            eap.max_sessions,
            radius_proto::eap::EapSessionManager::DEFAULT_MAX_SESSIONS
        );

        let mut zero_timeout = config.clone();
        zero_timeout.eap.as_mut().unwrap().session_idle_timeout_secs = 0;
        let err = zero_timeout.validate().unwrap_err().to_string();
        assert!(err.contains("session_idle_timeout_secs"), "{err}");

        let mut zero_sessions = config.clone();
        zero_sessions.eap.as_mut().unwrap().max_sessions = 0;
        let err = zero_sessions.validate().unwrap_err().to_string();
        assert!(err.contains("max_sessions"), "{err}");

        let explicit: Config = serde_json::from_str(
            r#"{"secret": "s3cret", "eap": {"enable_tls": true, "session_idle_timeout_secs": 30,
                "max_sessions": 10, "tls": {"cert_path": "c", "key_path": "k"}}}"#,
        )
        .unwrap();
        let eap = explicit.eap.unwrap();
        assert_eq!(eap.session_idle_timeout_secs, 30);
        assert_eq!(eap.max_sessions, 10);
    }

    #[test]
    fn revocation_block_defaults_to_crl_only_fail_closed_with_fetch() {
        let config: Config = serde_json::from_str(&eap_config_json(Some("{}"), true)).unwrap();
        let rev = config.eap.unwrap().tls.revocation.unwrap();
        assert_eq!(rev, RevocationConfig::default());
        assert_eq!(rev.mode, RevocationMode::CrlOnly);
        assert_eq!(rev.on_error, RevocationFailurePolicy::FailClosed);
        assert!(rev.crl.fetch);
        assert!(rev.crl.static_files.is_empty());
        assert_eq!(rev.crl.fetch_timeout_secs, 5);
        assert_eq!(rev.crl.cache_ttl_secs, 3600);
        assert_eq!(rev.crl.max_cache_entries, 100);
        assert_eq!(rev.crl.max_size_bytes, 10 * 1024 * 1024);
        assert_eq!(rev.ocsp.fetch_timeout_secs, 5);
        assert!(rev.ocsp.nonce);
        assert_eq!(rev.ocsp.max_response_size_bytes, 1024 * 1024);
    }

    #[test]
    fn revocation_block_parses_every_field_from_eap_and_radsec() {
        let json = r#"{
            "secret": "s3cret",
            "transport": "radsec",
            "eap": {
                "enable_tls": true,
                "tls": {
                    "cert_path": "c", "key_path": "k", "ca_path": "ca",
                    "require_client_cert": true,
                    "revocation": {
                        "mode": "crl_only",
                        "on_error": "fail_closed",
                        "crl": {
                            "static_files": ["/etc/radius/crl/ca.crl", "/etc/radius/crl/sub.crl"],
                            "fetch": false,
                            "fetch_timeout_secs": 3,
                            "cache_ttl_secs": 600,
                            "max_cache_entries": 10,
                            "max_size_bytes": 1048576
                        }
                    }
                }
            },
            "radsec": {
                "cert_path": "c", "key_path": "k", "client_ca_path": "ca",
                "revocation": {
                    "mode": "prefer_ocsp",
                    "on_error": "fail_open",
                    "ocsp": {
                        "fetch_timeout_secs": 2,
                        "cache_ttl_secs": 120,
                        "max_cache_entries": 50,
                        "nonce": false,
                        "max_response_size_bytes": 4096
                    }
                }
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();

        let eap = config
            .eap
            .as_ref()
            .unwrap()
            .tls
            .revocation
            .as_ref()
            .unwrap();
        assert_eq!(eap.mode, RevocationMode::CrlOnly);
        assert_eq!(eap.on_error, RevocationFailurePolicy::FailClosed);
        assert_eq!(
            eap.crl.static_files,
            vec!["/etc/radius/crl/ca.crl", "/etc/radius/crl/sub.crl"]
        );
        assert!(!eap.crl.fetch);
        assert_eq!(eap.crl.fetch_timeout_secs, 3);
        assert_eq!(eap.crl.cache_ttl_secs, 600);
        assert_eq!(eap.crl.max_cache_entries, 10);
        assert_eq!(eap.crl.max_size_bytes, 1_048_576);
        // Untouched sub-block keeps its defaults.
        assert_eq!(eap.ocsp, OcspSettings::default());

        let radsec = config.radsec.as_ref().unwrap().revocation.as_ref().unwrap();
        assert_eq!(radsec.mode, RevocationMode::PreferOcsp);
        assert_eq!(radsec.on_error, RevocationFailurePolicy::FailOpen);
        assert_eq!(radsec.ocsp.fetch_timeout_secs, 2);
        assert_eq!(radsec.ocsp.cache_ttl_secs, 120);
        assert_eq!(radsec.ocsp.max_cache_entries, 50);
        assert!(!radsec.ocsp.nonce);
        assert_eq!(radsec.ocsp.max_response_size_bytes, 4096);
        assert_eq!(radsec.crl, CrlSettings::default());

        // Round-trips through serde unchanged.
        let again: Config = serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(again.eap.unwrap().tls.revocation.unwrap(), *eap);
        assert_eq!(again.radsec.unwrap().revocation.unwrap(), *radsec);

        #[cfg(feature = "revocation")]
        assert!(config.validate().is_ok(), "{:?}", config.validate());
    }

    #[test]
    fn revocation_mode_and_policy_reject_unknown_values() {
        let bad_mode = eap_config_json(Some(r#"{"mode": "sometimes"}"#), true);
        assert!(serde_json::from_str::<Config>(&bad_mode).is_err());
        let bad_policy = eap_config_json(Some(r#"{"on_error": "shrug"}"#), true);
        assert!(serde_json::from_str::<Config>(&bad_policy).is_err());
    }

    #[test]
    fn revocation_mode_source_predicates() {
        assert!(RevocationMode::CrlOnly.uses_crl());
        assert!(!RevocationMode::CrlOnly.uses_ocsp());
        assert!(!RevocationMode::OcspOnly.uses_crl());
        assert!(RevocationMode::OcspOnly.uses_ocsp());
        assert!(RevocationMode::PreferOcsp.uses_crl() && RevocationMode::PreferOcsp.uses_ocsp());
        assert!(RevocationMode::Both.uses_crl() && RevocationMode::Both.uses_ocsp());
    }

    #[test]
    fn revocation_requires_verified_client_certificates() {
        // No client cert is ever presented, so there is nothing to revoke.
        let config: Config = serde_json::from_str(&eap_config_json(Some("{}"), false)).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("require_client_cert"), "{err}");

        // require_client_cert without a CA bundle is equally meaningless.
        let json = r#"{
            "secret": "s3cret",
            "eap": {"enable_tls": true, "tls": {"cert_path": "c", "key_path": "k",
                    "require_client_cert": true, "revocation": {}}}
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("ca_path"), "{err}");
    }

    #[cfg(feature = "revocation")]
    #[test]
    fn revocation_validation_rejects_crl_mode_without_a_crl_source() {
        let rev = r#"{"mode": "crl_only", "crl": {"fetch": false}}"#;
        let config: Config = serde_json::from_str(&eap_config_json(Some(rev), true)).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("eap.tls.revocation") && err.contains("no CRL source"),
            "{err}"
        );

        // OCSP-only does not need a CRL source.
        let rev = r#"{"mode": "ocsp_only", "crl": {"fetch": false}}"#;
        let config: Config = serde_json::from_str(&eap_config_json(Some(rev), true)).unwrap();
        assert!(config.validate().is_ok());
    }

    #[cfg(feature = "revocation")]
    #[test]
    fn revocation_validation_rejects_zero_limits_and_empty_paths() {
        for rev in [
            r#"{"crl": {"fetch_timeout_secs": 0}}"#,
            r#"{"crl": {"cache_ttl_secs": 0}}"#,
            r#"{"crl": {"max_cache_entries": 0}}"#,
            r#"{"crl": {"max_size_bytes": 0}}"#,
            r#"{"crl": {"fetch": false, "static_files": [""]}}"#,
            r#"{"mode": "ocsp_only", "ocsp": {"fetch_timeout_secs": 0}}"#,
            r#"{"mode": "both", "ocsp": {"cache_ttl_secs": 0}}"#,
            r#"{"mode": "prefer_ocsp", "ocsp": {"max_cache_entries": 0}}"#,
            r#"{"mode": "ocsp_only", "ocsp": {"max_response_size_bytes": 0}}"#,
        ] {
            let config: Config = serde_json::from_str(&eap_config_json(Some(rev), true)).unwrap();
            assert!(config.validate().is_err(), "should reject {rev}");
        }
        // The same rules apply to the RadSec block, named as such.
        let json = r#"{
            "secret": "s3cret",
            "radsec": {"cert_path": "c", "key_path": "k", "client_ca_path": "ca",
                       "revocation": {"crl": {"fetch_timeout_secs": 0}}}
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.starts_with("Invalid configuration: radsec.revocation"),
            "{err}"
        );
    }

    #[cfg(not(feature = "revocation"))]
    #[test]
    fn revocation_block_is_rejected_when_the_feature_is_compiled_out() {
        // Fail closed: a config that asks for revocation checking must not
        // start a binary that cannot enforce it.
        let config: Config = serde_json::from_str(&eap_config_json(Some("{}"), true)).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("revocation"), "{err}");
    }

    #[test]
    fn test_socket_addr() {
        let config = Config::default();
        let addr = config.socket_addr().unwrap();
        assert_eq!(addr.port(), 1812);
    }

    #[test]
    fn test_client_parse_network_single_ip() {
        let client = Client {
            address: "192.168.1.1".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        };

        let network = client.parse_network().unwrap();
        assert!(network.contains("192.168.1.1".parse().unwrap()));
        assert!(!network.contains("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_client_parse_network_cidr() {
        let client = Client {
            address: "192.168.1.0/24".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        };

        let network = client.parse_network().unwrap();
        assert!(network.contains("192.168.1.1".parse().unwrap()));
        assert!(network.contains("192.168.1.254".parse().unwrap()));
        assert!(!network.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_client_matches() {
        let client = Client {
            address: "10.0.0.0/8".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        };

        assert!(client.matches("10.1.2.3".parse().unwrap()).unwrap());
        assert!(client.matches("10.255.255.255".parse().unwrap()).unwrap());
        assert!(!client.matches("11.0.0.1".parse().unwrap()).unwrap());
    }

    #[test]
    fn test_client_invalid_address() {
        let client = Client {
            address: "invalid".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        };

        assert!(client.parse_network().is_err());
    }

    #[test]
    fn test_config_find_client() {
        let config = Config {
            clients: vec![
                Client {
                    address: "192.168.1.0/24".to_string(),
                    secret: "secret1".to_string(),
                    name: Some("Network 1".to_string()),
                    enabled: true,
                    nas_identifier: None,
                },
                Client {
                    address: "10.0.0.1".to_string(),
                    secret: "secret2".to_string(),
                    name: Some("Single IP".to_string()),
                    enabled: true,
                    nas_identifier: None,
                },
            ],
            ..Default::default()
        };

        // Should find matching client
        let client = config.find_client("192.168.1.50".parse().unwrap());
        assert!(client.is_some());
        assert_eq!(client.unwrap().secret, "secret1");

        // Should find exact IP match
        let client = config.find_client("10.0.0.1".parse().unwrap());
        assert!(client.is_some());
        assert_eq!(client.unwrap().secret, "secret2");

        // Should not find non-matching IP
        let client = config.find_client("172.16.0.1".parse().unwrap());
        assert!(client.is_none());
    }

    #[test]
    fn test_find_client_ipv4_mapped_ipv6() {
        // Regression: when the server binds dual-stack `[::]`, IPv4 datagrams arrive
        // with a v4-mapped source (`::ffff:a.b.c.d`). It must still match a v4 client
        // CIDR — otherwise every IPv4 NAS is rejected as unauthorized.
        let config = Config {
            clients: vec![Client {
                address: "10.0.0.0/8".to_string(),
                secret: "secret".to_string(),
                name: Some("v4 net".to_string()),
                enabled: true,
                nas_identifier: None,
            }],
            ..Default::default()
        };

        let mapped: IpAddr = "::ffff:10.0.100.34".parse().unwrap();
        assert!(mapped.is_ipv6(), "test input must be the v4-mapped form");
        assert!(
            config.find_client(mapped).is_some(),
            "v4-mapped IPv6 source must match the v4 client CIDR"
        );
        // And the per-client secret lookup (which routes through find_client) too.
        assert_eq!(config.get_secret_for_client(mapped), b"secret");
    }

    #[test]
    fn test_config_find_client_disabled() {
        let config = Config {
            clients: vec![Client {
                address: "192.168.1.0/24".to_string(),
                secret: "secret1".to_string(),
                name: Some("Network 1".to_string()),
                enabled: false, // Disabled
                nas_identifier: None,
            }],
            ..Default::default()
        };

        // Should not find disabled client
        let client = config.find_client("192.168.1.50".parse().unwrap());
        assert!(client.is_none());
    }

    #[test]
    fn test_config_get_secret_for_client() {
        let config = Config {
            secret: "default_secret".to_string(),
            clients: vec![Client {
                address: "192.168.1.0/24".to_string(),
                secret: "client_secret".to_string(),
                name: Some("Network 1".to_string()),
                enabled: true,
                nas_identifier: None,
            }],
            ..Default::default()
        };

        // Should return client-specific secret
        let secret = config.get_secret_for_client("192.168.1.50".parse().unwrap());
        assert_eq!(secret, b"client_secret");

        // Should return default secret for non-matching IP
        let secret = config.get_secret_for_client("10.0.0.1".parse().unwrap());
        assert_eq!(secret, b"default_secret");
    }

    #[test]
    fn test_config_validation_with_invalid_client_address() {
        let config = Config {
            clients: vec![Client {
                address: "invalid_ip".to_string(),
                secret: "secret".to_string(),
                name: Some("Test".to_string()),
                enabled: true,
                nas_identifier: None,
            }],
            ..Default::default()
        };

        // Should fail validation due to invalid address
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_client_parse_network_ipv6_single() {
        let client = Client {
            address: "::1".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        };

        let network = client.parse_network().unwrap();
        assert!(network.contains("::1".parse().unwrap()));
        assert!(!network.contains("::2".parse().unwrap()));
    }

    #[test]
    fn test_client_parse_network_ipv6_cidr() {
        let client = Client {
            address: "2001:db8::/32".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        };

        let network = client.parse_network().unwrap();
        assert!(network.contains("2001:db8::1".parse().unwrap()));
        assert!(network.contains("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!network.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_client_matches_ipv6() {
        let client = Client {
            address: "fe80::/10".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        };

        assert!(client.matches("fe80::1".parse().unwrap()).unwrap());
        assert!(client.matches("fe80::dead:beef".parse().unwrap()).unwrap());
        assert!(!client.matches("2001:db8::1".parse().unwrap()).unwrap());
    }

    #[test]
    fn test_config_find_client_ipv6() {
        let config = Config {
            clients: vec![
                Client {
                    address: "2001:db8::/32".to_string(),
                    secret: "secret1".to_string(),
                    name: Some("IPv6 Network".to_string()),
                    enabled: true,
                    nas_identifier: None,
                },
                Client {
                    address: "::1".to_string(),
                    secret: "secret2".to_string(),
                    name: Some("IPv6 Localhost".to_string()),
                    enabled: true,
                    nas_identifier: None,
                },
            ],
            ..Default::default()
        };

        // Should find matching IPv6 client
        let client = config.find_client("2001:db8::50".parse().unwrap());
        assert!(client.is_some());
        assert_eq!(client.unwrap().secret, "secret1");

        // Should find exact IPv6 match
        let client = config.find_client("::1".parse().unwrap());
        assert!(client.is_some());
        assert_eq!(client.unwrap().secret, "secret2");

        // Should not find non-matching IPv6
        let client = config.find_client("2001:db9::1".parse().unwrap());
        assert!(client.is_none());
    }

    #[test]
    fn test_config_socket_addr_ipv6() {
        let config = Config {
            listen_address: "::1".to_string(),
            listen_port: 1812,
            ..Default::default()
        };

        let addr = config.socket_addr().unwrap();
        assert_eq!(addr.port(), 1812);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_expand_env_vars() {
        // SAFETY: This test runs in isolation and sets/removes test-specific environment variables.
        // The variables are cleaned up at the end of the test.
        unsafe {
            env::set_var("TEST_SECRET", "my_secret_value");
            env::set_var("TEST_PORT", "1234");
        }

        let result = expand_env_vars("${TEST_SECRET}").unwrap();
        assert_eq!(result, "my_secret_value");

        let result = expand_env_vars("prefix_${TEST_SECRET}_suffix").unwrap();
        assert_eq!(result, "prefix_my_secret_value_suffix");

        let result = expand_env_vars("port=${TEST_PORT}").unwrap();
        assert_eq!(result, "port=1234");

        // SAFETY: Cleaning up test-specific environment variables
        unsafe {
            env::remove_var("TEST_SECRET");
            env::remove_var("TEST_PORT");
        }
    }

    #[test]
    fn test_expand_env_vars_not_found() {
        let result = expand_env_vars("${NONEXISTENT_VAR}");
        assert!(result.is_err());
        match result {
            Err(ConfigError::EnvVarNotFound(var)) => assert_eq!(var, "NONEXISTENT_VAR"),
            _ => panic!("Expected EnvVarNotFound error"),
        }
    }

    #[test]
    fn test_expand_env_vars_no_expansion() {
        let result = expand_env_vars("plain_text").unwrap();
        assert_eq!(result, "plain_text");

        let result = expand_env_vars("no_vars_here").unwrap();
        assert_eq!(result, "no_vars_here");
    }
}
