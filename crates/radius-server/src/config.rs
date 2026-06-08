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
    /// TLS certificate configuration shared by EAP-TLS and EAP-TEAP.
    pub tls: EapTlsConfig,
    /// Enable EAP-TLS (Type 13). Default: false.
    #[serde(default)]
    pub enable_tls: bool,
    /// Enable EAP-TEAP (Type 55, RFC 7170). Default: true.
    #[serde(default = "default_true")]
    pub enable_teap: bool,
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
}

fn default_true() -> bool {
    true
}

fn default_listen_address() -> String {
    "::".to_string() // IPv6 unspecified - accepts both IPv6 and IPv4-mapped IPv6 on most systems
}

fn default_listen_port() -> u16 {
    1812 // Standard RADIUS authentication port
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
        let mut config = Config::default();
        config.clients = vec![
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
        ];

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
    fn test_config_find_client_disabled() {
        let mut config = Config::default();
        config.clients = vec![Client {
            address: "192.168.1.0/24".to_string(),
            secret: "secret1".to_string(),
            name: Some("Network 1".to_string()),
            enabled: false, // Disabled
            nas_identifier: None,
        }];

        // Should not find disabled client
        let client = config.find_client("192.168.1.50".parse().unwrap());
        assert!(client.is_none());
    }

    #[test]
    fn test_config_get_secret_for_client() {
        let mut config = Config::default();
        config.secret = "default_secret".to_string();
        config.clients = vec![Client {
            address: "192.168.1.0/24".to_string(),
            secret: "client_secret".to_string(),
            name: Some("Network 1".to_string()),
            enabled: true,
            nas_identifier: None,
        }];

        // Should return client-specific secret
        let secret = config.get_secret_for_client("192.168.1.50".parse().unwrap());
        assert_eq!(secret, b"client_secret");

        // Should return default secret for non-matching IP
        let secret = config.get_secret_for_client("10.0.0.1".parse().unwrap());
        assert_eq!(secret, b"default_secret");
    }

    #[test]
    fn test_config_validation_with_invalid_client_address() {
        let mut config = Config::default();
        config.clients = vec![Client {
            address: "invalid_ip".to_string(),
            secret: "secret".to_string(),
            name: Some("Test".to_string()),
            enabled: true,
            nas_identifier: None,
        }];

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
        let mut config = Config::default();
        config.clients = vec![
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
        ];

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
        let mut config = Config::default();
        config.listen_address = "::1".to_string();
        config.listen_port = 1812;

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
