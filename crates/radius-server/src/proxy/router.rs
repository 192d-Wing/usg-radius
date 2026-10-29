//! RADIUS proxy routing engine
//!
//! The router determines where to forward RADIUS requests based on realm matching.

use crate::proxy::home_server::HomeServer;
use crate::proxy::realm::{Realm, extract_realm, strip_realm};
use radius_proto::Packet;
use radius_proto::attributes::AttributeType;
use std::sync::Arc;
use tracing::{debug, warn};

/// Routing decision
#[derive(Debug, Clone)]
pub enum RoutingDecision {
    /// Proxy the request to a home server
    Proxy {
        /// Target home server
        home_server: Arc<HomeServer>,
        /// Stripped username (if strip_realm is enabled)
        stripped_username: Option<String>,
    },
    /// Authenticate locally (no realm match)
    Local,
    /// Reject immediately (realm found but no route)
    Reject,
}

/// Router
pub struct Router {
    /// Configured realms (in order of priority)
    realms: Vec<Realm>,
    /// Default realm for unmatched requests
    /// "local" = authenticate locally
    /// realm name = proxy to that realm's pool
    default_realm: Option<String>,
}

impl Router {
    /// Create a new router
    pub fn new(realms: Vec<Realm>, default_realm: Option<String>) -> Self {
        Router {
            realms,
            default_realm,
        }
    }

    /// Route a request based on User-Name realm
    ///
    /// # Process
    /// 1. Extract User-Name attribute
    /// 2. Parse realm from username
    /// 3. Find matching Realm configuration
    /// 4. Select home server from pool
    /// 5. Return RoutingDecision
    pub fn route_request(&self, request: &Packet) -> RoutingDecision {
        // Extract username
        let username = match request
            .find_attribute(AttributeType::UserName as u8)
            .and_then(|attr| attr.as_string().ok())
        {
            Some(name) => name,
            None => {
                warn!("Access-Request missing User-Name attribute");
                return RoutingDecision::Reject;
            }
        };

        // Extract realm from username
        let realm = extract_realm(&username);

        debug!(
            username = %username,
            realm = ?realm,
            "Routing request"
        );

        // Try to find matching realm configuration
        if let Some(realm_str) = realm {
            for configured_realm in &self.realms {
                if configured_realm.matches(&realm_str) {
                    debug!(
                        realm = %realm_str,
                        configured_realm = %configured_realm.name,
                        "Found matching realm"
                    );

                    // Select server from pool
                    match configured_realm.pool.select_server() {
                        Some(home_server) => {
                            let stripped_username = if configured_realm.strip_realm {
                                Some(strip_realm(&username))
                            } else {
                                None
                            };

                            debug!(
                                home_server = %home_server.name,
                                strip_realm = configured_realm.strip_realm,
                                "Selected home server"
                            );

                            return RoutingDecision::Proxy {
                                home_server,
                                stripped_username,
                            };
                        }
                        None => {
                            warn!(
                                realm = %realm_str,
                                pool = %configured_realm.name,
                                "No available servers in pool"
                            );
                            return RoutingDecision::Reject;
                        }
                    }
                }
            }

            // Realm found but no matching configuration
            warn!(
                realm = %realm_str,
                "Realm found but no matching configuration"
            );

            // Check default realm
            return self.handle_default_realm();
        }

        // No realm in username
        debug!(username = %username, "No realm in username");

        // Check default realm
        self.handle_default_realm()
    }

    /// Handle default realm routing
    fn handle_default_realm(&self) -> RoutingDecision {
        match &self.default_realm {
            Some(default) if default == "local" => {
                debug!("Using default realm: local authentication");
                RoutingDecision::Local
            }
            Some(default) => {
                // Try to find the default realm in configured realms
                for realm in &self.realms {
                    if &realm.name == default {
                        match realm.pool.select_server() {
                            Some(home_server) => {
                                debug!(
                                    default_realm = %default,
                                    home_server = %home_server.name,
                                    "Using default realm routing"
                                );
                                return RoutingDecision::Proxy {
                                    home_server,
                                    stripped_username: None,
                                };
                            }
                            None => {
                                warn!(default_realm = %default, "No available servers in default realm pool");
                                return RoutingDecision::Reject;
                            }
                        }
                    }
                }

                warn!(default_realm = %default, "Default realm not found in configuration");
                RoutingDecision::Reject
            }
            None => {
                debug!("No default realm configured, authenticating locally");
                RoutingDecision::Local
            }
        }
    }

    /// Get number of configured realms
    pub fn realm_count(&self) -> usize {
        self.realms.len()
    }

    /// Check if a realm is configured
    pub fn has_realm(&self, realm_name: &str) -> bool {
        self.realms.iter().any(|r| r.name == realm_name)
    }
}

impl Default for Router {
    fn default() -> Self {
        Router::new(vec![], Some("local".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::home_server::HomeServerConfig;
    use crate::proxy::pool::{HomeServerPool, HomeServerPoolConfig, LoadBalanceStrategy};
    use crate::proxy::realm::{Realm, RealmConfig, RealmMatchConfig};
    use radius_proto::Code;
    use radius_proto::attributes::Attribute;

    fn create_test_pool(name: &str, server_name: &str) -> Arc<HomeServerPool> {
        let config = HomeServerPoolConfig {
            name: name.to_string(),
            strategy: LoadBalanceStrategy::RoundRobin,
            servers: vec![HomeServerConfig {
                name: Some(server_name.to_string()),
                ..HomeServerConfig::udp("127.0.0.1:1812", "test_secret")
            }],
        };

        Arc::new(HomeServerPool::new(config).unwrap())
    }

    fn create_test_request(username: &str) -> Packet {
        let mut packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
        packet.add_attribute(Attribute::string(AttributeType::UserName as u8, username).unwrap());
        packet
    }

    #[test]
    fn test_router_default() {
        let router = Router::default();
        assert_eq!(router.realm_count(), 0);

        let request = create_test_request("testuser");
        let decision = router.route_request(&request);

        match decision {
            RoutingDecision::Local => {}
            _ => panic!("Expected Local decision"),
        }
    }

    #[test]
    fn test_router_no_username() {
        let router = Router::default();
        let request = Packet::new(Code::AccessRequest, 1, [0u8; 16]);

        let decision = router.route_request(&request);

        match decision {
            RoutingDecision::Reject => {}
            _ => panic!("Expected Reject decision"),
        }
    }

    #[test]
    fn test_router_realm_match_exact() {
        let pool = create_test_pool("test_pool", "test_server");

        let realm_config = RealmConfig {
            name: "corporate".to_string(),
            match_config: RealmMatchConfig {
                match_type: "exact".to_string(),
                pattern: "CORPORATE".to_string(),
            },
            pool: "test_pool".to_string(),
            strip_realm: false,
        };

        let realm = Realm::new(realm_config, pool).unwrap();
        let router = Router::new(vec![realm], Some("local".to_string()));

        let request = create_test_request("CORPORATE\\john");
        let decision = router.route_request(&request);

        match decision {
            RoutingDecision::Proxy {
                home_server,
                stripped_username,
            } => {
                assert_eq!(home_server.name, "test_server");
                assert_eq!(stripped_username, None); // strip_realm is false
            }
            _ => panic!("Expected Proxy decision"),
        }
    }

    #[test]
    fn test_router_realm_match_suffix() {
        let pool = create_test_pool("example_pool", "example_server");

        let realm_config = RealmConfig {
            name: "example.com".to_string(),
            match_config: RealmMatchConfig {
                match_type: "suffix".to_string(),
                pattern: "example.com".to_string(),
            },
            pool: "example_pool".to_string(),
            strip_realm: true,
        };

        let realm = Realm::new(realm_config, pool).unwrap();
        let router = Router::new(vec![realm], None);

        let request = create_test_request("user@example.com");
        let decision = router.route_request(&request);

        match decision {
            RoutingDecision::Proxy {
                home_server,
                stripped_username,
            } => {
                assert_eq!(home_server.name, "example_server");
                assert_eq!(stripped_username, Some("user".to_string()));
            }
            _ => panic!("Expected Proxy decision"),
        }
    }

    #[test]
    fn test_router_no_realm_default_local() {
        let router = Router::new(vec![], Some("local".to_string()));

        let request = create_test_request("plainuser");
        let decision = router.route_request(&request);

        match decision {
            RoutingDecision::Local => {}
            _ => panic!("Expected Local decision"),
        }
    }

    #[test]
    fn test_router_no_realm_no_default() {
        let router = Router::new(vec![], None);

        let request = create_test_request("plainuser");
        let decision = router.route_request(&request);

        match decision {
            RoutingDecision::Local => {} // Falls back to local if no default
            _ => panic!("Expected Local decision"),
        }
    }

    #[test]
    fn test_router_realm_not_found() {
        let router = Router::new(vec![], Some("local".to_string()));

        let request = create_test_request("user@unknown.com");
        let decision = router.route_request(&request);

        match decision {
            RoutingDecision::Local => {} // Uses default realm (local)
            _ => panic!("Expected Local decision"),
        }
    }

    #[test]
    fn test_router_has_realm() {
        let pool = create_test_pool("test_pool", "test_server");
        let realm_config = RealmConfig {
            name: "test_realm".to_string(),
            match_config: RealmMatchConfig {
                match_type: "exact".to_string(),
                pattern: "TEST".to_string(),
            },
            pool: "test_pool".to_string(),
            strip_realm: false,
        };

        let realm = Realm::new(realm_config, pool).unwrap();
        let router = Router::new(vec![realm], None);

        assert!(router.has_realm("test_realm"));
        assert!(!router.has_realm("other_realm"));
    }
}
