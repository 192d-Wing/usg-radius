//! EAP Authentication Handler
//!
//! This module provides authentication handlers for various EAP methods including
//! EAP-TLS, EAP-MD5, and potentially other methods in the future.
//!
//! The EAP handler integrates with the RADIUS server's AuthHandler trait and manages
//! multi-round EAP authentication sessions.

use radius_proto::eap::{EapPacket, EapSessionManager, EapState, EapType};
use radius_proto::{Attribute, Packet};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, warn};

use crate::server::{AuthHandler, AuthResult};

#[cfg(feature = "tls")]
use radius_proto::eap::eap_tls::{
    EapTlsPacket, EapTlsServer, TlsCertificateConfig, build_server_config,
};

#[cfg(feature = "tls")]
use std::sync::Arc as StdArc;

/// EAP Authentication Handler
///
/// Manages EAP authentication sessions and delegates to method-specific handlers.
///
/// # Example
///
/// ```no_run
/// use radius_server::eap_auth::EapAuthHandler;
/// use radius_server::server::SimpleAuthHandler;
/// use std::sync::Arc;
///
/// // Create inner handler for credential verification
/// let mut inner = SimpleAuthHandler::new();
/// inner.add_user("alice", "password123");
///
/// // Create EAP handler
/// let eap_handler = EapAuthHandler::new(Arc::new(inner));
///
/// // EAP handler can now be used as AuthHandler for RADIUS server
/// ```
pub struct EapAuthHandler {
    /// Session manager for tracking EAP authentication sessions
    session_manager: Arc<RwLock<EapSessionManager>>,

    /// Inner authentication handler for credential verification
    /// Used by EAP methods that require password validation (e.g., EAP-MD5)
    inner_handler: Arc<dyn AuthHandler>,

    /// EAP-TLS server configurations (if TLS feature is enabled)
    #[cfg(feature = "tls")]
    tls_configs: Arc<RwLock<HashMap<String, StdArc<rustls::ServerConfig>>>>,

    /// Active EAP-TLS sessions (if TLS feature is enabled)
    #[cfg(feature = "tls")]
    tls_sessions: Arc<RwLock<HashMap<String, EapTlsServer>>>,

    /// Active EAP-TEAP sessions (if TLS feature is enabled)
    #[cfg(feature = "tls")]
    teap_sessions: Arc<RwLock<HashMap<String, radius_proto::eap::eap_teap::EapTeapServer>>>,
}

impl EapAuthHandler {
    /// Create a new EAP authentication handler
    ///
    /// # Arguments
    ///
    /// * `inner_handler` - Handler for credential verification (used by password-based EAP methods)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use radius_server::eap_auth::EapAuthHandler;
    /// # use radius_server::server::SimpleAuthHandler;
    /// # use std::sync::Arc;
    /// let inner = SimpleAuthHandler::new();
    /// let eap_handler = EapAuthHandler::new(Arc::new(inner));
    /// ```
    pub fn new(inner_handler: Arc<dyn AuthHandler>) -> Self {
        EapAuthHandler {
            session_manager: Arc::new(RwLock::new(EapSessionManager::new())),
            inner_handler,
            #[cfg(feature = "tls")]
            tls_configs: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "tls")]
            tls_sessions: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "tls")]
            teap_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure EAP-TLS for a specific realm or default
    ///
    /// # Arguments
    ///
    /// * `realm` - Realm identifier (use "" for default)
    /// * `cert_config` - TLS certificate configuration
    ///
    /// # Returns
    ///
    /// Result indicating success or error
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # {
    /// # use radius_server::eap_auth::EapAuthHandler;
    /// # use radius_server::server::SimpleAuthHandler;
    /// # use radius_proto::eap::eap_tls::TlsCertificateConfig;
    /// # use std::sync::Arc;
    /// # let inner = SimpleAuthHandler::new();
    /// let mut eap_handler = EapAuthHandler::new(Arc::new(inner));
    ///
    /// let tls_config = TlsCertificateConfig::simple(
    ///     "certs/server.pem".to_string(),
    ///     "certs/server-key.pem".to_string(),
    /// );
    ///
    /// eap_handler.configure_tls("", tls_config).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn configure_tls(
        &mut self,
        realm: &str,
        cert_config: TlsCertificateConfig,
    ) -> Result<(), String> {
        let server_config = build_server_config(&cert_config)
            .map_err(|e| format!("Failed to build TLS config: {:?}", e))?;

        let mut configs = self.tls_configs.write().unwrap();
        configs.insert(realm.to_string(), StdArc::new(server_config));

        Ok(())
    }

    /// Configure EAP-TEAP for a specific realm or default
    ///
    /// # Arguments
    ///
    /// * `realm` - Realm identifier (use "" for default)
    /// * `cert_config` - TLS certificate configuration (same as EAP-TLS)
    ///
    /// # Returns
    ///
    /// Result indicating success or error
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # {
    /// # use radius_server::eap_auth::EapAuthHandler;
    /// # use radius_server::server::SimpleAuthHandler;
    /// # use radius_proto::eap::eap_tls::TlsCertificateConfig;
    /// # use std::sync::Arc;
    /// # let inner = SimpleAuthHandler::new();
    /// let mut eap_handler = EapAuthHandler::new(Arc::new(inner));
    ///
    /// let tls_config = TlsCertificateConfig::simple(
    ///     "certs/server.pem".to_string(),
    ///     "certs/server-key.pem".to_string(),
    /// );
    ///
    /// // TEAP uses the same TLS configuration as EAP-TLS for Phase 1
    /// eap_handler.configure_teap("", tls_config).unwrap();
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn configure_teap(
        &mut self,
        realm: &str,
        cert_config: TlsCertificateConfig,
    ) -> Result<(), String> {
        // TEAP uses the same TLS config as EAP-TLS for Phase 1
        // Store it in tls_configs for use when creating TEAP sessions
        let server_config = build_server_config(&cert_config)
            .map_err(|e| format!("Failed to build TLS config: {:?}", e))?;

        let mut configs = self.tls_configs.write().unwrap();
        configs.insert(format!("teap_{}", realm), StdArc::new(server_config));

        Ok(())
    }

    /// Get or create an EAP session for a user
    fn get_or_create_session(&self, username: &str, state: Option<&[u8]>) -> String {
        let mut manager = self.session_manager.write().unwrap();

        // If state is provided, try to find existing session
        if let Some(state_bytes) = state {
            // State format: session_id encoded as string
            if let Ok(session_id) = String::from_utf8(state_bytes.to_vec())
                && manager.get_session(&session_id).is_some()
            {
                return session_id;
            }
        }

        // Create new session
        let session_id = format!("{}-{}", username, chrono::Utc::now().timestamp_millis());
        manager.create_session(session_id.clone());
        session_id
    }

    /// Handle EAP-Identity exchange.
    ///
    /// Decides which EAP method to propose to the peer based on what was
    /// configured: prefers EAP-TEAP when a TEAP TLS context exists, falls
    /// back to EAP-TLS, then EAP-MD5. The session-manager write lock is
    /// released before calling `start_eap_*` because those methods reacquire
    /// the same lock to bump the identifier counter — std::sync::RwLock is
    /// not reentrant.
    fn handle_identity(&self, username: &str, session_id: &str) -> AuthResult {
        // Pick the preferred method up-front so we can release the session
        // lock before calling start_eap_*.
        #[cfg(feature = "tls")]
        let preferred = {
            let configs = self.tls_configs.read().unwrap();
            if configs.keys().any(|k| k.starts_with("teap_")) {
                Some(EapType::Teap)
            } else if configs.contains_key("") {
                Some(EapType::Tls)
            } else {
                None
            }
        };
        #[cfg(not(feature = "tls"))]
        let preferred = Some(EapType::Md5Challenge);

        // Mutate session state, then drop the lock.
        {
            let mut manager = self.session_manager.write().unwrap();
            let Some(session) = manager.get_session_mut(session_id) else {
                warn!(session_id, "handle_identity: session not found");
                return AuthResult::Reject;
            };
            session.identity = Some(username.to_string());
            let _ = session.transition(EapState::IdentityReceived);
            let _ = session.transition(EapState::MethodRequested);
            session.eap_method = preferred;
        } // session_manager write lock released here

        debug!(username, session_id, method = ?preferred, "handle_identity dispatch");

        match preferred {
            #[cfg(feature = "tls")]
            Some(EapType::Teap) => self.start_eap_teap(username, session_id),
            #[cfg(feature = "tls")]
            Some(EapType::Tls) => self.start_eap_tls(username, session_id),
            #[cfg(not(feature = "tls"))]
            Some(EapType::Md5Challenge) => self.start_eap_md5(username, session_id),
            _ => {
                error!(
                    "handle_identity: no EAP method configured (configure_tls / configure_teap not called)"
                );
                AuthResult::Reject
            }
        }
    }

    /// Start EAP-MD5 Challenge authentication
    #[allow(dead_code)]
    fn start_eap_md5(&self, _username: &str, _session_id: &str) -> AuthResult {
        // EAP-MD5 implementation would go here
        // For now, not implemented
        AuthResult::Reject
    }

    /// Start EAP-TLS authentication
    #[cfg(feature = "tls")]
    fn start_eap_tls(&self, _username: &str, session_id: &str) -> AuthResult {
        let configs = self.tls_configs.read().unwrap();
        let Some(config) = configs.get("").or_else(|| configs.values().next()) else {
            error!(session_id, "start_eap_tls: no TLS config registered");
            return AuthResult::Reject;
        };
        let config = StdArc::clone(config);
        drop(configs);

        let mut tls_server = EapTlsServer::new(config);
        if let Err(e) = tls_server.initialize_connection() {
            error!(session_id, error = ?e, "start_eap_tls: initialize_connection failed");
            return AuthResult::Reject;
        }

        {
            let mut tls_sessions = self.tls_sessions.write().unwrap();
            tls_sessions.insert(session_id.to_string(), tls_server);
        }

        let identifier = {
            let mut manager = self.session_manager.write().unwrap();
            match manager.get_session_mut(session_id) {
                Some(s) => s.next_identifier(),
                None => {
                    error!(
                        session_id,
                        "start_eap_tls: session vanished before identifier bump"
                    );
                    return AuthResult::Reject;
                }
            }
        };

        let eap_packet = EapTlsPacket::start().to_eap_request(identifier);
        match radius_proto::eap::eap_to_radius_attributes(&eap_packet) {
            Ok(eap_attrs) => {
                debug!(
                    session_id,
                    identifier, "start_eap_tls: sending EAP-TLS Start"
                );
                AuthResult::Challenge {
                    message: Some("EAP-TLS authentication".to_string()),
                    state: session_id.as_bytes().to_vec(),
                    attributes: eap_attrs,
                }
            }
            Err(e) => {
                error!(session_id, error = ?e, "start_eap_tls: eap_to_radius_attributes failed");
                AuthResult::Reject
            }
        }
    }

    /// Start EAP-TEAP authentication
    #[cfg(feature = "tls")]
    fn start_eap_teap(&self, username: &str, session_id: &str) -> AuthResult {
        // Get TEAP TLS config for user's realm (or default)
        let configs = self.tls_configs.read().unwrap();
        let tls_config = configs.get("teap_").or_else(|| {
            // Fallback to checking for teap_<realm> configs
            configs
                .keys()
                .find(|k| k.starts_with("teap_"))
                .and_then(|k| configs.get(k))
        });

        if let Some(config) = tls_config {
            // Create inner authentication handler for Phase 2
            // Get user credentials from inner handler
            let password = self
                .inner_handler
                .get_user_password(username)
                .unwrap_or_else(|| String::from(""));

            let inner_method =
                Box::new(radius_proto::eap::eap_teap::BasicPasswordAuthHandler::new(
                    username.to_string(),
                    password,
                ));

            // Create EAP-TEAP server for this session
            let teap_server = radius_proto::eap::eap_teap::EapTeapServer::with_inner_method(
                StdArc::clone(config),
                inner_method,
            );

            // Store TEAP session
            let mut teap_sessions = self.teap_sessions.write().unwrap();
            teap_sessions.insert(session_id.to_string(), teap_server);

            // Create EAP-TEAP Start packet (uses EAP-TLS packet format)
            let start_packet = EapTlsPacket::start();
            let identifier = {
                let mut manager = self.session_manager.write().unwrap();
                if let Some(session) = manager.get_session_mut(session_id) {
                    session.next_identifier()
                } else {
                    0
                }
            };

            // Create EAP packet with TEAP type (55)
            let eap_data = start_packet.to_eap_data();
            let eap_packet = radius_proto::eap::EapPacket::new(
                radius_proto::eap::EapCode::Request,
                identifier,
                Some(radius_proto::eap::EapType::Teap),
                eap_data,
            );

            // Convert EAP packet to RADIUS attributes
            match radius_proto::eap::eap_to_radius_attributes(&eap_packet) {
                Ok(eap_attrs) => {
                    debug!(
                        session_id,
                        identifier, "start_eap_teap: sending EAP-TEAP Start"
                    );
                    return AuthResult::Challenge {
                        message: Some("EAP-TEAP authentication".to_string()),
                        state: session_id.as_bytes().to_vec(),
                        attributes: eap_attrs,
                    };
                }
                Err(e) => {
                    error!(session_id, error = ?e, "start_eap_teap: eap_to_radius_attributes failed");
                }
            }
        } else {
            error!(
                session_id,
                "start_eap_teap: no TEAP TLS config registered (configure_teap was never called)"
            );
        }

        AuthResult::Reject
    }

    /// Continue EAP-TLS authentication.
    ///
    /// Drives the TLS handshake one EAP round-trip at a time. The peer sends
    /// either (a) an EAP-TLS ACK — empty payload, signaling "ready for next
    /// fragment" — or (b) actual TLS data. We handle both by checking the
    /// per-session outgoing fragment queue first; only when it's drained do we
    /// feed the incoming bytes to rustls.
    #[cfg(feature = "tls")]
    fn continue_eap_tls(
        &self,
        username: &str,
        session_id: &str,
        eap_response: &EapPacket,
    ) -> AuthResult {
        let mut tls_sessions = self.tls_sessions.write().unwrap();
        let Some(tls_server) = tls_sessions.get_mut(session_id) else {
            error!(
                session_id,
                "continue_eap_tls: no TLS session (state expired?)"
            );
            return AuthResult::Reject;
        };

        // Helper to allocate the next EAP identifier (release the session
        // manager lock immediately so we don't hold it across the build path).
        let next_id = || {
            let mut manager = self.session_manager.write().unwrap();
            manager
                .get_session_mut(session_id)
                .map(|s| s.next_identifier())
                .unwrap_or_else(|| eap_response.identifier.wrapping_add(1))
        };

        // Helper to wrap a single outgoing EAP-TLS fragment into an
        // Access-Challenge result.
        let make_challenge = |frag: EapTlsPacket, id: u8| -> Option<AuthResult> {
            let eap_packet = frag.to_eap_request(id);
            match radius_proto::eap::eap_to_radius_attributes(&eap_packet) {
                Ok(attrs) => Some(AuthResult::Challenge {
                    message: None,
                    state: session_id.as_bytes().to_vec(),
                    attributes: attrs,
                }),
                Err(e) => {
                    error!(session_id, error = ?e, "continue_eap_tls: eap_to_radius_attributes failed");
                    None
                }
            }
        };

        // 1) Peer-ACK path: still have queued fragments from a previous round.
        if tls_server.has_pending_fragments() {
            let Some(frag) = tls_server.next_outgoing_fragment() else {
                error!(session_id, "continue_eap_tls: has_pending_fragments lied");
                return AuthResult::Reject;
            };
            let id = next_id();
            debug!(
                session_id,
                identifier = id,
                "continue_eap_tls: sending next fragment"
            );
            return make_challenge(frag, id).unwrap_or(AuthResult::Reject);
        }

        // 2) Otherwise: parse the inbound EAP-TLS packet and feed rustls.
        let tls_packet = match EapTlsPacket::from_eap_data(&eap_response.data) {
            Ok(p) => p,
            Err(e) => {
                error!(session_id, error = ?e, "continue_eap_tls: malformed EAP-TLS packet");
                return AuthResult::Reject;
            }
        };

        match tls_server.process_client_message(&tls_packet) {
            // Rustls produced outbound TLS data — queue it as fragments and
            // send the first one. Subsequent rounds will hit the ACK path.
            Ok(Some(response_data)) => {
                tls_server.queue_outgoing_tls(response_data, 1020);
                let Some(frag) = tls_server.next_outgoing_fragment() else {
                    error!(session_id, "continue_eap_tls: queue produced no fragments");
                    return AuthResult::Reject;
                };
                let id = next_id();
                debug!(
                    session_id,
                    identifier = id,
                    "continue_eap_tls: sending first fragment of new TLS message"
                );
                make_challenge(frag, id).unwrap_or(AuthResult::Reject)
            }

            // No outbound data. Either the handshake just finished, or rustls
            // is still waiting for more from the peer.
            Ok(None) => {
                if !tls_server.is_handshake_complete() {
                    // Mid-handshake with nothing to send back is wrong — peer
                    // sent us nothing we could act on.
                    warn!(
                        session_id,
                        "continue_eap_tls: no outbound TLS, handshake incomplete"
                    );
                    return AuthResult::Reject;
                }
                if tls_server.extract_keys().is_err() {
                    error!(
                        session_id,
                        "continue_eap_tls: extract_keys failed after handshake"
                    );
                    return AuthResult::Reject;
                }
                let identity_verified =
                    if let Some(_peer_certs) = tls_server.get_peer_certificates() {
                        tls_server.verify_peer_identity(username).unwrap_or(false)
                    } else {
                        true // server-only authentication
                    };
                if !identity_verified {
                    warn!(
                        session_id,
                        username, "continue_eap_tls: peer identity verification failed"
                    );
                    return AuthResult::Reject;
                }

                // Build an EAP-Success packet and attach it to the Accept as
                // EAP-Message attribute(s). RFC 3579 §3.3: the server.rs
                // helper will then add Message-Authenticator before computing
                // Response-Authenticator.
                let success_id = {
                    let mut manager = self.session_manager.write().unwrap();
                    if let Some(s) = manager.get_session_mut(session_id) {
                        let _ = s.transition(EapState::Success);
                        s.next_identifier()
                    } else {
                        eap_response.identifier.wrapping_add(1)
                    }
                };
                let success = EapPacket::success(success_id);
                let attrs = match radius_proto::eap::eap_to_radius_attributes(&success) {
                    Ok(a) => a,
                    Err(e) => {
                        error!(session_id, error = ?e, "continue_eap_tls: failed to wrap EAP-Success");
                        return AuthResult::Reject;
                    }
                };
                debug!(
                    session_id,
                    username, "continue_eap_tls: handshake complete, EAP-Success"
                );
                // TODO: derive MS-MPPE keys from the MSK and attach to the Accept.
                AuthResult::Accept { attributes: attrs }
            }

            Err(e) => {
                error!(session_id, error = ?e, "continue_eap_tls: TLS processing error");
                AuthResult::Reject
            }
        }
    }

    /// Continue EAP-TEAP authentication
    #[cfg(feature = "tls")]
    #[allow(unused_variables)]
    fn continue_eap_teap(
        &self,
        username: &str,
        session_id: &str,
        eap_response: &EapPacket,
    ) -> AuthResult {
        let mut teap_sessions = self.teap_sessions.write().unwrap();

        if let Some(teap_server) = teap_sessions.get_mut(session_id) {
            // Parse EAP-TLS packet from EAP data (TEAP uses EAP-TLS packet format)
            if let Ok(tls_packet) = EapTlsPacket::from_eap_data(&eap_response.data) {
                // Process client message through TEAP server
                match teap_server.process_client_message(&tls_packet) {
                    Ok(Some(ref response_data)) => {
                        // Create response packet
                        let identifier = {
                            let mut manager = self.session_manager.write().unwrap();
                            if let Some(session) = manager.get_session_mut(session_id) {
                                session.next_identifier()
                            } else {
                                eap_response.identifier.wrapping_add(1)
                            }
                        };

                        // Fragment if needed and create EAP-TEAP packets
                        let fragments =
                            radius_proto::eap::eap_tls::fragment_tls_message(response_data, 1020);

                        if let Some(first_fragment) = fragments.first() {
                            // Create EAP packet with TEAP type
                            let eap_data = first_fragment.to_eap_data();
                            let eap_packet = radius_proto::eap::EapPacket::new(
                                radius_proto::eap::EapCode::Request,
                                identifier,
                                Some(radius_proto::eap::EapType::Teap),
                                eap_data,
                            );

                            if let Ok(eap_attrs) =
                                radius_proto::eap::eap_to_radius_attributes(&eap_packet)
                            {
                                return AuthResult::Challenge {
                                    message: None,
                                    state: session_id.as_bytes().to_vec(),
                                    attributes: eap_attrs,
                                };
                            }
                        }
                    }
                    Ok(None) => {
                        // Check if TEAP authentication is complete
                        if teap_server.is_complete() {
                            // Success!
                            let identifier = {
                                let mut manager = self.session_manager.write().unwrap();
                                if let Some(session) = manager.get_session_mut(session_id) {
                                    let _ = session.transition(EapState::Success);
                                    session.next_identifier()
                                } else {
                                    eap_response.identifier.wrapping_add(1)
                                }
                            };

                            let success_packet = EapPacket::success(identifier);

                            match radius_proto::eap::eap_to_radius_attributes(&success_packet) {
                                Ok(eap_attrs) => {
                                    // Could add MS-MPPE keys here from MSK
                                    return AuthResult::Accept {
                                        attributes: eap_attrs,
                                    };
                                }
                                Err(e) => {
                                    error!(session_id, error = ?e, "continue_eap_teap: failed to wrap EAP-Success");
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // TEAP error
                        return AuthResult::Reject;
                    }
                }
            }
        }

        AuthResult::Reject
    }
}

impl AuthHandler for EapAuthHandler {
    fn authenticate(&self, _username: &str, _password: &str) -> bool {
        // EAP doesn't use simple PAP authentication
        false
    }

    fn authenticate_with_challenge(
        &self,
        username: &str,
        _password: Option<&str>,
        state: Option<&[u8]>,
    ) -> AuthResult {
        // Get or create session
        let session_id = self.get_or_create_session(username, state);

        // Check if this is initial request or continuation
        if state.is_none() {
            // Initial request - start EAP-Identity
            return self.handle_identity(username, &session_id);
        }

        // This method doesn't have access to EAP-Message attributes
        // Use authenticate_request instead
        AuthResult::Reject
    }

    fn authenticate_request(&self, request: &Packet, _secret: &[u8]) -> AuthResult {
        // Extract username
        let username = request
            .find_attribute(1) // UserName
            .and_then(|attr| attr.as_string().ok())
            .unwrap_or_default();

        // Extract state
        let state = request
            .find_attribute(24) // State
            .map(|attr| attr.value.as_slice());

        // Get or create session
        let session_id = self.get_or_create_session(&username, state);

        // Extract EAP-Message attributes
        let eap_messages: Vec<&Attribute> = request
            .attributes
            .iter()
            .filter(|attr| attr.attr_type == 79) // EAP-Message
            .collect();

        if eap_messages.is_empty() {
            // No EAP-Message - this is initial request, start EAP-Identity
            return self.handle_identity(&username, &session_id);
        }

        // Reassemble EAP packet from EAP-Message attributes
        let mut eap_data = Vec::new();
        for msg in eap_messages {
            eap_data.extend_from_slice(&msg.value);
        }

        // Parse EAP packet
        match EapPacket::from_bytes(&eap_data) {
            Ok(eap_packet) => {
                // Route to appropriate EAP method handler based on type
                #[cfg(feature = "tls")]
                {
                    match eap_packet.eap_type {
                        // First inbound EAP packet: peer's EAP-Response/Identity.
                        // Start the configured method (TEAP > TLS > MD5).
                        Some(EapType::Identity) => self.handle_identity(&username, &session_id),
                        Some(EapType::Tls) => {
                            self.continue_eap_tls(&username, &session_id, &eap_packet)
                        }
                        Some(EapType::Teap) => {
                            self.continue_eap_teap(&username, &session_id, &eap_packet)
                        }
                        // RFC 3748 §5.3.1: EAP-Nak (legacy=type 3 / expanded=254)
                        // means the peer rejected our proposed method and suggests
                        // alternatives in the data payload. TODO: honor the
                        // suggestion; for now reject with a logged reason so the
                        // failure is debuggable instead of silent.
                        Some(EapType::Nak) => {
                            warn!(
                                username, session_id,
                                proposed = ?eap_packet.data,
                                "EAP-Nak received from peer; method negotiation not yet implemented"
                            );
                            AuthResult::Reject
                        }
                        other => {
                            warn!(
                                username, session_id, eap_type = ?other,
                                "Unsupported EAP type from peer"
                            );
                            AuthResult::Reject
                        }
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    AuthResult::Reject
                }
            }
            Err(_) => AuthResult::Reject,
        }
    }

    fn get_user_password(&self, username: &str) -> Option<String> {
        // Delegate to inner handler
        self.inner_handler.get_user_password(username)
    }

    fn get_accept_attributes(&self, username: &str) -> Vec<Attribute> {
        // Could add MS-MPPE keys here from EAP-TLS MSK
        self.inner_handler.get_accept_attributes(username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::SimpleAuthHandler;

    #[test]
    fn test_eap_auth_handler_creation() {
        let inner = SimpleAuthHandler::new();
        let eap_handler = EapAuthHandler::new(Arc::new(inner));

        // Handler should be created successfully
        // Verify no sessions exist by trying to get a non-existent session
        assert!(
            eap_handler
                .session_manager
                .read()
                .unwrap()
                .get_session("nonexistent")
                .is_none()
        );
    }

    #[test]
    fn test_session_creation() {
        let inner = SimpleAuthHandler::new();
        let eap_handler = EapAuthHandler::new(Arc::new(inner));

        let session_id = eap_handler.get_or_create_session("testuser", None);
        assert!(!session_id.is_empty());

        let sessions = eap_handler.session_manager.read().unwrap();
        assert!(sessions.get_session(&session_id).is_some());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_tls_configuration() {
        let inner = SimpleAuthHandler::new();
        let mut eap_handler = EapAuthHandler::new(Arc::new(inner));

        // Note: This test requires actual certificate files to work
        // For now, we just test that the method exists and has the right signature

        let result = eap_handler.configure_tls(
            "",
            TlsCertificateConfig::simple(
                "nonexistent.pem".to_string(),
                "nonexistent-key.pem".to_string(),
            ),
        );

        // Expected to fail since files don't exist
        assert!(result.is_err());
    }
}
