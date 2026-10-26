//! EAP Authentication Handler
//!
//! This module provides authentication handlers for various EAP methods including
//! EAP-TLS, EAP-MD5, and potentially other methods in the future.
//!
//! The EAP handler integrates with the RADIUS server's AuthHandler trait and manages
//! multi-round EAP authentication sessions.

use radius_proto::eap::{EapPacket, EapSessionManager, EapState, EapType};
use radius_proto::{Attribute, AttributeType, Packet};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, warn};

use crate::server::{AuthHandler, AuthResult};

#[cfg(feature = "tls")]
use radius_proto::eap::eap_tls::{
    EapTlsPacket, EapTlsServer, TlsCertificateConfig, TlsFlags, build_server_config,
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

    /// Configure EAP-TLS for a realm from an already-built rustls `ServerConfig`
    /// (e.g. one whose client verifier checks revocation; see
    /// [`Self::configure_from_config`]).
    #[cfg(feature = "tls")]
    pub fn configure_tls_with_server_config(
        &mut self,
        realm: &str,
        server_config: StdArc<rustls::ServerConfig>,
    ) {
        let mut configs = self.tls_configs.write().unwrap();
        configs.insert(realm.to_string(), server_config);
    }

    /// Configure EAP-TEAP for a realm from an already-built rustls `ServerConfig`.
    #[cfg(feature = "tls")]
    pub fn configure_teap_with_server_config(
        &mut self,
        realm: &str,
        server_config: StdArc<rustls::ServerConfig>,
    ) {
        let mut configs = self.tls_configs.write().unwrap();
        configs.insert(format!("teap_{}", realm), server_config);
    }

    /// Configure EAP-TLS and/or EAP-TEAP (default realm) from the server's
    /// `eap` config block.
    ///
    /// Builds one rustls `ServerConfig` from `eap.tls`: server certificate and
    /// key, a WebPKI client verifier over `ca_path` when `require_client_cert`
    /// is set, wrapped in CRL/OCSP revocation checking when `eap.tls.revocation`
    /// is present (see [`crate::client_verifier`]). The same config serves both
    /// methods, as in [`Self::configure_tls`] / [`Self::configure_teap`].
    #[cfg(feature = "tls")]
    pub fn configure_from_config(
        &mut self,
        eap_cfg: &crate::config::EapConfig,
    ) -> Result<(), String> {
        let server_config = StdArc::new(build_eap_server_config(&eap_cfg.tls)?);
        if eap_cfg.enable_teap {
            self.configure_teap_with_server_config("", server_config.clone());
        }
        if eap_cfg.enable_tls {
            self.configure_tls_with_server_config("", server_config);
        }
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

        // 1b) RFC 9190 Section 2.5 protected success: once we have sent the
        // commitment message (a TLS 1.3 application-data 0x00), the peer's next
        // EAP-Response — an empty EAP-TLS ACK — is the cue to send EAP-Success.
        // Its payload needs no processing, so finish without feeding rustls.
        if tls_server.commitment_sent() && tls_server.is_handshake_complete() {
            return self.finish_eap_tls_success(
                username,
                session_id,
                tls_server,
                eap_response.identifier,
            );
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

            // No outbound handshake data. Either the handshake just
            // finished, or rustls is still waiting for more from the peer.
            Ok(None) => {
                // RFC 5216 §2.1.5: a Response with the M bit set is answered
                // with an EAP-Request of Type EAP-TLS carrying no data (flags
                // 0x00, no TLS Message Length), so the peer sends the next
                // fragment. The reassembler has already bounded the buffer.
                if tls_packet.flags.more_fragments() {
                    let ack =
                        EapTlsPacket::new(TlsFlags::new(false, false, false), None, Vec::new());
                    let id = next_id();
                    debug!(
                        session_id,
                        identifier = id,
                        "continue_eap_tls: ACKing non-final peer fragment"
                    );
                    return make_challenge(ack, id).unwrap_or(AuthResult::Reject);
                }

                if !tls_server.is_handshake_complete() {
                    // Mid-handshake with nothing to send back is wrong — peer
                    // sent us nothing we could act on.
                    warn!(
                        session_id,
                        "continue_eap_tls: no outbound TLS, handshake incomplete"
                    );
                    return AuthResult::Reject;
                }

                // Verify the peer certificate's identity (client-cert mode)
                // before signaling success either way.
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

                // RFC 9190 §2.5: EAP-TLS over TLS 1.3 requires a protected
                // success indication — a TLS application-data record of a single
                // 0x00 octet — that the peer acknowledges before EAP-Success.
                // Peers (e.g. wpa_supplicant) derive no MSK without it, so the
                // 4-way handshake and the MS-MPPE keys would both be unusable.
                // Send it as its own EAP-Request; the peer's ACK is handled by
                // the commitment fast path above. TLS 1.2 (RFC 5216) has no
                // commitment message, so it succeeds immediately.
                if tls_server.is_tls13() {
                    let record = match tls_server.write_commitment_record() {
                        Ok(r) => r,
                        Err(e) => {
                            error!(session_id, error = ?e, "continue_eap_tls: failed to build commitment message");
                            return AuthResult::Reject;
                        }
                    };
                    tls_server.queue_outgoing_tls(record, 1020);
                    let Some(frag) = tls_server.next_outgoing_fragment() else {
                        error!(
                            session_id,
                            "continue_eap_tls: commitment produced no fragment"
                        );
                        return AuthResult::Reject;
                    };
                    let id = next_id();
                    debug!(
                        session_id,
                        identifier = id,
                        "continue_eap_tls: sending RFC 9190 commitment message"
                    );
                    return make_challenge(frag, id).unwrap_or(AuthResult::Reject);
                }

                self.finish_eap_tls_success(
                    username,
                    session_id,
                    tls_server,
                    eap_response.identifier,
                )
            }

            Err(e) => {
                error!(session_id, error = ?e, "continue_eap_tls: TLS processing error");
                AuthResult::Reject
            }
        }
    }

    /// Build the EAP-Success Access-Accept for a completed EAP-TLS exchange.
    ///
    /// For TLS 1.3 this runs after the peer has acknowledged the RFC 9190 §2.5
    /// commitment message; for TLS 1.2 it runs as soon as the handshake
    /// completes. It extracts the MSK/EMSK (RFC 5216 §2.3 / RFC 9190 §2.3),
    /// wraps an EAP-Success whose Identifier echoes the peer's last
    /// EAP-Response (RFC 3748 §4.2), and attaches the EAP-Key-Name Session-Id
    /// (RFC 9190 §2.5 / RFC 4072 §3.2, TLS 1.3 only). The returned MSK is
    /// encrypted into MS-MPPE-Recv/Send-Key by the Access-Accept builder.
    #[cfg(feature = "tls")]
    fn finish_eap_tls_success(
        &self,
        username: &str,
        session_id: &str,
        tls_server: &mut EapTlsServer,
        last_eap_identifier: u8,
    ) -> AuthResult {
        if tls_server.extract_keys().is_err() {
            error!(
                session_id,
                "finish_eap_tls_success: extract_keys failed after handshake"
            );
            return AuthResult::Reject;
        }
        {
            let mut manager = self.session_manager.write().unwrap();
            if let Some(s) = manager.get_session_mut(session_id) {
                let _ = s.transition(EapState::Success);
            }
        }
        // RFC 3748 §4.2: the EAP-Success Identifier matches the peer's last
        // EAP-Response (the commitment ACK for TLS 1.3).
        let success = EapPacket::success(last_eap_identifier);
        let mut attrs = match radius_proto::eap::eap_to_radius_attributes(&success) {
            Ok(a) => a,
            Err(e) => {
                error!(session_id, error = ?e, "finish_eap_tls_success: failed to wrap EAP-Success");
                return AuthResult::Reject;
            }
        };
        let Some(msk) = tls_server.get_msk().map(|k| k.to_vec()) else {
            error!(
                session_id,
                "finish_eap_tls_success: MSK missing after extract_keys"
            );
            return AuthResult::Reject;
        };
        if let Some(session_id_bytes) = tls_server.session_id()
            && let Ok(a) = Attribute::new(AttributeType::EapKeyName as u8, session_id_bytes)
        {
            attrs.push(a);
        }
        debug!(
            session_id,
            username, "continue_eap_tls: success (MSK + EAP-Key-Name emitted)"
        );
        AuthResult::Accept {
            attributes: attrs,
            msk: Some(msk),
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

                            // RFC 7170 §5.4 MSK, present only when the inner
                            // method succeeded and the Crypto-Binding verified.
                            // A "complete" TEAP conversation without key
                            // material did not authenticate the peer.
                            let Some(msk) = teap_server.get_msk() else {
                                warn!(
                                    session_id,
                                    username,
                                    "continue_eap_teap: conversation complete without a verified crypto-binding"
                                );
                                return AuthResult::Reject;
                            };

                            let success_packet = EapPacket::success(identifier);

                            match radius_proto::eap::eap_to_radius_attributes(&success_packet) {
                                Ok(eap_attrs) => {
                                    return AuthResult::Accept {
                                        attributes: eap_attrs,
                                        msk: Some(msk),
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

/// Build the rustls `ServerConfig` for the `eap.tls` block.
///
/// Client certificates are requested and verified only when
/// `require_client_cert` is set (`ca_path` is then required); with
/// `revocation` present the verifier also checks CRL/OCSP status. Returns the
/// chosen verifier kind in the log line so operators can confirm it.
#[cfg(feature = "tls")]
pub fn build_eap_server_config(
    tls: &crate::config::EapTlsConfig,
) -> Result<rustls::ServerConfig, String> {
    use radius_proto::eap::eap_tls::build_server_config_with_client_verifier;

    let cert_config = TlsCertificateConfig::new(
        tls.cert_path.clone(),
        tls.key_path.clone(),
        tls.ca_path.clone(),
        tls.require_client_cert,
    );
    let client_verifier = if tls.require_client_cert {
        let ca_path = tls.ca_path.as_deref().ok_or_else(|| {
            "eap.tls.require_client_cert = true but eap.tls.ca_path is not set".to_string()
        })?;
        let verifier =
            crate::client_verifier::build_client_verifier(ca_path, None, tls.revocation.as_ref())
                .map_err(|e| e.to_string())?;
        if verifier.checks_revocation() {
            tracing::info!("EAP-TLS: supplicant certificates are checked for revocation");
        }
        Some(verifier.into_arc())
    } else {
        if tls.revocation.is_some() {
            return Err(
                "eap.tls.revocation requires eap.tls.require_client_cert = true".to_string(),
            );
        }
        None
    };
    build_server_config_with_client_verifier(&cert_config, client_verifier)
        .map_err(|e| format!("Failed to build TLS config: {:?}", e))
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
        // MS-MPPE keys are not added here: they are per-request (bound to the
        // Request Authenticator) and travel on `AuthResult::Accept::msk`.
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

/// End-to-end EAP-TLS conversations against an in-memory rustls supplicant,
/// checking that the concluding Access-Accept carries the RFC 2548 MS-MPPE
/// keys (and EAP-Key-Name) derived from the MSK both sides agree on.
#[cfg(all(test, feature = "tls"))]
mod eap_tls_mppe_tests {
    use super::*;
    use crate::config::Config;
    use crate::server::{RadiusServer, ServerConfig, SimpleAuthHandler};
    use radius_proto::eap::eap_tls::{EAP_TLS_TYPE_CODE, TlsFlags};
    use radius_proto::eap::{EapCode, eap_from_radius_packet};
    use radius_proto::mppe::{MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY, MS_MPPE_SEND_KEY};
    use radius_proto::{
        Code, MppeKeys, calculate_message_authenticator, generate_request_authenticator,
        verify_response_authenticator,
    };
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore};
    use std::io::Write as _;

    const SECRET: &[u8] = b"s3cret";
    const SERVER_NAME: &str = "radius.test";

    struct TestPki {
        _dir: tempfile::TempDir,
        cert_path: String,
        key_path: String,
        ca_der: CertificateDer<'static>,
    }

    /// Throwaway CA + CA-signed server certificate, written to PEM files the
    /// way `configure_tls` expects them.
    fn gen_pki() -> TestPki {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "USG Test EAP CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec![SERVER_NAME.to_string()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, data: &str| {
            let path = dir.path().join(name);
            std::fs::File::create(&path)
                .unwrap()
                .write_all(data.as_bytes())
                .unwrap();
            path.to_str().unwrap().to_string()
        };
        TestPki {
            cert_path: write("server.pem", &server.pem()),
            key_path: write("server.key", &server_key.serialize_pem()),
            ca_der: ca.der().clone(),
            _dir: dir,
        }
    }

    fn eap_handler(pki: &TestPki) -> EapAuthHandler {
        // `build_server_config` uses `ServerConfig::builder()`, which needs a
        // process-level default provider when several are compiled in.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut handler = EapAuthHandler::new(Arc::new(SimpleAuthHandler::new()));
        handler
            .configure_tls(
                "",
                TlsCertificateConfig::simple(pki.cert_path.clone(), pki.key_path.clone()),
            )
            .unwrap();
        handler
    }

    #[test]
    fn configure_from_config_builds_tls_and_teap_from_the_eap_block() {
        use crate::config::{EapConfig, EapTlsConfig};

        let pki = gen_pki();
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut handler = EapAuthHandler::new(Arc::new(SimpleAuthHandler::new()));
        let cfg = EapConfig {
            enable_tls: true,
            enable_teap: true,
            tls: EapTlsConfig {
                cert_path: pki.cert_path.clone(),
                key_path: pki.key_path.clone(),
                ca_path: None,
                require_client_cert: false,
                revocation: None,
            },
        };
        handler.configure_from_config(&cfg).unwrap();
        let configs = handler.tls_configs.read().unwrap();
        assert!(configs.contains_key(""), "EAP-TLS default realm configured");
        assert!(
            configs.contains_key("teap_"),
            "EAP-TEAP default realm configured"
        );
    }

    #[test]
    fn configure_from_config_rejects_revocation_without_client_certs() {
        use crate::config::{EapConfig, EapTlsConfig, RevocationConfig};

        let pki = gen_pki();
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut handler = EapAuthHandler::new(Arc::new(SimpleAuthHandler::new()));
        let cfg = EapConfig {
            enable_tls: true,
            enable_teap: false,
            tls: EapTlsConfig {
                cert_path: pki.cert_path.clone(),
                key_path: pki.key_path.clone(),
                ca_path: None,
                require_client_cert: false,
                revocation: Some(RevocationConfig::default()),
            },
        };
        let err = handler.configure_from_config(&cfg).unwrap_err();
        assert!(err.contains("require_client_cert"), "{err}");
    }

    /// Minimal in-memory EAP-TLS peer (RFC 5216 §2.1.1 flow, server-only
    /// authentication).
    struct Supplicant {
        conn: ClientConnection,
        reassembly: Vec<u8>,
        /// Application data the peer read post-handshake (e.g. the RFC 9190
        /// commitment 0x00).
        app_data: Vec<u8>,
    }

    impl Supplicant {
        fn new(pki: &TestPki) -> Self {
            let mut roots = RootCertStore::empty();
            roots.add(pki.ca_der.clone()).unwrap();
            // X25519 only: keeps the ClientHello within a single EAP-TLS
            // fragment (no hybrid ML-KEM key share).
            let provider = rustls::crypto::CryptoProvider {
                kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
                ..rustls::crypto::aws_lc_rs::default_provider()
            };
            let config = ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let conn =
                ClientConnection::new(Arc::new(config), ServerName::try_from(SERVER_NAME).unwrap())
                    .unwrap();
            Supplicant {
                conn,
                reassembly: Vec::new(),
                app_data: Vec::new(),
            }
        }

        fn pending_tls(&mut self) -> Vec<u8> {
            let mut out = Vec::new();
            self.conn.write_tls(&mut out).unwrap();
            out
        }

        /// Answer one EAP-Request/TLS with the peer's EAP-Response/TLS.
        fn respond(&mut self, request: &EapPacket) -> EapPacket {
            assert_eq!(request.code, EapCode::Request);
            assert_eq!(request.eap_type, Some(EapType::Tls), "unexpected EAP type");
            let pkt = EapTlsPacket::from_eap_data(&request.data).unwrap();

            if pkt.flags.start() {
                let client_hello = self.pending_tls();
                assert!(!client_hello.is_empty());
                return Self::tls_response(request.identifier, client_hello);
            }

            self.reassembly.extend_from_slice(&pkt.tls_data);
            if pkt.flags.more_fragments() {
                return Self::ack(request.identifier);
            }
            let data = std::mem::take(&mut self.reassembly);
            self.conn.read_tls(&mut &data[..]).unwrap();
            self.conn.process_new_packets().unwrap();
            // Drain any post-handshake application data (RFC 9190 commitment).
            use std::io::Read as _;
            let mut buf = [0u8; 64];
            while let Ok(n) = self.conn.reader().read(&mut buf) {
                if n == 0 {
                    break;
                }
                self.app_data.extend_from_slice(&buf[..n]);
            }
            let out = self.pending_tls();
            if out.is_empty() {
                Self::ack(request.identifier)
            } else {
                Self::tls_response(request.identifier, out)
            }
        }

        fn tls_response(identifier: u8, data: Vec<u8>) -> EapPacket {
            let len = data.len() as u32;
            EapTlsPacket::new(TlsFlags::new(true, false, false), Some(len), data)
                .to_eap_response(identifier)
        }

        fn ack(identifier: u8) -> EapPacket {
            EapTlsPacket::new(TlsFlags::new(false, false, false), None, Vec::new())
                .to_eap_response(identifier)
        }

        fn export(&self, label: &[u8], len: usize) -> Vec<u8> {
            let mut out = vec![0u8; len];
            self.conn
                .export_keying_material(out.as_mut_slice(), label, Some(&[EAP_TLS_TYPE_CODE]))
                .unwrap();
            out
        }

        /// The peer's own MSK (RFC 9190 §2.3; the handshake is TLS 1.3).
        fn msk(&self) -> Vec<u8> {
            assert_eq!(
                self.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            self.export(b"EXPORTER_EAP_TLS_Key_Material", 128)[..64].to_vec()
        }

        /// The peer's own EAP Session-Id (RFC 9190 §2.5).
        fn session_id(&self) -> Vec<u8> {
            let mut id = vec![EAP_TLS_TYPE_CODE];
            id.extend(self.export(b"EXPORTER_EAP_TLS_Method-Id", 64));
            id
        }
    }

    /// An Access-Request carrying `eap`, the optional State, and a valid
    /// Message-Authenticator (RFC 3579 §3.2).
    fn access_request(identifier: u8, eap: &EapPacket, state: Option<&[u8]>) -> Packet {
        let mut p = Packet::new(
            Code::AccessRequest,
            identifier,
            generate_request_authenticator(),
        );
        p.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
        p.add_attribute(Attribute::string(AttributeType::NasIdentifier as u8, "test-nas").unwrap());
        if let Some(s) = state {
            p.add_attribute(Attribute::new(AttributeType::State as u8, s.to_vec()).unwrap());
        }
        radius_proto::eap::add_eap_to_radius_packet(&mut p, eap).unwrap();
        // Zeroed placeholder last, so the encoded bytes are exactly the HMAC input.
        p.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        let mac = calculate_message_authenticator(&p.encode().unwrap(), SECRET);
        p.attributes.last_mut().unwrap().value = mac.to_vec();
        p
    }

    fn identity_request() -> Packet {
        access_request(1, &EapPacket::identity_response(1, "alice"), None)
    }

    /// Given the server's Access-Challenge, build the peer's next Access-Request.
    fn answer_challenge(peer: &mut Supplicant, challenge: &Packet) -> Packet {
        assert_eq!(challenge.code, Code::AccessChallenge);
        let state = challenge
            .find_attribute(AttributeType::State as u8)
            .expect("Access-Challenge must carry State")
            .value
            .clone();
        let eap_request = eap_from_radius_packet(challenge)
            .unwrap()
            .expect("Access-Challenge must carry EAP-Message");
        let eap_response = peer.respond(&eap_request);
        access_request(
            challenge.identifier.wrapping_add(1),
            &eap_response,
            Some(&state),
        )
    }

    fn packet_with(code: Code, identifier: u8, attributes: Vec<Attribute>) -> Packet {
        let mut p = Packet::new(code, identifier, [0u8; 16]);
        for a in attributes {
            p.add_attribute(a);
        }
        p
    }

    #[test]
    fn eap_tls_accept_carries_msk_and_eap_key_name() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        let mut peer = Supplicant::new(&pki);

        let mut request = identity_request();
        let (attributes, msk) = loop {
            assert!(
                request.identifier < 64,
                "EAP-TLS conversation did not converge"
            );
            match handler.authenticate_request(&request, SECRET) {
                AuthResult::Challenge {
                    state, attributes, ..
                } => {
                    let mut challenge =
                        packet_with(Code::AccessChallenge, request.identifier, attributes);
                    challenge
                        .add_attribute(Attribute::new(AttributeType::State as u8, state).unwrap());
                    request = answer_challenge(&mut peer, &challenge);
                }
                AuthResult::Accept { attributes, msk } => break (attributes, msk),
                AuthResult::Reject => panic!("EAP-TLS rejected at id {}", request.identifier),
            }
        };

        let msk = msk.expect("EAP-TLS Accept must carry the MSK");
        assert_eq!(msk.len(), 64);
        assert_eq!(
            msk,
            peer.msk(),
            "server MSK must match the peer's exporter output"
        );

        let accept = packet_with(Code::AccessAccept, 0, attributes);
        let success = eap_from_radius_packet(&accept).unwrap().unwrap();
        assert_eq!(success.code, EapCode::Success);

        let key_name = accept
            .find_attribute(AttributeType::EapKeyName as u8)
            .expect("EAP-Key-Name on a TLS 1.3 Access-Accept");
        assert_eq!(key_name.value, peer.session_id());

        // The handler never emits MPPE attributes itself: they need the
        // request authenticator and transport secret, which server.rs owns.
        assert!(
            accept
                .find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY)
                .is_empty()
        );
    }

    /// The peer can split ClientHello across EAP-TLS Responses. Every
    /// non-final fragment must receive an empty EAP-TLS Request/ACK.
    #[test]
    fn eap_tls_acknowledges_fragmented_client_hello() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        let mut peer = Supplicant::new(&pki);

        let (state, attributes) = match handler.authenticate_request(&identity_request(), SECRET) {
            AuthResult::Challenge {
                state, attributes, ..
            } => (state, attributes),
            _ => panic!("expected EAP-TLS Start"),
        };

        let start = packet_with(Code::AccessChallenge, 1, attributes);
        let start_eap = eap_from_radius_packet(&start).unwrap().unwrap();
        assert!(
            EapTlsPacket::from_eap_data(&start_eap.data)
                .unwrap()
                .flags
                .start()
        );

        let client_hello = peer.pending_tls();
        let split = client_hello.len() / 2;
        assert!(split > 0);

        let first = EapTlsPacket::new(
            TlsFlags::new(true, true, false),
            Some(client_hello.len() as u32),
            client_hello[..split].to_vec(),
        )
        .to_eap_response(start_eap.identifier);
        let request = access_request(2, &first, Some(&state));
        let (state, attributes) = match handler.authenticate_request(&request, SECRET) {
            AuthResult::Challenge {
                state, attributes, ..
            } => (state, attributes),
            AuthResult::Reject => panic!("server rejected a non-final ClientHello fragment"),
            AuthResult::Accept { .. } => panic!("server accepted an incomplete ClientHello"),
        };

        let ack_packet = packet_with(Code::AccessChallenge, request.identifier, attributes);
        let ack_eap = eap_from_radius_packet(&ack_packet).unwrap().unwrap();
        assert_eq!(ack_eap.code, EapCode::Request);
        assert_eq!(ack_eap.eap_type, Some(EapType::Tls));
        // RFC 3748 §4.1: the ACK is a new Request, so its Identifier differs
        // from the Start's; reusing it would read as a retransmitted Start and
        // make the peer resend its first fragment forever.
        assert_ne!(ack_eap.identifier, start_eap.identifier);

        let ack_tls = EapTlsPacket::from_eap_data(&ack_eap.data).unwrap();
        assert_eq!(ack_tls.flags.as_u8(), 0);
        assert_eq!(ack_tls.tls_message_length, None);
        assert!(ack_tls.tls_data.is_empty());

        // Send the final ClientHello fragment and finish the handshake.
        let last = EapTlsPacket::new(
            TlsFlags::new(false, false, false),
            None,
            client_hello[split..].to_vec(),
        )
        .to_eap_response(ack_eap.identifier);
        let mut request = access_request(3, &last, Some(&state));
        for _ in 0..64 {
            match handler.authenticate_request(&request, SECRET) {
                AuthResult::Challenge {
                    state, attributes, ..
                } => {
                    let mut challenge =
                        packet_with(Code::AccessChallenge, request.identifier, attributes);
                    challenge
                        .add_attribute(Attribute::new(AttributeType::State as u8, state).unwrap());
                    request = answer_challenge(&mut peer, &challenge);
                }
                AuthResult::Accept { msk, .. } => {
                    assert_eq!(msk.expect("missing MSK"), peer.msk());
                    return;
                }
                AuthResult::Reject => panic!("EAP-TLS rejected at id {}", request.identifier),
            }
        }
        panic!("fragmented EAP-TLS conversation did not complete");
    }

    /// RFC 9190 §2.5 regression (interop with wpa_supplicant / FreeRADIUS over
    /// TLS 1.3): before EAP-Success the server MUST send a commitment message —
    /// a TLS application-data record of a single 0x00 octet — as its own
    /// EAP-Request, and send EAP-Success only after the peer acknowledges it.
    /// Without it, an OpenSSL-based peer derives no MSK and the authentication
    /// fails even though the TLS handshake succeeded. The exchange here is
    /// driven explicitly so the extra round and the 0x00 payload are asserted,
    /// not merely tolerated.
    #[test]
    fn eap_tls_tls13_sends_rfc9190_commitment_before_success() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        let mut peer = Supplicant::new(&pki);

        let mut request = identity_request();
        let mut challenges_after_app_data = 0usize;
        let (attributes, msk) = loop {
            assert!(
                request.identifier < 64,
                "EAP-TLS conversation did not converge"
            );
            match handler.authenticate_request(&request, SECRET) {
                AuthResult::Challenge {
                    state, attributes, ..
                } => {
                    // Once the peer has seen the commitment, no further
                    // Challenge should carry TLS handshake data.
                    if !peer.app_data.is_empty() {
                        challenges_after_app_data += 1;
                    }
                    let mut challenge =
                        packet_with(Code::AccessChallenge, request.identifier, attributes);
                    challenge
                        .add_attribute(Attribute::new(AttributeType::State as u8, state).unwrap());
                    request = answer_challenge(&mut peer, &challenge);
                }
                AuthResult::Accept { attributes, msk } => break (attributes, msk),
                AuthResult::Reject => panic!("EAP-TLS rejected at id {}", request.identifier),
            }
        };

        // The peer received exactly the one-octet 0x00 commitment as TLS
        // application data, the hallmark of RFC 9190 §2.5 protected success.
        assert_eq!(
            peer.app_data,
            vec![0x00],
            "peer must receive the RFC 9190 commitment message (application data 0x00)"
        );
        // The commitment arrived as its own round: the peer saw it, then
        // answered once more (the ACK) before the Accept — no extra Challenge
        // carrying handshake data followed it.
        assert_eq!(
            challenges_after_app_data, 0,
            "EAP-Success must follow the commitment ACK with no further challenges"
        );

        // Success still carries the correct, peer-matching key material.
        let msk = msk.expect("EAP-TLS Accept must carry the MSK");
        assert_eq!(
            msk,
            peer.msk(),
            "server MSK must match the peer after commitment"
        );
        let accept = packet_with(Code::AccessAccept, 0, attributes);
        let key_name = accept
            .find_attribute(AttributeType::EapKeyName as u8)
            .expect("EAP-Key-Name on the Access-Accept");
        assert_eq!(
            key_name.value,
            peer.session_id(),
            "EAP-Key-Name must equal the peer's derived Session-Id"
        );
    }

    #[tokio::test]
    async fn access_accept_carries_encrypted_ms_mppe_keys() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        let mut peer = Supplicant::new(&pki);
        let config = Config {
            strict_rfc_compliance: false,
            ..Config::default()
        };
        let cfg = Arc::new(ServerConfig::from_config(config, Arc::new(handler)).unwrap());
        let nas_ip = "10.0.0.1:1812".parse().unwrap();

        let mut request = identity_request();
        let accept = loop {
            assert!(
                request.identifier < 64,
                "EAP-TLS conversation did not converge"
            );
            let bytes =
                RadiusServer::process_request(&request.encode().unwrap(), nas_ip, SECRET, &cfg)
                    .await
                    .unwrap()
                    .expect("Access-Request warrants a reply");
            let response = Packet::decode(&bytes).unwrap();
            // No reply before the Accept may leak key material.
            assert!(
                response
                    .find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY)
                    .is_empty()
                    || response.code == Code::AccessAccept
            );
            match response.code {
                Code::AccessChallenge => request = answer_challenge(&mut peer, &response),
                Code::AccessAccept => break response,
                other => panic!("unexpected {other:?} at id {}", request.identifier),
            }
        };

        assert!(verify_response_authenticator(
            &accept,
            &request.authenticator,
            SECRET
        ));
        assert!(
            accept
                .find_attribute(AttributeType::MessageAuthenticator as u8)
                .is_some()
        );

        // One Send-Key and one Recv-Key, encrypted with the client secret and
        // the authenticator of the request this Accept answers.
        assert_eq!(
            accept
                .find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY)
                .len(),
            1
        );
        assert_eq!(
            accept
                .find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY)
                .len(),
            1
        );
        let keys = MppeKeys::from_packet(&accept, SECRET, &request.authenticator)
            .unwrap()
            .expect("Access-Accept must carry MS-MPPE keys");
        let msk = peer.msk();
        assert_eq!(keys.recv_key, msk[..32], "Recv-Key = MSK[0..32]");
        assert_eq!(keys.send_key, msk[32..64], "Send-Key = MSK[32..64]");

        // Wrong secret must not recover the keys.
        if let Ok(Some(bogus)) = MppeKeys::from_packet(&accept, b"wrong", &request.authenticator) {
            assert_ne!(bogus, keys);
        }
    }
}
