//! EAP Authentication Handler
//!
//! This module provides authentication handlers for various EAP methods including
//! EAP-TLS, EAP-MD5, and potentially other methods in the future.
//!
//! The EAP handler integrates with the RADIUS server's AuthHandler trait and manages
//! multi-round EAP authentication sessions.

use radius_proto::eap::{EapCode, EapPacket, EapSessionManager, EapState, EapType, EvictionReason};
use radius_proto::{Attribute, AttributeType, Packet};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, warn};

use crate::server::{AuthHandler, AuthResult};

#[cfg(feature = "tls")]
use radius_proto::eap::eap_tls::{
    EapTlsPacket, EapTlsServer, TlsCertificateConfig, TlsFlags, build_server_config,
};

#[cfg(feature = "tls")]
use std::sync::Arc as StdArc;

/// Process-wide count of EAP sessions evicted for idling past the timeout
/// (exported as `radius_eap_sessions_evicted_total{reason="idle"}`).
pub static EAP_SESSIONS_EVICTED_IDLE: AtomicU64 = AtomicU64::new(0);
/// Process-wide count of EAP sessions evicted because the store was full
/// (exported as `radius_eap_sessions_evicted_total{reason="capacity"}`).
pub static EAP_SESSIONS_EVICTED_CAPACITY: AtomicU64 = AtomicU64::new(0);

/// Largest EAP-TLS / EAP-TEAP fragment the server sends, in bytes of
/// EAP-TLS Type-Data (RFC 5216 §2.1.5 / RFC 7170 §3.7). 1020 keeps a fragment
/// plus the EAP and RADIUS framing inside a 1500-byte Ethernet MTU.
pub const DEFAULT_MAX_FRAGMENT_SIZE: usize = 1020;

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

    /// Largest outbound EAP-TLS/TEAP fragment (see [`DEFAULT_MAX_FRAGMENT_SIZE`]).
    max_fragment_size: usize,

    /// Sessions this handler evicted for idling / for capacity.
    evicted_idle: AtomicU64,
    evicted_capacity: AtomicU64,

    /// Makes session IDs unique when one user starts several conversations
    /// within the same millisecond.
    session_seq: AtomicU64,

    /// Override of the per-conversation EAP-TEAP Phase 2 round bound
    /// (`None` = `EapTeapServer::MAX_PHASE2_ROUNDS`).
    #[cfg(feature = "tls")]
    teap_max_phase2_rounds: Option<u32>,
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
        let mut manager = EapSessionManager::new();
        manager.set_idle_timeout_secs(EapSessionManager::DEFAULT_IDLE_TIMEOUT_SECS);
        manager.set_max_sessions(EapSessionManager::DEFAULT_MAX_SESSIONS);
        EapAuthHandler {
            session_manager: Arc::new(RwLock::new(manager)),
            inner_handler,
            #[cfg(feature = "tls")]
            tls_configs: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "tls")]
            tls_sessions: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "tls")]
            teap_sessions: Arc::new(RwLock::new(HashMap::new())),
            max_fragment_size: DEFAULT_MAX_FRAGMENT_SIZE,
            evicted_idle: AtomicU64::new(0),
            evicted_capacity: AtomicU64::new(0),
            session_seq: AtomicU64::new(0),
            #[cfg(feature = "tls")]
            teap_max_phase2_rounds: None,
        }
    }

    /// Bound the number of Phase 2 messages a TEAP peer may send per
    /// conversation (default `EapTeapServer::MAX_PHASE2_ROUNDS`).
    #[cfg(feature = "tls")]
    pub fn set_teap_max_phase2_rounds(&mut self, rounds: u32) {
        self.teap_max_phase2_rounds = Some(rounds);
    }

    /// Bound the session store: evict a conversation after
    /// `idle_timeout_secs` without a packet from its peer, and keep at most
    /// `max_sessions` live conversations (least recently used evicted first).
    /// Zero values are raised to one.
    pub fn set_session_limits(&mut self, idle_timeout_secs: u64, max_sessions: usize) {
        let mut manager = self.session_manager.write().unwrap();
        manager.set_idle_timeout_secs(idle_timeout_secs.max(1));
        manager.set_max_sessions(max_sessions.max(1));
    }

    /// `(idle_timeout_secs, max_sessions)` currently enforced.
    pub fn session_limits(&self) -> (u64, usize) {
        let manager = self.session_manager.read().unwrap();
        (manager.idle_timeout_secs(), manager.max_sessions())
    }

    /// Largest outbound EAP-TLS / EAP-TEAP fragment in bytes of Type-Data.
    /// Values below 16 are raised to 16 so a fragment can carry at least the
    /// flags, the TLS Message Length and some data.
    pub fn set_max_fragment_size(&mut self, size: usize) {
        self.max_fragment_size = size.max(16);
    }

    /// Number of live EAP conversations.
    pub fn active_session_count(&self) -> usize {
        self.session_manager.read().unwrap().session_count()
    }

    /// `(idle, capacity)` eviction counts for this handler since start.
    pub fn eviction_counts(&self) -> (u64, u64) {
        (
            self.evicted_idle.load(Ordering::Relaxed),
            self.evicted_capacity.load(Ordering::Relaxed),
        )
    }

    /// Run the session reaper as of `now_secs` (Unix seconds): evicts every
    /// conversation idle past the timeout and, if the store is full, the
    /// least recently used ones, and drops their TLS/TEAP state. Called
    /// before every new conversation is created; exposed so operators'
    /// tooling and tests can trigger it. Returns the number of evicted
    /// conversations.
    pub fn reap_at(&self, now_secs: u64) -> usize {
        let evicted = {
            let mut manager = self.session_manager.write().unwrap();
            manager.evict_at(now_secs)
        }; // session-manager lock released before touching the method maps
        self.drop_evicted(evicted)
    }

    /// Evict every conversation idle past the timeout as of `now_secs` and
    /// drop its TLS/TEAP state, without displacing any live conversation for
    /// capacity. Runs on every incoming EAP packet, before the packet's State
    /// is resolved, so the idle timeout is enforced even when no new
    /// conversation ever starts and an idle session can never be revived by
    /// a late packet. Returns the number of evicted conversations.
    pub fn reap_idle_at(&self, now_secs: u64) -> usize {
        let evicted = {
            let mut manager = self.session_manager.write().unwrap();
            manager.evict_idle_at(now_secs)
        }; // session-manager lock released before touching the method maps
        self.drop_evicted(evicted)
    }

    /// Drop the method state of `evicted` sessions, count and log them.
    fn drop_evicted(&self, evicted: Vec<(String, EvictionReason)>) -> usize {
        if evicted.is_empty() {
            return 0;
        }
        let mut idle = 0u64;
        let mut capacity = 0u64;
        for (session_id, reason) in &evicted {
            match reason {
                EvictionReason::Idle => idle += 1,
                EvictionReason::Capacity => capacity += 1,
            }
            debug!(session_id, reason = ?reason, "EAP session evicted");
        }
        self.drop_method_state(evicted.iter().map(|(id, _)| id.as_str()));
        self.evicted_idle.fetch_add(idle, Ordering::Relaxed);
        self.evicted_capacity.fetch_add(capacity, Ordering::Relaxed);
        EAP_SESSIONS_EVICTED_IDLE.fetch_add(idle, Ordering::Relaxed);
        EAP_SESSIONS_EVICTED_CAPACITY.fetch_add(capacity, Ordering::Relaxed);
        debug!(
            idle,
            capacity,
            remaining = self.active_session_count(),
            "EAP session reaper ran"
        );
        evicted.len()
    }

    /// Drop the per-method (TLS / TEAP) state of the given sessions.
    #[allow(unused_variables)]
    fn drop_method_state<'a>(&self, session_ids: impl Iterator<Item = &'a str>) {
        #[cfg(feature = "tls")]
        {
            let ids: Vec<&str> = session_ids.collect();
            {
                let mut tls_sessions = self.tls_sessions.write().unwrap();
                for id in &ids {
                    tls_sessions.remove(*id);
                }
            }
            let mut teap_sessions = self.teap_sessions.write().unwrap();
            for id in &ids {
                teap_sessions.remove(*id);
            }
        }
    }

    /// Forget a conversation that reached a terminal outcome (Access-Accept
    /// or Access-Reject): its EAP session and TLS/TEAP state are released at
    /// once instead of lingering until the idle timeout.
    fn end_session(&self, session_id: &str) {
        {
            let mut manager = self.session_manager.write().unwrap();
            manager.remove_session(session_id);
        }
        self.drop_method_state(std::iter::once(session_id));
    }

    /// Release the conversation's state when `result` is terminal; mark the
    /// session as recently used only when the packet advanced the
    /// conversation (a Challenge). A rejected packet therefore never
    /// refreshes a session's LRU position.
    fn finish(&self, session_id: &str, result: AuthResult) -> AuthResult {
        if matches!(result, AuthResult::Challenge { .. }) {
            let mut manager = self.session_manager.write().unwrap();
            manager.get_session_mut(session_id);
        } else {
            self.end_session(session_id);
        }
        result
    }

    /// Current Unix time in seconds.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
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
        self.set_session_limits(eap_cfg.session_idle_timeout_secs, eap_cfg.max_sessions);
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

    /// Resolve the session a RADIUS State attribute refers to, without
    /// changing its LRU position (see [`Self::finish`]). `None` when there is
    /// no State or it names no live session (expired, evicted, finished or
    /// never ours).
    fn resolve_session(&self, state: Option<&[u8]>) -> Option<String> {
        // State format: session_id encoded as string
        let session_id = String::from_utf8(state?.to_vec()).ok()?;
        let manager = self.session_manager.read().unwrap();
        manager.get_session(&session_id)?;
        Some(session_id)
    }

    /// Get or create an EAP session for a user
    fn get_or_create_session(&self, username: &str, state: Option<&[u8]>) -> String {
        if let Some(session_id) = self.resolve_session(state) {
            return session_id;
        }

        // Make room first: idle conversations go, then (if the store is
        // full) the least recently used one.
        self.reap_at(Self::now_secs());

        // Create new session
        let seq = self.session_seq.fetch_add(1, Ordering::Relaxed);
        let session_id = format!(
            "{}-{}-{}",
            username,
            chrono::Utc::now().timestamp_millis(),
            seq
        );
        let mut manager = self.session_manager.write().unwrap();
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
            // Inner authentication handler for Phase 2 (Basic-Password-Auth).
            // When the inner handler has no password for this user (the
            // backend does not supply cleartext passwords, or the user is
            // unknown) the inner method fails closed: it never compares
            // against a substituted empty password, and the tunnel still
            // runs to completion so the peer learns nothing about whether
            // the user exists.
            use radius_proto::eap::eap_teap::BasicPasswordAuthHandler;
            let inner_method: Box<BasicPasswordAuthHandler> =
                match self.inner_handler.get_user_password(username) {
                    Some(password) => Box::new(BasicPasswordAuthHandler::new(
                        username.to_string(),
                        password,
                    )),
                    None => {
                        warn!(
                            session_id,
                            username,
                            "start_eap_teap: inner handler has no password for this user; \
                             Basic-Password-Auth will fail"
                        );
                        Box::new(BasicPasswordAuthHandler::without_password(
                            username.to_string(),
                        ))
                    }
                };

            // Create EAP-TEAP server for this session
            let mut teap_server = radius_proto::eap::eap_teap::EapTeapServer::with_inner_method(
                StdArc::clone(config),
                inner_method,
            );
            if let Some(rounds) = self.teap_max_phase2_rounds {
                teap_server.set_max_phase2_rounds(rounds);
            }
            if let Err(e) = teap_server.initialize_connection() {
                error!(session_id, error = ?e, "start_eap_teap: initialize_connection failed");
                return AuthResult::Reject;
            }

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
                tls_server.queue_outgoing_tls(response_data, self.max_fragment_size);
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
                    tls_server.queue_outgoing_tls(record, self.max_fragment_size);
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

    /// Continue EAP-TEAP authentication (RFC 7170).
    ///
    /// Same shape as [`Self::continue_eap_tls`]: the peer's packet is either
    /// an ACK for a server fragment still queued from the previous round
    /// (send the next one), a fragment of a larger message (ACK it and wait,
    /// RFC 7170 §3.7), or a complete message for the TEAP state machine
    /// (Phase 1 handshake data or Phase 2 encrypted TLVs). Every outbound
    /// TLS message, in either phase, is fragmented to the EAP MTU.
    #[cfg(feature = "tls")]
    fn continue_eap_teap(
        &self,
        username: &str,
        session_id: &str,
        eap_response: &EapPacket,
    ) -> AuthResult {
        let mut teap_sessions = self.teap_sessions.write().unwrap();
        let Some(teap_server) = teap_sessions.get_mut(session_id) else {
            error!(
                session_id,
                "continue_eap_teap: no TEAP session (state expired?)"
            );
            return AuthResult::Reject;
        };

        let next_id = || {
            let mut manager = self.session_manager.write().unwrap();
            manager
                .get_session_mut(session_id)
                .map(|s| s.next_identifier())
                .unwrap_or_else(|| eap_response.identifier.wrapping_add(1))
        };

        // Wrap one outgoing EAP-TEAP fragment (EAP-TLS packet format, Type 55)
        // into an Access-Challenge result.
        let make_challenge = |frag: EapTlsPacket, id: u8| -> Option<AuthResult> {
            let eap_packet = EapPacket::new(
                EapCode::Request,
                id,
                Some(EapType::Teap),
                frag.to_eap_data(),
            );
            match radius_proto::eap::eap_to_radius_attributes(&eap_packet) {
                Ok(attrs) => Some(AuthResult::Challenge {
                    message: None,
                    state: session_id.as_bytes().to_vec(),
                    attributes: attrs,
                }),
                Err(e) => {
                    error!(session_id, error = ?e, "continue_eap_teap: eap_to_radius_attributes failed");
                    None
                }
            }
        };

        let tls_packet = match EapTlsPacket::from_eap_data(&eap_response.data) {
            Ok(p) => p,
            Err(e) => {
                error!(session_id, error = ?e, "continue_eap_teap: malformed EAP-TEAP packet");
                return AuthResult::Reject;
            }
        };

        // 1) Peer-ACK path: server fragments queued from the previous round.
        if teap_server.has_pending_fragments() {
            if !tls_packet.tls_data.is_empty() || tls_packet.flags.more_fragments() {
                // The peer may only acknowledge while we are mid-message
                // (RFC 7170 §3.7); data here is out of order. Fail closed.
                warn!(
                    session_id,
                    "continue_eap_teap: peer sent data while server fragments were pending"
                );
                return AuthResult::Reject;
            }
            let Some(frag) = teap_server.next_outgoing_fragment() else {
                error!(session_id, "continue_eap_teap: has_pending_fragments lied");
                return AuthResult::Reject;
            };
            let id = next_id();
            debug!(
                session_id,
                identifier = id,
                "continue_eap_teap: sending next fragment"
            );
            return make_challenge(frag, id).unwrap_or(AuthResult::Reject);
        }

        // 2) Feed the TEAP state machine (reassembly happens inside).
        match teap_server.process_client_message(&tls_packet) {
            Ok(Some(response_data)) => {
                teap_server.queue_outgoing_tls(response_data, self.max_fragment_size);
                let Some(frag) = teap_server.next_outgoing_fragment() else {
                    error!(session_id, "continue_eap_teap: queue produced no fragments");
                    return AuthResult::Reject;
                };
                let id = next_id();
                debug!(
                    session_id,
                    identifier = id,
                    phase = ?teap_server.get_phase(),
                    "continue_eap_teap: sending first fragment of new TLS message"
                );
                make_challenge(frag, id).unwrap_or(AuthResult::Reject)
            }

            Ok(None) => {
                // RFC 7170 §3.7 (via RFC 5216 §2.1.5): a non-final peer
                // fragment is answered with an empty EAP-TEAP Request (ACK).
                if tls_packet.flags.more_fragments() {
                    let ack =
                        EapTlsPacket::new(TlsFlags::new(false, false, false), None, Vec::new());
                    let id = next_id();
                    debug!(
                        session_id,
                        identifier = id,
                        phase = ?teap_server.get_phase(),
                        "continue_eap_teap: ACKing peer fragment"
                    );
                    return make_challenge(ack, id).unwrap_or(AuthResult::Reject);
                }

                if !teap_server.is_complete() {
                    warn!(
                        session_id,
                        phase = ?teap_server.get_phase(),
                        "continue_eap_teap: nothing to send and conversation not complete"
                    );
                    return AuthResult::Reject;
                }

                // RFC 7170 §5.4 MSK, present only when the inner method
                // succeeded, the Crypto-Binding verified and the peer
                // acknowledged Result=Success. A "complete" TEAP conversation
                // without key material did not authenticate the peer.
                let Some(msk) = teap_server.get_msk() else {
                    warn!(
                        session_id,
                        username,
                        "continue_eap_teap: conversation complete without a verified crypto-binding"
                    );
                    return AuthResult::Reject;
                };

                {
                    let mut manager = self.session_manager.write().unwrap();
                    if let Some(session) = manager.get_session_mut(session_id) {
                        let _ = session.transition(EapState::Success);
                    }
                }

                // RFC 3748 §4.2: the EAP-Success Identifier matches the
                // peer's last EAP-Response (its Result TLV acknowledgement).
                let success_packet = EapPacket::success(eap_response.identifier);
                match radius_proto::eap::eap_to_radius_attributes(&success_packet) {
                    Ok(eap_attrs) => {
                        debug!(
                            session_id,
                            username,
                            identifier = eap_response.identifier,
                            "continue_eap_teap: success (MSK emitted)"
                        );
                        AuthResult::Accept {
                            attributes: eap_attrs,
                            msk: Some(msk),
                        }
                    }
                    Err(e) => {
                        error!(session_id, error = ?e, "continue_eap_teap: failed to wrap EAP-Success");
                        AuthResult::Reject
                    }
                }
            }

            Err(e) => {
                error!(session_id, error = ?e, "continue_eap_teap: TEAP processing error");
                AuthResult::Reject
            }
        }
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
        // A continuation carries EAP-Message attributes, which this entry
        // point cannot see: use authenticate_request. Reject without looking
        // up or touching the session.
        if state.is_some() {
            return AuthResult::Reject;
        }

        // Initial request - start EAP-Identity
        let session_id = self.get_or_create_session(username, None);
        let result = self.handle_identity(username, &session_id);
        self.finish(&session_id, result)
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

        // Extract EAP-Message attributes
        let eap_messages: Vec<&Attribute> = request
            .attributes
            .iter()
            .filter(|attr| attr.attr_type == 79) // EAP-Message
            .collect();

        // Enforce the idle timeout on every packet, before State is resolved:
        // an idle conversation is gone whether or not anything new starts,
        // and a late packet for it fails closed instead of reviving it.
        self.reap_idle_at(Self::now_secs());

        if eap_messages.is_empty() {
            // No EAP-Message - this is initial request, start EAP-Identity
            let session_id = self.get_or_create_session(&username, state);
            let result = self.handle_identity(&username, &session_id);
            return self.finish(&session_id, result);
        }

        // Reassemble EAP packet from EAP-Message attributes
        let mut eap_data = Vec::new();
        for msg in eap_messages {
            eap_data.extend_from_slice(&msg.value);
        }

        // Parse EAP packet
        let eap_packet = match EapPacket::from_bytes(&eap_data) {
            Ok(p) => p,
            Err(_) => return AuthResult::Reject,
        };

        // An EAP-Response/Identity starts a conversation (creating the
        // session, after the reaper has made room). Any other EAP-Response
        // must name a live conversation through State; one that does not
        // (expired, evicted, finished, forged) is rejected without allocating
        // anything, so stale or bogus State cannot churn the session store.
        let session_id = match eap_packet.eap_type {
            Some(EapType::Identity) => {
                let session_id = self.get_or_create_session(&username, state);
                // RFC 3748 §4.1: the NAS chose the Identifier of its
                // EAP-Request/Identity, which the peer echoed here; our first
                // Request must carry a different one, so continue the NAS's
                // sequence instead of starting at 0.
                if let Some(session) = self
                    .session_manager
                    .write()
                    .unwrap()
                    .get_session_mut(&session_id)
                {
                    session.seed_identifier_after(eap_packet.identifier);
                }
                session_id
            }
            _ => match self.resolve_session(state) {
                Some(id) => id,
                None => {
                    warn!(
                        username,
                        eap_type = ?eap_packet.eap_type,
                        has_state = state.is_some(),
                        "EAP-Response for no live session (expired, evicted or unknown State); rejecting"
                    );
                    return AuthResult::Reject;
                }
            },
        };

        // Route to appropriate EAP method handler based on type
        #[cfg(feature = "tls")]
        let result = match eap_packet.eap_type {
            // First inbound EAP packet: peer's EAP-Response/Identity.
            // Start the configured method (TEAP > TLS > MD5).
            Some(EapType::Identity) => self.handle_identity(&username, &session_id),
            Some(EapType::Tls) => self.continue_eap_tls(&username, &session_id, &eap_packet),
            Some(EapType::Teap) => self.continue_eap_teap(&username, &session_id, &eap_packet),
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
        };
        #[cfg(not(feature = "tls"))]
        let result = AuthResult::Reject;

        // Release the conversation's state on Accept / Reject.
        self.finish(&session_id, result)
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
            session_idle_timeout_secs: 30,
            max_sessions: 10,
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
        assert_eq!(handler.session_limits(), (30, 10));
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
            session_idle_timeout_secs: 120,
            max_sessions: 4096,
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

    // =====================================================================
    // EAP-TEAP (RFC 7170) through the handler: fragmentation in both phases
    // and directions, EAP-Success Identifier, fail-closed negative cases.
    // =====================================================================

    use radius_proto::eap::eap_teap::{
        CryptoBinding, CryptoBindingTlv, IdentityType, TeapResult, TeapTlv, TlvType,
    };
    use radius_proto::eap::eap_tls::TlsFragmentAssembler;

    const TEAP_USER: &str = "alice";

    /// The inner-method password shared by the test handler and the test
    /// peer: random per test process, so no credential is hard-coded.
    fn teap_password() -> &'static str {
        static PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PASSWORD.get_or_init(|| {
            let bytes: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        })
    }
    /// Non-mandatory, unassigned TLV type the server ignores; used as padding
    /// to make a peer Phase 2 message span several fragments.
    const PADDING_TLV_TYPE: u16 = 0x3FFF;

    fn teap_handler(pki: &TestPki) -> EapAuthHandler {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut inner = SimpleAuthHandler::new();
        inner.add_user(TEAP_USER, teap_password());
        let mut handler = EapAuthHandler::new(Arc::new(inner));
        handler
            .configure_teap(
                "",
                TlsCertificateConfig::simple(pki.cert_path.clone(), pki.key_path.clone()),
            )
            .unwrap();
        handler
    }

    /// In-memory TEAP peer: rustls client for Phase 1, Basic-Password-Auth
    /// inner method and crypto-binding for Phase 2, with RFC 7170 §3.7
    /// fragmentation of its own messages and reassembly of the server's.
    struct TeapPeer {
        conn: ClientConnection,
        /// Largest EAP-TLS Type-Data this peer sends per fragment.
        fragment_size: usize,
        /// Fragments of the peer's current message not yet sent.
        out_queue: std::collections::VecDeque<EapTlsPacket>,
        /// Reassembly of a fragmented server message.
        reassembly: Vec<u8>,
        /// Encoded Phase 2 TLVs in conversation order (RFC 7170 §5.3 BUFFER prefix).
        history: Vec<u8>,
        /// Extra non-mandatory TLV bytes appended to the Identity-Type
        /// response, to make it span fragments.
        identity_padding: usize,
        /// Password the peer presents (`None` = the right one).
        password: Option<String>,
        /// Answer the server's Basic-Password-Auth-Req with another
        /// Identity-Type TLV instead of a password (protocol error).
        answer_password_request_with_identity_type: bool,
        /// The server's Result TLV, once received; the peer echoes it.
        server_result: Option<TeapResult>,
        /// Counts, for assertions.
        acks_received: usize,
        acks_sent: usize,
        phase2_fragments_received: usize,
        handshake_done: bool,
        peer_result_sent: bool,
    }

    impl TeapPeer {
        fn new(pki: &TestPki, fragment_size: usize) -> Self {
            let mut roots = RootCertStore::empty();
            roots.add(pki.ca_der.clone()).unwrap();
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
            TeapPeer {
                conn,
                fragment_size,
                out_queue: Default::default(),
                reassembly: Vec::new(),
                history: Vec::new(),
                identity_padding: 0,
                password: None,
                answer_password_request_with_identity_type: false,
                server_result: None,
                acks_received: 0,
                acks_sent: 0,
                phase2_fragments_received: 0,
                handshake_done: false,
                peer_result_sent: false,
            }
        }

        fn pending_tls(&mut self) -> Vec<u8> {
            let mut out = Vec::new();
            self.conn.write_tls(&mut out).unwrap();
            out
        }

        fn teap_response(identifier: u8, pkt: &EapTlsPacket) -> EapPacket {
            EapPacket::new(
                EapCode::Response,
                identifier,
                Some(EapType::Teap),
                pkt.to_eap_data(),
            )
        }

        fn ack(identifier: u8) -> EapPacket {
            Self::teap_response(
                identifier,
                &EapTlsPacket::new(TlsFlags::new(false, false, false), None, Vec::new()),
            )
        }

        /// Queue `data` as RFC 7170 §3.7 fragments and send the first.
        fn send_message(&mut self, identifier: u8, data: Vec<u8>) -> EapPacket {
            let frags = radius_proto::eap::eap_tls::fragment_tls_message(&data, self.fragment_size);
            self.out_queue = frags.into_iter().collect();
            let first = self.out_queue.pop_front().expect("message has a fragment");
            Self::teap_response(identifier, &first)
        }

        /// The peer's own TEAP MSK (RFC 7170 §5.4), computable after Phase 1.
        fn crypto_binding(&self) -> CryptoBinding {
            // Output buffer for the exporter; its initial contents are
            // overwritten, so start from random bytes rather than a literal.
            let mut seed: Vec<u8> = (0..40).map(|_| rand::random::<u8>()).collect();
            self.conn
                .export_keying_material(
                    seed.as_mut_slice(),
                    b"EXPORTER: teap session key seed",
                    None,
                )
                .unwrap();
            CryptoBinding::new(&seed, &[0u8; 32])
        }

        fn msk(&self) -> Vec<u8> {
            self.crypto_binding().derive_msk()
        }

        /// Answer one server TLV message with the peer's TLVs.
        fn answer_tlvs(&mut self, tlvs: &[TeapTlv]) -> Vec<TeapTlv> {
            let mut out = Vec::new();
            for tlv in tlvs {
                // Every server TLV, including its Crypto-Binding request
                // (with MAC), is part of the BUFFER; the peer's own
                // Crypto-Binding response is not.
                self.history.extend_from_slice(&tlv.to_bytes());
                match tlv.get_type() {
                    Some(TlvType::IdentityType) => {
                        out.push(IdentityType::User.to_tlv());
                        if self.identity_padding > 0 {
                            out.push(TeapTlv::new_raw(
                                PADDING_TLV_TYPE,
                                false,
                                vec![0xAB; self.identity_padding],
                            ));
                        }
                    }
                    Some(TlvType::BasicPasswordAuthReq) => {
                        if self.answer_password_request_with_identity_type {
                            out.push(IdentityType::User.to_tlv());
                            continue;
                        }
                        let mut value = Vec::new();
                        value.extend_from_slice(&(TEAP_USER.len() as u16).to_be_bytes());
                        value.extend_from_slice(TEAP_USER.as_bytes());
                        let password = self
                            .password
                            .clone()
                            .unwrap_or_else(|| teap_password().to_string());
                        value.extend_from_slice(&(password.len() as u16).to_be_bytes());
                        value.extend_from_slice(password.as_bytes());
                        out.push(TeapTlv::new(TlvType::BasicPasswordAuthResp, true, value));
                    }
                    Some(TlvType::CryptoBinding) => {
                        let request = CryptoBindingTlv::from_tlv(tlv).unwrap();
                        assert_eq!(request.sub_type, CryptoBindingTlv::SUBTYPE_REQUEST);
                        let template = CryptoBindingTlv {
                            version: CryptoBindingTlv::VERSION,
                            received_version: request.version,
                            sub_type: CryptoBindingTlv::SUBTYPE_RESPONSE,
                            nonce: [0x42u8; 32],
                            compound_mac: vec![0u8; 32],
                        };
                        let mut buffer = self.history.clone();
                        buffer.extend_from_slice(&template.to_tlv().to_bytes());
                        let cmk = self.crypto_binding().cmk;
                        let compound_mac = CryptoBinding::calculate_compound_mac(&cmk, &buffer);
                        let response = CryptoBindingTlv {
                            compound_mac,
                            ..template
                        }
                        .to_tlv();
                        // Not part of the history: the server verifies the
                        // response against the history *without* it.
                        return vec![response];
                    }
                    Some(TlvType::Result) => {
                        // RFC 7170 §3.3.3: the peer acknowledges the server's
                        // Result TLV with its own, agreeing with it.
                        let result = TeapResult::from_result_tlv(tlv).unwrap();
                        self.server_result = Some(result);
                        self.peer_result_sent = true;
                        out.push(result.to_result_tlv());
                    }
                    other => panic!("unexpected server TLV {other:?}"),
                }
            }
            for tlv in &out {
                self.history.extend_from_slice(&tlv.to_bytes());
            }
            out
        }

        /// Answer one EAP-Request/TEAP with the peer's EAP-Response/TEAP.
        fn respond(&mut self, request: &EapPacket) -> EapPacket {
            assert_eq!(request.code, EapCode::Request);
            assert_eq!(request.eap_type, Some(EapType::Teap), "unexpected EAP type");
            let pkt = EapTlsPacket::from_eap_data(&request.data).unwrap();

            if pkt.flags.start() {
                let client_hello = self.pending_tls();
                assert!(!client_hello.is_empty());
                return self.send_message(request.identifier, client_hello);
            }

            // Server ACK of one of our fragments: send the next one.
            if pkt.tls_data.is_empty()
                && !pkt.flags.more_fragments()
                && let Some(next) = self.out_queue.pop_front()
            {
                self.acks_received += 1;
                return Self::teap_response(request.identifier, &next);
            }
            assert!(
                self.out_queue.is_empty(),
                "server sent data while our fragments were pending"
            );

            if self.handshake_done {
                self.phase2_fragments_received += 1;
            }
            self.reassembly.extend_from_slice(&pkt.tls_data);
            if pkt.flags.more_fragments() {
                self.acks_sent += 1;
                return Self::ack(request.identifier);
            }
            let data = std::mem::take(&mut self.reassembly);
            self.conn.read_tls(&mut &data[..]).unwrap();
            self.conn.process_new_packets().unwrap();
            if !self.conn.is_handshaking() {
                self.handshake_done = true;
            }

            // Phase 2 TLVs, if any arrived in this message.
            use std::io::Read as _;
            let mut plaintext = Vec::new();
            let _ = self.conn.reader().read_to_end(&mut plaintext);
            let mut out = self.pending_tls();
            if !plaintext.is_empty() {
                let tlvs = TeapTlv::parse_tlvs(&plaintext).unwrap();
                let reply = self.answer_tlvs(&tlvs);
                use std::io::Write as _;
                self.conn
                    .writer()
                    .write_all(&TeapTlv::encode_tlvs(&reply))
                    .unwrap();
                out.extend(self.pending_tls());
            }
            if out.is_empty() {
                Self::ack(request.identifier)
            } else {
                self.send_message(request.identifier, out)
            }
        }
    }

    /// Drive a whole TEAP conversation. Returns the final result and the
    /// Identifier of the peer's last EAP-Response.
    fn run_teap(handler: &EapAuthHandler, peer: &mut TeapPeer) -> (AuthResult, u8) {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init();
        let mut request = identity_request();
        let mut last_response_id = 1u8;
        for _ in 0..512 {
            match handler.authenticate_request(&request, SECRET) {
                AuthResult::Challenge {
                    state, attributes, ..
                } => {
                    let mut challenge =
                        packet_with(Code::AccessChallenge, request.identifier, attributes);
                    challenge
                        .add_attribute(Attribute::new(AttributeType::State as u8, state).unwrap());
                    let eap_request = eap_from_radius_packet(&challenge).unwrap().unwrap();
                    let eap_response = peer.respond(&eap_request);
                    last_response_id = eap_response.identifier;
                    request = access_request(
                        challenge.identifier.wrapping_add(1),
                        &eap_response,
                        Some(
                            &challenge
                                .find_attribute(AttributeType::State as u8)
                                .unwrap()
                                .value,
                        ),
                    );
                }
                terminal => return (terminal, last_response_id),
            }
        }
        panic!("TEAP conversation did not terminate");
    }

    fn eap_success_identifier(attributes: &[Attribute]) -> u8 {
        let accept = packet_with(Code::AccessAccept, 9, attributes.to_vec());
        let eap = eap_from_radius_packet(&accept).unwrap().unwrap();
        assert_eq!(eap.code, EapCode::Success);
        eap.identifier
    }

    #[test]
    fn eap_teap_fragments_server_messages_in_both_phases() {
        let pki = gen_pki();
        let mut handler = teap_handler(&pki);
        // Small EAP MTU: the handshake flight and every Phase 2 TLV message
        // the server sends span several fragments.
        handler.set_max_fragment_size(64);
        let mut peer = TeapPeer::new(&pki, 4096);

        let (result, last_id) = run_teap(&handler, &mut peer);
        let (attributes, msk) = match result {
            AuthResult::Accept { attributes, msk } => (attributes, msk),
            other => panic!("expected Accept, got {other:?}"),
        };
        assert_eq!(msk.expect("MSK"), peer.msk(), "RFC 7170 §5.4 MSK agrees");
        // RFC 3748 §4.2: EAP-Success echoes the peer's last Response.
        assert_eq!(eap_success_identifier(&attributes), last_id);
        assert_eq!(peer.server_result, Some(TeapResult::Success));
        assert!(peer.peer_result_sent, "peer acknowledged the Result TLV");
        assert!(
            peer.acks_sent >= 4,
            "server fragments were ACKed: {}",
            peer.acks_sent
        );
        assert!(
            peer.phase2_fragments_received > 4,
            "Phase 2 server messages were fragmented: {}",
            peer.phase2_fragments_received
        );
        // Terminal outcome released the session.
        assert_eq!(handler.active_session_count(), 0);
        assert!(handler.teap_sessions.read().unwrap().is_empty());
    }

    #[test]
    fn eap_teap_acks_fragmented_peer_messages_in_both_phases() {
        let pki = gen_pki();
        let handler = teap_handler(&pki);
        // The peer fragments at 100 bytes: its ClientHello (Phase 1) and its
        // padded Identity-Type response (Phase 2) each need several ACKs.
        let mut peer = TeapPeer::new(&pki, 100);
        peer.identity_padding = 1500;

        let (result, last_id) = run_teap(&handler, &mut peer);
        let (attributes, msk) = match result {
            AuthResult::Accept { attributes, msk } => (attributes, msk),
            other => panic!("expected Accept, got {other:?}"),
        };
        assert_eq!(msk.expect("MSK"), peer.msk());
        assert_eq!(eap_success_identifier(&attributes), last_id);
        assert!(
            peer.acks_received >= 2 + 15,
            "every non-final peer fragment got an ACK: {}",
            peer.acks_received
        );
    }

    /// Drive a whole TEAP conversation that must end in Access-Reject, and
    /// check that nothing of it is left behind.
    fn assert_teap_rejected(handler: &EapAuthHandler, peer: &mut TeapPeer) {
        let (result, _) = run_teap(handler, peer);
        assert!(
            matches!(result, AuthResult::Reject),
            "expected Reject, got {result:?}"
        );
        assert_eq!(handler.active_session_count(), 0, "session released");
        assert!(
            handler.teap_sessions.read().unwrap().is_empty(),
            "TEAP state released"
        );
    }

    /// A TEAP handler whose inner handler knows the given users.
    fn teap_handler_with_users(pki: &TestPki, users: &[(&str, &str)]) -> EapAuthHandler {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut inner = SimpleAuthHandler::new();
        for (user, password) in users {
            inner.add_user(*user, *password);
        }
        let mut handler = EapAuthHandler::new(Arc::new(inner));
        handler
            .configure_teap(
                "",
                TlsCertificateConfig::simple(pki.cert_path.clone(), pki.key_path.clone()),
            )
            .unwrap();
        handler
    }

    #[test]
    fn eap_teap_rejects_wrong_password() {
        let pki = gen_pki();
        let handler = teap_handler(&pki);
        let mut peer = TeapPeer::new(&pki, 4096);
        peer.password = Some(format!("{}x", teap_password()));
        assert_teap_rejected(&handler, &mut peer);
        assert_eq!(
            peer.server_result,
            Some(TeapResult::Failure),
            "server sent Result=Failure before EAP-Failure"
        );
    }

    /// A user the inner handler has no password for (every user with a
    /// backend that does not supply cleartext passwords; an unknown user with
    /// the in-memory backend) used to be compared against a substituted empty
    /// password, so an empty supplied password was accepted. The tunnel now
    /// completes with Result=Failure and Access-Reject.
    #[test]
    fn eap_teap_rejects_empty_password_for_user_without_stored_password() {
        let pki = gen_pki();
        // Inner handler knows no users at all: get_user_password → None.
        let handler = teap_handler_with_users(&pki, &[]);
        assert!(handler.get_user_password(TEAP_USER).is_none());
        let mut peer = TeapPeer::new(&pki, 4096);
        peer.password = Some(String::new());
        assert_teap_rejected(&handler, &mut peer);
        assert_eq!(peer.server_result, Some(TeapResult::Failure));

        // Nor does the right password of some other user help.
        let handler = teap_handler_with_users(&pki, &[("bob", teap_password())]);
        let mut peer = TeapPeer::new(&pki, 4096);
        assert_teap_rejected(&handler, &mut peer);
        assert_eq!(peer.server_result, Some(TeapResult::Failure));
    }

    #[test]
    fn eap_teap_rejects_empty_password_for_known_user() {
        let pki = gen_pki();
        let handler = teap_handler(&pki);
        let mut peer = TeapPeer::new(&pki, 4096);
        peer.password = Some(String::new());
        assert_teap_rejected(&handler, &mut peer);
        assert_eq!(peer.server_result, Some(TeapResult::Failure));
    }

    /// A user whose stored password is empty never authenticates, with or
    /// without an empty supplied password.
    #[test]
    fn eap_teap_rejects_user_with_empty_stored_password() {
        let pki = gen_pki();
        for supplied in ["", "anything"] {
            let handler = teap_handler_with_users(&pki, &[(TEAP_USER, "")]);
            let mut peer = TeapPeer::new(&pki, 4096);
            peer.password = Some(supplied.to_string());
            assert_teap_rejected(&handler, &mut peer);
            assert_eq!(
                peer.server_result,
                Some(TeapResult::Failure),
                "{supplied:?}"
            );
        }
    }

    /// A peer that answers Basic-Password-Auth-Req with another Identity-Type
    /// TLV used to be re-prompted without bound; it is now a protocol error.
    #[test]
    fn eap_teap_rejects_repeated_identity_type() {
        let pki = gen_pki();
        let handler = teap_handler(&pki);
        let mut peer = TeapPeer::new(&pki, 4096);
        peer.answer_password_request_with_identity_type = true;
        assert_teap_rejected(&handler, &mut peer);
        assert_eq!(
            peer.server_result, None,
            "conversation ended before any Result TLV"
        );
    }

    /// The Phase 2 round bound ends the conversation: with a bound of one,
    /// the peer's second Phase 2 message (its correct password) is rejected.
    #[test]
    fn eap_teap_rejects_past_phase2_round_limit() {
        let pki = gen_pki();
        let mut handler = teap_handler(&pki);
        handler.set_teap_max_phase2_rounds(1);
        let mut peer = TeapPeer::new(&pki, 4096);
        assert_teap_rejected(&handler, &mut peer);
        assert_eq!(peer.server_result, None);

        // The same peer under the default bound authenticates.
        let handler = teap_handler(&pki);
        let mut peer = TeapPeer::new(&pki, 4096);
        let (result, _) = run_teap(&handler, &mut peer);
        assert!(matches!(result, AuthResult::Accept { .. }), "{result:?}");
    }

    fn lru_seq(handler: &EapAuthHandler, session_id: &str) -> u64 {
        handler
            .session_manager
            .read()
            .unwrap()
            .get_session(session_id)
            .expect("live session")
            .lru_seq
    }

    /// Looking a session up for an inbound packet leaves its LRU position
    /// alone; only a packet that advances the conversation (Challenge)
    /// refreshes it, and a rejected packet releases it.
    #[test]
    fn eap_teap_rejected_packets_do_not_refresh_lru_position() {
        let pki = gen_pki();
        let handler = teap_handler(&pki);
        let (state, start_eap) = teap_start(&handler);
        let session_id = String::from_utf8(state.clone()).unwrap();
        let seq_after_start = lru_seq(&handler, &session_id);

        assert_eq!(
            handler.resolve_session(Some(&state)),
            Some(session_id.clone())
        );
        assert_eq!(lru_seq(&handler, &session_id), seq_after_start);

        // The peer's ClientHello advances the conversation.
        let mut peer = TeapPeer::new(&pki, 4096);
        let response = peer.respond(&start_eap);
        let result =
            handler.authenticate_request(&access_request(2, &response, Some(&state)), SECRET);
        assert!(matches!(result, AuthResult::Challenge { .. }));
        assert!(lru_seq(&handler, &session_id) > seq_after_start);

        // A malformed packet is rejected and the session is gone, so it can
        // neither be refreshed nor displace anything.
        let bad = EapTlsPacket::new(TlsFlags::new(false, true, false), None, vec![0x16; 10]);
        let result = handler.authenticate_request(
            &access_request(3, &teap_raw_response(7, bad), Some(&state)),
            SECRET,
        );
        assert!(matches!(result, AuthResult::Reject));
        assert!(handler.resolve_session(Some(&state)).is_none());
    }

    /// Server's Start, peer's first packet built by hand.
    fn teap_start(handler: &EapAuthHandler) -> (Vec<u8>, EapPacket) {
        let (state, attributes) = match handler.authenticate_request(&identity_request(), SECRET) {
            AuthResult::Challenge {
                state, attributes, ..
            } => (state, attributes),
            other => panic!("expected EAP-TEAP Start, got {other:?}"),
        };
        let start = packet_with(Code::AccessChallenge, 1, attributes);
        let start_eap = eap_from_radius_packet(&start).unwrap().unwrap();
        assert_eq!(start_eap.eap_type, Some(EapType::Teap));
        assert!(
            EapTlsPacket::from_eap_data(&start_eap.data)
                .unwrap()
                .flags
                .start()
        );
        (state, start_eap)
    }

    fn teap_raw_response(id: u8, pkt: EapTlsPacket) -> EapPacket {
        TeapPeer::teap_response(id, &pkt)
    }

    #[test]
    fn eap_teap_phase1_rejects_malformed_fragments() {
        let pki = gen_pki();
        let cases: Vec<(&str, EapTlsPacket)> = vec![
            (
                "first fragment with M but no L",
                EapTlsPacket::new(TlsFlags::new(false, true, false), None, vec![0x16; 50]),
            ),
            (
                "announced length above the 64 KiB bound",
                EapTlsPacket::new(
                    TlsFlags::new(true, true, false),
                    Some(TlsFragmentAssembler::MAX_MESSAGE_LENGTH as u32 + 1),
                    vec![0x16; 50],
                ),
            ),
            (
                "empty non-final fragment",
                EapTlsPacket::new(TlsFlags::new(true, true, false), Some(100), Vec::new()),
            ),
            (
                "peer set the S bit",
                EapTlsPacket::new(TlsFlags::new(false, true, true), None, vec![0x16; 50]),
            ),
        ];
        for (name, pkt) in cases {
            let handler = teap_handler(&pki);
            let (state, start_eap) = teap_start(&handler);
            let request = access_request(
                2,
                &teap_raw_response(start_eap.identifier, pkt),
                Some(&state),
            );
            assert!(
                matches!(
                    handler.authenticate_request(&request, SECRET),
                    AuthResult::Reject
                ),
                "{name}: expected Reject"
            );
            assert_eq!(
                handler.active_session_count(),
                0,
                "{name}: session released"
            );
        }
    }

    #[test]
    fn eap_teap_phase1_rejects_overrun_before_final_fragment() {
        let pki = gen_pki();
        let handler = teap_handler(&pki);
        let (state, start_eap) = teap_start(&handler);
        let first = EapTlsPacket::new(TlsFlags::new(true, true, false), Some(60), vec![0x16; 40]);
        let request = access_request(
            2,
            &teap_raw_response(start_eap.identifier, first),
            Some(&state),
        );
        let (state, attributes) = match handler.authenticate_request(&request, SECRET) {
            AuthResult::Challenge {
                state, attributes, ..
            } => (state, attributes),
            other => panic!("expected ACK, got {other:?}"),
        };
        let ack = eap_from_radius_packet(&packet_with(Code::AccessChallenge, 2, attributes))
            .unwrap()
            .unwrap();
        let ack_pkt = EapTlsPacket::from_eap_data(&ack.data).unwrap();
        assert_eq!(ack_pkt.flags.as_u8(), 0);
        assert!(ack_pkt.tls_data.is_empty());
        assert_ne!(ack.identifier, start_eap.identifier);

        // 40 + 40 > 60 announced: rejected before buffering.
        let overrun = EapTlsPacket::new(TlsFlags::new(false, true, false), None, vec![0x16; 40]);
        let request = access_request(3, &teap_raw_response(ack.identifier, overrun), Some(&state));
        assert!(matches!(
            handler.authenticate_request(&request, SECRET),
            AuthResult::Reject
        ));
    }

    /// Run a TEAP peer up to the first Phase 2 server message and return the
    /// handler, peer, State and that EAP-Request.
    fn teap_into_phase2(
        pki: &TestPki,
        fragment_size: usize,
    ) -> (EapAuthHandler, TeapPeer, Vec<u8>, EapPacket) {
        let mut handler = teap_handler(pki);
        handler.set_max_fragment_size(fragment_size);
        let mut peer = TeapPeer::new(pki, 4096);
        let mut request = identity_request();
        for _ in 0..64 {
            let (state, attributes) = match handler.authenticate_request(&request, SECRET) {
                AuthResult::Challenge {
                    state, attributes, ..
                } => (state, attributes),
                other => panic!("expected Challenge, got {other:?}"),
            };
            let challenge = packet_with(Code::AccessChallenge, request.identifier, attributes);
            let eap_request = eap_from_radius_packet(&challenge).unwrap().unwrap();
            let pkt = EapTlsPacket::from_eap_data(&eap_request.data).unwrap();
            if peer.handshake_done && !pkt.tls_data.is_empty() {
                return (handler, peer, state, eap_request);
            }
            let eap_response = peer.respond(&eap_request);
            request = access_request(
                challenge.identifier.wrapping_add(1),
                &eap_response,
                Some(&state),
            );
        }
        panic!("never reached Phase 2");
    }

    #[test]
    fn eap_teap_phase2_rejects_malformed_fragments() {
        let pki = gen_pki();
        let cases: Vec<(&str, EapTlsPacket)> = vec![
            (
                "first fragment with M but no L",
                EapTlsPacket::new(TlsFlags::new(false, true, false), None, vec![0x17; 50]),
            ),
            (
                "empty non-final fragment",
                EapTlsPacket::new(TlsFlags::new(true, true, false), Some(100), Vec::new()),
            ),
            (
                "peer set the S bit in Phase 2",
                EapTlsPacket::new(TlsFlags::new(false, false, true), None, vec![0x17; 50]),
            ),
            (
                "announced length above the bound",
                EapTlsPacket::new(
                    TlsFlags::new(true, true, false),
                    Some(u32::MAX),
                    vec![0x17; 50],
                ),
            ),
        ];
        for (name, pkt) in cases {
            let (handler, _peer, state, eap_request) = teap_into_phase2(&pki, 4096);
            let request = access_request(
                7,
                &teap_raw_response(eap_request.identifier, pkt),
                Some(&state),
            );
            assert!(
                matches!(
                    handler.authenticate_request(&request, SECRET),
                    AuthResult::Reject
                ),
                "{name}: expected Reject"
            );
        }
    }

    #[test]
    fn eap_teap_phase2_rejects_overrun_and_data_during_server_fragments() {
        let pki = gen_pki();

        // Overrun: announced 30, first fragment 20 (ACKed), second 20 → Reject.
        let (handler, _peer, state, eap_request) = teap_into_phase2(&pki, 4096);
        let first = EapTlsPacket::new(TlsFlags::new(true, true, false), Some(30), vec![0x17; 20]);
        let request = access_request(
            7,
            &teap_raw_response(eap_request.identifier, first),
            Some(&state),
        );
        let (state, attributes) = match handler.authenticate_request(&request, SECRET) {
            AuthResult::Challenge {
                state, attributes, ..
            } => (state, attributes),
            other => panic!("expected ACK, got {other:?}"),
        };
        let ack = eap_from_radius_packet(&packet_with(Code::AccessChallenge, 7, attributes))
            .unwrap()
            .unwrap();
        assert!(
            EapTlsPacket::from_eap_data(&ack.data)
                .unwrap()
                .tls_data
                .is_empty()
        );
        let overrun = EapTlsPacket::new(TlsFlags::new(false, true, false), None, vec![0x17; 20]);
        let request = access_request(8, &teap_raw_response(ack.identifier, overrun), Some(&state));
        assert!(matches!(
            handler.authenticate_request(&request, SECRET),
            AuthResult::Reject
        ));

        // Data while server fragments are pending: the server's Phase 2
        // message (MTU 64) is mid-flight; the peer must ACK, not send data.
        let (handler, _peer, state, eap_request) = teap_into_phase2(&pki, 64);
        assert!(
            EapTlsPacket::from_eap_data(&eap_request.data)
                .unwrap()
                .flags
                .more_fragments(),
            "server message is fragmented at MTU 64"
        );
        let data = EapTlsPacket::new(TlsFlags::new(true, false, false), Some(10), vec![0x17; 10]);
        let request = access_request(
            7,
            &teap_raw_response(eap_request.identifier, data),
            Some(&state),
        );
        assert!(matches!(
            handler.authenticate_request(&request, SECRET),
            AuthResult::Reject
        ));
    }

    // =====================================================================
    // Session store: eviction (capacity LRU, idle), terminal release, and
    // fail-closed handling of State for sessions that no longer exist.
    // =====================================================================

    /// Start an EAP-TLS conversation (Identity → Start) and return its State.
    fn start_conversation(handler: &EapAuthHandler, id: u8) -> Vec<u8> {
        let request = access_request(id, &EapPacket::identity_response(id, "alice"), None);
        match handler.authenticate_request(&request, SECRET) {
            AuthResult::Challenge { state, .. } => state,
            other => panic!("expected Start, got {other:?}"),
        }
    }

    /// Continue conversation `state` with an empty EAP-TLS Response.
    fn continue_conversation(handler: &EapAuthHandler, state: &[u8], id: u8) -> AuthResult {
        let response = EapTlsPacket::new(TlsFlags::new(false, false, false), None, Vec::new())
            .to_eap_response(id);
        handler.authenticate_request(&access_request(id, &response, Some(state)), SECRET)
    }

    /// Advance conversation `state` with the peer's ClientHello: a packet
    /// the server answers with a Challenge, which refreshes the session's
    /// LRU position (merely looking it up does not).
    fn advance_conversation(
        handler: &EapAuthHandler,
        pki: &TestPki,
        state: &[u8],
        id: u8,
    ) -> AuthResult {
        let mut peer = Supplicant::new(pki);
        let start = EapTlsPacket::start().to_eap_request(id);
        let response = peer.respond(&start);
        handler.authenticate_request(&access_request(id, &response, Some(state)), SECRET)
    }

    #[test]
    fn capacity_eviction_drops_least_recently_used_session_which_then_fails_closed() {
        let pki = gen_pki();
        let mut handler = eap_handler(&pki);
        handler.set_session_limits(600, 2);

        let a = start_conversation(&handler, 1);
        let b = start_conversation(&handler, 2);
        assert_eq!(handler.active_session_count(), 2);
        assert_eq!(handler.tls_sessions.read().unwrap().len(), 2);

        // Advance A so B becomes the least recently used.
        assert!(matches!(
            advance_conversation(&handler, &pki, &a, 10),
            AuthResult::Challenge { .. }
        ));

        // Third conversation: B is evicted.
        let _c = start_conversation(&handler, 3);
        assert_eq!(handler.active_session_count(), 2);
        assert_eq!(handler.tls_sessions.read().unwrap().len(), 2);
        assert_eq!(handler.eviction_counts(), (0, 1));

        // B's next packet is rejected (never accepted) and creates nothing.
        assert!(matches!(
            continue_conversation(&handler, &b, 4),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 2);
        assert!(handler.resolve_session(Some(&b)).is_none());
        assert!(handler.resolve_session(Some(&a)).is_some());
    }

    #[test]
    fn idle_session_is_reaped_and_fails_closed() {
        let pki = gen_pki();
        let mut handler = eap_handler(&pki);
        handler.set_session_limits(5, 100);
        let a = start_conversation(&handler, 1);
        assert_eq!(handler.active_session_count(), 1);

        let before = EAP_SESSIONS_EVICTED_IDLE.load(Ordering::Relaxed);
        let now = EapAuthHandler::now_secs();
        assert_eq!(
            handler.reap_at(now + 5),
            0,
            "not idle yet at exactly the timeout"
        );
        assert_eq!(handler.reap_at(now + 6), 1);
        assert_eq!(handler.active_session_count(), 0);
        assert!(handler.tls_sessions.read().unwrap().is_empty());
        assert_eq!(handler.eviction_counts(), (1, 0));
        assert!(EAP_SESSIONS_EVICTED_IDLE.load(Ordering::Relaxed) > before);

        assert!(matches!(
            continue_conversation(&handler, &a, 2),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 0);
    }

    /// RFC 3748 §4.1: the first Request of a conversation continues the
    /// NAS's Identifier sequence (Identity Response id + 1) instead of
    /// starting at 0, so it never repeats the Identity Request's Identifier.
    #[test]
    fn first_request_identifier_follows_the_nas_identity_request() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        for identity_id in [0u8, 1, 0x2A, 0xFE, 0xFF] {
            let request =
                access_request(7, &EapPacket::identity_response(identity_id, "alice"), None);
            let AuthResult::Challenge { attributes, .. } =
                handler.authenticate_request(&request, SECRET)
            else {
                panic!("expected EAP-TLS Start for identity id {identity_id}");
            };
            let challenge = packet_with(Code::AccessChallenge, 7, attributes);
            let start = eap_from_radius_packet(&challenge).unwrap().unwrap();
            assert_eq!(start.code, EapCode::Request);
            assert_eq!(start.eap_type, Some(EapType::Tls));
            assert_ne!(
                start.identifier, identity_id,
                "first Request reused the Identity Request's Identifier"
            );
            assert_eq!(start.identifier, identity_id.wrapping_add(1));
        }
    }

    /// The idle timeout is enforced by every incoming EAP packet, not only
    /// when a new conversation runs the reaper: an unrelated packet (here
    /// one with a forged State, which creates nothing) evicts the idle
    /// conversation, and its own late packet then fails closed.
    #[test]
    fn idle_session_is_evicted_by_any_incoming_packet() {
        let pki = gen_pki();
        let mut handler = eap_handler(&pki);
        handler.set_session_limits(5, 100);
        let a = start_conversation(&handler, 1);
        let a_id = String::from_utf8(a.clone()).unwrap();
        assert_eq!(handler.active_session_count(), 1);

        // Backdate A past the idle timeout without touching the LRU order.
        {
            let mut manager = handler.session_manager.write().unwrap();
            let session = manager.get_session_mut(&a_id).unwrap();
            session.last_activity -= 10;
        }

        // A packet for no live session: not a new conversation, still
        // evicts A before its own State is looked up.
        assert!(matches!(
            continue_conversation(&handler, b"nobody-0-0", 2),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 0);
        assert!(handler.tls_sessions.read().unwrap().is_empty());
        assert_eq!(handler.eviction_counts(), (1, 0));

        // A's own late packet fails closed and revives nothing.
        assert!(matches!(
            continue_conversation(&handler, &a, 3),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 0);
        assert_eq!(handler.eviction_counts(), (1, 0));
    }

    /// An idle conversation's own late packet is rejected rather than
    /// touching (and reviving) the session, even when no other traffic ran
    /// the reaper in between.
    #[test]
    fn idle_session_cannot_be_revived_by_its_own_late_packet() {
        let pki = gen_pki();
        let mut handler = eap_handler(&pki);
        handler.set_session_limits(5, 100);
        let a = start_conversation(&handler, 1);
        let a_id = String::from_utf8(a.clone()).unwrap();
        handler
            .session_manager
            .write()
            .unwrap()
            .get_session_mut(&a_id)
            .unwrap()
            .last_activity -= 10;

        assert!(matches!(
            continue_conversation(&handler, &a, 2),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 0);
        assert!(handler.tls_sessions.read().unwrap().is_empty());
        assert_eq!(handler.eviction_counts(), (1, 0));
    }

    /// A continuation of a live conversation at capacity evicts nothing: the
    /// per-packet reaper handles idle sessions only.
    #[test]
    fn per_packet_reaper_does_not_evict_for_capacity() {
        let pki = gen_pki();
        let mut handler = eap_handler(&pki);
        handler.set_session_limits(600, 2);
        let a = start_conversation(&handler, 1);
        let _b = start_conversation(&handler, 2);
        assert_eq!(handler.active_session_count(), 2);

        // A bogus-State packet while the store is full displaces nobody.
        assert!(matches!(
            continue_conversation(&handler, b"nobody-0-0", 3),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 2);
        assert!(handler.resolve_session(Some(&a)).is_some());
        assert_eq!(handler.eviction_counts(), (0, 0));
    }

    #[test]
    fn unknown_state_is_rejected_without_creating_a_session() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        assert!(matches!(
            continue_conversation(&handler, b"alice-0-forged", 1),
            AuthResult::Reject
        ));
        // Non-UTF-8 State too.
        assert!(matches!(
            continue_conversation(&handler, &[0xFF, 0xFE, 0x00], 2),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 0);
        assert!(handler.tls_sessions.read().unwrap().is_empty());
    }

    #[test]
    fn terminal_outcomes_release_session_state() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        let mut peer = Supplicant::new(&pki);

        // Accept releases everything.
        let mut request = identity_request();
        loop {
            match handler.authenticate_request(&request, SECRET) {
                AuthResult::Challenge {
                    state, attributes, ..
                } => {
                    assert_eq!(handler.active_session_count(), 1);
                    let mut challenge =
                        packet_with(Code::AccessChallenge, request.identifier, attributes);
                    challenge
                        .add_attribute(Attribute::new(AttributeType::State as u8, state).unwrap());
                    request = answer_challenge(&mut peer, &challenge);
                }
                AuthResult::Accept { .. } => break,
                AuthResult::Reject => panic!("EAP-TLS rejected"),
            }
        }
        assert_eq!(handler.active_session_count(), 0);
        assert!(handler.tls_sessions.read().unwrap().is_empty());

        // Reject releases everything too.
        let state = start_conversation(&handler, 1);
        assert_eq!(handler.active_session_count(), 1);
        let bad = EapTlsPacket::new(TlsFlags::new(false, true, false), None, vec![1, 2, 3]);
        let request = access_request(2, &bad.to_eap_response(0), Some(&state));
        assert!(matches!(
            handler.authenticate_request(&request, SECRET),
            AuthResult::Reject
        ));
        assert_eq!(handler.active_session_count(), 0);
        assert!(handler.tls_sessions.read().unwrap().is_empty());
    }

    #[test]
    fn eap_tls_rejects_peer_start_bit() {
        let pki = gen_pki();
        let handler = eap_handler(&pki);
        let state = start_conversation(&handler, 1);
        let pkt = EapTlsPacket::new(TlsFlags::new(false, false, true), None, vec![0x16; 10]);
        let request = access_request(2, &pkt.to_eap_response(0), Some(&state));
        assert!(matches!(
            handler.authenticate_request(&request, SECRET),
            AuthResult::Reject
        ));
    }
}
