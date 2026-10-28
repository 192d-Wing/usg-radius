//! Outbound RadSec link: RADIUS over mutually-authenticated TLS 1.3 from the
//! proxy to a `transport = "radsec"` home server (RFC 6614).
//!
//! One link task per RadSec home server owns **one persistent TLS connection**
//! (RFC 6614 §2.5: every RADIUS code travels on the same connection; §3.4:
//! long-lived connections watched by Status-Server). The connection is built
//! with the same [`usg_fips_tls`] provider the inbound listener uses — TLS 1.3
//! only, ML-KEM-1024-only key exchange, AES-256-GCM-SHA384 — and is mutually
//! authenticated: our client certificate from `tls.cert_path`/`tls.key_path`,
//! the home server's chain against `tls.ca_path` and `tls.server_name`
//! (RFC 6614 §2.3: the client MUST verify the server certificate), optionally
//! with CRL/OCSP revocation checking. The negotiated parameters are re-checked
//! with `enforce_fips_parameters` after every handshake and the connection is
//! dropped if anything falls outside the allow-list. There is no fallback to
//! UDP anywhere: a link that cannot be established stays down.
//!
//! Inside the tunnel the bytes are the same RADIUS packets the UDP path sends,
//! delimited by `Length` (RFC 6614 §2.5, shared [`take_frame`]) and keyed by
//! the fixed secret `"radsec"` (RFC 6614 §2.3) — `HomeServer::secret()`
//! returns it, so the proxy's re-keying code is untouched.
//!
//! **Disconnected ⇒ fail fast, no queue.** [`RadsecLinkHandle::send`] returns
//! [`LinkSendError::Down`] while the connection is down; the caller's entry
//! stays in the proxy cache and the retry manager resends it, so the only
//! queue is the one that already exists and is already bounded.
//!
//! The link task **verifies nothing**: a frame carrying a Proxy-State is a
//! proxied response and is delivered as a [`LinkResponse`] for
//! `ProxyHandler::handle_link_response` (correlation, Response Authenticator,
//! re-keying — exactly as for UDP, with the home server matched by `Arc`
//! identity instead of source address); a frame without one is a Status-Server
//! reply and is handed to the probe registered under its Identifier, where
//! `health.rs` applies the same checks as the UDP probe.
//!
//! RFC 6613 §2.6 / RFC 6614 §2.5 give one connection a single 256-value
//! Identifier space. The proxy forwards the NAS Identifier unchanged (as it
//! does over UDP), so two NASes using the same Identifier at the same time
//! collide on the link exactly as they would on the UDP socket; correlation
//! is by Proxy-State, not Identifier, so the collision only matters to a home
//! server that deduplicates on Identifier.
//! TODO(gap): Identifier management on the upstream hop (RFC 6613 §2.6).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use radius_proto::attributes::AttributeType;
use radius_proto::{Code, Packet};
use rand::RngExt;
use rustls::ClientConfig;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::version::TLS13;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::proxy::error::ProxyError;
use crate::proxy::home_server::{HomeServer, HomeServerTlsConfig};
use crate::radsec_frame::{FrameError, RADIUS_MAX_LEN, take_frame};
use crate::server_verifier::ServerVerifierError;

/// A proxied response read off a RadSec link, for
/// `ProxyHandler::handle_link_response`. `home_server` is the server the link
/// belongs to; the handler checks it against the cache entry by `Arc` identity.
pub struct LinkResponse {
    pub home_server: Arc<HomeServer>,
    pub packet: Packet,
}

/// Errors building or running a RadSec link. `Display` carries no key material.
#[derive(Debug, thiserror::Error)]
pub enum RadsecClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate/key PEM error: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("server certificate verifier: {0}")]
    ServerVerifier(#[from] ServerVerifierError),
    #[error("invalid server_name {0:?}: not a DNS name or IP address")]
    BadServerName(String),
    #[error("home server {0} is not configured with transport = \"radsec\"")]
    NotRadsec(String),
    #[error(
        "negotiated TLS parameters outside the FIPS/PQ allow-list: {0} \
         (RadSec requires TLS 1.3 + AES-256-GCM-SHA384 + ML-KEM-1024)"
    )]
    DisallowedParameters(usg_fips_tls::error::FipsError),
    #[error("{0}")]
    Frame(#[from] FrameError),
    #[error("{0} timed out")]
    Timeout(&'static str),
}

impl From<RadsecClientError> for ProxyError {
    fn from(e: RadsecClientError) -> Self {
        ProxyError::Tls(e.to_string())
    }
}

/// Why [`RadsecLinkHandle::send`] did not take a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSendError {
    /// The connection is down (connecting or backing off). Nothing is queued.
    Down,
    /// The connection is up but the bounded outbound queue is full.
    Busy,
}

impl LinkSendError {
    /// The proxy-level error for a send to `server` that failed this way.
    pub fn into_proxy_error(self, server: &str) -> ProxyError {
        match self {
            Self::Down => ProxyError::LinkDown(server.to_string()),
            Self::Busy => ProxyError::LinkBusy(server.to_string()),
        }
    }
}

/// Connection and reconnect timing for a link.
#[derive(Debug, Clone, Copy)]
pub struct LinkParams {
    /// Deadline for the TCP connect and, separately, for the TLS handshake.
    pub connect_timeout: Duration,
    /// Delay before the first reconnect attempt after a failure.
    pub initial_backoff: Duration,
    /// Cap on the (doubling, ±25 % jittered) reconnect delay.
    pub max_backoff: Duration,
    /// A connection that lived at least this long resets the backoff.
    pub stable_after: Duration,
}

impl Default for LinkParams {
    fn default() -> Self {
        LinkParams {
            connect_timeout: Duration::from_secs(10),
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            stable_after: Duration::from_secs(10),
        }
    }
}

/// Where probe replies go: Identifier → the waiting probe's sender, with a
/// token so a probe deregisters only its own registration.
type ProbeTable = DashMap<u8, (u64, mpsc::Sender<Packet>)>;

/// Handle to a running link: send frames, register Status-Server probes, read
/// the connection state. Cheap to clone; the `HomeServer` holds one.
#[derive(Clone)]
pub struct RadsecLinkHandle {
    outbound: mpsc::Sender<Vec<u8>>,
    connected: Arc<AtomicBool>,
    probes: Arc<ProbeTable>,
    connections: Arc<AtomicU64>,
}

impl RadsecLinkHandle {
    /// Queue one RADIUS frame for the connection. Fails immediately when the
    /// link is down (nothing is queued) or the bounded outbound queue is full.
    pub fn send(&self, frame: Vec<u8>) -> Result<(), LinkSendError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkSendError::Down);
        }
        self.outbound.try_send(frame).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => LinkSendError::Busy,
            mpsc::error::TrySendError::Closed(_) => LinkSendError::Down,
        })
    }

    /// Whether the TLS connection is currently established.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Register to receive frames without a Proxy-State that carry
    /// `identifier` — a Status-Server reply (RFC 5997). Register **before**
    /// sending the probe. The registration is removed when the receiver is
    /// dropped, and the receiver yields `None` when the link is lost.
    pub fn register_probe(&self, identifier: u8) -> ProbeReceiver {
        static TOKEN: AtomicU64 = AtomicU64::new(1);
        let token = TOKEN.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(8);
        self.probes.insert(identifier, (token, tx));
        ProbeReceiver {
            identifier,
            token,
            rx,
            probes: Arc::clone(&self.probes),
        }
    }

    /// Number of TLS connections established so far (for tests and stats).
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for RadsecLinkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RadsecLinkHandle")
            .field("connected", &self.is_connected())
            .field("connections", &self.connections())
            .finish()
    }
}

/// The receiving end of [`RadsecLinkHandle::register_probe`].
pub struct ProbeReceiver {
    identifier: u8,
    token: u64,
    rx: mpsc::Receiver<Packet>,
    probes: Arc<ProbeTable>,
}

impl ProbeReceiver {
    /// The next frame for this Identifier, or `None` once the link is lost
    /// (every probe sender is dropped on disconnect).
    pub async fn recv(&mut self) -> Option<Packet> {
        self.rx.recv().await
    }
}

impl Drop for ProbeReceiver {
    fn drop(&mut self) {
        self.probes
            .remove_if(&self.identifier, |_, (token, _)| *token == self.token);
    }
}

/// Build the rustls `ClientConfig` for a RadSec home server: the ML-KEM-1024-only
/// FIPS provider, TLS 1.3 only, our client certificate (mTLS), and the server
/// verifier for `tls.ca_path`/`tls.server_name` (+ revocation when configured).
/// Session resumption is disabled so every reconnect is a full handshake with
/// full certificate and revocation verification. No ALPN (RFC 6614 defines
/// none). Fails on any unreadable or malformed PEM, CA bundle or CRL so a bad
/// home server is rejected at startup.
pub fn build_client_config(
    tls: &HomeServerTlsConfig,
) -> Result<Arc<ClientConfig>, RadsecClientError> {
    let provider = usg_fips_tls::provider::fips_provider_arc();

    let certs = crate::tls_certs::load_cert_chain(&tls.cert_path)?;
    let key = crate::tls_certs::load_private_key(&tls.key_path)?;

    let verifier = crate::server_verifier::build_server_verifier(
        &tls.ca_path,
        Arc::clone(&provider),
        tls.revocation.as_ref(),
    )?;
    if verifier.checks_revocation() {
        info!(
            server_name = %tls.server_name,
            "RadSec link: the home server certificate is checked for revocation"
        );
    }

    // `dangerous()` is rustls's name for installing any verifier that is not
    // the one `with_root_certificates` builds; ours *is* that verifier
    // (`WebPkiServerVerifier`: chain, validity, server_name), optionally
    // followed by the revocation check — nothing is weakened.
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier.into_arc())
        .with_client_auth_cert(certs, key)?;
    config.resumption = Resumption::disabled();

    Ok(Arc::new(config))
}

/// Start the link task for `home_server` (which must be `transport = "radsec"`).
/// Building the TLS configuration happens here, synchronously, so a bad
/// certificate, key, CA bundle, CRL or `server_name` fails startup. Proxied
/// responses are delivered on `responses`; the returned handle is what
/// `HomeServer::attach_link` stores. The task ends when every handle is gone.
pub fn spawn_link(
    home_server: Arc<HomeServer>,
    responses: mpsc::Sender<LinkResponse>,
    params: LinkParams,
) -> Result<RadsecLinkHandle, RadsecClientError> {
    let tls = home_server
        .tls_config()
        .ok_or_else(|| RadsecClientError::NotRadsec(home_server.name.clone()))?;
    let config = build_client_config(tls)?;
    let server_name = ServerName::try_from(tls.server_name.as_str())
        .map_err(|_| RadsecClientError::BadServerName(tls.server_name.clone()))?
        .to_owned();

    let (outbound_tx, outbound_rx) = mpsc::channel(home_server.max_outstanding.max(1));
    let handle = RadsecLinkHandle {
        outbound: outbound_tx,
        connected: Arc::new(AtomicBool::new(false)),
        probes: Arc::new(DashMap::new()),
        connections: Arc::new(AtomicU64::new(0)),
    };

    let link = Link {
        name: home_server.name.clone(),
        address: home_server.address,
        server_name,
        connector: TlsConnector::from(config),
        params,
        // Weak: the `HomeServer` holds the handle, the task must not hold the
        // `HomeServer`, or neither would ever be dropped.
        home_server: Arc::downgrade(&home_server),
        responses,
        connected: Arc::clone(&handle.connected),
        probes: Arc::clone(&handle.probes),
        connections: Arc::clone(&handle.connections),
        outbound: outbound_rx,
    };
    tokio::spawn(link.run());

    Ok(handle)
}

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// How a connection ended.
enum LinkEnd {
    /// The home server closed the connection (clean EOF).
    Eof,
    /// Every `RadsecLinkHandle` was dropped: the task is done.
    HandleDropped,
}

/// Negotiated parameters of an established connection, for the log line.
struct Negotiated {
    version: Option<rustls::ProtocolVersion>,
    suite: Option<rustls::CipherSuite>,
    group: Option<rustls::NamedGroup>,
}

/// The link task's state.
struct Link {
    name: String,
    address: SocketAddr,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    params: LinkParams,
    home_server: Weak<HomeServer>,
    responses: mpsc::Sender<LinkResponse>,
    connected: Arc<AtomicBool>,
    probes: Arc<ProbeTable>,
    connections: Arc<AtomicU64>,
    outbound: mpsc::Receiver<Vec<u8>>,
}

impl Link {
    /// Connect, serve, back off, reconnect — until the handle is dropped.
    async fn run(mut self) {
        let mut backoff = self.params.initial_backoff;
        loop {
            if self.outbound.is_closed() {
                debug!(server = %self.name, "RadSec link handle dropped; link task ending");
                return;
            }

            match self.connect().await {
                Ok((tls, negotiated)) => {
                    self.connections.fetch_add(1, Ordering::Relaxed);
                    self.connected.store(true, Ordering::Release);
                    info!(
                        server = %self.name,
                        address = %self.address,
                        version = ?negotiated.version,
                        suite = ?negotiated.suite,
                        group = ?negotiated.group,
                        "RadSec link established"
                    );
                    let established = Instant::now();

                    let end = self.serve(tls).await;

                    // Down: refuse new sends first, then fail every waiting
                    // probe and discard what was queued for the dead connection.
                    self.connected.store(false, Ordering::Release);
                    self.probes.clear();
                    let dropped = self.drain_outbound();
                    match end {
                        Ok(LinkEnd::HandleDropped) => {
                            debug!(server = %self.name, "RadSec link handle dropped; link task ending");
                            return;
                        }
                        Ok(LinkEnd::Eof) => info!(
                            server = %self.name,
                            address = %self.address,
                            reason = "closed by peer",
                            dropped_frames = dropped,
                            "RadSec link lost"
                        ),
                        Err(e) => info!(
                            server = %self.name,
                            address = %self.address,
                            reason = %e,
                            dropped_frames = dropped,
                            "RadSec link lost"
                        ),
                    }
                    if established.elapsed() >= self.params.stable_after {
                        backoff = self.params.initial_backoff;
                    }
                }
                Err(e) => {
                    warn!(
                        server = %self.name,
                        address = %self.address,
                        error = %e,
                        retry_in = ?backoff,
                        "RadSec link connect failed"
                    );
                }
            }

            // Capped exponential backoff with ±25 % jitter so a fleet of
            // proxies does not reconnect in lockstep.
            let jitter = rand::rng().random_range(0.75..=1.25);
            time::sleep(backoff.mul_f64(jitter)).await;
            backoff = backoff.saturating_mul(2).min(self.params.max_backoff);
        }
    }

    /// TCP connect, TLS handshake, allow-list check — each failure is logged
    /// by the caller via `Display` only (no key material in any of them).
    async fn connect(&self) -> Result<(TlsStream, Negotiated), RadsecClientError> {
        let tcp = time::timeout(
            self.params.connect_timeout,
            TcpStream::connect(self.address),
        )
        .await
        .map_err(|_| RadsecClientError::Timeout("TCP connect"))??;
        tcp.set_nodelay(true)?;

        let tls = time::timeout(
            self.params.connect_timeout,
            self.connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| RadsecClientError::Timeout("TLS handshake"))??;

        // Fail closed on anything outside the allow-list before a byte of
        // RADIUS is written (same gate as the inbound listener).
        let (_, conn) = tls.get_ref();
        let negotiated = Negotiated {
            version: conn.protocol_version(),
            suite: conn.negotiated_cipher_suite().map(|s| s.suite()),
            group: conn.negotiated_key_exchange_group().map(|g| g.name()),
        };
        usg_fips_tls::params::enforce_fips_parameters(
            negotiated.version,
            negotiated.suite,
            negotiated.group,
        )
        .map_err(RadsecClientError::DisallowedParameters)?;

        Ok((tls, negotiated))
    }

    /// Serve one established connection: inbound frames are demultiplexed,
    /// outbound frames are written as they are queued.
    async fn serve(&mut self, tls: TlsStream) -> Result<LinkEnd, RadsecClientError> {
        let (mut rd, mut wr) = tokio::io::split(tls);

        // Accumulating read buffer: `read_buf` is cancel-safe in `select!`
        // (unlike `read_exact`), so an outbound frame arriving mid-read never
        // corrupts the stream.
        let mut buf: Vec<u8> = Vec::with_capacity(RADIUS_MAX_LEN);

        loop {
            // Drain every complete frame already buffered before awaiting more
            // I/O. A bad Length (RFC 2865 §3) means the stream is out of sync:
            // the error closes the connection, as the inbound listener does.
            while let Some(frame) = take_frame(&mut buf)? {
                if let Some(end) = self.demux(frame).await {
                    return Ok(end);
                }
            }

            tokio::select! {
                read = rd.read_buf(&mut buf) => {
                    if read? == 0 {
                        return Ok(LinkEnd::Eof);
                    }
                }
                frame = self.outbound.recv() => match frame {
                    Some(frame) => {
                        // RFC 6614 §2.5: the packet as is, no extra framing.
                        wr.write_all(&frame).await?;
                        wr.flush().await?;
                    }
                    None => return Ok(LinkEnd::HandleDropped),
                },
            }
        }
    }

    /// Route one inbound frame. Nothing is verified here (see the module
    /// docs); the handler and the probe do that. Returns `Some` when the task
    /// must end (the `HomeServer` is gone).
    async fn demux(&self, frame: Vec<u8>) -> Option<LinkEnd> {
        let packet = match Packet::decode(&frame) {
            Ok(packet) => packet,
            Err(e) => {
                // Undecodable but correctly framed: drop it, keep the connection.
                debug!(server = %self.name, error = %e, "RadSec link: dropping undecodable frame");
                return None;
            }
        };

        // RFC 2865 §5.33: the last Proxy-State is the one we appended, so any
        // Proxy-State marks a proxied response. Its length and cache hit are
        // the handler's business (`CorrelationFailed` as over UDP).
        let has_proxy_state = packet
            .attributes
            .iter()
            .any(|a| a.attr_type == AttributeType::ProxyState as u8);
        if has_proxy_state {
            let Some(home_server) = self.home_server.upgrade() else {
                return Some(LinkEnd::HandleDropped);
            };
            if self
                .responses
                .send(LinkResponse {
                    home_server,
                    packet,
                })
                .await
                .is_err()
            {
                debug!(server = %self.name, "RadSec link: response channel closed; dropping frame");
            }
            return None;
        }

        // CoA/Disconnect from the home server over this connection is out of
        // scope (RFC 6614 §2.5 permits it; the proxy does not relay it).
        if matches!(packet.code, Code::CoaRequest | Code::DisconnectRequest) {
            debug!(
                server = %self.name,
                code = ?packet.code,
                identifier = packet.identifier,
                "RadSec link: dropping unsupported server-originated request"
            );
            return None;
        }

        // RFC 5997 Status-Server reply: no Proxy-State, matched by Identifier
        // to the waiting probe (RFC 5997 §4.4 verification happens there).
        match self.probes.get(&packet.identifier) {
            Some(entry) => {
                let identifier = packet.identifier;
                if entry.value().1.try_send(packet).is_err() {
                    debug!(
                        server = %self.name,
                        identifier,
                        "RadSec link: probe receiver full or gone; dropping reply"
                    );
                }
            }
            None => debug!(
                server = %self.name,
                code = ?packet.code,
                identifier = packet.identifier,
                "RadSec link: dropping unsolicited frame"
            ),
        }
        None
    }

    /// Discard frames queued for a connection that no longer exists. Their
    /// cache entries stay; the retry manager resends them on the next link.
    fn drain_outbound(&mut self) -> usize {
        let mut dropped = 0;
        while self.outbound.try_recv().is_ok() {
            dropped += 1;
        }
        if dropped > 0 {
            debug!(
                server = %self.name,
                dropped,
                "RadSec link: discarded frames queued for the lost connection"
            );
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;
    use crate::proxy::home_server::HomeServerConfig;
    use crate::radsec_frame::RADSEC_SECRET;
    use crate::test_pki::{
        FakeAction, TestPaths, gen_chain, gen_chain_with, lenient_server_config,
        spawn_fake_tls_home, spawn_fake_tls_home_with_provider, spawn_radsec_home,
    };
    use radius_proto::attributes::Attribute;
    use radius_proto::auth::{
        calculate_response_authenticator, encrypt_user_password, generate_request_authenticator,
    };
    use radius_proto::calculate_message_authenticator;

    const PROXY_STATE: [u8; 16] = [0x50; 16];

    /// Fast timings so reconnect tests finish in well under a second.
    fn fast() -> LinkParams {
        LinkParams {
            connect_timeout: Duration::from_secs(2),
            initial_backoff: Duration::from_millis(40),
            max_backoff: Duration::from_millis(160),
            stable_after: Duration::from_secs(10),
        }
    }

    fn tls_block(paths: &TestPaths, server_name: &str) -> HomeServerTlsConfig {
        HomeServerTlsConfig {
            ca_path: paths.ca.clone(),
            cert_path: paths.client_cert.clone(),
            key_path: paths.client_key.clone(),
            server_name: server_name.to_string(),
            revocation: None,
        }
    }

    fn home_server(addr: SocketAddr, tls: HomeServerTlsConfig) -> Arc<HomeServer> {
        Arc::new(
            HomeServer::new(HomeServerConfig {
                name: Some(format!("home-{}", addr.port())),
                timeout: 2,
                max_outstanding: 8,
                ..HomeServerConfig::radsec(addr.to_string(), tls)
            })
            .unwrap(),
        )
    }

    /// `spawn_link` + `attach_link`, waiting up to 5 s for the connection.
    async fn connected_link(
        hs: &Arc<HomeServer>,
        tx: mpsc::Sender<LinkResponse>,
        params: LinkParams,
    ) -> RadsecLinkHandle {
        let handle = spawn_link(Arc::clone(hs), tx, params).unwrap();
        hs.attach_link(handle.clone());
        wait_for(|| handle.is_connected(), Duration::from_secs(5)).await;
        assert!(handle.is_connected(), "link did not come up");
        assert!(hs.is_connected());
        handle
    }

    async fn wait_for(mut cond: impl FnMut() -> bool, max: Duration) {
        let deadline = Instant::now() + max;
        while !cond() && Instant::now() < deadline {
            time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Set the Message-Authenticator (RFC 3579 §3.2) under `secret`.
    fn sign(packet: &mut Packet, secret: &[u8]) {
        for ma in packet
            .attributes
            .iter_mut()
            .filter(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
        {
            ma.value = vec![0u8; 16];
        }
        let mac = calculate_message_authenticator(&packet.encode().unwrap(), secret);
        if let Some(ma) = packet
            .attributes
            .iter_mut()
            .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
        {
            ma.value = mac.to_vec();
        }
    }

    /// PAP Access-Request as the proxy would forward it over the link: keyed
    /// `"radsec"`, our Proxy-State appended. Password built at runtime.
    fn forwarded_access_request(id: u8, password: &str) -> Vec<u8> {
        let auth = generate_request_authenticator();
        let mut p = Packet::new(Code::AccessRequest, id, auth);
        p.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
        p.add_attribute(
            Attribute::new(
                AttributeType::UserPassword as u8,
                encrypt_user_password(password, RADSEC_SECRET, &auth),
            )
            .unwrap(),
        );
        p.add_attribute(Attribute::string(AttributeType::NasIdentifier as u8, "proxy").unwrap());
        p.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        p.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, PROXY_STATE.to_vec()).unwrap(),
        );
        sign(&mut p, RADSEC_SECRET);
        p.encode().unwrap()
    }

    /// RFC 5997 Status-Server probe keyed `"radsec"`.
    fn status_server(id: u8) -> Vec<u8> {
        let mut p = Packet::new(Code::StatusServer, id, generate_request_authenticator());
        p.add_attribute(
            Attribute::new(AttributeType::MessageAuthenticator as u8, vec![0u8; 16]).unwrap(),
        );
        sign(&mut p, RADSEC_SECRET);
        p.encode().unwrap()
    }

    /// What a home server answers to a proxied request: Access-Accept echoing
    /// every Proxy-State, Response Authenticator under `"radsec"`.
    fn echo_accept(request: &Packet) -> Vec<u8> {
        let mut reply = Packet::new(Code::AccessAccept, request.identifier, [0u8; 16]);
        for ps in request
            .attributes
            .iter()
            .filter(|a| a.attr_type == AttributeType::ProxyState as u8)
        {
            reply.add_attribute(ps.clone());
        }
        reply.authenticator =
            calculate_response_authenticator(&reply, &request.authenticator, RADSEC_SECRET);
        reply.encode().unwrap()
    }

    fn password() -> String {
        ('a'..='p').collect()
    }

    #[test]
    fn client_config_offers_only_tls13_aes256_mlkem1024() {
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let config = build_client_config(&tls_block(&paths, "localhost")).unwrap();
        let provider = config.crypto_provider();
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups, vec![rustls::NamedGroup::MLKEM1024]);
        let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(suites, vec![rustls::CipherSuite::TLS13_AES_256_GCM_SHA384]);
        assert!(config.alpn_protocols.is_empty(), "RFC 6614 defines no ALPN");
    }

    #[test]
    fn missing_certificate_file_fails_at_build_time() {
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let mut tls = tls_block(&paths, "localhost");
        tls.cert_path = format!("{}.missing", tls.cert_path);
        assert!(matches!(
            build_client_config(&tls).unwrap_err(),
            RadsecClientError::Pem(_)
        ));
        let mut tls = tls_block(&paths, "localhost");
        tls.ca_path = format!("{}.missing", tls.ca_path);
        assert!(matches!(
            build_client_config(&tls).unwrap_err(),
            RadsecClientError::ServerVerifier(_)
        ));
    }

    #[test]
    fn spawn_link_refuses_a_udp_home_server() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let hs =
                Arc::new(HomeServer::new(HomeServerConfig::udp("127.0.0.1:1812", "x")).unwrap());
            let (tx, _rx) = mpsc::channel(1);
            assert!(matches!(
                spawn_link(hs, tx, fast()).unwrap_err(),
                RadsecClientError::NotRadsec(_)
            ));
        });
    }

    #[tokio::test]
    async fn access_request_over_the_link_yields_a_link_response_from_our_home_server() {
        // The real inbound listener plays the home server, with a PAP user.
        let chain = gen_chain();
        let pw = password();
        let (addr, _registry, paths) =
            spawn_radsec_home(&chain, false, lenient_server_config(&[("alice", &pw)])).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;
        assert_eq!(link.connections(), 1);

        link.send(forwarded_access_request(42, &pw)).unwrap();

        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert!(
            Arc::ptr_eq(&response.home_server, &hs),
            "LinkResponse must name the link's own home server"
        );
        assert_eq!(response.packet.code, Code::AccessAccept);
        assert_eq!(response.packet.identifier, 42);
        let echoed = response
            .packet
            .find_attribute(AttributeType::ProxyState as u8)
            .expect("home server echoes Proxy-State (RFC 2865 §5.33)");
        assert_eq!(echoed.value, PROXY_STATE.to_vec());
    }

    #[tokio::test]
    async fn status_server_reply_goes_to_the_registered_probe_not_the_response_channel() {
        let chain = gen_chain();
        let (addr, _registry, paths) =
            spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;

        let mut probe = link.register_probe(0x5a);
        link.send(status_server(0x5a)).unwrap();

        let reply = time::timeout(Duration::from_secs(5), probe.recv())
            .await
            .expect("probe reply within 5 s")
            .expect("link up");
        assert_eq!(reply.code, Code::AccessAccept);
        assert_eq!(reply.identifier, 0x5a);
        assert!(
            rx.try_recv().is_err(),
            "a probe reply must not be delivered as a proxied response"
        );

        // Dropping the receiver deregisters the Identifier.
        drop(probe);
        assert!(link.probes.get(&0x5a).is_none());
    }

    #[tokio::test]
    async fn probe_registration_survives_a_later_probe_with_the_same_identifier() {
        let chain = gen_chain();
        let (addr, _registry, paths) =
            spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, _rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;

        let first = link.register_probe(7);
        let second = link.register_probe(7);
        drop(first);
        assert!(
            link.probes.get(&7).is_some(),
            "dropping the superseded probe must not remove the live one"
        );
        drop(second);
        assert!(link.probes.get(&7).is_none());
    }

    #[tokio::test]
    async fn non_mlkem_server_never_connects() {
        // A server offering only classical X25519: no group in common with the
        // ML-KEM-1024-only client, so the handshake fails closed every time.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let x25519_only = rustls::crypto::CryptoProvider {
            kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let addr =
            spawn_fake_tls_home_with_provider(&chain, x25519_only, |_, _| FakeAction::Close).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, _rx) = mpsc::channel(4);
        let link = spawn_link(Arc::clone(&hs), tx, fast()).unwrap();
        hs.attach_link(link.clone());

        time::sleep(Duration::from_millis(400)).await;
        assert!(!link.is_connected());
        assert!(!hs.is_connected());
        assert_eq!(link.connections(), 0, "no connection may ever be counted");
        assert_eq!(link.send(status_server(1)), Err(LinkSendError::Down));
    }

    #[tokio::test]
    async fn server_name_mismatch_never_connects() {
        // Valid chain, but the certificate is for "localhost" and we insist on
        // another name (RFC 6614 §2.3: the client MUST verify the server).
        let chain = gen_chain();
        let (addr, _registry, paths) =
            spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
        let hs = home_server(addr, tls_block(&paths, "other.test"));
        let (tx, _rx) = mpsc::channel(4);
        let link = spawn_link(Arc::clone(&hs), tx, fast()).unwrap();
        hs.attach_link(link.clone());

        time::sleep(Duration::from_millis(400)).await;
        assert!(!link.is_connected());
        assert_eq!(link.connections(), 0);
        assert_eq!(link.send(status_server(1)), Err(LinkSendError::Down));
    }

    #[tokio::test]
    async fn reconnects_after_the_home_server_drops_the_connection() {
        // Connection 1 reads one frame and hangs up; every later connection
        // answers properly.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let addr = spawn_fake_tls_home(&chain, |connection, request| {
            if connection == 1 {
                FakeAction::Close
            } else {
                FakeAction::Reply(vec![echo_accept(request)])
            }
        })
        .await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;
        assert_eq!(link.connections(), 1);

        link.send(forwarded_access_request(1, &password())).unwrap();

        // The link notices the drop and comes back on its own.
        wait_for(
            || link.connections() == 2 && link.is_connected(),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(link.connections(), 2, "link must reconnect once");
        assert!(link.is_connected());
        assert!(
            rx.try_recv().is_err(),
            "the dropped request produced no response"
        );

        // The next send goes over the new connection and is answered.
        link.send(forwarded_access_request(2, &password())).unwrap();
        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert_eq!(response.packet.identifier, 2);
        assert!(Arc::ptr_eq(&response.home_server, &hs));
    }

    #[tokio::test]
    async fn probe_waiting_on_a_lost_link_is_told_so() {
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let addr = spawn_fake_tls_home(&chain, |_, _| FakeAction::Close).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, _rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;

        let mut probe = link.register_probe(9);
        link.send(status_server(9)).unwrap();
        // The fake home hangs up on the probe: the receiver ends instead of
        // waiting out the deadline.
        let got = time::timeout(Duration::from_secs(5), probe.recv())
            .await
            .expect("probe receiver must resolve when the link drops");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn send_while_down_fails_fast_without_queueing() {
        // Nothing listens on the port: connects are refused, the link stays
        // down, and a send is refused in O(1) rather than queued.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let addr = {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap()
        };
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, _rx) = mpsc::channel(4);
        let link = spawn_link(Arc::clone(&hs), tx, fast()).unwrap();
        hs.attach_link(link.clone());
        time::sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        let result = link.send(status_server(1));
        let elapsed = started.elapsed();
        assert_eq!(result, Err(LinkSendError::Down));
        assert!(elapsed < Duration::from_millis(10), "took {elapsed:?}");
        assert!(!hs.is_connected());
    }

    #[tokio::test]
    async fn link_task_ends_when_the_home_server_is_dropped() {
        let chain = gen_chain();
        let (addr, _registry, paths) =
            spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, _rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;
        let connected = Arc::clone(&link.connected);

        drop(link);
        drop(hs);
        // The task notices the closed outbound channel and exits; the
        // connection flag is cleared on the way out.
        wait_for(
            || !connected.load(Ordering::Acquire),
            Duration::from_secs(5),
        )
        .await;
        assert!(!connected.load(Ordering::Acquire));
    }

    #[cfg(feature = "revocation")]
    mod with_revocation {
        use super::*;
        use crate::config::{CrlSettings, RevocationConfig};

        fn static_crl(paths: &TestPaths) -> RevocationConfig {
            RevocationConfig {
                crl: CrlSettings {
                    static_files: vec![paths.crl.clone()],
                    fetch: false,
                    ..CrlSettings::default()
                },
                ..RevocationConfig::default()
            }
        }

        #[tokio::test]
        async fn revoked_home_server_certificate_never_connects() {
            // The CA's CRL lists the *server* certificate.
            let chain = gen_chain_with(&["localhost"], true);
            let (addr, _registry, paths) =
                spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
            let tls = HomeServerTlsConfig {
                revocation: Some(static_crl(&paths)),
                ..tls_block(&paths, "localhost")
            };
            let hs = home_server(addr, tls);
            let (tx, _rx) = mpsc::channel(4);
            let link = spawn_link(Arc::clone(&hs), tx, fast()).unwrap();
            hs.attach_link(link.clone());

            time::sleep(Duration::from_millis(400)).await;
            assert!(
                !link.is_connected(),
                "a revoked home server must fail closed"
            );
            assert_eq!(link.connections(), 0);
            assert_eq!(link.send(status_server(1)), Err(LinkSendError::Down));
        }

        #[tokio::test]
        async fn unrevoked_home_server_certificate_connects_with_crl_checking() {
            // Same layout; the CRL lists the client certificate, not the server's.
            let chain = gen_chain_with(&["localhost"], false);
            let (addr, _registry, paths) =
                spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
            let tls = HomeServerTlsConfig {
                revocation: Some(static_crl(&paths)),
                ..tls_block(&paths, "localhost")
            };
            let hs = home_server(addr, tls);
            let (tx, _rx) = mpsc::channel(4);
            let link = connected_link(&hs, tx, fast()).await;

            let mut probe = link.register_probe(3);
            link.send(status_server(3)).unwrap();
            let reply = time::timeout(Duration::from_secs(5), probe.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.code, Code::AccessAccept);
        }
    }
}
