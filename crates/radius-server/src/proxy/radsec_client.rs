//! Outbound RadSec link: RADIUS over mutually-authenticated TLS 1.3 from the
//! proxy to a `transport = "radsec"` home server (RFC 6614).
//!
//! One link task per RadSec home server owns **one persistent TLS connection**
//! (RFC 6614 §2.5: every RADIUS code travels on the same connection; the
//! connection is established and kept "as per RFC 6613", §2.3 item 1, and
//! watched by the RFC 3539 §3.4 application-layer watchdog that RFC 6613 §2.6
//! mandates, with Status-Server as the watchdog message — see `health.rs`).
//! The connection is built with the same [`usg_fips_tls`] provider the inbound
//! listener uses — TLS 1.3 only, ML-KEM-1024-only key exchange,
//! AES-256-GCM-SHA384 — and is mutually authenticated: our client certificate
//! from `tls.cert_path`/`tls.key_path`, the home server's chain against
//! `tls.ca_path` and `tls.server_name` (RFC 6614 §2.3 item 2: mutual
//! authentication is REQUIRED; item 3: RFC 5280 validation and the expected
//! DNS name), optionally with CRL/OCSP revocation checking. The negotiated
//! parameters are re-checked with `enforce_fips_parameters` after every
//! handshake and the connection is dropped if anything falls outside the
//! allow-list. There is no fallback to UDP anywhere: a link that cannot be
//! established stays down.
//!
//! Inside the tunnel the bytes are the same RADIUS packets the UDP path sends,
//! delimited by `Length` (RFC 6614 §3.4 item 1, receiver rules RFC 6613
//! §2.6.4; shared [`take_frame`]) and keyed by the fixed secret `"radsec"`
//! (RFC 6614 §2.3 item 4) — `HomeServer::secret()` returns it, so the proxy's
//! re-keying code is untouched.
//!
//! **Disconnected ⇒ fail fast, no queue.** [`RadsecLinkHandle::send`] returns
//! [`LinkSendError::Down`] while the connection is down; the caller's entry
//! stays in the proxy cache and the retry manager resends it, so the only
//! queue is the one that already exists and is already bounded. A frame that
//! was queued for a connection that died is discarded, never written to the
//! next connection (the retry manager re-sends it there if it is still due).
//!
//! **The connection is closed when the peer breaks the protocol** (RFC 6613
//! §2.6.4): a frame whose `Length` is out of range or that does not decode as
//! a RADIUS packet ends the connection from inside the task; a response whose
//! Response Authenticator or Message-Authenticator fails verification is
//! detected by the handler / the probe and ends it through
//! [`RadsecLinkHandle::reset`], as does the watchdog after two unanswered
//! Status-Server probes (RFC 3539 §3.4). Every close goes through the same
//! backoff-and-reconnect path.
//!
//! The link task **verifies nothing**: a frame carrying a Proxy-State is a
//! proxied response and is delivered as a [`LinkResponse`] for
//! `ProxyHandler::handle_link_response` (correlation, Response Authenticator,
//! re-keying — exactly as for UDP, with the home server matched by `Arc`
//! identity instead of source address); a frame without one is a Status-Server
//! reply and is handed to the probe registered under its Identifier, where
//! `health.rs` applies the same checks as the UDP probe. A CoA-Request or
//! Disconnect-Request from the home server is answered with a CoA-NAK /
//! Disconnect-NAK carrying `Error-Cause 406` (RFC 6614 §2.5, RFC 5176 §3.5);
//! the proxy does not relay dynamic authorization to the NAS.
//!
//! **Identifier space.** RFC 6613 §2.6 / §2.6.5 give one connection a single
//! 256-value Identifier space, with one Identifier reserved for the watchdog
//! and no more than 256 requests outstanding. The link tracks the Identifiers
//! of the requests it has written on the current connection
//! ([`RadsecLinkHandle::send`] records them, a frame coming back with that
//! Identifier releases it, a reconnect clears them) and the Status-Server
//! probe takes its Identifier from the ones that are free
//! ([`RadsecLinkHandle::free_identifier`]), so a probe never shares an
//! Identifier with a forwarded request; `max_outstanding` is bounded to 255
//! for a RadSec home server at config load.
//! TODO(gap): the proxy forwards the NAS Identifier unchanged over the link
//! (as it does over the UDP socket) — there is no Identifier rewriting on the
//! upstream hop. Two NASes using the same Identifier at the same time
//! therefore collide on the one connection exactly as they would on the UDP
//! socket; correlation on our side is by Proxy-State, not Identifier, so the
//! collision only matters to a home server that deduplicates on
//! (connection, Identifier) and may discard the older of the two requests
//! (RFC 6613 §2.6.1 "Servers SHOULD still perform duplicate detection"). An
//! accepted gap for this release.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use radius_proto::attributes::{Attribute, AttributeType};
use radius_proto::auth::calculate_response_authenticator;
use radius_proto::{Code, ErrorCause, Packet, PacketError, calculate_message_authenticator};
use rand::RngExt;
use rand::seq::IndexedRandom;
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
use crate::radsec_frame::{FrameError, RADIUS_MAX_LEN, RADSEC_SECRET, take_frame};
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
    /// A correctly framed frame that is not a RADIUS packet. RFC 6613 §2.6.4:
    /// the connection MUST be closed.
    #[error("malformed RADIUS packet on the connection: {0}")]
    Malformed(String),
    /// Building a reply (CoA-NAK / Disconnect-NAK) failed.
    #[error("packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("{0} timed out")]
    Timeout(&'static str),
}

/// Why [`RadsecLinkHandle::register_probe`] refused a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProbeRegistrationError {
    /// A probe with this Identifier is already waiting on this link
    /// (RFC 5997 §3: one Identifier, one outstanding probe).
    #[error("a Status-Server probe with Identifier {0} is already outstanding")]
    Duplicate(u8),
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
    /// How long an Identifier written on the connection counts as in flight
    /// when no frame with that Identifier comes back (a request the home
    /// server never answers). Keeps the free-Identifier pool for the watchdog
    /// from draining one unanswered request at a time; a reconnect clears
    /// the pool outright.
    pub identifier_ttl: Duration,
}

impl Default for LinkParams {
    fn default() -> Self {
        LinkParams {
            connect_timeout: Duration::from_secs(10),
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            stable_after: Duration::from_secs(10),
            identifier_ttl: Duration::from_secs(60),
        }
    }
}

/// Where probe replies go: Identifier → the waiting probe's sender, with a
/// token so a probe deregisters only its own registration.
type ProbeTable = DashMap<u8, (u64, mpsc::Sender<Packet>)>;

/// Identifiers of requests written on the current connection and not yet
/// answered, with the time they were written (RFC 6613 §2.6 / §2.6.5: one
/// Identifier space per connection).
type InFlight = DashMap<u8, Instant>;

/// Handle to a running link: send frames, register Status-Server probes, read
/// the connection state. Cheap to clone; the `HomeServer` holds one.
#[derive(Clone)]
pub struct RadsecLinkHandle {
    outbound: mpsc::Sender<Vec<u8>>,
    /// One pending reset at most; the task drains it on every (re)connect.
    reset: mpsc::Sender<String>,
    connected: Arc<AtomicBool>,
    probes: Arc<ProbeTable>,
    in_flight: Arc<InFlight>,
    identifier_ttl: Duration,
    connections: Arc<AtomicU64>,
}

impl RadsecLinkHandle {
    /// Queue one RADIUS frame for the connection. Fails immediately when the
    /// link is down (nothing is queued) or the bounded outbound queue is full.
    /// The frame's Identifier (octet 1) is recorded as in flight on this
    /// connection until a frame with that Identifier comes back.
    pub fn send(&self, frame: Vec<u8>) -> Result<(), LinkSendError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkSendError::Down);
        }
        let identifier = frame.get(1).copied();
        self.outbound.try_send(frame).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => LinkSendError::Busy,
            mpsc::error::TrySendError::Closed(_) => LinkSendError::Down,
        })?;
        if let Some(identifier) = identifier {
            self.in_flight.insert(identifier, Instant::now());
        }
        Ok(())
    }

    /// Whether the TLS connection is currently established.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Register to receive frames without a Proxy-State that carry
    /// `identifier` — a Status-Server reply (RFC 5997). Register **before**
    /// sending the probe. The registration is removed when the receiver is
    /// dropped, and the receiver yields `None` when the link is lost. A
    /// second registration for an Identifier that already has a probe
    /// waiting is refused rather than stealing its replies.
    pub fn register_probe(&self, identifier: u8) -> Result<ProbeReceiver, ProbeRegistrationError> {
        static TOKEN: AtomicU64 = AtomicU64::new(1);
        let token = TOKEN.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(8);
        match self.probes.entry(identifier) {
            Entry::Occupied(_) => return Err(ProbeRegistrationError::Duplicate(identifier)),
            Entry::Vacant(slot) => {
                slot.insert((token, tx));
            }
        }
        Ok(ProbeReceiver {
            identifier,
            token,
            rx,
            probes: Arc::clone(&self.probes),
            in_flight: Arc::clone(&self.in_flight),
        })
    }

    /// An Identifier not in flight on the current connection and not held by
    /// a waiting probe, chosen at random among the free ones; `None` when all
    /// 256 are taken (RFC 6613 §2.6: one Identifier per connection is
    /// reserved for the watchdog, so the probe never shares one with a
    /// forwarded request). An Identifier unanswered for longer than
    /// [`LinkParams::identifier_ttl`] counts as free again.
    pub fn free_identifier(&self) -> Option<u8> {
        let now = Instant::now();
        let free: Vec<u8> = (0..=u8::MAX)
            .filter(|id| !self.identifier_busy(*id, now))
            .collect();
        free.choose(&mut rand::rng()).copied()
    }

    fn identifier_busy(&self, identifier: u8, now: Instant) -> bool {
        if self.probes.contains_key(&identifier) {
            return true;
        }
        self.in_flight
            .get(&identifier)
            .is_some_and(|sent| now.duration_since(*sent) < self.identifier_ttl)
    }

    /// Close the current connection and reconnect with backoff, because the
    /// peer broke the protocol on it (RFC 6613 §2.6.4: failed Response
    /// Authenticator or Message-Authenticator) or the watchdog gave up on it
    /// (RFC 3539 §3.4). A no-op while the link is down; `reason` goes into
    /// the "RadSec link lost" log line.
    pub fn reset(&self, reason: &str) {
        if !self.connected.load(Ordering::Acquire) {
            return;
        }
        // Full ⇒ a reset is already pending for this connection.
        let _ = self.reset.try_send(reason.to_string());
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
            .field("in_flight", &self.in_flight.len())
            .finish()
    }
}

/// The receiving end of [`RadsecLinkHandle::register_probe`].
pub struct ProbeReceiver {
    identifier: u8,
    token: u64,
    rx: mpsc::Receiver<Packet>,
    probes: Arc<ProbeTable>,
    in_flight: Arc<InFlight>,
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
        if self
            .probes
            .remove_if(&self.identifier, |_, (token, _)| *token == self.token)
            .is_some()
        {
            // The probe owned this Identifier (it was free when chosen); an
            // unanswered probe must not keep it busy until the TTL.
            self.in_flight.remove(&self.identifier);
        }
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
    let (reset_tx, reset_rx) = mpsc::channel(1);
    let handle = RadsecLinkHandle {
        outbound: outbound_tx,
        reset: reset_tx,
        connected: Arc::new(AtomicBool::new(false)),
        probes: Arc::new(DashMap::new()),
        in_flight: Arc::new(DashMap::new()),
        identifier_ttl: params.identifier_ttl,
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
        in_flight: Arc::clone(&handle.in_flight),
        connections: Arc::clone(&handle.connections),
        outbound: outbound_rx,
        reset: reset_rx,
    };
    tokio::spawn(link.run());

    Ok(handle)
}

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;
type TlsWriteHalf = tokio::io::WriteHalf<TlsStream>;

/// How a connection ended.
enum LinkEnd {
    /// The home server closed the connection (clean EOF).
    Eof,
    /// [`RadsecLinkHandle::reset`] asked for the connection to be dropped.
    Reset(String),
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
    in_flight: Arc<InFlight>,
    connections: Arc<AtomicU64>,
    outbound: mpsc::Receiver<Vec<u8>>,
    reset: mpsc::Receiver<String>,
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
                    // A fresh connection starts clean: nothing queued during
                    // the backoff rides it (the retry manager owns resends),
                    // no reset aimed at the old connection, and an empty
                    // Identifier space (RFC 6613 §2.6: per connection).
                    self.drain_outbound();
                    while self.reset.try_recv().is_ok() {}
                    self.in_flight.clear();
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
                    let reason = match end {
                        Ok(LinkEnd::HandleDropped) => {
                            debug!(server = %self.name, "RadSec link handle dropped; link task ending");
                            return;
                        }
                        Ok(LinkEnd::Eof) => "closed by peer".to_string(),
                        Ok(LinkEnd::Reset(reason)) => reason,
                        Err(e) => e.to_string(),
                    };
                    info!(
                        server = %self.name,
                        address = %self.address,
                        reason = %reason,
                        dropped_frames = dropped,
                        "RadSec link lost"
                    );
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
            // I/O. A bad Length (RFC 2865 §3) or an undecodable packet means
            // the stream is out of sync or the peer is broken: RFC 6613 §2.6.4
            // says the connection MUST be closed, so the error ends `serve`
            // and `run` reconnects.
            while let Some(frame) = take_frame(&mut buf)? {
                if let Some(end) = self.demux(frame, &mut wr).await? {
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
                        // RFC 6614 §3.4 item 1: the packet as is, delimited by
                        // its own Length, no extra framing.
                        wr.write_all(&frame).await?;
                        wr.flush().await?;
                    }
                    None => return Ok(LinkEnd::HandleDropped),
                },
                reason = self.reset.recv() => match reason {
                    Some(reason) => return Ok(LinkEnd::Reset(reason)),
                    None => return Ok(LinkEnd::HandleDropped),
                },
            }
        }
    }

    /// Route one inbound frame. Nothing is verified here (see the module
    /// docs); the handler and the probe do that. Returns `Ok(Some)` when the
    /// task must end (the `HomeServer` is gone) and `Err` when the connection
    /// must be closed (RFC 6613 §2.6.4: the frame is not a RADIUS packet).
    async fn demux(
        &self,
        frame: Vec<u8>,
        wr: &mut TlsWriteHalf,
    ) -> Result<Option<LinkEnd>, RadsecClientError> {
        let packet = match Packet::decode(&frame) {
            Ok(packet) => packet,
            Err(e) => {
                // Correctly framed but not a RADIUS packet (attribute Length
                // 0 or 1, attributes not filling the packet, ...): RFC 6613
                // §2.6.4 — the connection MUST be closed.
                warn!(
                    server = %self.name,
                    error = %e,
                    "RadSec link: malformed packet on the connection; closing it (RFC 6613 §2.6.4)"
                );
                return Err(RadsecClientError::Malformed(e.to_string()));
            }
        };

        // A CoA-Request / Disconnect-Request from the home server (RFC 6614
        // §2.5 permits every code on the one connection). The proxy does not
        // relay dynamic authorization to the NAS, so it answers as §2.5 says a
        // peer that does not handle them must: a NAK with Error-Cause 406
        // (Unsupported Extension, RFC 5176 §3.5), signed under "radsec".
        if matches!(packet.code, Code::CoaRequest | Code::DisconnectRequest) {
            debug!(
                server = %self.name,
                code = ?packet.code,
                identifier = packet.identifier,
                "RadSec link: answering unsupported server-originated request with a NAK (Error-Cause 406)"
            );
            let nak = unsupported_extension_nak(&packet)?;
            wr.write_all(&nak).await?;
            wr.flush().await?;
            return Ok(None);
        }

        // Whatever comes back under an Identifier answers the request written
        // under it: that Identifier is free again on this connection.
        self.in_flight.remove(&packet.identifier);

        // RFC 2865 §5.33: the last Proxy-State is the one we appended, so any
        // Proxy-State marks a proxied response. Its length and cache hit are
        // the handler's business (`CorrelationFailed` as over UDP).
        let has_proxy_state = packet
            .attributes
            .iter()
            .any(|a| a.attr_type == AttributeType::ProxyState as u8);
        if has_proxy_state {
            let Some(home_server) = self.home_server.upgrade() else {
                return Ok(Some(LinkEnd::HandleDropped));
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
            return Ok(None);
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
        Ok(None)
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

/// The CoA-NAK / Disconnect-NAK for a CoA-Request / Disconnect-Request the
/// proxy does not handle: same Identifier, `Error-Cause (101) = 406`
/// Unsupported Extension (RFC 6614 §2.5, RFC 5176 §3.5), a
/// Message-Authenticator and the Response Authenticator (RFC 5176 §3 →
/// RFC 2865 §3 formula) under the fixed hop secret `"radsec"`.
fn unsupported_extension_nak(request: &Packet) -> Result<Vec<u8>, RadsecClientError> {
    let code = match request.code {
        Code::CoaRequest => Code::CoaNak,
        _ => Code::DisconnectNak,
    };
    let mut nak = Packet::new(code, request.identifier, request.authenticator);
    nak.add_attribute(Attribute::integer(
        AttributeType::ErrorCause as u8,
        ErrorCause::UnsupportedExtension.as_u32(),
    )?);
    nak.add_attribute(Attribute::new(
        AttributeType::MessageAuthenticator as u8,
        vec![0u8; 16],
    )?);
    // RFC 3579 §3.2: a response's Message-Authenticator is computed with the
    // Request Authenticator in the header and the attribute zeroed.
    let mac = calculate_message_authenticator(&nak.encode()?, RADSEC_SECRET);
    if let Some(ma) = nak
        .attributes
        .iter_mut()
        .find(|a| a.attr_type == AttributeType::MessageAuthenticator as u8)
    {
        ma.value = mac.to_vec();
    }
    nak.authenticator =
        calculate_response_authenticator(&nak, &request.authenticator, RADSEC_SECRET);
    Ok(nak.encode()?)
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
    use radius_proto::auth::{
        encrypt_user_password, generate_request_authenticator, verify_response_authenticator,
    };

    const PROXY_STATE: [u8; 16] = [0x50; 16];

    /// Fast timings so reconnect tests finish in well under a second.
    fn fast() -> LinkParams {
        LinkParams {
            connect_timeout: Duration::from_secs(2),
            initial_backoff: Duration::from_millis(40),
            max_backoff: Duration::from_millis(160),
            stable_after: Duration::from_secs(10),
            identifier_ttl: Duration::from_secs(60),
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

        let mut probe = link.register_probe(0x5a).unwrap();
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
    async fn a_second_probe_registration_for_the_same_identifier_is_refused() {
        // RFC 5997 §3: one outstanding probe per Identifier. The second
        // registration must not steal the first one's replies, and its
        // failure must not deregister the first.
        let chain = gen_chain();
        let (addr, _registry, paths) =
            spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, _rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;

        let first = link.register_probe(7).unwrap();
        assert_eq!(
            link.register_probe(7).err(),
            Some(ProbeRegistrationError::Duplicate(7))
        );
        assert!(
            link.probes.get(&7).is_some(),
            "the refused registration must not remove the live one"
        );
        assert_eq!(
            link.free_identifier().map(|id| id == 7),
            Some(false),
            "an Identifier held by a waiting probe is not free"
        );
        drop(first);
        assert!(link.probes.get(&7).is_none());
        // Free again, and registrable again.
        let again = link.register_probe(7).unwrap();
        drop(again);
    }

    #[tokio::test]
    async fn probe_identifier_is_never_one_in_flight_on_the_connection() {
        // RFC 6613 §2.6 / §2.6.5: one Identifier space per connection, one
        // Identifier reserved for the watchdog. With 0..=254 written and
        // unanswered, the only free Identifier is 255 — every time. A reply
        // under an Identifier releases it; a reconnect releases them all; an
        // Identifier unanswered for longer than `identifier_ttl` is free again.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        // Answers Status-Server (no Proxy-State) and Access-Request 254 only.
        let addr = spawn_fake_tls_home(&chain, |_, request| match request.code {
            Code::StatusServer => {
                let mut reply = Packet::new(Code::AccessAccept, request.identifier, [0u8; 16]);
                reply.authenticator =
                    calculate_response_authenticator(&reply, &request.authenticator, RADSEC_SECRET);
                FakeAction::Reply(vec![reply.encode().unwrap()])
            }
            _ if request.identifier == 254 => FakeAction::Reply(vec![echo_accept(request)]),
            _ => FakeAction::Reply(vec![]),
        })
        .await;
        let hs = Arc::new(
            HomeServer::new(HomeServerConfig {
                name: Some("home-ids".to_string()),
                timeout: 2,
                max_outstanding: 255,
                ..HomeServerConfig::radsec(addr.to_string(), tls_block(&paths, "localhost"))
            })
            .unwrap(),
        );
        let (tx, mut rx) = mpsc::channel(4);
        let params = LinkParams {
            identifier_ttl: Duration::from_millis(400),
            ..fast()
        };
        let link = connected_link(&hs, tx, params).await;

        let pw = password();
        for id in 0..=253u8 {
            link.send(forwarded_access_request(id, &pw)).unwrap();
        }
        for _ in 0..32 {
            assert!(
                matches!(link.free_identifier(), Some(254) | Some(255)),
                "only 254 and 255 are free"
            );
        }
        link.send(forwarded_access_request(254, &pw)).unwrap();
        // 254 is answered: its Identifier is released when the reply is demuxed.
        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert_eq!(response.packet.identifier, 254);
        wait_for(
            || !link.in_flight.contains_key(&254),
            Duration::from_secs(2),
        )
        .await;
        for _ in 0..32 {
            assert!(matches!(link.free_identifier(), Some(254) | Some(255)));
        }

        // The probe takes a free Identifier and holds it while waiting.
        let probe_id = 255;
        let mut probe = link.register_probe(probe_id).unwrap();
        link.send(status_server(probe_id)).unwrap();
        assert_eq!(link.free_identifier(), Some(254), "255 is the probe's");
        let reply = time::timeout(Duration::from_secs(5), probe.recv())
            .await
            .expect("probe reply within 5 s")
            .expect("link up");
        assert_eq!(reply.identifier, probe_id);
        drop(probe);
        assert!(matches!(link.free_identifier(), Some(254) | Some(255)));

        // Unanswered requests expire from the in-flight set after the TTL ...
        time::sleep(Duration::from_millis(500)).await;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(link.free_identifier().unwrap());
        }
        assert!(
            seen.len() > 2,
            "after the TTL the whole space is free again: {seen:?}"
        );

        // ... and a reconnect clears it outright.
        for id in 0..=253u8 {
            link.send(forwarded_access_request(id, &pw)).unwrap();
        }
        assert!(link.in_flight.len() >= 250);
        link.reset("test");
        wait_for(
            || link.connections() == 2 && link.is_connected(),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(link.connections(), 2);
        assert!(
            link.in_flight.is_empty(),
            "a new connection starts with an empty Identifier space"
        );
    }

    #[tokio::test]
    async fn reset_drops_the_connection_and_the_link_reconnects() {
        let chain = gen_chain();
        let (addr, _registry, paths) =
            spawn_radsec_home(&chain, false, lenient_server_config(&[])).await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, _rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;
        assert_eq!(link.connections(), 1);

        // A probe waiting on the connection is told the link is gone.
        let mut probe = link.register_probe(1).unwrap();
        link.reset("test: peer fault");
        let got = time::timeout(Duration::from_secs(5), probe.recv())
            .await
            .expect("probe receiver resolves on reset");
        assert!(got.is_none());

        wait_for(
            || link.connections() == 2 && link.is_connected(),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(link.connections(), 2, "reset must reconnect exactly once");
        assert!(link.is_connected());

        // The new connection works, and a reset while down is a no-op (it
        // must not kill the connection that comes up next).
        let mut probe = link.register_probe(2).unwrap();
        link.send(status_server(2)).unwrap();
        let reply = time::timeout(Duration::from_secs(5), probe.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.identifier, 2);
        drop(probe);
        link.connected.store(false, Ordering::Release);
        link.reset("ignored while down");
        link.connected.store(true, Ordering::Release);
        time::sleep(Duration::from_millis(100)).await;
        assert_eq!(link.connections(), 2, "a reset while down must be dropped");
        assert!(link.is_connected());
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
        // another name (RFC 6614 §2.3 item 3: expected DNS name).
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

        let mut probe = link.register_probe(9).unwrap();
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

    /// An Access-Accept for `request` whose only Proxy-State is `proxy_state`
    /// (any length), Response Authenticator under `"radsec"`.
    fn accept_with_proxy_state(request: &Packet, proxy_state: &[u8]) -> Vec<u8> {
        let mut reply = Packet::new(Code::AccessAccept, request.identifier, [0u8; 16]);
        reply.add_attribute(
            Attribute::new(AttributeType::ProxyState as u8, proxy_state.to_vec()).unwrap(),
        );
        reply.authenticator =
            calculate_response_authenticator(&reply, &request.authenticator, RADSEC_SECRET);
        reply.encode().unwrap()
    }

    #[tokio::test]
    async fn unsolicited_frames_are_dropped_and_the_link_stays_up() {
        // Before the genuine echo the home server sends two frames nobody asked
        // for: an Access-Accept without Proxy-State under an Identifier no probe
        // is registered for, and a CoA-Request (RFC 6614 §2.5 permits it; the
        // proxy answers it with a CoA-NAK, see the NAK test). Neither reaches
        // the response channel, no probe table entry appears, and the
        // connection is kept.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let addr = spawn_fake_tls_home(&chain, |_, request| {
            if request.code != Code::AccessRequest {
                return FakeAction::Reply(vec![]); // our CoA-NAK: nothing to say
            }
            let mut stray = Packet::new(
                Code::AccessAccept,
                request.identifier.wrapping_add(100),
                [0u8; 16],
            );
            stray.authenticator =
                calculate_response_authenticator(&stray, &request.authenticator, RADSEC_SECRET);
            let mut coa = Packet::new(Code::CoaRequest, 200, generate_request_authenticator());
            coa.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
            FakeAction::Reply(vec![
                stray.encode().unwrap(),
                coa.encode().unwrap(),
                echo_accept(request),
            ])
        })
        .await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;

        link.send(forwarded_access_request(5, &password())).unwrap();
        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert_eq!(response.packet.code, Code::AccessAccept);
        assert_eq!(response.packet.identifier, 5);
        assert!(
            response
                .packet
                .find_attribute(AttributeType::ProxyState as u8)
                .is_some(),
            "only the proxied response is delivered"
        );

        time::sleep(Duration::from_millis(50)).await;
        assert!(
            rx.try_recv().is_err(),
            "stray frames must not be delivered as proxied responses"
        );
        assert!(link.probes.is_empty(), "stray frames register nothing");
        assert!(link.is_connected());
        assert_eq!(
            link.connections(),
            1,
            "unsolicited frames do not drop the connection"
        );
    }

    #[tokio::test]
    async fn a_frame_with_a_malformed_proxy_state_is_routed_to_the_handler_not_dropped() {
        // The link routes on the *presence* of Proxy-State; a 4-octet value is
        // the handler's `CorrelationFailed` (tested in `handler.rs`), delivered
        // with the link's own home server attached, and no reason to drop the
        // connection.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let addr = spawn_fake_tls_home(&chain, |_, request| {
            FakeAction::Reply(vec![accept_with_proxy_state(request, &[0x11; 4])])
        })
        .await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;

        link.send(forwarded_access_request(6, &password())).unwrap();
        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert!(Arc::ptr_eq(&response.home_server, &hs));
        assert_eq!(
            response
                .packet
                .find_attribute(AttributeType::ProxyState as u8)
                .unwrap()
                .value
                .len(),
            4
        );
        assert!(link.is_connected());
        assert_eq!(link.connections(), 1);
    }

    #[tokio::test]
    async fn a_bad_length_on_the_stream_closes_the_connection_and_the_link_reconnects() {
        // RFC 2865 §3 / RFC 6613 §2.6.4: a Length outside 20..=4096 means the
        // stream has lost synchronisation and the connection MUST be closed. Connection 1 answers with Length 19,
        // connection 2 with Length 4097; each time the link drops the
        // connection without delivering anything and reconnects. Connection 3
        // behaves and its reply is delivered.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let addr = spawn_fake_tls_home(&chain, |connection, request| {
            let mut frame = echo_accept(request);
            match connection {
                1 => {
                    frame[2..4].copy_from_slice(&19u16.to_be_bytes());
                }
                2 => {
                    frame[2..4].copy_from_slice(&4097u16.to_be_bytes());
                }
                _ => {}
            }
            FakeAction::Reply(vec![frame])
        })
        .await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;
        assert_eq!(link.connections(), 1);

        link.send(forwarded_access_request(1, &password())).unwrap();
        wait_for(
            || link.connections() == 2 && link.is_connected(),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(link.connections(), 2, "Length 19 must drop the connection");

        link.send(forwarded_access_request(2, &password())).unwrap();
        wait_for(
            || link.connections() == 3 && link.is_connected(),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(
            link.connections(),
            3,
            "Length 4097 must drop the connection"
        );
        assert!(
            rx.try_recv().is_err(),
            "nothing from a desynchronised stream may be delivered"
        );

        link.send(forwarded_access_request(3, &password())).unwrap();
        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert_eq!(response.packet.identifier, 3);
        assert!(Arc::ptr_eq(&response.home_server, &hs));
    }

    #[tokio::test]
    async fn an_undecodable_but_well_framed_frame_closes_the_connection() {
        // Length is a valid 24, but the trailing attribute header claims 16
        // octets and carries 2: `Packet::decode` fails. RFC 6613 §2.6.4: the
        // connection MUST be closed — nothing from it is delivered (not even
        // the well-formed echo the peer sends right after), the link
        // reconnects, and the next request is answered on connection 2.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let addr = spawn_fake_tls_home(&chain, |connection, request| {
            if connection == 1 {
                let mut junk = Packet::new(Code::AccessAccept, request.identifier, [0u8; 16])
                    .encode()
                    .unwrap();
                junk.extend_from_slice(&[AttributeType::ProxyState as u8, 16, 0xaa, 0xbb]);
                junk[2..4].copy_from_slice(&24u16.to_be_bytes());
                assert_eq!(junk.len(), 24);
                FakeAction::Reply(vec![junk, echo_accept(request)])
            } else {
                FakeAction::Reply(vec![echo_accept(request)])
            }
        })
        .await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;
        assert_eq!(link.connections(), 1);

        link.send(forwarded_access_request(7, &password())).unwrap();
        wait_for(
            || link.connections() == 2 && link.is_connected(),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(
            link.connections(),
            2,
            "a malformed packet must close the connection (RFC 6613 §2.6.4)"
        );
        assert!(
            rx.try_recv().is_err(),
            "nothing read after the malformed packet may be delivered"
        );

        link.send(forwarded_access_request(8, &password())).unwrap();
        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert_eq!(response.packet.identifier, 8);
        assert_eq!(link.connections(), 2);
    }

    #[tokio::test]
    async fn coa_and_disconnect_requests_from_the_home_server_get_a_nak_with_error_cause_406() {
        // RFC 6614 §2.5 / RFC 5176 §3.5: a peer that does not handle CoA /
        // Disconnect answers with a NAK carrying Error-Cause 406 (Unsupported
        // Extension). The fake home server records every frame it receives;
        // the NAKs must be signed under "radsec" against the request's
        // authenticator, carry its Identifier, and not drop the connection.
        let chain = gen_chain();
        let paths = chain.write_to_tempdir();
        let coa_auth = generate_request_authenticator();
        let disconnect_auth = generate_request_authenticator();
        let received: Arc<std::sync::Mutex<Vec<Packet>>> = Arc::default();
        let seen = Arc::clone(&received);
        let addr = spawn_fake_tls_home(&chain, move |_, request| {
            seen.lock().unwrap().push(request.clone());
            if request.code != Code::AccessRequest {
                return FakeAction::Reply(vec![]);
            }
            let mut coa = Packet::new(Code::CoaRequest, 200, coa_auth);
            coa.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
            let mut disc = Packet::new(Code::DisconnectRequest, 201, disconnect_auth);
            disc.add_attribute(
                Attribute::string(AttributeType::AcctSessionId as u8, "s-1").unwrap(),
            );
            FakeAction::Reply(vec![
                coa.encode().unwrap(),
                disc.encode().unwrap(),
                echo_accept(request),
            ])
        })
        .await;
        let hs = home_server(addr, tls_block(&paths, "localhost"));
        let (tx, mut rx) = mpsc::channel(4);
        let link = connected_link(&hs, tx, fast()).await;

        link.send(forwarded_access_request(5, &password())).unwrap();
        let response = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("response within 5 s")
            .expect("channel open");
        assert_eq!(response.packet.identifier, 5);

        wait_for(
            || received.lock().unwrap().len() >= 3,
            Duration::from_secs(5),
        )
        .await;
        let frames = received.lock().unwrap().clone();
        let nak = |code: Code| {
            frames
                .iter()
                .find(|p| p.code == code)
                .unwrap_or_else(|| panic!("home server must receive a {code:?}"))
                .clone()
        };
        for (nak, request_auth, identifier) in [
            (nak(Code::CoaNak), coa_auth, 200u8),
            (nak(Code::DisconnectNak), disconnect_auth, 201u8),
        ] {
            assert_eq!(nak.identifier, identifier);
            let cause = nak
                .find_attribute(AttributeType::ErrorCause as u8)
                .expect("Error-Cause present");
            assert_eq!(
                cause.value,
                406u32.to_be_bytes().to_vec(),
                "Unsupported Extension"
            );
            assert!(
                verify_response_authenticator(&nak, &request_auth, RADSEC_SECRET),
                "NAK Response Authenticator under \"radsec\""
            );
            assert!(
                matches!(
                    crate::server::check_message_authenticator(&nak, &request_auth, RADSEC_SECRET),
                    Ok(crate::server::MessageAuthenticatorCheck::Valid)
                ),
                "NAK Message-Authenticator under \"radsec\""
            );
        }
        assert!(link.is_connected());
        assert_eq!(link.connections(), 1, "a NAK keeps the connection");
        assert!(
            link.in_flight.get(&200).is_none() && link.in_flight.get(&201).is_none(),
            "a NAK is a response, not a request in flight"
        );
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

            let mut probe = link.register_probe(3).unwrap();
            link.send(status_server(3)).unwrap();
            let reply = time::timeout(Duration::from_secs(5), probe.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.code, Code::AccessAccept);
        }
    }
}
