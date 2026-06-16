//! RadSec listener: RADIUS over mutually-authenticated TLS 1.3 (RFC 6614).
//!
//! This is the FIPS-posture transport from the authenticator SERVER-CONTRACT
//! (G-1). Compared to UDP RADIUS it replaces the spoofable shared-secret +
//! source-IP trust with a TLS layer:
//!
//! - **TLS 1.3 only, ML-KEM-1024-only key exchange** (FIPS 203), via the shared
//!   [`usg_fips_tls`] provider. The negotiated parameters are re-checked against
//!   the allow-list after the handshake and the connection is dropped if anything
//!   falls outside it (fail closed).
//! - **Mutual TLS:** the NAS presents a client certificate verified against the
//!   configured CA; that cert identity is the server's authenticated notion of
//!   "which switch".
//! - Inside the tunnel the bytes are **standard RADIUS**, delimited by the RADIUS
//!   `Length` header field, processed by the same pipeline as UDP. Per RFC 6614
//!   §2.3 the RADIUS Authenticator/Message-Authenticator math uses the fixed
//!   shared secret `"radsec"`; the real transport security is TLS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rustls::version::TLS13;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::RadSecConfig;
use crate::server::{RadiusServer, ServerConfig};

/// RFC 6614 §2.3: RadSec uses a fixed shared secret of the ASCII string
/// `"radsec"` for the RADIUS Authenticator / Message-Authenticator computations.
const RADSEC_SECRET: &[u8] = b"radsec";

/// A RADIUS packet header is 20 octets; the `Length` field is octets 2..4.
const RADIUS_HEADER_LEN: usize = 20;

/// RFC 2865 §3: the RADIUS `Length` field ranges 20..=4096.
const RADIUS_MIN_LEN: usize = RADIUS_HEADER_LEN;
const RADIUS_MAX_LEN: usize = 4096;

/// Errors from the RadSec listener.
#[derive(Debug, thiserror::Error)]
pub enum RadSecError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate/key PEM error: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("client CA bundle error: {0}")]
    RootStore(#[from] crate::tls_certs::RootStoreError),
    #[error("invalid listen address {0:?}: {1}")]
    BadListenAddr(String, std::net::AddrParseError),
    #[error(
        "negotiated TLS parameters outside the FIPS/PQ allow-list: {0} \
         (RadSec requires TLS 1.3 + AES-256-GCM-SHA384 + ML-KEM-1024)"
    )]
    DisallowedParameters(usg_fips_tls::error::FipsError),
    #[error("peer presented no client certificate (mTLS required)")]
    NoClientCert,
    #[error("invalid RADIUS Length field: {0} (must be {RADIUS_MIN_LEN}..={RADIUS_MAX_LEN})")]
    BadRadiusLength(usize),
}

/// Build the rustls `ServerConfig` for the RadSec listener: the ML-KEM-1024-only
/// FIPS provider, TLS 1.3 only, server cert, and a required client-cert verifier
/// (mTLS) against the configured NAS CA bundle.
pub fn build_server_config(cfg: &RadSecConfig) -> Result<Arc<rustls::ServerConfig>, RadSecError> {
    let provider = usg_fips_tls::provider::fips_provider_arc();

    let certs = crate::tls_certs::load_cert_chain(&cfg.cert_path)?;
    let key = crate::tls_certs::load_private_key(&cfg.key_path)?;

    // RadSec is always mutually authenticated: require + verify a NAS client cert.
    let roots = crate::tls_certs::load_root_store(&cfg.client_ca_path)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|e| rustls::Error::General(e.to_string()))?;

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Run the RadSec listener until the process is shut down. Binds TCP and accepts
/// one long-lived TLS connection per NAS, dispatching each framed RADIUS packet
/// into the shared request pipeline.
pub async fn run(cfg: RadSecConfig, server_config: Arc<ServerConfig>) -> Result<(), RadSecError> {
    let tls_config = build_server_config(&cfg)?;
    let acceptor = TlsAcceptor::from(tls_config);

    let ip: IpAddr = cfg
        .listen_address
        .parse()
        .map_err(|e| RadSecError::BadListenAddr(cfg.listen_address.clone(), e))?;
    let bind_addr = SocketAddr::new(ip, cfg.listen_port);

    let listener = TcpListener::bind(bind_addr).await?;
    info!("RadSec listening on {bind_addr} (RFC 6614, TLS 1.3, ML-KEM-1024-only, mTLS)");

    serve(listener, acceptor, server_config).await
}

/// Accept loop over an already-bound listener. Split out from [`run`] so tests
/// can drive it on an ephemeral port with an injected acceptor.
async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    server_config: Arc<ServerConfig>,
) -> Result<(), RadSecError> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let server_config = Arc::clone(&server_config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, acceptor, server_config).await {
                debug!("RadSec connection from {peer} ended: {e}");
            }
        });
    }
}

/// Terminate TLS for one NAS connection, enforce the FIPS/PQ allow-list, then
/// serve framed RADIUS packets over the tunnel until it closes.
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    server_config: Arc<ServerConfig>,
) -> Result<(), RadSecError> {
    let mut tls = acceptor.accept(stream).await?;

    // Fail closed on anything outside the allow-list, and require the client cert.
    {
        let (_, conn) = tls.get_ref();
        usg_fips_tls::params::enforce_fips_parameters(
            conn.protocol_version(),
            conn.negotiated_cipher_suite().map(|s| s.suite()),
            conn.negotiated_key_exchange_group().map(|g| g.name()),
        )
        .map_err(RadSecError::DisallowedParameters)?;

        if conn.peer_certificates().is_none_or(<[_]>::is_empty) {
            return Err(RadSecError::NoClientCert);
        }
    }

    let peer_ip = peer.ip();
    debug!("RadSec connection established from {peer} (mTLS verified)");

    // NOTE: unlike the UDP path, RadSec does not yet apply per-source rate
    // limiting — admission is gated by the mTLS handshake (a valid NAS client
    // cert) and its cost. Per-connection / per-identity rate limiting is a
    // follow-up if a trusted NAS is ever a flooding concern.

    loop {
        // Read the fixed RADIUS header, then the remainder per the Length field.
        let mut header = [0u8; RADIUS_HEADER_LEN];
        match tls.read_exact(&mut header).await {
            Ok(_) => {}
            // Clean connection close between packets.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if !(RADIUS_MIN_LEN..=RADIUS_MAX_LEN).contains(&length) {
            return Err(RadSecError::BadRadiusLength(length));
        }

        let mut packet = vec![0u8; length];
        packet[..RADIUS_HEADER_LEN].copy_from_slice(&header);
        tls.read_exact(&mut packet[RADIUS_HEADER_LEN..]).await?;

        match RadiusServer::process_request(&packet, peer_ip, RADSEC_SECRET, &server_config).await {
            Ok(Some(response)) => {
                tls.write_all(&response).await?;
                tls.flush().await?;
            }
            // No reply warranted (e.g. unsupported packet type); keep the tunnel open.
            Ok(None) => {}
            // A bad request drops this packet but not the connection — a transient
            // malformed frame from one NAS shouldn't tear down its session.
            Err(e) => warn!("RadSec request from {peer} rejected: {e}"),
        }
    }

    Ok(())
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
    use std::io::Write as _;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};

    use crate::config::Config;
    use crate::server::{ServerConfig, SimpleAuthHandler};

    /// A throwaway CA plus a CA-signed server cert and NAS client cert.
    struct TestChain {
        ca_pem: String,
        ca_der: CertificateDer<'static>,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_der: CertificateDer<'static>,
        client_key_der: PrivateKeyDer<'static>,
    }

    fn gen_chain() -> TestChain {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "USG Test NAS CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(vec!["nas-1.usg.test".to_string()]).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "switch-eth0");
        let client = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();

        TestChain {
            ca_pem: ca.pem(),
            ca_der: ca.der().clone(),
            server_cert_pem: server.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_der: client.der().clone(),
            client_key_der: PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
        }
    }

    /// Build a minimal radius `ServerConfig` (lenient validation so a bare
    /// Status-Server is accepted without a Message-Authenticator).
    fn test_server_config() -> Arc<ServerConfig> {
        let config = Config {
            strict_rfc_compliance: false,
            ..Config::default()
        };
        let handler = Arc::new(SimpleAuthHandler::new());
        Arc::new(ServerConfig::from_config(config, handler).unwrap())
    }

    /// Write the server cert/key + CA to temp files and start `serve` on an
    /// ephemeral loopback port. Returns the bound address (and keeps the temp
    /// dir alive for the test's duration).
    async fn start_listener(chain: &TestChain) -> (SocketAddr, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, data: &str| {
            let path = dir.path().join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(data.as_bytes()).unwrap();
            path.to_str().unwrap().to_string()
        };
        let cfg = RadSecConfig {
            listen_address: "127.0.0.1".to_string(),
            listen_port: 0,
            cert_path: write("server.pem", &chain.server_cert_pem),
            key_path: write("server.key", &chain.server_key_pem),
            client_ca_path: write("ca.pem", &chain.ca_pem),
        };

        let tls_config = build_server_config(&cfg).unwrap();
        let acceptor = TlsAcceptor::from(tls_config);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_config = test_server_config();
        tokio::spawn(async move {
            let _ = serve(listener, acceptor, server_config).await;
        });
        (addr, dir)
    }

    /// Client config pinned to the given kx-group provider, with the NAS client
    /// cert for mTLS and the test CA as the trust anchor.
    fn client_config(chain: &TestChain, provider: rustls::crypto::CryptoProvider) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(chain.ca_der.clone()).unwrap();
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![chain.client_cert_der.clone()],
                chain.client_key_der.clone_key(),
            )
            .unwrap()
    }

    /// A 20-octet Status-Server request (RFC 5997): code 12, no attributes.
    fn status_server_packet(id: u8) -> Vec<u8> {
        let mut p = vec![0u8; RADIUS_HEADER_LEN];
        p[0] = 12; // Status-Server
        p[1] = id;
        p[2..4].copy_from_slice(&(RADIUS_HEADER_LEN as u16).to_be_bytes());
        p
    }

    #[tokio::test]
    async fn mlkem_handshake_round_trip() {
        let chain = gen_chain();
        let (addr, _dir) = start_listener(&chain).await;

        // Client offers the same ML-KEM-1024-only provider the server requires.
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(
            &chain,
            usg_fips_tls::provider::fips_provider(),
        )));
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .expect("ML-KEM-1024 mTLS handshake should succeed");

        // Confirm the negotiated group really is ML-KEM-1024.
        let group = tls.get_ref().1.negotiated_key_exchange_group().unwrap();
        assert_eq!(group.name(), rustls::NamedGroup::MLKEM1024);

        // Send Status-Server, expect an Access-Accept (code 2) back over the tunnel.
        tls.write_all(&status_server_packet(7)).await.unwrap();
        tls.flush().await.unwrap();

        let mut resp = [0u8; RADIUS_HEADER_LEN];
        tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 2, "expected Access-Accept");
        assert_eq!(resp[1], 7, "response id must echo the request id");
    }

    #[tokio::test]
    async fn non_mlkem_client_fails_closed() {
        let chain = gen_chain();
        let (addr, _dir) = start_listener(&chain).await;

        // Client offering only classical X25519 — no group in common with the
        // ML-KEM-1024-only server, so the handshake must fail closed.
        let x25519_only = rustls::crypto::CryptoProvider {
            kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(client_config(&chain, x25519_only)));
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await;
        assert!(
            result.is_err(),
            "a non-ML-KEM client must not complete the RadSec handshake"
        );
    }
}
