//! Throwaway PKI and RadSec peers for tests (`cfg(all(test, feature = "tls"))`).
//!
//! One CA, a server certificate, a client certificate and a CRL, generated
//! with `rcgen` per test so nothing is checked in. The inbound listener tests
//! (`radsec`), the client verifier tests, the outbound link tests
//! (`proxy::radsec_client`), the health probe tests and the server end-to-end
//! test all draw from here, so the same material is exercised from both ends.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use radius_proto::Packet;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::TLS13;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::coa::NasRegistry;
use crate::config::{Config, RadSecConfig};
use crate::radsec_frame::{RADIUS_MAX_LEN, take_frame};
use crate::server::{ServerConfig, SimpleAuthHandler};

/// A throwaway CA plus a CA-signed server cert and client cert.
pub(crate) struct TestChain {
    pub ca_pem: String,
    pub ca_der: CertificateDer<'static>,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub client_cert_der: CertificateDer<'static>,
    pub client_key_der: PrivateKeyDer<'static>,
    /// DER CRL from the test CA. [`gen_chain`] revokes `client_cert_der`;
    /// [`gen_chain_with`] with `revoke_server` revokes the server certificate
    /// instead (for outbound-verifier tests).
    pub crl_der: Vec<u8>,
}

/// The default chain: server cert for `localhost`, CRL revoking the client.
pub(crate) fn gen_chain() -> TestChain {
    gen_chain_with(&["localhost"], false)
}

/// A chain whose server certificate carries `server_sans` and whose CRL
/// revokes either the client (`revoke_server == false`) or the server
/// certificate (`revoke_server == true`).
pub(crate) fn gen_chain_with(server_sans: &[&str], revoke_server: bool) -> TestChain {
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
        KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams, SerialNumber, date_time_ymd,
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "USG Test NAS CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(
        server_sans
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let server_serial = SerialNumber::from(vec![0x53, 0x52, 0x56, 0x01]);
    server_params.serial_number = Some(server_serial.clone());
    let server = server_params.signed_by(&server_key, &issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec!["nas-1.usg.test".to_string()]).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "switch-eth0");
    let client_serial = SerialNumber::from(vec![0x4e, 0x41, 0x53, 0x01]);
    client_params.serial_number = Some(client_serial.clone());
    let client = client_params.signed_by(&client_key, &issuer).unwrap();

    // A CRL from the same CA that revokes one of the two end-entity certs.
    let revoked_serial = if revoke_server {
        server_serial
    } else {
        client_serial
    };
    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2099, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: revoked_serial,
            revocation_time: date_time_ymd(2026, 1, 2),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .unwrap();

    TestChain {
        ca_pem: ca.pem(),
        ca_der: ca.der().clone(),
        server_cert_pem: server.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client.pem(),
        client_key_pem: client_key.serialize_pem(),
        client_cert_der: client.der().clone(),
        client_key_der: PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
        crl_der: crl.der().as_ref().to_vec(),
    }
}

/// The chain written to disk, as the config loaders read it. Dropping this
/// deletes the files.
pub(crate) struct TestPaths {
    pub _dir: tempfile::TempDir,
    pub ca: String,
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
    pub crl: String,
}

impl TestChain {
    /// Write every artefact to a fresh temp dir.
    pub(crate) fn write_to_tempdir(&self) -> TestPaths {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, data: &[u8]| {
            let path = dir.path().join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(data).unwrap();
            path.to_str().unwrap().to_string()
        };
        TestPaths {
            ca: write("ca.pem", self.ca_pem.as_bytes()),
            server_cert: write("server.pem", self.server_cert_pem.as_bytes()),
            server_key: write("server.key", self.server_key_pem.as_bytes()),
            client_cert: write("client.pem", self.client_cert_pem.as_bytes()),
            client_key: write("client.key", self.client_key_pem.as_bytes()),
            crl: write("ca.crl", &self.crl_der),
            _dir: dir,
        }
    }
}

/// A `ServerConfig` with lenient validation (so a bare Status-Server is
/// accepted without a Message-Authenticator) and the given PAP users.
pub(crate) fn lenient_server_config(users: &[(&str, &str)]) -> Arc<ServerConfig> {
    let config = Config {
        strict_rfc_compliance: false,
        ..Config::default()
    };
    let mut handler = SimpleAuthHandler::new();
    for (user, password) in users {
        handler.add_user(*user, *password);
    }
    Arc::new(ServerConfig::from_config(config, Arc::new(handler)).unwrap())
}

/// Start the real RadSec listener (`radsec::serve`) on an ephemeral loopback
/// port with `chain`'s server certificate, verifying client certificates
/// against `chain`'s CA — and, with `check_crl`, against its CRL. Returns the
/// bound address, the CoA registry and the paths (kept alive by the caller).
pub(crate) async fn spawn_radsec_home(
    chain: &TestChain,
    check_crl: bool,
    server_config: Arc<ServerConfig>,
) -> (SocketAddr, Arc<NasRegistry>, TestPaths) {
    let paths = chain.write_to_tempdir();
    let revocation = check_crl.then(|| crate::config::RevocationConfig {
        crl: crate::config::CrlSettings {
            static_files: vec![paths.crl.clone()],
            fetch: false,
            ..Default::default()
        },
        ..Default::default()
    });
    let cfg = RadSecConfig {
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0,
        cert_path: paths.server_cert.clone(),
        key_path: paths.server_key.clone(),
        client_ca_path: paths.ca.clone(),
        revocation,
    };

    let tls_config = crate::radsec::build_server_config(&cfg).unwrap();
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let registry = NasRegistry::new();
    let reg = Arc::clone(&registry);
    tokio::spawn(async move {
        let _ = crate::radsec::serve(listener, acceptor, server_config, reg).await;
    });
    (addr, registry, paths)
}

/// What a scripted fake home server does with one inbound frame.
pub(crate) enum FakeAction {
    /// Write these frames back, in order, and keep the connection.
    Reply(Vec<Vec<u8>>),
    /// Drop the connection without replying.
    Close,
}

/// A scripted RadSec home server: mTLS acceptor over `chain` (client
/// certificates verified against the CA) using the given provider, one task
/// per connection, each decoded frame handed to `on_frame(connection_index,
/// &packet)`. Undecodable frames close the connection. Connections are
/// numbered from 1 in accept order.
pub(crate) async fn spawn_fake_tls_home_with_provider(
    chain: &TestChain,
    provider: rustls::crypto::CryptoProvider,
    on_frame: impl Fn(u64, &Packet) -> FakeAction + Send + Sync + 'static,
) -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::server::WebPkiClientVerifier;

    let provider = Arc::new(provider);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(chain.ca_der.clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(chain.server_cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(chain.server_key_pem.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let on_frame = Arc::new(on_frame);
    let connections = Arc::new(AtomicU64::new(0));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let n = connections.fetch_add(1, Ordering::SeqCst) + 1;
            let acceptor = acceptor.clone();
            let on_frame = Arc::clone(&on_frame);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf: Vec<u8> = Vec::with_capacity(RADIUS_MAX_LEN);
                loop {
                    while let Ok(Some(frame)) = take_frame(&mut buf) {
                        let Ok(packet) = Packet::decode(&frame) else {
                            return;
                        };
                        match on_frame(n, &packet) {
                            FakeAction::Reply(frames) => {
                                for f in frames {
                                    if tls.write_all(&f).await.is_err() {
                                        return;
                                    }
                                }
                                if tls.flush().await.is_err() {
                                    return;
                                }
                            }
                            FakeAction::Close => return,
                        }
                    }
                    match tls.read_buf(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    addr
}

/// A RadSec home server that completes the mTLS handshake and then never
/// reads again, keeping the TCP connection open (no FIN, no RST): a wedged
/// peer as the link's writer sees it. Its sockets get a small receive buffer
/// so the kernel stops accepting our bytes after a handful of frames rather
/// than after megabytes.
pub(crate) async fn spawn_fake_tls_home_that_never_reads(chain: &TestChain) -> SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::server::WebPkiClientVerifier;
    use tokio::net::TcpSocket;

    let provider = Arc::new(usg_fips_tls::provider::fips_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(chain.ca_der.clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(chain.server_cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(chain.server_key_pem.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Accepted sockets inherit the listener's receive buffer size.
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(16).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Hold the connection open and never read from it.
                let _deaf = tls;
                std::future::pending::<()>().await;
            });
        }
    });
    addr
}

/// [`spawn_fake_tls_home_with_provider`] with the project's ML-KEM-1024-only
/// FIPS provider — what a conformant usg-radius / FreeRADIUS peer offers.
pub(crate) async fn spawn_fake_tls_home(
    chain: &TestChain,
    on_frame: impl Fn(u64, &Packet) -> FakeAction + Send + Sync + 'static,
) -> SocketAddr {
    spawn_fake_tls_home_with_provider(chain, usg_fips_tls::provider::fips_provider(), on_frame)
        .await
}
