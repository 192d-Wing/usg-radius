//! Server-certificate verifier selection for the outbound RadSec link
//! (proxy → home server, RFC 6614).
//!
//! The mirror image of [`crate::client_verifier`]: the home server's
//! certificate is verified against a CA bundle with rustls's
//! `WebPkiServerVerifier` (chain, validity, and the configured `server_name`,
//! as RFC 6614 §2.3 requires of a RadSec client), and when the home server's
//! `tls.revocation` block is configured that verifier is followed by
//! `radius_proto::revocation::RevocationCheckingVerifier::check_revocation`,
//! so static CRLs, CRL Distribution Points, OCSP and the fail-open/closed
//! policy behave exactly as they do for `eap.tls.revocation` and
//! `radsec.revocation`. Without the block the plain WebPKI verifier is used
//! unchanged.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
#[cfg(feature = "revocation")]
use rustls::pki_types::pem::PemObject;

use crate::config::RevocationConfig;

/// The verifier selected for a RadSec home server.
pub enum ServerVerifier {
    /// Chain, validity and name validation against the CA bundle only.
    WebPki(Arc<WebPkiServerVerifier>),
    /// WebPKI validation plus CRL/OCSP revocation checking.
    #[cfg(feature = "revocation")]
    RevocationChecking(Arc<RevocationCheckingServerVerifier>),
}

impl ServerVerifier {
    /// Whether the home server's certificate is checked for revocation.
    pub fn checks_revocation(&self) -> bool {
        match self {
            Self::WebPki(_) => false,
            #[cfg(feature = "revocation")]
            Self::RevocationChecking(_) => true,
        }
    }

    /// The verifier to hand to `rustls::ClientConfig`.
    pub fn into_arc(self) -> Arc<dyn ServerCertVerifier> {
        match self {
            Self::WebPki(v) => v,
            #[cfg(feature = "revocation")]
            Self::RevocationChecking(v) => v,
        }
    }
}

impl std::fmt::Debug for ServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebPki(_) => f.write_str("ServerVerifier::WebPki"),
            #[cfg(feature = "revocation")]
            Self::RevocationChecking(_) => f.write_str("ServerVerifier::RevocationChecking"),
        }
    }
}

/// Errors building a server-certificate verifier.
#[derive(Debug, thiserror::Error)]
pub enum ServerVerifierError {
    #[error("home server CA bundle error: {0}")]
    RootStore(#[from] crate::tls_certs::RootStoreError),
    #[error("home server CA bundle PEM error: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("cannot build server certificate verifier: {0}")]
    Build(String),
    #[error("revocation checking: {0}")]
    Revocation(String),
}

/// Build the server-certificate verifier for one RadSec home server.
///
/// * `ca_path` — PEM bundle of the CAs that issue the home server's certificate.
/// * `provider` — the rustls `CryptoProvider` to verify signatures with (the
///   link's FIPS/PQ provider).
/// * `revocation` — the home server's `tls.revocation` block, if any. `Some`
///   requires the `revocation` cargo feature; without it this is an error
///   rather than a silent downgrade to chain-only validation.
pub fn build_server_verifier(
    ca_path: &str,
    provider: Arc<CryptoProvider>,
    revocation: Option<&RevocationConfig>,
) -> Result<ServerVerifier, ServerVerifierError> {
    let roots = Arc::new(crate::tls_certs::load_root_store(ca_path)?);
    let webpki = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(|e| ServerVerifierError::Build(e.to_string()))?;

    match revocation {
        None => Ok(ServerVerifier::WebPki(webpki)),
        #[cfg(feature = "revocation")]
        Some(cfg) => {
            use rustls::pki_types::CertificateDer;
            use rustls::server::WebPkiClientVerifier;

            // The CA certificates double as issuer candidates for OCSP requests
            // (a home server rarely sends its issuer as an intermediate).
            let issuers: Vec<Vec<u8>> = CertificateDer::pem_file_iter(ca_path)?
                .map(|c| c.map(|c| c.as_ref().to_vec()))
                .collect::<Result<_, _>>()?;
            // `RevocationCheckingVerifier` wants a `ClientCertVerifier` to wrap;
            // the adapter below never invokes it (WebPKI validation of the
            // *server* certificate is done by `webpki` above, name check
            // included). It only exists to satisfy the constructor.
            let inner = WebPkiClientVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| ServerVerifierError::Build(e.to_string()))?;
            let revocation =
                radius_proto::revocation::RevocationCheckingVerifier::with_webpki_verifier(
                    cfg.to_proto(),
                    inner,
                )
                .map_err(|e| ServerVerifierError::Revocation(e.to_string()))?
                .with_issuer_certificates(issuers);
            Ok(ServerVerifier::RevocationChecking(Arc::new(
                RevocationCheckingServerVerifier { webpki, revocation },
            )))
        }
        #[cfg(not(feature = "revocation"))]
        Some(_) => Err(ServerVerifierError::Revocation(
            "this binary was built without the `revocation` feature".to_string(),
        )),
    }
}

/// `WebPkiServerVerifier` (chain, validity, `server_name`) followed by the
/// `radius_proto` revocation check on the end-entity certificate. Errors are
/// mapped exactly as the proto module's `ClientCertVerifier` impl maps them:
/// a positive "revoked" is `CertificateError::Revoked`, an inconclusive check
/// under fail-closed is `CertificateError::Other` carrying the reason.
///
/// A stapled OCSP response (`ocsp_response`) is passed through to WebPKI and
/// not consulted by the revocation checker, which fetches its own.
#[cfg(feature = "revocation")]
#[derive(Debug)]
pub struct RevocationCheckingServerVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    revocation: radius_proto::revocation::RevocationCheckingVerifier,
}

#[cfg(feature = "revocation")]
impl ServerCertVerifier for RevocationCheckingServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // RFC 6614 §2.3: the client MUST verify the server certificate; chain,
        // validity and name first, so a wrong name never reaches a fetch.
        self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        let intermediates: Vec<&[u8]> = intermediates.iter().map(|c| c.as_ref()).collect();
        match self
            .revocation
            .check_revocation(end_entity.as_ref(), &intermediates)
        {
            Ok(()) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            Err(radius_proto::revocation::RevocationError::CertificateRevoked(_)) => Err(
                rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked),
            ),
            // Inconclusive under fail-closed: surface the reason to the log,
            // not a misleading "revoked".
            Err(e) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(e))),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::test_pki::{TestChain, TestPaths, gen_chain_with};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn server_der(chain: &TestChain) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(chain.server_cert_pem.as_bytes()).unwrap()
    }

    fn verify(
        v: &ServerVerifier,
        cert: &CertificateDer<'_>,
        name: &str,
    ) -> Result<(), rustls::Error> {
        let verifier: Arc<dyn ServerCertVerifier> = match v {
            ServerVerifier::WebPki(v) => v.clone(),
            #[cfg(feature = "revocation")]
            ServerVerifier::RevocationChecking(v) => v.clone(),
        };
        let name = ServerName::try_from(name).unwrap().to_owned();
        verifier
            .verify_server_cert(cert, &[], &name, &[], UnixTime::now())
            .map(|_| ())
    }

    fn provider() -> Arc<CryptoProvider> {
        usg_fips_tls::provider::fips_provider_arc()
    }

    fn build(paths: &TestPaths, revocation: Option<&RevocationConfig>) -> ServerVerifier {
        build_server_verifier(&paths.ca, provider(), revocation).unwrap()
    }

    #[test]
    fn no_revocation_block_selects_the_plain_webpki_verifier() {
        let chain = gen_chain_with(&["home.test"], true);
        let paths = chain.write_to_tempdir();
        let v = build(&paths, None);
        assert!(!v.checks_revocation());
        assert!(matches!(v, ServerVerifier::WebPki(_)));
        // Chain and name validation apply; nothing knows about the CRL.
        verify(&v, &server_der(&chain), "home.test").unwrap();
        assert!(verify(&v, &server_der(&chain), "other.test").is_err());
    }

    #[test]
    fn missing_ca_bundle_is_an_error() {
        let err = build_server_verifier("/nonexistent/ca.pem", provider(), None).unwrap_err();
        assert!(matches!(err, ServerVerifierError::RootStore(_)), "{err}");
    }

    #[cfg(not(feature = "revocation"))]
    #[test]
    fn revocation_block_without_the_feature_is_an_error_not_a_downgrade() {
        let chain = gen_chain_with(&["home.test"], true);
        let paths = chain.write_to_tempdir();
        let cfg = RevocationConfig::default();
        let err = build_server_verifier(&paths.ca, provider(), Some(&cfg)).unwrap_err();
        assert!(matches!(err, ServerVerifierError::Revocation(_)), "{err}");
    }

    #[cfg(feature = "revocation")]
    mod with_revocation {
        use super::*;
        use crate::config::{CrlSettings, RevocationFailurePolicy, RevocationMode};

        fn static_crl(paths: &TestPaths) -> RevocationConfig {
            RevocationConfig {
                mode: RevocationMode::CrlOnly,
                on_error: RevocationFailurePolicy::FailClosed,
                crl: CrlSettings {
                    static_files: vec![paths.crl.clone()],
                    fetch: false,
                    ..CrlSettings::default()
                },
                ..RevocationConfig::default()
            }
        }

        #[test]
        fn revoked_server_certificate_is_rejected_as_revoked() {
            let chain = gen_chain_with(&["home.test"], true);
            let paths = chain.write_to_tempdir();
            let v = build(&paths, Some(&static_crl(&paths)));
            assert!(v.checks_revocation());
            let err = verify(&v, &server_der(&chain), "home.test").expect_err("revoked");
            assert_eq!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked)
            );
        }

        #[test]
        fn unrevoked_server_certificate_passes() {
            // Same CA and CRL layout, but the CRL lists the *client* cert.
            let chain = gen_chain_with(&["home.test"], false);
            let paths = chain.write_to_tempdir();
            let v = build(&paths, Some(&static_crl(&paths)));
            verify(&v, &server_der(&chain), "home.test").expect("not revoked");
        }

        #[test]
        fn wrong_name_is_rejected_before_revocation_is_consulted() {
            // Revoked *and* the wrong name: the error is the name failure,
            // which proves WebPKI ran first (fail closed either way).
            let chain = gen_chain_with(&["home.test"], true);
            let paths = chain.write_to_tempdir();
            let v = build(&paths, Some(&static_crl(&paths)));
            let err = verify(&v, &server_der(&chain), "other.test").expect_err("wrong name");
            assert!(
                matches!(
                    err,
                    rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)
                        | rustls::Error::InvalidCertificate(
                            rustls::CertificateError::NotValidForNameContext { .. }
                        )
                ),
                "expected a name error, got {err:?}"
            );
        }

        #[test]
        fn missing_static_crl_file_fails_at_build_time() {
            let chain = gen_chain_with(&["home.test"], true);
            let paths = chain.write_to_tempdir();
            let mut cfg = static_crl(&paths);
            cfg.crl.static_files = vec![format!("{}.missing", paths.crl)];
            let err = build_server_verifier(&paths.ca, provider(), Some(&cfg)).unwrap_err();
            assert!(matches!(err, ServerVerifierError::Revocation(_)), "{err}");
        }
    }
}
