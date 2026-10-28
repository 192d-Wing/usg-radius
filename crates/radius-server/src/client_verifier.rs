//! Client-certificate verifier selection for the TLS listeners.
//!
//! Both mutually-authenticated surfaces — EAP-TLS (supplicant certificates)
//! and RadSec (NAS certificates) — verify the peer certificate against a CA
//! bundle with rustls's `WebPkiClientVerifier`. When a `revocation` block is
//! configured, that verifier is wrapped in
//! `radius_proto::revocation::RevocationCheckingVerifier`, which adds CRL and/or
//! OCSP checking at handshake time. Without the block the plain WebPKI verifier
//! is used unchanged, so deployments that do not opt in see no behavioral
//! difference.
//!
//! The choice is explicit in [`ClientVerifier`] so it can be asserted in tests
//! and logged at startup.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
#[cfg_attr(not(feature = "revocation"), allow(unused_imports))]
use rustls::pki_types::CertificateDer;
#[cfg(feature = "revocation")]
use rustls::pki_types::pem::PemObject;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;

use crate::config::RevocationConfig;

/// The verifier selected for a listener.
pub enum ClientVerifier {
    /// Chain validation against the CA bundle only.
    WebPki(Arc<dyn ClientCertVerifier>),
    /// Chain validation plus CRL/OCSP revocation checking.
    #[cfg(feature = "revocation")]
    RevocationChecking(Arc<dyn ClientCertVerifier>),
}

impl ClientVerifier {
    /// Whether peer certificates are checked for revocation.
    pub fn checks_revocation(&self) -> bool {
        match self {
            Self::WebPki(_) => false,
            #[cfg(feature = "revocation")]
            Self::RevocationChecking(_) => true,
        }
    }

    /// The verifier to hand to `rustls::ServerConfig`.
    pub fn into_arc(self) -> Arc<dyn ClientCertVerifier> {
        match self {
            Self::WebPki(v) => v,
            #[cfg(feature = "revocation")]
            Self::RevocationChecking(v) => v,
        }
    }
}

impl std::fmt::Debug for ClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebPki(_) => f.write_str("ClientVerifier::WebPki"),
            #[cfg(feature = "revocation")]
            Self::RevocationChecking(_) => f.write_str("ClientVerifier::RevocationChecking"),
        }
    }
}

/// Errors building a client-certificate verifier.
#[derive(Debug, thiserror::Error)]
pub enum ClientVerifierError {
    #[error("client CA bundle error: {0}")]
    RootStore(#[from] crate::tls_certs::RootStoreError),
    #[error("client CA bundle PEM error: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("cannot build client certificate verifier: {0}")]
    Build(String),
    #[error("revocation checking: {0}")]
    Revocation(String),
}

/// Build the client-certificate verifier for a listener.
///
/// * `ca_path` — PEM bundle of the CAs that issue peer certificates.
/// * `provider` — the rustls `CryptoProvider` to verify signatures with
///   (`None` ⇒ the process default; RadSec passes its FIPS/PQ provider).
/// * `revocation` — the listener's `revocation` block, if any. `Some` requires
///   the `revocation` cargo feature; without it this is an error rather than a
///   silent downgrade to chain-only validation.
pub fn build_client_verifier(
    ca_path: &str,
    provider: Option<Arc<CryptoProvider>>,
    revocation: Option<&RevocationConfig>,
) -> Result<ClientVerifier, ClientVerifierError> {
    let roots = Arc::new(crate::tls_certs::load_root_store(ca_path)?);
    // CRL/OCSP signatures are verified with the same algorithms as the chain.
    #[cfg(feature = "revocation")]
    let signature_algorithms = provider
        .as_ref()
        .map(|provider| provider.signature_verification_algorithms);
    let webpki = match provider {
        Some(provider) => WebPkiClientVerifier::builder_with_provider(roots, provider),
        None => WebPkiClientVerifier::builder(roots),
    }
    .build()
    .map_err(|e| ClientVerifierError::Build(e.to_string()))?;

    match revocation {
        None => Ok(ClientVerifier::WebPki(webpki)),
        #[cfg(feature = "revocation")]
        Some(cfg) => {
            // The CA certificates anchor the chain the revocation checks walk:
            // CRL and OCSP signatures are trusted only when they chain to one,
            // and they are the OCSP request issuer (peers rarely send theirs).
            let issuers: Vec<Vec<u8>> = CertificateDer::pem_file_iter(ca_path)?
                .map(|c| c.map(|c| c.as_ref().to_vec()))
                .collect::<Result<_, _>>()?;
            let mut verifier =
                radius_proto::revocation::RevocationCheckingVerifier::with_webpki_verifier(
                    cfg.to_proto(),
                    webpki,
                )
                .map_err(|e| ClientVerifierError::Revocation(e.to_string()))?
                .with_issuer_certificates(issuers);
            if let Some(algorithms) = signature_algorithms {
                verifier = verifier.with_signature_verification_algorithms(algorithms);
            }
            Ok(ClientVerifier::RevocationChecking(Arc::new(verifier)))
        }
        #[cfg(not(feature = "revocation"))]
        Some(_) => Err(ClientVerifierError::Revocation(
            "this binary was built without the `revocation` feature".to_string(),
        )),
    }
}

#[cfg(feature = "revocation")]
impl RevocationConfig {
    /// Translate the server config block into the `radius_proto` module's
    /// configuration.
    pub fn to_proto(&self) -> radius_proto::revocation::RevocationConfig {
        use crate::config::{RevocationFailurePolicy, RevocationMode};
        use radius_proto::revocation::{
            CrlConfig, FallbackBehavior, OcspConfig, RevocationCheckMode,
        };

        let check_mode = match self.mode {
            RevocationMode::CrlOnly => RevocationCheckMode::CrlOnly,
            RevocationMode::OcspOnly => RevocationCheckMode::OcspOnly,
            RevocationMode::PreferOcsp => RevocationCheckMode::PreferOcsp,
            RevocationMode::Both => RevocationCheckMode::Both,
        };
        let fallback_behavior = match self.on_error {
            RevocationFailurePolicy::FailClosed => FallbackBehavior::FailClosed,
            RevocationFailurePolicy::FailOpen => FallbackBehavior::FailOpen,
        };
        radius_proto::revocation::RevocationConfig {
            check_mode,
            fallback_behavior,
            crl_config: CrlConfig {
                static_crl_paths: self.crl.static_files.clone(),
                enable_http_fetch: self.crl.fetch,
                http_timeout_secs: self.crl.fetch_timeout_secs,
                cache_ttl_secs: self.crl.cache_ttl_secs,
                max_cache_entries: self.crl.max_cache_entries,
                max_crl_size_bytes: self.crl.max_size_bytes,
            },
            ocsp_config: OcspConfig {
                enabled: self.mode.uses_ocsp(),
                http_timeout_secs: self.ocsp.fetch_timeout_secs,
                cache_ttl_secs: self.ocsp.cache_ttl_secs,
                max_cache_entries: self.ocsp.max_cache_entries,
                enable_nonce: self.ocsp.nonce,
                max_response_size_bytes: self.ocsp.max_response_size_bytes,
                prefer_ocsp: matches!(self.mode, RevocationMode::PreferOcsp),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "revocation")]
    use crate::config::{CrlSettings, RevocationFailurePolicy, RevocationMode};
    use rustls::pki_types::UnixTime;
    use std::io::Write as _;

    /// Throwaway PKI: a CA, a client certificate with a known serial that the
    /// CA's CRL revokes, and a second client certificate that stays valid.
    /// Everything the verifier reads from disk is written to a temp dir.
    #[cfg_attr(not(feature = "revocation"), allow(dead_code))]
    struct TestPki {
        _dir: tempfile::TempDir,
        ca_path: String,
        crl_path: String,
        /// Empty CRL naming the CA as issuer, signed by another key.
        forged_crl_path: String,
        revoked_der: CertificateDer<'static>,
        valid_der: CertificateDer<'static>,
    }

    fn gen_pki() -> TestPki {
        use rcgen::{
            BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa,
            Issuer, KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams, SerialNumber,
            date_time_ymd,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "USG Test Client CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        // Top bit set on purpose: DER pads it with 0x00, which the CRL parser
        // must strip to match the certificate's serial.
        let revoked_serial = SerialNumber::from(vec![0xA5, 0x01, 0x02, 0x03]);
        let revoked_key = KeyPair::generate().unwrap();
        let mut revoked_params = CertificateParams::new(Vec::new()).unwrap();
        revoked_params.serial_number = Some(revoked_serial.clone());
        revoked_params
            .distinguished_name
            .push(DnType::CommonName, "revoked@usg.test");
        let revoked = revoked_params.signed_by(&revoked_key, &issuer).unwrap();

        let valid_key = KeyPair::generate().unwrap();
        let mut valid_params = CertificateParams::new(Vec::new()).unwrap();
        valid_params.serial_number = Some(SerialNumber::from(vec![0x10, 0x20, 0x30]));
        valid_params
            .distinguished_name
            .push(DnType::CommonName, "eaptls@usg.test");
        let valid = valid_params.signed_by(&valid_key, &issuer).unwrap();

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

        let forger_key = KeyPair::generate().unwrap();
        let forged_crl = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(2u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&Issuer::from_params(&ca_params, &forger_key))
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, data: &[u8]| {
            let path = dir.path().join(name);
            std::fs::File::create(&path)
                .unwrap()
                .write_all(data)
                .unwrap();
            path.to_str().unwrap().to_string()
        };
        TestPki {
            ca_path: write("ca.pem", ca.pem().as_bytes()),
            crl_path: write("ca.crl", crl.der().as_ref()),
            forged_crl_path: write("forged.crl", forged_crl.der().as_ref()),
            revoked_der: revoked.der().clone(),
            valid_der: valid.der().clone(),
            _dir: dir,
        }
    }

    fn verify(v: &ClientVerifier, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let verifier = match v {
            ClientVerifier::WebPki(v) => v.clone(),
            #[cfg(feature = "revocation")]
            ClientVerifier::RevocationChecking(v) => v.clone(),
        };
        verifier
            .verify_client_cert(cert, &[], UnixTime::now())
            .map(|_| ())
    }

    #[cfg(feature = "revocation")]
    fn static_crl(pki: &TestPki, on_error: RevocationFailurePolicy) -> RevocationConfig {
        RevocationConfig {
            mode: RevocationMode::CrlOnly,
            on_error,
            crl: CrlSettings {
                static_files: vec![pki.crl_path.clone()],
                fetch: false,
                ..CrlSettings::default()
            },
            ..RevocationConfig::default()
        }
    }

    #[test]
    fn no_revocation_block_selects_the_plain_webpki_verifier() {
        let pki = gen_pki();
        let v = build_client_verifier(&pki.ca_path, None, None).unwrap();
        assert!(!v.checks_revocation());
        assert!(matches!(v, ClientVerifier::WebPki(_)));
        // Chain validation still applies, and nothing knows about the CRL.
        verify(&v, &pki.valid_der).unwrap();
        verify(&v, &pki.revoked_der).unwrap();
    }

    #[test]
    fn explicit_provider_is_honored() {
        let pki = gen_pki();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let v = build_client_verifier(&pki.ca_path, Some(provider), None).unwrap();
        verify(&v, &pki.valid_der).unwrap();
    }

    #[test]
    fn missing_ca_bundle_is_an_error() {
        let err = build_client_verifier("/nonexistent/ca.pem", None, None).unwrap_err();
        assert!(matches!(err, ClientVerifierError::RootStore(_)), "{err}");
    }

    #[cfg(not(feature = "revocation"))]
    #[test]
    fn revocation_block_without_the_feature_is_an_error_not_a_downgrade() {
        let pki = gen_pki();
        let cfg = RevocationConfig::default();
        let err = build_client_verifier(&pki.ca_path, None, Some(&cfg)).unwrap_err();
        assert!(matches!(err, ClientVerifierError::Revocation(_)), "{err}");
    }

    #[cfg(feature = "revocation")]
    mod with_revocation {
        use super::*;

        #[test]
        fn revocation_block_selects_the_checking_verifier() {
            let pki = gen_pki();
            let cfg = static_crl(&pki, RevocationFailurePolicy::FailClosed);
            let v = build_client_verifier(&pki.ca_path, None, Some(&cfg)).unwrap();
            assert!(v.checks_revocation());
            assert!(matches!(v, ClientVerifier::RevocationChecking(_)));
        }

        #[test]
        fn static_crl_rejects_the_revoked_certificate_and_accepts_the_valid_one() {
            let pki = gen_pki();
            for on_error in [
                RevocationFailurePolicy::FailClosed,
                RevocationFailurePolicy::FailOpen,
            ] {
                let cfg = static_crl(&pki, on_error);
                let v = build_client_verifier(&pki.ca_path, None, Some(&cfg)).unwrap();
                verify(&v, &pki.valid_der).expect("valid certificate must pass");
                let err = verify(&v, &pki.revoked_der).expect_err("revoked must fail");
                assert_eq!(
                    err,
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked),
                    "revoked is revoked even under fail-open ({on_error:?})"
                );
            }
        }

        #[test]
        fn crl_signed_by_another_key_is_not_trusted() {
            // Names the real CA, revokes nothing, signed by a different key: a
            // forged "all clear". Fail-closed rejects even the valid certificate,
            // and never as "revoked".
            let pki = gen_pki();
            let mut cfg = static_crl(&pki, RevocationFailurePolicy::FailClosed);
            cfg.crl.static_files = vec![pki.forged_crl_path.clone()];
            let v = build_client_verifier(&pki.ca_path, None, Some(&cfg)).unwrap();
            for cert in [&pki.valid_der, &pki.revoked_der] {
                let err = verify(&v, cert).expect_err("forged CRL must not be trusted");
                assert!(
                    matches!(
                        err,
                        rustls::Error::InvalidCertificate(rustls::CertificateError::Other(_))
                    ),
                    "{err:?}"
                );
            }
        }

        #[test]
        fn static_crl_also_works_with_the_fips_provider_path() {
            // RadSec builds its verifier with an explicit provider.
            let pki = gen_pki();
            let cfg = static_crl(&pki, RevocationFailurePolicy::FailClosed);
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let v = build_client_verifier(&pki.ca_path, Some(provider), Some(&cfg)).unwrap();
            verify(&v, &pki.valid_der).unwrap();
            assert!(verify(&v, &pki.revoked_der).is_err());
        }

        #[test]
        fn undeterminable_status_follows_the_on_error_policy() {
            // No static CRL and the certificates carry no CRL Distribution
            // Points, so the status cannot be determined (no network involved).
            let pki = gen_pki();
            let mut cfg = RevocationConfig::default();
            assert!(cfg.crl.fetch);

            cfg.on_error = RevocationFailurePolicy::FailClosed;
            let v = build_client_verifier(&pki.ca_path, None, Some(&cfg)).unwrap();
            let err = verify(&v, &pki.valid_der).expect_err("fail-closed must reject");
            assert!(
                matches!(
                    err,
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(_))
                ),
                "an inconclusive check is not reported as 'revoked': {err:?}"
            );

            cfg.on_error = RevocationFailurePolicy::FailOpen;
            let v = build_client_verifier(&pki.ca_path, None, Some(&cfg)).unwrap();
            verify(&v, &pki.valid_der).expect("fail-open must accept");
        }

        #[test]
        fn missing_static_crl_file_fails_at_build_time() {
            let pki = gen_pki();
            let mut cfg = static_crl(&pki, RevocationFailurePolicy::FailOpen);
            cfg.crl.static_files = vec![format!("{}.missing", pki.crl_path)];
            let err = build_client_verifier(&pki.ca_path, None, Some(&cfg)).unwrap_err();
            assert!(matches!(err, ClientVerifierError::Revocation(_)), "{err}");
        }

        #[test]
        fn to_proto_maps_every_field() {
            use radius_proto::revocation::{FallbackBehavior, RevocationCheckMode};

            let cfg = RevocationConfig {
                mode: RevocationMode::PreferOcsp,
                on_error: RevocationFailurePolicy::FailOpen,
                crl: CrlSettings {
                    static_files: vec!["/a.crl".into()],
                    fetch: false,
                    fetch_timeout_secs: 3,
                    cache_ttl_secs: 60,
                    max_cache_entries: 7,
                    max_size_bytes: 1234,
                },
                ocsp: crate::config::OcspSettings {
                    fetch_timeout_secs: 4,
                    cache_ttl_secs: 90,
                    max_cache_entries: 8,
                    nonce: false,
                    max_response_size_bytes: 4321,
                },
            };
            let p = cfg.to_proto();
            assert_eq!(p.check_mode, RevocationCheckMode::PreferOcsp);
            assert_eq!(p.fallback_behavior, FallbackBehavior::FailOpen);
            assert_eq!(p.crl_config.static_crl_paths, vec!["/a.crl".to_string()]);
            assert!(!p.crl_config.enable_http_fetch);
            assert_eq!(p.crl_config.http_timeout_secs, 3);
            assert_eq!(p.crl_config.cache_ttl_secs, 60);
            assert_eq!(p.crl_config.max_cache_entries, 7);
            assert_eq!(p.crl_config.max_crl_size_bytes, 1234);
            assert!(p.ocsp_config.enabled);
            assert!(p.ocsp_config.prefer_ocsp);
            assert_eq!(p.ocsp_config.http_timeout_secs, 4);
            assert_eq!(p.ocsp_config.cache_ttl_secs, 90);
            assert_eq!(p.ocsp_config.max_cache_entries, 8);
            assert!(!p.ocsp_config.enable_nonce);
            assert_eq!(p.ocsp_config.max_response_size_bytes, 4321);

            let crl_only = RevocationConfig::default().to_proto();
            assert_eq!(crl_only.check_mode, RevocationCheckMode::CrlOnly);
            assert_eq!(crl_only.fallback_behavior, FallbackBehavior::FailClosed);
            assert!(!crl_only.ocsp_config.enabled);
            assert!(!crl_only.ocsp_config.prefer_ocsp);
            let both = RevocationConfig {
                mode: RevocationMode::Both,
                ..RevocationConfig::default()
            }
            .to_proto();
            assert_eq!(both.check_mode, RevocationCheckMode::Both);
            assert!(both.ocsp_config.enabled);
            assert!(!both.ocsp_config.prefer_ocsp);
        }
    }
}
