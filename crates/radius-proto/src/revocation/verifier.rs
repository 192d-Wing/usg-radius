//! Custom certificate verifier with CRL / OCSP revocation checking
//!
//! This module provides `RevocationCheckingVerifier`, a rustls
//! [`ClientCertVerifier`] that wraps the standard `WebPkiClientVerifier` and
//! adds certificate revocation checking.
//!
//! # Overview
//!
//! The verifier integrates into the rustls TLS handshake to check whether the
//! client (supplicant or NAS) certificate has been revoked. The flow is:
//!
//! 1. **Standard validation**: the wrapped WebPKI verifier checks the chain,
//!    expiry and signatures against the configured trust anchors.
//! 2. **Static CRLs**: CRL files preloaded from
//!    [`CrlConfig::static_crl_paths`](super::CrlConfig::static_crl_paths) are
//!    consulted first, matched to the certificate by issuer name.
//! 3. **CRL Distribution Points**: when no current static CRL covers the
//!    issuer and HTTP fetching is enabled, the CRL is fetched from the URLs in
//!    the certificate's CRL Distribution Points extension (with caching).
//! 4. **OCSP**: when the check mode asks for it, an OCSP request for the
//!    certificate is built against its issuer (taken from the handshake's
//!    intermediates or the configured issuer certificates) and sent to the
//!    responder named in the Authority Information Access extension.
//! 5. **Fail-open / fail-closed**: fetch, parse and freshness errors are
//!    handled per [`FallbackBehavior`]. A positive "revoked" answer always
//!    rejects, regardless of the fallback policy.
//!
//! # Example
//!
//! ```no_run
//! use radius_proto::revocation::{RevocationConfig, RevocationCheckingVerifier};
//! use rustls::ServerConfig;
//! use std::sync::Arc;
//!
//! # fn example(webpki: Arc<dyn rustls::server::danger::ClientCertVerifier>,
//! #            server_cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
//! #            server_key: rustls::pki_types::PrivateKeyDer<'static>)
//! #     -> Result<(), Box<dyn std::error::Error>> {
//! let revocation_config = RevocationConfig::default();
//!
//! // Wrap the WebPKI verifier built from the deployment's trust anchors.
//! let verifier = RevocationCheckingVerifier::with_webpki_verifier(revocation_config, webpki)?;
//!
//! let tls_config = ServerConfig::builder()
//!     .with_client_cert_verifier(Arc::new(verifier))
//!     .with_single_cert(server_cert_chain, server_key)?;
//! # Ok(())
//! # }
//! ```

use super::{
    cache::CrlCache,
    config::{FallbackBehavior, RevocationCheckMode, RevocationConfig},
    crl::CrlInfo,
    error::RevocationError,
    fetch::{CrlFetcher, extract_crl_distribution_points},
    ocsp::{OcspClient, OcspRequestBuilder, OcspResponse},
    ocsp_cache::OcspCache,
};
use pki_types::{CertificateDer, UnixTime};
use rustls::server::{
    WebPkiClientVerifier,
    danger::{ClientCertVerified, ClientCertVerifier},
};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError};
use std::sync::Arc;
use std::time::Duration;

/// Length of the OCSP request nonce (RFC 8954 §2.1 allows 1..=32 octets).
const OCSP_NONCE_LEN: usize = 16;

/// Custom certificate verifier with CRL and OCSP revocation checking
///
/// This verifier wraps a `WebPkiClientVerifier` and adds CRL and/or OCSP
/// checking. It implements rustls's `ClientCertVerifier` trait to integrate
/// into the TLS handshake.
///
/// # Behavior Modes
///
/// - **Fail-Open**: If a CRL/OCSP fetch, parse or freshness check fails, allow
///   the authentication (a warning is printed)
/// - **Fail-Closed**: If a CRL/OCSP check cannot be completed, reject the
///   authentication (secure default)
///
/// A certificate that a CRL or OCSP responder reports as revoked is always
/// rejected.
///
/// # Caching
///
/// Fetched CRLs and OCSP responses are cached with configurable TTL to avoid
/// repeated HTTP fetches. Caches are thread-safe and shared across all TLS
/// connections. Static CRL files are parsed once, when the verifier is built.
#[derive(Debug)]
pub struct RevocationCheckingVerifier {
    /// Underlying WebPki verifier for standard validation
    webpki_verifier: Arc<dyn ClientCertVerifier>,

    /// Revocation checking configuration
    config: RevocationConfig,

    /// CRLs preloaded from `CrlConfig::static_crl_paths`
    static_crls: Vec<CrlInfo>,

    /// DER certificates that may have issued the client certificates (the
    /// trust anchors, typically). Used to find the issuer for OCSP requests
    /// when the client did not send it as an intermediate.
    issuer_certs: Vec<Vec<u8>>,

    /// CRL cache (thread-safe)
    crl_cache: Arc<CrlCache>,

    /// HTTP fetcher for CRLs
    crl_fetcher: Option<CrlFetcher>,

    /// OCSP response cache (thread-safe)
    ocsp_cache: Option<Arc<OcspCache>>,

    /// OCSP client for querying responders
    ocsp_client: Option<OcspClient>,
}

impl RevocationCheckingVerifier {
    /// Create a new revocation-checking verifier over an **empty** trust store.
    ///
    /// This exists for API symmetry; because rustls refuses to build a client
    /// verifier without trust anchors, it always fails. Build the WebPKI
    /// verifier from your CA bundle and use [`Self::with_webpki_verifier`].
    pub fn new(config: RevocationConfig) -> Result<Self, RevocationError> {
        let webpki_verifier =
            WebPkiClientVerifier::builder(Arc::new(rustls::RootCertStore::empty()))
                .build()
                .map_err(|e| {
                    RevocationError::ConfigError(format!("Failed to create WebPki verifier: {}", e))
                })?;
        Self::with_webpki_verifier(config, webpki_verifier)
    }

    /// Create a verifier that wraps an existing WebPKI client verifier.
    ///
    /// Static CRL files named in `config.crl_config.static_crl_paths` are read
    /// and parsed here (PEM or DER); a missing or malformed file is an error so
    /// that a misconfigured deployment fails at startup rather than silently
    /// skipping revocation checks.
    pub fn with_webpki_verifier(
        config: RevocationConfig,
        webpki_verifier: Arc<dyn ClientCertVerifier>,
    ) -> Result<Self, RevocationError> {
        let revocation_enabled = !matches!(config.check_mode, RevocationCheckMode::Disabled);
        let uses_crl = revocation_enabled
            && matches!(
                config.check_mode,
                RevocationCheckMode::CrlOnly
                    | RevocationCheckMode::PreferOcsp
                    | RevocationCheckMode::Both
            );
        let uses_ocsp = revocation_enabled
            && matches!(
                config.check_mode,
                RevocationCheckMode::OcspOnly
                    | RevocationCheckMode::PreferOcsp
                    | RevocationCheckMode::Both
            );

        let static_crls = if uses_crl {
            config
                .crl_config
                .static_crl_paths
                .iter()
                .map(|path| load_static_crl(path))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };

        let crl_cache = CrlCache::new(config.crl_config.max_cache_entries.max(1));

        let crl_fetcher = if uses_crl && config.crl_config.enable_http_fetch {
            Some(CrlFetcher::with_max_size(
                config.crl_config.http_timeout_secs,
                config.crl_config.max_crl_size_bytes,
            )?)
        } else {
            None
        };

        let (ocsp_cache, ocsp_client) = if uses_ocsp {
            (
                Some(OcspCache::new(config.ocsp_config.max_cache_entries.max(1))),
                Some(OcspClient::new(config.ocsp_config.http_timeout_secs)?),
            )
        } else {
            (None, None)
        };

        Ok(Self {
            webpki_verifier,
            config,
            static_crls,
            issuer_certs: Vec::new(),
            crl_cache,
            crl_fetcher,
            ocsp_cache,
            ocsp_client,
        })
    }

    /// Provide DER certificates that may have issued the client certificates
    /// (normally the trust anchors the WebPKI verifier was built from).
    ///
    /// OCSP requests identify the certificate by hashes of its issuer's name
    /// and public key (RFC 6960 §4.1.1), so the issuer certificate is needed to
    /// build one. EAP supplicants and NAS devices usually present only their
    /// end-entity certificate, so without these candidates OCSP checking can
    /// only succeed when the client sends its issuer as an intermediate.
    pub fn with_issuer_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.issuer_certs = certs;
        self
    }

    /// Number of static CRLs loaded at construction.
    pub fn static_crl_count(&self) -> usize {
        self.static_crls.len()
    }

    /// The revocation configuration this verifier enforces.
    pub fn config(&self) -> &RevocationConfig {
        &self.config
    }

    /// Check if a certificate is revoked
    ///
    /// This performs revocation checking according to the configured check mode:
    /// - OcspOnly: Check OCSP only
    /// - CrlOnly: Check CRL only
    /// - PreferOcsp: Try OCSP first, fall back to CRL when OCSP cannot answer
    /// - Both: Check both OCSP and CRL (fail if either indicates revoked)
    ///
    /// # Arguments
    ///
    /// * `cert_der` - DER-encoded client certificate
    /// * `intermediates` - DER-encoded intermediate certificates the client
    ///   sent (used to find the issuer for OCSP)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Certificate is NOT revoked (or the check failed under fail-open)
    /// * `Err(RevocationError)` - Certificate is revoked OR check failed under fail-closed
    fn check_revocation(
        &self,
        cert_der: &[u8],
        intermediates: &[&[u8]],
    ) -> Result<(), RevocationError> {
        match self.config.check_mode {
            RevocationCheckMode::Disabled => Ok(()),

            RevocationCheckMode::OcspOnly => {
                // OCSP only: an inconclusive answer falls to the fail policy.
                match self.check_ocsp(cert_der, intermediates) {
                    Ok(()) => Ok(()),
                    Err(e @ RevocationError::CertificateRevoked(_)) => Err(e),
                    Err(e) => self.handle_error(e),
                }
            }

            RevocationCheckMode::CrlOnly => self.check_crl(cert_der),

            RevocationCheckMode::PreferOcsp => {
                // Try OCSP first; anything but a definite answer falls back to CRL.
                match self.check_ocsp(cert_der, intermediates) {
                    Ok(()) => Ok(()),
                    Err(e @ RevocationError::CertificateRevoked(_)) => Err(e),
                    Err(_) => {
                        // The reason is not logged: it can carry certificate
                        // identifiers; the CRL outcome decides.
                        eprintln!("OCSP check inconclusive, trying CRL");
                        self.check_crl(cert_der)
                    }
                }
            }

            RevocationCheckMode::Both => {
                // Check both OCSP and CRL. `check_crl` already applies the fail
                // policy to its own errors; OCSP errors are handled here.
                let ocsp_result = self.check_ocsp(cert_der, intermediates);
                let crl_result = self.check_crl(cert_der);

                match (ocsp_result, crl_result) {
                    (Err(RevocationError::CertificateRevoked(_)), _) => {
                        Err(RevocationError::CertificateRevoked(
                            "Certificate revoked (OCSP)".to_string(),
                        ))
                    }
                    (_, Err(RevocationError::CertificateRevoked(_))) => {
                        Err(RevocationError::CertificateRevoked(
                            "Certificate revoked (CRL)".to_string(),
                        ))
                    }
                    (Ok(()), Ok(())) => Ok(()),
                    // CRL failed under fail-closed: reject.
                    (_, Err(e)) => Err(e),
                    // OCSP inconclusive but CRL answered: the CRL answer stands.
                    (Err(_), Ok(())) => {
                        eprintln!("OCSP check inconclusive, CRL check passed");
                        Ok(())
                    }
                }
            }
        }
    }

    /// Check certificate revocation via CRL
    ///
    /// Static CRLs whose issuer matches the certificate's issuer are consulted
    /// first. When none is current, the CRL Distribution Points are fetched
    /// (if HTTP fetching is enabled). Errors are handled per the fail policy.
    fn check_crl(&self, cert_der: &[u8]) -> Result<(), RevocationError> {
        let (issuer, serial) = extract_issuer_and_serial(cert_der)?;

        // 1. Static CRLs for this issuer.
        let mut stale_static: Option<RevocationError> = None;
        let mut have_static = false;
        for crl in self.static_crls.iter().filter(|c| c.issuer == issuer) {
            have_static = true;
            match crl.validate_current(chrono::Utc::now()) {
                Ok(()) => {
                    return if crl.is_revoked(&serial) {
                        Err(revoked(&serial))
                    } else {
                        Ok(())
                    };
                }
                Err(e) => stale_static = Some(e),
            }
        }

        // 2. CRL Distribution Points (HTTP fetch, cached).
        if self.crl_fetcher.is_some() {
            let distribution_points = match extract_crl_distribution_points(cert_der) {
                Ok(points) => points,
                Err(e) => {
                    // No distribution points: the stale static CRL (if any) is
                    // the more useful error to report.
                    return self.handle_error(stale_static.unwrap_or(e));
                }
            };

            let mut last_error = None;
            for url in &distribution_points {
                match self.check_crl_from_url(url, &serial) {
                    Ok(()) => return Ok(()),
                    Err(e @ RevocationError::CertificateRevoked(_)) => return Err(e),
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                }
            }

            return self.handle_error(last_error.unwrap_or_else(|| {
                RevocationError::DistributionPointError("No valid CRL found".to_string())
            }));
        }

        // 3. Static files only, none current for this issuer.
        self.handle_error(stale_static.unwrap_or_else(|| {
            if have_static {
                RevocationError::CrlExpired("static CRL".to_string())
            } else {
                RevocationError::ConfigError(format!(
                    "no static CRL configured for issuer {issuer} and HTTP fetching is disabled"
                ))
            }
        }))
    }

    /// Check certificate revocation via OCSP
    ///
    /// Returns the raw outcome; callers decide how an inconclusive result
    /// (no responder URL, no issuer, HTTP failure, malformed response) is
    /// handled.
    fn check_ocsp(&self, cert_der: &[u8], intermediates: &[&[u8]]) -> Result<(), RevocationError> {
        let ocsp_client = self.ocsp_client.as_ref().ok_or_else(|| {
            RevocationError::ConfigError("OCSP client not initialized".to_string())
        })?;
        let ocsp_cache = self.ocsp_cache.as_ref().ok_or_else(|| {
            RevocationError::ConfigError("OCSP cache not initialized".to_string())
        })?;

        let serial = self.extract_serial_number(cert_der)?;

        // Cached response first.
        if let Some(cached_response) = ocsp_cache.get(&serial) {
            return self.check_ocsp_response_status(&cached_response);
        }

        let ocsp_url = OcspClient::extract_ocsp_url(cert_der)?;
        let issuer_der = self.find_issuer(cert_der, intermediates)?;

        let mut request_builder = OcspRequestBuilder::new(cert_der, issuer_der)?;
        let nonce = if self.config.ocsp_config.enable_nonce {
            use rand::RngExt;
            let nonce = rand::rng().random::<[u8; OCSP_NONCE_LEN]>().to_vec();
            request_builder = request_builder.with_nonce(nonce.clone());
            Some(nonce)
        } else {
            None
        };
        let request_der = request_builder.build()?;

        let response_der = ocsp_client.query(
            &ocsp_url,
            &request_der,
            self.config.ocsp_config.max_response_size_bytes,
        )?;
        let response = OcspResponse::parse(&response_der)?;

        // RFC 8954: a response that carries a nonce must echo ours. A responder
        // that omits the nonce (pre-produced responses) is tolerated, but the
        // response is then not cached beyond this check.
        let nonce_ok = match (&nonce, &response.nonce) {
            (Some(sent), Some(got)) if sent != got => {
                return Err(RevocationError::OcspError(
                    "OCSP response nonce mismatch".to_string(),
                ));
            }
            (Some(_), None) => false,
            _ => true,
        };

        let status = self.check_ocsp_response_status(&response);
        if nonce_ok && response.is_fresh() {
            ocsp_cache.insert(serial, response);
        }
        status
    }

    /// Find the DER certificate that issued `cert_der` among the handshake
    /// intermediates and the configured issuer certificates.
    fn find_issuer<'a>(
        &'a self,
        cert_der: &[u8],
        intermediates: &[&'a [u8]],
    ) -> Result<&'a [u8], RevocationError> {
        use x509_parser::prelude::*;

        let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
            RevocationError::CertificateError(format!("Failed to parse certificate: {}", e))
        })?;
        let issuer_raw = cert.issuer().as_raw();

        let candidates = intermediates
            .iter()
            .copied()
            .chain(self.issuer_certs.iter().map(Vec::as_slice));
        for candidate in candidates {
            if let Ok((_, c)) = parse_x509_certificate(candidate)
                && c.subject().as_raw() == issuer_raw
            {
                return Ok(candidate);
            }
        }

        Err(RevocationError::OcspError(format!(
            "issuer certificate for {} not available (not sent by the peer and not configured)",
            cert.issuer()
        )))
    }

    /// Check OCSP response status
    fn check_ocsp_response_status(&self, response: &OcspResponse) -> Result<(), RevocationError> {
        use super::ocsp::{CertificateStatus, OcspResponseStatus};

        if response.status != OcspResponseStatus::Successful {
            return Err(RevocationError::OcspError(format!(
                "OCSP responder returned error status: {:?}",
                response.status
            )));
        }

        match &response.cert_status {
            Some(CertificateStatus::Good) => Ok(()),
            Some(CertificateStatus::Revoked { .. }) => Err(RevocationError::CertificateRevoked(
                "Certificate revoked (OCSP)".to_string(),
            )),
            Some(CertificateStatus::Unknown) => Err(RevocationError::OcspError(
                "OCSP responder returned 'unknown' status".to_string(),
            )),
            None => Err(RevocationError::OcspError(
                "OCSP response missing certificate status".to_string(),
            )),
        }
    }

    /// Check a certificate serial against the CRL at `url` (cache first).
    fn check_crl_from_url(&self, url: &str, serial: &[u8]) -> Result<(), RevocationError> {
        if let Some(crl_info) = self.crl_cache.get(url)
            && crl_info.validate_current(chrono::Utc::now()).is_ok()
        {
            return if crl_info.is_revoked(serial) {
                Err(revoked(serial))
            } else {
                Ok(())
            };
            // Expired cache entries fall through to a re-fetch.
        }

        let fetcher = self
            .crl_fetcher
            .as_ref()
            .ok_or_else(|| RevocationError::FetchError("HTTP fetching is disabled".to_string()))?;
        let crl_bytes = fetcher.fetch_crl(url)?;

        let crl_info = parse_crl_bytes(&crl_bytes)?;
        crl_info.validate_current(chrono::Utc::now())?;

        self.crl_cache.insert(
            url.to_string(),
            crl_info.clone(),
            Duration::from_secs(self.config.crl_config.cache_ttl_secs),
        );

        if crl_info.is_revoked(serial) {
            Err(revoked(serial))
        } else {
            Ok(())
        }
    }

    /// Extract serial number from certificate
    fn extract_serial_number(&self, cert_der: &[u8]) -> Result<Vec<u8>, RevocationError> {
        extract_issuer_and_serial(cert_der).map(|(_, serial)| serial)
    }

    /// Handle an inconclusive check according to the fail-open/closed policy
    fn handle_error(&self, error: RevocationError) -> Result<(), RevocationError> {
        match self.config.fallback_behavior {
            FallbackBehavior::FailOpen => {
                // Allow authentication; keep the log line generic.
                eprintln!("WARNING: revocation check failed (fail-open mode)");
                Ok(())
            }
            FallbackBehavior::FailClosed => Err(error),
        }
    }
}

/// `CertificateRevoked` error for a serial.
fn revoked(serial: &[u8]) -> RevocationError {
    RevocationError::CertificateRevoked(format!("Certificate serial {:02x?} is revoked", serial))
}

/// Issuer DN (as rendered by x509-parser, the same form `CrlInfo::issuer`
/// uses) and big-endian serial number of a DER certificate.
fn extract_issuer_and_serial(cert_der: &[u8]) -> Result<(String, Vec<u8>), RevocationError> {
    use x509_parser::prelude::*;

    let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
        RevocationError::CertificateError(format!("Failed to parse certificate: {}", e))
    })?;
    Ok((
        cert.issuer().to_string(),
        cert.serial.to_bytes_be().to_vec(),
    ))
}

/// Parse a CRL from PEM or DER bytes (PEM is detected by its armor).
fn parse_crl_bytes(bytes: &[u8]) -> Result<CrlInfo, RevocationError> {
    if bytes.starts_with(b"-----BEGIN") {
        CrlInfo::parse_pem(bytes)
    } else {
        CrlInfo::parse_der(bytes)
    }
}

/// Read and parse a static CRL file.
fn load_static_crl(path: &str) -> Result<CrlInfo, RevocationError> {
    let bytes = std::fs::read(path).map_err(|e| {
        RevocationError::ConfigError(format!("cannot read static CRL file {path}: {e}"))
    })?;
    parse_crl_bytes(&bytes)
        .map_err(|e| RevocationError::ConfigError(format!("static CRL file {path}: {e}")))
}

impl ClientCertVerifier for RevocationCheckingVerifier {
    fn offer_client_auth(&self) -> bool {
        self.webpki_verifier.offer_client_auth()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.webpki_verifier.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // Standard WebPKI validation first (chain, expiry, signatures).
        self.webpki_verifier
            .verify_client_cert(end_entity, intermediates, now)?;

        let intermediates: Vec<&[u8]> = intermediates.iter().map(|c| c.as_ref()).collect();
        match self.check_revocation(end_entity.as_ref(), &intermediates) {
            Ok(()) => Ok(ClientCertVerified::assertion()),
            Err(RevocationError::CertificateRevoked(_)) => Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::Revoked,
            )),
            // Inconclusive under fail-closed: surface the reason to the log,
            // not a misleading "revoked".
            Err(e) => Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(e))),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        self.webpki_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        self.webpki_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.webpki_verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::CrlConfig;

    /// A `ClientCertVerifier` that accepts everything; the tests here exercise
    /// the revocation layer, not WebPKI.
    #[derive(Debug)]
    struct AcceptAll;

    impl ClientCertVerifier for AcceptAll {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }
        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, RustlsError> {
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    fn accept_all() -> Arc<dyn ClientCertVerifier> {
        Arc::new(AcceptAll)
    }

    #[test]
    fn test_new_fails_without_trust_anchors() {
        // rustls refuses a client verifier over an empty root store.
        assert!(RevocationCheckingVerifier::new(RevocationConfig::default()).is_err());
    }

    #[test]
    fn test_verifier_disabled_mode() {
        let config = RevocationConfig {
            check_mode: RevocationCheckMode::Disabled,
            ..Default::default()
        };
        let verifier = RevocationCheckingVerifier::with_webpki_verifier(config, accept_all())
            .expect("disabled verifier builds without network or files");

        // Garbage input is fine: nothing is inspected when disabled.
        assert!(verifier.check_revocation(&[0x00, 0x01, 0x02], &[]).is_ok());
        assert_eq!(verifier.static_crl_count(), 0);
    }

    #[test]
    fn test_handle_error_fail_open() {
        let config = RevocationConfig {
            fallback_behavior: FallbackBehavior::FailOpen,
            ..Default::default()
        };
        let verifier =
            RevocationCheckingVerifier::with_webpki_verifier(config, accept_all()).unwrap();
        let error = RevocationError::FetchError("Test error".to_string());
        assert!(verifier.handle_error(error).is_ok());
    }

    #[test]
    fn test_handle_error_fail_closed() {
        let config = RevocationConfig {
            fallback_behavior: FallbackBehavior::FailClosed,
            ..Default::default()
        };
        let verifier =
            RevocationCheckingVerifier::with_webpki_verifier(config, accept_all()).unwrap();
        let error = RevocationError::FetchError("Test error".to_string());
        assert!(verifier.handle_error(error).is_err());
    }

    #[test]
    fn test_extract_serial_number_invalid_cert() {
        let verifier = RevocationCheckingVerifier::with_webpki_verifier(
            RevocationConfig::default(),
            accept_all(),
        )
        .unwrap();
        let result = verifier.extract_serial_number(&[0x00, 0x01, 0x02]);
        assert!(matches!(result, Err(RevocationError::CertificateError(_))));
    }

    #[test]
    fn test_missing_static_crl_file_is_a_config_error() {
        let config = RevocationConfig::static_files(
            vec!["/nonexistent/interop/ca.crl".to_string()],
            FallbackBehavior::FailClosed,
        );
        let err = RevocationCheckingVerifier::with_webpki_verifier(config, accept_all())
            .expect_err("missing CRL file must fail at construction");
        assert!(matches!(err, RevocationError::ConfigError(_)), "{err}");
    }

    #[test]
    fn test_static_crl_paths_ignored_when_mode_does_not_use_crl() {
        // OCSP-only never reads CRL files, so a bogus path is not an error.
        let config = RevocationConfig {
            check_mode: RevocationCheckMode::OcspOnly,
            fallback_behavior: FallbackBehavior::FailClosed,
            crl_config: CrlConfig::static_files(vec!["/nonexistent/ca.crl".to_string()]),
            ocsp_config: crate::revocation::OcspConfig::http_fetch(1, 60, 10),
        };
        let verifier =
            RevocationCheckingVerifier::with_webpki_verifier(config, accept_all()).unwrap();
        assert_eq!(verifier.static_crl_count(), 0);
    }

    #[test]
    fn test_parse_crl_bytes_rejects_garbage_in_both_encodings() {
        assert!(matches!(
            parse_crl_bytes(b"-----BEGIN X509 CRL-----\nnot base64\n-----END X509 CRL-----\n"),
            Err(RevocationError::ParseError(_))
        ));
        assert!(matches!(
            parse_crl_bytes(&[0x30, 0x03, 0x02, 0x01]),
            Err(RevocationError::ParseError(_))
        ));
    }
}
