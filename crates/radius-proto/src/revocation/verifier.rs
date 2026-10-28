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
    crl::{CrlInfo, crl_der_from_bytes},
    error::RevocationError,
    fetch::{CrlFetcher, extract_crl_distribution_points},
    ocsp::{CertId, OcspClient, OcspRequestBuilder, OcspResponse, ResponderAuthorization},
    ocsp_cache::OcspCache,
    signature::{default_algorithms, is_ca, split_signed, verify_signed_data},
};
use dashmap::DashMap;
use pki_types::{CertificateDer, UnixTime};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::server::{
    WebPkiClientVerifier,
    danger::{ClientCertVerified, ClientCertVerifier},
};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use x509_parser::num_bigint::BigUint;

/// Length of the OCSP request nonce: RFC 8954 §2.1 requires clients to send
/// 32 octets (responders accept 1..=32).
const OCSP_NONCE_LEN: usize = 32;

/// Longest chain (end entity, intermediates, trust anchor) the verifier will
/// link; matches the depth limits of common path builders.
const MAX_CHAIN_LEN: usize = 8;

/// Most complete certification paths checked for one handshake.
// TODO(gap): configured certificates count toward the path and extension
// budgets, so a `ca_path` bundle with many same-key renewals or bridge
// cross-certificates can exceed them (rejected regardless of the fail
// policy). See RFC-COMPLIANCE.md, Certificate Revocation.
const MAX_PATHS: usize = 8;

/// Most path extensions (dead ends included) explored for one handshake.
const MAX_PATH_NODES: usize = 32;

/// Most certificate signature verifications spent linking one handshake's
/// chain. An honest chain needs one per link; WebPKI itself budgets 100.
const MAX_SIGNATURE_CHECKS: usize = 64;

/// A CRL file preloaded from `CrlConfig::static_crl_paths`.
#[derive(Debug)]
struct StaticCrl {
    /// File the CRL was read from (for messages)
    path: String,
    /// DER of the CRL, kept to verify its signature once the issuer is known
    der: Vec<u8>,
    /// Parsed CRL (unverified until `verified_with` is set)
    info: CrlInfo,
    /// SubjectPublicKeyInfo the signature was verified with
    verified_with: Mutex<Option<Vec<u8>>>,
}

/// Custom certificate verifier with CRL and OCSP revocation checking
///
/// This verifier wraps a `WebPkiClientVerifier` and adds CRL and/or OCSP
/// checking. It implements rustls's `ClientCertVerifier` trait to integrate
/// into the TLS handshake.
///
/// # What is trusted
///
/// After the wrapped verifier accepts the chain, this verifier rebuilds it
/// from the end-entity certificate through the peer's intermediates to one of
/// the issuer certificates given to [`Self::with_issuer_certificates`] (the
/// trust anchors), linking each step by name *and* signature. Every
/// certificate in that chain except the anchor is then checked, each against
/// its own issuer:
///
/// - a CRL is used only if its signature verifies with the issuer's key, its
///   issuer Name matches, the issuer's keyUsage (if present) permits cRLSign,
///   it is current, and its crlNumber is not lower than one already accepted
///   for that issuer (RFC 5280 §5.2.3, §6.3.3);
/// - an OCSP response is used only if it answers the requested CertID and is
///   signed by the issuer or by a delegated responder certificate the issuer
///   issued with id-kp-OCSPSigning (RFC 6960 §3.2, §4.2.2.2).
///
/// A CRL or response that fails these checks is not evidence of anything: it
/// is treated like an unreachable source and handled by the fail policy.
///
/// # Behavior Modes
///
/// - **Fail-Open**: If a CRL/OCSP fetch, parse, signature or freshness check
///   fails, allow the authentication (a warning is printed)
/// - **Fail-Closed**: If a CRL/OCSP check cannot be completed, reject the
///   authentication (secure default)
///
/// A certificate that a verified CRL or OCSP response reports as revoked is
/// always rejected.
///
/// # Caching
///
/// Fetched CRLs and OCSP responses are cached, after verification, with
/// configurable TTL to avoid repeated HTTP fetches. Caches are thread-safe and
/// shared across all TLS connections. Static CRL files are parsed once, when
/// the verifier is built, and their signatures verified on first use.
#[derive(Debug)]
pub struct RevocationCheckingVerifier {
    /// Underlying WebPki verifier for standard validation
    webpki_verifier: Arc<dyn ClientCertVerifier>,

    /// Revocation checking configuration
    config: RevocationConfig,

    /// CRLs preloaded from `CrlConfig::static_crl_paths`, highest crlNumber
    /// first
    static_crls: Vec<StaticCrl>,

    /// DER certificates trusted to issue the client certificates (the trust
    /// anchors). Chains are linked to these, and CRL/OCSP signatures are only
    /// trusted when they chain to one of them.
    issuer_certs: Vec<Vec<u8>>,

    /// Signature algorithms for CRL, OCSP and certificate-link signatures
    algorithms: WebPkiSupportedAlgorithms,

    /// Highest crlNumber accepted per CRL issuer: its DER Name and the
    /// SubjectPublicKeyInfo that verified the CRL (a CA rekeyed under the
    /// same Name may number each key's CRLs separately)
    crl_numbers: DashMap<(Vec<u8>, Vec<u8>), BigUint>,

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
    /// skipping revocation checks. Their signatures are verified on first use,
    /// against the issuer found in the chain being checked.
    ///
    /// Revocation checking also needs the trust anchors: call
    /// [`Self::with_issuer_certificates`]. Without them no chain can be linked
    /// and every check is inconclusive (rejected under fail-closed).
    pub fn with_webpki_verifier(
        config: RevocationConfig,
        webpki_verifier: Arc<dyn ClientCertVerifier>,
    ) -> Result<Self, RevocationError> {
        let uses_crl = mode_uses_crl(config.check_mode);
        let uses_ocsp = matches!(
            config.check_mode,
            RevocationCheckMode::OcspOnly
                | RevocationCheckMode::PreferOcsp
                | RevocationCheckMode::Both
        );

        let mut static_crls = if uses_crl {
            config
                .crl_config
                .static_crl_paths
                .iter()
                .map(|path| load_static_crl(path))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        // Consult the newest CRL of an issuer first.
        static_crls.sort_by(|a, b| b.info.crl_number.cmp(&a.info.crl_number));

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
                Some(OcspCache::with_max_ttl(
                    config.ocsp_config.max_cache_entries.max(1),
                    Duration::from_secs(config.ocsp_config.cache_ttl_secs),
                )),
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
            algorithms: default_algorithms(),
            crl_numbers: DashMap::new(),
            crl_cache,
            crl_fetcher,
            ocsp_cache,
            ocsp_client,
        })
    }

    /// Provide the DER certificates trusted to issue the client certificates
    /// (normally the trust anchors the WebPKI verifier was built from).
    ///
    /// They anchor the chain the revocation checks walk: a CRL or OCSP
    /// response is trusted only if its signature chains to one of these
    /// (RFC 5280 §6.3.3, RFC 6960 §3.2). OCSP requests also identify the
    /// certificate by hashes of its issuer's name and key (RFC 6960 §4.1.1),
    /// and EAP supplicants and NAS devices usually present only their
    /// end-entity certificate, so the issuer generally has to come from here.
    pub fn with_issuer_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.issuer_certs = certs;
        self
    }

    /// Verify CRL, OCSP and certificate-link signatures with these
    /// algorithms instead of rustls's aws-lc-rs defaults (for example the
    /// `signature_verification_algorithms` of the deployment's FIPS
    /// `CryptoProvider`).
    pub fn with_signature_verification_algorithms(
        mut self,
        algorithms: WebPkiSupportedAlgorithms,
    ) -> Self {
        self.algorithms = algorithms;
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

    /// Check every certificate of the peer's chain except the trust anchor.
    ///
    /// When more than one path links the end entity to a configured issuer
    /// (a CA renewed under the same Name and key, cross-certificates), every
    /// path is checked and any revoked link rejects: the handshake may have
    /// been validated over any of them.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Nothing is revoked (or a check failed under fail-open)
    /// * `Err(RevocationError)` - A certificate is revoked OR a check failed
    ///   under fail-closed
    fn check_chain(
        &self,
        end_entity: &[u8],
        intermediates: &[&[u8]],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        if self.config.check_mode == RevocationCheckMode::Disabled {
            return Ok(());
        }
        let paths = match self.build_paths(end_entity, intermediates, now) {
            Ok(paths) => paths,
            // More candidate paths than the bound: the peer controls the
            // intermediates, so this must not turn into "allowed" under
            // fail-open.
            Err(e @ RevocationError::PathBudgetExceeded(_)) => return Err(e),
            Err(e) => return self.handle_error(e),
        };
        let mut checked: Vec<(&[u8], &[u8])> = Vec::new();
        for path in &paths {
            for link in path.windows(2) {
                let pair = (link[0], link[1]);
                if !checked.contains(&pair) {
                    self.check_revocation(pair.0, pair.1, now)?;
                    checked.push(pair);
                }
            }
        }
        Ok(())
    }

    /// Every path that links `end_entity` to a configured issuer
    /// certificate, each `[end_entity, ..., anchor]`; every element but the
    /// anchor is then checked for revocation.
    ///
    /// - Each step requires the issuer's subject to equal the certificate's
    ///   issuer Name *and* the certificate's signature to verify with the
    ///   issuer's key, so a certificate the peer made up cannot stand in for
    ///   the real issuer.
    /// - Anchors are the self-issued certificates of
    ///   [`Self::with_issuer_certificates`]. Other configured certificates (an
    ///   issuing CA placed in the bundle next to its root) are linked further
    ///   like intermediates, so they are checked too; a path that cannot be
    ///   extended to an anchor ends at the furthest configured certificate on
    ///   it, which is then the anchor (a peer that appends its root to a chain
    ///   anchored at a configured issuing CA does not make it unlinkable).
    ///   Configured certificates are trusted as configured, like WebPKI
    ///   trusts its anchors, whatever their validity period.
    /// - A peer intermediate counts only if it is a CA (basicConstraints cA)
    ///   within its validity period at `now`, the criteria WebPKI applies to
    ///   the intermediates of the path it validated.
    /// - The peer controls the intermediates, so the work is bounded: each
    ///   certificate is parsed once, each (certificate, issuer) signature is
    ///   verified at most once, and more than [`MAX_SIGNATURE_CHECKS`]
    ///   signature verifications, [`MAX_PATH_NODES`] path extensions or
    ///   [`MAX_PATHS`] complete paths is [`RevocationError::PathBudgetExceeded`],
    ///   which rejects regardless of the fail policy.
    fn build_paths<'a>(
        &'a self,
        end_entity: &'a [u8],
        intermediates: &[&'a [u8]],
        now: UnixTime,
    ) -> Result<Vec<Vec<&'a [u8]>>, RevocationError> {
        let ee = PathCert::parse(end_entity, false).ok_or_else(|| {
            RevocationError::CertificateError("Failed to parse certificate".to_string())
        })?;
        // Arena: [end entity, configured certificates..., peer intermediates...]
        let mut certs = vec![ee];
        for der in self.issuer_certs.iter().map(Vec::as_slice) {
            if !certs.iter().any(|c| c.der == der)
                && let Some(cert) = PathCert::parse(der, true)
            {
                certs.push(cert);
            }
        }
        for &der in intermediates {
            if !certs.iter().any(|c| c.der == der)
                && let Some(cert) = PathCert::parse(der, false)
                && cert.usable_intermediate_at(now)
            {
                certs.push(cert);
            }
        }

        let mut links = LinkCache::new(&self.algorithms, &certs);
        let mut paths: Vec<Vec<usize>> = Vec::new();
        let mut pending: Vec<Vec<usize>> = vec![vec![0]];
        let mut expansions = 0usize;
        while let Some(path) = pending.pop() {
            expansions += 1;
            if expansions > MAX_PATH_NODES {
                return Err(RevocationError::PathBudgetExceeded(format!(
                    "more than {MAX_PATH_NODES} path extensions"
                )));
            }
            let current = path[path.len() - 1];

            // TODO(gap): a node that links to a self-issued anchor is not
            // extended through its other issuers, so a cross-certificate the
            // peer sent next to such an anchor (WebPKI may validate through
            // it, e.g. after a name-constraint failure on the anchor) is not
            // checked. See RFC-COMPLIANCE.md, Certificate Revocation.
            let mut anchor = None;
            for (index, cert) in certs.iter().enumerate() {
                if cert.anchor && links.issued_by(current, index)? {
                    anchor = Some(index);
                    break;
                }
            }
            let complete = if let Some(anchor) = anchor {
                let mut path = path.clone();
                path.push(anchor);
                Some(path)
            } else {
                let mut next = Vec::new();
                if path.len() < MAX_CHAIN_LEN {
                    for (index, cert) in certs.iter().enumerate() {
                        if index != 0
                            && !cert.anchor
                            && !path.contains(&index)
                            && links.issued_by(current, index)?
                        {
                            next.push(index);
                        }
                    }
                }
                if next.is_empty() {
                    // Dead end: end at the furthest configured certificate.
                    path.iter()
                        .rposition(|&index| certs[index].configured)
                        .filter(|&at| at > 0)
                        .map(|at| path[..=at].to_vec())
                } else {
                    for index in next {
                        let mut extended = path.clone();
                        extended.push(index);
                        pending.push(extended);
                    }
                    None
                }
            };
            if let Some(complete) = complete
                && !paths.contains(&complete)
            {
                paths.push(complete);
                if paths.len() > MAX_PATHS {
                    return Err(RevocationError::PathBudgetExceeded(format!(
                        "more than {MAX_PATHS} certification paths"
                    )));
                }
            }
        }
        if paths.is_empty() {
            return Err(RevocationError::CertificateError(
                "cannot link the certificate to a configured issuer certificate, so its \
                 revocation status cannot be verified"
                    .to_string(),
            ));
        }
        Ok(paths
            .into_iter()
            .map(|path| path.into_iter().map(|index| certs[index].der).collect())
            .collect())
    }

    /// Check one certificate, issued by `issuer`, per the configured mode:
    /// - OcspOnly: Check OCSP only
    /// - CrlOnly: Check CRL only
    /// - PreferOcsp: Try OCSP first, fall back to CRL when OCSP cannot answer
    /// - Both: Check both OCSP and CRL (fail if either indicates revoked)
    fn check_revocation(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        match self.config.check_mode {
            RevocationCheckMode::Disabled => Ok(()),

            RevocationCheckMode::OcspOnly => {
                // OCSP only: an inconclusive answer falls to the fail policy.
                match self.ocsp_status(cert_der, issuer_der, now) {
                    Ok(()) => Ok(()),
                    Err(e @ RevocationError::CertificateRevoked(_)) => Err(e),
                    Err(e) => self.handle_error(e),
                }
            }

            RevocationCheckMode::CrlOnly => self.check_crl(cert_der, issuer_der, now),

            RevocationCheckMode::PreferOcsp => {
                // Try OCSP first; anything but a definite answer falls back to CRL.
                match self.ocsp_status(cert_der, issuer_der, now) {
                    Ok(()) => Ok(()),
                    Err(e @ RevocationError::CertificateRevoked(_)) => Err(e),
                    Err(_) => {
                        // The reason is not logged: it can carry certificate
                        // identifiers; the CRL outcome decides.
                        eprintln!("OCSP check inconclusive, trying CRL");
                        self.check_crl(cert_der, issuer_der, now)
                    }
                }
            }

            RevocationCheckMode::Both => {
                // Check both OCSP and CRL. `check_crl` already applies the fail
                // policy to its own errors; OCSP errors are handled here.
                let ocsp_result = self.ocsp_status(cert_der, issuer_der, now);
                let crl_result = self.check_crl(cert_der, issuer_der, now);

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

    /// CRL check with the fail policy applied to inconclusive outcomes.
    fn check_crl(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        match self.crl_status(cert_der, issuer_der, now) {
            Ok(()) => Ok(()),
            Err(e @ RevocationError::CertificateRevoked(_)) => Err(e),
            Err(e) => self.handle_error(e),
        }
    }

    /// Raw CRL outcome for `cert_der`, issued by `issuer_der`.
    ///
    /// Static CRLs for the certificate's issuer are consulted first. When
    /// none is usable, the CRL Distribution Points are fetched (if HTTP
    /// fetching is enabled). A CRL is usable only when its signature verifies
    /// with the issuer's key, it is current, and its crlNumber is not stale.
    fn crl_status(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        let (issuer_name, serial) = extract_issuer_and_serial(cert_der)?;
        let issuer_spki = subject_public_key_info(issuer_der)?;

        // 1. Static CRLs for this issuer.
        let mut last_error: Option<RevocationError> = None;
        for crl in self
            .static_crls
            .iter()
            .filter(|c| c.info.issuer_raw == issuer_name)
        {
            match self.accept_static_crl(crl, issuer_der, &issuer_spki, now) {
                Ok(()) => return lookup(&crl.info, &serial),
                Err(e) => last_error = Some(e),
            }
        }

        // 2. CRL Distribution Points (HTTP fetch, cached).
        if self.crl_fetcher.is_some() {
            let distribution_points = match extract_crl_distribution_points(cert_der) {
                Ok(points) => points,
                // No distribution points: an unusable static CRL (if any) is
                // the more useful error to report.
                Err(e) => return Err(last_error.unwrap_or(e)),
            };

            for url in &distribution_points {
                match self.check_crl_from_url(
                    url,
                    &issuer_name,
                    &serial,
                    issuer_der,
                    &issuer_spki,
                    now,
                ) {
                    Ok(()) => return Ok(()),
                    Err(e @ RevocationError::CertificateRevoked(_)) => return Err(e),
                    Err(e) => last_error = Some(e),
                }
            }

            return Err(last_error.unwrap_or_else(|| {
                RevocationError::DistributionPointError("No valid CRL found".to_string())
            }));
        }

        // 3. Static files only, none usable for this issuer.
        Err(last_error.unwrap_or_else(|| {
            RevocationError::ConfigError(format!(
                "no static CRL configured for issuer {} and HTTP fetching is disabled",
                display_subject(issuer_der)
            ))
        }))
    }

    /// Verify a static CRL against `issuer_der` (once per issuer key) and
    /// accept it.
    fn accept_static_crl(
        &self,
        crl: &StaticCrl,
        issuer_der: &[u8],
        issuer_spki: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        {
            let mut verified = crl
                .verified_with
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if verified.as_deref() != Some(issuer_spki) {
                crl.info
                    .check_signature(&crl.der, issuer_der, &self.algorithms)
                    .map_err(|e| match e {
                        RevocationError::InvalidSignature(why) => {
                            RevocationError::InvalidSignature(format!(
                                "static CRL file {}: {why}",
                                crl.path
                            ))
                        }
                        other => other,
                    })?;
                *verified = Some(issuer_spki.to_vec());
            }
        }
        self.accept_crl(&crl.info, issuer_spki, now)
    }

    /// Freshness and crlNumber checks for a CRL whose signature has been
    /// verified.
    fn accept_crl(
        &self,
        crl: &CrlInfo,
        issuer_spki: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        crl.validate_current(to_chrono(now))?;
        self.record_crl_number(crl, issuer_spki)
    }

    /// RFC 5280 §5.2.3: CRL numbers increase monotonically per issuer. Refuse
    /// a CRL older than the newest one already accepted for its issuer, so a
    /// replayed (still unexpired) CRL cannot hide a later revocation.
    fn record_crl_number(&self, crl: &CrlInfo, issuer_spki: &[u8]) -> Result<(), RevocationError> {
        use dashmap::mapref::entry::Entry;

        match (
            self.crl_numbers
                .entry((crl.issuer_raw.clone(), issuer_spki.to_vec())),
            &crl.crl_number,
        ) {
            (Entry::Occupied(mut seen), Some(number)) => {
                if number < seen.get() {
                    return Err(RevocationError::StaleCrl(format!(
                        "crlNumber {number} from {} is lower than the accepted {}",
                        crl.issuer,
                        seen.get()
                    )));
                }
                if number > seen.get() {
                    *seen.get_mut() = number.clone();
                }
                Ok(())
            }
            (Entry::Occupied(seen), None) => Err(RevocationError::StaleCrl(format!(
                "CRL from {} has no crlNumber after crlNumber {} was accepted",
                crl.issuer,
                seen.get()
            ))),
            (Entry::Vacant(slot), Some(number)) => {
                slot.insert(number.clone());
                Ok(())
            }
            (Entry::Vacant(_), None) => Ok(()),
        }
    }

    /// Check a certificate serial against the CRL at `url` (cache first).
    fn check_crl_from_url(
        &self,
        url: &str,
        issuer_name: &[u8],
        serial: &[u8],
        issuer_der: &[u8],
        issuer_spki: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        // A cached CRL was verified when it was fetched; reuse it only for
        // the same issuer key, and only while it is current and not stale.
        // Anything else falls through to a re-fetch.
        if let Some(crl_info) = self.crl_cache.get(url)
            && crl_info.is_verified_by(issuer_spki)
            && crl_info.issuer_raw == issuer_name
            && self.accept_crl(&crl_info, issuer_spki, now).is_ok()
        {
            return lookup(&crl_info, serial);
        }

        let fetcher = self
            .crl_fetcher
            .as_ref()
            .ok_or_else(|| RevocationError::FetchError("HTTP fetching is disabled".to_string()))?;
        let crl_der = crl_der_from_bytes(&fetcher.fetch_crl(url)?)?;

        let crl_info = CrlInfo::parse_and_verify(&crl_der, issuer_der, &self.algorithms)?;
        self.accept_crl(&crl_info, issuer_spki, now)?;

        let result = lookup(&crl_info, serial);
        self.crl_cache.insert(
            url.to_string(),
            crl_info,
            Duration::from_secs(self.config.crl_config.cache_ttl_secs),
        );
        result
    }

    /// Raw OCSP outcome for `cert_der`, issued by `issuer_der`. Callers
    /// decide how an inconclusive result (no responder URL, HTTP failure,
    /// malformed, unverifiable or unauthorized response) is handled.
    fn ocsp_status(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        let ocsp_client = self.ocsp_client.as_ref().ok_or_else(|| {
            RevocationError::ConfigError("OCSP client not initialized".to_string())
        })?;
        let ocsp_cache = self.ocsp_cache.as_ref().ok_or_else(|| {
            RevocationError::ConfigError("OCSP cache not initialized".to_string())
        })?;

        let mut request_builder = OcspRequestBuilder::new(cert_der, issuer_der)?;
        let cert_id = request_builder.cert_id();
        // Keyed by the whole CertID (issuer key and name hashes plus serial):
        // a serial number alone is only unique per issuer.
        let cache_key = cert_id.cache_key();

        // Cached (already verified) response first.
        if let Some(cached_response) = ocsp_cache.get(&cache_key)
            && cached_response.is_fresh_at(to_system_time(now))
            && cached_response.is_within_max_age(
                to_system_time(now),
                Duration::from_secs(self.config.ocsp_config.cache_ttl_secs),
            )
        {
            return self.check_ocsp_response_status(&cached_response);
        }

        let ocsp_url = OcspClient::extract_ocsp_url(cert_der)?;
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
        let (response, cacheable) = self.evaluate_ocsp_response(
            &response_der,
            &cert_id,
            issuer_der,
            nonce.as_deref(),
            now,
        )?;

        let status = self.check_ocsp_response_status(&response);
        if cacheable {
            ocsp_cache.insert(cache_key, response);
        }
        status
    }

    /// Verify an OCSP response for `cert_id` (RFC 6960 §3.2) and its nonce
    /// (RFC 8954). Returns the response and whether it may be cached.
    fn evaluate_ocsp_response(
        &self,
        response_der: &[u8],
        cert_id: &CertId,
        issuer_der: &[u8],
        nonce: Option<&[u8]>,
        now: UnixTime,
    ) -> Result<(OcspResponse, bool), RevocationError> {
        let (response, authorization) = OcspResponse::parse_verified(
            response_der,
            cert_id,
            issuer_der,
            &self.algorithms,
            to_system_time(now),
            Duration::from_secs(self.config.ocsp_config.cache_ttl_secs),
        )?;

        // RFC 8954: a response that carries a nonce must echo ours. A responder
        // that omits the nonce (pre-produced responses) is tolerated, but the
        // response is then not cached beyond this check.
        let cacheable = match (nonce, &response.nonce) {
            (Some(sent), Some(got)) if sent != got.as_slice() => {
                return Err(RevocationError::OcspError(
                    "OCSP response nonce mismatch".to_string(),
                ));
            }
            (Some(_), None) => false,
            _ => true,
        };

        // RFC 6960 §4.2.2.2.1: id-pkix-ocsp-nocheck exempts the responder
        // certificate (and only it) from revocation checking. Without it the
        // responder's own status must be established before its answer counts.
        if let ResponderAuthorization::Delegated {
            certificate,
            nocheck: false,
        } = &authorization
        {
            self.check_responder_certificate(certificate, issuer_der, now)?;
        }

        Ok((response, cacheable))
    }

    /// Revocation status of a delegated OCSP responder certificate that lacks
    /// id-pkix-ocsp-nocheck, from the issuer's CRL. Any outcome but "not
    /// revoked" makes the response unusable (never "subject revoked").
    fn check_responder_certificate(
        &self,
        responder_der: &[u8],
        issuer_der: &[u8],
        now: UnixTime,
    ) -> Result<(), RevocationError> {
        if !mode_uses_crl(self.config.check_mode) {
            return Err(RevocationError::OcspError(
                "delegated OCSP responder certificate lacks id-pkix-ocsp-nocheck and no CRL \
                 source is configured to check it"
                    .to_string(),
            ));
        }
        match self.crl_status(responder_der, issuer_der, now) {
            Ok(()) => Ok(()),
            Err(RevocationError::CertificateRevoked(_)) => Err(RevocationError::OcspError(
                "OCSP responder certificate is revoked".to_string(),
            )),
            Err(e) => Err(RevocationError::OcspError(format!(
                "revocation status of the OCSP responder certificate is unknown: {e}"
            ))),
        }
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

/// Does the mode consult CRLs?
fn mode_uses_crl(mode: RevocationCheckMode) -> bool {
    matches!(
        mode,
        RevocationCheckMode::CrlOnly | RevocationCheckMode::PreferOcsp | RevocationCheckMode::Both
    )
}

/// Revoked or not, per a CRL that has been accepted.
fn lookup(crl: &CrlInfo, serial: &[u8]) -> Result<(), RevocationError> {
    if crl.is_revoked(serial) {
        Err(revoked(serial))
    } else {
        Ok(())
    }
}

/// `CertificateRevoked` error for a serial.
fn revoked(serial: &[u8]) -> RevocationError {
    RevocationError::CertificateRevoked(format!("Certificate serial {:02x?} is revoked", serial))
}

/// Issuer Name (DER, the form `CrlInfo::issuer_raw` uses) and big-endian
/// serial number of a DER certificate.
fn extract_issuer_and_serial(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RevocationError> {
    use x509_parser::prelude::*;

    let (_, cert) = parse_x509_certificate(cert_der).map_err(|e| {
        RevocationError::CertificateError(format!("Failed to parse certificate: {}", e))
    })?;
    Ok((
        cert.issuer().as_raw().to_vec(),
        cert.serial.to_bytes_be().to_vec(),
    ))
}

/// DER SubjectPublicKeyInfo of a certificate.
fn subject_public_key_info(cert_der: &[u8]) -> Result<Vec<u8>, RevocationError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).map_err(|e| {
        RevocationError::CertificateError(format!("Failed to parse issuer certificate: {}", e))
    })?;
    Ok(cert.public_key().raw.to_vec())
}

/// Subject of a certificate, for messages.
fn display_subject(cert_der: &[u8]) -> String {
    x509_parser::parse_x509_certificate(cert_der)
        .map(|(_, cert)| cert.subject().to_string())
        .unwrap_or_else(|_| "<unparseable certificate>".to_string())
}

/// A certificate in the path-building arena, parsed once.
struct PathCert<'a> {
    der: &'a [u8],
    subject: Vec<u8>,
    issuer: Vec<u8>,
    spki: Vec<u8>,
    is_ca: bool,
    not_before: i64,
    not_after: i64,
    /// From [`RevocationCheckingVerifier::with_issuer_certificates`]
    configured: bool,
    /// Configured and self-issued
    anchor: bool,
}

impl<'a> PathCert<'a> {
    fn parse(der: &'a [u8], configured: bool) -> Option<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
        let subject = cert.subject().as_raw().to_vec();
        let issuer = cert.issuer().as_raw().to_vec();
        Some(Self {
            der,
            anchor: configured && subject == issuer,
            subject,
            issuer,
            spki: cert.public_key().raw.to_vec(),
            is_ca: is_ca(&cert),
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
            configured,
        })
    }

    /// WebPKI's criteria for a peer intermediate: a CA (basicConstraints
    /// cA) within its validity period. (WebPKI does not require keyCertSign,
    /// so neither does this; being stricter would make validated chains
    /// unlinkable.)
    fn usable_intermediate_at(&self, now: UnixTime) -> bool {
        let now = now.as_secs() as i64;
        self.is_ca && self.not_before <= now && now <= self.not_after
    }
}

/// Memoized "is `certs[child]` issued by `certs[parent]`" over the arena,
/// with a hard budget on signature verifications.
struct LinkCache<'c, 'a> {
    algorithms: &'c WebPkiSupportedAlgorithms,
    certs: &'c [PathCert<'a>],
    known: std::collections::HashMap<(usize, usize), bool>,
    verifications: usize,
}

impl<'c, 'a> LinkCache<'c, 'a> {
    fn new(algorithms: &'c WebPkiSupportedAlgorithms, certs: &'c [PathCert<'a>]) -> Self {
        Self {
            algorithms,
            certs,
            known: std::collections::HashMap::new(),
            verifications: 0,
        }
    }

    fn issued_by(&mut self, child: usize, parent: usize) -> Result<bool, RevocationError> {
        let (c, p) = (&self.certs[child], &self.certs[parent]);
        if c.issuer != p.subject {
            return Ok(false);
        }
        if let Some(&known) = self.known.get(&(child, parent)) {
            return Ok(known);
        }
        self.verifications += 1;
        if self.verifications > MAX_SIGNATURE_CHECKS {
            return Err(RevocationError::PathBudgetExceeded(format!(
                "more than {MAX_SIGNATURE_CHECKS} signature verifications"
            )));
        }
        let linked = split_signed(c.der)
            .and_then(|signed| verify_signed_data(self.algorithms, &p.spki, &signed))
            .is_ok();
        self.known.insert((child, parent), linked);
        Ok(linked)
    }
}

fn to_system_time(now: UnixTime) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(now.as_secs())
}

fn to_chrono(now: UnixTime) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(now.as_secs() as i64, 0).unwrap_or_default()
}

/// Read and parse a static CRL file.
fn load_static_crl(path: &str) -> Result<StaticCrl, RevocationError> {
    let bytes = std::fs::read(path).map_err(|e| {
        RevocationError::ConfigError(format!("cannot read static CRL file {path}: {e}"))
    })?;
    let der = crl_der_from_bytes(&bytes)
        .map_err(|e| RevocationError::ConfigError(format!("static CRL file {path}: {e}")))?;
    let info = CrlInfo::parse_der(&der)
        .map_err(|e| RevocationError::ConfigError(format!("static CRL file {path}: {e}")))?;
    Ok(StaticCrl {
        path: path.to_string(),
        der,
        info,
        verified_with: Mutex::new(None),
    })
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
        match self.check_chain(end_entity.as_ref(), &intermediates, now) {
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
        assert!(
            verifier
                .check_chain(&[0x00, 0x01, 0x02], &[], UnixTime::now())
                .is_ok()
        );
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
    fn test_extract_issuer_and_serial_invalid_cert() {
        let result = extract_issuer_and_serial(&[0x00, 0x01, 0x02]);
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
    fn test_crl_bytes_reject_garbage_in_both_encodings() {
        assert!(matches!(
            crl_der_from_bytes(b"-----BEGIN X509 CRL-----\nnot base64\n-----END X509 CRL-----\n"),
            Err(RevocationError::ParseError(_))
        ));
        assert!(matches!(
            CrlInfo::parse_der(&[0x30, 0x03, 0x02, 0x01]),
            Err(RevocationError::ParseError(_))
        ));
    }

    // ---------------------------------------------------------------------
    // Signed CRLs, OCSP responder authorization and chain checks, against
    // rcgen-generated PKIs.
    // ---------------------------------------------------------------------

    use crate::revocation::OcspConfig;
    use crate::revocation::ocsp::{CertificateStatus, OcspRequestBuilder};
    use crate::revocation::test_pki::{Ca, OcspAnswer, OcspResponseSpec, subject_of};
    use rcgen::{KeyPair, KeyUsagePurpose};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A temporary file removed on drop.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(bytes: &[u8]) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "usg-radius-revocation-{}-{}.crl",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, bytes).unwrap();
            Self(path)
        }

        fn path(&self) -> String {
            self.0.to_str().unwrap().to_string()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Verifier in `mode` over static CRL files, anchored at `anchors`.
    fn verifier_with(
        mode: RevocationCheckMode,
        fallback_behavior: FallbackBehavior,
        crls: &[&[u8]],
        anchors: &[&Ca],
    ) -> (RevocationCheckingVerifier, Vec<TempFile>) {
        let files: Vec<TempFile> = crls.iter().map(|crl| TempFile::new(crl)).collect();
        let config = RevocationConfig {
            check_mode: mode,
            fallback_behavior,
            crl_config: CrlConfig::static_files(files.iter().map(TempFile::path).collect()),
            ocsp_config: OcspConfig::http_fetch(1, 60, 10),
        };
        let verifier = RevocationCheckingVerifier::with_webpki_verifier(config, accept_all())
            .unwrap()
            .with_issuer_certificates(anchors.iter().map(|ca| ca.der.clone()).collect());
        (verifier, files)
    }

    fn crl_verifier(
        crls: &[&[u8]],
        anchors: &[&Ca],
    ) -> (RevocationCheckingVerifier, Vec<TempFile>) {
        verifier_with(
            RevocationCheckMode::CrlOnly,
            FallbackBehavior::FailClosed,
            crls,
            anchors,
        )
    }

    fn check(
        verifier: &RevocationCheckingVerifier,
        leaf: &[u8],
        intermediates: &[&[u8]],
    ) -> Result<(), RevocationError> {
        verifier.check_chain(leaf, intermediates, UnixTime::now())
    }

    #[test]
    fn signed_crl_is_accepted() {
        let ca = Ca::root("USG Test CA");
        let good = ca.leaf("good@usg.test", &[0x10, 0x01]);
        // Top bit set: DER pads the serial with 0x00.
        let bad = ca.leaf("revoked@usg.test", &[0xA5, 0x01]);
        let crl = ca.crl(1, &[&bad]);
        let (verifier, _files) = crl_verifier(&[&crl], &[&ca]);

        check(&verifier, &good, &[]).expect("unrevoked certificate under a valid CRL");
        assert!(matches!(
            check(&verifier, &bad, &[]),
            Err(RevocationError::CertificateRevoked(_))
        ));
    }

    #[test]
    fn crl_signed_by_the_wrong_key_is_rejected() {
        let ca = Ca::root("USG Test CA");
        let impostor = Ca::impostor_of(&ca);
        let leaf = ca.leaf("good@usg.test", &[0x10, 0x02]);
        // An empty CRL ("nothing is revoked") naming the real CA as issuer.
        let forged = impostor.crl(1, &[]);

        let (verifier, _files) = crl_verifier(&[&forged], &[&ca]);
        let err = check(&verifier, &leaf, &[]).expect_err("forged CRL must not vouch for anyone");
        assert!(matches!(err, RevocationError::InvalidSignature(_)), "{err}");

        // Fail-open lets the handshake through, as for any unusable CRL; it
        // never treats the forged CRL as a positive answer either way.
        let (verifier, _files) = verifier_with(
            RevocationCheckMode::CrlOnly,
            FallbackBehavior::FailOpen,
            &[&forged],
            &[&ca],
        );
        check(&verifier, &leaf, &[]).unwrap();
    }

    #[test]
    fn tampered_crl_is_rejected() {
        let ca = Ca::root("USG Test CA");
        let leaf = ca.leaf("good@usg.test", &[0x10, 0x03]);
        let mut crl = ca.crl(1, &[]);
        let last = crl.len() - 1;
        crl[last] ^= 0x01;
        let (verifier, _files) = crl_verifier(&[&crl], &[&ca]);
        assert!(matches!(
            check(&verifier, &leaf, &[]),
            Err(RevocationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn crl_issuer_without_crl_sign_is_rejected() {
        // keyUsage present without cRLSign (RFC 5280 §4.2.1.3).
        let ca = Ca::root_with_usages(
            "USG No-CRL-Sign CA",
            vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
            ],
        );
        let leaf = ca.leaf("good@usg.test", &[0x10, 0x04]);
        let crl = ca.crl(1, &[]);
        let (verifier, _files) = crl_verifier(&[&crl], &[&ca]);
        let err = check(&verifier, &leaf, &[]).unwrap_err();
        assert!(
            matches!(&err, RevocationError::InvalidSignature(why) if why.contains("cRLSign")),
            "{err}"
        );
    }

    #[test]
    fn stale_crl_number_is_rejected() {
        let ca = Ca::root("USG Test CA");
        let algorithms = default_algorithms();
        let (verifier, _files) = crl_verifier(&[], &[&ca]);
        let verified =
            |number| CrlInfo::parse_and_verify(&ca.crl(number, &[]), &ca.der, &algorithms).unwrap();
        let now = UnixTime::now();
        let spki = subject_public_key_info(&ca.der).unwrap();

        verifier.accept_crl(&verified(5), &spki, now).unwrap();
        // The same CRL again, and a newer one, are fine.
        verifier.accept_crl(&verified(5), &spki, now).unwrap();
        verifier.accept_crl(&verified(6), &spki, now).unwrap();
        // An older (still unexpired, correctly signed) CRL is a replay.
        let err = verifier.accept_crl(&verified(5), &spki, now).unwrap_err();
        assert!(matches!(err, RevocationError::StaleCrl(_)), "{err}");
    }

    #[test]
    fn newest_static_crl_wins_and_older_one_is_then_stale() {
        let ca = Ca::root("USG Test CA");
        let leaf = ca.leaf("later-revoked@usg.test", &[0x10, 0x05]);
        let old = ca.crl(1, &[]);
        let new = ca.crl(2, &[&leaf]);
        // Listed oldest first; the verifier still consults #2 first.
        let (verifier, _files) = crl_verifier(&[&old, &new], &[&ca]);
        assert!(matches!(
            check(&verifier, &leaf, &[]),
            Err(RevocationError::CertificateRevoked(_))
        ));
    }

    #[test]
    fn revoked_intermediate_is_rejected() {
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("eaptls@usg.test", &[0x20, 0x01]);
        let intermediate_crl = intermediate.crl(1, &[]);

        // The leaf itself is fine; its issuer is revoked by the root.
        let root_crl = root.crl(1, &[&intermediate.der]);
        let (verifier, _files) = crl_verifier(&[&root_crl, &intermediate_crl], &[&root]);
        assert!(matches!(
            check(&verifier, &leaf, &[&intermediate.der]),
            Err(RevocationError::CertificateRevoked(_))
        ));

        // Same chain, root CRL revokes nothing.
        let root_crl = root.crl(1, &[]);
        let (verifier, _files) = crl_verifier(&[&root_crl, &intermediate_crl], &[&root]);
        check(&verifier, &leaf, &[&intermediate.der]).unwrap();

        // Without a CRL for the intermediate's issuer the chain cannot be
        // fully checked: fail-closed rejects.
        let (verifier, _files) = crl_verifier(&[&intermediate_crl], &[&root]);
        assert!(matches!(
            check(&verifier, &leaf, &[&intermediate.der]),
            Err(RevocationError::ConfigError(_))
        ));
    }

    #[test]
    fn made_up_intermediate_cannot_stand_in_for_the_issuer() {
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("eaptls@usg.test", &[0x20, 0x02]);
        // Same Name as the real intermediate, attacker's key, plus a CRL it
        // signed. The leaf's signature does not verify with that key, so no
        // chain forms and nothing it signed is trusted.
        let fake = Ca::impostor_of(&intermediate);
        let fake_crl = fake.crl(1, &[]);
        let root_crl = root.crl(1, &[]);
        let (verifier, _files) = crl_verifier(&[&root_crl, &fake_crl], &[&root]);
        assert!(matches!(
            check(&verifier, &leaf, &[&fake.der]),
            Err(RevocationError::CertificateError(_))
        ));
    }

    #[test]
    fn without_issuer_certificates_checks_fail_closed() {
        let ca = Ca::root("USG Test CA");
        let leaf = ca.leaf("good@usg.test", &[0x10, 0x06]);
        let crl = ca.crl(1, &[]);
        let (verifier, _files) = crl_verifier(&[&crl], &[]);
        assert!(matches!(
            check(&verifier, &leaf, &[]),
            Err(RevocationError::CertificateError(_))
        ));
    }

    // --- OCSP ----------------------------------------------------------------

    fn ocsp_verifier(ca: &Ca) -> RevocationCheckingVerifier {
        verifier_with(
            RevocationCheckMode::OcspOnly,
            FallbackBehavior::FailClosed,
            &[],
            &[ca],
        )
        .0
    }

    fn evaluate(
        verifier: &RevocationCheckingVerifier,
        response: &[u8],
        leaf: &[u8],
        ca: &Ca,
        nonce: Option<&[u8]>,
    ) -> Result<(crate::revocation::ocsp::OcspResponse, bool), RevocationError> {
        let cert_id = OcspRequestBuilder::new(leaf, &ca.der).unwrap().cert_id();
        verifier.evaluate_ocsp_response(response, &cert_id, &ca.der, nonce, UnixTime::now())
    }

    #[test]
    fn ocsp_response_signed_by_the_ca_is_accepted() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x01]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let verifier = ocsp_verifier(&ca);

        let response = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &ca.key).build();
        let (parsed, cacheable) = evaluate(&verifier, &response, &leaf, &ca, None).unwrap();
        assert_eq!(parsed.cert_status, Some(CertificateStatus::Good));
        assert!(cacheable);
        verifier.check_ocsp_response_status(&parsed).unwrap();

        let mut revoked = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &ca.key);
        revoked.answer = OcspAnswer::Revoked;
        let (parsed, _) = evaluate(&verifier, &revoked.build(), &leaf, &ca, None).unwrap();
        assert!(matches!(
            verifier.check_ocsp_response_status(&parsed),
            Err(RevocationError::CertificateRevoked(_))
        ));
    }

    #[test]
    fn ocsp_unknown_status_is_inconclusive() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x0A]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &ca.key);
        spec.answer = OcspAnswer::Unknown;
        let verifier = ocsp_verifier(&ca);
        let (parsed, _) = evaluate(&verifier, &spec.build(), &leaf, &ca, None).unwrap();
        assert!(matches!(
            verifier.check_ocsp_response_status(&parsed),
            Err(RevocationError::OcspError(_))
        ));
    }

    #[test]
    fn ocsp_delegated_responder_with_eku_is_accepted() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x02]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let (responder_key, responder) = ca.responder("USG OCSP Responder", true, true);
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&responder), &responder_key);
        spec.certs = vec![responder.clone()];

        let verifier = ocsp_verifier(&ca);
        let (parsed, _) = evaluate(&verifier, &spec.build(), &leaf, &ca, None).unwrap();
        assert_eq!(parsed.cert_status, Some(CertificateStatus::Good));
    }

    #[test]
    fn ocsp_delegated_responder_without_eku_is_rejected() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x03]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        // Issued by the CA, but for client auth, not OCSP signing.
        let (responder_key, responder) = ca.responder("USG Not A Responder", false, true);
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&responder), &responder_key);
        spec.certs = vec![responder];

        let verifier = ocsp_verifier(&ca);
        let err = evaluate(&verifier, &spec.build(), &leaf, &ca, None).unwrap_err();
        assert!(
            matches!(&err, RevocationError::InvalidSignature(why) if why.contains("OCSPSigning")),
            "{err}"
        );
    }

    #[test]
    fn ocsp_response_signed_by_an_unrelated_key_is_rejected() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x04]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let verifier = ocsp_verifier(&ca);

        // A bare key claiming to be the CA.
        let stranger = KeyPair::generate().unwrap();
        let response = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &stranger).build();
        assert!(matches!(
            evaluate(&verifier, &response, &leaf, &ca, None),
            Err(RevocationError::InvalidSignature(_))
        ));

        // A responder certificate with the right EKU, from a CA with the same
        // Name but another key: not issued by the certificate's CA.
        let impostor = Ca::impostor_of(&ca);
        let (key, responder) = impostor.responder("USG OCSP Responder", true, true);
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&responder), &key);
        spec.certs = vec![responder];
        let err = evaluate(&verifier, &spec.build(), &leaf, &ca, None).unwrap_err();
        assert!(
            matches!(&err, RevocationError::InvalidSignature(why) if why.contains("not issued")),
            "{err}"
        );

        // A responder from an unrelated CA.
        let other = Ca::root("Somebody Else CA");
        let (key, responder) = other.responder("Other Responder", true, true);
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&responder), &key);
        spec.certs = vec![responder];
        assert!(matches!(
            evaluate(&verifier, &spec.build(), &leaf, &ca, None),
            Err(RevocationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn ocsp_responder_without_nocheck_needs_its_own_status() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x05]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let (responder_key, responder) = ca.responder("USG OCSP Responder", true, false);
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&responder), &responder_key);
        spec.certs = vec![responder.clone()];
        let response = spec.build();

        // OCSP only: nothing can vouch for the responder.
        let verifier = ocsp_verifier(&ca);
        assert!(matches!(
            evaluate(&verifier, &response, &leaf, &ca, None),
            Err(RevocationError::OcspError(_))
        ));

        // With the CA's CRL available the responder is checked against it.
        let clean = ca.crl(1, &[]);
        let (verifier, _files) = verifier_with(
            RevocationCheckMode::Both,
            FallbackBehavior::FailClosed,
            &[&clean],
            &[&ca],
        );
        evaluate(&verifier, &response, &leaf, &ca, None).unwrap();

        let responder_revoked = ca.crl(1, &[&responder]);
        let (verifier, _files) = verifier_with(
            RevocationCheckMode::Both,
            FallbackBehavior::FailClosed,
            &[&responder_revoked],
            &[&ca],
        );
        // The responder is revoked; that is not a statement about the leaf.
        let err = evaluate(&verifier, &response, &leaf, &ca, None).unwrap_err();
        assert!(
            matches!(&err, RevocationError::OcspError(why) if why.contains("revoked")),
            "{err}"
        );
    }

    #[test]
    fn ocsp_response_for_another_certificate_is_rejected() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x06]);
        let other = ca.leaf("other@usg.test", &[0x30, 0x07]);
        let other_id = OcspRequestBuilder::new(&other, &ca.der).unwrap().cert_id();
        let response = OcspResponseSpec::good(&other_id, subject_of(&ca.der), &ca.key).build();
        let err = evaluate(&ocsp_verifier(&ca), &response, &leaf, &ca, None).unwrap_err();
        assert!(
            matches!(&err, RevocationError::OcspError(why) if why.contains("CertID")),
            "{err}"
        );
    }

    #[test]
    fn ocsp_nonce_is_checked() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x08]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let verifier = ocsp_verifier(&ca);
        let sent = [0x42u8; 16];

        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &ca.key);
        spec.nonce = Some(sent.to_vec());
        let (_, cacheable) = evaluate(&verifier, &spec.build(), &leaf, &ca, Some(&sent)).unwrap();
        assert!(cacheable);

        spec.nonce = Some(vec![0x24; 16]);
        assert!(matches!(
            evaluate(&verifier, &spec.build(), &leaf, &ca, Some(&sent)),
            Err(RevocationError::OcspError(why)) if why.contains("nonce")
        ));

        // No nonce echoed: usable now, not cached.
        spec.nonce = None;
        let (_, cacheable) = evaluate(&verifier, &spec.build(), &leaf, &ca, Some(&sent)).unwrap();
        assert!(!cacheable);
    }

    #[test]
    fn expired_ocsp_response_is_rejected() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x30, 0x09]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &ca.key);
        spec.this_update = chrono::Utc::now() - chrono::Duration::days(2);
        spec.next_update = Some(chrono::Utc::now() - chrono::Duration::days(1));
        assert!(matches!(
            evaluate(&ocsp_verifier(&ca), &spec.build(), &leaf, &ca, None),
            Err(RevocationError::OcspError(_))
        ));
    }

    // --- Round 1 review: CRL profile, path, OCSP edge cases -------------------

    use crate::revocation::test_pki::extension;

    const OID_CRL_NUMBER: &[u8] = &[0x55, 0x1D, 0x14];
    const OID_DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1D, 0x1B];
    const OID_ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1D, 0x1C];
    /// 1.2.3.4, an extension nobody understands
    const OID_UNKNOWN: &[u8] = &[0x2A, 0x03, 0x04];
    const ECDSA_SHA384_ALG_ID: &[u8] =
        &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

    fn crl_number_ext(n: u8) -> Vec<u8> {
        extension(OID_CRL_NUMBER, false, &[0x02, 0x01, n])
    }

    fn parse_err_contains(crl: &[u8], needle: &str) {
        match CrlInfo::parse_der(crl) {
            Err(RevocationError::ParseError(why)) => assert!(why.contains(needle), "{why}"),
            other => panic!("expected ParseError containing {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn hand_built_crl_is_accepted_as_a_control() {
        // The helper below must produce a CRL the verifier accepts, or the
        // rejections that follow prove nothing.
        let ca = Ca::root("USG Test CA");
        let leaf = ca.leaf("revoked@usg.test", &[0x40, 0x01]);
        let crl = ca.crl_with(&[crl_number_ext(1)], Some(&[0x40, 0x01]), &[], None);
        let (verifier, _files) = crl_verifier(&[&crl], &[&ca]);
        assert!(matches!(
            check(&verifier, &leaf, &[]),
            Err(RevocationError::CertificateRevoked(_))
        ));
    }

    #[test]
    fn delta_crl_is_rejected() {
        let ca = Ca::root("USG Test CA");
        let delta = extension(OID_DELTA_CRL_INDICATOR, true, &[0x02, 0x01, 0x01]);
        parse_err_contains(
            &ca.crl_with(&[crl_number_ext(2), delta], None, &[], None),
            "delta",
        );
    }

    #[test]
    fn issuing_distribution_point_crl_is_rejected() {
        let ca = Ca::root("USG Test CA");
        // IssuingDistributionPoint { distributionPoint fullName URI }
        let idp = extension(
            OID_ISSUING_DISTRIBUTION_POINT,
            true,
            &[
                0x30, 0x0C, 0xA0, 0x0A, 0xA0, 0x08, 0x86, 0x06, b'h', b't', b't', b'p', b':', b'x',
            ],
        );
        parse_err_contains(
            &ca.crl_with(&[crl_number_ext(1), idp], None, &[], None),
            "Issuing Distribution Point",
        );
    }

    #[test]
    fn unrecognized_critical_crl_extensions_are_rejected() {
        let ca = Ca::root("USG Test CA");
        let critical = extension(OID_UNKNOWN, true, &[0x05, 0x00]);
        parse_err_contains(
            &ca.crl_with(&[crl_number_ext(1), critical.clone()], None, &[], None),
            "critical CRL extension",
        );
        parse_err_contains(
            &ca.crl_with(&[crl_number_ext(1)], Some(&[0x40, 0x02]), &[critical], None),
            "critical CRL entry extension",
        );
        // Not critical: ignored.
        let benign = extension(OID_UNKNOWN, false, &[0x05, 0x00]);
        CrlInfo::parse_der(&ca.crl_with(&[crl_number_ext(1), benign], None, &[], None)).unwrap();
    }

    #[test]
    fn crl_signature_algorithm_mismatch_is_rejected() {
        let ca = Ca::root("USG Test CA");
        let crl = ca.crl_with(&[crl_number_ext(1)], None, &[], Some(ECDSA_SHA384_ALG_ID));
        parse_err_contains(&crl, "signatureAlgorithm");
    }

    #[test]
    fn unnumbered_crl_after_a_numbered_one_is_stale() {
        let ca = Ca::root("USG Test CA");
        let algorithms = default_algorithms();
        let spki = subject_public_key_info(&ca.der).unwrap();
        let (verifier, _files) = crl_verifier(&[], &[&ca]);
        let now = UnixTime::now();
        let numbered = CrlInfo::parse_and_verify(&ca.crl(3, &[]), &ca.der, &algorithms).unwrap();
        let unnumbered =
            CrlInfo::parse_and_verify(&ca.crl_with(&[], None, &[], None), &ca.der, &algorithms)
                .unwrap();
        verifier.accept_crl(&numbered, &spki, now).unwrap();
        assert!(matches!(
            verifier.accept_crl(&unnumbered, &spki, now),
            Err(RevocationError::StaleCrl(_))
        ));
    }

    #[test]
    fn crls_from_other_signature_algorithms_verify() {
        for alg in [&rcgen::PKCS_ECDSA_P384_SHA384, &rcgen::PKCS_ED25519] {
            let ca = Ca::root_with_algorithm("USG Alg CA", alg);
            let good = ca.leaf("good@usg.test", &[0x41, 0x01]);
            let bad = ca.leaf("revoked@usg.test", &[0x41, 0x02]);
            let crl = ca.crl(1, &[&bad]);
            let (verifier, _files) = crl_verifier(&[&crl], &[&ca]);
            check(&verifier, &good, &[]).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
            assert!(matches!(
                check(&verifier, &bad, &[]),
                Err(RevocationError::CertificateRevoked(_))
            ));
        }
    }

    #[test]
    fn expired_same_key_intermediate_cannot_hide_a_revoked_one() {
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("eaptls@usg.test", &[0x42, 0x01]);
        // Same Name and key: an expired earlier certificate the root no longer
        // lists, and the current one, which the root has revoked.
        let expired = intermediate.reissue(&root, 2000, 2001);
        let root_crl = root.crl(1, &[&intermediate.der]);
        let intermediate_crl = intermediate.crl(1, &[]);
        let (verifier, _files) = crl_verifier(&[&root_crl, &intermediate_crl], &[&root]);
        assert!(matches!(
            check(&verifier, &leaf, &[&expired, &intermediate.der]),
            Err(RevocationError::CertificateRevoked(_))
        ));
    }

    #[test]
    fn every_path_through_same_key_intermediates_is_checked() {
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("eaptls@usg.test", &[0x42, 0x02]);
        let renewed = intermediate.reissue(&root, 2020, 2090);
        let intermediate_crl = intermediate.crl(1, &[]);

        // Root revokes one of the two current twins: rejected whichever the
        // peer lists first, and under fail-open too (it is a definite answer).
        let root_crl = root.crl(1, &[&intermediate.der]);
        for fallback in [FallbackBehavior::FailClosed, FallbackBehavior::FailOpen] {
            let (verifier, _files) = verifier_with(
                RevocationCheckMode::CrlOnly,
                fallback,
                &[&root_crl, &intermediate_crl],
                &[&root],
            );
            for order in [
                [renewed.as_slice(), intermediate.der.as_slice()],
                [intermediate.der.as_slice(), renewed.as_slice()],
            ] {
                assert!(matches!(
                    check(&verifier, &leaf, &order),
                    Err(RevocationError::CertificateRevoked(_))
                ));
            }
        }

        // Neither revoked: both paths check out.
        let root_crl = root.crl(1, &[]);
        let (verifier, _files) = crl_verifier(&[&root_crl, &intermediate_crl], &[&root]);
        check(&verifier, &leaf, &[&renewed, &intermediate.der]).unwrap();
    }

    #[test]
    fn padding_the_chain_with_alternatives_is_rejected_even_fail_open() {
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("eaptls@usg.test", &[0x42, 0x04]);
        let twins: Vec<Vec<u8>> = (0..MAX_PATHS + 1)
            .map(|_| intermediate.reissue(&root, 2020, 2090))
            .collect();
        let refs: Vec<&[u8]> = twins.iter().map(Vec::as_slice).collect();
        let (verifier, _files) = verifier_with(
            RevocationCheckMode::CrlOnly,
            FallbackBehavior::FailOpen,
            &[],
            &[&root],
        );
        assert!(matches!(
            check(&verifier, &leaf, &refs),
            Err(RevocationError::PathBudgetExceeded(_))
        ));
    }

    #[test]
    fn peer_sent_root_beyond_a_configured_issuing_ca_is_ignored() {
        // ca_path = issuing CA only; the peer sends leaf, issuing CA, root.
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("revoked@usg.test", &[0x42, 0x05]);
        let intermediate_crl = intermediate.crl(1, &[&leaf]);
        for fallback in [FallbackBehavior::FailClosed, FallbackBehavior::FailOpen] {
            let (verifier, _files) = verifier_with(
                RevocationCheckMode::CrlOnly,
                fallback,
                &[&intermediate_crl],
                &[&intermediate],
            );
            assert!(matches!(
                check(&verifier, &leaf, &[&intermediate.der, &root.der]),
                Err(RevocationError::CertificateRevoked(_))
            ));
        }
    }

    #[test]
    fn issuing_ca_in_the_bundle_is_checked_against_its_root() {
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("eaptls@usg.test", &[0x42, 0x03]);
        let intermediate_crl = intermediate.crl(1, &[]);

        // Bundle = root + issuing CA, peer sends only its leaf: the issuing CA
        // is linked to the root and checked, not trusted as an anchor.
        let root_crl = root.crl(1, &[&intermediate.der]);
        let (verifier, _files) =
            crl_verifier(&[&root_crl, &intermediate_crl], &[&root, &intermediate]);
        assert!(matches!(
            check(&verifier, &leaf, &[]),
            Err(RevocationError::CertificateRevoked(_))
        ));

        // Bundle = issuing CA only: it is the anchor, only the leaf is checked.
        let (verifier, _files) = crl_verifier(&[&intermediate_crl], &[&intermediate]);
        check(&verifier, &leaf, &[]).unwrap();
    }

    #[test]
    fn ocsp_nonce_is_32_octets() {
        assert_eq!(OCSP_NONCE_LEN, 32);
    }

    fn evaluate_spec(
        ca: &Ca,
        leaf: &[u8],
        adjust: impl FnOnce(&mut OcspResponseSpec<'_>),
    ) -> Result<(), RevocationError> {
        let cert_id = OcspRequestBuilder::new(leaf, &ca.der).unwrap().cert_id();
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &ca.key);
        adjust(&mut spec);
        let response = spec.build();
        evaluate(&ocsp_verifier(ca), &response, leaf, ca, None).map(|_| ())
    }

    #[test]
    fn ocsp_response_without_next_update_has_a_maximum_age() {
        // The test verifier's ocsp.cache_ttl_secs is 60.
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x43, 0x01]);
        evaluate_spec(&ca, &leaf, |spec| {
            spec.next_update = None;
            spec.this_update = chrono::Utc::now() - chrono::Duration::seconds(10);
        })
        .unwrap();
        let err = evaluate_spec(&ca, &leaf, |spec| {
            spec.next_update = None;
            spec.this_update = chrono::Utc::now() - chrono::Duration::hours(2);
        })
        .unwrap_err();
        assert!(
            matches!(&err, RevocationError::OcspError(why) if why.contains("nextUpdate")),
            "{err}"
        );
    }

    #[test]
    fn ocsp_this_update_in_the_future_is_rejected() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x43, 0x02]);
        // Within the 5-minute leeway: fine. Beyond it: not current.
        evaluate_spec(&ca, &leaf, |spec| {
            spec.this_update = chrono::Utc::now() + chrono::Duration::minutes(2);
        })
        .unwrap();
        assert!(matches!(
            evaluate_spec(&ca, &leaf, |spec| {
                spec.this_update = chrono::Utc::now() + chrono::Duration::minutes(30);
            }),
            Err(RevocationError::OcspError(_))
        ));
    }

    #[test]
    fn ocsp_responder_id_must_name_the_signer() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x43, 0x03]);
        let other = Ca::root("Somebody Else");
        assert!(matches!(
            evaluate_spec(&ca, &leaf, |spec| spec.responder_name =
                subject_of(&other.der)),
            Err(RevocationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn ocsp_unrecognized_critical_extension_is_rejected() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x43, 0x04]);
        assert!(matches!(
            evaluate_spec(&ca, &leaf, |spec| {
                spec.extra_extensions = vec![extension(OID_UNKNOWN, true, &[0x05, 0x00])];
            }),
            Err(RevocationError::ParseError(why)) if why.contains("critical")
        ));
        // A BER (non-0xFF) TRUE is malformed, not "not critical".
        assert!(matches!(
            evaluate_spec(&ca, &leaf, |spec| {
                spec.extra_extensions = vec![crate::revocation::test_pki::seq(&[
                    &[0x06, 0x03, 0x2A, 0x03, 0x04],
                    &[0x01, 0x01, 0x01],
                    &[0x04, 0x02, 0x05, 0x00],
                ])];
            }),
            Err(RevocationError::ParseError(_))
        ));
        // Not critical: ignored.
        evaluate_spec(&ca, &leaf, |spec| {
            spec.extra_extensions = vec![extension(OID_UNKNOWN, false, &[0x05, 0x00])];
        })
        .unwrap();
    }

    fn evaluate_delegated(
        ca: &Ca,
        leaf: &[u8],
        adjust: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> Result<(), RevocationError> {
        let cert_id = OcspRequestBuilder::new(leaf, &ca.der).unwrap().cert_id();
        let (key, responder) = ca.responder_with("USG OCSP Responder", true, true, adjust);
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&responder), &key);
        spec.certs = vec![responder];
        evaluate(&ocsp_verifier(ca), &spec.build(), leaf, ca, None).map(|_| ())
    }

    #[test]
    fn ocsp_delegated_responder_key_usage_validity_and_critical_extensions() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x43, 0x05]);
        evaluate_delegated(&ca, &leaf, |_| {}).unwrap();

        let err = evaluate_delegated(&ca, &leaf, |p| {
            p.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
        })
        .unwrap_err();
        assert!(
            matches!(&err, RevocationError::InvalidSignature(why) if why.contains("keyUsage")),
            "{err}"
        );

        let err = evaluate_delegated(&ca, &leaf, |p| {
            p.not_before = rcgen::date_time_ymd(2000, 1, 1);
            p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        })
        .unwrap_err();
        assert!(
            matches!(&err, RevocationError::InvalidSignature(why) if why.contains("validity")),
            "{err}"
        );

        let err = evaluate_delegated(&ca, &leaf, |p| {
            let mut ext = rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![0x05, 0x00]);
            ext.set_criticality(true);
            p.custom_extensions.push(ext);
        })
        .unwrap_err();
        assert!(
            matches!(&err, RevocationError::InvalidSignature(why) if why.contains("critical")),
            "{err}"
        );
    }

    #[test]
    fn expired_copy_of_the_responder_certificate_does_not_mask_the_valid_one() {
        // `certs` is unsigned: an expired renewal-predecessor (same key) listed
        // first must not make the response unusable.
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x43, 0x06]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let key = KeyPair::generate().unwrap();
        let expired = ca.responder_cert_for(&key, "USG OCSP Responder", |p| {
            p.not_before = rcgen::date_time_ymd(2000, 1, 1);
            p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        });
        let current = ca.responder_cert_for(&key, "USG OCSP Responder", |_| {});
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&current), &key);
        spec.certs = vec![expired.clone(), current];
        evaluate(&ocsp_verifier(&ca), &spec.build(), &leaf, &ca, None).unwrap();

        // Only the expired one: rejected, and the reason is reported.
        spec.certs = vec![expired];
        let err = evaluate(&ocsp_verifier(&ca), &spec.build(), &leaf, &ca, None).unwrap_err();
        assert!(
            matches!(&err, RevocationError::InvalidSignature(why) if why.contains("validity")),
            "{err}"
        );
    }

    #[test]
    fn ocsp_max_age_is_overflow_safe() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x43, 0x07]);
        let cert_id = OcspRequestBuilder::new(&leaf, &ca.der).unwrap().cert_id();
        let mut spec = OcspResponseSpec::good(&cert_id, subject_of(&ca.der), &ca.key);
        spec.next_update = None;
        let (response, _) = OcspResponse::parse_verified(
            &spec.build(),
            &cert_id,
            &ca.der,
            &default_algorithms(),
            std::time::SystemTime::now(),
            Duration::MAX,
        )
        .unwrap();
        assert!(response.is_within_max_age(std::time::SystemTime::now(), Duration::MAX));
        assert!(!response.is_within_max_age(std::time::SystemTime::now(), Duration::ZERO));
    }

    #[test]
    fn dead_end_padding_exhausts_the_budget_and_is_rejected_even_fail_open() {
        // Many CA certificates carrying the issuing CA's Name but other keys:
        // each costs a signature verification at the leaf and leads nowhere.
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let leaf = intermediate.leaf("eaptls@usg.test", &[0x44, 0x01]);
        let junk: Vec<Vec<u8>> = (0..MAX_SIGNATURE_CHECKS + 1)
            .map(|_| Ca::impostor_of(&intermediate).der)
            .collect();
        let mut sent: Vec<&[u8]> = junk.iter().map(Vec::as_slice).collect();
        sent.push(&intermediate.der);
        let (verifier, _files) = verifier_with(
            RevocationCheckMode::CrlOnly,
            FallbackBehavior::FailOpen,
            &[],
            &[&root],
        );
        assert!(matches!(
            check(&verifier, &leaf, &sent),
            Err(RevocationError::PathBudgetExceeded(_))
        ));
    }

    #[test]
    fn peer_intermediate_without_key_cert_sign_is_linked_like_webpki_does() {
        // WebPKI does not require keyCertSign on intermediates; refusing to
        // link one would leave a validated chain unchecked under fail-open.
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate_with_usages(
            "USG Issuing CA",
            &root,
            // cRLSign so its CRL is usable; no keyCertSign.
            vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::CrlSign],
        );
        let leaf = intermediate.leaf("revoked@usg.test", &[0x44, 0x02]);
        let root_crl = root.crl(1, &[]);
        let intermediate_crl = intermediate.crl(1, &[&leaf]);
        let (verifier, _files) = verifier_with(
            RevocationCheckMode::CrlOnly,
            FallbackBehavior::FailOpen,
            &[&root_crl, &intermediate_crl],
            &[&root],
        );
        assert!(matches!(
            check(&verifier, &leaf, &[&intermediate.der]),
            Err(RevocationError::CertificateRevoked(_))
        ));
    }

    #[test]
    fn expired_configured_issuing_ca_still_anchors_the_chain() {
        // ca_path holds only an issuing CA whose certificate has expired
        // (WebPKI does not check anchor validity): its leaves are still
        // checked against its CRL.
        let root = Ca::root("USG Root CA");
        let intermediate = Ca::intermediate("USG Issuing CA", &root);
        let expired = intermediate.reissue(&root, 2000, 2001);
        let anchor = Ca {
            key: KeyPair::try_from(intermediate.key.serialize_der()).unwrap(),
            params: intermediate.params.clone(),
            der: expired,
        };
        let leaf = intermediate.leaf("revoked@usg.test", &[0x44, 0x03]);
        let intermediate_crl = intermediate.crl(1, &[&leaf]);
        let (verifier, _files) = verifier_with(
            RevocationCheckMode::CrlOnly,
            FallbackBehavior::FailOpen,
            &[&intermediate_crl],
            &[&anchor],
        );
        assert!(matches!(
            check(&verifier, &leaf, &[]),
            Err(RevocationError::CertificateRevoked(_))
        ));
    }

    #[test]
    fn ocsp_explicit_critical_false_is_tolerated() {
        let ca = Ca::root("USG OCSP CA");
        let leaf = ca.leaf("good@usg.test", &[0x44, 0x04]);
        evaluate_spec(&ca, &leaf, |spec| {
            spec.extra_extensions = vec![crate::revocation::test_pki::seq(&[
                &[0x06, 0x03, 0x2A, 0x03, 0x04],
                &[0x01, 0x01, 0x00],
                &[0x04, 0x02, 0x05, 0x00],
            ])];
        })
        .unwrap();
    }
}
