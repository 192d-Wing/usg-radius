//! Shared PEM loading for the TLS listeners (RadSec and the management API), so
//! certificate/key/CA loading lives in one place rather than being duplicated per
//! listener.

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Load a certificate chain (leaf first) from a PEM file.
///
/// # Errors
/// Returns the underlying PEM parse error if the file is missing or malformed.
pub fn load_cert_chain(
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, rustls::pki_types::pem::Error> {
    CertificateDer::pem_file_iter(path)?.collect()
}

/// Load a private key from a PEM file.
///
/// # Errors
/// Returns the underlying PEM parse error if the file is missing or malformed.
pub fn load_private_key(
    path: &str,
) -> Result<PrivateKeyDer<'static>, rustls::pki_types::pem::Error> {
    PrivateKeyDer::from_pem_file(path)
}

/// Build a [`RootCertStore`] from a PEM CA bundle, used as a trust anchor for
/// verifying peer certificates.
///
/// # Errors
/// [`RootStoreError`] if the bundle can't be read or a certificate is rejected.
pub fn load_root_store(path: &str) -> Result<RootCertStore, RootStoreError> {
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(path)? {
        roots.add(c?)?;
    }
    Ok(roots)
}

/// Error building a [`RootCertStore`] from a PEM CA bundle.
#[derive(Debug, thiserror::Error)]
pub enum RootStoreError {
    #[error("CA bundle PEM error: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("CA certificate rejected: {0}")]
    Cert(#[from] rustls::Error),
}
