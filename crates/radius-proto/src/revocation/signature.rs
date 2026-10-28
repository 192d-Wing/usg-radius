//! Signature verification for CRLs, OCSP responses and certificate links
//!
//! CRLs (RFC 5280 §5.1), BasicOCSPResponses (RFC 6960 §4.2.1) and X.509
//! certificates share one shape:
//!
//! ```asn1
//! Signed ::= SEQUENCE {
//!     tbs                 SEQUENCE { ... },
//!     signatureAlgorithm  AlgorithmIdentifier,
//!     signature           BIT STRING,
//!     ...                 -- BasicOCSPResponse: [0] EXPLICIT certs OPTIONAL
//! }
//! ```
//!
//! The signature covers the DER bytes of `tbs` exactly as received, so this
//! module splits the structure with a small DER reader rather than
//! re-encoding a parsed form. Verification goes through the
//! [`SignatureVerificationAlgorithm`](pki_types::SignatureVerificationAlgorithm)s
//! of a rustls `CryptoProvider` (aws-lc-rs by default), so no second crypto
//! implementation is involved.

use super::error::RevocationError;
use rustls::crypto::WebPkiSupportedAlgorithms;
use x509_parser::prelude::*;

/// DER tags used here.
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_ENUMERATED: u8 = 0x0A;
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;

/// id-kp-OCSPSigning (RFC 5280 §4.2.1.12) is read through x509-parser;
/// id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1) is not, so match its OID.
const OID_OCSP_NOCHECK: &str = "1.3.6.1.5.5.7.48.1.5";

/// The signature algorithms of the process-default rustls `CryptoProvider`
/// (the one a `WebPkiClientVerifier` built without an explicit provider
/// uses), or of rustls's aws-lc-rs provider when none is installed yet.
pub(crate) fn default_algorithms() -> WebPkiSupportedAlgorithms {
    rustls::crypto::CryptoProvider::get_default()
        .map(|provider| provider.signature_verification_algorithms)
        .unwrap_or_else(|| {
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
        })
}

/// One DER TLV.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    /// Identifier octet (class, constructed bit, tag number < 31)
    pub tag: u8,
    /// Contents octets
    pub content: &'a [u8],
    /// Identifier, length and contents octets
    pub raw: &'a [u8],
}

fn malformed(what: &str) -> RevocationError {
    RevocationError::ParseError(format!("malformed DER: {what}"))
}

/// Read one DER TLV from the front of `input`; returns it and the rest.
///
/// Only definite, minimally encoded lengths and single-octet tags are
/// accepted (DER, X.690 §10.1); nothing in CRLs or OCSP responses needs more.
pub(crate) fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), RevocationError> {
    let (&tag, rest) = input.split_first().ok_or_else(|| malformed("truncated"))?;
    if tag & 0x1F == 0x1F {
        return Err(malformed("multi-octet tag"));
    }
    let (&first, rest) = rest.split_first().ok_or_else(|| malformed("truncated"))?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7F) as usize;
        // 0x80 is the BER indefinite form; more than 4 octets is absurd here.
        if n == 0 || n > 4 || rest.len() < n || rest[0] == 0 {
            return Err(malformed("length"));
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        if len < 0x80 {
            return Err(malformed("non-minimal length"));
        }
        (len, &rest[n..])
    };
    if rest.len() < len {
        return Err(malformed("truncated"));
    }
    let header = input.len() - rest.len();
    Ok((
        Tlv {
            tag,
            content: &rest[..len],
            raw: &input[..header + len],
        },
        &rest[len..],
    ))
}

/// Read one TLV and require its tag.
pub(crate) fn expect_tlv(input: &[u8], tag: u8) -> Result<(Tlv<'_>, &[u8]), RevocationError> {
    let (tlv, rest) = read_tlv(input)?;
    if tlv.tag != tag {
        return Err(malformed(&format!(
            "expected tag {tag:#04x}, found {:#04x}",
            tlv.tag
        )));
    }
    Ok((tlv, rest))
}

/// Contents of a BIT STRING with no unused bits (keys and signatures).
pub(crate) fn bit_string_octets<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], RevocationError> {
    match tlv.content.split_first() {
        Some((0, bits)) if tlv.tag == TAG_BIT_STRING => Ok(bits),
        _ => Err(malformed("BIT STRING")),
    }
}

/// A signed structure split into the parts the signature covers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedData<'a> {
    /// DER of the to-be-signed SEQUENCE, tag and length included
    pub tbs: &'a [u8],
    /// Contents of the signatureAlgorithm AlgorithmIdentifier
    pub algorithm: &'a [u8],
    /// Signature octets (BIT STRING contents after the unused-bits octet)
    pub signature: &'a [u8],
    /// Elements of the outer SEQUENCE after the signature
    pub trailing: &'a [u8],
}

/// Split `der` (a complete signed SEQUENCE, nothing after it).
pub(crate) fn split_signed(der: &[u8]) -> Result<SignedData<'_>, RevocationError> {
    let (outer, rest) = expect_tlv(der, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return Err(malformed("data after signed structure"));
    }
    let (tbs, rest) = expect_tlv(outer.content, TAG_SEQUENCE)?;
    let (algorithm, rest) = expect_tlv(rest, TAG_SEQUENCE)?;
    let (signature, trailing) = expect_tlv(rest, TAG_BIT_STRING)?;
    Ok(SignedData {
        tbs: tbs.raw,
        algorithm: algorithm.content,
        signature: bit_string_octets(&signature)?,
        trailing,
    })
}

/// Verify `signed` with the key in `spki_der` (a DER SubjectPublicKeyInfo).
///
/// The algorithm is chosen by matching both the signatureAlgorithm and the
/// key's algorithm against the provider's table, so an RSA signature cannot be
/// checked against an EC key or with a different hash than the one declared.
pub(crate) fn verify_signed_data(
    algorithms: &WebPkiSupportedAlgorithms,
    spki_der: &[u8],
    signed: &SignedData<'_>,
) -> Result<(), RevocationError> {
    let (spki, _) = expect_tlv(spki_der, TAG_SEQUENCE)?;
    let (key_algorithm, rest) = expect_tlv(spki.content, TAG_SEQUENCE)?;
    let (key, _) = expect_tlv(rest, TAG_BIT_STRING)?;
    let key = bit_string_octets(&key)?;

    let mut supported = false;
    for alg in algorithms.all.iter().filter(|alg| {
        alg.signature_alg_id().as_ref() == signed.algorithm
            && alg.public_key_alg_id().as_ref() == key_algorithm.content
    }) {
        supported = true;
        if alg
            .verify_signature(key, signed.tbs, signed.signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(RevocationError::InvalidSignature(if supported {
        "signature does not verify with the issuer's key".to_string()
    } else {
        "unsupported signature or key algorithm".to_string()
    }))
}

/// Does `issuer_der` name and sign `cert_der`? (Name chaining plus signature;
/// the caller decides what else the issuer must satisfy.)
pub(crate) fn is_issued_by(
    algorithms: &WebPkiSupportedAlgorithms,
    cert_der: &[u8],
    issuer_der: &[u8],
) -> bool {
    let (Ok((_, cert)), Ok((_, issuer))) = (
        parse_x509_certificate(cert_der),
        parse_x509_certificate(issuer_der),
    ) else {
        return false;
    };
    cert.issuer().as_raw() == issuer.subject().as_raw()
        && split_signed(cert_der)
            .and_then(|signed| verify_signed_data(algorithms, issuer.public_key().raw, &signed))
            .is_ok()
}

/// Is `cert` a CA certificate (basicConstraints cA = TRUE)?
pub(crate) fn is_ca(cert: &X509Certificate<'_>) -> bool {
    matches!(cert.basic_constraints(), Ok(Some(bc)) if bc.value.ca)
}

/// Does `cert` carry id-pkix-ocsp-nocheck?
pub(crate) fn has_ocsp_nocheck(cert: &X509Certificate<'_>) -> bool {
    cert.extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == OID_OCSP_NOCHECK)
}

/// Minimal big-endian magnitude of a non-negative DER INTEGER's contents.
pub(crate) fn integer_magnitude(content: &[u8]) -> &[u8] {
    let start = content
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(content.len());
    &content[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_tlv_short_and_long_lengths() {
        let (tlv, rest) = read_tlv(&[0x04, 0x02, 0xAA, 0xBB, 0xFF]).unwrap();
        assert_eq!(tlv.tag, TAG_OCTET_STRING);
        assert_eq!(tlv.content, &[0xAA, 0xBB]);
        assert_eq!(tlv.raw, &[0x04, 0x02, 0xAA, 0xBB]);
        assert_eq!(rest, &[0xFF]);

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend(std::iter::repeat_n(0x11, 0x80));
        let (tlv, rest) = read_tlv(&long).unwrap();
        assert_eq!(tlv.content.len(), 0x80);
        assert!(rest.is_empty());
    }

    #[test]
    fn read_tlv_rejects_non_der() {
        // Indefinite length (BER only).
        assert!(read_tlv(&[0x30, 0x80, 0x00, 0x00]).is_err());
        // Long form for a short length.
        assert!(read_tlv(&[0x04, 0x81, 0x01, 0xAA]).is_err());
        // Leading zero length octet.
        assert!(read_tlv(&[0x04, 0x82, 0x00, 0x81]).is_err());
        // Truncated contents.
        assert!(read_tlv(&[0x04, 0x05, 0x01]).is_err());
        // Multi-octet tag.
        assert!(read_tlv(&[0x1F, 0x81, 0x00]).is_err());
        assert!(read_tlv(&[]).is_err());
    }

    #[test]
    fn split_signed_rejects_trailing_garbage_and_unused_bits() {
        // SEQUENCE { SEQUENCE {}, SEQUENCE {}, BIT STRING 00 AA }
        let good = [0x30, 0x08, 0x30, 0x00, 0x30, 0x00, 0x03, 0x02, 0x00, 0xAA];
        let signed = split_signed(&good).unwrap();
        assert_eq!(signed.tbs, &[0x30, 0x00]);
        assert_eq!(signed.signature, &[0xAA]);
        assert!(signed.trailing.is_empty());

        let mut trailing = good.to_vec();
        trailing.push(0x00);
        assert!(split_signed(&trailing).is_err());

        let mut unused_bits = good;
        unused_bits[8] = 0x01;
        assert!(split_signed(&unused_bits).is_err());
    }

    #[test]
    fn integer_magnitude_strips_sign_padding() {
        assert_eq!(integer_magnitude(&[0x00, 0xA5, 0x01]), &[0xA5, 0x01]);
        assert_eq!(integer_magnitude(&[0x10]), &[0x10]);
        assert_eq!(integer_magnitude(&[0x00]), &[] as &[u8]);
    }
}
