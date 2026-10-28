//! rcgen-generated PKI fixtures for the revocation unit tests.
//!
//! Every fixture is generated fresh per test, so nothing expires and no key
//! material is checked in.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CustomExtension, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SerialNumber, SigningKey, date_time_ymd,
};

/// A certificate authority: its key, its parameters (the issuer identity
/// rcgen signs with) and its DER certificate.
pub(crate) struct Ca {
    pub key: KeyPair,
    pub params: CertificateParams,
    pub der: Vec<u8>,
}

fn ca_params(cn: &str, key_usages: Vec<KeyUsagePurpose>) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, cn);
    params.key_usages = key_usages;
    params
}

fn full_ca_usages() -> Vec<KeyUsagePurpose> {
    vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ]
}

impl Ca {
    /// Self-signed root with keyCertSign, cRLSign and digitalSignature.
    pub fn root(cn: &str) -> Self {
        Self::root_with_usages(cn, full_ca_usages())
    }

    /// Self-signed root with the given keyUsage bits (empty = no extension).
    pub fn root_with_usages(cn: &str, key_usages: Vec<KeyUsagePurpose>) -> Self {
        let key = KeyPair::generate().unwrap();
        let params = ca_params(cn, key_usages);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Self { key, params, der }
    }

    /// Intermediate CA issued by `parent`.
    pub fn intermediate(cn: &str, parent: &Ca) -> Self {
        let key = KeyPair::generate().unwrap();
        let params = ca_params(cn, full_ca_usages());
        let der = params
            .signed_by(&key, &parent.issuer())
            .unwrap()
            .der()
            .to_vec();
        Self { key, params, der }
    }

    /// Intermediate CA issued by `parent` with the given keyUsage bits.
    pub fn intermediate_with_usages(
        cn: &str,
        parent: &Ca,
        key_usages: Vec<KeyUsagePurpose>,
    ) -> Self {
        let key = KeyPair::generate().unwrap();
        let params = ca_params(cn, key_usages);
        let der = params
            .signed_by(&key, &parent.issuer())
            .unwrap()
            .der()
            .to_vec();
        Self { key, params, der }
    }

    /// An impostor: same subject Name as `real`, different key. Its CRLs and
    /// OCSP responses claim to come from `real`.
    pub fn impostor_of(real: &Ca) -> Self {
        let key = KeyPair::generate().unwrap();
        let params = real.params.clone();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Self { key, params, der }
    }

    pub fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key)
    }

    /// End-entity certificate with the given serial.
    pub fn leaf(&self, cn: &str, serial: &[u8]) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.serial_number = Some(SerialNumber::from(serial.to_vec()));
        params.distinguished_name.push(DnType::CommonName, cn);
        params
            .signed_by(&key, &self.issuer())
            .unwrap()
            .der()
            .to_vec()
    }

    /// Serial number of a DER certificate (minimal big-endian).
    pub fn serial_of(cert_der: &[u8]) -> Vec<u8> {
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der).unwrap();
        cert.serial.to_bytes_be()
    }

    /// A current CRL with `crl_number` revoking `revoked` (DER certificates).
    pub fn crl(&self, crl_number: u64, revoked: &[&[u8]]) -> Vec<u8> {
        // rcgen refuses to sign a CRL when the issuer's keyUsage lacks
        // cRLSign; sign with an identity that carries no keyUsage so the
        // verifier, not the generator, decides.
        let mut params = self.params.clone();
        params.key_usages.clear();
        let issuer = Issuer::from_params(&params, &self.key);
        CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|cert| RevokedCertParams {
                    serial_number: SerialNumber::from(Self::serial_of(cert)),
                    revocation_time: date_time_ymd(2026, 1, 2),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .unwrap()
        .der()
        .to_vec()
    }

    /// Self-signed root whose key uses `alg` (P-384, Ed25519, ...).
    pub fn root_with_algorithm(cn: &str, alg: &'static rcgen::SignatureAlgorithm) -> Self {
        let key = KeyPair::generate_for(alg).unwrap();
        let params = ca_params(cn, full_ca_usages());
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Self { key, params, der }
    }

    /// Another certificate for this CA's Name and key (a renewal), issued by
    /// `parent`, valid from 1 January `from_year` to 1 January `to_year`.
    pub fn reissue(&self, parent: &Ca, from_year: i32, to_year: i32) -> Vec<u8> {
        let mut params = self.params.clone();
        params.not_before = date_time_ymd(from_year, 1, 1);
        params.not_after = date_time_ymd(to_year, 1, 1);
        params.serial_number = Some(SerialNumber::from(rand_serial()));
        params
            .signed_by(&self.key, &parent.issuer())
            .unwrap()
            .der()
            .to_vec()
    }

    /// A CRL assembled by hand (so it can carry extensions rcgen does not
    /// write), signed with this CA's key. `extensions` and the single entry's
    /// `entry_extensions` are DER Extension SEQUENCEs; `outer_alg` overrides
    /// the outer signatureAlgorithm contents.
    pub fn crl_with(
        &self,
        extensions: &[Vec<u8>],
        revoked_serial: Option<&[u8]>,
        entry_extensions: &[Vec<u8>],
        outer_alg: Option<&[u8]>,
    ) -> Vec<u8> {
        let alg = seq(&[ECDSA_SHA256_ALG_ID]);
        let entries = revoked_serial
            .map(|serial| {
                let entry_exts = if entry_extensions.is_empty() {
                    Vec::new()
                } else {
                    let refs: Vec<&[u8]> = entry_extensions.iter().map(Vec::as_slice).collect();
                    seq(&refs)
                };
                seq(&[&seq(&[
                    &tlv(0x02, serial),
                    &tlv(0x17, b"260102000000Z"),
                    &entry_exts,
                ])])
            })
            .unwrap_or_default();
        let exts = if extensions.is_empty() {
            Vec::new()
        } else {
            let refs: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
            tlv(0xA0, &seq(&refs))
        };
        let tbs = seq(&[
            &tlv(0x02, &[0x01]),
            &alg,
            &subject_of(&self.der),
            &tlv(0x17, b"260101000000Z"),
            &tlv(0x18, b"20990101000000Z"),
            &entries,
            &exts,
        ]);
        let mut bits = vec![0x00];
        bits.extend_from_slice(&sign(&self.key, &tbs));
        let outer = outer_alg.map(|a| seq(&[a])).unwrap_or(alg);
        seq(&[&tbs, &outer, &tlv(0x03, &bits)])
    }

    /// A responder certificate (OCSP-signing EKU, no nocheck adjustments
    /// beyond `adjust`) for an existing `key`, issued by this CA.
    pub fn responder_cert_for(
        &self,
        key: &KeyPair,
        cn: &str,
        adjust: impl FnOnce(&mut CertificateParams),
    ) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5],
            vec![0x05, 0x00],
        )];
        params.serial_number = Some(SerialNumber::from(rand_serial()));
        adjust(&mut params);
        params
            .signed_by(key, &self.issuer())
            .unwrap()
            .der()
            .to_vec()
    }

    /// Delegated OCSP responder certificate issued by this CA.
    pub fn responder(&self, cn: &str, ocsp_signing_eku: bool, nocheck: bool) -> (KeyPair, Vec<u8>) {
        self.responder_with(cn, ocsp_signing_eku, nocheck, |_| {})
    }

    /// [`Ca::responder`] with a final adjustment of the parameters.
    pub fn responder_with(
        &self,
        cn: &str,
        ocsp_signing_eku: bool,
        nocheck: bool,
        adjust: impl FnOnce(&mut CertificateParams),
    ) -> (KeyPair, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = if ocsp_signing_eku {
            vec![ExtendedKeyUsagePurpose::OcspSigning]
        } else {
            vec![ExtendedKeyUsagePurpose::ClientAuth]
        };
        if nocheck {
            // id-pkix-ocsp-nocheck, value NULL (RFC 6960 §4.2.2.2.1)
            params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5],
                vec![0x05, 0x00],
            )];
        }
        adjust(&mut params);
        let der = params
            .signed_by(&key, &self.issuer())
            .unwrap()
            .der()
            .to_vec();
        (key, der)
    }
}

fn rand_serial() -> Vec<u8> {
    use rand::RngExt;
    let mut serial = rand::rng().random::<[u8; 8]>().to_vec();
    serial[0] = (serial[0] & 0x7F) | 0x01;
    serial
}

/// DER Extension { extnID, critical, extnValue }.
pub(crate) fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let critical = if critical {
        vec![0x01, 0x01, 0xFF]
    } else {
        Vec::new()
    };
    seq(&[&tlv(0x06, oid), &critical, &tlv(0x04, value)])
}

/// DER AlgorithmIdentifier contents of ecdsa-with-SHA256 (rcgen's default
/// key type is ECDSA P-256).
pub(crate) const ECDSA_SHA256_ALG_ID: &[u8] =
    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// Sign `tbs` with `key` (ECDSA P-256 SHA-256).
pub(crate) fn sign(key: &KeyPair, tbs: &[u8]) -> Vec<u8> {
    key.sign(tbs).unwrap()
}

/// DER TLV with a definite length.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// DER SEQUENCE of already-encoded parts.
pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// DER GeneralizedTime for `t`.
pub(crate) fn generalized_time(t: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    tlv(0x18, t.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
}

/// What a test OCSP response says about the certificate.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OcspAnswer {
    Good,
    Revoked,
    Unknown,
}

/// A BasicOCSPResponse to build and sign.
pub(crate) struct OcspResponseSpec<'a> {
    pub cert_id: &'a crate::revocation::ocsp::CertId,
    pub answer: OcspAnswer,
    /// ResponderID byName: the signer's DER subject Name
    pub responder_name: Vec<u8>,
    pub signer: &'a KeyPair,
    /// Certificates to include in `certs`
    pub certs: Vec<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    /// Further responseExtensions (DER Extension SEQUENCEs)
    pub extra_extensions: Vec<Vec<u8>>,
    pub this_update: chrono::DateTime<chrono::Utc>,
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,
}

impl<'a> OcspResponseSpec<'a> {
    /// A current "good" response, signed by `signer` named `responder_name`.
    pub fn good(
        cert_id: &'a crate::revocation::ocsp::CertId,
        responder_name: Vec<u8>,
        signer: &'a KeyPair,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            cert_id,
            answer: OcspAnswer::Good,
            responder_name,
            signer,
            certs: Vec::new(),
            nonce: None,
            extra_extensions: Vec::new(),
            this_update: now - chrono::Duration::hours(1),
            next_update: Some(now + chrono::Duration::days(1)),
        }
    }

    /// Encode the full OCSPResponse.
    pub fn build(&self) -> Vec<u8> {
        const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        const NONCE_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
        const BASIC_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

        // INTEGER contents: prefix 0x00 when empty or the top bit is set.
        let magnitude = self.cert_id.serial_number.as_slice();
        let pad: &[u8] = if magnitude.first().is_none_or(|b| b & 0x80 != 0) {
            &[0x00]
        } else {
            &[]
        };
        let serial = [pad, magnitude].concat();
        let cert_id = seq(&[
            &seq(&[&tlv(0x06, SHA256_OID), &[0x05, 0x00]]),
            &tlv(0x04, &self.cert_id.issuer_name_hash),
            &tlv(0x04, &self.cert_id.issuer_key_hash),
            &tlv(0x02, &serial),
        ]);
        let status = match self.answer {
            OcspAnswer::Good => vec![0x80, 0x00],
            OcspAnswer::Revoked => tlv(
                0xA1,
                &generalized_time(self.this_update - chrono::Duration::days(1)),
            ),
            OcspAnswer::Unknown => vec![0x82, 0x00],
        };
        let next_update = self
            .next_update
            .map(|t| tlv(0xA0, &generalized_time(t)))
            .unwrap_or_default();
        let single = seq(&[
            &cert_id,
            &status,
            &generalized_time(self.this_update),
            &next_update,
        ]);
        let mut exts: Vec<Vec<u8>> = self
            .nonce
            .iter()
            .map(|nonce| seq(&[&tlv(0x06, NONCE_OID), &tlv(0x04, &tlv(0x04, nonce))]))
            .collect();
        exts.extend(self.extra_extensions.iter().cloned());
        let extensions = if exts.is_empty() {
            Vec::new()
        } else {
            let refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
            tlv(0xA1, &seq(&refs))
        };
        let tbs = seq(&[
            &tlv(0xA1, &self.responder_name),
            &generalized_time(self.this_update),
            &seq(&[&single]),
            &extensions,
        ]);

        let mut bits = vec![0x00];
        bits.extend_from_slice(&sign(self.signer, &tbs));
        let certs = if self.certs.is_empty() {
            Vec::new()
        } else {
            let refs: Vec<&[u8]> = self.certs.iter().map(Vec::as_slice).collect();
            tlv(0xA0, &seq(&refs))
        };
        let basic = seq(&[
            &tbs,
            &seq(&[ECDSA_SHA256_ALG_ID]),
            &tlv(0x03, &bits),
            &certs,
        ]);
        seq(&[
            &tlv(0x0A, &[0x00]),
            &tlv(0xA0, &seq(&[&tlv(0x06, BASIC_OID), &tlv(0x04, &basic)])),
        ])
    }
}

/// DER subject Name of a certificate.
pub(crate) fn subject_of(cert_der: &[u8]) -> Vec<u8> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).unwrap();
    cert.subject().as_raw().to_vec()
}
