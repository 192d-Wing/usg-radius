//! Tunnel-Password (attribute 69) — RFC 2868 §3.5.
//!
//! Tunnel-Password carries the password a NAS must present to a remote tunnel
//! endpoint (L2TP, PPTP, ...) and travels on an Access-Accept, encrypted under
//! the shared secret of the hop that sent it. The construction is the RFC 2548
//! §2.4.2 MS-MPPE salt + MD5 XOR chain with a Tag octet in front:
//!
//! ```text
//! Value = Tag (1 octet) || Salt (2 octets, MSB set) || C(1) || ... || C(n)
//!
//! P = Data-Length (1 octet) || Password || zero padding to a multiple of 16
//!
//! b(1) = MD5(Secret || Request-Authenticator || Salt)   c(1) = p(1) XOR b(1)
//! b(i) = MD5(Secret || c(i-1))                          c(i) = p(i) XOR b(i)
//! ```
//!
//! The Tag (`0x00` when unused, `0x01..=0x1F` otherwise) groups the attribute
//! with the other Tunnel-* attributes of one tunnel and is sent in the clear.
//! The Salt is chosen by the sender, must have its most significant bit set
//! and must be unique among the salt-encrypted attributes of one packet.
//!
//! Because the keystream is bound to the Request Authenticator *and* the
//! secret, a proxy cannot relay a Tunnel-Password unchanged: it has to decrypt
//! it under the home server secret and re-encrypt it under the NAS's secret
//! with a fresh salt (see `radius-server`'s proxy response path).

use crate::attributes::{Attribute, AttributeType};
use crate::mppe::{BLOCK, SALT_LENGTH, generate_salts, md5_chain, md5_next};
use crate::packet::PacketError;
use thiserror::Error;

/// Size of the Tag octet that prefixes the Salt.
pub const TAG_LENGTH: usize = 1;
/// Highest Tag value a tunnel group may use (RFC 2868 §3.1); `0x00` means
/// "no tag".
pub const MAX_TAG: u8 = 0x1F;
/// Size of the Data-Length octet that prefixes the plaintext password.
const DATA_LENGTH_FIELD: usize = 1;
/// Longest password that still fits in one attribute: the value is
/// `1 + 2 + 16·ceil((1 + len) / 16)` octets and must not exceed
/// [`Attribute::MAX_VALUE_LENGTH`] (253), so `1 + len ≤ 240`.
pub const MAX_PASSWORD_LENGTH: usize =
    ((Attribute::MAX_VALUE_LENGTH - TAG_LENGTH - SALT_LENGTH) / BLOCK) * BLOCK - DATA_LENGTH_FIELD;

/// Errors from Tunnel-Password encoding/decoding.
#[derive(Debug, Error)]
pub enum TunnelPasswordError {
    /// Password longer than [`MAX_PASSWORD_LENGTH`].
    #[error("Tunnel-Password too long: {0} octets (max {MAX_PASSWORD_LENGTH})")]
    PasswordTooLong(usize),
    /// Tag outside `0x00..=0x1F` (RFC 2868 §3.1).
    #[error("Tunnel-Password tag {0:#04x} exceeds 0x1f")]
    InvalidTag(u8),
    /// Salt without its most significant bit set (RFC 2868 §3.5).
    #[error("Tunnel-Password salt {0:#06x} must have its most significant bit set")]
    InvalidSalt(u16),
    /// Value not `1 + 2 + 16·n` octets with `n ≥ 1`.
    #[error("Tunnel-Password has invalid length {0}")]
    InvalidLength(usize),
    /// Decrypted Data-Length octet exceeds the available plaintext — wrong
    /// secret or Request Authenticator, or a corrupted attribute.
    #[error(
        "Tunnel-Password data-length {declared} exceeds decrypted payload of {available} octets"
    )]
    InvalidDataLength {
        /// Data-Length octet as decrypted.
        declared: usize,
        /// Plaintext octets available after the Data-Length field.
        available: usize,
    },
    /// Attribute is not Tunnel-Password (69).
    #[error("attribute type {0} is not Tunnel-Password (69)")]
    WrongAttributeType(u8),
    /// Attribute construction failed.
    #[error(transparent)]
    Attribute(#[from] PacketError),
}

/// Encrypt `password` into a Tunnel-Password value (`Tag || Salt || ciphertext`).
///
/// `salt` must have its most significant bit set and be unique among the
/// salt-encrypted attributes of one packet; see [`generate_salts`].
pub fn encrypt(
    tag: u8,
    password: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
    salt: [u8; 2],
) -> Result<Vec<u8>, TunnelPasswordError> {
    if tag > MAX_TAG {
        return Err(TunnelPasswordError::InvalidTag(tag));
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(TunnelPasswordError::PasswordTooLong(password.len()));
    }
    if salt[0] & 0x80 == 0 {
        return Err(TunnelPasswordError::InvalidSalt(u16::from_be_bytes(salt)));
    }

    // P = Data-Length || Password || zero padding to a multiple of 16.
    let padded = (DATA_LENGTH_FIELD + password.len()).div_ceil(BLOCK) * BLOCK;
    let mut plaintext = Vec::with_capacity(padded);
    plaintext.push(password.len() as u8);
    plaintext.extend_from_slice(password);
    plaintext.resize(padded, 0);

    let mut out = Vec::with_capacity(TAG_LENGTH + SALT_LENGTH + padded);
    out.push(tag);
    out.extend_from_slice(&salt);

    let mut b = md5_chain(secret, request_authenticator, salt);
    for (i, block) in plaintext.as_chunks::<BLOCK>().0.iter().enumerate() {
        if i > 0 {
            let prev = &out[out.len() - BLOCK..];
            b = md5_next(secret, prev);
        }
        out.extend(block.iter().zip(b.iter()).map(|(p, k)| p ^ k));
    }
    Ok(out)
}

/// Decrypt a Tunnel-Password value produced by [`encrypt`] (or by any
/// RFC 2868 conformant server), returning `(tag, password)`.
pub fn decrypt(
    value: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<(u8, Vec<u8>), TunnelPasswordError> {
    const HEADER: usize = TAG_LENGTH + SALT_LENGTH;
    let cipher_len = value.len().saturating_sub(HEADER);
    if value.len() < HEADER + BLOCK || !cipher_len.is_multiple_of(BLOCK) {
        return Err(TunnelPasswordError::InvalidLength(value.len()));
    }
    let tag = value[0];
    if tag > MAX_TAG {
        return Err(TunnelPasswordError::InvalidTag(tag));
    }
    let salt = [value[1], value[2]];
    if salt[0] & 0x80 == 0 {
        return Err(TunnelPasswordError::InvalidSalt(u16::from_be_bytes(salt)));
    }
    let cipher = &value[HEADER..];

    let mut plaintext = Vec::with_capacity(cipher_len);
    let mut b = md5_chain(secret, request_authenticator, salt);
    for (i, block) in cipher.as_chunks::<BLOCK>().0.iter().enumerate() {
        if i > 0 {
            b = md5_next(secret, &cipher[(i - 1) * BLOCK..i * BLOCK]);
        }
        plaintext.extend(block.iter().zip(b.iter()).map(|(c, k)| c ^ k));
    }

    let declared = plaintext[0] as usize;
    let available = plaintext.len() - DATA_LENGTH_FIELD;
    if declared > available {
        return Err(TunnelPasswordError::InvalidDataLength {
            declared,
            available,
        });
    }
    Ok((
        tag,
        plaintext[DATA_LENGTH_FIELD..DATA_LENGTH_FIELD + declared].to_vec(),
    ))
}

/// A decrypted Tunnel-Password: the tunnel group Tag and the password itself.
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelPassword {
    /// Tunnel group tag, `0x00` when unused (RFC 2868 §3.1).
    pub tag: u8,
    /// The password in the clear.
    pub password: Vec<u8>,
}

impl std::fmt::Debug for TunnelPassword {
    /// Never print the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelPassword")
            .field("tag", &self.tag)
            .field("password_len", &self.password.len())
            .finish()
    }
}

impl TunnelPassword {
    /// Encrypt for the Access-Accept answering the request with
    /// `request_authenticator`, using a freshly generated salt.
    pub fn to_attribute(
        &self,
        secret: &[u8],
        request_authenticator: &[u8; 16],
    ) -> Result<Attribute, TunnelPasswordError> {
        self.to_attribute_with_salt(secret, request_authenticator, generate_salts(1)[0])
    }

    /// Deterministic variant of [`TunnelPassword::to_attribute`] with a
    /// caller-chosen salt.
    pub fn to_attribute_with_salt(
        &self,
        secret: &[u8],
        request_authenticator: &[u8; 16],
        salt: [u8; 2],
    ) -> Result<Attribute, TunnelPasswordError> {
        let value = encrypt(
            self.tag,
            &self.password,
            secret,
            request_authenticator,
            salt,
        )?;
        Ok(Attribute::new(AttributeType::TunnelPassword as u8, value)?)
    }

    /// Decrypt a received Tunnel-Password attribute.
    ///
    /// `request_authenticator` is the authenticator of the Access-Request the
    /// packet answers.
    pub fn from_attribute(
        attribute: &Attribute,
        secret: &[u8],
        request_authenticator: &[u8; 16],
    ) -> Result<Self, TunnelPasswordError> {
        if attribute.attr_type != AttributeType::TunnelPassword as u8 {
            return Err(TunnelPasswordError::WrongAttributeType(attribute.attr_type));
        }
        let (tag, password) = decrypt(&attribute.value, secret, request_authenticator)?;
        Ok(TunnelPassword { tag, password })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mppe;
    use crate::packet::{Code, Packet};

    const SECRET: &[u8] = b"testing123";
    const REQ_AUTH: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    /// Known-answer vectors. RFC 2868 publishes no worked example, so these
    /// were produced by an independent, from-the-text implementation of §3.5
    /// (Python `hashlib.md5`, ~15 lines) and are pinned here so any change to
    /// the Tag/Salt framing, XOR chain, padding or Data-Length octet is caught.
    #[test]
    fn kat_tagged_short_password() {
        let enc = encrypt(0x01, b"tunnel-pass", SECRET, &REQ_AUTH, [0x80, 0x01]).unwrap();
        assert_eq!(hex::encode(&enc), "01800139d07123647f4915bf46c318b2ba15f3");
        assert_eq!(enc.len(), TAG_LENGTH + SALT_LENGTH + BLOCK);
        assert_eq!(
            decrypt(&enc, SECRET, &REQ_AUTH).unwrap(),
            (0x01, b"tunnel-pass".to_vec())
        );
    }

    #[test]
    fn kat_untagged_32_octet_password_spans_three_blocks() {
        let password: Vec<u8> = (0x01..=0x20).collect();
        let enc = encrypt(0x00, &password, SECRET, &REQ_AUTH, [0x80, 0x02]).unwrap();
        assert_eq!(
            hex::encode(&enc),
            "008002374a3c3de81e9ab53ae9f9b0fcfe3c0b0834a1b8c2a2285d5f040aad2e4e767b2cd40470cbf70045ecd046d10ee534a3"
        );
        assert_eq!(enc.len(), TAG_LENGTH + SALT_LENGTH + 3 * BLOCK);
        assert_eq!(decrypt(&enc, SECRET, &REQ_AUTH).unwrap(), (0x00, password));
    }

    #[test]
    fn kat_max_tag_15_octets_fills_one_block_exactly() {
        let enc = encrypt(MAX_TAG, b"fifteen-octets!", SECRET, &REQ_AUTH, [0xff, 0xff]).unwrap();
        assert_eq!(hex::encode(&enc), "1fffff4d40a057594c52ee41a00e75403d282f");
        assert_eq!(
            decrypt(&enc, SECRET, &REQ_AUTH).unwrap(),
            (MAX_TAG, b"fifteen-octets!".to_vec())
        );
    }

    #[test]
    fn kat_empty_password() {
        let enc = encrypt(0x05, b"", SECRET, &REQ_AUTH, [0x80, 0x00]).unwrap();
        assert_eq!(hex::encode(&enc), "0580008e87df01071d1f314ccffdc084c59e6e");
        assert_eq!(decrypt(&enc, SECRET, &REQ_AUTH).unwrap(), (0x05, vec![]));
    }

    #[test]
    fn ciphertext_is_the_mppe_chain_behind_the_tag() {
        // Same secret, authenticator, salt and plaintext framing as RFC 2548:
        // only the Tag octet differs.
        let password = b"fifteen-octets!";
        let salt = [0xff, 0xff];
        let tp = encrypt(0x1f, password, SECRET, &REQ_AUTH, salt).unwrap();
        let mppe = mppe::encrypt_key(password, SECRET, &REQ_AUTH, salt).unwrap();
        assert_eq!(&tp[TAG_LENGTH..], &mppe[..]);
    }

    #[test]
    fn round_trip_all_lengths_up_to_max() {
        for len in 0..=MAX_PASSWORD_LENGTH {
            let password: Vec<u8> = (0..len).map(|i| (i * 11 + 5) as u8).collect();
            let enc = encrypt(0x03, &password, SECRET, &REQ_AUTH, [0x80, 0x00]).unwrap();
            assert_eq!(
                enc.len(),
                TAG_LENGTH + SALT_LENGTH + (1 + len).div_ceil(BLOCK) * BLOCK
            );
            assert!(enc.len() <= Attribute::MAX_VALUE_LENGTH);
            assert_eq!(
                decrypt(&enc, SECRET, &REQ_AUTH).unwrap(),
                (0x03, password),
                "len {len}"
            );
        }
        assert!(matches!(
            encrypt(0, &vec![0; MAX_PASSWORD_LENGTH + 1], SECRET, &REQ_AUTH, [0x80, 0x00]),
            Err(TunnelPasswordError::PasswordTooLong(n)) if n == MAX_PASSWORD_LENGTH + 1
        ));
    }

    #[test]
    fn tag_must_be_at_most_0x1f() {
        assert!(matches!(
            encrypt(0x20, b"p", SECRET, &REQ_AUTH, [0x80, 0x00]),
            Err(TunnelPasswordError::InvalidTag(0x20))
        ));
        let mut enc = encrypt(0x01, b"p", SECRET, &REQ_AUTH, [0x80, 0x00]).unwrap();
        enc[0] = 0xff;
        assert!(matches!(
            decrypt(&enc, SECRET, &REQ_AUTH),
            Err(TunnelPasswordError::InvalidTag(0xff))
        ));
    }

    #[test]
    fn salt_must_have_high_bit_set() {
        assert!(matches!(
            encrypt(0, b"p", SECRET, &REQ_AUTH, [0x7f, 0xff]),
            Err(TunnelPasswordError::InvalidSalt(0x7fff))
        ));
        let mut enc = encrypt(0, b"p", SECRET, &REQ_AUTH, [0x80, 0x00]).unwrap();
        enc[1] = 0x00;
        assert!(matches!(
            decrypt(&enc, SECRET, &REQ_AUTH),
            Err(TunnelPasswordError::InvalidSalt(0x0000))
        ));
    }

    #[test]
    fn decrypt_rejects_bad_lengths() {
        for bad in [vec![0x00, 0x80, 0x01], vec![0x80; 18], vec![0x80; 20]] {
            let len = bad.len();
            assert!(matches!(
                decrypt(&bad, SECRET, &REQ_AUTH),
                Err(TunnelPasswordError::InvalidLength(n)) if n == len
            ));
        }
    }

    #[test]
    fn wrong_secret_or_authenticator_does_not_yield_the_password() {
        let password: Vec<u8> = (0..32).collect();
        let enc = encrypt(0x01, &password, SECRET, &REQ_AUTH, [0x80, 0x01]).unwrap();
        // Either an error (garbage length octet) or a different password —
        // never the plaintext.
        if let Ok((_, p)) = decrypt(&enc, b"wrong", &REQ_AUTH) {
            assert_ne!(p, password);
        }
        if let Ok((_, p)) = decrypt(&enc, SECRET, &[0xFF; 16]) {
            assert_ne!(p, password);
        }
    }

    #[test]
    fn attribute_round_trip_through_a_packet() {
        let tp = TunnelPassword {
            tag: 0x02,
            password: b"s3cret-l2tp".to_vec(),
        };
        let attr = tp.to_attribute(SECRET, &REQ_AUTH).unwrap();
        assert_eq!(attr.attr_type, AttributeType::TunnelPassword as u8);
        assert_eq!(attr.value[0], 0x02);
        assert!(attr.value[1] & 0x80 != 0, "fresh salt has MSB set");

        let mut p = Packet::new(Code::AccessAccept, 9, [0u8; 16]);
        p.add_attribute(attr);
        let p = Packet::decode(&p.encode().unwrap()).unwrap();

        let received = p
            .find_attribute(AttributeType::TunnelPassword as u8)
            .unwrap();
        assert_eq!(
            TunnelPassword::from_attribute(received, SECRET, &REQ_AUTH).unwrap(),
            tp
        );
    }

    #[test]
    fn deterministic_attribute_matches_kat() {
        let tp = TunnelPassword {
            tag: 0x01,
            password: b"tunnel-pass".to_vec(),
        };
        let attr = tp
            .to_attribute_with_salt(SECRET, &REQ_AUTH, [0x80, 0x01])
            .unwrap();
        assert_eq!(
            hex::encode(&attr.value),
            "01800139d07123647f4915bf46c318b2ba15f3"
        );
    }

    #[test]
    fn from_attribute_rejects_other_types() {
        let attr = Attribute::string(AttributeType::UserName as u8, "alice").unwrap();
        assert!(matches!(
            TunnelPassword::from_attribute(&attr, SECRET, &REQ_AUTH),
            Err(TunnelPasswordError::WrongAttributeType(1))
        ));
    }

    #[test]
    fn debug_does_not_leak_password() {
        let tp = TunnelPassword {
            tag: 1,
            password: b"hunter2".to_vec(),
        };
        let s = format!("{tp:?}");
        assert!(!s.contains("hunter2"));
        assert!(s.contains("password_len: 7"));
    }
}
