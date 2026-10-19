//! Microsoft MPPE key attributes — RFC 2548 §2.4.2 (MS-MPPE-Send-Key) and
//! §2.4.3 (MS-MPPE-Recv-Key).
//!
//! After a key-deriving EAP method (EAP-TLS, EAP-TEAP, ...) completes, the
//! RADIUS server must hand the 64-octet EAP Master Session Key (MSK) to the
//! authenticator so it can run the 802.11i 4-way handshake (or MPPE/PPP
//! encryption). The MSK travels in two Microsoft (Vendor-Id 311) sub-attributes
//! on the Access-Accept, each encrypted under the client's shared secret:
//!
//! | Attribute        | Vendor type | Contents                       |
//! |------------------|-------------|--------------------------------|
//! | MS-MPPE-Recv-Key | 17          | MSK octets 0..32 (peer → NAS)  |
//! | MS-MPPE-Send-Key | 16          | MSK octets 32..64 (NAS → peer) |
//!
//! (RFC 3748 §7.10 / RFC 5216 §2.3 / FreeRADIUS and hostapd convention: the
//! first half of the MSK is the authenticator's *receive* key.)
//!
//! # Encryption (RFC 2548 §2.4.2)
//!
//! ```text
//! String = Salt (2 octets, MSB set) || C(1) || C(2) || ... || C(n)
//!
//! P = Key-Length (1 octet) || Key || zero padding to a multiple of 16
//!
//! b(1) = MD5(Secret || Request-Authenticator || Salt)   c(1) = p(1) XOR b(1)
//! b(i) = MD5(Secret || c(i-1))                          c(i) = p(i) XOR b(i)
//! ```
//!
//! The Salt is chosen by the server, must have its most significant bit set
//! and must be unique per attribute in a packet — the two keys of one
//! Access-Accept therefore never share a keystream. Because the keystream is
//! bound to the Request Authenticator, encryption can only happen once the
//! Access-Accept is being finalized against a specific request, which is why
//! `radius-server` performs it in the response builder rather than inside
//! the EAP handler.

use crate::attributes::{Attribute, VendorSpecific};
use crate::packet::{Packet, PacketError};
use thiserror::Error;

/// Microsoft's IANA Private Enterprise Number.
pub const MICROSOFT_VENDOR_ID: u32 = 311;
/// MS-MPPE-Send-Key vendor type (RFC 2548 §2.4.2).
pub const MS_MPPE_SEND_KEY: u8 = 16;
/// MS-MPPE-Recv-Key vendor type (RFC 2548 §2.4.3).
pub const MS_MPPE_RECV_KEY: u8 = 17;
/// Size of the Salt that prefixes the encrypted String.
pub const SALT_LENGTH: usize = 2;
/// Size of the Key-Length octet that prefixes the plaintext key.
const KEY_LENGTH_FIELD: usize = 1;
/// MD5 block size used by the XOR chain (shared with Tunnel-Password).
pub(crate) const BLOCK: usize = 16;
/// Longest key that still fits in one sub-attribute: the encrypted String is
/// `2 + 16·ceil((1 + len) / 16)` octets and must not exceed
/// [`VendorSpecific::MAX_VALUE_LENGTH`] (247), so `1 + len ≤ 240`.
pub const MAX_KEY_LENGTH: usize =
    ((VendorSpecific::MAX_VALUE_LENGTH - SALT_LENGTH) / BLOCK) * BLOCK - KEY_LENGTH_FIELD;
/// Length of each MPPE key carved out of the MSK.
pub const MPPE_KEY_LENGTH: usize = 32;
/// Minimum MSK length that yields both keys (RFC 3748 §7.10 guarantees 64).
pub const MIN_MSK_LENGTH: usize = 2 * MPPE_KEY_LENGTH;

/// Errors from MS-MPPE key encoding/decoding.
#[derive(Debug, Error)]
pub enum MppeError {
    /// Key longer than [`MAX_KEY_LENGTH`].
    #[error("MPPE key too long: {0} octets (max {MAX_KEY_LENGTH})")]
    KeyTooLong(usize),
    /// Salt without its most significant bit set (RFC 2548 §2.4.2).
    #[error("MPPE salt {0:#06x} must have its most significant bit set")]
    InvalidSalt(u16),
    /// Encrypted String not `2 + 16·n` octets with `n ≥ 1`.
    #[error("MPPE encrypted key has invalid length {0}")]
    InvalidLength(usize),
    /// Decrypted Key-Length octet exceeds the available plaintext — wrong
    /// secret or Request Authenticator, or a corrupted attribute.
    #[error("MPPE key-length {declared} exceeds decrypted payload of {available} octets")]
    InvalidKeyLength {
        /// Key-Length octet as decrypted.
        declared: usize,
        /// Plaintext octets available after the Key-Length field.
        available: usize,
    },
    /// MSK shorter than [`MIN_MSK_LENGTH`].
    #[error("MSK too short for MS-MPPE keys: {0} octets (need {MIN_MSK_LENGTH})")]
    MskTooShort(usize),
    /// Attribute construction failed.
    #[error(transparent)]
    Attribute(#[from] PacketError),
}

/// b(1) = MD5(Secret || Request-Authenticator || Salt) — the first keystream
/// block of the RFC 2548 §2.4.2 chain.
pub(crate) fn md5_chain(
    secret: &[u8],
    request_authenticator: &[u8; 16],
    salt: [u8; 2],
) -> [u8; 16] {
    let mut data = Vec::with_capacity(secret.len() + 16 + SALT_LENGTH);
    data.extend_from_slice(secret);
    data.extend_from_slice(request_authenticator);
    data.extend_from_slice(&salt);
    md5::compute(&data).0
}

/// b(i) = MD5(Secret || c(i-1)) — every subsequent keystream block is chained
/// off the previous *ciphertext* block, for encryption and decryption alike.
pub(crate) fn md5_next(secret: &[u8], prev_cipher: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(secret.len() + BLOCK);
    data.extend_from_slice(secret);
    data.extend_from_slice(prev_cipher);
    md5::compute(&data).0
}

/// Encrypt `key` into an MS-MPPE `String` field (`Salt || ciphertext`).
///
/// `salt` must have its most significant bit set and be unique among the
/// MPPE attributes of one packet; see [`generate_salts`].
pub fn encrypt_key(
    key: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
    salt: [u8; 2],
) -> Result<Vec<u8>, MppeError> {
    if key.len() > MAX_KEY_LENGTH {
        return Err(MppeError::KeyTooLong(key.len()));
    }
    if salt[0] & 0x80 == 0 {
        return Err(MppeError::InvalidSalt(u16::from_be_bytes(salt)));
    }

    // P = Key-Length || Key || zero padding to a multiple of 16.
    let mut plaintext = Vec::with_capacity((KEY_LENGTH_FIELD + key.len()).div_ceil(BLOCK) * BLOCK);
    plaintext.push(key.len() as u8);
    plaintext.extend_from_slice(key);
    plaintext.resize(plaintext.len().div_ceil(BLOCK) * BLOCK, 0);

    let mut out = Vec::with_capacity(SALT_LENGTH + plaintext.len());
    out.extend_from_slice(&salt);

    let mut b = md5_chain(secret, request_authenticator, salt);
    for (i, block) in plaintext.as_chunks::<BLOCK>().0.iter().enumerate() {
        if i > 0 {
            let prev = &out[out.len() - BLOCK..];
            b = md5_next(secret, prev);
        }
        for (p, k) in block.iter().zip(b.iter()) {
            out.push(p ^ k);
        }
    }
    Ok(out)
}

/// Decrypt an MS-MPPE `String` field produced by [`encrypt_key`] (or by any
/// RFC 2548 conformant server), returning the key.
pub fn decrypt_key(
    encrypted: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<Vec<u8>, MppeError> {
    let cipher_len = encrypted.len().saturating_sub(SALT_LENGTH);
    if encrypted.len() < SALT_LENGTH + BLOCK || !cipher_len.is_multiple_of(BLOCK) {
        return Err(MppeError::InvalidLength(encrypted.len()));
    }
    let salt = [encrypted[0], encrypted[1]];
    if salt[0] & 0x80 == 0 {
        return Err(MppeError::InvalidSalt(u16::from_be_bytes(salt)));
    }
    let cipher = &encrypted[SALT_LENGTH..];

    let mut plaintext = Vec::with_capacity(cipher_len);
    let mut b = md5_chain(secret, request_authenticator, salt);
    for (i, block) in cipher.as_chunks::<BLOCK>().0.iter().enumerate() {
        if i > 0 {
            b = md5_next(secret, &cipher[(i - 1) * BLOCK..i * BLOCK]);
        }
        plaintext.extend(block.iter().zip(b.iter()).map(|(c, k)| c ^ k));
    }

    let declared = plaintext[0] as usize;
    let available = plaintext.len() - KEY_LENGTH_FIELD;
    if declared > available {
        return Err(MppeError::InvalidKeyLength {
            declared,
            available,
        });
    }
    Ok(plaintext[KEY_LENGTH_FIELD..KEY_LENGTH_FIELD + declared].to_vec())
}

/// Encrypt `key` and wrap it as a Microsoft Vendor-Specific attribute of the
/// given vendor type ([`MS_MPPE_SEND_KEY`] or [`MS_MPPE_RECV_KEY`]).
pub fn encrypt_key_attribute(
    vendor_type: u8,
    key: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
    salt: [u8; 2],
) -> Result<Attribute, MppeError> {
    let encrypted = encrypt_key(key, secret, request_authenticator, salt)?;
    Ok(VendorSpecific::new(MICROSOFT_VENDOR_ID, vendor_type, encrypted)?.to_attribute()?)
}

/// Produce `count` distinct salts with the most significant bit set: a random
/// 15-bit base, incremented per attribute (RFC 2548 §2.4.2 uniqueness rule;
/// RFC 2868 §3.5 Tunnel-Password shares the same salt space).
pub fn generate_salts(count: usize) -> Vec<[u8; 2]> {
    use rand::RngExt;
    let base: u16 = rand::rng().random::<u16>() & 0x7FFF;
    (0..count)
        .map(|i| (0x8000 | (base.wrapping_add(i as u16) & 0x7FFF)).to_be_bytes())
        .collect()
}

/// The pair of MPPE keys carried on an Access-Accept.
#[derive(Clone, PartialEq, Eq)]
pub struct MppeKeys {
    /// MS-MPPE-Send-Key (vendor type 16): NAS → peer direction.
    pub send_key: Vec<u8>,
    /// MS-MPPE-Recv-Key (vendor type 17): peer → NAS direction.
    pub recv_key: Vec<u8>,
}

impl std::fmt::Debug for MppeKeys {
    /// Never print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MppeKeys")
            .field("send_key_len", &self.send_key.len())
            .field("recv_key_len", &self.recv_key.len())
            .finish()
    }
}

impl MppeKeys {
    /// Split an EAP MSK into the two MPPE keys: Recv-Key = MSK[0..32],
    /// Send-Key = MSK[32..64] (RFC 5216 §2.3; any octets beyond 64 are unused).
    pub fn from_msk(msk: &[u8]) -> Result<Self, MppeError> {
        if msk.len() < MIN_MSK_LENGTH {
            return Err(MppeError::MskTooShort(msk.len()));
        }
        Ok(MppeKeys {
            recv_key: msk[..MPPE_KEY_LENGTH].to_vec(),
            send_key: msk[MPPE_KEY_LENGTH..MIN_MSK_LENGTH].to_vec(),
        })
    }

    /// Encrypt both keys for the Access-Accept answering the request with
    /// `request_authenticator`, using freshly generated distinct salts.
    /// Returns `[MS-MPPE-Send-Key, MS-MPPE-Recv-Key]`.
    pub fn to_attributes(
        &self,
        secret: &[u8],
        request_authenticator: &[u8; 16],
    ) -> Result<Vec<Attribute>, MppeError> {
        let salts = generate_salts(2);
        self.to_attributes_with_salts(secret, request_authenticator, salts[0], salts[1])
    }

    /// Deterministic variant of [`MppeKeys::to_attributes`] with caller-chosen
    /// salts (the two must differ).
    pub fn to_attributes_with_salts(
        &self,
        secret: &[u8],
        request_authenticator: &[u8; 16],
        send_salt: [u8; 2],
        recv_salt: [u8; 2],
    ) -> Result<Vec<Attribute>, MppeError> {
        if send_salt == recv_salt {
            return Err(MppeError::InvalidSalt(u16::from_be_bytes(recv_salt)));
        }
        Ok(vec![
            encrypt_key_attribute(
                MS_MPPE_SEND_KEY,
                &self.send_key,
                secret,
                request_authenticator,
                send_salt,
            )?,
            encrypt_key_attribute(
                MS_MPPE_RECV_KEY,
                &self.recv_key,
                secret,
                request_authenticator,
                recv_salt,
            )?,
        ])
    }

    /// Decrypt the MPPE keys from a received Access-Accept.
    ///
    /// `request_authenticator` is the authenticator of the Access-Request the
    /// packet answers. Returns `Ok(None)` when the packet carries neither key,
    /// and an error when only one is present or either fails to decrypt.
    pub fn from_packet(
        packet: &Packet,
        secret: &[u8],
        request_authenticator: &[u8; 16],
    ) -> Result<Option<Self>, MppeError> {
        let send = packet.find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY);
        let recv = packet.find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY);
        match (send.first(), recv.first()) {
            (None, None) => Ok(None),
            (Some(s), Some(r)) => Ok(Some(MppeKeys {
                send_key: decrypt_key(&s.value, secret, request_authenticator)?,
                recv_key: decrypt_key(&r.value, secret, request_authenticator)?,
            })),
            (Some(_), None) => Err(MppeError::Attribute(PacketError::AttributeError(
                "MS-MPPE-Send-Key present without MS-MPPE-Recv-Key".into(),
            ))),
            (None, Some(_)) => Err(MppeError::Attribute(PacketError::AttributeError(
                "MS-MPPE-Recv-Key present without MS-MPPE-Send-Key".into(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Code;

    const SECRET: &[u8] = b"testing123";
    const REQ_AUTH: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    /// Known-answer vectors. RFC 2548 publishes no worked example, so these
    /// were produced by an independent, from-the-text implementation of
    /// §2.4.2 (Python `hashlib.md5`, ~20 lines) and are pinned here so any
    /// change to the XOR chain, padding or Key-Length framing is caught.
    #[test]
    fn kat_32_octet_key_salt_8001() {
        let key: Vec<u8> = (0x01..=0x20).collect();
        let enc = encrypt_key(&key, SECRET, &REQ_AUTH, [0x80, 0x01]).unwrap();
        assert_eq!(
            hex::encode(&enc),
            "800112a5064e0e1f233fc72eba60beb71bfce4ede0d50ba52bc0a32f0da3fa38cd7b156dc665e0e02367d63cd5e8aebca0bc"
        );
        assert_eq!(enc.len(), SALT_LENGTH + 3 * BLOCK);
        assert_eq!(decrypt_key(&enc, SECRET, &REQ_AUTH).unwrap(), key);
    }

    #[test]
    fn kat_8_octet_key_is_zero_padded_to_one_block() {
        let key = hex::decode("0123456789abcdef").unwrap();
        let enc = encrypt_key(&key, SECRET, &REQ_AUTH, [0x80, 0x02]).unwrap();
        assert_eq!(hex::encode(&enc), "80021f4a1d7b8b92377fdde0f3bbf0f33204");
        assert_eq!(decrypt_key(&enc, SECRET, &REQ_AUTH).unwrap(), key);
    }

    #[test]
    fn kat_15_octet_key_fills_one_block_exactly() {
        let key = b"fifteen-octets!";
        let enc = encrypt_key(key, SECRET, &REQ_AUTH, [0xff, 0xff]).unwrap();
        assert_eq!(hex::encode(&enc), "ffff4d40a057594c52ee41a00e75403d282f");
        assert_eq!(decrypt_key(&enc, SECRET, &REQ_AUTH).unwrap(), key);
    }

    #[test]
    fn first_block_matches_user_password_style_md5() {
        // b(1) = MD5(secret || RA || salt); c(1) = p(1) XOR b(1). Check the
        // chain start independently of the KATs.
        let key = [0xAAu8; 5];
        let salt = [0x90, 0x12];
        let enc = encrypt_key(&key, SECRET, &REQ_AUTH, salt).unwrap();
        let mut data = SECRET.to_vec();
        data.extend_from_slice(&REQ_AUTH);
        data.extend_from_slice(&salt);
        let b1 = md5::compute(&data).0;
        let mut p1 = vec![5u8];
        p1.extend_from_slice(&key);
        p1.resize(16, 0);
        let c1: Vec<u8> = p1.iter().zip(b1.iter()).map(|(p, b)| p ^ b).collect();
        assert_eq!(&enc[2..], &c1[..]);
    }

    #[test]
    fn round_trip_all_lengths_up_to_max() {
        for len in 0..=MAX_KEY_LENGTH {
            let key: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = encrypt_key(&key, SECRET, &REQ_AUTH, [0x80, 0x00]).unwrap();
            assert_eq!(enc.len(), SALT_LENGTH + (1 + len).div_ceil(BLOCK) * BLOCK);
            assert!(enc.len() <= VendorSpecific::MAX_VALUE_LENGTH);
            assert_eq!(
                decrypt_key(&enc, SECRET, &REQ_AUTH).unwrap(),
                key,
                "len {len}"
            );
        }
        assert!(matches!(
            encrypt_key(&vec![0; MAX_KEY_LENGTH + 1], SECRET, &REQ_AUTH, [0x80, 0x00]),
            Err(MppeError::KeyTooLong(n)) if n == MAX_KEY_LENGTH + 1
        ));
    }

    #[test]
    fn salt_must_have_high_bit_set() {
        assert!(matches!(
            encrypt_key(b"k", SECRET, &REQ_AUTH, [0x7f, 0xff]),
            Err(MppeError::InvalidSalt(0x7fff))
        ));
        let mut enc = encrypt_key(b"k", SECRET, &REQ_AUTH, [0x80, 0x00]).unwrap();
        enc[0] = 0x00;
        assert!(matches!(
            decrypt_key(&enc, SECRET, &REQ_AUTH),
            Err(MppeError::InvalidSalt(0x0000))
        ));
    }

    #[test]
    fn decrypt_rejects_bad_lengths() {
        for bad in [vec![0x80, 0x01], vec![0x80; 17], vec![0x80; 19]] {
            let len = bad.len();
            assert!(matches!(
                decrypt_key(&bad, SECRET, &REQ_AUTH),
                Err(MppeError::InvalidLength(n)) if n == len
            ));
        }
    }

    #[test]
    fn wrong_secret_or_authenticator_does_not_yield_the_key() {
        let key: Vec<u8> = (0..32).collect();
        let enc = encrypt_key(&key, SECRET, &REQ_AUTH, [0x80, 0x01]).unwrap();
        // Either an error (garbage length octet) or a different key — never
        // the plaintext.
        if let Ok(k) = decrypt_key(&enc, b"wrong", &REQ_AUTH) {
            assert_ne!(k, key);
        }
        if let Ok(k) = decrypt_key(&enc, SECRET, &[0xFF; 16]) {
            assert_ne!(k, key);
        }
    }

    #[test]
    fn generate_salts_are_distinct_with_high_bit() {
        for _ in 0..64 {
            let salts = generate_salts(2);
            assert_eq!(salts.len(), 2);
            assert_ne!(salts[0], salts[1]);
            assert!(salts.iter().all(|s| s[0] & 0x80 != 0));
        }
        // Counter wraps within the 15-bit space without clearing the MSB.
        let salts = generate_salts(40_000);
        assert!(salts.iter().all(|s| s[0] & 0x80 != 0));
    }

    #[test]
    fn msk_split_follows_rfc_5216() {
        let msk: Vec<u8> = (0..64).collect();
        let keys = MppeKeys::from_msk(&msk).unwrap();
        assert_eq!(keys.recv_key, msk[..32]);
        assert_eq!(keys.send_key, msk[32..64]);
        assert!(matches!(
            MppeKeys::from_msk(&msk[..63]),
            Err(MppeError::MskTooShort(63))
        ));
        // Longer MSKs (e.g. a future method) use only the first 64 octets.
        let long: Vec<u8> = (0..100).map(|i| i as u8).collect();
        assert_eq!(MppeKeys::from_msk(&long).unwrap(), keys);
    }

    #[test]
    fn attributes_round_trip_through_a_packet() {
        let msk: Vec<u8> = (0..64).map(|i| 255 - i).collect();
        let keys = MppeKeys::from_msk(&msk).unwrap();
        let attrs = keys.to_attributes(SECRET, &REQ_AUTH).unwrap();
        assert_eq!(attrs.len(), 2);

        let mut p = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
        for a in attrs {
            p.add_attribute(a);
        }
        // Survive a wire round trip.
        let p = Packet::decode(&p.encode().unwrap()).unwrap();

        let send = p.find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY);
        let recv = p.find_vendor_attributes(MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY);
        assert_eq!(send.len(), 1);
        assert_eq!(recv.len(), 1);
        // 2-octet salt + 48 octets of ciphertext (33 plaintext → 3 blocks).
        assert_eq!(send[0].value.len(), 50);
        assert_ne!(send[0].value[..2], recv[0].value[..2], "salts must differ");

        let decoded = MppeKeys::from_packet(&p, SECRET, &REQ_AUTH)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, keys);
    }

    #[test]
    fn deterministic_attributes_match_kat() {
        let mut msk = vec![0u8; 32];
        msk.extend(0x01..=0x20u8);
        let keys = MppeKeys::from_msk(&msk).unwrap();
        let attrs = keys
            .to_attributes_with_salts(SECRET, &REQ_AUTH, [0x80, 0x01], [0x80, 0x02])
            .unwrap();
        // Send-Key = MSK[32..64] = 0x01..0x20 under salt 8001 → first KAT.
        let send = VendorSpecific::from_attribute(&attrs[0]).unwrap();
        assert_eq!(send[0].vendor_id, MICROSOFT_VENDOR_ID);
        assert_eq!(send[0].vendor_type, MS_MPPE_SEND_KEY);
        assert_eq!(
            hex::encode(&send[0].value),
            "800112a5064e0e1f233fc72eba60beb71bfce4ede0d50ba52bc0a32f0da3fa38cd7b156dc665e0e02367d63cd5e8aebca0bc"
        );
        let recv = VendorSpecific::from_attribute(&attrs[1]).unwrap();
        assert_eq!(recv[0].vendor_type, MS_MPPE_RECV_KEY);
        assert_eq!(&recv[0].value[..2], &[0x80, 0x02]);

        assert!(
            keys.to_attributes_with_salts(SECRET, &REQ_AUTH, [0x80, 0x01], [0x80, 0x01])
                .is_err()
        );
    }

    #[test]
    fn from_packet_absent_and_half_present() {
        let mut p = Packet::new(Code::AccessAccept, 1, [0u8; 16]);
        assert!(matches!(
            MppeKeys::from_packet(&p, SECRET, &REQ_AUTH),
            Ok(None)
        ));
        p.add_attribute(
            encrypt_key_attribute(MS_MPPE_SEND_KEY, &[1; 32], SECRET, &REQ_AUTH, [0x80, 0])
                .unwrap(),
        );
        assert!(MppeKeys::from_packet(&p, SECRET, &REQ_AUTH).is_err());
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let keys = MppeKeys::from_msk(&[0x42; 64]).unwrap();
        let s = format!("{keys:?}");
        assert!(!s.contains("42, 42"));
        assert!(s.contains("send_key_len: 32"));
    }
}
