//! Known-answer-test (KAT) vectors for the authenticator ↔ RADIUS wire format
//! (SERVER-CONTRACT §5 V-5).
//!
//! These byte-exact vectors lock the encoding of the packets both ends exchange,
//! so a change to the codec on either side is caught immediately. They live in
//! the shared `radius-proto` crate so usg-radius and usg-authenticator validate
//! against the *same* bytes.
//!
//! The 16-octet Authenticator field is fixed to [`KAT_AUTHENTICATOR`] so the
//! vectors are deterministic; the Request/Response Authenticator *algorithms* are
//! covered by [`crate::auth`] tests, not here.

use crate::{Attribute, AttributeType, Code, Packet};

/// Fixed Authenticator used in every KAT packet so the bytes are deterministic.
/// (ASCII "RADIUS-KAT-VEC1".)
pub const KAT_AUTHENTICATOR: [u8; 16] = *b"RADIUS-KAT-VEC1\0";

/// Canonical bytes of [`vlan_access_accept`] (lowercase hex).
pub const VLAN_ACCESS_ACCEPT: &str =
    "020700255241444955532d4b41542d564543310040060100000d4106010000065105013432";

/// Canonical bytes of [`filter_id_access_accept`] (lowercase hex).
pub const FILTER_ID_ACCESS_ACCEPT: &str =
    "020800245241444955532d4b41542d56454331000b1051756172616e74696e652d41434c";

/// Canonical bytes of [`fragmented_eap_access_request`] (lowercase hex).
pub const FRAGMENTED_EAP_ACCESS_REQUEST: &str = "0109014b5241444955532d4b41542d56454331000107616c6963654fff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa00014f3102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";

/// **VLAN-assigning Access-Accept** (SERVER-CONTRACT §3.1). An RFC 2868 tag-1
/// group assigning VLAN 42:
/// - `Tunnel-Type` (64): tagged integer `01 00 00 0D` → VLAN (13)
/// - `Tunnel-Medium-Type` (65): tagged integer `01 00 00 06` → 802 (6)
/// - `Tunnel-Private-Group-ID` (81): tag `01` + ASCII `"42"`
#[must_use]
pub fn vlan_access_accept() -> Packet {
    let mut p = Packet::new(Code::AccessAccept, 0x07, KAT_AUTHENTICATOR);
    // RFC 2868 tunnel attributes (no enum variants; encoded by number, matching
    // the server's policy_enforce emit path): 64 / 65 / 81.
    p.add_attribute(Attribute::new(64, vec![0x01, 0x00, 0x00, 0x0D]).unwrap());
    p.add_attribute(Attribute::new(65, vec![0x01, 0x00, 0x00, 0x06]).unwrap());
    let mut tpg = vec![0x01];
    tpg.extend_from_slice(b"42");
    p.add_attribute(Attribute::new(81, tpg).unwrap());
    p
}

/// **`Filter-Id` Access-Accept** (SERVER-CONTRACT §3.2): a named ACL the switch
/// already has provisioned — `Filter-Id` (11) = `"Quarantine-ACL"`.
#[must_use]
pub fn filter_id_access_accept() -> Packet {
    let mut p = Packet::new(Code::AccessAccept, 0x08, KAT_AUTHENTICATOR);
    p.add_attribute(Attribute::string(AttributeType::FilterId as u8, "Quarantine-ACL").unwrap());
    p
}

/// **Fragmented EAP-Message Access-Request** (SERVER-CONTRACT §2, RFC 3579 §3.1):
/// a 300-octet EAP payload split across two `EAP-Message` (79) attributes
/// (253 + 47), plus `User-Name`. The deterministic payload is `i % 251`.
#[must_use]
pub fn fragmented_eap_access_request() -> Packet {
    let mut p = Packet::new(Code::AccessRequest, 0x09, KAT_AUTHENTICATOR);
    p.add_attribute(Attribute::string(AttributeType::UserName as u8, "alice").unwrap());
    let eap: Vec<u8> = (0..300u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    for chunk in eap.chunks(253) {
        p.add_attribute(Attribute::new(AttributeType::EapMessage as u8, chunk.to_vec()).unwrap());
    }
    p
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Each builder encodes to exactly its published vector, and each vector
    /// decodes and re-encodes back to itself (encode and decode are both locked).
    #[test]
    fn vectors_are_byte_exact_and_round_trip() {
        for (build, vector) in [
            (vlan_access_accept as fn() -> Packet, VLAN_ACCESS_ACCEPT),
            (filter_id_access_accept, FILTER_ID_ACCESS_ACCEPT),
            (fragmented_eap_access_request, FRAGMENTED_EAP_ACCESS_REQUEST),
        ] {
            assert_eq!(hex(&build().encode().unwrap()), vector, "encode mismatch");
            let decoded = Packet::decode(&unhex(vector)).unwrap();
            assert_eq!(
                hex(&decoded.encode().unwrap()),
                vector,
                "decode round-trip mismatch"
            );
        }
    }

    /// Spot-check the decoded structure so the vectors are self-documenting.
    #[test]
    fn vector_structure() {
        let vlan = Packet::decode(&unhex(VLAN_ACCESS_ACCEPT)).unwrap();
        assert_eq!(vlan.code, Code::AccessAccept);
        assert_eq!(vlan.find_attribute(81).unwrap().value, b"\x0142");

        let filt = Packet::decode(&unhex(FILTER_ID_ACCESS_ACCEPT)).unwrap();
        assert_eq!(
            filt.find_attribute(AttributeType::FilterId as u8)
                .unwrap()
                .value,
            b"Quarantine-ACL"
        );

        // EAP-Message fragmented across two attributes (253 + 47 = 300 octets).
        let eap = Packet::decode(&unhex(FRAGMENTED_EAP_ACCESS_REQUEST)).unwrap();
        let frags: Vec<_> = eap
            .attributes
            .iter()
            .filter(|a| a.attr_type == AttributeType::EapMessage as u8)
            .collect();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].value.len(), 253);
        assert_eq!(frags[1].value.len(), 47);
    }
}
