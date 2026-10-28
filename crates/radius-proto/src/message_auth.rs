//! Message-Authenticator Support (RFC 2869)
//!
//! This module implements the Message-Authenticator attribute for RADIUS.
//! Message-Authenticator provides integrity protection using HMAC-MD5.
//!
//! Per RFC 2869 Section 5.14:
//! - Computed as HMAC-MD5(shared_secret, packet)
//! - Always 16 bytes (128 bits)
//! - Required for Access-Request with EAP-Message
//! - Recommended for Access-Challenge, Access-Accept, Access-Reject with EAP
//!
//! The Message-Authenticator is computed over the entire RADIUS packet with:
//! - The *Request* Authenticator in the Authenticator field for both requests
//!   and responses (RFC 2869 §5.14: for Access-Accept, Access-Challenge and
//!   Access-Reject the HMAC is computed before the Response Authenticator, with
//!   the Request Authenticator in the header)
//! - Message-Authenticator field set to all zeros during calculation

use hmac::{Hmac, KeyInit, Mac};
use md5_digest::Md5;

type HmacMd5 = Hmac<Md5>;

/// Calculate Message-Authenticator for a RADIUS packet
///
/// # Arguments
/// * `packet_bytes` - The complete RADIUS packet bytes with Message-Authenticator set to zeros
/// * `secret` - The shared secret
///
/// # Returns
/// 16-byte HMAC-MD5 hash
pub fn calculate_message_authenticator(packet_bytes: &[u8], secret: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(packet_bytes);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut output = [0u8; 16];
    output.copy_from_slice(&bytes);
    output
}

/// Verify Message-Authenticator in a RADIUS packet
///
/// # Arguments
/// * `packet_bytes` - The complete RADIUS packet bytes
/// * `secret` - The shared secret
/// * `message_auth_offset` - Byte offset where Message-Authenticator value starts (after type+length)
///
/// # Returns
/// true if Message-Authenticator is valid, false otherwise
pub fn verify_message_authenticator(
    packet_bytes: &[u8],
    secret: &[u8],
    message_auth_offset: usize,
) -> bool {
    if message_auth_offset + 16 > packet_bytes.len() {
        return false;
    }

    // Extract the Message-Authenticator from the packet
    let received_auth = &packet_bytes[message_auth_offset..message_auth_offset + 16];

    // Create a copy of the packet with Message-Authenticator set to zeros
    let mut packet_copy = packet_bytes.to_vec();
    packet_copy[message_auth_offset..message_auth_offset + 16].fill(0);

    // Constant-time comparison (CWE-208): `Mac::verify_slice` compares through
    // `subtle`, so a wrong guess costs the same whatever its first octets are.
    let mut mac = HmacMd5::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&packet_copy);
    mac.verify_slice(received_auth).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_message_authenticator() {
        let packet = vec![0u8; 20]; // Minimal packet header
        let secret = b"testing123";

        let auth = calculate_message_authenticator(&packet, secret);
        assert_eq!(auth.len(), 16);

        // Should be deterministic
        let auth2 = calculate_message_authenticator(&packet, secret);
        assert_eq!(auth, auth2);
    }

    #[test]
    fn test_message_authenticator_different_secrets() {
        let packet = vec![0u8; 20];
        let secret1 = b"secret1";
        let secret2 = b"secret2";

        let auth1 = calculate_message_authenticator(&packet, secret1);
        let auth2 = calculate_message_authenticator(&packet, secret2);

        assert_ne!(
            auth1, auth2,
            "Different secrets should produce different authenticators"
        );
    }

    #[test]
    fn test_message_authenticator_different_packets() {
        let packet1 = vec![0u8; 20];
        let mut packet2 = vec![0u8; 20];
        packet2[0] = 1; // Change one byte
        let secret = b"testing123";

        let auth1 = calculate_message_authenticator(&packet1, secret);
        let auth2 = calculate_message_authenticator(&packet2, secret);

        assert_ne!(
            auth1, auth2,
            "Different packets should produce different authenticators"
        );
    }

    #[test]
    fn test_verify_message_authenticator_valid() {
        // Create a packet with space for Message-Authenticator
        let mut packet = vec![0u8; 40];
        let secret = b"testing123";
        let msg_auth_offset = 20;

        // Calculate and insert Message-Authenticator
        let auth = calculate_message_authenticator(&packet, secret);
        packet[msg_auth_offset..msg_auth_offset + 16].copy_from_slice(&auth);

        // Verify should succeed
        assert!(verify_message_authenticator(
            &packet,
            secret,
            msg_auth_offset
        ));
    }

    #[test]
    fn test_verify_message_authenticator_invalid() {
        let mut packet = vec![0u8; 40];
        let secret = b"testing123";
        let msg_auth_offset = 20;

        // Insert wrong Message-Authenticator
        packet[msg_auth_offset..msg_auth_offset + 16].fill(0xFF);

        // Verify should fail
        assert!(!verify_message_authenticator(
            &packet,
            secret,
            msg_auth_offset
        ));
    }

    #[test]
    fn test_verify_message_authenticator_wrong_secret() {
        let mut packet = vec![0u8; 40];
        let secret1 = b"secret1";
        let secret2 = b"secret2";
        let msg_auth_offset = 20;

        // Calculate with secret1
        let auth = calculate_message_authenticator(&packet, secret1);
        packet[msg_auth_offset..msg_auth_offset + 16].copy_from_slice(&auth);

        // Verify with secret2 should fail
        assert!(!verify_message_authenticator(
            &packet,
            secret2,
            msg_auth_offset
        ));
    }

    #[test]
    fn test_verify_message_authenticator_out_of_bounds() {
        let packet = vec![0u8; 20];
        let secret = b"testing123";

        // Offset beyond packet length
        assert!(!verify_message_authenticator(&packet, secret, 100));
    }
}
