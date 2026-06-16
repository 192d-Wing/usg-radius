use crate::packet::Packet;
use rand::Rng;

/// Generate a random Request Authenticator (16 bytes) per RFC 2865 Section 3
pub fn generate_request_authenticator() -> [u8; 16] {
    let mut rng = rand::rng();
    let mut authenticator = [0u8; 16];
    rng.fill(&mut authenticator);
    authenticator
}

/// Calculate Accounting Request Authenticator per RFC 2866 Section 3
///
/// Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
///
/// This is used for Accounting-Request packets (Code 4), and — by the same
/// algorithm (RFC 5176 §3.4) — for Disconnect-Request (40) and CoA-Request (43).
/// The function keys off `packet.code`, so it is correct for all of them.
/// The authenticator field should be set to all zeros before calling this function.
pub fn calculate_accounting_request_authenticator(packet: &Packet, secret: &[u8]) -> [u8; 16] {
    let mut data = Vec::new();

    // Code (1 byte)
    data.push(packet.code.as_u8());

    // Identifier (1 byte)
    data.push(packet.identifier);

    // Length (2 bytes)
    let length = packet.length();
    data.push((length >> 8) as u8);
    data.push((length & 0xff) as u8);

    // 16 zero octets (placeholder for authenticator)
    data.extend_from_slice(&[0u8; 16]);

    // Attributes
    for attr in &packet.attributes {
        let encoded = attr.encode().expect("Failed to encode attribute");
        data.extend_from_slice(&encoded);
    }

    // Secret
    data.extend_from_slice(secret);

    // Calculate MD5
    let digest = md5::compute(&data);
    let mut authenticator = [0u8; 16];
    authenticator.copy_from_slice(&digest.0);
    authenticator
}

/// Calculate Response Authenticator per RFC 2865 Section 3
///
/// Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Attributes + Secret)
///
/// This is used for Access-Accept, Access-Reject, and Access-Challenge packets.
pub fn calculate_response_authenticator(
    packet: &Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> [u8; 16] {
    let mut data = Vec::new();

    // Code (1 byte)
    data.push(packet.code.as_u8());

    // Identifier (1 byte)
    data.push(packet.identifier);

    // Length (2 bytes)
    let length = packet.length();
    data.push((length >> 8) as u8);
    data.push((length & 0xff) as u8);

    // Request Authenticator (16 bytes)
    data.extend_from_slice(request_authenticator);

    // Attributes
    for attr in &packet.attributes {
        let encoded = attr.encode().expect("Failed to encode attribute");
        data.extend_from_slice(&encoded);
    }

    // Secret
    data.extend_from_slice(secret);

    // Calculate MD5
    let digest = md5::compute(&data);
    let mut authenticator = [0u8; 16];
    authenticator.copy_from_slice(&digest.0);
    authenticator
}

/// Verify Request Authenticator for Access-Request packets
///
/// Per RFC 2865 Section 3, the Request Authenticator in Access-Request is a random value.
/// We don't verify it directly, but we use it to verify the Response Authenticator.
pub fn verify_request_authenticator(packet: &Packet) -> bool {
    // For Access-Request, the authenticator should be 16 bytes of random data
    // We just verify it's the correct length, actual verification happens in response
    packet.authenticator.len() == 16
}

/// Verify Response Authenticator
///
/// Verifies that the Response Authenticator matches the expected value
/// calculated from the request and secret.
pub fn verify_response_authenticator(
    response: &Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> bool {
    let calculated = calculate_response_authenticator(response, request_authenticator, secret);
    response.authenticator == calculated
}

/// Encrypt User-Password attribute per RFC 2865 Section 5.2
///
/// The password is first padded to a multiple of 16 bytes, then XORed with
/// MD5(secret + request_authenticator) for the first 16 bytes, and
/// MD5(secret + previous_block) for subsequent blocks.
pub fn encrypt_user_password(password: &str, secret: &[u8], authenticator: &[u8; 16]) -> Vec<u8> {
    let password_bytes = password.as_bytes();

    // Pad password to multiple of 16 bytes
    let mut padded = password_bytes.to_vec();
    let padding_needed = (16 - (padded.len() % 16)) % 16;
    if padding_needed > 0 || padded.is_empty() {
        padded.resize(padded.len() + padding_needed, 0);
    }
    if padded.is_empty() {
        padded.resize(16, 0);
    }

    let mut result = Vec::new();
    let mut previous_block = authenticator.to_vec();

    for chunk in padded.chunks(16) {
        let mut data = Vec::new();
        data.extend_from_slice(secret);
        data.extend_from_slice(&previous_block);
        let hash = md5::compute(&data);

        let mut encrypted_block = [0u8; 16];
        for i in 0..16 {
            encrypted_block[i] = chunk[i] ^ hash.0[i];
        }

        previous_block = encrypted_block.to_vec();
        result.extend_from_slice(&encrypted_block);
    }

    result
}

/// Decrypt User-Password attribute per RFC 2865 Section 5.2
pub fn decrypt_user_password(
    encrypted: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> Result<String, String> {
    if !encrypted.len().is_multiple_of(16) || encrypted.is_empty() {
        return Err("Invalid encrypted password length".to_string());
    }

    let mut result = Vec::new();
    let mut previous_block = authenticator.to_vec();

    for chunk in encrypted.chunks(16) {
        let mut data = Vec::new();
        data.extend_from_slice(secret);
        data.extend_from_slice(&previous_block);
        let hash = md5::compute(&data);

        let mut decrypted_block = [0u8; 16];
        for i in 0..16 {
            decrypted_block[i] = chunk[i] ^ hash.0[i];
        }

        previous_block = chunk.to_vec();
        result.extend_from_slice(&decrypted_block);
    }

    // Remove padding (null bytes at the end)
    while result.last() == Some(&0) {
        result.pop();
    }

    String::from_utf8(result).map_err(|e| format!("Invalid UTF-8 in password: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Code;

    #[test]
    fn test_generate_authenticator() {
        let auth1 = generate_request_authenticator();
        let auth2 = generate_request_authenticator();
        assert_eq!(auth1.len(), 16);
        assert_eq!(auth2.len(), 16);
        // Should be random
        assert_ne!(auth1, auth2);
    }

    #[test]
    fn test_password_encryption_decryption() {
        let password = "mysecretpassword";
        let secret = b"sharedsecret";
        let authenticator = [1u8; 16];

        let encrypted = encrypt_user_password(password, secret, &authenticator);
        let decrypted = decrypt_user_password(&encrypted, secret, &authenticator).unwrap();

        assert_eq!(password, decrypted);
    }

    #[test]
    fn test_password_encryption_empty() {
        let password = "";
        let secret = b"sharedsecret";
        let authenticator = [1u8; 16];

        let encrypted = encrypt_user_password(password, secret, &authenticator);
        assert_eq!(encrypted.len(), 16); // Should be padded to 16 bytes
    }

    #[test]
    fn test_response_authenticator() {
        let secret = b"sharedsecret";
        let request_auth = [1u8; 16];
        let mut packet = Packet::new(Code::AccessAccept, 42, [0u8; 16]);

        let response_auth = calculate_response_authenticator(&packet, &request_auth, secret);
        packet.authenticator = response_auth;

        assert!(verify_response_authenticator(
            &packet,
            &request_auth,
            secret
        ));
    }

    #[test]
    fn test_accounting_request_authenticator() {
        use crate::Attribute;

        let secret = b"testing123";

        // Create a packet with zero authenticator
        let mut packet = Packet::new(Code::AccountingRequest, 1, [0u8; 16]);

        // Add some attributes (like in the integration test)
        packet.add_attribute(Attribute::new(40, vec![0, 0, 0, 1]).unwrap()); // Acct-Status-Type = Start
        packet.add_attribute(Attribute::string(44, "session123").unwrap()); // Acct-Session-Id
        packet.add_attribute(Attribute::string(1, "testuser").unwrap()); // User-Name

        // Calculate authenticator on client side
        let client_auth = calculate_accounting_request_authenticator(&packet, secret);
        packet.authenticator = client_auth;

        // Server side validation: create copy with zero authenticator
        let mut validation_packet = packet.clone();
        validation_packet.authenticator = [0u8; 16];
        let server_auth = calculate_accounting_request_authenticator(&validation_packet, secret);

        // They should match
        assert_eq!(client_auth, server_auth);
        assert_eq!(packet.authenticator, server_auth);
    }
}
