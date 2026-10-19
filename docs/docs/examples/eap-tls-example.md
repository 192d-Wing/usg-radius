# EAP-TLS Authentication Example

This example demonstrates how to use the EAP-TLS implementation for certificate-based authentication.

## Prerequisites

Before running this example, you need:

1. Server certificate and private key
2. (Optional) CA certificate for client verification
3. RADIUS server configured with EAP support

## Setup

### 1. Generate Test Certificates

For testing purposes, generate self-signed certificates:

```bash
#!/bin/bash
# generate-test-certs.sh

# Create certificates directory
mkdir -p certs
cd certs

# 1. Generate CA
echo "Generating CA..."
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem -days 3650 \
    -subj "/C=US/ST=TestState/L=TestCity/O=TestOrg/CN=Test CA"

# 2. Generate Server Certificate
echo "Generating server certificate..."
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=US/ST=TestState/L=TestCity/O=TestOrg/CN=radius.test.local"

# Sign with CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 365

# 3. Generate Client Certificate (for mutual TLS)
echo "Generating client certificate..."
openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out client.csr \
    -subj "/C=US/ST=TestState/L=TestCity/O=TestOrg/CN=testuser@test.local"

# Sign with CA
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out client.pem -days 365

# 4. Create PKCS#12 for client (for distribution)
openssl pkcs12 -export -out client.p12 \
    -inkey client-key.pem -in client.pem -certfile ca.pem \
    -passout pass:testpassword

# Set proper permissions
chmod 600 *-key.pem
chmod 644 *.pem

echo "Certificates generated successfully!"
echo "  CA: ca.pem"
echo "  Server: server.pem, server-key.pem"
echo "  Client: client.pem, client-key.pem, client.p12"
```

### 2. Verify Certificates

```bash
# Verify certificate chain
openssl verify -CAfile ca.pem server.pem
openssl verify -CAfile ca.pem client.pem

# View certificate details
openssl x509 -in server.pem -text -noout
openssl x509 -in client.pem -text -noout
```

## Example Code

### Basic EAP-TLS Server Setup

```rust
use radius_proto::eap::eap_tls::*;
use radius_proto::eap::{EapPacket, EapCode, EapType, EapSession};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load server certificate and key
    println!("Loading certificates...");

    let cert_config = TlsCertificateConfig::simple(
        "certs/server.pem".to_string(),
        "certs/server-key.pem".to_string(),
    );

    let certs = load_certificates_from_pem(&cert_config.server_cert_path)?;
    let key = load_private_key_from_pem(&cert_config.server_key_path)?;

    println!("Loaded {} certificate(s)", certs.len());
    println!("Server certificate: {} bytes", certs[0].len());
    println!("Private key: {} bytes", key.len());

    // 2. Validate certificate
    validate_cert_key_pair(&certs[0], &key)?;
    println!("Certificate validation: OK");

    // 3. Create EAP session
    let mut eap_session = EapSession::new("testuser@test.local".to_string());

    // 4. Create EAP-TLS context
    let mut tls_ctx = EapTlsContext::new();

    // 5. Send EAP-TLS Start
    println!("\n--- EAP-TLS Handshake Start ---");
    let start_packet = EapTlsPacket::start();
    let eap_start = start_packet.to_eap_request(eap_session.next_identifier());

    println!("Sent: EAP-Request/TLS (Start)");
    println!("  Identifier: {}", eap_start.identifier);
    println!("  Flags: S (Start)");

    // At this point, the packet would be wrapped in RADIUS Access-Challenge
    // and sent to the client. The client would respond with ClientHello.

    println!("\nEAP-TLS context initialized successfully!");
    println!("Ready to process TLS handshake messages.");

    Ok(())
}
```

### Handling Fragmentation

```rust
use radius_proto::eap::eap_tls::*;

fn demonstrate_fragmentation() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = EapTlsContext::new();

    // Simulate large TLS ServerHello + Certificate message (>16KB)
    let large_tls_message = vec![0x16; 20000]; // 20KB of TLS data

    println!("Large TLS message: {} bytes", large_tls_message.len());

    // Fragment the message
    let max_fragment_size = 1020; // Typical for Ethernet MTU
    ctx.queue_tls_data(large_tls_message.clone(), max_fragment_size);

    println!("Fragmented into {} packets", ctx.outgoing_fragments.len());

    // Send fragments one at a time
    let mut identifier = 1u8;
    let mut fragment_num = 1;

    while ctx.has_pending_fragments() {
        if let Some(fragment) = ctx.get_next_fragment() {
            let eap_packet = fragment.to_eap_request(identifier);
            identifier = identifier.wrapping_add(1);

            println!("\nFragment {}: {} bytes", fragment_num, fragment.tls_data.len());
            println!("  Flags: L={}, M={}, S={}",
                fragment.flags.length_included(),
                fragment.flags.more_fragments(),
                fragment.flags.start()
            );

            if let Some(len) = fragment.tls_message_length {
                println!("  Total Length: {} bytes", len);
            }

            fragment_num += 1;
        }
    }

    println!("\nAll fragments sent!");
    Ok(())
}
```

### Receiving Fragmented Messages

```rust
use radius_proto::eap::eap_tls::*;

fn demonstrate_fragment_reception() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = EapTlsContext::new();

    // Simulate receiving fragmented TLS ClientKeyExchange message

    // Fragment 1 (with L and M flags)
    println!("Receiving fragment 1...");
    let frag1 = EapTlsPacket::new(
        TlsFlags::new(true, true, false),  // L=1, M=1, S=0
        Some(1500),                        // Total length
        vec![0x16; 995],                   // First chunk
    );

    match ctx.process_incoming(&frag1)? {
        Some(_) => println!("  Complete!"),
        None => println!("  Waiting for more fragments..."),
    }

    // Fragment 2 (with M flag only)
    println!("Receiving fragment 2...");
    let frag2 = EapTlsPacket::new(
        TlsFlags::new(false, true, false), // L=0, M=1, S=0
        None,
        vec![0x16; 500],
    );

    match ctx.process_incoming(&frag2)? {
        Some(_) => println!("  Complete!"),
        None => println!("  Waiting for more fragments..."),
    }

    // Fragment 3 (final, no flags)
    println!("Receiving fragment 3 (final)...");
    let frag3 = EapTlsPacket::new(
        TlsFlags::new(false, false, false), // L=0, M=0, S=0
        None,
        vec![0x16; 5],
    );

    match ctx.process_incoming(&frag3)? {
        Some(complete_data) => {
            println!("  Complete! Reassembled {} bytes", complete_data.len());
            assert_eq!(complete_data.len(), 1500);
        }
        None => println!("  Still waiting..."),
    }

    Ok(())
}
```

### Key Derivation

```rust
use radius_proto::eap::eap_tls::*;

fn demonstrate_key_derivation() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = EapTlsContext::new();

    // Simulate TLS handshake parameters (normally extracted from rustls)
    let master_secret = vec![0x42u8; 48];  // 48 bytes from TLS
    let client_random = [0xAAu8; 32];      // 32 bytes from ClientHello
    let server_random = [0xBBu8; 32];      // 32 bytes from ServerHello

    // Set parameters
    ctx.master_secret = Some(master_secret);
    ctx.client_random = Some(client_random);
    ctx.server_random = Some(server_random);

    println!("TLS Handshake Parameters:");
    println!("  Master Secret: 48 bytes");
    println!("  Client Random: 32 bytes");
    println!("  Server Random: 32 bytes");

    // Derive MSK and EMSK
    ctx.derive_session_keys()?;

    println!("\nDerived Session Keys:");

    if let Some(msk) = ctx.get_msk() {
        println!("  MSK: {} bytes", msk.len());
        println!("    First 16 bytes: {:02x?}", &msk[0..16]);

        // MSK is used to derive RADIUS MS-MPPE keys (RFC 2548 §2.4)
        // MS-MPPE-Recv-Key = first 32 bytes of MSK
        // MS-MPPE-Send-Key = second 32 bytes of MSK
        println!("    MS-MPPE-Recv-Key: {:02x?}", &msk[0..32]);
        println!("    MS-MPPE-Send-Key: {:02x?}", &msk[32..64]);
    }

    if let Some(emsk) = ctx.get_emsk() {
        println!("  EMSK: {} bytes (reserved for future use)", emsk.len());
    }

    Ok(())
}
```

### Mutual TLS (Client Certificate)

```rust
use radius_proto::eap::eap_tls::*;

fn setup_mutual_tls() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration requiring client certificates
    let config = TlsCertificateConfig::new(
        "certs/server.pem".to_string(),
        "certs/server-key.pem".to_string(),
        Some("certs/ca.pem".to_string()),  // CA for client cert verification
        true,                              // require_client_cert
    );

    println!("Mutual TLS Configuration:");
    println!("  Server Cert: {}", config.server_cert_path);
    println!("  Server Key: {}", config.server_key_path);
    println!("  CA Cert: {:?}", config.ca_cert_path);
    println!("  Require Client Cert: {}", config.require_client_cert);

    // Load CA certificate for client verification
    if let Some(ca_path) = &config.ca_cert_path {
        let ca_certs = load_certificates_from_pem(ca_path)?;
        println!("\nLoaded {} CA certificate(s)", ca_certs.len());

        // In actual implementation, these would be used to configure rustls
        // to verify client certificates during the TLS handshake
    }

    Ok(())
}
```

## Complete Workflow Example with rustls Integration

```rust
use radius_proto::eap::eap_tls::*;
use radius_proto::eap::{EapSession, EapState};
use std::sync::Arc;

fn complete_eap_tls_workflow() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Complete EAP-TLS Workflow with rustls ===\n");

    // 1. Server Setup
    println!("1. Loading server certificates and building TLS config...");
    let cert_config = TlsCertificateConfig::simple(
        "certs/server.pem".to_string(),
        "certs/server-key.pem".to_string(),
    );

    // Build rustls ServerConfig
    let server_config = build_server_config(&cert_config)?;
    println!("   ✓ rustls ServerConfig created\n");

    // 2. EAP Identity Exchange
    println!("2. EAP Identity Exchange");
    let mut session = EapSession::new("testuser@test.local".to_string());
    session.transition(EapState::IdentityRequested)?;
    session.identity = Some("testuser@test.local".to_string());
    session.transition(EapState::IdentityReceived)?;
    println!("   ✓ Identity: {}\n", session.identity.as_ref().unwrap());

    // 3. Initialize EAP-TLS Server
    println!("3. Initializing EAP-TLS Server");
    session.eap_method = Some(radius_proto::eap::EapType::Tls);
    session.transition(EapState::MethodRequested)?;

    let mut tls_server = EapTlsServer::new(Arc::new(server_config));
    tls_server.initialize_connection()?;
    println!("   ✓ TLS connection initialized\n");

    // 4. Send EAP-TLS Start
    println!("4. Sending EAP-TLS Start packet");
    let start = EapTlsPacket::start();
    println!("   ✓ Sent EAP-Request/TLS (Start)\n");

    // 5. TLS Handshake (would process client messages in real scenario)
    println!("5. TLS Handshake Flow");
    println!("   → [Would receive] ClientHello from client");
    println!("   ← [Would send] ServerHello, Certificate, ServerHelloDone");
    println!("   → [Would receive] ClientKeyExchange, ChangeCipherSpec, Finished");
    println!("   ← [Would send] ChangeCipherSpec, Finished");
    println!("   Note: In production, use process_client_message() for each client packet\n");

    // 6. After handshake complete (simulated)
    println!("6. Authentication Success");
    if tls_server.is_handshake_complete() {
        // Extract MSK/EMSK
        tls_server.extract_keys()?;
        println!("   ✓ MSK derived (64 bytes)");
        println!("   ✓ EMSK derived (64 bytes)");

        // Get the MSK for RADIUS
        if let Some(msk) = tls_server.get_msk() {
            println!("   ✓ MSK available for MS-MPPE keys");
        }
    }

    session.transition(EapState::Success)?;
    println!("   ✓ EAP-Success sent");
    println!("   ✓ RADIUS Access-Accept with MS-MPPE keys\n");

    println!("=== Workflow Complete ===");

    Ok(())
}

fn main() {
    match complete_eap_tls_workflow() {
        Ok(_) => println!("\n✓ Example completed successfully!"),
        Err(e) => eprintln!("\n✗ Error: {}", e),
    }
}
```

## Mutual TLS Example with Client Certificate Verification

```rust
use radius_proto::eap::eap_tls::*;
use std::sync::Arc;

fn mutual_tls_authentication() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Mutual TLS Authentication Example ===\n");

    // 1. Configure mutual TLS (require client certificate)
    println!("1. Configuring mutual TLS...");
    let cert_config = TlsCertificateConfig::new(
        "certs/server.pem".to_string(),
        "certs/server-key.pem".to_string(),
        Some("certs/ca.pem".to_string()),  // CA for client verification
        true,  // Require client certificate
    );

    // Build server config with client cert verification
    let server_config = build_server_config(&cert_config)?;
    println!("   ✓ Server config with client cert verification\n");

    // 2. Initialize TLS server
    let mut tls_server = EapTlsServer::new(Arc::new(server_config));
    tls_server.initialize_connection()?;
    println!("2. TLS server initialized");
    println!("   ✓ Client certificate will be verified by CA\n");

    // 3. After TLS handshake completes (simulated)
    println!("3. Verifying client certificate...");

    // Check if client provided a certificate
    if let Some(peer_certs) = tls_server.get_peer_certificates() {
        println!("   ✓ Client presented {} certificate(s)", peer_certs.len());

        // Verify that certificate identity matches EAP identity
        let expected_identity = "testuser@test.local";
        match tls_server.verify_peer_identity(expected_identity) {
            Ok(true) => {
                println!("   ✓ Certificate identity matches: {}", expected_identity);
                println!("   ✓ Authentication SUCCESSFUL\n");
            }
            Ok(false) => {
                println!("   ✗ Certificate identity does NOT match");
                println!("   ✗ Authentication FAILED\n");
                return Err("Identity mismatch".into());
            }
            Err(e) => {
                println!("   ✗ Certificate verification error: {}", e);
                return Err(e.into());
            }
        }
    } else {
        println!("   ✗ No client certificate presented");
        println!("   ✗ Authentication FAILED\n");
        return Err("Missing client certificate".into());
    }

    println!("=== Mutual TLS Complete ===");
    Ok(())
}

fn main() {
    match mutual_tls_authentication() {
        Ok(_) => println!("\n✓ Mutual TLS example completed successfully!"),
        Err(e) => eprintln!("\n✗ Error: {}", e),
    }
}
```

## Testing the Implementation

### Unit Tests

Run the EAP-TLS test suite:

```bash
# Run all EAP-TLS tests
cargo test --package radius-proto --features tls eap_tls

# Run specific test
cargo test --package radius-proto --features tls test_fragment_tls_message_large

# Run with output
cargo test --package radius-proto --features tls eap_tls -- --nocapture
```

### Integration Testing

```bash
# Generate test certificates
chmod +x generate-test-certs.sh
./generate-test-certs.sh

# Run integration tests (when available)
cargo test --package radius-server --features tls integration_eap_tls
```

## Common Issues and Solutions

### Issue 1: Certificate Load Failure

```
Error: IoError("Failed to open certificate file '/path/to/cert.pem': No such file or directory")
```

**Solution**: Check file path and ensure certificates exist

```bash
# Verify file exists
ls -la certs/server.pem

# Check permissions
chmod 644 certs/server.pem
chmod 600 certs/server-key.pem
```

### Issue 2: Certificate Validation Error

```
Error: CertificateError("Certificate has expired (not after: ...)")
```

**Solution**: Regenerate certificates with longer validity

```bash
# Check certificate expiry
openssl x509 -in certs/server.pem -noout -dates

# Regenerate if needed
./generate-test-certs.sh
```

### Issue 3: Fragmentation Issues

If large TLS messages fail:

```rust
// Reduce fragment size
ctx.queue_tls_data(tls_data, 800); // Instead of 1020
```

## Next Steps

1. **Production Deployment**: See [deployment guide](../deployment/)
2. **RADIUS Configuration**: Configure server for EAP-TLS
3. **Client Setup**: Configure supplicants (wpa_supplicant, Windows, macOS)
4. **Monitoring**: Set up logging and metrics
5. **Security Hardening**: Follow [security best practices](../security/)

## References

- [EAP-TLS Protocol Documentation](../protocol/EAP-TLS.md)
- [RADIUS Server Configuration](../configuration/)
- [Security Guidelines](../security/)
- [RFC 5216 - EAP-TLS](https://tools.ietf.org/html/rfc5216)
