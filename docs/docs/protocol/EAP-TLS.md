# EAP-TLS (Type 13) - RFC 5216

EAP-TLS is one of the most secure EAP methods, providing certificate-based mutual authentication using TLS. It is widely used in enterprise wireless networks (802.1X/WPA-Enterprise) and provides strong cryptographic protection.

## Overview

EAP-TLS implements the Transport Layer Security (TLS) protocol within EAP to provide:

- **Mutual Authentication**: Both client and server authenticate using X.509 certificates
- **Strong Cryptography**: TLS 1.2/1.3 with modern cipher suites
- **Key Derivation**: Generates Master Session Key (MSK) and Extended MSK (EMSK) for wireless encryption
- **Perfect Forward Secrecy**: When using ephemeral key exchange (DHE/ECDHE)
- **Resistance to Attacks**: Protection against man-in-the-middle, replay, and dictionary attacks

## Implementation Status

### ✅ Completed Features

- **EAP-TLS Packet Structure**: Complete packet parsing and encoding with flags (L/M/S)
- **Fragmentation**: Automatic fragmentation and reassembly for large TLS records (>16KB)
- **MSK/EMSK Derivation**: RFC 5216 compliant key derivation using TLS PRF
- **Session Management**: `EapTlsContext` for managing handshake state and buffers
- **Certificate Loading**: Support for PEM-encoded certificates and private keys
- **Certificate Validation**: X.509 parsing and validity period checking
- **Test Coverage**: 30+ comprehensive unit tests

### 🔄 In Progress

- **TLS Handshake**: Integration with rustls for actual TLS 1.2/1.3 handshakes
- **Server Integration**: RADIUS server authentication handler
- **Client Certificates**: Full mutual TLS support

## Usage

### Basic Example

```rust
use radius_proto::eap::eap_tls::*;

// Load server certificate and key
let cert_config = TlsCertificateConfig::simple(
    "/path/to/server.pem".to_string(),
    "/path/to/server-key.pem".to_string(),
);

// Load certificates
let certs = load_certificates_from_pem(&cert_config.server_cert_path)?;
let key = load_private_key_from_pem(&cert_config.server_key_path)?;

// Validate the certificate
validate_cert_key_pair(&certs[0], &key)?;

// Create EAP-TLS context for a session
let mut ctx = EapTlsContext::new();

// Process EAP-TLS Start packet (from authenticator)
let start_packet = EapTlsPacket::start();
let eap_request = start_packet.to_eap_request(1);

// Client would respond with TLS ClientHello...
// (Full TLS handshake integration coming soon)
```

### Certificate Configuration

#### Server-Only Authentication (No Client Certificate)

```rust
let config = TlsCertificateConfig::simple(
    "/etc/radius/certs/server.pem".to_string(),
    "/etc/radius/certs/server-key.pem".to_string(),
);
```

#### Mutual TLS (Client Certificate Required)

```rust
let config = TlsCertificateConfig::new(
    "/etc/radius/certs/server.pem".to_string(),
    "/etc/radius/certs/server-key.pem".to_string(),
    Some("/etc/radius/certs/ca.pem".to_string()),
    true, // require_client_cert
);
```

### Handling Fragmentation

EAP-TLS automatically handles fragmentation of large TLS records:

```rust
let mut ctx = EapTlsContext::new();

// Queue large TLS data for transmission (e.g., ServerHello + Certificate)
let tls_handshake_data = vec![/* ... large TLS records ... */];
ctx.queue_tls_data(tls_handshake_data, 1020); // Max 1020 bytes per fragment

// Send fragments one at a time
while ctx.has_pending_fragments() {
    if let Some(fragment) = ctx.get_next_fragment() {
        let eap_packet = fragment.to_eap_request(identifier);
        // Send eap_packet in RADIUS Access-Challenge
    }
}
```

### Receiving Fragmented Messages

```rust
let mut ctx = EapTlsContext::new();

// Process incoming EAP-TLS packet
let tls_packet = EapTlsPacket::from_eap_data(&eap_data)?;

// Process and reassemble
if let Some(complete_data) = ctx.process_incoming(&tls_packet)? {
    // All fragments received, complete_data contains the full TLS message
    println!("Received complete TLS message: {} bytes", complete_data.len());

    // Process TLS handshake message
    // (Integration with rustls coming soon)
}
```

### Key Derivation

After successful TLS handshake, derive MSK and EMSK:

```rust
// Set handshake parameters (extracted from TLS connection)
ctx.master_secret = Some(master_secret_from_tls);
ctx.client_random = Some(client_random_from_tls);
ctx.server_random = Some(server_random_from_tls);

// Derive session keys
ctx.derive_session_keys()?;

// Get keys for RADIUS attributes (MS-MPPE keys)
if let Some(msk) = ctx.get_msk() {
    println!("MSK: {} bytes", msk.len()); // 64 bytes
    // radius_proto::MppeKeys::from_msk(msk) splits it into MS-MPPE-Recv-Key
    // (MSK[0..32]) and MS-MPPE-Send-Key (MSK[32..64]); `to_attributes` encrypts
    // them per RFC 2548 §2.4 for the Access-Accept. The server does this
    // automatically when an EAP handler returns `AuthResult::Accept { msk }`.
}

if let Some(emsk) = ctx.get_emsk() {
    println!("EMSK: {} bytes", emsk.len()); // 64 bytes
    // EMSK is reserved for future use
}
```

## Certificate Generation

### Generate Self-Signed Server Certificate (Testing)

```bash
# Generate private key
openssl genrsa -out server-key.pem 2048

# Generate self-signed certificate
openssl req -new -x509 -key server-key.pem -out server.pem -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=radius.example.com"
```

### Generate CA and Server Certificate (Production)

```bash
# 1. Generate CA private key
openssl genrsa -out ca-key.pem 4096

# 2. Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca.pem -days 3650 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=CA"

# 3. Generate server private key
openssl genrsa -out server-key.pem 2048

# 4. Generate server certificate signing request (CSR)
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=radius.example.com"

# 5. Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 365

# 6. Verify certificate
openssl verify -CAfile ca.pem server.pem
```

### Generate Client Certificate (Mutual TLS)

```bash
# 1. Generate client private key
openssl genrsa -out client-key.pem 2048

# 2. Generate client CSR
openssl req -new -key client-key.pem -out client.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=user@example.com"

# 3. Sign client certificate with CA
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out client.pem -days 365

# 4. Create PKCS#12 bundle for distribution to client
openssl pkcs12 -export -out client.p12 -inkey client-key.pem \
    -in client.pem -certfile ca.pem
```

## Protocol Flow

### EAP-TLS Authentication Sequence

```
Client (Supplicant)          Authenticator          RADIUS Server
      |                            |                        |
      |---- EAPOL-Start ---------->|                        |
      |                            |                        |
      |<--- EAP-Request/Identity --|                        |
      |                            |                        |
      |---- EAP-Response/Identity ->                        |
      |                            |--Access-Request------->|
      |                            |  (EAP-Response/Identity)|
      |                            |                        |
      |                            |<--Access-Challenge-----|
      |                            |  (EAP-Request/TLS-Start)|
      |<--- EAP-Request/TLS-Start -|                        |
      |     (S flag set)           |                        |
      |                            |                        |
      |---- EAP-Response/TLS ----->|                        |
      |     (ClientHello)          |--Access-Request------->|
      |                            |  (EAP-Response/TLS)    |
      |                            |                        |
      |                            |<--Access-Challenge-----|
      |                            |  (EAP-Request/TLS)     |
      |<--- EAP-Request/TLS -------|  (ServerHello,         |
      |     (L flag, fragmented)   |   Certificate,         |
      |                            |   ServerKeyExchange,   |
      |                            |   CertificateRequest,  |
      |                            |   ServerHelloDone)     |
      |                            |                        |
      |---- EAP-Response/TLS ----->|                        |
      |     (ACK - empty)          |--Access-Request------->|
      |                            |  (EAP-Response/TLS)    |
      |                            |                        |
      |     ... (more fragments as needed) ...              |
      |                            |                        |
      |---- EAP-Response/TLS ----->|                        |
      |     (Certificate,          |--Access-Request------->|
      |      ClientKeyExchange,    |  (EAP-Response/TLS)    |
      |      CertificateVerify,    |                        |
      |      ChangeCipherSpec,     |                        |
      |      Finished)             |                        |
      |                            |                        |
      |                            |<--Access-Challenge-----|
      |                            |  (EAP-Request/TLS)     |
      |<--- EAP-Request/TLS -------|  (ChangeCipherSpec,    |
      |     (L flag, fragmented)   |   Finished)            |
      |                            |                        |
      |---- EAP-Response/TLS ----->|                        |
      |     (ACK - empty)          |--Access-Request------->|
      |                            |  (EAP-Response/TLS)    |
      |                            |                        |
      |                            |<--Access-Accept--------|
      |                            |  (EAP-Success,         |
      |<--- EAP-Success -----------|   MS-MPPE-Keys)        |
      |                            |                        |
```

## EAP-TLS Flags

The first byte of EAP-TLS Type-Data contains flags:

```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|L M S R R R R R|
+-+-+-+-+-+-+-+-+
```

- **L (Length included)** - Bit 7 (0x80): TLS Message Length field is present
- **M (More fragments)** - Bit 6 (0x40): More fragments to follow
- **S (Start)** - Bit 5 (0x20): TLS handshake start
- **R (Reserved)** - Bits 0-4: Must be zero

### Flag Combinations

| Flags | Meaning                                    |
|-------|--------------------------------------------|
| `0x00` | Unfragmented final packet                 |
| `0x20` | TLS Start (initiates handshake)            |
| `0x40` | Fragmented, more to come (not first)       |
| `0x80` | Unfragmented with length (large message)   |
| `0xC0` | First fragment of fragmented message       |

## Security Considerations

### Certificate Validation

Always validate certificates properly:

1. **Check validity period** - Ensure certificate is not expired
2. **Verify chain of trust** - Validate up to trusted root CA
3. **Check revocation** - Use CRL or OCSP when possible
4. **Verify hostname** - Match CN/SAN to expected server name
5. **Check key usage** - Ensure certificate allows TLS server authentication

### Private Key Protection

- Store private keys with restricted permissions (chmod 600)
- Never commit private keys to version control
- Consider using Hardware Security Modules (HSM) for production
- Rotate certificates regularly (before expiration)

### Cipher Suite Selection

Prefer modern cipher suites with:

- Forward secrecy (ECDHE/DHE)
- AEAD encryption (GCM/ChaCha20-Poly1305)
- Strong key sizes (2048-bit RSA minimum, prefer 256-bit ECDSA)

Avoid:

- Export ciphers
- NULL encryption
- MD5 and SHA1 (prefer SHA256+)
- SSLv3, TLS 1.0, TLS 1.1

## Troubleshooting

### Common Issues

**1. Certificate Load Failure**

```
Error: IoError("Failed to open certificate file '/path/to/cert.pem': ...")
```

Solution: Check file path and permissions

**2. Certificate Parse Error**

```
Error: CertificateError("Failed to parse certificates: ...")
```

Solution: Ensure file is valid PEM format, verify with `openssl x509 -in cert.pem -text`

**3. Certificate Expired**

```
Error: CertificateError("Certificate has expired (not after: ...)")
```

Solution: Regenerate certificate or update system time

**4. Fragmentation Issues**

If large certificates fail to transmit:

- Reduce maximum fragment size (default 1020 bytes)
- Check MTU settings on network
- Verify authenticator supports fragmentation

## Performance

### Benchmarks

Typical performance metrics (on modern hardware):

- **Packet Parsing**: ~50ns per packet
- **Fragmentation**: ~2µs for 16KB message
- **Key Derivation**: ~100µs for MSK/EMSK

### Optimization Tips

1. **Reuse TLS sessions** - Reduce handshake overhead
2. **Pre-load certificates** - Load once at startup
3. **Tune fragment size** - Match network MTU
4. **Use ECDSA** - Faster than RSA for same security level

## References

- [RFC 5216](https://tools.ietf.org/html/rfc5216) - EAP-TLS Authentication Protocol
- [RFC 3748](https://tools.ietf.org/html/rfc3748) - Extensible Authentication Protocol (EAP)
- [RFC 3579](https://tools.ietf.org/html/rfc3579) - RADIUS Support For EAP
- [RFC 2865](https://tools.ietf.org/html/rfc2865) - RADIUS Protocol
- [RFC 2548](https://tools.ietf.org/html/rfc2548) - Microsoft Vendor-Specific RADIUS Attributes (MS-MPPE)

## Next Steps

- [Configuration Examples](../configuration/) - Server configuration for EAP-TLS
- [RADIUS Integration](../backends/) - Backend authentication setup
- [Security Best Practices](../security/) - Hardening your deployment
- [Troubleshooting Guide](../deployment/) - Common issues and solutions
