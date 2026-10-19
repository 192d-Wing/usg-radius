# EAP-TLS API Reference

Quick reference for the EAP-TLS implementation in `radius-proto`.

## Module: `radius_proto::eap::eap_tls`

All EAP-TLS functionality is available under the `tls` feature flag.

```rust
use radius_proto::eap::eap_tls::*;
```

---

## Core Structures

### `TlsFlags`

Represents EAP-TLS packet flags (L/M/S bits).

```rust
pub struct TlsFlags(u8);

impl TlsFlags {
    pub const LENGTH_INCLUDED: u8 = 0x80;
    pub const MORE_FRAGMENTS: u8 = 0x40;
    pub const START: u8 = 0x20;

    pub fn new(length_included: bool, more_fragments: bool, start: bool) -> Self;
    pub fn from_u8(value: u8) -> Self;
    pub fn as_u8(self) -> u8;
    pub fn length_included(self) -> bool;
    pub fn more_fragments(self) -> bool;
    pub fn start(self) -> bool;
}
```

**Example:**

```rust
let flags = TlsFlags::new(true, true, false); // L=1, M=1, S=0
assert!(flags.length_included());
assert!(flags.more_fragments());
```

---

### `EapTlsPacket`

Represents an EAP-TLS packet.

```rust
pub struct EapTlsPacket {
    pub flags: TlsFlags,
    pub tls_message_length: Option<u32>,
    pub tls_data: Vec<u8>,
}

impl EapTlsPacket {
    pub const MAX_RECORD_SIZE: usize = 16384;

    pub fn new(flags: TlsFlags, tls_message_length: Option<u32>, tls_data: Vec<u8>) -> Self;
    pub fn start() -> Self;
    pub fn from_eap_data(data: &[u8]) -> Result<Self, EapError>;
    pub fn to_eap_data(&self) -> Vec<u8>;
    pub fn to_eap_request(&self, identifier: u8) -> EapPacket;
    pub fn to_eap_response(&self, identifier: u8) -> EapPacket;
}
```

**Example:**

```rust
// Create start packet
let start = EapTlsPacket::start();
let eap_request = start.to_eap_request(1);

// Parse from EAP data
let packet = EapTlsPacket::from_eap_data(&eap_data)?;
```

---

### `TlsHandshakeState`

TLS handshake state enumeration.

```rust
pub enum TlsHandshakeState {
    Initial,
    Started,
    Handshaking,
    CertificateExchange,
    KeyExchange,
    Complete,
    Failed,
}
```

---

### `TlsFragmentAssembler`

Reassembles fragmented TLS messages.

```rust
pub struct TlsFragmentAssembler { /* ... */ }

impl TlsFragmentAssembler {
    pub fn new() -> Self;
    pub fn add_fragment(&mut self, packet: &EapTlsPacket) -> Result<Option<Vec<u8>>, EapError>;
    pub fn reset(&mut self);
}
```

**Example:**

```rust
let mut assembler = TlsFragmentAssembler::new();

// Add fragments
let result = assembler.add_fragment(&fragment1)?;
assert!(result.is_none()); // More fragments needed

let result = assembler.add_fragment(&fragment2)?;
if let Some(complete_data) = result {
    println!("Reassembled {} bytes", complete_data.len());
}
```

---

### `EapTlsContext`

Manages EAP-TLS session state.

```rust
pub struct EapTlsContext {
    pub handshake_state: TlsHandshakeState,
    pub assembler: TlsFragmentAssembler,
    pub outgoing_fragments: Vec<EapTlsPacket>,
    pub current_fragment_index: usize,
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
    pub master_secret: Option<Vec<u8>>,
    pub msk: Option<[u8; 64]>,
    pub emsk: Option<[u8; 64]>,
}

impl EapTlsContext {
    pub fn new() -> Self;
    pub fn reset(&mut self);

    // Fragment management
    pub fn has_pending_fragments(&self) -> bool;
    pub fn get_next_fragment(&mut self) -> Option<&EapTlsPacket>;
    pub fn queue_tls_data(&mut self, tls_data: Vec<u8>, max_fragment_size: usize);

    // Packet processing
    pub fn process_incoming(&mut self, packet: &EapTlsPacket) -> Result<Option<Vec<u8>>, EapError>;

    // Key derivation
    pub fn derive_session_keys(&mut self) -> Result<(), EapError>;
    pub fn get_msk(&self) -> Option<&[u8; 64]>;
    pub fn get_emsk(&self) -> Option<&[u8; 64]>;
}
```

**Example:**

```rust
let mut ctx = EapTlsContext::new();

// Queue large TLS data
ctx.queue_tls_data(server_hello_data, 1020);

// Send fragments
while ctx.has_pending_fragments() {
    if let Some(fragment) = ctx.get_next_fragment() {
        send_to_client(fragment);
    }
}

// Process incoming
if let Some(complete_msg) = ctx.process_incoming(&tls_packet)? {
    // Handle complete TLS message
}

// Derive keys after handshake
ctx.derive_session_keys()?;
let msk = ctx.get_msk().unwrap();
```

---

### `TlsCertificateConfig`

Certificate configuration for EAP-TLS server.

```rust
pub struct TlsCertificateConfig {
    pub server_cert_path: String,
    pub server_key_path: String,
    pub ca_cert_path: Option<String>,
    pub require_client_cert: bool,
}

impl TlsCertificateConfig {
    pub fn new(
        server_cert_path: String,
        server_key_path: String,
        ca_cert_path: Option<String>,
        require_client_cert: bool,
    ) -> Self;

    pub fn simple(server_cert_path: String, server_key_path: String) -> Self;
}
```

**Example:**

```rust
// Server-only authentication
let config = TlsCertificateConfig::simple(
    "/etc/radius/server.pem".to_string(),
    "/etc/radius/server-key.pem".to_string(),
);

// Mutual TLS
let config = TlsCertificateConfig::new(
    "/etc/radius/server.pem".to_string(),
    "/etc/radius/server-key.pem".to_string(),
    Some("/etc/radius/ca.pem".to_string()),
    true,
);
```

---

### `EapTlsServer`

Manages TLS handshake for a single EAP-TLS authentication session.

```rust
pub struct EapTlsServer {
    connection: Option<rustls::ServerConnection>,
    context: EapTlsContext,
    config: std::sync::Arc<rustls::ServerConfig>,
}

impl EapTlsServer {
    pub fn new(config: std::sync::Arc<rustls::ServerConfig>) -> Self;
    pub fn initialize_connection(&mut self) -> Result<(), EapError>;
    pub fn process_client_message(&mut self, eap_tls_packet: &EapTlsPacket)
        -> Result<Option<Vec<u8>>, EapError>;
    pub fn is_handshake_complete(&self) -> bool;
    pub fn extract_keys(&mut self) -> Result<(), EapError>;
    pub fn get_msk(&self) -> Option<&[u8; 64]>;
    pub fn get_emsk(&self) -> Option<&[u8; 64]>;
    pub fn get_peer_certificates(&self) -> Option<Vec<Vec<u8>>>;
    pub fn verify_peer_identity(&self, expected_identity: &str) -> Result<bool, EapError>;
    pub fn context(&self) -> &EapTlsContext;
    pub fn context_mut(&mut self) -> &mut EapTlsContext;
}
```

**Example:**

```rust
use std::sync::Arc;

// Build server configuration
let cert_config = TlsCertificateConfig::new(
    "server.pem".to_string(),
    "server-key.pem".to_string(),
    Some("ca.pem".to_string()),
    true,  // require client cert
);

let server_config = build_server_config(&cert_config)?;
let mut tls_server = EapTlsServer::new(Arc::new(server_config));

// Initialize connection after receiving EAP-Identity
tls_server.initialize_connection()?;

// Process client messages
if let Some(tls_response) = tls_server.process_client_message(&client_packet)? {
    // Send TLS response back to client
}

// After handshake complete
if tls_server.is_handshake_complete() {
    // Extract MSK/EMSK
    tls_server.extract_keys()?;

    // Verify client certificate identity
    if tls_server.verify_peer_identity("user@example.com")? {
        println!("Client certificate matches identity");
    }

    let msk = tls_server.get_msk().unwrap();
}
```

---

## Functions

### `build_server_config`

Builds rustls ServerConfig from certificate configuration.

```rust
pub fn build_server_config(
    cert_config: &TlsCertificateConfig
) -> Result<rustls::ServerConfig, EapError>
```

**Features:**

- Server-only authentication (no client cert required)
- Mutual TLS with client certificate verification
- CA certificate chain validation
- Automatic certificate validation

**Errors:**

- `CertificateError` - Invalid certificates, missing CA when client cert required
- `TlsError` - Failed to build TLS configuration
- `IoError` - Certificate files not found

**Example:**

```rust
// Server-only authentication
let config = TlsCertificateConfig::simple(
    "server.pem".to_string(),
    "server-key.pem".to_string(),
);
let server_config = build_server_config(&config)?;

// Mutual TLS
let mutual_config = TlsCertificateConfig::new(
    "server.pem".to_string(),
    "server-key.pem".to_string(),
    Some("ca.pem".to_string()),
    true,
);
let mutual_server_config = build_server_config(&mutual_config)?;
```

---

### `fragment_tls_message`

Fragments a large TLS message into EAP-TLS packets.

```rust
pub fn fragment_tls_message(
    tls_data: &[u8],
    max_fragment_size: usize
) -> Vec<EapTlsPacket>
```

**Example:**

```rust
let large_message = vec![0x42; 20000]; // 20KB
let fragments = fragment_tls_message(&large_message, 1020);
println!("Created {} fragments", fragments.len());
```

---

### `derive_keys`

Derives MSK and EMSK from TLS master secret (RFC 5216 Section 2.3).

```rust
pub fn derive_keys(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> ([u8; 64], [u8; 64])
```

**Returns:** `(MSK, EMSK)` - Each is 64 bytes

**Example:**

```rust
let master_secret = vec![0x42; 48];
let client_random = [0xAA; 32];
let server_random = [0xBB; 32];

let (msk, emsk) = derive_keys(&master_secret, &client_random, &server_random);
println!("MSK: {} bytes", msk.len());
println!("EMSK: {} bytes", emsk.len());
```

---

### `load_certificates_from_pem`

Loads X.509 certificates from PEM file.

```rust
pub fn load_certificates_from_pem(path: &str) -> Result<Vec<Vec<u8>>, EapError>
```

**Returns:** Vector of DER-encoded certificates

**Errors:**

- `IoError` - File not found or cannot be read
- `CertificateError` - Invalid PEM format or no certificates found

**Example:**

```rust
let certs = load_certificates_from_pem("/etc/radius/server.pem")?;
println!("Loaded {} certificate(s)", certs.len());
```

---

### `load_private_key_from_pem`

Loads private key from PEM file.

```rust
pub fn load_private_key_from_pem(path: &str) -> Result<Vec<u8>, EapError>
```

**Returns:** DER-encoded private key

**Supports:** RSA, ECDSA, Ed25519 keys in PKCS#8 or traditional format

**Errors:**

- `IoError` - File not found or cannot be read
- `CertificateError` - Invalid PEM format or no key found

**Example:**

```rust
let key = load_private_key_from_pem("/etc/radius/server-key.pem")?;
println!("Loaded private key ({} bytes)", key.len());
```

---

### `validate_cert_key_pair`

Validates certificate and key pair.

```rust
pub fn validate_cert_key_pair(cert_der: &[u8], key_der: &[u8]) -> Result<(), EapError>
```

**Checks:**

- Certificate is valid X.509 DER
- Certificate is not expired
- Certificate validity period is current

**Errors:**

- `CertificateError` - Invalid certificate, expired, or not yet valid

**Example:**

```rust
let certs = load_certificates_from_pem("server.pem")?;
let key = load_private_key_from_pem("server-key.pem")?;

validate_cert_key_pair(&certs[0], &key)?;
println!("Certificate and key are valid!");
```

---

## Error Types

### `EapError`

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EapError {
    PacketTooShort { expected: usize, actual: usize },
    InvalidCode(u8),
    InvalidLength(usize),
    UnknownType(u8),
    FragmentationNotSupported,
    SessionNotFound,
    InvalidState,
    AuthenticationFailed,
    InvalidChallengeLength(usize),
    InvalidResponseFormat,
    EncodingError(String),

    #[cfg(feature = "tls")]
    TlsError(String),

    #[cfg(feature = "tls")]
    CertificateError(String),

    #[cfg(feature = "tls")]
    IoError(String),
}
```

---

## Usage Patterns

### Pattern 1: Server Initialization

```rust
// Load certificates once at startup
let config = TlsCertificateConfig::simple(
    "certs/server.pem".to_string(),
    "certs/server-key.pem".to_string(),
);

let certs = load_certificates_from_pem(&config.server_cert_path)?;
let key = load_private_key_from_pem(&config.server_key_path)?;
validate_cert_key_pair(&certs[0], &key)?;
```

### Pattern 2: Starting EAP-TLS

```rust
// Create context for new session
let mut ctx = EapTlsContext::new();

// Send Start
let start = EapTlsPacket::start();
let eap_request = start.to_eap_request(identifier);

// Wrap in RADIUS Access-Challenge
add_eap_to_radius_packet(&mut radius_packet, &eap_request)?;
```

### Pattern 3: Processing Client Response

```rust
// Extract EAP from RADIUS
let eap_packet = eap_from_radius_packet(&radius_request)?.unwrap();

// Parse EAP-TLS data
let tls_packet = EapTlsPacket::from_eap_data(&eap_packet.data)?;

// Process and reassemble
if let Some(complete_tls_data) = ctx.process_incoming(&tls_packet)? {
    // Feed to TLS library (rustls)
    // Process TLS handshake message
}
```

### Pattern 4: Sending Large TLS Message

```rust
// Queue large TLS response
ctx.queue_tls_data(server_hello_plus_cert, 1020);

// Send first fragment in Access-Challenge
if let Some(fragment) = ctx.get_next_fragment() {
    let eap_req = fragment.to_eap_request(identifier);
    add_eap_to_radius_packet(&mut radius_packet, &eap_req)?;
}

// Client will ACK, then send next fragment in subsequent Access-Challenge
```

### Pattern 5: Completing Authentication

```rust
// After TLS Finished messages exchanged
ctx.master_secret = Some(extract_master_secret_from_tls());
ctx.client_random = Some(extract_client_random_from_tls());
ctx.server_random = Some(extract_server_random_from_tls());

// Derive keys
ctx.derive_session_keys()?;

// Get MSK for RADIUS MS-MPPE keys (RFC 2548 §2.4): Recv-Key = MSK[0..32],
// Send-Key = MSK[32..64]. Encryption needs the client's shared secret and the
// Request Authenticator of the Access-Request being answered.
if let Some(msk) = ctx.get_msk() {
    let keys = radius_proto::MppeKeys::from_msk(msk)?;
    for attr in keys.to_attributes(shared_secret, &request.authenticator)? {
        radius_packet.add_attribute(attr);
    }
}

// Send EAP-Success
let success = EapPacket::success(identifier);
add_eap_to_radius_packet(&mut radius_packet, &success)?;
```

---

## Feature Flags

All EAP-TLS functionality requires the `tls` feature:

```toml
[dependencies]
radius-proto = { version = "0.1", features = ["tls"] }
```

---

## See Also

- [EAP-TLS Protocol Documentation](../protocol/EAP-TLS.md)
- [EAP-TLS Examples](../examples/eap-tls-example.md)
- [RADIUS Integration](../protocol/)
- [EAP Core API](./EAP.md)
