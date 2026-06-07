# USG RADIUS Server

A RADIUS (Remote Authentication Dial-In User Service) server implementation in Rust, compliant with RFC 2865 and related standards.

## Features

### Core Protocol

- **RFC 2865 Compliant**: Full implementation of the RADIUS authentication protocol
- **RFC 2866 Accounting**: Complete accounting protocol support with session tracking
- **Authentication**: Support for Access-Request, Access-Accept, Access-Reject, and Access-Challenge
- **Accounting**: Accounting-Request and Accounting-Response with full session lifecycle
- **EAP Support**: EAP-Message attribute (Type 79) for 802.1X authentication (v0.5.0 in progress)
- **Status Server**: RFC 5997 Status-Server support for monitoring
- **Password Encryption**: MD5-based User-Password encryption per RFC 2865 Section 5.2
- **Packet Authentication**: Request/Response Authenticator validation
- **Strict Validation**: RFC 2865 attribute validation with strict/lenient modes

### Accounting Features (v0.4.0)

- **Session Lifecycle Management**: Start, interim-update, and stop session tracking
- **PostgreSQL Backend**: Production-ready async backend with connection pooling
- **Comprehensive Attributes**: All RFC 2866 accounting attributes including gigaword counters
- **Data Export**: CSV and JSON export functionality with automatic unit conversion
  - User usage aggregation (bandwidth and session statistics)
  - Detailed session export (active and completed)
  - JSON reports with summary statistics and top users
- **Query Operations**: Session lookup, user history, active sessions, statistics
- **Trait-based Design**: Extensible AccountingHandler trait for custom backends

### Security Features

- **Client Authorization**: IP/CIDR-based client validation
- **Request Deduplication**: Replay attack prevention with caching
- **Rate Limiting**: Per-client and global rate limiting with token bucket algorithm
- **Message-Authenticator**: HMAC-MD5 integrity protection (RFC 2869)
- **Audit Logging**: JSON audit trail for compliance and forensics
- **Structured Logging**: Configurable log levels with tracing framework

### Configuration & Operations

- **JSON Configuration**: Schema-validated configuration with comprehensive options
- **Dual-Stack Networking**: Full IPv4 and IPv6 support for all network operations
- **Async/Await**: Built on Tokio for high-performance asynchronous I/O
- **Extensible**: Trait-based handlers for custom authentication and accounting logic
- **Production Ready**: DoS protection, security hardening, monitoring capabilities

## Supported RFCs

- **RFC 2865**: Remote Authentication Dial In User Service (RADIUS) - Full compliance
- **RFC 2866**: RADIUS Accounting - Full implementation with PostgreSQL backend
- **RFC 2869**: RADIUS Extensions - Message-Authenticator, Gigaword counters
- **RFC 3579**: RADIUS Support for EAP - EAP-Message attribute (v0.5.0 in progress)
- **RFC 3748**: Extensible Authentication Protocol (EAP) - Core framework (v0.5.0 in progress)
- **RFC 5997**: RADIUS Status-Server packets

## Installation

### From Source

```bash
git clone https://github.com/yourusername/usg-radius.git
cd usg-radius
cargo build --release
```

## Quick Start

1. Run the server (it will create an example config file on first run):

```bash
cargo run
```

2. Edit the generated `config.json` file:

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "testing123",
  "clients": [
    {
      "address": "192.168.1.0/24",
      "secret": "client_secret_1",
      "name": "Internal Network"
    }
  ],
  "users": [
    {
      "username": "admin",
      "password": "admin123",
      "attributes": {}
    }
  ],
  "verbose": false
}
```

3. Restart the server:

```bash
cargo run
```

> The steps above are for **local development**. For running in production, see
> **Deployment** below.

## Deployment (Kubernetes + Cilium)

The only supported deployment target is **Kubernetes (k3s or k8s) with the Cilium
CNI**. The server runs as a stateless `Deployment`; scaling and availability come
from the ReplicaSet, and the RADIUS VIP is exposed as a **dual-stack (IPv4 + IPv6)
L3 anycast VIP** advertised by Cilium's BGP control plane — preserving the NAS
source IP via `externalTrafficPolicy: Local` and Cilium DSR (no SNAT).

Manifests live under [`deploy/`](deploy/) (Kustomize base + `overlays/k3s` and
`overlays/k8s`). Build the multi-arch image (Iron Bank Alpine base) and apply an
overlay:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t <registry>/usg-radius-server:<tag> --push .

kubectl apply -k deploy/overlays/k8s     # or deploy/overlays/k3s
```

See **[deploy/README.md](deploy/README.md)** for the full guide (Cilium install
values, BGP peering, dual-stack VIPs, and verification).

> Docker Compose, systemd, HAProxy, and the Redis/Valkey HA backend have been
> removed in favor of this Kubernetes-native, stateless model.

## Configuration

The server uses a JSON configuration file with full JSON Schema validation available.

### Configuration Schema

A complete JSON Schema is provided in [`config.schema.json`](config.schema.json) for IDE integration and validation.

**VSCode Integration:**

```json
{
  "$schema": "./config.schema.json"
}
```

### Key Configuration Options

**Server Settings:**

- `listen_address`: IP address to bind to (default: "0.0.0.0")
- `listen_port`: Port to listen on (default: 1812)
- `secret`: Default shared secret for clients

**Security & Logging:**

- `log_level`: Structured logging level ("trace", "debug", "info", "warn", "error")
- `audit_log_path`: Path to JSON audit log (optional)
- `strict_rfc_compliance`: Enable strict RFC 2865 validation (default: true)

**Rate Limiting:**

- `rate_limit_per_client_rps`: Max requests/sec per client (default: 100)
- `rate_limit_per_client_burst`: Per-client burst capacity (default: 200)
- `rate_limit_global_rps`: Max requests/sec globally (default: 1000)
- `rate_limit_global_burst`: Global burst capacity (default: 2000)

**Request Deduplication:**

- `request_cache_ttl`: Cache TTL in seconds (default: 60)
- `request_cache_max_entries`: Max cached requests (default: 10000)

For complete documentation, see:

- [Server Configuration Guide](docs/docs/configuration/server.md)
- [Security Best Practices](docs/docs/security/overview.md)

## Testing with radtest

You can test the server using the `radtest` tool from FreeRADIUS:

```bash
# Install radtest (on Ubuntu/Debian)
sudo apt-get install freeradius-utils

# Test authentication
radtest admin admin123 localhost 1812 testing123
```

Expected output for successful authentication:

```
Sending Access-Request...
Received Access-Accept
```

## Architecture

### Core Components

- **Packet Module** ([src/packet/](src/packet/)): RADIUS packet encoding/decoding
  - `Code`: Packet type enumeration
  - `Packet`: Main packet structure with attributes

- **Attributes Module** ([src/attributes/](src/attributes/)): RADIUS attribute handling
  - `Attribute`: Generic attribute structure
  - `AttributeType`: Standard RADIUS attribute types

- **Auth Module** ([src/auth.rs](src/auth.rs)): Cryptographic operations
  - Request/Response Authenticator generation and verification
  - User-Password encryption/decryption

- **Server Module** ([src/server.rs](src/server.rs)): Server implementation
  - `RadiusServer`: Main server struct
  - `AuthHandler`: Trait for custom authentication logic
  - `SimpleAuthHandler`: Basic in-memory authentication

- **Config Module** ([src/config.rs](src/config.rs)): Configuration management
  - JSON-based configuration loading/saving
  - Validation

## Protocol Implementation Details

### Packet Structure

Per RFC 2865 Section 3:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Authenticator                         |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attributes ...
+-+-+-+-+-+-+-+-+-+-+-+-+-
```

### Supported Packet Types

**Authentication (RFC 2865):**

- **Access-Request (1)**: Client authentication request
- **Access-Accept (2)**: Authentication successful
- **Access-Reject (3)**: Authentication failed
- **Access-Challenge (11)**: Additional authentication required (multi-round auth, EAP)

**Accounting (RFC 2866):**

- **Accounting-Request (4)**: Session accounting data (start, interim, stop)
- **Accounting-Response (5)**: Accounting acknowledgment

**Monitoring (RFC 5997):**

- **Status-Server (12)**: Server health check
- **Status-Client (13)**: Client health check response

### Authentication Flow

1. Client sends Access-Request with:
   - User-Name attribute
   - User-Password attribute (encrypted)
   - Request Authenticator (random 16 bytes)

2. Server:
   - Decrypts User-Password
   - Validates credentials
   - Generates Response Authenticator

3. Server responds with:
   - Access-Accept or Access-Reject
   - Response Authenticator (MD5 hash)
   - Optional attributes

### Password Encryption

Per RFC 2865 Section 5.2, passwords are encrypted using:

```
Encrypted = P1 XOR MD5(Secret + RA)
           P2 XOR MD5(Secret + C(1))
           ...
```

Where:

- P1, P2, ... are 16-byte blocks of the password (padded)
- RA is the Request Authenticator
- C(1), C(2), ... are the previous ciphertext blocks

## Library Usage

You can use this as a library in your own Rust projects:

```toml
[dependencies]
usg_radius = "0.1.0"
```

Example custom authentication handler:

```rust
use usg_radius::{AuthHandler, Attribute, AttributeType};
use std::sync::Arc;

struct DatabaseAuthHandler {
    // Your database connection
}

impl AuthHandler for DatabaseAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // Check credentials against database
        // Return true if valid
        todo!()
    }

    fn get_accept_attributes(&self, username: &str) -> Vec<Attribute> {
        // Return user-specific attributes
        vec![
            Attribute::string(
                AttributeType::ReplyMessage as u8,
                format!("Welcome, {}!", username)
            ).unwrap()
        ]
    }
}
```

## Security Considerations

1. **Secrets**: Store shared secrets securely. Consider using environment variables or secret management systems.

2. **MD5**: RADIUS uses MD5 for authentication, which is considered weak by modern standards. Consider this when deploying in security-sensitive environments.

3. **Plaintext Passwords**: The example configuration stores passwords in plaintext. In production, integrate with a proper authentication backend.

4. **Network Security**: RADIUS does not encrypt the entire packet. Use VPNs or other network security measures for sensitive deployments.

5. **Port Security**: Standard RADIUS uses UDP port 1812. Ensure proper firewall rules.

## Development

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cargo doc --open
```

### Running with Debug Logging

```bash
RUST_LOG=debug cargo run
```

## License

This project is licensed under the Apache License 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## References

- [RFC 2865 - RADIUS](https://tools.ietf.org/html/rfc2865)
- [RFC 2866 - RADIUS Accounting](https://tools.ietf.org/html/rfc2866)
- [RFC 2869 - RADIUS Extensions](https://tools.ietf.org/html/rfc2869)
- [RFC 5997 - RADIUS Status-Server](https://tools.ietf.org/html/rfc5997)

## Author

John Edward Willman V <john.willman.1@us.af.mil>

