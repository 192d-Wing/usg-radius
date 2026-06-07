# USG RADIUS Crates

This directory contains the modular crates that make up the USG RADIUS project.

## Crate Structure

### [`radius-proto`](radius-proto/) - Protocol Implementation

The core RADIUS protocol implementation following RFC 2865, 2866, 2869, and 5997.

**Purpose**: Low-level RADIUS protocol handling
**Dependencies**: Minimal (md5, rand, thiserror)
**Can be used**: Standalone for building RADIUS clients or custom servers

**Features**:

- Packet encoding/decoding
- All standard RADIUS attributes (Types 1-80+)
- MD5-based cryptography
- Request/Response Authenticator calculation
- Zero-copy parsing where possible

**Example**:

```rust
use radius_proto::{Packet, Code, Attribute};

let packet = Packet::new(Code::AccessRequest, 1, [0u8; 16]);
let bytes = packet.encode()?;
```

---

### [`radius-server`](radius-server/) - Server Implementation

Production-ready RADIUS server built on `radius-proto`.

**Purpose**: Complete RADIUS server application
**Dependencies**: radius-proto, tokio, serde, log
**Provides**: Binary `usg-radius` and library for custom servers

**Features**:

- Async I/O with Tokio
- JSON configuration
- Pluggable authentication handlers
- User and client management
- Logging and monitoring

**Example**:

```rust
use radius_server::{RadiusServer, ServerConfig, SimpleAuthHandler};
use std::sync::Arc;

let mut handler = SimpleAuthHandler::new();
handler.add_user("alice", "password");

let config = ServerConfig::new(
    "0.0.0.0:1812".parse()?,
    b"secret",
    Arc::new(handler)
);

let server = RadiusServer::new(config).await?;
server.run().await?;
```

---

## Future Crates

### `radius-client` (Planned)

RADIUS client library for testing and integration.

### `radius-proxy` (Planned)

Standalone RADIUS proxy server.

### `radius-tools` (Planned)

CLI tools (radtest, radclient, raddebug).

### `radius-dict` (Planned)

Dictionary file parser for vendor-specific attributes.

---

## Development

Build all crates:

```bash
cargo build --workspace
```

Test all crates:

```bash
cargo test --workspace
```

Build specific crate:

```bash
cargo build -p radius-proto
cargo build -p radius-server
```

Run server:

```bash
cargo run -p radius-server
```

---

## Documentation

Generate documentation for all crates:

```bash
cargo doc --workspace --no-deps --open
```

---

## License

All crates are licensed under Apache-2.0.
