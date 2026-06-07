# USG RADIUS Server

A high-performance RADIUS (Remote Authentication Dial-In User Service) server implementation in Rust, fully compliant with RFC 2865 and related standards.

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)

## Overview

USG RADIUS is a modern, secure, and efficient RADIUS server written in Rust. It provides authentication services for network access control, VPN connections, and other AAA (Authentication, Authorization, and Accounting) scenarios.

### Key Features

- **RFC Compliant**: Full implementation of RFC 2865, 2866, 2869, and 5997
- **High Performance**: Built on Tokio async runtime for concurrent request handling
- **Secure**: MD5-based password encryption and authenticator validation
- **Configurable**: JSON-based configuration with user and client management
- **Extensible**: Trait-based authentication handler for custom logic
- **Well Tested**: Comprehensive unit and integration tests

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/192d-Cyberspace-Control-Squadron/usg-radius.git
cd usg-radius

# Build the project
cargo build --release

# Run the server
cargo run --release
```

### Basic Configuration

On first run, the server will create an example `config.json` file:

```json
{
  "listen_address": "0.0.0.0",
  "listen_port": 1812,
  "secret": "testing123",
  "users": [
    {
      "username": "admin",
      "password": "admin123",
      "attributes": {}
    }
  ]
}
```

### Testing Authentication

Using the built-in test client:

```bash
cargo run --example simple_client admin admin123 testing123
```

Using `radtest` (from FreeRADIUS utils):

```bash
radtest admin admin123 localhost 1812 testing123
```

## Use Cases

- **VPN Authentication**: Authenticate VPN users against a centralized server
- **Network Access Control**: Control access to network resources
- **WiFi Authentication**: 802.1X authentication for wireless networks
- **Remote Access**: Dial-in and remote access authentication
- **Testing**: Development and testing of RADIUS clients

## Architecture

USG RADIUS follows a modular architecture:

```
┌─────────────────────────────────────────┐
│          RADIUS Client                  │
│    (VPN, NAS, WiFi Controller)          │
└────────────────┬────────────────────────┘
                 │ UDP Port 1812
                 ▼
┌─────────────────────────────────────────┐
│         USG RADIUS Server               │
├─────────────────────────────────────────┤
│  ┌────────────┐  ┌──────────────┐      │
│  │   Packet   │  │  Attributes  │      │
│  │   Handler  │  │   Parser     │      │
│  └────────────┘  └──────────────┘      │
│  ┌────────────┐  ┌──────────────┐      │
│  │    Auth    │  │    Config    │      │
│  │   Module   │  │   Manager    │      │
│  └────────────┘  └──────────────┘      │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│      Authentication Backend             │
│  (In-Memory, Database, LDAP, etc.)      │
└─────────────────────────────────────────┘
```

## Documentation Sections

<div class="grid cards" markdown>

- :material-rocket-launch:{ .lg .middle } **Getting Started**

    ---

    Installation, configuration, and first steps

    [:octicons-arrow-right-24: Get Started](getting-started/installation.md)

- :material-file-document:{ .lg .middle } **Protocol Reference**

    ---

    RADIUS protocol details and RFC compliance

    [:octicons-arrow-right-24: Protocol](protocol/overview.md)

- :material-code-braces:{ .lg .middle } **API Reference**

    ---

    Library usage and custom authentication handlers

    [:octicons-arrow-right-24: API](api/overview.md)

- :material-cog:{ .lg .middle } **Configuration**

    ---

    Server configuration and client setup

    [:octicons-arrow-right-24: Configure](configuration/server.md)

- :material-database:{ .lg .middle } **Authentication Backends**

    ---

    LDAP/AD, PostgreSQL, and file-based authentication

    [:octicons-arrow-right-24: Backends](backends/BACKEND_INTEGRATIONS.md)

- :material-shield-lock:{ .lg .middle } **Security**

    ---

    Security considerations and best practices

    [:octicons-arrow-right-24: Security](security/overview.md)

- :material-information:{ .lg .middle } **Examples**

    ---

    Real-world examples and tutorials

    [:octicons-arrow-right-24: Examples](examples/basic-auth.md)

</div>

## Project Status

USG RADIUS is production-ready for basic RADIUS authentication scenarios. The core protocol implementation is stable and well-tested.

### Implemented Features

- ✅ Access-Request / Accept / Reject
- ✅ User-Password encryption/decryption
- ✅ Request/Response Authenticator validation
- ✅ Status-Server support (RFC 5997)
- ✅ JSON configuration
- ✅ Extensible authentication handlers

### Roadmap

- 🔄 Full RADIUS Accounting (RFC 2866)
- 🔄 EAP authentication methods
- 🔄 Database backend integration
- 🔄 RADIUS proxy support
- 🔄 Rate limiting and DoS protection
- 🔄 TLS/DTLS support (RadSec)

## Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/blob/main/CONTRIBUTING.md) for details.

## License

This project is licensed under the Apache License 2.0 (Apache-2.0).

## Contact

**Author**: John Edward Willman V
**Email**: john.willman.1@us.af.mil
**Repository**: [github.com/192d-Cyberspace-Control-Squadron/usg-radius](https://github.com/192d-Cyberspace-Control-Squadron/usg-radius)
