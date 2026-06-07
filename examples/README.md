# USG RADIUS Examples

This directory contains example configuration files and Rust library examples.

> **Deployment:** USG RADIUS is deployed on Kubernetes (k3s or k8s) with the Cilium CNI.
> See the canonical guide [`deploy/README.md`](../deploy/README.md) for the full flow
> (install Cilium with the provided values, build/push the `usg-radius-server` image, edit
> an overlay, `kubectl apply -k deploy/overlays/<env>`, and verify with `cilium bgp routes`).

## Directory Structure

```
examples/
├── configs/                 # Example configuration files (JSON)
│   ├── basic-homelab.json   # Minimal config for testing
│   ├── small-business.json  # SMB production config
│   ├── enterprise.json      # Enterprise/high-scale config
│   └── docker.json          # Container/Kubernetes config (env-var driven)
├── proxy_config.json        # RADIUS proxy configuration example
├── postgres_schema.sql      # PostgreSQL schema (auth + accounting)
├── postgres-schema.sql      # PostgreSQL schema (alternate)
├── eap_server.rs            # EAP-TLS server example (with OCSP/CRL)
├── eap_teap_server.rs       # EAP-TEAP tunneled-auth server example
├── ocsp_check.rs            # Standalone OCSP certificate checker
├── perf_bench.rs            # Performance benchmark tool
└── proxy_server.rs          # RADIUS proxy server example
```

## Configuration Examples

### Basic Home Lab (`configs/basic-homelab.json`)

**Use case:** Home lab testing, development, learning

**Features:**

- Localhost-only binding
- Debug logging
- Minimal rate limits
- No audit logging
- Weak secrets (NOT for production)

**Start (local dev):**

```bash
cargo run --release -- examples/configs/basic-homelab.json
```

### Small Business (`configs/small-business.json`)

**Use case:** Small business (10-100 users)

**Features:**

- Dual-stack IPv4/IPv6
- Environment variable secrets
- Audit logging enabled
- Moderate rate limits
- Multiple client networks (wireless, VPN, switches)

**Setup:**

```bash
# Set environment variables
export RADIUS_DEFAULT_SECRET=$(openssl rand -base64 32)
export RADIUS_WIRELESS_SECRET=$(openssl rand -base64 32)
export RADIUS_VPN_SECRET=$(openssl rand -base64 32)
export RADIUS_SWITCH_SECRET=$(openssl rand -base64 32)
export RADIUS_ADMIN_PASSWORD=$(openssl rand -base64 32)

# Start server (local dev)
cargo run --release -- examples/configs/small-business.json
```

### Enterprise (`configs/enterprise.json`)

**Use case:** Enterprise deployment (1000+ users)

**Features:**

- High-performance settings
- Large request cache
- High rate limits
- IPv6 support
- No users array (expects external auth backend)
- Multiple security zones

**Recommendations:**

- Deploy on Kubernetes with multiple replicas (see [`deploy/README.md`](../deploy/README.md))
- Use external authentication (LDAP/AD or PostgreSQL)
- Configure monitoring and alerting (Prometheus `/metrics`)
- Implement log aggregation
- Regular secret rotation

### Container / Kubernetes (`configs/docker.json`)

**Use case:** Container deployments (mounted from a Kubernetes Secret)

**Features:**

- All secrets via environment variables
- Designed for immutable infrastructure
- Works with Kubernetes Secrets

**Usage:** Mount as the RADIUS config Secret in your overlay. See
[`deploy/README.md`](../deploy/README.md).

## Database Schemas

PostgreSQL schemas for the auth and accounting backends are provided:

- [`postgres_schema.sql`](postgres_schema.sql) — performance-indexed schema for users,
  attributes, and accounting tables.
- [`postgres-schema.sql`](postgres-schema.sql) — alternate schema.

Load with:

```bash
psql -U radius -d radiusdb < examples/postgres_schema.sql
```

## Proxy Configuration

[`proxy_config.json`](proxy_config.json) is a complete RADIUS proxy configuration (home
servers, pools, realms, health checks). See the [proxy documentation](../docs/docs/proxy/README.md)
and the [`proxy_server.rs`](proxy_server.rs) example.

## Security Best Practices

### Secrets

```bash
# Generate strong secrets (Linux/macOS)
openssl rand -base64 32
```

**Requirements:**

- Minimum 16 characters
- Include uppercase, lowercase, numbers, symbols
- Unique secret per client
- Never commit to version control
- Rotate regularly (quarterly recommended)
- Store secrets in Kubernetes Secrets (or an external secret manager)

### Network

Restrict access to the RADIUS VIP at the upstream router/firewall so only legitimate NAS
devices can reach UDP 1812 (auth) and 1813 (accounting). Keep the health (TCP 2812) and
metrics (TCP 3812) endpoints internal.

## Code Examples

### EAP-TLS Server (`eap_server.rs`)

Example RADIUS server with EAP-TLS authentication and optional OCSP/CRL revocation checking.

**Run:**

```bash
cargo run --example eap_server --features tls
```

**Features:**

- EAP-TLS with mutual TLS authentication
- Optional OCSP/CRL certificate revocation checking
- Fallback to PAP/CHAP authentication
- Configurable TLS certificates

See [eap_server.rs](eap_server.rs) for complete documentation including certificate generation.

### OCSP Certificate Checker (`ocsp_check.rs`)

Standalone tool for checking certificate revocation status using OCSP.

**Run:**

```bash
cargo run --example ocsp_check -- client.pem ca.pem
```

**Features:**

- Builds OCSP requests with nonce for replay protection
- Queries OCSP responders via HTTP POST
- Parses and validates OCSP responses
- Shows certificate status (Good/Revoked/Unknown)
- Displays response freshness and expiration

**Example output:**

```
OCSP Certificate Status Checker
================================

Loading certificate: client.pem
Loading issuer: ca.pem

Extracting OCSP URL from certificate...
OCSP Responder URL: http://ocsp.example.com

Building OCSP request...
OCSP request size: 124 bytes
Nonce included: yes (replay protection enabled)

Querying OCSP responder...

OCSP Response
=============
Status: Successful
Certificate Status: Good ✅
Produced At: 2025-12-31 12:00:00 UTC
This Update: 2025-12-31 12:00:00 UTC
Next Update: 2025-12-31 18:00:00 UTC
Response fresh for: 21456 seconds
Nonce: present ✅ (verified - replay protection active)
Response Size: 856 bytes

✅ Certificate is VALID (not revoked)
```

### EAP-TEAP Server (`eap_teap_server.rs`)

Example RADIUS server with EAP-TEAP tunneled authentication.

**Run:**

```bash
cargo run --example eap_teap_server --features tls
```

### Performance Benchmark (`perf_bench.rs`)

Benchmark tool for measuring RADIUS server performance.

**Run:**

```bash
cargo run --example perf_bench --release
```

### RADIUS Proxy Server (`proxy_server.rs`)

Example RADIUS proxy that forwards requests to home servers using realm-based routing.

**Run:**

```bash
cargo run --example proxy_server -- examples/proxy_config.json
```

## Testing

### Using radtest

Install FreeRADIUS utils:

```bash
# Debian/Ubuntu
sudo apt install freeradius-utils

# RHEL/CentOS
sudo yum install freeradius-utils
```

Test authentication:

```bash
radtest username password server_ip 1812 shared_secret
```

Example:

```bash
radtest admin admin123 localhost 1812 testing123
```

Expected output (success):

```
Sent Access-Request Id 123 from 0.0.0.0:12345 to 127.0.0.1:1812 length 77
Received Access-Accept Id 123 from 127.0.0.1:1812 to 127.0.0.1:12345 length 20
```

## Troubleshooting

### Configuration Validation

Validate config before starting:

```bash
usg-radius --validate config.json
```

### Common Issues

**Environment variable not found:**

```bash
# Make sure to export variables
export RADIUS_SECRET="your_secret"
```

**Firewall blocking:**

```bash
# Test network connectivity
sudo tcpdump -i any -n port 1812
```

## More Information

- [Deployment Guide](../deploy/README.md)
- [Server Configuration Docs](../docs/docs/configuration/server.md)
- [Security Best Practices](../docs/docs/security/overview.md)
- [Project README](../README.md)

## Contributing

Found an issue or have a suggestion for improving these examples?

Open an issue: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
