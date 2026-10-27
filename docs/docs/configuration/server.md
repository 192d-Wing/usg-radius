# Server Configuration

This guide covers the configuration of the USG RADIUS server.

## Configuration File

USG RADIUS uses JSON for configuration. The default configuration file is `config.json` in the working directory.

### Specify Custom Config File

```bash
cargo run -- /path/to/custom-config.json
# or
usg_radius /path/to/custom-config.json
```

## Configuration Structure

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "testing123",
  "clients": [],
  "users": [],
  "verbose": false,
  "log_level": "info",
  "audit_log_path": "/var/log/radius/audit.log",
  "strict_rfc_compliance": true,
  "request_cache_ttl": 60,
  "request_cache_max_entries": 10000,
  "rate_limit_per_client_rps": 100,
  "rate_limit_per_client_burst": 200,
  "rate_limit_global_rps": 1000,
  "rate_limit_global_burst": 2000
}
```

## Server Settings

### listen_address

The IP address the server binds to.

- **Type**: String (IP address)
- **Default**: `"::"`
- **Valid values**:
  - `"::"` - Dual-stack: Listen on all IPv6 and IPv4 interfaces (recommended)
  - `"0.0.0.0"` - IPv4-only: Listen on all IPv4 interfaces
  - `"127.0.0.1"` - IPv4 localhost only
  - `"::1"` - IPv6 localhost only
  - `"192.168.1.10"` - Specific IPv4 interface
  - `"fe80::1"` - Specific IPv6 interface

**Example:**

```json
{
  "listen_address": "::"
}
```

!!! tip
    Use `"::"` for dual-stack production deployments (accepts both IPv4 and IPv6).
    Use `"127.0.0.1"` or `"::1"` for localhost-only testing.

### listen_port

The UDP port the server listens on.

- **Type**: Integer
- **Default**: `1812`
- **Valid range**: 1-65535
- **Standard ports**:
  - 1812: RADIUS authentication (RFC 2865)
  - 1813: RADIUS accounting (RFC 2866)
  - 1645/1646: Legacy RADIUS ports

**Example:**

```json
{
  "listen_port": 1812
}
```

!!! warning
    Changing from standard port 1812 requires configuring all clients to use the custom port.

### secret

The default shared secret for client authentication.

- **Type**: String
- **Default**: `"testing123"`
- **Minimum length**: 1 character
- **Recommended length**: 16+ characters
- **Environment Variables**: Supported via `${VAR_NAME}` syntax

**Example:**

```json
{
  "secret": "MyVerySecureSecret2024!"
}
```

**Environment Variable Example:**

```json
{
  "secret": "${RADIUS_SECRET}"
}
```

```bash
# Set environment variable
export RADIUS_SECRET="MyVerySecureSecret2024!"
usg_radius
```

!!! danger "Security Critical"
    - Use a strong, random secret (16+ characters)
    - Include uppercase, lowercase, numbers, and symbols
    - Never use default secrets in production
    - Rotate secrets regularly
    - Use different secrets per client (see Clients configuration)
    - Store secrets in environment variables for containerized deployments

### verbose

Enable verbose logging.

- **Type**: Boolean
- **Default**: `false`

**Example:**

```json
{
  "verbose": true
}
```

When enabled, logs include:

- All packet details
- Attribute contents
- Authentication decisions
- Cryptographic operations

!!! warning
    Verbose mode may log sensitive information. Use only for debugging.

### log_level

Structured logging level (replaces verbose flag).

- **Type**: String
- **Default**: `"info"`
- **Valid values**: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`

**Example:**

```json
{
  "log_level": "debug"
}
```

**Environment Override:**

```bash
RUST_LOG=debug usg_radius
```

### audit_log_path

Path to JSON audit log file for compliance and forensics.

- **Type**: String (optional)
- **Default**: `null` (disabled)
- **Format**: JSON lines

**Example:**

```json
{
  "audit_log_path": "/var/log/radius/audit.log"
}
```

When enabled, logs all security events in JSON format:

- Authentication attempts, successes, failures
- Rate limit violations
- Unauthorized client attempts
- Duplicate request detection

!!! tip
    Use `logrotate` to manage audit log rotation and retention.

### strict_rfc_compliance

Enable strict RFC 2865 compliance validation.

- **Type**: Boolean
- **Default**: `true` (recommended)

**Example:**

```json
{
  "strict_rfc_compliance": true
}
```

When enabled:

- ✅ Enforces required attributes (User-Name, User-Password/CHAP-Password)
- ✅ Validates enumerated values (Service-Type 1-13, etc.)
- ✅ Type-specific validation (string UTF-8, integer/IPv4 lengths)
- ✅ Rejects malformed packets

When disabled (lenient mode):

- ⚠️ Only enforces critical requirements
- ⚠️ Allows invalid enumerated values for compatibility
- ⚠️ Use only if you have non-compliant RADIUS clients

!!! danger "Security Recommendation"
    Keep strict mode enabled unless you have legacy clients that don't comply with RFC 2865.

### request_cache_ttl

Request deduplication cache time-to-live in seconds.

- **Type**: Integer
- **Default**: `60`
- **Valid range**: 1-3600

**Example:**

```json
{
  "request_cache_ttl": 60
}
```

Prevents replay attacks by caching request authenticators.

### request_cache_max_entries

Maximum number of cached requests for deduplication.

- **Type**: Integer
- **Default**: `10000`
- **Valid range**: 100-1000000

**Example:**

```json
{
  "request_cache_max_entries": 10000
}
```

### rate_limit_per_client_rps

Maximum requests per second per client IP.

- **Type**: Integer
- **Default**: `100`
- **Valid range**: 0 (unlimited) - 10000

**Example:**

```json
{
  "rate_limit_per_client_rps": 100
}
```

### rate_limit_per_client_burst

Burst capacity for per-client rate limiting.

- **Type**: Integer
- **Default**: `200`
- **Valid range**: 0-20000

**Example:**

```json
{
  "rate_limit_per_client_burst": 200
}
```

### rate_limit_global_rps

Maximum requests per second globally (all clients).

- **Type**: Integer
- **Default**: `1000`
- **Valid range**: 0 (unlimited) - 100000

**Example:**

```json
{
  "rate_limit_global_rps": 1000
}
```

### rate_limit_global_burst

Burst capacity for global rate limiting.

- **Type**: Integer
- **Default**: `2000`
- **Valid range**: 0-200000

**Example:**

```json
{
  "rate_limit_global_burst": 2000
}
```

## EAP (`eap` block)

Optional. When present, the server answers Access-Requests that carry
EAP-Message with EAP-TLS and/or EAP-TEAP (RFC 3579); the in-memory `users`
list is the credential store for TEAP's inner Basic-Password-Auth. At least
one of `enable_tls` and `enable_teap` must be set, or the server refuses to
start.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `tls.cert_path`, `tls.key_path` | string | required | Server certificate and private key (PEM), shared by both methods |
| `tls.ca_path` | string | none | CA bundle used to verify supplicant certificates |
| `tls.require_client_cert` | bool | `false` | Require and verify a supplicant certificate (EAP-TLS) |
| `tls.revocation` | object | none | CRL/OCSP checking of supplicant certificates; needs `require_client_cert` and `ca_path` |
| `enable_tls` | bool | `false` | Offer EAP-TLS (Type 13) |
| `enable_teap` | bool | `false` | Offer EAP-TEAP (Type 55); offered before EAP-TLS when both are on |
| `session_idle_timeout_secs` | integer ≥ 1 | `120` | Evict an EAP conversation after this long without a packet from the peer |
| `max_sessions` | integer ≥ 1 | `4096` | Most live EAP conversations; the least recently used is evicted when full |

**Example:**

```json
{
  "eap": {
    "enable_tls": true,
    "enable_teap": false,
    "tls": {
      "cert_path": "/etc/radius/certs/server.pem",
      "key_path": "/etc/radius/certs/server-key.pem",
      "ca_path": "/etc/radius/certs/ca.pem",
      "require_client_cert": true
    },
    "session_idle_timeout_secs": 120,
    "max_sessions": 4096
  }
}
```

!!! warning "EAP-TEAP is opt-in"
    `enable_teap` defaults to `false`. TEAP's only inner method is
    Basic-Password-Auth, which compares the password the supplicant sends
    inside the TLS tunnel against the password stored for that user in
    `users`. A user without a stored password (unknown user, or a backend
    that does not supply cleartext passwords) is always rejected; an empty
    stored or supplied password is always rejected. The TEAP wire format is
    not yet interoperable with wpa_supplicant (see
    [RFC-COMPLIANCE](../protocol/RFC-COMPLIANCE.md)), and when TEAP is
    enabled it is offered before EAP-TLS. Enable it only for supplicants you
    have tested against this server.

## Complete Configuration Example

### Basic Configuration

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "SecureSharedSecret2024!",
  "clients": [
    {
      "address": "192.168.1.0/24",
      "secret": "NetworkSecret123!",
      "name": "Internal Network"
    },
    {
      "address": "10.0.0.1",
      "secret": "VPNSecret456!",
      "name": "VPN Gateway"
    }
  ],
  "users": [
    {
      "username": "admin",
      "password": "Admin!Pass123",
      "attributes": {}
    },
    {
      "username": "john.doe",
      "password": "UserPass456!",
      "attributes": {}
    }
  ],
  "verbose": false
}
```

### Production Configuration

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "secret": "ProductionDefaultSecret2024!Change",
  "clients": [
    {
      "address": "192.168.100.0/24",
      "secret": "WirelessAPSecret!2024",
      "name": "Wireless Access Points",
      "enabled": true
    },
    {
      "address": "10.20.30.40",
      "secret": "VPNGatewaySecret!2024",
      "name": "Primary VPN Gateway",
      "enabled": true
    },
    {
      "address": "10.20.30.41",
      "secret": "VPNGatewaySecret!2024",
      "name": "Backup VPN Gateway",
      "enabled": true
    },
    {
      "address": "172.16.0.0/16",
      "secret": "InternalNASSecret!2024",
      "name": "Internal Network Access Servers",
      "enabled": true
    }
  ],
  "users": [],
  "verbose": false,
  "log_level": "info",
  "audit_log_path": "/var/log/radius/audit.log",
  "strict_rfc_compliance": true,
  "request_cache_ttl": 60,
  "request_cache_max_entries": 10000,
  "rate_limit_per_client_rps": 100,
  "rate_limit_per_client_burst": 200,
  "rate_limit_global_rps": 1000,
  "rate_limit_global_burst": 2000
}
```

!!! note
    Production systems should integrate with external authentication backends (LDAP, AD, database) rather than storing users in config.

## Configuration Validation

The server validates configuration on startup:

### Valid Configuration

```plain
✓ Valid listen address: 0.0.0.0
✓ Valid port: 1812
✓ Valid secret (16+ characters)
✓ All clients have valid addresses
✓ All clients have valid secrets
✓ All users have usernames
```

### Invalid Examples

**Empty Secret:**

```json
{
  "secret": ""
}
```

```plain
Error: Secret cannot be empty
```

**Invalid Port:**

```json
{
  "listen_port": 0
}
```

```plain
Error: Port cannot be 0
```

**Invalid IP Address:**

```json
{
  "listen_address": "999.999.999.999"
}
```

```plain
Error: Invalid listen address: 999.999.999.999
```

## Environment Variables

Environment variable expansion is supported for all secret fields using `${VAR_NAME}` syntax.

**Supported Fields:**

- `secret` (default shared secret)
- `clients[].secret` (per-client secrets)

**Syntax:**

```json
{
  "secret": "${RADIUS_SECRET}",
  "clients": [
    {
      "address": "192.168.1.0/24",
      "secret": "${CLIENT_NETWORK_SECRET}",
      "name": "Internal Network"
    }
  ]
}
```

**Usage:**

```bash
# Set environment variables
export RADIUS_SECRET="MyVerySecureSecret2024!"
export CLIENT_NETWORK_SECRET="NetworkSecret123!"

# Start server (variables are expanded on startup)
usg_radius
```

**Error Handling:**

If an environment variable is referenced but not set, the server will fail to start:

```plain
Error: Environment variable not found: RADIUS_SECRET
```

!!! tip "Best Practices"
    - Use environment variables in containerized deployments (Docker, Kubernetes)
    - Never commit `.env` files with real secrets to version control
    - Validate environment variables are set before starting the server
    - Use secret management systems (HashiCorp Vault, AWS Secrets Manager) in production

## Reloading Configuration

Currently, configuration changes require a server restart:

```bash
# Stop server (Ctrl+C)
# Edit config.json
# Start server
cargo run --release
```

!!! info "Future Feature"
    Hot reloading of configuration (SIGHUP) is planned for a future release.

## Configuration Best Practices

### Security

1. **File Permissions**: Restrict access to config file

   ```bash
   chmod 600 config.json
   chown radius:radius config.json
   ```

2. **Secret Management**:
   - Generate secrets using cryptographic random generators
   - Never commit config files with real secrets to version control
   - Use `.gitignore` to exclude `config.json`

3. **Separate Secrets**: Use different secrets for each client

4. **Regular Rotation**: Change secrets periodically

### Reliability

1. **Backup**: Keep backups of configuration

   ```bash
   cp config.json config.json.backup
   ```

2. **Version Control**: Track config structure (not secrets) in Git

   ```bash
   cp config.json config.example.json
   # Remove real secrets from config.example.json
   git add config.example.json
   ```

3. **Validation**: Test config changes before deploying

   ```bash
   # Dry-run validation (future feature)
   usg_radius --validate config.json
   ```

### Performance

1. **Specific Binding**: Bind to specific interface when possible
2. **Client Networks**: Use CIDR notation for client networks
3. **Minimal Verbosity**: Disable verbose logging in production

## Troubleshooting

### Server Won't Start

**Problem**: `Error: Permission denied`

**Solution**: Port below 1024 requires elevated privileges

```bash
sudo cargo run --release
# or use capabilities
sudo setcap 'cap_net_bind_service=+ep' target/release/usg_radius
```

---

**Problem**: `Error: Address already in use`

**Solution**: Another process is using port 1812

```bash
sudo lsof -i :1812
# Stop conflicting process or change port
```

### Configuration Errors

**Problem**: `Error: Could not load config file`

**Solution**: Check file path and permissions

```bash
ls -l config.json
# Ensure file exists and is readable
```

---

**Problem**: `Error: Invalid configuration`

**Solution**: Validate JSON syntax

```bash
# Use a JSON validator
cat config.json | python -m json.tool
```

## Next Steps

- [Client Configuration](clients.md)
- [User Management](users.md)
- [Security Best Practices](../security/overview.md)
