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
  "accounting_port": 1813,
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
  "rate_limit_global_burst": 2000,
  "eap": {
    "enable_tls": true,
    "enable_teap": false,
    "session_idle_timeout_secs": 120,
    "max_sessions": 4096,
    "tls": {
      "cert_path": "/etc/radius/eap/server.pem",
      "key_path": "/etc/radius/eap/server.key",
      "ca_path": "/etc/radius/eap/supplicant-ca.pem",
      "require_client_cert": true
    }
  }
}
```

The `eap` block is optional; without it the server answers EAP-Message
requests with Access-Reject. See [EAP Settings](#eap-settings).

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

The UDP port for authentication traffic (Access-Request, and Status-Server
answered with Access-Accept). Accounting has its own socket, see
[`accounting_port`](#accounting_port).

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

### accounting_port

Where Accounting-Request (RFC 2866) is accepted over UDP. The default binds a
second UDP socket on `listen_address:1813` next to the authentication socket,
so a NAS sends accounting to the standard port and gets its Accounting-Response
back from source port 1813. A Status-Server received on this socket is answered
with Accounting-Response (RFC 5997 §4.2).

- **Type**: Integer (1-65535) or one of the strings `"shared"`, `"disabled"`
- **Default**: `1813`
- **Forms**:
  - An integer: bind a dedicated accounting socket on that port. The same
    `listen_address` is used, so dual-stack (`"::"`) binding applies to both
    sockets. Accounting-Request arriving on the authentication port is
    silently discarded (one warn-level log line, no reply).
  - `"shared"`: no second socket; Accounting-Request is accepted on the
    authentication socket. This is the behaviour of releases before the
    accounting socket existed.
  - `"disabled"`: no second socket; Accounting-Request over UDP is discarded.

Access-Request on the accounting socket is always discarded. A failure to
bind the accounting socket is fatal, like a failure to bind the
authentication socket.

**Example:**

```json
{
  "listen_port": 1812,
  "accounting_port": 1813
}
```

**Validation:**

- `0` is rejected: `accounting_port cannot be 0 (use "disabled" or "shared")`
- A value equal to `listen_port` is rejected: `accounting_port 1812 must differ from listen_port`
- Any string other than `"shared"` or `"disabled"` fails to parse

!!! note
    Ignored under `transport = "radsec"`: authentication, accounting and
    Status-Server share the single TLS connection on 2083/tcp (RFC 6614 §2.5).

!!! warning "Migration"
    Earlier releases bound only `listen_port` and accepted accounting there.
    With the default `accounting_port: 1813`, a NAS still sending
    Accounting-Request to the authentication port gets no reply and
    retransmits. Either point the NAS's accounting server at 1813, or set
    `"accounting_port": "shared"` until every NAS has moved. The shipped
    `examples/configs/*.json` and the Kubernetes manifest set the key
    explicitly.

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

Prevents replay attacks by caching request authenticators. Within the TTL a
byte-identical retransmission of a locally answered Access-Request (a NAS that
lost the reply), from the same address and port, gets the cached reply again,
unchanged (RFC 5080 §2.2.2); other duplicates are dropped. Keep the TTL longer than your NASes' retransmission
schedule.

### request_cache_max_entries

Maximum number of cached requests for deduplication. Each entry holds at most
one cached reply (≤ 4096 octets), so the cache uses at most about 4 KiB per
entry.

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

## EAP Settings

The optional `eap` object enables EAP-TLS (RFC 5216) and/or EAP-TEAP
(RFC 9930) and bounds the server's per-conversation EAP state. It needs a
binary built with the `tls` cargo feature (the release binary and the
container image are); a binary built without it refuses a configuration that
has an `eap` block. `examples/configs/eap-tls-revocation.json` shows the
complete block.
At least one of `enable_tls` and `enable_teap` must be set, or the
server refuses to start. The in-memory `users` list is the credential
store for TEAP's inner Basic-Password-Auth.

```json
{
  "eap": {
    "enable_tls": true,
    "enable_teap": false,
    "session_idle_timeout_secs": 120,
    "max_sessions": 4096,
    "tls": {
      "cert_path": "/etc/radius/eap/server.pem",
      "key_path": "/etc/radius/eap/server.key",
      "ca_path": "/etc/radius/eap/supplicant-ca.pem",
      "require_client_cert": true,
      "revocation": {
        "mode": "crl_only",
        "on_error": "fail_closed",
        "crl": { "static_files": ["/etc/radius/eap/supplicant-ca.crl"] }
      }
    },
    "teap_tls": {
      "cert_path": "/etc/radius/eap/server.pem",
      "key_path": "/etc/radius/eap/server.key",
      "require_client_cert": false
    }
  }
}
```

### eap.tls

TLS material for EAP-TLS, and for the EAP-TEAP tunnel (Phase 1) when
`eap.teap_tls` is absent. Required when the `eap` block is present.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `cert_path` | String | required | PEM server certificate chain presented to supplicants |
| `key_path` | String | required | PEM private key for `cert_path` |
| `ca_path` | String | none | PEM CA bundle used to verify supplicant certificates |
| `require_client_cert` | Boolean | `false` | Require and verify a supplicant certificate (mutual TLS). EAP-TLS deployments set this to `true` |
| `revocation` | Object | none | CRL/OCSP checking of supplicant certificates; requires `require_client_cert: true` and `ca_path`, and a binary built with the `revocation` feature. Fields as in `examples/configs/eap-tls-revocation.json` |

The TLS stack is rustls with aws-lc-rs: TLS 1.2 and 1.3, no DTLS.

### eap.teap_tls

Optional TLS material for the EAP-TEAP tunnel, with the same keys as
`eap.tls`. Use it when EAP-TLS must require (and revocation-check) supplicant
certificates while TEAP authenticates the tunnel with the server certificate
only and the user with a password inside it; `require_client_cert: false`
makes the tunnel server-authenticated. Omitted, TEAP shares `eap.tls`,
including its `require_client_cert`. The same validation applies (a
`revocation` block needs `require_client_cert: true` and `ca_path`).

### eap.enable_tls

Offer EAP-TLS (EAP Type 13).

- **Type**: Boolean
- **Default**: `false`

### eap.enable_teap

Offer EAP-TEAP (EAP Type 55).

- **Type**: Boolean
- **Default**: `false`

When both methods are enabled the server proposes TEAP first; a supplicant
configured for EAP-TLS answers with an EAP-Nak listing Type 13 and is switched
to EAP-TLS (RFC 3748 §5.3.1), once per conversation. TEAP with
Basic-Password-Auth interoperates with wpa_supplicant 2.12 (see
[RFC-COMPLIANCE.md](../protocol/RFC-COMPLIANCE.md#rfc-9930---tunnel-eap-teap-version-1-obsoletes-rfc-7170));
supplicants must validate the server certificate (`ca_cert` / `domain_match`),
since the password is protected by the tunnel alone.

!!! warning "EAP-TEAP is opt-in"
    `enable_teap` defaults to `false`. TEAP's only inner method is
    Basic-Password-Auth, which compares the password the supplicant sends
    inside the TLS tunnel against the password stored for that user in
    `users`. A user without a stored password (unknown user, or a backend
    that does not supply cleartext passwords, such as PostgreSQL or LDAP) is
    always rejected; an empty stored or supplied password is always rejected.
    Enable TEAP only where the in-memory `users` list is the credential store.

### eap.session_idle_timeout_secs

Seconds an EAP conversation may go without a packet from the peer before
its state (the EAP session plus its EAP-TLS / EAP-TEAP TLS context) is
evicted. The reaper runs on every incoming EAP packet, so the timeout holds
on a quiet server too. An evicted conversation fails closed: the next
Access-Request carrying its State is answered with Access-Reject +
EAP-Failure and allocates nothing.

- **Type**: Integer (seconds)
- **Default**: `120`
- **Validation**: must be at least 1 (`eap.session_idle_timeout_secs must be at least 1`)

Conversations are also released as soon as they reach Access-Accept or
Access-Reject, so this only governs abandoned ones. Set it above the
supplicant's longest retransmission interval (wpa_supplicant and Windows
retry within 30 s; eapol_test within 10 s).

### eap.max_sessions

Maximum number of live EAP conversations. When the store is full and a new
conversation starts, the least recently used one is evicted (and fails
closed as above). Continuations of live conversations never evict anything.

- **Type**: Integer
- **Default**: `4096`
- **Validation**: must be at least 1 (`eap.max_sessions must be at least 1`)

Each conversation holds a rustls connection plus at most 64 KiB of fragment
reassembly, so the default bounds EAP state to a few hundred MiB in the worst
case. Size it together with `rate_limit_per_client_rps` and
`rate_limit_global_rps`: a peer within the rate limits can still fill the
store and displace in-progress conversations once the cap is reached.
Evictions are logged at debug level and counted in the
`radius_eap_sessions_evicted_total{reason="idle"|"capacity"}` metric.

## Complete Configuration Example

### Basic Configuration

```json
{
  "listen_address": "::",
  "listen_port": 1812,
  "accounting_port": 1813,
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
  "accounting_port": 1813,
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

**Accounting port of 0:**

```json
{
  "accounting_port": 0
}
```

```plain
Error: accounting_port cannot be 0 (use "disabled" or "shared")
```

**Accounting port equal to the authentication port:**

```json
{
  "listen_port": 1812,
  "accounting_port": 1812
}
```

```plain
Error: accounting_port 1812 must differ from listen_port
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

**EAP session bounds:**

```json
{
  "eap": {
    "session_idle_timeout_secs": 0,
    "tls": { "cert_path": "server.pem", "key_path": "server.key" }
  }
}
```

```plain
Error: eap.session_idle_timeout_secs must be at least 1
```

`eap.max_sessions: 0` is rejected the same way, and `eap.tls.revocation`
without `require_client_cert: true` and `ca_path` is rejected because there
would be no supplicant certificate to check.

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

**Solution**: Another process is using port 1812 or 1813. The server binds
both the authentication socket (`listen_port`) and, by default, the
accounting socket (`accounting_port`); either one failing to bind stops
startup.

```bash
sudo lsof -i :1812 -i :1813
# Stop the conflicting process, change the port, or set
# "accounting_port": "shared" / "disabled" if 1813 is taken on purpose
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
