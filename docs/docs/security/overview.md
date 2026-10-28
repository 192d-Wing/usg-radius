# Security Overview

RADIUS was designed in 1997, and while widely used, it has known security limitations. This guide explains the security considerations when deploying USG RADIUS.

## RADIUS Security Model

### What RADIUS Protects

✅ **User passwords** - Encrypted in transit using MD5
✅ **Message integrity** - Response Authenticator prevents tampering
✅ **Replay protection** - Request Authenticator is random
✅ **Server authentication** - Shared secret proves server identity

### What RADIUS Does NOT Protect

❌ **Usernames** - Sent in cleartext
❌ **Attributes** - Sent in cleartext (except User-Password)
❌ **Eavesdropping** - No end-to-end encryption
❌ **Client authentication** - Clients not cryptographically authenticated
❌ **Traffic analysis** - Packet metadata visible

These weaknesses apply to the plain UDP transport (`transport: "udp-insecure"`). The default RadSec transport (RFC 6614) wraps the whole exchange in mutually authenticated TLS 1.3 and closes all five gaps; see [Transport Security (RadSec)](#transport-security-radsec) below.

## Cryptographic Weaknesses

### MD5 Hash Function

RADIUS uses MD5, which has known weaknesses:

- **Collision attacks**: MD5 collisions can be found in seconds
- **Pre-image attacks**: Theoretical weaknesses exist
- **Deprecated**: Considered cryptographically broken for many uses

**However**, for RADIUS:

- ✅ MD5 use is acceptable for password encryption (XOR with hash)
- ✅ Request/Response Authenticator use is acceptable
- ⚠️ Not suitable for password hashing (use bcrypt/argon2)

### Password Encryption

User-Password encryption process:

```
Encrypted = Password XOR MD5(Secret + Authenticator)
```

**Vulnerabilities:**

1. **Offline dictionary attacks** if:
   - Shared secret is weak
   - Attacker captures traffic
   - Attacker can try password guesses

2. **Known-plaintext attacks**:
   - If attacker knows some passwords
   - Can derive information about secret

**Mitigations:**

- Use RadSec (`transport: "radsec"`) so the packet is never exposed on the wire
- Use strong shared secrets (16+ characters, random) where UDP is unavoidable
- Use network security (VPN, IPsec) for any remaining UDP legs
- Monitor for unusual traffic
- Implement account lockout policies

## Shared Secret Security

The shared secret is the foundation of RADIUS security.

### Secret Requirements

**Minimum:** 16 characters
**Recommended:** 24-32 characters
**Composition:** Random, high-entropy

### Generating Strong Secrets

```bash
# Linux/macOS - 32 random bytes, base64 encoded
openssl rand -base64 32

# Result:
vK3mNx8Qq7RzPtW5YhU2jLdF9GbSaE4c
```

```bash
# Alternative - hexadecimal
openssl rand -hex 24

# Result:
a3f9c2e1b5d8f0a6c9e4b2d7f1a5c8e3b6d9f2a5c8e1
```

### Secret Management

1. **Unique Secrets**: Different secret per client/network
2. **Secure Storage**:

   ```bash
   chmod 600 config.json
   chown radius:radius config.json
   ```

3. **No Version Control**: Add to `.gitignore`
4. **Regular Rotation**: Change every 90-180 days
5. **Secure Distribution**: Use encrypted channels
6. **Secure Deletion**: Overwrite when changing

### Secret Rotation Procedure

1. **Generate new secret**:

   ```bash
   NEW_SECRET=$(openssl rand -base64 32)
   echo "New secret: $NEW_SECRET"
   ```

2. **Update server** configuration with new secret

3. **Grace period**: Support both old and new secret (future feature)

4. **Update clients** one by one

5. **Verify** each client works with new secret

6. **Remove old secret** from server config

## Network Security

### Deployment Architectures

#### Insecure (Not Recommended)

```
[Client]──────Internet──────>[RADIUS Server]
          ❌ Cleartext
          ❌ No encryption
          ❌ Easily intercepted
```

**Problems:**

- Usernames visible
- Attributes visible
- Vulnerable to MITM
- Vulnerable to replay

#### Secure (Recommended)

```
[Client]──────VPN/IPsec──────>[RADIUS Server]
          ✓ Encrypted tunnel
          ✓ Authenticated
          ✓ Protected from eavesdropping
```

**Benefits:**

- All traffic encrypted
- Mutual authentication
- Perfect Forward Secrecy (with right config)

### VPN/IPsec for RADIUS

Wrap RADIUS in encrypted tunnel:

**IPsec Example:**

```bash
# Server-side
ipsec pki --gen > strongswanKey.pem
ipsec pki --pub --in strongswanKey.pem | ipsec pki --issue \
    --lifetime 3650 --cacert caCert.pem --cakey caKey.pem \
    --dn "C=US, O=Company, CN=radius.example.com" \
    --san radius.example.com > strongswanCert.pem
```

**OpenVPN Example:**

```
# Tunnel RADIUS through OpenVPN
server 10.8.0.0 255.255.255.0
push "route 192.168.1.100 255.255.255.255"
```

### Firewall Rules

Restrict RADIUS access:

```bash
# UFW - Allow only from specific network
sudo ufw allow from 192.168.1.0/24 to any port 1812 proto udp

# iptables - Allow only from specific IPs
sudo iptables -A INPUT -p udp --dport 1812 \
    -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 1812 -j DROP
```

### Network Isolation

```
┌─────────────────────────────────────┐
│     Management Network (Isolated)   │
│                                     │
│  ┌──────────┐      ┌─────────────┐ │
│  │  RADIUS  │      │  Auth DB    │ │
│  │  Server  │──────│             │ │
│  └────┬─────┘      └─────────────┘ │
│       │                             │
└───────┼─────────────────────────────┘
        │
   ┌────┴────┐
   │ Firewall│
   └────┬────┘
        │
┌───────┼─────────────────────────────┐
│  Production Network                 │
│                                     │
│  [NAS] [VPN] [WiFi APs]             │
└─────────────────────────────────────┘
```

## Authentication Security

### Password Policies

Enforce strong passwords:

```rust
struct PasswordPolicy {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_numbers: bool,
    require_symbols: bool,
}

fn validate_password(password: &str, policy: &PasswordPolicy) -> bool {
    if password.len() < policy.min_length {
        return false;
    }

    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return false;
    }

    // ... additional checks

    true
}
```

Recommended policy:

- Minimum 12 characters
- Mix of upper/lower/numbers/symbols
- No dictionary words
- No personal information

### Account Lockout

Prevent brute force attacks:

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct FailedAttempts {
    count: u32,
    last_attempt: Instant,
}

struct RateLimiter {
    attempts: HashMap<String, FailedAttempts>,
    max_attempts: u32,
    lockout_duration: Duration,
}

impl RateLimiter {
    fn check_attempt(&mut self, username: &str) -> bool {
        let now = Instant::now();

        let entry = self.attempts.entry(username.to_string())
            .or_insert(FailedAttempts {
                count: 0,
                last_attempt: now,
            });

        // Reset if lockout duration passed
        if now.duration_since(entry.last_attempt) > self.lockout_duration {
            entry.count = 0;
        }

        // Check if locked out
        if entry.count >= self.max_attempts {
            return false;
        }

        true
    }

    fn record_failure(&mut self, username: &str) {
        let entry = self.attempts.entry(username.to_string())
            .or_insert(FailedAttempts {
                count: 0,
                last_attempt: Instant::now(),
            });

        entry.count += 1;
        entry.last_attempt = Instant::now();
    }
}
```

### Multi-Factor Authentication

RADIUS supports MFA via Access-Challenge:

```
Client               Server
  │                    │
  │ Access-Request     │
  │ (username)         │
  │───────────────────>│
  │                    │
  │ Access-Challenge   │
  │ (OTP prompt)       │
  │<───────────────────│
  │                    │
  │ Access-Request     │
  │ (OTP code)         │
  │───────────────────>│
  │                    │
  │ Access-Accept      │
  │<───────────────────│
```

Implementation (future feature):

```rust
impl AuthHandler for MFAAuthHandler {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        // 1. Check password
        // 2. Send OTP
        // 3. Verify OTP
        // Return true only if both succeed
        todo!()
    }
}
```

## Operational Security

### Logging & Audit Trail

USG RADIUS provides comprehensive logging and JSON audit trail capabilities.

#### Structured Logging

All authentication attempts are logged using the `tracing` framework:

```rust
// Structured logging with fields
info!(
    username = %username,
    client_ip = %source_ip,
    request_id = request.identifier,
    "Authentication successful"
);

warn!(
    username = %username,
    client_ip = %source_ip,
    request_id = request.identifier,
    "Authentication failed"
);
```

**Log Levels:**

- `trace`: Extremely detailed debugging
- `debug`: Detailed debugging information
- `info`: Normal operational messages
- `warn`: Warning messages (failed auth, rate limits)
- `error`: Error messages

**Configuration:**

```json
{
  "log_level": "info"
}
```

Or use environment variable:

```bash
RUST_LOG=debug usg_radius
```

#### JSON Audit Trail

For compliance and forensic analysis, enable JSON audit logging:

```json
{
  "audit_log_path": "/var/log/radius/audit.log"
}
```

**Audit Events Logged:**

- `auth_attempt` - Every authentication request
- `auth_success` - Successful authentication
- `auth_failure` - Failed authentication
- `rate_limit_exceeded` - Rate limit violations
- `unauthorized_client` - Requests from unauthorized IPs
- `duplicate_request` - Replay attack attempts

**Audit Entry Format:**

```json
{
  "timestamp": 1735596000,
  "timestamp_iso": "2025-12-30T12:00:00Z",
  "event_type": "auth_success",
  "username": "admin",
  "client_ip": "192.168.1.50",
  "client_name": "Internal Network",
  "request_id": 42,
  "server_version": "0.1.0"
}
```

**What to log:**

- ✅ Username (success and failure)
- ✅ Source IP
- ✅ Client name (from config)
- ✅ Timestamp (Unix + ISO 8601)
- ✅ Event type
- ✅ Request ID
- ✅ Server version
- ❌ Passwords (never log passwords)

**Log Rotation and Retention:**

The server runs as a Kubernetes `Deployment` (the systemd unit was removed in v0.9.0), so there is no host `logrotate` hook and no `systemctl reload`. Send the audit trail to stdout and let the cluster log pipeline handle rotation and retention:

```json
{
  "audit_log_path": "stdout"
}
```

`"stdout"` (or `"-"`) is recognized by the audit logger (`crates/radius-server/src/audit.rs`) and emits one JSON object per line, interleaved with the regular `tracing` output. From there:

- **Node level**: the container runtime (containerd) rotates `/var/log/pods/...` according to the kubelet's `containerLogMaxSize` / `containerLogMaxFiles` settings.
- **Cluster level**: ship the stream with your log collector (Fluent Bit, Vector, Promtail/Alloy, Datadog agent, etc.) and apply the 90-day retention required by your compliance program in the log store (Loki, Elasticsearch, S3, SIEM).
- **Filtering**: audit entries carry `"event_type"`; filter on it in the collector to route the audit trail to a dedicated index or bucket separate from debug logs.

If you must write to a file instead (for example a sidecar collector that tails a shared `emptyDir`), the server appends to `audit_log_path` without rotating it; the sidecar is responsible for rotation, and the server does not need to be signalled after rotation because it reopens nothing (rotate by copy-truncate).

### Monitoring

Monitor for security events:

1. **Failed login patterns**:
   - Multiple failures for same user
   - Multiple users from same IP
   - Failures outside business hours

2. **Anomaly detection**:
   - Login from unusual location
   - Login at unusual time
   - Unusual number of requests

3. **Service availability**:
   - Server uptime
   - Response time
   - Request rate

### Incident Response

1. **Detection**: Automated alerting for suspicious activity

2. **Investigation**:

   ```bash
   # Recent auth failures (audit sink on stdout)
   kubectl -n radius logs deploy/usg-radius-server --since=1h | grep '"event_type":"auth_failure"' | tail -100

   # Specific user
   kubectl -n radius logs deploy/usg-radius-server --since=24h | grep '"username":"alice"'
   ```

   Use your log store's query language (LogQL, KQL, etc.) for anything older than the pod's local log window.

3. **Response**:
   - Lock compromised accounts
   - Block attacking IPs
   - Rotate shared secrets if compromised

4. **Recovery**:
   - Reset affected passwords
   - Review and update security policies
   - Document incident

## Compliance

### Regulatory Requirements

Different industries have different requirements:

**PCI DSS (Payment Card Industry):**

- Strong password policies
- Multi-factor authentication
- Encrypted transmission
- Access logging and monitoring
- Regular security audits

**HIPAA (Healthcare):**

- Access controls
- Audit logging
- Encryption in transit
- Risk assessments

**NIST Guidelines:**

- Follow NIST SP 800-63B for authentication
- Use strong cryptography
- Implement account lockout
- Monitor and log access

## Transport Security (RadSec)

RadSec (RADIUS over TLS, RFC 6614) shipped in v0.10.0 and is the **default transport for configuration files**. It replaces the shared-secret + source-IP trust model with mutually authenticated TLS:

- ✅ **TLS 1.3 only**, ML-KEM-1024-only key exchange (FIPS 203) via the shared `usg-fips-tls` provider; the negotiated parameters are re-checked after the handshake and the connection is dropped if anything falls outside the allow-list.
- ✅ **Mutual TLS**: every NAS presents a client certificate verified against `radsec.client_ca_path`. The certificate Common Name is the server's authenticated notion of "which switch" and is the identity used to address CoA/Disconnect requests.
- ✅ **Forward secrecy** from the ephemeral ML-KEM key exchange.
- ✅ Inside the tunnel the payload is standard RADIUS using the fixed secret `"radsec"` (RFC 6614 §2.3); the real protection is the TLS layer.
- ✅ Authentication, accounting, Status-Server and server-originated CoA/Disconnect (RFC 5176) share one long-lived connection per NAS on 2083/tcp. A Status-Server inside the tunnel must carry a Message-Authenticator under the fixed `"radsec"` secret or it is silently discarded (RFC 5997 §4.1); over UDP the same rule applies with the client's secret, on both the authentication and the accounting socket.
- ✅ **Outbound hop (proxy → home server)**: a home server configured with `transport: "radsec"` is reached over one persistent TLS 1.3 connection built with the same `usg-fips-tls` provider (ML-KEM-1024 only, `TLS_AES_256_GCM_SHA384`, parameters re-checked after every handshake, resumption disabled). The proxy presents its own client certificate (`tls.cert_path`/`tls.key_path`); the home server's chain is validated against `tls.ca_path` and must be valid for `tls.server_name`, with optional CRL/OCSP checking through the same `revocation` block used elsewhere. The hop secret is the fixed `"radsec"` (a configured `secret` is rejected), so the TLS certificates are the only authentication on that hop; the link therefore never falls back to UDP, and a response is attributed to the home server by the connection it arrived on, never by source address. The connection is closed and re-established with backoff on any protocol violation (RFC 6613 §2.6.4) and after two unanswered Status-Server probes (RFC 3539 §3.4 watchdog, mandatory: `health_check.enabled` is required for RadSec home servers). See [Proxy: RadSec to home servers](../proxy/README.md#radsec-to-home-servers-rfc-6614).

**Configuration** (`transport` selects the listener; `radsec` is required when `transport` is `"radsec"`):

```json
{
  "transport": "radsec",
  "radsec": {
    "listen_address": "::",
    "listen_port": 2083,
    "cert_path": "/etc/radius/radsec/server.pem",
    "key_path": "/etc/radius/radsec/server-key.pem",
    "client_ca_path": "/etc/radius/radsec/nas-ca.pem"
  }
}
```

| `transport` | Listener | Trust model | Notes |
|-------------|----------|-------------|-------|
| `"radsec"` (default for config files) | 2083/tcp, TLS 1.3 mTLS | NAS client certificate | Requires the `tls` cargo feature (built into the container image since v0.10.1) |
| `"udp-insecure"` | `listen_port`/udp (1812) | Shared secret + source IP | **Not FIPS-approved**, spoofable; logs a prominent startup warning. Only for development against legacy NASes |

Limitations: no DTLS (RFC 7360); no certificate hot-rotation for the listener or the proxy's outbound client certificate (restart the pod to pick up renewed certificates); no certificate pinning or TLS-PSK trust; CRL/OCSP checking of NAS certificates (`radsec.revocation`, v0.12.0) and of RadSec home-server certificates (`tls.revocation` on the home server) does not verify CRL/OCSP signatures, ignores stapled OCSP and runs its network fetches inside the handshake; the proxy components run only under the `udp-insecure` NAS listener, so RadSec-in → RadSec-out proxying is not available; the proxy forwards NAS Identifiers unchanged on its upstream hop (RFC 6613 §2.6).

## Management API Authentication

The management API (`/api/v1/*`, including `PUT /api/v1/policy` and `POST /api/v1/coa`) is protected by an optional `mgmt` block (v0.9.0): mutual TLS on the listener plus an AWS-IAM-style attribute-based access policy with explicit-deny-wins and default-deny. **Without a `mgmt` block the API is open** and the server logs a warning at startup, so configure it before exposing the port beyond the pod network.

```json
{
  "mgmt": {
    "tls": {
      "cert_path": "/etc/radius/mgmt/server.pem",
      "key_path": "/etc/radius/mgmt/server-key.pem",
      "client_ca_path": "/etc/radius/mgmt/client-ca.pem"
    },
    "access_policy_file": "/etc/radius/access-policy.json",
    "trust_forwarded_identity": true
  }
}
```

- `tls.client_ca_path` present ⇒ client certificates are required and verified.
- `access_policy_file` set ⇒ authorization is enforced; the policy can be hot-reloaded with `SIGHUP` and never fails open.
- Authorization denials are written to the JSON audit log as `unauthorized_client` events.

See [Management API Authentication](mgmt-api-auth.md) for the policy schema, condition keys, and the BFF client-certificate setup.

## EAP Methods

- ✅ **EAP-TLS** (RFC 5216): certificate-based 802.1X with mutual TLS, MSK/EMSK derivation via RFC 5705. See [EAP-TLS](../protocol/EAP-TLS.md).
- ⚠️ **EAP-TEAP** (RFC 7170): TLS tunnel and TLV protocol with RFC-correct Crypto-Binding; inner methods producing real keying material are still pending.
- ✅ **Message-Authenticator** is required on every EAP Access-Request (RFC 3579 §3.2, Blast-RADIUS / CVE-2024-3596 mitigation) and added to every EAP-bearing reply.
- ❌ EAP-TTLS and PEAP are not planned; use EAP-TLS or EAP-TEAP.
- ✅ **MS-MPPE-Send-Key / MS-MPPE-Recv-Key** (RFC 2548 §2.4) are attached to the EAP Access-Accept, salt-encrypted under the client secret, so the NAS receives the PMK for the 802.11i 4-way handshake (since v0.11.0). The proxy re-encrypts them (and Tunnel-Password) for the NAS and re-keys User-Password / Message-Authenticator for the home server.

## Future Enhancements

Remaining security work:

1. **RadSec**: DTLS transport, certificate hot-rotation and pinning, proxying under the inbound RadSec listener, Identifier rewriting on the proxy's upstream hop, CRL/OCSP signature verification and revocation fetches off the handshake path
2. **EAP**: EAP-TEAP inner methods with real IMSK
3. **Modern Crypto for UDP**: the UDP transport is bound to MD5 by RFC 2865; prefer RadSec rather than waiting for stronger UDP primitives

## Security Checklist

Before deploying to production:

- [ ] RadSec transport enabled (`transport: "radsec"`) with a NAS client CA; `udp-insecure` only where unavoidable
- [ ] Proxy home servers reached over RadSec (`"transport": "radsec"` with a `tls` block and, where a CRL or OCSP responder exists, `tls.revocation`); `health_check.interval` below the home server's TLS idle timeout
- [ ] Management API protected (`mgmt.tls.client_ca_path` and `mgmt.access_policy_file` set)
- [ ] Strong shared secrets (16+ characters) for any `udp-insecure` clients
- [ ] Unique secrets per client
- [ ] Firewall rules restricting access
- [ ] Network isolation or VPN
- [ ] File permissions on config (chmod 600)
- [ ] No secrets in version control
- [ ] Strong password policy
- [ ] Account lockout implemented
- [ ] Comprehensive logging enabled (`log_level: "info"`)
- [ ] JSON audit trail enabled (`audit_log_path` set to `"stdout"` or a collected file)
- [ ] Strict RFC compliance enabled (`strict_rfc_compliance: true`)
- [ ] Rate limiting configured appropriately
- [ ] Request deduplication cache enabled
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented
- [ ] Regular security audits scheduled
- [ ] Secret rotation procedure defined
- [ ] Backup and recovery tested
- [ ] Log retention configured in the cluster log pipeline (collector + store)

## References

- [RFC 2865 - RADIUS](https://tools.ietf.org/html/rfc2865)
- [RFC 2866 - RADIUS Accounting](https://tools.ietf.org/html/rfc2866)
- [RFC 3579 - RADIUS EAP Support](https://tools.ietf.org/html/rfc3579)
- [RFC 5176 - Dynamic Authorization Extensions (CoA/Disconnect)](https://tools.ietf.org/html/rfc5176)
- [RFC 5216 - EAP-TLS](https://tools.ietf.org/html/rfc5216)
- [RFC 6613 - RADIUS over TCP](https://tools.ietf.org/html/rfc6613)
- [RFC 6614 - RADIUS over TLS (RadSec)](https://tools.ietf.org/html/rfc6614)
- [RFC 7170 - EAP-TEAP](https://tools.ietf.org/html/rfc7170)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Next Steps

- [Server Configuration](../configuration/server.md)
- [Client Configuration](../configuration/clients.md)
- [Management API Authentication](mgmt-api-auth.md)
- [Monitoring and Logging](monitoring.md) (future)
