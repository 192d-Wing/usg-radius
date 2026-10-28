# RFC Compliance Gap Analysis

This document identifies gaps between the current USG RADIUS implementation and full RFC compliance.

## Summary

**Overall Status**: Production-ready for modern enterprise authentication with EAP-TLS over RadSec, server-originated CoA/Disconnect, certificate revocation checking, comprehensive rate limiting, accounting, and security features. Reflects the code at **v0.13.0**.

**Implemented**: Core RADIUS authentication (RFC 2865, PAP + CHAP), Accounting (RFC 2866) on a dedicated 1813/udp socket, Message-Authenticator (RFC 2869 / RFC 3579), EAP-TLS (RFC 5216 / RFC 9190), EAP-TEAP (RFC 9930, Basic-Password-Auth inner method, interoperable with wpa_supplicant), EAP-Nak method negotiation (RFC 3748 §5.3.1), MS-MPPE key delivery (RFC 2548), RadSec (RFC 6614), Status-Server (RFC 5997), CoA/Disconnect (RFC 5176), certificate revocation checking (RFC 5280 CRL, RFC 6960 OCSP, signatures verified) for EAP-TLS supplicant, RadSec NAS and RadSec home-server certificates, RADIUS proxy with secret re-keying on both legs and a UDP or RadSec (RFC 6614 / RFC 6613) upstream leg per home server, Rate Limiting, DoS Protection
**Partial**: EAP-TEAP inner methods that derive keying material (EAP-MSCHAPv2, inner EAP-TLS); certificate revocation (no delta or partitioned CRLs, no hot reload of static CRLs)
**Missing**: legacy tunneled EAP methods (TTLS/PEAP), DTLS transport, UDP-originated CoA

**Major Milestones Completed**:

- ✅ v0.1.1: Client validation, request deduplication, per-client secrets
- ✅ v0.2.0: Rate limiting, DoS protection, concurrent connection limits, bandwidth throttling
- ✅ v0.3.0: RADIUS accounting with database backend
- ✅ v0.4.0: Accounting exports and reporting
- ✅ v0.5.0: EAP-TLS with production key extraction (RFC 5216)
- ✅ v0.6.0: PostgreSQL and LDAP backends, health checks, Prometheus metrics
- ✅ v0.7.x: RADIUS proxy, EAP-TEAP Phase 1+2, CRL/OCSP module (`revocation` feature)
- ✅ v0.9.0: Kubernetes-only deployment, management API mTLS + ABAC, live session index
- ✅ v0.10.0: RadSec transport (RFC 6614), server-originated CoA/Disconnect (RFC 5176), Message-Authenticator required on EAP requests
- ✅ v0.10.1: Container image built with the `tls` feature (RadSec / EAP-TLS fix)
- ✅ v0.11.0: MS-MPPE-Send/Recv-Key (RFC 2548) on EAP Access-Accepts, RFC 9190 TLS 1.3 exporter labels + EAP-Key-Name, RFC 7170 §5.2 IMCK/CMK and §5.4 MSK, Vendor-Specific and Tunnel-Password codecs, proxy re-keying of User-Password / Message-Authenticator / MS-MPPE / Tunnel-Password
- ✅ v0.12.0: CRL/OCSP revocation checking wired into EAP-TLS and RadSec client-certificate verification (`revocation` block, fail-closed default), EAP-Failure on every EAP Access-Reject, interop harness (24 assertions incl. a revoked supplicant) running in CI
- ✅ v0.13.0: EAP-TEAP (RFC 9930) interoperable with wpa_supplicant (Crypto-Binding TLV, key schedule, fragmentation, EAP-Nak negotiation, `eap.teap_tls`), bounded EAP session store, Basic-Password-Auth fails closed, `eap.enable_teap` off by default; Status-Server per RFC 5997 with conformant health probes; dedicated 1813/udp accounting socket (`accounting_port`); interop harness at 67 assertions

---

## RFC 2865 - RADIUS Protocol

### ✅ Implemented

- ✅ Packet structure (Code, Identifier, Length, Authenticator)
- ✅ Access-Request packet handling
- ✅ Access-Accept packet generation
- ✅ Access-Reject packet generation
- ✅ Access-Challenge packet generation (for EAP)
- ✅ Request Authenticator (random 16 bytes)
- ✅ Response Authenticator calculation (MD5-based)
- ✅ User-Password encryption/decryption (MD5 XOR)
- ✅ Basic attribute encoding/decoding
- ✅ User-Name attribute (Type 1)
- ✅ User-Password attribute (Type 2)
- ✅ State attribute (Type 24) for multi-round authentication
- ✅ Standard attribute types (1-80+)
- ✅ Client validation with IP/CIDR matching
- ✅ Per-client shared secrets
- ✅ Request deduplication and replay attack prevention

### ✅ Security Features Implemented (v0.1.1+)

#### Client Validation ✅ IMPLEMENTED (v0.1.1)

**Status**: ✅ Complete
**Implementation**: Server validates source IP against authorized client list with CIDR support
**RFC**: RFC 2865 Section 3 - "A RADIUS server SHOULD use the source IP address of the RADIUS UDP packet to determine if the packet is from an authorized client"

**Features**:

- ✅ IP address validation (single IP or CIDR notation)
- ✅ Per-client shared secrets
- ✅ Enable/disable flag for clients
- ✅ IPv4 and IPv6 support
- ✅ Backward compatibility (empty client list allows all)

**Files**:

- [crates/radius-server/src/config.rs](../../crates/radius-server/src/config.rs) - Client struct with IP matching
- [crates/radius-server/src/server.rs](../../crates/radius-server/src/server.rs) - Client validation and per-client secrets

---

#### Request Deduplication ✅ IMPLEMENTED (v0.1.1)

**Status**: ✅ Complete
**Implementation**: Thread-safe cache with automatic expiry and replay attack prevention
**RFC**: RFC 2865 Section 2 - "The Identifier field aids in matching requests and replies"; RFC 5080 §2.2.2

**Features**:

- ✅ Request fingerprinting (Source IP + Identifier + first 8 octets of the Request Authenticator), plus a SHA-256 over the transport's shared secret and the whole request
- ✅ **Retransmitted Access-Requests get the cached reply** (RFC 5080 §2.2.2, unreleased): a byte-identical retransmission, under the same shared secret, of a locally answered Access-Request (PAP, CHAP, EAP) within the TTL is answered with the identical reply, final Access-Accept / Access-Reject included, without processing the request again. The replay re-sends bytes already computed for exactly that request (for EAP, after its Message-Authenticator was verified) and acts on nothing new; it goes only to the source address and port the original came from, at most 8 times. A duplicate still in progress, one answered with no reply, or different content (or another secret) under the same fingerprint is dropped. `radius_retransmissions_replayed_total` counter. Interop scenario 15
- ✅ Automatic cache expiry (configurable TTL, default 60s), also checked on lookup
- ✅ Thread-safe concurrent cache (DashMap); admission is atomic per fingerprint
- ✅ Configurable max entries (default 10,000); at most one cached reply (≤ 4096 octets) per entry. A full cache evicts an arbitrary entry (an unreleased fix: eviction used to deadlock the request task once the cache was full)
- ✅ Packets failing Message-Authenticator verification, and Accounting-Requests failing their Request Authenticator (RFC 2866 §3), never reach the cache (RFC 5080 §2.2.2 "MUST NOT affect the cache in any way")
- ⚠️ Non-EAP Access-Requests without a Message-Authenticator have nothing to verify, so a spoofer of a client address can still fill the cache with them (bounded by the rate limits) and push out cached replies; a full cache evicts an arbitrary entry
- ⚠️ The default TTL (60 s) exceeds RFC 5080 §2.2.2's 5–30 s SHOULD; set `request_cache_ttl` to 30 or less to follow it. The TTL is also the window in which a reply can be replayed
- ⚠️ Differences from RFC 2865 §3 / RFC 5080 §2.2.2 that do not affect a conformant NAS: the duplicate key is source IP + Identifier + Request Authenticator (the source port is compared only for a replay, which goes back to the original address and port), an older entry is not purged when its Identifier is reused with a new authenticator (it ages out), and a reply is replayed at most 8 times
- ✅ Protection against replay attacks
- ✅ Cache statistics and monitoring
- ⚠️ Accounting-Request retransmissions are still dropped, not answered with the Accounting-Response again (outside RFC 5080 §2.2.2, which covers Access-Request; Status-Server is answered once by design, see RFC 5997)
- ⚠️ Proxied Access-Requests are answered asynchronously by the proxy, so their replies are not cached: a NAS retransmission to the proxy is dropped while the original is in the cache (pre-existing behaviour)

**Files**:

- [crates/radius-server/src/cache.rs](../../crates/radius-server/src/cache.rs) - RequestCache implementation

---

### ✅ Rate Limiting & DoS Protection (v0.2.0)

#### Rate Limiting ✅ IMPLEMENTED (v0.2.0)

**Status**: ✅ Complete
**Implementation**: Token bucket algorithm with per-client and global limits

**Features**:

- ✅ Per-client request rate limiting
- ✅ Global request rate limiting
- ✅ Configurable RPS (requests per second) and burst capacity
- ✅ Concurrent connection limits (default: 100 per client)
- ✅ Bandwidth throttling (default: 1 MB/s per client)
- ✅ Automatic cleanup of old trackers
- ✅ Thread-safe with DashMap

**Configuration**:

```json
{
  "rate_limit_per_client_rps": 100,
  "rate_limit_per_client_burst": 200,
  "rate_limit_global_rps": 1000,
  "rate_limit_global_burst": 2000,
  "max_concurrent_connections": 100,
  "max_bandwidth_bps": 1000000
}
```

**Files**:

- [crates/radius-server/src/ratelimit.rs](../../crates/radius-server/src/ratelimit.rs) - Rate limiter implementation

---

### ⚠️ Partial Implementation

#### Proxy-State Attribute (Type 33)

**Status**: Echoed in response, ordering tests pending
**Current**: Proxy-State attributes from the request are copied into
Access-Accept, Access-Reject, Access-Challenge, and Accounting-Response
in the order they appear in the request
([crates/radius-server/src/server.rs](../../crates/radius-server/src/server.rs)).
**Required**: RFC 2865 Section 5.33 - Must be returned unmodified.
**Gap**: Lacks integration test coverage for multi-Proxy-State ordering and
correct stripping of server-added Proxy-State on the response leg.
**Priority**: LOW (proxy functionality usable; tighten with regression tests).

---

### ✅ Authentication Methods & Validation (v0.2.0 - v0.3.0)

#### 1. CHAP Support ✅ IMPLEMENTED (v0.3.0)

**RFC**: RFC 2865 Section 5.3
**Purpose**: Challenge/response password authentication (no cleartext password on the wire)
**Status**: ✅ Complete

**Features**:

- ✅ CHAP-Password attribute (Type 3) parsing (CHAP Ident + 16-byte MD5 response)
- ✅ CHAP-Challenge attribute (Type 60), falling back to the Request Authenticator as the challenge when absent (RFC 2865 §5.40)
- ✅ CHAP response verification (`MD5(Ident + password + challenge)`)
- ✅ Validation rejects a request carrying both User-Password and CHAP-Password
- ✅ Integration tests (`test_chap_*` in `tests/integration_tests.rs`)

**Files**:

- [crates/radius-proto/src/chap.rs](../../crates/radius-proto/src/chap.rs) - CHAP challenge/response primitives
- [crates/radius-server/src/server.rs](../../crates/radius-server/src/server.rs) - `ChapPassword` branch in Access-Request handling

---

#### 2. NAS Identification Validation ✅ IMPLEMENTED

**RFC**: RFC 2865 Section 5.32
**Required**: Either NAS-IP-Address (Type 4) OR NAS-Identifier (Type 32) must be present
**Current**: ✅ Enforced in both strict and lenient mode; an Access-Request with neither is rejected as malformed
**Also**: ✅ NAS-IPv6-Address (Type 95) parsing (v0.10.0)

**Files**:

- [crates/radius-proto/src/validation.rs](../../crates/radius-proto/src/validation.rs) - `validate_access_request`
- [crates/radius-server/src/server.rs](../../crates/radius-server/src/server.rs) - `validate_packet` call before dispatch

---

#### 3. Service-Type Enforcement ✅ IMPLEMENTED (strict mode)

**RFC**: RFC 2865 Section 5.6
**Current**: ✅ Enumerated values validated for Service-Type (Type 6), Framed-Protocol (7), Framed-Routing (10), Framed-Compression (13), Login-Service (15), and Termination-Action (29); Acct-Status-Type presence is required on Accounting-Request
**Modes**: Invalid enumerations are rejected when `strict_rfc_compliance: true` (the default) and accepted for compatibility in lenient mode

**Files**:

- [crates/radius-proto/src/validation.rs](../../crates/radius-proto/src/validation.rs) - `validate_service_type` and related validators

---

## RFC 2866 - RADIUS Accounting

### ✅ Implemented (v0.3.0 - v0.4.0)

**Status**: ✅ Complete
**Priority**: Production-ready

**Features**:

- ✅ Accounting-Request (Code 4) handling
- ✅ Accounting-Response (Code 5) generation
- ✅ Acct-Status-Type (Type 40) validation (Start, Stop, Interim-Update, Accounting-On, Accounting-Off)
- ✅ Accounting session tracking
- ✅ Multiple backend support:
  - ✅ File-based logging (JSONL format)
  - ✅ PostgreSQL database with full schema
- ✅ Interim update support
- ✅ Session aggregation and usage tracking
- ✅ Automatic cleanup of old data
- ✅ Export capabilities:
  - ✅ CSV export for sessions and usage
  - ✅ JSON export for reporting
  - ✅ Configurable retention policies

**Configuration**:

```json
{
  "accounting_log_path": "/var/log/radius/accounting.jsonl",
  "accounting_database_url": "postgresql://radius:pass@localhost/radius",
  "accounting_retention_days": 90
}
```

### ✅ Transport (v0.13.0)

**Status**: ✅ Dedicated UDP accounting socket on 1813
**Current**: In `udp-insecure` mode the server binds a second UDP socket on `listen_address:accounting_port` (default 1813, RFC 2866 §2) next to the authentication socket, with the same dual-stack (`::`) binding and IPv4-mapped source canonicalisation. Accounting-Response leaves through the socket that received the request, so its source port is 1813. The `accounting_port` key takes three forms:

- an integer (default `1813`): a dedicated accounting socket on that port; `0` and a value equal to `listen_port` are rejected when the configuration loads, and a bind failure is fatal (the server never runs half-listening);
- `"shared"`: no second socket; Accounting-Request is accepted on the authentication socket (the behaviour before this change);
- `"disabled"`: no second socket and Accounting-Request is discarded over UDP.

**Port admission**: Each UDP socket serves only the codes assigned to it. An Access-Request on the accounting socket, and an Accounting-Request on the authentication socket when a dedicated socket is bound or accounting is disabled, are silently discarded (no Access-Reject) with a warn-level log line. RFC 2866 §2 assigns the port; the discard itself follows RFC 2865 §3 (codes a listener does not serve are silently discarded) and matches FreeRADIUS.
**RadSec**: Not affected. Authentication, accounting and Status-Server share the single TLS connection on 2083/tcp (RFC 6614 §2.5); `accounting_port` is ignored under `transport = "radsec"`.
**Migration**: A NAS that still sends accounting to the authentication port gets no Accounting-Response once the dedicated socket is bound. Move its accounting destination to 1813, or set `"accounting_port": "shared"` while NASes migrate. Library embedders: `ServerConfig::new()` keeps the single-socket (`shared`) contract; only `ServerConfig::from_config` reads the key.
**Evidence**: unit tests `dual_sockets_route_by_port`, `shared_mode_binds_one_socket`, `accounting_request_on_auth_port_is_discarded_unless_shared`, `access_request_on_accounting_port_is_discarded`, `accounting_request_with_bad_request_authenticator_is_not_answered`; interop scenario 14 (radclient Accounting-Request to usg-home:1813 answered from 1813; Access-Request to 1813 and Accounting-Request to 1812 get no reply).

**Files**:

- [crates/radius-server/src/server.rs](../../crates/radius-server/src/server.rs) - `RadiusServer::new` binds the authentication socket and, for an integer `accounting_port`, the accounting socket; `PortRole` gates the codes each socket serves
- [crates/radius-server/src/config.rs](../../crates/radius-server/src/config.rs) - `AccountingPort` (integer | `"shared"` | `"disabled"`) and its validation
- [crates/radius-server/src/accounting/mod.rs](../../crates/radius-server/src/accounting/mod.rs) - Core accounting
- [crates/radius-server/src/accounting/file.rs](../../crates/radius-server/src/accounting/file.rs) - File backend
- [crates/radius-server/src/accounting/postgres.rs](../../crates/radius-server/src/accounting/postgres.rs) - PostgreSQL backend

---

## RFC 2869 - RADIUS Extensions

### ✅ Implemented

- ✅ Message-Authenticator attribute definition (Type 80)
- ✅ Message-Authenticator verification and generation (Section 5.14, see below)
- ✅ EAP-Message attribute (Type 79)
- ✅ EAP Support (RFC 3748 + RFC 2869 Section 5.13)

---

### ✅ EAP Support (v0.5.0)

#### EAP-TLS (RFC 5216) ✅ IMPLEMENTED (v0.5.0)

**Status**: ✅ 100% Complete (Production-Ready)
**Purpose**: Certificate-based authentication for 802.1X, WiFi, VPN
**Priority**: Production-ready for enterprise deployments

**Implemented Features**:

**Protocol Layer (100%)**:

- ✅ EAP-TLS packet structure (RFC 5216)
- ✅ TLS flags handling (L/M/S bits)
- ✅ Packet parsing and encoding
- ✅ EAP-TLS Start packet
- ✅ TLS handshake data packets
- ✅ TLS acknowledgment packets, both directions: the peer's ACKs for our
  fragments, and our empty EAP-TLS Request for each non-final peer fragment
  (RFC 5216 §2.1.5; v0.12.0, verified against eapol_test with `fragment_size=300`,
  interop scenarios 8 and 9)

**Fragmentation (100%)**:

- ✅ Automatic fragmentation (1020-byte fragments; `EapAuthHandler::set_max_fragment_size`, no config key yet)
- ✅ Fragment reassembly, fail-closed: the first fragment of a fragmented
  message must carry L and a TLS Message Length of 1–65536 octets, a fragment
  may not carry the message past the announced length, a non-final fragment
  must carry data, and a peer-sent S bit is rejected (v0.12.0)
- ✅ Multi-fragment handshake support in both directions
- ✅ TLS Message Length field handling
- ✅ More Fragments (M) flag coordination

**TLS Integration (100%)**:

- ✅ rustls 0.23 integration (TLS 1.2 and 1.3)
- ✅ Server certificate configuration
- ✅ Client certificate verification (mutual TLS)
- ✅ CA certificate chain validation
- ✅ Certificate expiry checking
- ✅ Subject Alternative Name (SAN) verification
- ✅ Common Name (CN) verification

**Cryptography (100%)**:

- ✅ Production key extraction using RFC 5705 (export_keying_material)
- ✅ MSK derivation (64 bytes) - RFC 5216 Section 2.3 (TLS 1.2) / RFC 9190 Section 2.3 (TLS 1.3)
- ✅ EMSK derivation (64 bytes) - RFC 5295
- ✅ Version-correct exporter labels: `"client EAP encryption"` (TLS 1.2),
  `"EXPORTER_EAP_TLS_Key_Material"` with the `0x0D` Type-Code context (TLS 1.3)
- ✅ MS-MPPE-Recv-Key (MSK[0..32]) / MS-MPPE-Send-Key (MSK[32..64]) on the
  Access-Accept, salt-encrypted per RFC 2548 §2.4 under the client secret and
  Request Authenticator (`"radsec"` under RadSec)
- ✅ EAP-Key-Name (RFC 9190 §2.5 Session-Id) on TLS 1.3 Access-Accepts
- ✅ RFC 9190 §2.5 commitment message (protected success indication) sent after the TLS 1.3 handshake; EAP-Success only on the peer's acknowledgement, with its Identifier echoing the peer's last EAP-Response (RFC 3748 §4.2)
- ✅ Cryptographically secure session binding

**Session Management (100%)**:

- ✅ EAP state machine (RFC 3748)
- ✅ Session context tracking
- ✅ Multi-round authentication flow
- ✅ Session identifiers and buffering
- ✅ Bounded session store: conversations are released on Access-Accept /
  Access-Reject, evicted after `eap.session_idle_timeout_secs` (default 120)
  of silence, and capped at `eap.max_sessions` (default 4096, least recently
  used evicted first). The idle reaper runs on every incoming EAP packet,
  before its State is resolved, so an idle conversation is evicted whether or
  not a new one starts and its own late packet cannot revive it. An evicted
  conversation fails closed (its State is rejected without allocating
  anything); evictions are logged and counted in
  `radius_eap_sessions_evicted_total{reason}`. Configuration:
  [server.md](../configuration/server.md#eap-settings)

**RADIUS Integration (100%)**:

- ✅ EapAuthHandler for RADIUS server
- ✅ EAP-Message attribute fragmentation
- ✅ State attribute handling
- ✅ Access-Challenge generation
- ✅ Access-Accept on EAP-Success carrying MS-MPPE-Send/Recv-Key (see Cryptography)
- ✅ Integration with inner auth handlers

**Certificate Management (100%)**:

- ✅ PEM certificate loading (rustls-pemfile)
- ✅ Private key loading (RSA/ECDSA/Ed25519)
- ✅ Certificate validation (x509-parser)
- ✅ CA chain verification
- ✅ Mutual TLS configuration

**Testing (100%)**:

- ✅ 84 comprehensive test suites
- ✅ 100% test pass rate
- ✅ Unit tests for all components
- ✅ Integration tests for handshake flow

**Documentation (100%)**:

- ✅ Protocol guide (400+ lines)
- ✅ Usage examples (600+ lines)
- ✅ API reference (400+ lines)
- ✅ Certificate generation guides
- ✅ Troubleshooting documentation

**Configuration Example**:

```rust
use radius_server::EapAuthHandler;
use radius_proto::eap::eap_tls::TlsCertificateConfig;
use std::sync::Arc;

// Create inner handler for fallback auth
let mut inner_handler = SimpleAuthHandler::new();
inner_handler.add_user("testuser", "testpass");

// Create EAP handler
let mut eap_handler = EapAuthHandler::new(Arc::new(inner_handler));

// Configure TLS certificates
let cert_config = TlsCertificateConfig::new(
    "server.pem".to_string(),
    "server-key.pem".to_string(),
    Some("ca.pem".to_string()), // CA for client verification
    true,                        // Require client certificate
);

eap_handler.configure_tls("", cert_config)?;
```

**Files**:

- [crates/radius-proto/src/eap.rs](../../crates/radius-proto/src/eap.rs) - EAP-TLS implementation (1,100+ lines)
- [crates/radius-server/src/eap_auth.rs](../../crates/radius-server/src/eap_auth.rs) - RADIUS integration
- [docs/docs/protocol/EAP-TLS.md](../protocol/EAP-TLS.md) - Protocol documentation
- [docs/docs/examples/eap-tls-example.md](../examples/eap-tls-example.md) - Usage examples

---

#### Legacy EAP Methods (Not Planned)

**EAP-TTLS, PEAP, EAP-MSCHAPv2**: Deferred indefinitely
**Rationale**:

- EAP-TLS provides superior security
- EAP-TEAP (RFC 9930, formerly RFC 7170) is the modern IETF standard that supersedes all legacy tunneled methods
- Resources better spent on EAP-TEAP implementation
- Legacy methods have known security weaknesses

**Migration Path**: Users should migrate to EAP-TLS or await EAP-TEAP implementation.

---

### ✅ Message-Authenticator Validation ✅ IMPLEMENTED (v0.3.0, hardened v0.10.0)

**RFC**: RFC 2869 Section 5.14, RFC 3579 Section 3.2, RFC 5080
**Purpose**: HMAC-MD5 integrity protection of the whole packet
**Status**: ✅ Complete

**Features**:

- ✅ HMAC-MD5 calculation over the packet with the attribute value zeroed
- ✅ Verified whenever present on an Access-Request; an invalid value rejects the request
- ✅ Verified first, before the duplicate cache and before proxy routing (unreleased): a packet failing the check leaves no cache entry and evicts nothing (RFC 5080 §2.2.2), and the proxy never forwards it re-signed under a home server's secret (before, routing ran first, so an EAP Access-Request with a missing or invalid Message-Authenticator from a spoofed client address reached the home server validly signed). Status-Server is checked at the same point
- ✅ **Required** when EAP-Message is present; an EAP Access-Request without Message-Authenticator is rejected (RFC 3579 §3.2, "Blast-RADIUS" CVE-2024-3596 mitigation, v0.10.0)
- ✅ Added to every Access-Accept, Access-Reject, and Access-Challenge that carries EAP-Message
- ✅ Inside RadSec the fixed secret `"radsec"` is used for the HMAC per RFC 6614 §2.3
- ✅ **Required and verified on Status-Server** (RFC 5997 §4.1); absent, invalid, not 16 octets long, or present more than once → silent discard. Added to every Status-Server reply
- ✅ Verified on a health-probe reply when present (RFC 3579 §3.2) before the home server counts as alive
- ✅ HMAC-MD5 and Response Authenticator comparisons are constant-time

**Gaps**:

- ⚠️ Not required on non-EAP Access-Requests (RFC 5080 §2.2.2 recommends it; configurable enforcement is not available)

**Files**:

- [crates/radius-proto/src/message_auth.rs](../../crates/radius-proto/src/message_auth.rs) - `calculate_message_authenticator` / `verify_message_authenticator`
- [crates/radius-server/src/server.rs](../../crates/radius-server/src/server.rs) - verification in Access-Request handling, `add_message_authenticator_if_eap` on replies

---

### ❌ Not Implemented

#### Tunnel Attributes

**RFC**: RFC 2868 Section 3.1-3.11
**Purpose**: VPN and tunnel configuration
**Priority**: MEDIUM
**Status**: Future enhancement

**Implemented**: Tunnel-Password (Type 69, RFC 2868 §3.5) salt-encrypt /
decrypt codec in [crates/radius-proto/src/tunnel_password.rs](../../crates/radius-proto/src/tunnel_password.rs),
used by the proxy to re-encrypt home-server passwords for the NAS.

**Missing**: Tagged tunnel attribute codecs (Types 64-68, 81-83, 90-91); the
server does not originate tunnel attributes itself.

---

## RFC 3748 - Extensible Authentication Protocol (EAP)

### ✅ Implemented (v0.5.0)

**Core EAP Protocol**:

- ✅ EAP packet structure
- ✅ EAP-Request/Response
- ✅ EAP-Success/Failure
- ✅ EAP-Identity exchange
- ✅ EAP state machine
- ✅ Multi-round authentication
- ✅ EAP-TLS method (Type 13)

- ✅ §4.1 Identifier: the first EAP-Request of a conversation continues the
  NAS's sequence (Identity Response Identifier + 1) rather than starting at
  0, so it never repeats the Identifier of the NAS's EAP-Request/Identity;
  every later Request increments it
- ✅ §4.2 EAP-Success / EAP-Failure Identifier echoes the peer's last
  EAP-Response
- ✅ §4.1 Identifier matching (unreleased): each conversation tracks
  the Identifier of its outstanding EAP-Request and accepts only an
  EAP-Response carrying it, once. A Response with any other Identifier,
  or a duplicate of one already processed that reaches the server under a
  new RADIUS Identifier, is silently discarded (no RADIUS reply) without
  advancing or refreshing the conversation; the matching Response then
  proceeds. Concurrent copies cannot both be processed
- ✅ State (RFC 2865 §5.24, RFC 5080 §2.1.1 / §2.1.2, unreleased): 16 octets from the
  operating system's CSPRNG (`getrandom`), fixed length, never derived from
  the User-Name or the time, constant for the whole conversation. The
  conversation is bound to the RADIUS client address that started it and to
  the request's NAS-IP-Address, NAS-IPv6-Address, NAS-Identifier and
  User-Name; a State presented by another NAS or for another user gets an
  Access-Reject and leaves the live conversation untouched. An
  EAP-Response/Identity (or an Access-Request without EAP-Message) always
  starts a new conversation, so a replayed State can neither resume nor
  restart one
- ⚠️ Over RadSec the shared secret is the public `"radsec"`, so the binding
  rests on the peer IP and the NAS attributes, not on the peer's verified
  client certificate: two RadSec NASes behind one NAT address are not told
  apart. Binding the certificate identity is a follow-up
- ✅ NAS retransmissions of an Access-Request get the cached reply, the final
  Access-Accept / Access-Reject included (RFC 5080 §2.2.2; see Request
  Deduplication under RFC 2865)
- ✅ RFC 3579 §2.6.2 (unreleased): an Access-Request encapsulating an
  EAP-Request (role reversal), EAP-Success or EAP-Failure gets an
  Access-Reject without touching any conversation; for an EAP-Request the
  Reject carries an EAP-Response/Nak offering no method
- ✅ RFC 3579 §2.1 EAP-Start (an EAP-Message of length 2) starts a
  conversation like an Access-Request without EAP-Message (unreleased; it
  used to be rejected), provided the request carries a User-Name: every
  Access-Request without one is dropped before the EAP handler
- ⚠️ A Response that does not answer the outstanding Request is silently
  discarded at the RADIUS level too (no reply), as RFC 3748 §4.1 asks of the
  EAP authenticator; the RFC 3579 §2.2 alternative (an Access-Challenge with
  Error-Cause 202 and the last EAP-Request, ending the conversation after
  about 5 invalid packets) is not implemented. A NAS that forwards such
  packets sees a RADIUS timeout for each; the conversation itself is
  unaffected and idles out if nothing valid follows

---

## RFC 5216 - EAP-TLS Authentication Protocol

### ✅ Implemented (v0.5.0)

**Status**: ✅ 100% Complete - Production-Ready

See EAP-TLS section under RFC 2869 for complete details.

**Key RFC 5216 Compliance**:

- ✅ Section 2.1.1: Base case (server-only and mutual authentication)
- ✅ Section 2.1.5: Fragmentation — outgoing fragments of at most 1020 octets
  (L and TLS Message Length on the first, M on all but the last); each
  non-final peer fragment acknowledged with an EAP-TLS Request carrying no
  data; reassembly bounded at 64 KiB and fail-closed (v0.12.0)
- ✅ Section 2.3: Key hierarchy — MSK and EMSK, 64 octets each, from the
  RFC 5705 exporter (`client EAP encryption`); TLS 1.3 uses RFC 9190 §2.3
- ✅ Section 3.1 / 3.2: Request and Response packet format — Flags (L/M/S),
  TLS Message Length only with L, TLS Data; S accepted only on our own Start
- ⚠️ Section 2.1.2: Session resumption not implemented (full handshake only)

---

## RFC 9930 - Tunnel EAP (TEAP) Version 1 (obsoletes RFC 7170)

### ✅ Implemented (Basic-Password-Auth inner method; v0.13.0)

**Status**: ✅ Interoperable with wpa_supplicant 2.12's `eapol_test` (the first
release whose TEAP follows RFC 9930): the interop harness runs EAP-TEAP with
Basic-Password-Auth over TLS 1.3 and TLS 1.2, directly and through the proxy,
plus a wrong-password case, and asserts the MS-MPPE keys match the
supplicant's own TEAP MSK (`tests/interop/`, scenarios 10–13). The key schedule
and Crypto-Binding TLV are also pinned by known-answer vectors from an
independent implementation (`tests/vectors/teap_rfc9930_vectors.py`, Python
standard library, written from the RFC text and self-checked against the
published RFC 5246 `P_SHA256` vector) in `crates/radius-proto/src/eap/eap_teap.rs`.
**Off by default** (`eap.enable_teap`, default `false`): Basic-Password-Auth
needs the inner handler to supply the user's cleartext password, which only
the in-memory `users` list does.

- ✅ §3.1 Version negotiation: every server packet carries Version 1 in the
  Flags/Ver octet (`TeapPacket`); the peer's first response must propose
  version 1 and later packets must keep it, otherwise the conversation ends
  (fail closed). The negotiated version is echoed in the Crypto-Binding TLV's
  Received-Ver and checked there against a downgrade
- ✅ §3.2 TEAP/Start: S bit, version 1, empty TLS payload, no Outer TLVs
  (the Authority-ID TLV is optional and not sent)
- ✅ §3.3 Fragmentation, both phases and directions: outbound TLS messages
  (handshake flights and encrypted TLV messages) are fragmented to the EAP
  MTU and sent one per peer ACK; inbound non-final fragments are ACKed and
  reassembled through the same bounded, fail-closed assembler as EAP-TLS; a
  peer that sends data while server fragments are pending is rejected
- ✅ §3.3 L flag: set, with the TLS Message Length, on the first fragment of
  a fragmented message and on no other message (EAP-TLS keeps L on every
  first packet, which RFC 5216 permits and the interop suite was validated
  against)
- ✅ §3.2 / §3.6.3 Phase 2 opens in the TLS message that ends the handshake
  flight: Basic-Password-Auth-Req TLV (empty prompt) + Identity-Type TLV
  (User); the peer answers with a Basic-Password-Auth-Resp (§4.2.15: one-octet
  Userlen / Passlen, trailing octets rejected, constant-time password compare)
  and its Identity-Type (must be User)
- ✅ §3.6.6 / Appendix C.1 Protected termination: on inner success the server
  sends Intermediate-Result (Success), Result (Success) and the Crypto-Binding
  Request in one message; the peer must answer with Intermediate-Result
  (Success), its Crypto-Binding Response and Result (Success). The
  Crypto-Binding is verified before either result is examined (§3.1); a
  missing or invalid binding, an Intermediate-Result other than Success or a
  missing Result ends the conversation. On inner failure the server sends
  Result (Failure) and waits for the peer's Result before the cleartext
  EAP-Failure. The MSK is released only when the binding verified and both
  Results were Success
- ✅ §4.2.13 Crypto-Binding TLV: 76-octet Value (Reserved, Version 1,
  Received-Ver, Flags ‖ Sub-Type, 32-octet Nonce, 20-octet EMSK Compound-MAC,
  20-octet MSK Compound-MAC); the request nonce has the LSB of its last octet
  clear and the response nonce must be the request nonce with that bit set;
  Flags = 2 (MSK Compound-MAC only) since no implemented inner method derives
  an EMSK; a response claiming an EMSK Compound-MAC (Flags 1 or 3), another
  Sub-Type, another Version/Received-Ver or another nonce is rejected
- ✅ §6.1 `session_key_seed` = TLS-Exporter("EXPORTER: teap session key seed", , 40)
- ✅ §6.2 IMCK[j] = TLS-PRF(S-IMCK[j-1], "Inner Methods Compound Keys",
  IMSK[j], 60), S-IMCK[j] / CMK[j] its first 40 / last 20 octets, with
  IMSK = 32 zero octets for Basic-Password-Auth (§6.2.1); the TLS-PRF is
  RFC 5246 `P_<hash>` with the hash of the negotiated cipher suite (SHA-384
  for `TLS_AES_256_GCM_SHA384` and the `*_SHA384` TLS 1.2 suites, SHA-256
  otherwise), as wpa_supplicant and hostapd select it
- ✅ §6.3 Compound-MAC = first 20 octets of HMAC-<hash>(CMK[n], BUFFER),
  BUFFER = the Crypto-Binding TLV with both MAC fields zeroed ‖ 0x37 ‖ the
  server's Outer TLVs ‖ the peer's Outer TLVs. Outer TLVs (O bit) are accepted
  on the peer's first (unfragmented) message only and enter the BUFFER
- ✅ §6.4 MSK / EMSK = first 64 octets of TLS-PRF(S-IMCK[n], "Session Key
  Generating Function" / "Extended Session Key Generating Function"); the
  MSK feeds the MS-MPPE keys (RFC 2548)
- ✅ RFC 3748 §4.2: EAP-Success echoes the Identifier of the peer's last
  EAP-Response
- ✅ RFC 3748 §5.3.1 EAP-Nak: a peer that declines the proposed method and
  lists EAP-TLS (13) or EAP-TEAP (55) is switched to that method once per
  conversation, provided it is configured and no method data was processed
  yet; so a server with both methods enabled (TEAP proposed first) serves
  EAP-TLS supplicants. Any other Nak ends the conversation
- ✅ `eap.teap_tls`: optional TLS configuration of the TEAP tunnel (same
  schema as `eap.tls`), so the tunnel can be server-authenticated only while
  EAP-TLS keeps requiring supplicant certificates
- ⚠️ Inner methods: Basic-Password-Auth (interop-tested) and EAP-MD5 (unit
  tests only), both with the zero IMSK of §6.2.1, which RFC 9930 marks NOT
  RECOMMENDED on its own: the tunnel is bound to the server certificate, not
  to a key the inner method derived. Inner methods with keying material
  (EAP-MSCHAPv2, inner EAP-TLS), the EMSK-based S-IMCK chain and method
  sequences are pending
- ⚠️ Not sent: Authority-ID TLV, EAP-Key-Name / Session-Id (§3.8), Error TLV
  with Result (Failure), PAC / Request-Action handling (a Request-Action TLV
  from the peer is ignored; an unknown mandatory TLV ends the conversation)
- ⚠️ Peer Outer TLVs in a fragmented first message (O with M) are rejected
- ⚠️ TLS session resumption is not supported
- ℹ️ wpa_supplicant ≤ 2.11 derives the Basic-Password-Auth MSK from S-IMCK[0]
  (its pre-RFC 9930 reading of RFC 7170 §5.2) and reports an MS-MPPE key
  mismatch against this server; 2.12 and hostap master derive it from
  S-IMCK[1] as RFC 9930 §6.2.2 / §6.4 specify
- ✅ §4.2.14 / §4.2.15 Basic-Password-Auth fails closed: a user the inner
  handler has no password for is rejected inside the tunnel (Result=Failure;
  the tunnel still completes, so an unknown user is indistinguishable from a
  wrong password), an empty expected or supplied password never matches, and
  the password comparison is constant-time. Previously a missing password was
  replaced by an empty string and an empty supplied password authenticated
  (never released; see CHANGELOG). Handler-level tests
  (`eap_teap_rejects_*` in `eap_auth.rs`) drive wrong-password,
  empty-password (known and unknown user) and empty-stored-password
  conversations to Access-Reject
- ✅ Phase 2 bounded per conversation: at most 32 reassembled Phase 2
  messages (`EapTeapServer::MAX_PHASE2_ROUNDS`), and a repeated Identity-Type
  TLV is a protocol error; both fail closed (`EapError::Phase2LimitExceeded`
  → Access-Reject, session released). Only a packet answered with an
  Access-Challenge refreshes the session's LRU position

---

## RFC 5997 - Status-Server

### ✅ Implemented (v0.13.0)

**Status**: ✅ Server and client (health-probe) behaviour per RFC 5997 over UDP and RadSec

- ✅ Status-Server (Code 12) handled on the authentication socket, the accounting socket and RadSec
- ✅ **Message-Authenticator required and verified** with the hop secret (per-client secret over UDP, `"radsec"` inside RadSec). A Status-Server without one, with an invalid one, with a value that is not 16 octets, or with more than one Message-Authenticator attribute is **silently discarded** — no reply, a warn log line without secret material (§4.1, §4.2)
- ✅ **Reply code follows the port** (§4.2): Access-Accept on the authentication socket and over RadSec, Accounting-Response on the accounting socket
- ✅ Reply carries a correct Response Authenticator (RFC 2865 §3 / RFC 2866 §3) and a Message-Authenticator (the §5 attribute table permits it on both reply codes; radclient and FreeRADIUS verify it when present); Proxy-State echoed unmodified and in order (RFC 2865 §5.33); nothing else — no State, EAP-Message or Reply-Message
- ✅ **The proxy never forwards Status-Server** (§4.3): it is answered before any routing decision, so a NAS probing the proxy learns the proxy's liveness only
- ✅ **Home-server health probes are RFC 5997 clients**: random Request Authenticator (§3), Message-Authenticator under the home server's secret (§4.1; the fixed `"radsec"` over RadSec). Over UDP each probe uses an ephemeral socket and a random Identifier, so concurrent probes cannot mis-attribute replies, and a reply counts only if it comes from the probed address; over a RadSec link the probe travels on the home server's authenticated TLS connection with an Identifier chosen from the ones free on that connection, and the TLS peer authentication stands in for the source-address check. On both transports the reply must carry the probe's Identifier, its Response Authenticator must verify under that secret, and any Message-Authenticator it carries must verify too (§4.4, RFC 3579 §3.2). Access-Accept, Accounting-Response and an authenticated Access-Reject (which §4.2 permits a server to send) count as alive; an undecodable datagram, any other code, or a reply that fails either check is skipped and the probe keeps waiting, so the probe fails only when its deadline passes without a verified reply. Over RadSec the probe is also the RFC 6613 §2.6 / RFC 3539 §3.4 watchdog of the connection (§4.3): a reply that fails an authenticator check closes the connection, as do two consecutive unanswered probes
- ✅ Rate limiting and the duplicate-request cache apply to Status-Server as to every other code (§6). An identical copy within the cache TTL is dropped: clients do not retransmit Status-Server (§4.1) and get at most one reply (§3); RFC 5080 §2.2.2's reply replay covers Access-Request only
- ✅ Interop (scenario 14): radclient Status-Server to usg-home on 1812 → Access-Accept, on 1813 → Accounting-Response, to the proxy on 1812 → Access-Accept, each reply carrying a Message-Authenticator; wrong secret → no reply. The proxy's own probes against its three home servers — FreeRADIUS over UDP, FreeRADIUS over RadSec (inside the TLS connection) and usg-home — are asserted to succeed with health checks enabled

### ⚠️ Partial

**Gaps**:

- ⚠️ **No administrative switch.** §4.2 says servers SHOULD let an administrator globally enable or disable the acceptance of Status-Server (per-client control MAY be offered). Acceptance is always on — the default the RFC recommends — and cannot be turned off; use a firewall if a deployment must not answer probes
- ⚠️ Response always indicates healthy; it is not tied to backend (LDAP/PostgreSQL) health. Kubernetes probes use the HTTP `/health/*` endpoints instead

**Priority**: LOW

---

## RFC 5176 - Dynamic Authorization Extensions (CoA / Disconnect)

### ✅ Implemented (v0.10.0)

**Status**: ✅ Server-originated CoA/Disconnect over RadSec
**Trigger**: Management API `POST /api/v1/coa` (action `disconnect` | `coa`), gated by the `mgmt` mTLS + ABAC layer (`radius:SendCoA`)

**Features**:

- ✅ Packet codes Disconnect-Request/ACK/NAK (40-42) and CoA-Request/ACK/NAK (43-45)
- ✅ Request Authenticator computed per RFC 5176 §3.4 (Accounting-Request style)
- ✅ `Error-Cause` (Type 101) values for NAK handling
- ✅ Requests written server→NAS over the NAS's established RadSec connection; ACK/NAK correlated by Identifier with Response Authenticator verification
- ✅ `NasRegistry` maps the authenticated NAS identity (client-cert CN) to its live connection
- ✅ `Termination-Action` reply attribute for silent in-place re-auth on Session-Timeout

### ❌ Not Implemented

- ❌ **CoA/Disconnect over UDP** (RFC 5176 default port 3799). Only the RadSec path exists; a NAS that is not connected via RadSec cannot be reached.
- ❌ Inbound CoA/Disconnect handling (the server only originates requests; it is not a Dynamic Authorization Server for upstream systems). A CoA-Request / Disconnect-Request that a home server sends down the proxy's outbound RadSec link is answered with CoA-NAK / Disconnect-NAK, `Error-Cause` 406 (§3.5, RFC 6614 §2.5), not relayed to the NAS
- ❌ Automatic retransmission / Event-Timestamp replay window on the server side

**Files**:

- [crates/radius-proto/src/dynauth.rs](../../crates/radius-proto/src/dynauth.rs) - Codes and `ErrorCause`
- [crates/radius-server/src/coa.rs](../../crates/radius-server/src/coa.rs) - `NasRegistry` and request correlation
- [crates/radius-server/src/radsec.rs](../../crates/radius-server/src/radsec.rs) - Bidirectional connection loop

---

## RFC 6614 - RADIUS over TLS (RadSec)

### ✅ Implemented (v0.10.0 inbound; outbound unreleased)

**Status**: ✅ Default transport for configuration files (`transport = "radsec"`); plain UDP is the explicit `transport = "udp-insecure"` fallback and logs a startup warning. ✅ The proxy reaches a home server over RadSec when that home server is configured with `transport = "radsec"` (unreleased)
**Build**: Requires the `tls` cargo feature (default features; the container image builds it since v0.10.1). A `transport = "radsec"` home server is a configuration error in a binary built without it (fail closed)

**Features (inbound listener, NAS → server)**:

- ✅ TLS 1.3 listener on 2083/tcp (default `::`, dual-stack) with ML-KEM-1024-only key exchange (FIPS 203) via `usg-fips-tls`; negotiated parameters re-checked after the handshake, fail closed
- ✅ Mutual TLS: NAS client certificate verified against `radsec.client_ca_path`; the client-cert CN is the authenticated NAS identity
- ✅ RADIUS packets sent as-is on the stream and delimited by their own `Length` field (RFC 6614 §3.4 item 1); a `Length` outside 20..=4096 closes the connection (RFC 6613 §2.6.4)
- ✅ Fixed shared secret `"radsec"` for Authenticator / Message-Authenticator math (RFC 6614 §2.3 item 4)
- ✅ Authentication, accounting, and Status-Server on the single connection (§2.5); a Status-Server inside the tunnel must carry a Message-Authenticator under `"radsec"` and is answered with Access-Accept (RFC 5997 §4.1, §4.2)
- ✅ Bidirectional connection used for server-originated CoA/Disconnect (RFC 5176)

**Features (outbound link, proxy → home server; unreleased)**:

- ✅ Per home server `transport: "udp"` (default) or `"radsec"` in `proxy.pools[].servers[]`, with a `tls` block (`ca_path`, `cert_path`, `key_path`, `server_name`, optional `revocation`). No `secret` is accepted for a RadSec home server: the hop secret is the fixed `"radsec"` (§2.3 item 4), so every re-keying step the proxy already performs (User-Password and Message-Authenticator on the request leg; Response Authenticator, MS-MPPE-Send/Recv-Key, Tunnel-Password and Message-Authenticator on the response leg) is keyed by `"radsec"` on that hop ([crates/radius-server/src/proxy/home_server.rs](../../crates/radius-server/src/proxy/home_server.rs))
- ✅ **One persistent TLS connection per RadSec home server** (§2.5; "as per RFC 6613", §2.3 item 1) owned by a link task, built with the same `usg-fips-tls` provider as the listener: TLS 1.3 only, ML-KEM-1024-only key exchange, `TLS_AES_256_GCM_SHA384`, session resumption disabled so every reconnect is a full handshake with full certificate verification, no ALPN; `enforce_fips_parameters` re-checks the negotiated version, suite and group before a RADIUS byte is written. Failure to connect leads to continuous retries with exponentially growing, jittered intervals (§2.3 item 1: 500 ms doubling to a 30 s cap, ±25 %) ([crates/radius-server/src/proxy/radsec_client.rs](../../crates/radius-server/src/proxy/radsec_client.rs))
- ✅ **Mutual authentication** (§2.3 item 2) with X.509 certificates: the proxy presents `tls.cert_path`/`tls.key_path`; the home server's chain is validated per RFC 5280 against `tls.ca_path` and must be valid for `tls.server_name` (DNS name or IP literal, also sent as SNI) (§2.3 item 3). The TLS connection authenticates the home server, so a proxied response is attributed to the home server by the connection it arrived on, never by source address, and a UDP datagram can never satisfy a RadSec entry
- ✅ **Fail closed, no UDP fallback**: a TLS verification or parameter failure keeps the link down; while it is down a forwarded request stays in the proxy cache and the retry manager resends it on a new connection or, after `retry.max_retries`, answers the NAS with the signed Access-Reject it already understands
- ✅ Home-server certificate **revocation checking** through the same `revocation` block as `eap.tls.revocation` / `radsec.revocation` (static CRLs, CRL Distribution Points, OCSP, fail-closed default): a `ServerCertVerifier` adapter runs WebPKI chain/validity/name validation first, then `RevocationCheckingVerifier::check_chain` — CRL/OCSP signatures verified, every certificate but the anchor checked ([crates/radius-server/src/server_verifier.rs](../../crates/radius-server/src/server_verifier.rs))
- ✅ Packets delimited by `Length` on the stream (§3.4 item 1) with the shared `take_frame`; **the connection is closed** on a `Length` outside 20..=4096, on a correctly framed packet that does not decode, on a proxied response whose Response Authenticator fails, and on a Status-Server reply whose Response Authenticator or Message-Authenticator fails (RFC 6613 §2.6.4); it is then re-established with backoff. A response that matches no outstanding request is discarded and the connection kept (§2.6.4 permits either)
- ✅ RFC 5997 Status-Server probes travel over the same connection as the **RFC 3539 §3.4 application-layer watchdog** RFC 6613 §2.6 mandates (see RFC 6613 below); the probe's Identifier is chosen from the ones free on the connection
- ✅ CoA-Request / Disconnect-Request arriving on the outbound link from the home server are answered with CoA-NAK / Disconnect-NAK carrying `Error-Cause` 406 (Unsupported Extension), signed under `"radsec"` (§2.5, RFC 5176 §3.5); dynamic authorization is not relayed to the NAS
- ✅ Interop (scenario 17, `tests/interop/run.sh`): eapol_test EAP-TLS and radclient PAP → usg-radius proxy → FreeRADIUS 3.2.7 (OpenSSL 3.5.7) over RadSec, with a different secret on the NAS hop. FreeRADIUS's own log is the independent witness: `RADIUS/TLS - Connection Established`, `TLS-Session-Version = "TLS 1.3"`, `TLS-Session-Cipher-Suite = "TLS_AES_256_GCM_SHA384"`, the proxy's client certificate `CN=usg-proxy`, requests for the RadSec realm received on 2083 and never on UDP 1812; the proxy's log shows `RadSec link established` with `group=Some(MLKEM1024)`; eapol_test's `MPPE keys OK: 1  mismatch: 0` proves the response-leg re-keying from `"radsec"` to the NAS secret, and the PAP Access-Accept / wrong-password Access-Reject prove the request-leg re-keying to `"radsec"` (FreeRADIUS requires Message-Authenticator on that client)

### ⚠️ Partial

- ⚠️ **Proxy inactive under inbound `transport = "radsec"`** (pre-existing): `main.rs` runs the RadSec accept loop and never constructs the proxy components, so RadSec-in → RadSec-out proxying is not available; the proxy, and with it the outbound link, run only when the NAS hop is `transport = "udp-insecure"`
- ⚠️ Stapled OCSP responses (RFC 6066 §8) on the home server's certificate are **ignored**; revocation is decided solely by `tls.revocation`
- ⚠️ With `crl.fetch = true` or any OCSP mode the revocation fetch runs blocking inside the TLS handshake on the link's worker; the effective handshake deadline is the home server's `timeout` plus the fetch timeout, and the worker is pinned for that long on every reconnect (same pattern as the inbound listener; static CRLs never block). `// TODO(gap)` in [crates/radius-server/src/server_verifier.rs](../../crates/radius-server/src/server_verifier.rs)
- ⚠️ No TCP keepalive or write timeout on the link: a half-dead peer is detected by the watchdog only (two unanswered probes: `2 × health_check.interval + health_check.timeout`), and a peer that stops reading while its socket stays alive stalls the link task until it resumes (the pool still fails over once probes mark the server Down)
- ⚠️ Accounting-Request is not proxied over either transport (pre-existing)

### ❌ Not Implemented

- ❌ **DTLS** (RFC 7360)
- ❌ TLS 1.1/1.2 and the mandatory-to-implement suite `TLS_RSA_WITH_3DES_EDE_CBC_SHA` of §2.2 (intentionally excluded by the FIPS/PQ posture, inbound and outbound alike); a peer that cannot negotiate TLS 1.3 + ML-KEM-1024 + AES-256-GCM-SHA384 does not connect
- ❌ Certificate hot-rotation (listener and outbound client certificates and CA bundles are loaded at startup; rotate via pod restart)
- ❌ Certificate pinning / fingerprint-based trust (§2.3 item 3 SHOULD) and TLS-PSK (§2.3 item 2 MAY), inbound and outbound; X.509 chains to a configured CA only
- ❌ Identifier rewriting on the upstream hop (see RFC 6613 below)

**Files**:

- [crates/radius-server/src/radsec.rs](../../crates/radius-server/src/radsec.rs) - Listener and connection loop
- [crates/radius-server/src/radsec_frame.rs](../../crates/radius-server/src/radsec_frame.rs) - `RADSEC_SECRET`, `take_frame` and the `Length` bounds, shared by the listener and the link
- [crates/radius-server/src/proxy/radsec_client.rs](../../crates/radius-server/src/proxy/radsec_client.rs) - Outbound link task (connect, FIPS gate, framing, demux, reconnect, CoA/Disconnect NAK)
- [crates/radius-server/src/proxy/home_server.rs](../../crates/radius-server/src/proxy/home_server.rs) - `HomeServerTransport`, `HomeServerTlsConfig` and validation
- [crates/radius-server/src/server_verifier.rs](../../crates/radius-server/src/server_verifier.rs) - Home-server certificate verifier (WebPKI + revocation)
- [crates/radius-server/src/config.rs](../../crates/radius-server/src/config.rs) - `Transport` and `RadSecConfig`

---

## RFC 6613 - RADIUS over TCP (as used by RadSec)

RFC 6613 is a normative reference of RFC 6614: RadSec connections are established and used "as per RFC 6613" (RFC 6614 §2.3 item 1) and receiver behaviour on bad frames is deferred to RFC 6613 §2.6.4 (RFC 6614 §3.4). usg-radius implements no plain RADIUS/TCP listener or client (RFC 6613 is Experimental and offers no security without TLS); the rules below apply to the RadSec connections.

### ✅ Implemented (outbound link; unreleased)

- ✅ **No retransmission over the same connection** (§2.6.1): the proxy cache records the link connection a request was written on; the retry manager resends a timed-out request only when the link is down or has moved to a new connection, and otherwise lets the deadline run to the signed Access-Reject after `retry.max_retries` ([crates/radius-server/src/proxy/retry.rs](../../crates/radius-server/src/proxy/retry.rs)). Modulo a reconnect racing the send: the connection generation is read just before the frame is queued, so a reconnect completing in that window can yield one extra copy on the new connection
- ✅ **Connection closed on protocol violations** (§2.6.4): bad `Length`, undecodable packet, failed Response Authenticator on a proxied response, failed Response Authenticator or Message-Authenticator on a watchdog reply; re-established with backoff. A response that matches no request (unknown Proxy-State, unknown probe Identifier) is discarded and the connection kept
- ✅ **Application-layer watchdog** (§2.4, §2.6; RFC 3539 §3.4; RFC 5997 §4.3): Status-Server is the watchdog message on every RadSec link, so `health_check.enabled = false` with a RadSec home server is a configuration error; two consecutive unanswered probes close the connection (RFC 3539 §3.4: not before the watchdog timer has expired twice) and the link reconnects. The miss counter is per home server, not per connection: after an outage the first missed probe on a fresh connection already resets it (earlier than RFC 3539 strictly requires, never later)
- ✅ **Identifier space per connection** (§2.6, §2.6.5): the link tracks the Identifiers in flight on the current connection (released by the matching reply, aged out after 60 s, cleared on reconnect); the probe never takes an Identifier already in flight, but a forwarded request arriving later may still carry the probe's Identifier because NAS Identifiers are not rewritten (the accepted gap below), so the reservation is one-directional; `max_outstanding ≤ 255` is enforced at config load for a RadSec home server (one connection carries at most 256 outstanding requests with one reserved for the watchdog)

### ⚠️ Partial

- ⚠️ **NAS Identifiers are forwarded unchanged** on the one connection (§2.6, §2.6.5 "proxies ... with several clients need Identifier management"): no Identifier rewriting on the upstream hop, exactly as on the UDP socket today. Two NASes using the same Identifier at the same time collide on the connection; the proxy correlates by Proxy-State, so only a home server that deduplicates on (connection, Identifier) is affected and may discard the older request (§2.6.1 "Servers SHOULD still perform duplicate detection"). Accepted gap for this release — `// TODO(gap)` in [crates/radius-server/src/proxy/radsec_client.rs](../../crates/radius-server/src/proxy/radsec_client.rs)
- ⚠️ §2.6.5 SHOULD reserve Identifier zero for Status-Server; the probe uses any free Identifier instead
- ⚠️ An Identifier the home server never answers stays in flight for 60 s (`identifier_ttl`), longer than the retry manager's reject; a home server that silently drops many requests can leave the watchdog no free Identifier, and a probe that finds none is skipped and counted as a miss (two in a row reset the connection, which clears the set) — availability only
- ⚠️ A write to a peer that stops reading (TCP window closed, socket alive) cannot be pre-empted by the watchdog reset: no write timeout and no TCP keepalive / `TCP_USER_TIMEOUT`; the health checker still marks the server Down and the pool fails over, the link itself recovers when the peer resumes or its TCP state disappears
- ⚠️ The inbound listener closes the connection on a bad `Length` only; an undecodable frame or a failed authenticator on an inbound request is dropped and the connection kept (pre-existing)

**Priority**: LOW (availability under Identifier collision; no authentication impact)

---

## Security Features

### ✅ Implemented

#### 1. Rate Limiting ✅ COMPLETE (v0.2.0)

**Status**: Production-ready with comprehensive DoS protection

**Features**:

- ✅ Per-client request rate limiting (token bucket algorithm)
- ✅ Global request rate limiting
- ✅ Configurable RPS and burst capacity
- ✅ Concurrent connection limits (100 per client default)
- ✅ Bandwidth throttling (1 MB/s per client default)
- ✅ Automatic cleanup and memory management
- ✅ Thread-safe concurrent tracking

**Protection Against**:

- ✅ Brute force attacks
- ✅ DoS attacks
- ✅ Request flooding
- ✅ Resource exhaustion
- ✅ Bandwidth exhaustion

---

#### 2. Request Deduplication ✅ COMPLETE (v0.1.1)

**Status**: Production-ready
**Implementation**: Comprehensive replay attack prevention

See Request Deduplication section under RFC 2865 for details.

---

#### 3. Audit Logging ✅ COMPLETE (v0.1.1+)

**Status**: Production-ready

**Features**:

- ✅ Structured logging (tracing framework)
- ✅ Audit trail with JSON output
- ✅ Failed authentication tracking
- ✅ Configurable log levels
- ✅ Event types:
  - Authentication attempts (success/failure)
  - Authorization decisions
  - Accounting events
  - Configuration changes
  - Security events

**Configuration**:

```json
{
  "log_level": "info",
  "audit_log_path": "/var/log/radius/audit.log"
}
```

Set `"audit_log_path": "stdout"` (or `"-"`) to emit JSON Lines on stdout for the Kubernetes log pipeline instead of a file.

---

#### 4. Authentication Backends ✅ COMPLETE

**Status**: Multiple backend support

**Implemented**:

- ✅ Simple in-memory handler (for testing)
- ✅ LDAP/Active Directory integration
- ✅ PostgreSQL database backend
- ✅ EAP-TLS certificate-based authentication

**Files**:

- [crates/radius-server/src/ldap_auth.rs](../../crates/radius-server/src/ldap_auth.rs) - LDAP backend
- [crates/radius-server/src/postgres_auth.rs](../../crates/radius-server/src/postgres_auth.rs) - PostgreSQL backend

---

### ⚠️ Partial Implementation

#### Certificate Revocation (CRL/OCSP) ✅ INTEGRATED

**Status**: ✅ Wired into EAP-TLS and RadSec client-certificate verification (v0.12.0) and into the proxy's verification of RadSec home-server certificates (unreleased)
**RFC**: RFC 5280 (CRL), RFC 6960 (OCSP), RFC 8954 (OCSP nonce)

**Implemented** (`revocation` cargo feature of `radius-server`, which enables `radius-proto`'s; built into the container image, the release binary and the interop image):

- ✅ `revocation` config block under `eap.tls` (supplicant certificates), under `radsec` (NAS client certificates) and under `proxy.pools[].servers[].tls` (RadSec home-server certificates, checked by the proxy as a TLS client): `mode` (`crl_only` default, `ocsp_only`, `prefer_ocsp`, `both`), `on_error` (`fail_closed` default, `fail_open`), `crl.static_files`, `crl.fetch` + timeout/TTL/cache/size limits, `ocsp` timeout/TTL/cache/nonce/size limits. Validated at startup; a binary without the feature rejects a config that asks for it.
- ✅ The rustls `WebPkiClientVerifier` of each listener is wrapped in `RevocationCheckingVerifier` when the block is present (chain validation first, then revocation); without the block the plain verifier is used unchanged. On the outbound RadSec link the same chain check (`RevocationCheckingVerifier::check_chain`, with the CA bundle as anchors and the link provider's signature algorithms) runs behind rustls's `WebPkiServerVerifier` (chain, validity, `server_name`, then revocation), so the home server's certificate gets the same CRL/OCSP signature verification, crlNumber tracking and whole-chain check; a stapled OCSP response is not consulted
- ✅ Static CRL files (PEM/DER) loaded at startup and matched to the certificate's issuer; CRL Distribution Points fetched over HTTP(S) with TTL cache when enabled; `thisUpdate`/`nextUpdate` freshness enforced
- ✅ **Chain**: after WebPKI validation the verifier links the end-entity certificate through the peer's intermediates to a self-issued certificate in `ca_path`, each step by issuer Name *and* signature (an intermediate the peer made up cannot stand in for the real one), and checks **every certificate except the trust anchor** against its own issuer — intermediates as well as the end entity. Peer intermediates count only if they are CA certificates (basicConstraints cA) valid at the time — WebPKI's own criteria — so an expired twin cannot hide a revoked one; certificates in `ca_path` are trusted as configured, like WebPKI's anchors. When more than one path links through intermediates (a renewal under the same Name and key, cross-certificates), every such path is checked and any revoked link rejects, whatever the peer's ordering (a node that links directly to a self-issued anchor is not extended further; see Limitations). Path building is budgeted because the peer controls the intermediates: each certificate is parsed once, each (certificate, issuer) signature verified at most once, and more than 64 signature verifications, 32 path extensions or 8 complete paths rejects the handshake regardless of `on_error`. An issuing CA placed in `ca_path` next to its root is linked to the root and checked like an intermediate; a path that cannot reach a self-issued anchor ends at the furthest configured certificate on it (so a peer appending its root behind a configured issuing CA changes nothing)
- ✅ **CRL signatures (RFC 5280 §6.3.3)**: a CRL — static file or Distribution Point alike — is used only if its issuer Name equals the issuing CA's subject, the CA's keyUsage (when present) asserts cRLSign (§4.2.1.3), TBSCertList.signature equals signatureAlgorithm (§5.1.1.2), and the signature verifies with the CA's public key. Unsigned, wrongly signed or tampered CRLs are unusable and the fail policy applies (rejected under the default `fail_closed`). Verification uses the rustls `CryptoProvider`'s signature algorithms (aws-lc-rs; the listener's FIPS provider for RadSec), no second crypto implementation
- ✅ **crlNumber (RFC 5280 §5.2.3)** tracked per issuer (Name and verifying key): a CRL with a lower crlNumber than one already accepted for that issuer (or none, after a numbered one) is refused, so an older still-unexpired CRL cannot be replayed to hide a later revocation; of several static files for one issuer the highest crlNumber is consulted first
- ✅ CRLs that cannot be processed correctly are rejected rather than misread: delta CRLs, Issuing Distribution Point (partitioned/indirect) CRLs, and unrecognized critical CRL or CRL entry extensions (§5.2, §5.3). A CRL without nextUpdate is refused (conforming issuers MUST include it, §5.1.2.5), so an old CRL cannot be current forever
- ✅ OCSP request per RFC 6960 §4.1.1 (SHA-256 CertID; issuer taken from the linked chain), byte-identical to `openssl ocsp -sha256` (known-answer test), 32-octet RFC 8954 nonce (§2.1; RFC 9654 keeps the length), response cache keyed by the full CertID and bounded by both `nextUpdate` and `ocsp.cache_ttl_secs`
- ✅ **OCSP response verification (RFC 6960 §3.2, §4.2.2.2)**: the response must be a BasicOCSPResponse with a SingleResponse for exactly the requested CertID; its signature must verify with the issuing CA's key, or with the key of a delegated responder certificate (from the response's `certs`) that the CA issued directly, that carries id-kp-OCSPSigning, whose keyUsage (if present) permits signing, that carries no unrecognized critical extension, and that is within its validity period; ResponderID byName must name the signer. id-pkix-ocsp-nocheck is honoured for the responder certificate only; without it the responder certificate is checked against the CA's CRL (modes with a CRL source) or the response is unusable (`ocsp_only`). thisUpdate may lead the local clock by at most 5 minutes; nextUpdate must not have passed, and a response without nextUpdate must have a thisUpdate no older than `ocsp.cache_ttl_secs` (§3.2 item 5, "sufficiently recent"), on first use and again on every cache hit, so a recorded response without a nonce cannot be replayed indefinitely. Unrecognized critical response or single extensions are refused (§4.4); an explicitly encoded `critical FALSE` is tolerated. A certificate in `certs` that made the signature but is not authorized only disqualifies itself (`certs` is unsigned), so an expired copy listed first does not mask the current responder certificate. Error responses (unsigned per §2.3) are never treated as an answer
- ✅ CRL and OCSP HTTP fetches read at most the configured size limit (the body is never buffered whole first) and do not follow redirects
- ✅ Fail-closed by default: an undeterminable status (no source covers the issuer, fetch/parse/freshness error, responder unreachable) rejects the client; `fail_open` accepts and logs. A positive "revoked" always rejects
- ✅ Access-Rejects that end an EAP conversation carry EAP-Failure (RFC 3579 §2.6.3), so a revoked supplicant fails promptly rather than by timeout
- ✅ Tests: config parsing/validation, verifier selection, static-CRL rejection with an rcgen-generated CRL (EAP-TLS verifier and RadSec listener); rcgen fixtures for a signed CRL accepted (ECDSA P-256, P-384, Ed25519), a CRL signed by the wrong key / tampered / from an issuer without cRLSign / with a mismatched signatureAlgorithm rejected, delta, IDP and unrecognized-critical-extension CRLs rejected, stale or missing crlNumber rejected, a revoked intermediate rejected (also behind an expired same-key twin, on either of two same-key paths in either order and under fail-open, and as an issuing CA in the bundle), a peer-appended root behind a configured issuing CA ignored, an expired configured issuing CA still anchoring, a peer intermediate without keyCertSign linked as WebPKI does, chain padding (complete paths, and dead-end certificates exhausting the signature budget) rejected under fail-open, a made-up intermediate refused, OCSP responses signed by the CA and by a delegated responder accepted, a responder without the EKU, an unrelated key and an impostor CA's responder rejected, responders with a non-signing keyUsage, outside their validity or with an unknown critical extension rejected, an expired copy of the responder certificate not masking the current one, CertID, ResponderID, nonce, future-thisUpdate, max-age (overflow-safe) and unknown-critical-extension cases; the bounded HTTP body reader; OpenSSL-generated known-answer fixtures (OCSP request bytes; ECDSA CA-signed, delegated-responder-signed and revoked responses; RSA PKCS#1 v1.5 and PSS responses and CRLs); and the interop harness (revoked `revoked@usg.test` fails with EAP-Failure, valid `eaptls@usg.test` succeeds, both directly and through the proxy; the valid certificate is rejected by a server whose static CRL names the CA but is signed by another key, and that server's log shows the signature failure as the reason; FreeRADIUS/eapol_test, OpenSSL-issued CRLs)

**Limitations**:

- ⚠️ CRL/OCSP fetches block the TLS handshake for up to the configured timeout (default 5 s); size the timeout against the NAS's RADIUS timeout. On the outbound RadSec link the fetch runs on the link task's worker on every (re)connect and the home server's `timeout` cannot pre-empt it, so the effective handshake deadline is `timeout` + fetch timeout; static CRLs never block
- ⚠️ No delta CRLs and no Issuing Distribution Point (partitioned or indirect) CRLs: such CRLs are rejected (fail policy applies), so a CA that publishes only those needs OCSP. CRL signers other than the certificate's issuer (indirect CRLs, §6.3.3 (b)) are not supported
- ⚠️ Because intermediates are checked too, every CA below the trust anchor needs a CRL (static or Distribution Point) or an OCSP responder in the configured mode; a chain that cannot be linked to `ca_path` is undeterminable (rejected under `fail_closed`)
- ⚠️ ResponderID byKey (a SHA-1 key hash) is not compared; the signer is identified by signature verification against the CA and the response's `certs`. A locally configured OCSP signing authority (§4.2.2.2 item 1) is not supported
- ⚠️ CertIDs are SHA-256 only: a responder that answers only SHA-1 CertIDs (the RFC 5019 lightweight profile) yields no usable answer (fail policy applies). The CertID hash uses RustCrypto `sha2`, not aws-lc; signatures use the rustls provider
- ⚠️ A responder that does not echo the nonce is accepted (bounded by nextUpdate, or by `ocsp.cache_ttl_secs` without one); there is no switch to require the echo
- ⚠️ Path-building gaps (fix loop capped; open decisions): (1) a certificate that links directly to a self-issued anchor in `ca_path` is not also extended through other issuers, so a revoked cross-certificate the peer sends next to such an anchor — one WebPKI may validate through, e.g. when the anchor's name constraints fail — is not checked; (2) configured certificates count toward the 8-path / 32-extension budget, so a `ca_path` bundle with nine or more same-key versions of a CA, or a bridge-style (FPKI-like) bundle with three or more cross-certificate tiers, exceeds it and every handshake through it is rejected regardless of `on_error`. Keep `ca_path` to the roots (and issuing CAs) actually in use
- ⚠️ crlNumber state lives in memory: it is reset on restart, and an older CRL accepted first is superseded only once a newer one is seen
- ⚠️ Static CRL files are read once at startup (no hot reload)

**Files**:

- [crates/radius-proto/src/revocation/](../../crates/radius-proto/src/revocation/) - CRL/OCSP module and `RevocationCheckingVerifier`
- [crates/radius-server/src/client_verifier.rs](../../crates/radius-server/src/client_verifier.rs) - verifier selection for EAP-TLS and RadSec
- [crates/radius-server/src/server_verifier.rs](../../crates/radius-server/src/server_verifier.rs) - verifier selection for RadSec home-server certificates (outbound link)
- [crates/radius-server/src/config.rs](../../crates/radius-server/src/config.rs) - `RevocationConfig` and validation
- [examples/configs/eap-tls-revocation.json](../../examples/configs/eap-tls-revocation.json) - documented example
- [docs/docs/development/CRL-IMPLEMENTATION-PLAN.md](../development/CRL-IMPLEMENTATION-PLAN.md) - Design notes

---

#### Authenticator Validation

**Status**: Basic validation only
**Current**: Request Authenticator validated for length
**Missing**: Randomness quality checks
**Priority**: LOW

---

#### Maximum Packet Size Enforcement

**Status**: Enforced in encode, could be improved in decode
**RFC 2865**: 4096 bytes maximum
**Priority**: LOW

---

### ❌ Not Implemented

#### Packet Source Port Validation

**RFC 2865**: Should validate source port (usually 1645/1812 for clients)
**Current**: Accepts from any port
**Priority**: LOW (most deployments don't require this)

---

## Configuration & Management

### ✅ Implemented

**Configuration**:

- ✅ JSON configuration file
- ✅ Environment variable support for secrets
- ✅ Configuration validation on startup
- ✅ Per-client configuration
- ✅ Client CIDR network validation
- ✅ Feature flags (TLS, accounting, etc.)

**Management**:

- ✅ Structured logging with tracing
- ✅ Audit logging
- ✅ Statistics and monitoring
- ✅ Cache statistics
- ✅ Rate limit statistics
- ✅ Accounting reports and exports

---

### ❌ Not Implemented

#### Hot Reload Configuration (SIGHUP)

**Status**: Deferred to future release
**Priority**: MEDIUM
**Impact**: Requires server restart for configuration changes
**Note**: Since v0.9.0 `SIGHUP` reloads only the management API access policy (`mgmt.access_policy_file`); clients, secrets, and transport settings still require a restart.

---

#### Secret Rotation

**Status**: Not implemented
**Priority**: MEDIUM
**Workaround**: Update config and restart server

---

## Attribute Handling

### ✅ Implemented

- ✅ All standard attributes (Types 1-80+)
- ✅ EAP-Message (Type 79)
- ✅ Message-Authenticator (Type 80)
- ✅ Accounting attributes (Types 40-47)
- ✅ Attribute encoding/decoding
- ✅ Length validation

---

### ❌ Not Implemented

#### 1. Vendor-Specific Attributes (Type 26)

**Status**: Sub-attribute codec implemented (`radius_proto::attributes::VendorSpecific`:
Vendor-Id + vendor-type/vendor-length TLVs, RFC 2865 §5.26), used for the RFC 2548
MS-MPPE keys
**Priority**: MEDIUM
**Missing**: Vendor dictionaries / named vendor attributes in policy reply attributes

---

#### 2. Strict Attribute Validation ⚠️ MOSTLY IMPLEMENTED

**Priority**: LOW
**Implemented** (`crates/radius-proto/src/validation.rs`):

- ✅ Enumerated value validation (Service-Type, Framed-Protocol, Framed-Routing, Framed-Compression, Login-Service, Termination-Action) in strict mode; Acct-Status-Type presence required on Accounting-Request
- ✅ Length checks for integer (4 bytes) and IPv4 address (4 bytes) attributes
- ✅ String attribute validation

**Missing**:

- ❌ Range checks on non-enumerated integers (e.g. Session-Timeout bounds)
- ❌ Cross-attribute consistency beyond the password/EAP mutual-exclusion rules

---

#### 3. Required Attributes Enforcement ✅ IMPLEMENTED

**Priority**: -
**Enforced** for Access-Request in both validation modes:

- ✅ User-Name required
- ✅ Exactly one of User-Password or CHAP-Password, or EAP-Message with neither (RFC 3579 §3.1)
- ✅ NAS-IP-Address or NAS-Identifier required
- ✅ Message-Authenticator required when EAP-Message is present (RFC 3579 §3.2)

---

## Testing

### ✅ Implemented

**Test Coverage**:

- ✅ 78+ test suites (72 passing, 6 integration tests requiring setup)
- ✅ Comprehensive unit tests
- ✅ Integration tests for accounting
- ✅ EAP-TLS test coverage (84 tests)
- ✅ Rate limiting tests (25 tests)
- ✅ Cache tests
- ✅ Configuration validation tests

**Test Results**:

```
radius-proto:   84 tests passing (EAP-TLS)
radius-server:  72 tests passing (server functionality)
Total:         156+ tests
```

---

### ⚠️ Partial Testing

**Areas with Limited Coverage**:

- Malformed packet handling (basic tests present)
- Load testing (manual testing only)
- Interoperability testing (tested with wpa_supplicant, eapol_test)

---

## Documentation

### ✅ Implemented

**Comprehensive Documentation**:

- ✅ Protocol guides (EAP-TLS, Accounting, etc.)
- ✅ Usage examples (600+ lines for EAP-TLS alone)
- ✅ API reference documentation
- ✅ Configuration examples
- ✅ Certificate generation guides
- ✅ Troubleshooting guides
- ✅ Development roadmap
- ✅ RFC compliance analysis (this document)

**Files**:

- [docs/docs/protocol/](../protocol/) - Protocol documentation
- [docs/docs/examples/](../examples/) - Usage examples
- [docs/docs/api/](../api/) - API reference
- [docs/docs/development/](../development/) - Development guides

---

## Implementation Status Summary

### Priority 1 (CRITICAL) - ✅ COMPLETE

1. ✅ **Client Validation** (v0.1.1) - Per-client secrets and IP validation
2. ✅ **Rate Limiting** (v0.2.0) - Request rate limiting and DoS protection
3. ✅ **Duplicate Detection** (v0.1.1) - Replay attack prevention
4. ✅ **Structured Logging** (v0.1.1+) - tracing framework with audit logging
5. ✅ **Concurrent Connection Limits** (v0.2.0) - Per-client connection tracking
6. ✅ **Bandwidth Throttling** (v0.2.0) - Per-client bandwidth limits

### Priority 2 (HIGH) - ✅ MOSTLY COMPLETE

1. ✅ **EAP Support** (v0.5.0) - EAP-TLS production-ready
2. ✅ **Accounting** (v0.3.0-v0.4.0) - Full accounting with database backend
3. ✅ **Access-Challenge** (v0.5.0) - Multi-round authentication for EAP
4. ✅ **Authentication Backends** - LDAP, PostgreSQL, EAP-TLS
5. ✅ **CHAP Support** (v0.3.0) - Challenge/response with CHAP-Challenge fallback to the Request Authenticator
6. ✅ **Message-Authenticator** (v0.3.0, required on EAP since v0.10.0) - HMAC-MD5 verification and generation
7. ✅ **RadSec** (v0.10.0; outbound unreleased) - TLS 1.3 / ML-KEM-1024 mutual-TLS transport, default for config files; the proxy reaches `transport = "radsec"` home servers over one persistent connection each, watched by Status-Server per RFC 6613
8. ✅ **CoA/Disconnect** (v0.10.0) - Server-originated over RadSec via the management API

### Priority 3 (MEDIUM) - ⚠️ PARTIAL

1. ✅ **EAP-TLS** (v0.5.0) - Complete
2. ✅ **EAP-TEAP** (RFC 9930; v0.7.x Phase 1+2, completion and interop
   v0.13.0) - Phase 1 tunnel and Phase 2 TLV protocol through the RADIUS
   handler: §3.3 fragmentation in both phases and directions, §3.1 version
   negotiation, §4.2.13 Crypto-Binding TLV with §6.3 Compound-MACs over the
   BUFFER, §6.2 / §6.4 key schedule with the negotiated cipher suite's hash,
   §3.6.6 protected termination with Intermediate-Result + Result +
   Crypto-Binding, RFC 3748 §5.3.1 EAP-Nak method switching. Interoperable
   with wpa_supplicant 2.12 (`eapol_test`, TLS 1.3 and TLS 1.2, direct and
   through the proxy, MS-MPPE keys matching). Inner methods producing real
   keying material (e.g. EAP-MSCHAPv2) are still pending; current inner
   methods (Basic-Password-Auth, EAP-MD5) use the zero IMSK of §6.2.1. Basic-Password-Auth fails closed
   (no stored password, empty password → Result=Failure; constant-time
   comparison), Phase 2 rounds are bounded, and TEAP is off by default
   (`eap.enable_teap`).
3. ⚠️ **Proxy-State** - Echoed in responses; ordering covered by a
   regression test on the Status-Server path only (Access-Accept/Reject
   ordering tests pending)
4. ❌ **Hot Configuration Reload** - Deferred (only the mgmt access policy reloads on SIGHUP)
5. ✅ **Health Monitoring** - Status-Server per RFC 5997 (Message-Authenticator required and verified, reply code by port, Proxy-State echoed, proxy answers locally) and conformant home-server probes (v0.13.0); replies are not tied to backend health
6. ✅ **Certificate Revocation (CRL/OCSP)** - CRL (static files + Distribution Points) and OCSP checking of EAP-TLS supplicant and RadSec NAS certificates via the `revocation` block, fail-closed by default (v0.12.0); CRL signatures (RFC 5280 §6.3.3), crlNumber monotonicity, OCSP response signatures and responder authorization (RFC 6960 §3.2, §4.2.2.2) verified, intermediates checked (unreleased)
7. ✅ **MS-MPPE Keys** - MS-MPPE-Send/Recv-Key (RFC 2548 §2.4) attached to EAP Access-Accepts (v0.11.0)

### Priority 4 (LOW) - ❌ NOT PLANNED

1. ⚠️ **Vendor Attributes** - Type 26 codec and RFC 2548 MS-MPPE keys implemented; vendor dictionaries not prioritized
2. ⚠️ **Tunnel Attributes** - Tunnel-Password (69) codec + proxy re-encryption only; the rest is a future enhancement
3. ❌ **CoA/Disconnect over UDP** - Only the RadSec path shipped (v0.10.0)
4. ❌ **DTLS (RFC 7360)** - Not planned; RadSec is TLS-only
5. ✅ **Accounting on a dedicated 1813 socket** - `accounting_port` (integer, default 1813 | `"shared"` | `"disabled"`); Accounting-Response from source port 1813 (v0.13.0)

---

## Compliance Summary Matrix

| Feature | RFC | Status | Version | Priority | Notes |
|---------|-----|--------|---------|----------|-------|
| Basic Auth (PAP) | 2865 | ✅ Complete | v0.1.0 | - | Core functionality |
| Client Validation | 2865 | ✅ Complete | v0.1.1 | CRITICAL | Production-ready |
| Per-Client Secrets | 2865 | ✅ Complete | v0.1.1 | CRITICAL | Security requirement |
| Request Deduplication | 2865 | ✅ Complete | v0.1.1 | HIGH | Replay protection |
| Access-Challenge | 2865 | ✅ Complete | v0.5.0 | HIGH | For EAP |
| Rate Limiting | - | ✅ Complete | v0.2.0 | CRITICAL | DoS protection |
| Concurrent Limits | - | ✅ Complete | v0.2.0 | CRITICAL | Resource protection |
| Bandwidth Throttling | - | ✅ Complete | v0.2.0 | CRITICAL | Bandwidth protection |
| Accounting | 2866 | ✅ Complete | v0.3.0 | HIGH | Session tracking |
| EAP-TLS | 5216 | ✅ Complete | v0.5.0 | HIGH | Modern auth |
| EAP-TLS over TLS 1.3 keys | 9190 | ✅ Complete | v0.11.0 | HIGH | Exporter labels, §2.5 commitment message, EAP-Key-Name; verified against eapol_test |
| MS-MPPE-Send/Recv-Key | 2548 | ✅ Complete | v0.11.0 | HIGH | Required for the 802.11i 4-way handshake |
| Vendor-Specific codec | 2865 §5.26 | ✅ Complete | v0.11.0 | MEDIUM | Sub-attribute encode/decode; no dictionaries |
| Tunnel-Password | 2868 §3.5 | ⚠️ Codec + proxy re-key | v0.11.0 | LOW | Other tunnel attributes not interpreted |
| EAP Framework | 3748 | ✅ Complete | v0.5.0 | HIGH | Infrastructure |
| Audit Logging | - | ✅ Complete | v0.1.1+ | HIGH | Compliance |
| LDAP Backend | - | ✅ Complete | - | MEDIUM | Enterprise auth |
| PostgreSQL Backend | - | ✅ Complete | - | MEDIUM | Database auth |
| Status-Server | 5997 | ✅ Complete | v0.13.0 | LOW | Message-Authenticator required and verified, Access-Accept / Accounting-Response by port, Proxy-State echoed, proxy answers locally, probes conformant; reply not tied to backend health, no enable/disable switch |
| CHAP | 2865 | ✅ Complete | v0.3.0 | LOW | CHAP-Challenge or Request Authenticator |
| Message-Authenticator | 2869 / 3579 | ✅ Complete | v0.3.0 / v0.10.0 | HIGH | Required on EAP requests since v0.10.0 |
| RadSec | 6614 | ✅ Complete | v0.10.0 (inbound) / unreleased (outbound) | HIGH | TLS 1.3 + ML-KEM-1024 mTLS, inbound listener and proxy → home-server link (per home server `transport = "radsec"`, fixed `"radsec"` secret, home-server certificate revocation); no DTLS, no certificate pinning/PSK; proxy inactive under an inbound RadSec listener |
| RADIUS over TCP rules | 6613 | ⚠️ On RadSec links | unreleased | LOW | No retransmission on a connection, close on protocol violation, Status-Server watchdog, Identifier tracking + `max_outstanding ≤ 255`; NAS Identifiers forwarded unchanged (no rewriting on the upstream hop) |
| CoA/Disconnect | 5176 | ✅ RadSec only | v0.10.0 | MEDIUM | Server-originated via mgmt API; no UDP path |
| NAS Identification | 2865 | ✅ Complete | v0.2.0 | MEDIUM | NAS-IP-Address or NAS-Identifier enforced |
| Enumerated Values | 2865 | ✅ Strict mode | v0.2.0 | LOW | Lenient mode accepts unknown values |
| Certificate Revocation | 5280 / 6960 / 8954 | ✅ Integrated | v0.7.x / v0.12.0 / unreleased | HIGH | `revocation` block for EAP-TLS, the RadSec listener and (unreleased) RadSec home servers, fail-closed default; CRL and OCSP signatures verified against the issuing CA (delegated responders need id-kp-OCSPSigning), crlNumber tracked, whole chain checked; no delta / IDP CRLs; stapled OCSP ignored |
| Accounting Port 1813 | 2866 | ✅ Bound | v0.13.0 | - | `accounting_port`: 1813 (default) / `"shared"` / `"disabled"`; replies from 1813; wrong-port codes discarded |
| Proxy-State | 2865 | ⚠️ Echoed | v0.x | MEDIUM | Ordering test on the Status-Server path; Access-Accept/Reject ordering tests pending |
| Hot Reload | - | ❌ Deferred | - | MEDIUM | Only mgmt access policy reloads on SIGHUP |
| EAP-TEAP | 9930 (obsoletes 7170) | ✅ Basic-Password-Auth, off by default | v0.7.x / v0.13.0 | MEDIUM | §4.2.13 Crypto-Binding TLV, §6.2–§6.4 key schedule (KATs + eapol_test interop over TLS 1.3 and 1.2, direct and via proxy), §3.3 fragmentation both ways (L only on fragmented messages), §3.6.6 protected termination, EAP-Nak switching; Basic-Password-Auth fails closed, Phase 2 rounds bounded; inner methods with real IMSK pending |

---

## Production Readiness

The current implementation is **PRODUCTION-READY** for:

### ✅ Fully Supported Use Cases

1. **Enterprise WiFi (802.1X with EAP-TLS)**
   - Certificate-based authentication
   - WPA2/WPA3 Enterprise
   - Mutual TLS authentication
   - ✅ MS-MPPE-Send/Recv-Key delivered on the Access-Accept for the 4-way handshake (v0.11.0)

2. **VPN Authentication with EAP-TLS**
   - Certificate-based VPN access
   - Mutual authentication
   - Strong cryptographic binding

3. **Modern Wireless Networks**
   - 802.1X port-based authentication
   - RadSec (RFC 6614) transport between NAS and server, and from the proxy to its home servers
   - Server-originated CoA/Disconnect (RFC 5176) over RadSec
   - RADIUS accounting for usage tracking

4. **High-Security Environments**
   - DoS protection with rate limiting
   - Concurrent connection limits
   - Bandwidth throttling
   - Comprehensive audit logging
   - Replay attack prevention

5. **Multi-Tenant Deployments**
   - Per-client rate limits
   - Per-client secrets
   - Client isolation
   - Resource protection

---

### ⚠️ Partially Supported Use Cases

1. **RADIUS Proxy**
   - Basic forwarding works
   - Request leg re-encrypts User-Password (RFC 2865 §5.2) from the client
     secret to the home server secret and recomputes Message-Authenticator
     (RFC 3579 §3.2) under the home server secret over the packet including the
     appended Proxy-State; the Request Authenticator is forwarded unchanged
     (RFC 2865 §2.3) and CHAP-Password, bound to the challenge rather than the
     secret, is relayed as is
   - Response leg verifies the home server's Response Authenticator, re-encrypts
     RFC 2548 MS-MPPE-Send/Recv-Key and RFC 2868 §3.5 Tunnel-Password (Tag
     preserved, fresh per-packet-unique salts) from the home server secret to
     the client secret, dropping any that fail to decrypt, and recomputes
     Message-Authenticator / Response Authenticator for the NAS
     ([crates/radius-server/src/proxy/handler.rs](../../crates/radius-server/src/proxy/handler.rs))
   - Relayed responses and timeout Access-Rejects are sent from the server's
     listening socket (the port the NAS sent to), so `connect()`ed NAS sockets
     accept them; interop-tested against FreeRADIUS + eapol_test with a
     different secret on each hop (`tests/interop/run.sh`)
   - Proxy-State echoed; multi-Proxy-State ordering regression tests pending
   - Hot reload not available
   - Upstream leg is UDP or RadSec per home server (`transport = "radsec"`
     with a `tls` block, fixed `"radsec"` hop secret, one persistent
     TLS 1.3 / ML-KEM-1024 connection, Status-Server watchdog per RFC 6613,
     no UDP fallback; interop scenario 17 against FreeRADIUS over RadSec)
   - The proxy runs only when the NAS hop is `transport = "udp-insecure"`;
     under an inbound RadSec listener the proxy components are not started
   - NAS Identifiers are forwarded unchanged on the upstream hop (UDP socket
     or RadSec connection): two NASes using the same Identifier at the same
     time collide at a home server that deduplicates on Identifier
     (RFC 6613 §2.6 gap)
   - Accounting-Request is not proxied

2. **Legacy Authentication**
   - PAP and CHAP supported
   - EAP-MD5 supported as an EAP-TEAP inner method only

3. **Dynamic Authorization (CoA/Disconnect)**
   - Server-originated over RadSec only; no UDP (port 3799) path

4. **Certificate Revocation**
   - No delta or Issuing Distribution Point CRLs; fetches block the handshake for up to the configured timeout

---

### ❌ Not Supported Use Cases

1. **Legacy EAP Methods**
   - EAP-TTLS, PEAP, EAP-MSCHAPv2 not implemented
   - Use EAP-TLS or EAP-TEAP

2. **RADIUS over DTLS (RFC 7360)**
   - Not implemented; RadSec is TLS 1.3 only

---

## Security Posture

### ✅ Strong Security Features

1. **Authentication Security**
   - ✅ Certificate-based authentication (EAP-TLS)
   - ✅ Mutual TLS with client verification
   - ✅ Strong key derivation (RFC 5705)
   - ✅ Cryptographic session binding
   - ✅ Message-Authenticator required on EAP requests (Blast-RADIUS mitigation)
   - ✅ RadSec transport: TLS 1.3, ML-KEM-1024, mutually authenticated — NAS → server and proxy → home server; the outbound link never falls back to UDP

2. **DoS Protection**
   - ✅ Per-client rate limiting
   - ✅ Global rate limiting
   - ✅ Concurrent connection limits
   - ✅ Bandwidth throttling
   - ✅ Request deduplication

3. **Access Control**
   - ✅ Client IP/CIDR validation
   - ✅ Per-client shared secrets
   - ✅ Client enable/disable flags

4. **Audit & Compliance**
   - ✅ Comprehensive audit logging
   - ✅ Failed authentication tracking
   - ✅ Structured logging
   - ✅ Accounting with retention policies

---

### ⚠️ Security Considerations

1. **Configuration Management**
   - ⚠️ No hot reload (requires restart for config changes)
   - ⚠️ No automated secret rotation
   - ✅ Environment variable support for secrets

2. **Protocol Validation**
   - ⚠️ Non-enumerated integer ranges not validated
   - ⚠️ Randomness quality not validated
   - ✅ Status-Server Message-Authenticator required and verified; unsigned probes get no reply (RFC 5997 §4.1)
   - ✅ Required attributes and enumerations validated (strict mode)

3. **Certificate Lifecycle**
   - ✅ CRL/OCSP revocation checking of supplicant, NAS and RadSec home-server certificates at handshake time (`revocation` block, fail-closed default)
   - ✅ CRL and OCSP response signatures verified against the issuing CA (RFC 5280 §6.3.3, RFC 6960 §3.2), delegated OCSP responders must carry id-kp-OCSPSigning, crlNumber rollback refused, intermediates checked as well as the end entity — for the inbound listeners and the outbound RadSec link alike (same module)
   - ⚠️ Static CRL files read once at startup; crlNumber state not persisted across restarts; stapled OCSP on a home-server certificate ignored
   - ⚠️ CRL Distribution Point / OCSP fetches block the TLS handshake on the worker that runs it (listener and outbound link alike); size the fetch timeout against the home server's `timeout`
   - ⚠️ No certificate hot-rotation for RadSec (listener or outbound client certificate) or EAP-TLS

4. **Proxy Upstream Hop**
   - ✅ RadSec home servers: mutual X.509 authentication, chain + `server_name` validation, parameters re-checked after the handshake, resumption disabled, fail closed with no UDP fallback; responses attributed by the authenticated connection, never by source address; connection closed on a failed Response Authenticator or Message-Authenticator (RFC 6613 §2.6.4)
   - ⚠️ The fixed `"radsec"` secret authenticates nothing on that hop: anyone on the TLS connection is the home server, which is why the link must never fall back and why `secret` is rejected on a RadSec home server
   - ⚠️ NAS Identifiers forwarded unchanged on one connection (availability under collision, RFC 6613 §2.6; correlation by Proxy-State is unaffected)

5. **EAP Resource Exhaustion**
   - ✅ Inbound EAP-TLS / EAP-TEAP fragment reassembly bounded at 64 KiB per conversation, L required on the first fragment, overrun and empty non-final fragments rejected, fail closed
   - ✅ EAP session store bounded: idle timeout (default 120 s) and LRU cap (default 4096) on conversations and their TLS state, released on Accept/Reject; evicted conversations fail closed; `radius_eap_sessions_evicted_total` counter
   - ✅ EAP-TEAP Phase 2 bounded per conversation (32 rounds, repeated Identity-Type TLV rejected), fail closed; a rejected packet never refreshes a session's LRU position
   - ⚠️ Capacity eviction is LRU, so a peer within the rate limits can still displace in-progress conversations once the cap is reached; size `eap.max_sessions` and the rate limits together
   - ✅ EAP-TEAP Crypto-Binding (RFC 9930 §4.2.13 / §6.3) verified before any Result is examined, fail closed on an invalid binding, nonce, version or Flags, and the MSK released only after a verified binding and both Results Success; version negotiation and EAP-Nak switching bounded to one renegotiation per conversation
   - ⚠️ EAP-TEAP with Basic-Password-Auth binds the inner method with the zero IMSK of RFC 9930 §6.2.1: the password is protected by the server-authenticated tunnel only, which the RFC marks NOT RECOMMENDED without a key-deriving inner method; supplicants must validate the server certificate (`ca_cert` / `domain_match`)
   - ⚠️ An Access-Request without EAP-Message (which therefore needs no Message-Authenticator) still starts an EAP conversation, so a spoofer of a client address can allocate sessions and push live ones toward LRU eviction within the rate limits (pre-existing)
   - ✅ The proxy verifies the NAS's Message-Authenticator before routing (unreleased): an EAP Access-Request with a missing or invalid one is no longer forwarded re-signed under the home secret (RFC 3579 §3.2)
   - ✅ EAP conversations are named by a 16-octet CSPRNG State bound to the NAS (client address, NAS-IP-Address / NAS-IPv6-Address / NAS-Identifier) and the User-Name; a State from anyone else is rejected without touching the conversation, an Identity Response never resumes or restarts one, and EAP-Responses must answer the outstanding Request's Identifier (others silently discarded, RFC 3748 §4.1); NAS retransmissions get the cached reply (RFC 5080 §2.2.2)

6. **EAP-TEAP Inner Authentication**
   - ✅ Basic-Password-Auth fails closed: no stored password, empty stored password or empty supplied password → Result=Failure inside the tunnel and Access-Reject; constant-time password comparison. An unreleased build (after v0.12.0, before v0.13.0) accepted an empty password for any user without a stored password
   - ⚠️ Basic-Password-Auth needs the inner handler to supply the user's cleartext password (`get_user_password`): only the in-memory `users` list does; the PostgreSQL and LDAP handlers reject every TEAP authentication. `eap.enable_teap` therefore defaults to `false`
   - ⚠️ Inner methods with real keying material (EAP-MSCHAPv2, inner EAP-TLS) pending; current inner methods use the zero IMSK of RFC 9930 §6.2.1

---

## Conclusion

### Current Status: PRODUCTION-READY ✅

The USG RADIUS server is **production-ready** for modern enterprise deployments with:

**Strengths**:

1. ✅ **Complete EAP-TLS implementation** - Industry-standard certificate authentication with MS-MPPE key delivery
2. ✅ **RadSec transport and CoA/Disconnect** - TLS 1.3 / ML-KEM-1024 mutual TLS with server-originated session control
3. ✅ **Comprehensive DoS protection** - Rate limiting, connection limits, bandwidth throttling
4. ✅ **Full accounting support** - Database backend with exports and reporting
5. ✅ **Strong security posture** - Client validation, replay protection, Message-Authenticator, certificate revocation checking, audit logging
6. ✅ **Excellent test coverage** - 156+ tests with high pass rate
7. ✅ **Comprehensive documentation** - 2,000+ lines of guides and examples

**Suitable For**:

- ✅ Enterprise WiFi (802.1X) with EAP-TLS
- ✅ VPN authentication
- ✅ High-security environments
- ✅ Multi-tenant deployments
- ✅ Compliance-sensitive environments

**Not Recommended For** (without additional work):

- ❌ Deployments requiring legacy EAP methods (TTLS, PEAP, MSCHAPv2)
- ❌ Environments requiring hot configuration reload

**Next Development Priorities**:

1. EAP-TEAP inner methods with real keying material (EAP-MSCHAPv2, inner EAP-TLS) and the EMSK-based S-IMCK chain (RFC 9930 §6.2.2)
2. Hot configuration reload (including static CRL files)
3. Administrative enable/disable switch for Status-Server acceptance (RFC 5997 §4.2 SHOULD)

---

## Version History

- **v0.1.0**: Core RADIUS authentication (PAP)
- **v0.1.1**: Client validation, request deduplication, per-client secrets, audit logging
- **v0.2.0**: Rate limiting, concurrent connection limits, bandwidth throttling
- **v0.3.0**: RADIUS accounting with file and PostgreSQL backends
- **v0.4.0**: Accounting exports (CSV, JSON), usage reporting, retention policies
- **v0.5.0**: **EAP-TLS 100% complete** - Certificate-based authentication, production key extraction, mutual TLS
- **v0.6.0**: PostgreSQL and LDAP authentication backends, HTTP health checks, Prometheus metrics
- **v0.7.x**: RADIUS proxy, EAP-TEAP Phase 1+2, CRL/OCSP module (`revocation` feature, not integrated)
- **v0.9.0**: Kubernetes-only deployment (systemd/Compose removed), management API mTLS + ABAC, live session index, dual-stack IPv4 fix
- **v0.10.0**: **RadSec (RFC 6614)** transport, **CoA/Disconnect (RFC 5176)** over RadSec, Message-Authenticator required on EAP requests, NAS-IPv6-Address, Termination-Action
- **v0.10.1**: Container image built with the `tls` feature
- **v0.11.0**: **MS-MPPE-Send/Recv-Key (RFC 2548)** on EAP Access-Accepts, RFC 9190 TLS 1.3 exporter labels + EAP-Key-Name, EAP-TEAP IMCK/CMK (RFC 7170 §5.2) and MSK (§5.4), Vendor-Specific and Tunnel-Password codecs, proxy re-keying of User-Password / Message-Authenticator (request leg) and MS-MPPE / Tunnel-Password / Message-Authenticator (response leg), signed proxy timeout rejects
- **v0.12.0**: **Certificate revocation checking (RFC 5280 / RFC 6960)** wired into EAP-TLS and RadSec via the `revocation` block, fail-closed by default; EAP-Failure on every EAP Access-Reject (RFC 3579 §2.6.3); interop harness (revoked supplicant, 24 assertions) running in CI
- **v0.13.0**: **EAP-TEAP interoperable with wpa_supplicant (RFC 9930)**: §4.2.13 Crypto-Binding TLV with §6.3 Compound-MACs, §6.2 / §6.4 key schedule with the negotiated cipher suite's hash (pinned by independent known-answer vectors), §3.1 version bits, §3.6.6 Intermediate-Result + Result + Crypto-Binding termination, §4.2.15 one-octet Basic-Password-Auth-Resp lengths, RFC 3748 §5.3.1 EAP-Nak method switching, `eap.teap_tls`; interop harness on wpa_supplicant 2.12 with four TEAP scenarios (57 assertions). EAP-TEAP fragmentation in both phases and directions (§3.3) through the bounded reassembler, L flag only on fragmented TEAP messages, Phase 2 opened with the handshake flight, EAP-Success Identifier echoing the peer's last Response (RFC 3748 §4.2), first EAP-Request Identifier following the NAS's Identity Request (RFC 3748 §4.1); bounded EAP session store (idle timeout enforced on every packet + LRU cap, released on Accept/Reject, fail closed, `radius_eap_sessions_evicted_total`); `eap` block documented; EAP-TEAP Basic-Password-Auth fails closed (fixes an unreleased empty-password bypass), Phase 2 rounds bounded, `eap.enable_teap` default `false`. **Status-Server per RFC 5997**: Message-Authenticator required and verified with silent discard (§4.1), Access-Accept on the authentication port / Accounting-Response on the accounting port (§4.2), Message-Authenticator on every reply, Proxy-State echoed, proxy answers locally and never forwards (§4.3); **dedicated accounting socket** (`accounting_port`: 1813 default / `"shared"` / `"disabled"`, RFC 2866 §2) with per-socket code admission and Accounting-Response from 1813; home-server health probes made RFC 5997 clients (random Request Authenticator, signed, reply source / Identifier / Response Authenticator / Message-Authenticator verified, per-probe socket — fixes probes that conformant home servers discarded and concurrent probes sharing one socket); constant-time authenticator comparison; interop scenario 14 (Status-Server and the accounting port against radclient, proxy probes against FreeRADIUS and usg-home)
- **Unreleased**: **EAP conversation hardening**: 16-octet CSPRNG State bound to the NAS (client address, NAS-IP-Address / NAS-IPv6-Address / NAS-Identifier) and User-Name (RFC 2865 §5.24, RFC 5080 §2.1.1), EAP-Responses matched to the outstanding Request's Identifier (RFC 3748 §4.1), RFC 3579 §2.6.2 role-reversal rejects and §2.1 EAP-Start, retransmitted Access-Requests answered from the cached reply (RFC 5080 §2.2.2, `radius_retransmissions_replayed_total`), Message-Authenticator verified before the duplicate cache and before proxy routing (RFC 3579 §3.2), `AuthResult::Discard`; interop scenario 15 (retransmitting bash NAS). **CRL and OCSP signatures verified** (RFC 5280 §6.3.3, RFC 6960 §3.2 / §4.2.2.2): CRLs and OCSP responses trusted only when signed by the issuing CA (or, for OCSP, a delegated responder with id-kp-OCSPSigning) using the rustls provider's algorithms, crlNumber tracked per issuer (rollback refused), every certificate of the chain except the trust anchor checked with a bounded path builder, delta / IDP / unknown-critical CRLs rejected, CRLs without nextUpdate refused; OpenSSL-generated known-answer fixtures (ECDSA and RSA PKCS#1 v1.5 / PSS); interop scenario 16 (CRL signed by the wrong key, fail-closed). **Outbound RadSec (RFC 6614) for the proxy**: per home server `transport = "radsec"` with a `tls` block (`ca_path`, `cert_path`, `key_path`, `server_name`, optional `revocation`), no `secret` (fixed `"radsec"`, §2.3 item 4); one persistent mutually authenticated TLS 1.3 / ML-KEM-1024 / AES-256-GCM-SHA384 connection per home server with `enforce_fips_parameters` after every handshake, resumption disabled, fail closed with no UDP fallback, reconnect with capped jittered exponential backoff (§2.3 item 1); home-server certificate revocation through the same `revocation` block and module (static CRL, CRL-DP, OCSP, with the signature verification and whole-chain check above) via a `ServerCertVerifier` adapter; RFC 6613 rules on the link — no retransmission over the same connection (§2.6.1), connection closed on a bad `Length`, an undecodable packet or a failed Response-/Message-Authenticator (§2.6.4), Status-Server as the mandatory RFC 3539 §3.4 watchdog (`health_check.enabled` required, two unanswered probes reset the connection), probe Identifiers chosen from the free ones and `max_outstanding ≤ 255` (§2.6, §2.6.5); CoA-/Disconnect-Request from a home server answered with NAK + `Error-Cause` 406 (RFC 6614 §2.5); NAS Identifiers still forwarded unchanged (accepted gap). Proxy fixes found on the way: a failed resend no longer loses the retry-count increment (infinite retries), `outstanding` no longer underflows, a stray datagram with a guessed Proxy-State can no longer evict a live cache entry (Response Authenticator verified before the entry is consumed), the proxy block is validated at config load. Interop harness: FreeRADIUS image on Debian trixie (3.2.7 / OpenSSL 3.5.7) running `-fxx -l stdout`, RadSec listener pinned to TLS 1.3 + `ecdh_curve = "MLKEM1024"` + client certificate; scenario 17 (EAP-TLS and PAP through the proxy to FreeRADIUS over RadSec, wrong password rejected) — 89 in-container assertions across 17 scenarios plus 13 host-side checks

---

*Last Updated: 2026-10-28*
*Document Version: 3.6 (unreleased: outbound RadSec for the proxy with RFC 6613 connection rules, CRL and OCSP signature verification with whole-chain revocation checks, NAS-bound random EAP State, Identifier matching, cached replies for retransmissions; v0.13.0: EAP-TEAP interop with wpa_supplicant, bounded EAP session store, RFC 5997 Status-Server conformance, dedicated 1813/udp accounting socket, conformant health probes)*
