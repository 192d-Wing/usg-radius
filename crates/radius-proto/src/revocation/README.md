# Certificate Revocation Module

Production-grade certificate revocation checking for EAP-TLS mutual authentication in RADIUS servers.

## Overview

This module provides CRL (Certificate Revocation List) support according to RFC 5280. It integrates seamlessly with rustls to enable revocation checking during the TLS handshake for EAP-TLS authentication.

**Version**: 0.7.4 (Phase 2: OCSP Support Complete)
**Status**: ✅ Production Ready
**OCSP Support**: ✅ Available (v0.7.4+)

## Features

### CRL Support

- ✅ **CRL Parsing**: Full DER/PEM parsing with x509-parser
- ✅ **HTTP Fetching**: Automatic download from certificate distribution points
- ✅ **Thread-Safe Caching**: TTL-based caching with LRU eviction
- ✅ **Static CRL Files**: Support for air-gapped environments
- ✅ **O(1) Lookups**: HashSet-based serial number checking

### OCSP Support (v0.7.4+)

- ✅ **OCSP Request Building**: ASN.1 DER encoding with manual construction
- ✅ **HTTP POST Queries**: RFC 6960-compliant OCSP responder communication
- ✅ **Response Parsing**: Full BasicOCSPResponse parsing
- ✅ **Nonce Support**: RFC 8954 replay protection
- ✅ **Response Caching**: TTL-based caching with automatic expiry
- ✅ **Multiple Check Modes**: OcspOnly, CrlOnly, PreferOcsp, Both

### Common Features

- ✅ **Fail-Open/Fail-Closed**: Configurable error handling policies
- ✅ **rustls Integration**: Custom ClientCertVerifier implementation
- ✅ **Thread-Safe**: Concurrent access via DashMap and Arc

## Quick Start

### 1. Enable the Feature

Add to your `Cargo.toml`:

```toml
[dependencies]
radius-proto = { version = "0.6.0", features = ["revocation"] }
```

### 2. Configure Revocation Checking

```rust
use radius_proto::revocation::{RevocationConfig, CrlConfig, FallbackBehavior};

// Production configuration with HTTP CRL fetching
let config = RevocationConfig::crl_only(
    CrlConfig::http_fetch(
        5,      // 5 second HTTP timeout
        3600,   // 1 hour cache TTL
        100,    // Max 100 cached CRLs
    ),
    FallbackBehavior::FailClosed,  // Secure default: reject on errors
);
```

### 3. Create Verifier

```rust
use radius_proto::revocation::RevocationCheckingVerifier;

let verifier = RevocationCheckingVerifier::new(config)?;
```

### 4. Integrate with rustls

```rust
use rustls::ServerConfig;
use std::sync::Arc;

let tls_config = ServerConfig::builder()
    .with_client_cert_verifier(Arc::new(verifier))
    .with_single_cert(server_cert_chain, server_key)?;
```

## Configuration Examples

### Production (High Security)

```rust
use radius_proto::revocation::{RevocationConfig, CrlConfig, FallbackBehavior};

let config = RevocationConfig::crl_only(
    CrlConfig {
        static_crl_paths: vec![
            "/etc/radius/crls/root-ca.crl".to_string(),
            "/etc/radius/crls/intermediate-ca.crl".to_string(),
        ],
        enable_http_fetch: true,       // Allow dynamic fetching
        http_timeout_secs: 5,          // 5 second timeout
        cache_ttl_secs: 3600,          // 1 hour cache
        max_cache_entries: 100,        // Cache up to 100 CRLs
        max_crl_size_bytes: 10 * 1024 * 1024,  // 10 MB limit
    },
    FallbackBehavior::FailClosed,      // Maximum security
);
```

### Air-Gapped Environment

```rust
let config = RevocationConfig::static_files(
    vec![
        "/etc/radius/crls/root-ca.crl".to_string(),
        "/etc/radius/crls/intermediate-ca.crl".to_string(),
    ],
    FallbackBehavior::FailClosed,
);
```

### Development/Testing

```rust
// Disabled mode - no revocation checking
let config = RevocationConfig::disabled();

// OR: Fail-open for testing with unreliable CRL infrastructure
let config = RevocationConfig::crl_only(
    CrlConfig::default(),
    FallbackBehavior::FailOpen,  // Allow auth on CRL fetch failures
);
```

## OCSP Configuration (v0.7.4+)

OCSP provides real-time certificate revocation checking with lower latency and bandwidth than CRL.

### OCSP Only Mode

Use when OCSP is the primary revocation method:

```rust
use radius_proto::revocation::{RevocationConfig, OcspConfig, FallbackBehavior};

let config = RevocationConfig::ocsp_only(
    OcspConfig::http_fetch(
        5,      // 5 second HTTP timeout
        3600,   // 1 hour cache TTL
        100,    // Max 100 cached responses
    ),
    FallbackBehavior::FailClosed,
);
```

### Prefer OCSP with CRL Fallback (Recommended)

Best of both worlds - try OCSP first, fallback to CRL if OCSP fails:

```rust
use radius_proto::revocation::{
    RevocationConfig, RevocationCheckMode, OcspConfig, CrlConfig, FallbackBehavior
};

let config = RevocationConfig {
    check_mode: RevocationCheckMode::PreferOcsp,
    fallback_behavior: FallbackBehavior::FailClosed,
    ocsp_config: OcspConfig {
        enabled: true,
        http_timeout_secs: 5,
        cache_ttl_secs: 3600,
        max_cache_entries: 100,
        enable_nonce: true,              // Replay protection
        max_response_size_bytes: 1024 * 1024,  // 1 MB limit
        prefer_ocsp: true,
    },
    crl_config: CrlConfig::http_fetch(5, 3600, 100),
};
```

### Check Both Methods

Maximum security - certificate must pass both OCSP and CRL checks:

```rust
let config = RevocationConfig {
    check_mode: RevocationCheckMode::Both,
    fallback_behavior: FallbackBehavior::FailClosed,
    ocsp_config: OcspConfig::http_fetch(5, 3600, 100),
    crl_config: CrlConfig::http_fetch(5, 3600, 100),
};
```

### OCSP vs CRL Decision Matrix

| Requirement | Recommended Mode | Rationale |
|-------------|------------------|-----------|
| Real-time revocation needed | `OcspOnly` or `PreferOcsp` | OCSP provides near real-time status |
| Low bandwidth environment | `OcspOnly` | ~2-5KB per check vs 50-500KB CRL |
| Maximum security | `Both` | Redundant validation |
| High availability required | `PreferOcsp` | Automatic CRL fallback |
| Offline/air-gapped | `CrlOnly` with static files | OCSP requires internet access |
| Large certificate population | `CrlOnly` | CRL cache benefits many certs |

## Configuration Guide

### Fail-Open vs Fail-Closed

| Mode | Behavior | When to Use | Security Impact |
|------|----------|-------------|-----------------|
| **Fail-Closed** | Reject authentication on CRL fetch/parse failure | Production, high-security environments | ✅ Maximum security<br>⚠️ May impact availability if CRL servers are unreachable |
| **Fail-Open** | Allow authentication on CRL fetch/parse failure | Development, testing, low-security environments | ⚠️ Reduced security<br>✅ Maximum availability |

**Recommendation**: Always use `FailClosed` for production unless you have specific availability requirements that outweigh security concerns.

### Cache TTL Tuning

Choose cache TTL based on your CRL update frequency:

| CRL Update Frequency | Recommended TTL | Notes |
|---------------------|-----------------|-------|
| Every 15 minutes | 600s (10 min) | High-security environments |
| Hourly | 1800s (30 min) | Balanced security/performance |
| Daily | 3600s (1 hour) | **Default**, suitable for most deployments |
| Weekly | 86400s (24 hours) | Low-churn environments |

**Important**: Cache TTL should be **less than** the CRL's `nextUpdate` interval to avoid using stale CRLs.

### HTTP Timeout Settings

Choose timeout based on network conditions and RADIUS timeout constraints:

| Network Conditions | Recommended Timeout | Notes |
|-------------------|---------------------|-------|
| Low-latency LAN | 1-3 seconds | Fast failover |
| General internet | 5 seconds | **Default**, balanced approach |
| High-latency WAN | 10 seconds | Allow for slow CRL servers |

**RADIUS Constraint**: EAP-TLS authentication must complete within the RADIUS request timeout (typically 30-60 seconds). Factor in TLS handshake round-trips (~3-5) plus CRL fetch time.

## Security Best Practices

### 1. Use HTTPS for CRL Distribution Points

**Always** use HTTPS URLs in your certificate CRL Distribution Points extensions:

```
✅ GOOD: https://ca.example.com/crl.der
❌ BAD:  http://ca.example.com/crl.der
```

HTTP URLs are vulnerable to man-in-the-middle attacks where an attacker could serve a modified CRL to hide revocations.

### 2. Enforce Appropriate Size Limits

Protect against memory exhaustion from malicious CRLs:

```rust
let config = CrlConfig {
    max_crl_size_bytes: 10 * 1024 * 1024,  // 10 MB default
    ..CrlConfig::default()
};
```

Typical CRL sizes:

- **Small CA**: 10-100 KB (hundreds of revocations)
- **Medium CA**: 100 KB - 1 MB (thousands of revocations)
- **Large CA**: 1-10 MB (tens of thousands of revocations)
- **Very Large CA**: 10+ MB (may require custom limit)

### 3. Regular Updates for Static CRL Files

If using static CRL files, automate updates to avoid stale revocation data:

```bash
#!/bin/bash
# /etc/cron.daily/update-crls

# Update root CA CRL
curl -o /etc/radius/crls/root-ca.crl https://ca.example.com/root-ca.crl

# Update intermediate CA CRL
curl -o /etc/radius/crls/intermediate-ca.crl https://ca.example.com/intermediate-ca.crl

# Restart RADIUS server to reload CRLs (if needed)
# systemctl reload radiusd
```

### 4. Monitor Cache Performance

Track cache hit rates to optimize TTL:

```rust
// Future API (not yet implemented in v0.6.0):
// let (total_entries, expired_entries) = verifier.cache_stats();
// let hit_rate = calculate_hit_rate();
// if hit_rate < 0.8 {
//     // Consider increasing cache TTL
// }
```

### 5. Validate CRL Freshness

The implementation automatically validates:

- ✅ `thisUpdate <= current_time` (CRL is active)
- ✅ `nextUpdate >= current_time` (CRL has not expired)

Expired CRLs are **always rejected** in Fail-Closed mode, even if cached.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   EAP-TLS TLS Handshake                      │
│                    (rustls ServerConfig)                     │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│           RevocationCheckingVerifier                         │
│   (implements rustls::ClientCertVerifier)                    │
├──────────────────────────────────────────────────────────────┤
│  1. WebPkiClientVerifier (standard TLS validation)           │
│  2. Extract CRL distribution points from cert                │
│  3. Check cache for CRL                                      │
│  4. If miss: HTTP fetch → parse → validate → cache           │
│  5. Check if cert serial is in revoked set                   │
│  6. Apply fail-open/fail-closed policy on errors             │
└──────────────────────────────────────────────────────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│  CrlCache   │    │  CrlFetcher  │    │    CrlInfo      │
│  (DashMap)  │    │  (reqwest)   │    │  (x509-parser)  │
└─────────────┘    └──────────────┘    └─────────────────┘
```

## Performance Characteristics

### Complexity

- **CRL Parsing**: O(n) where n = number of revoked certificates
- **Serial Lookup**: O(1) using HashSet
- **Cache Lookup**: O(1) using DashMap
- **Cache Eviction**: O(k) where k = cache size (only when cache is full)

### Memory Usage

- **Per CRL**: ~(revoked_count × 32 bytes) + metadata (~200 bytes)
- **Cache**: max_cache_entries × avg_crl_size
- **Example**: 100 cached CRLs with 1000 revocations each ≈ 3-5 MB

### Latency Impact

| Scenario | Typical Latency |
|----------|-----------------|
| Cache hit | < 1 ms |
| Cache miss (HTTP fetch) | 5-50 ms |
| First TLS connection | 100-500 ms (TLS handshake + CRL fetch) |
| Subsequent connections | 50-100 ms (TLS handshake + cache hit) |

## Error Handling

The module defines comprehensive error types:

| Error | Description | Fail-Open Behavior | Fail-Closed Behavior |
|-------|-------------|--------------------|-----------------------|
| `CertificateRevoked` | Certificate is in CRL | ❌ Reject | ❌ Reject |
| `FetchError` | HTTP fetch failed | ✅ Allow | ❌ Reject |
| `ParseError` | CRL parsing failed | ✅ Allow | ❌ Reject |
| `CrlExpired` | CRL nextUpdate passed | ✅ Allow | ❌ Reject |
| `HttpTimeout` | HTTP request timed out | ✅ Allow | ❌ Reject |
| `CrlTooLarge` | CRL exceeds size limit | ✅ Allow | ❌ Reject |

## Testing

### Unit Tests

Run unit tests with:

```bash
cargo test --features revocation
```

Coverage:

- ✅ 42 unit tests covering all modules
- ✅ CRL parsing (DER/PEM)
- ✅ Cache eviction (LRU)
- ✅ HTTP fetching with real endpoints
- ✅ Thread safety (concurrent access)

### Integration Tests

Run integration tests with:

```bash
cargo test --test revocation_integration --features revocation
```

Coverage:

- ✅ Configuration serialization/deserialization
- ✅ Fail-open vs fail-closed modes
- ✅ Static CRL file loading
- ⏳ Real CRL parsing (requires test PKI - marked as `#[ignore]`)
- ⏳ Revoked certificate detection (requires test PKI - marked as `#[ignore]`)

### Generating Test PKI

See [integration tests](../../tests/revocation_integration.rs) for full OpenSSL commands to generate:

- Root CA
- Intermediate CA
- Client certificates
- CRLs (empty and with revocations)

## Troubleshooting

### CRL Fetch Failures

**Symptom**: Warnings in logs about CRL fetch failures

**Causes**:

- CRL distribution point URL is unreachable
- Network timeout
- Invalid/expired TLS certificate on CRL server

**Solutions**:

1. Check network connectivity to CRL distribution point
2. Increase `http_timeout_secs` if network is slow
3. Add static CRL files as backup
4. Use Fail-Open mode (development only)

### High Memory Usage

**Symptom**: Increasing memory consumption

**Causes**:

- Too many cached CRLs
- Very large CRLs being cached
- Cache not evicting old entries

**Solutions**:

1. Reduce `max_cache_entries`
2. Reduce `max_crl_size_bytes`
3. Reduce `cache_ttl_secs` to expire entries faster

### Authentication Delays

**Symptom**: Slow EAP-TLS authentication

**Causes**:

- CRL cache misses requiring HTTP fetches
- Slow CRL distribution point servers
- Large CRL download times

**Solutions**:

1. Increase `cache_ttl_secs` to improve cache hit rate
2. Pre-load static CRL files
3. Reduce `http_timeout_secs` for faster failover
4. Monitor cache hit rate and tune accordingly

## Migration Guide

### From No Revocation Checking

1. Start with disabled mode to test integration:

   ```rust
   let config = RevocationConfig::disabled();
   ```

2. Enable in Fail-Open mode for testing:

   ```rust
   let config = RevocationConfig::crl_only(
       CrlConfig::default(),
       FallbackBehavior::FailOpen,
   );
   ```

3. Switch to Fail-Closed for production:

   ```rust
   let config = RevocationConfig::crl_only(
       CrlConfig::default(),
       FallbackBehavior::FailClosed,
   );
   ```

### From Other Revocation Systems

If migrating from custom CRL checking:

1. Replace custom HTTP fetching with `CrlFetcher`
2. Replace custom parsing with `CrlInfo`
3. Replace custom caching with `CrlCache`
4. Integrate with rustls via `RevocationCheckingVerifier`

## Future Roadmap

### v0.7.0 - OCSP Support (Phase 2)

- OCSP responder support (RFC 6960)
- OCSP stapling
- Hybrid CRL + OCSP modes
- OCSP response caching

### v0.8.0 - Advanced Features (Phase 3)

- Delta CRL support
- Indirect / Issuing Distribution Point CRL support

CRL and OCSP signature verification against the issuing CA, crlNumber
tracking and checking of intermediates are implemented; see
`docs/docs/protocol/RFC-COMPLIANCE.md` (Certificate Revocation).
- Certificate status monitoring API

## References

- [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 6960 - X.509 Internet Public Key Infrastructure OCSP](https://tools.ietf.org/html/rfc6960) (planned)
- [RADIUS Protocol - RFC 2865](https://tools.ietf.org/html/rfc2865)
- [EAP-TLS - RFC 5216](https://tools.ietf.org/html/rfc5216)

## Support

For issues, questions, or contributions:

- **Documentation**: See module-level docs in `src/revocation/mod.rs`
- **Examples**: See `tests/revocation_integration.rs`
- **Issues**: Report at project issue tracker

## License

Same as parent project.
