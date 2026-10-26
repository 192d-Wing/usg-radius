# Certificate Revocation List (CRL) Implementation Plan

## Overview

Implement production-grade Certificate Revocation List (CRL) checking for EAP-TLS mutual authentication. This is Phase 1 of the complete Certificate Revocation implementation (v0.6.0).

**Status**: Implemented and integrated. The module (CRL + OCSP) lives in
`crates/radius-proto/src/revocation/`; `radius-server` wires it into EAP-TLS
and RadSec client-certificate verification through the `revocation` config
block (`crates/radius-server/src/client_verifier.rs`, feature `revocation`).
This document is the original design plan; where it differs from the code, the
code and `docs/docs/protocol/RFC-COMPLIANCE.md` are authoritative.
**Priority**: HIGH (required for production compliance)

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    EAP-TLS Authentication                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│             RevocationCheckingVerifier                       │
│  (wraps WebPkiClientVerifier + adds CRL checking)           │
└──────────────────────┬──────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌──────────────────┐      ┌──────────────────┐
│  WebPkiClient    │      │  CRL Verifier    │
│   Verifier       │      │                  │
│  (rustls built-in)│     │  - CRL fetch     │
│                  │      │  - CRL parse     │
│  - Basic cert    │      │  - Serial check  │
│    validation    │      │  - Cache manage  │
│  - Chain verify  │      │                  │
└──────────────────┘      └──────────────────┘
                                   │
                          ┌────────┴────────┐
                          ▼                 ▼
                   ┌────────────┐    ┌──────────────┐
                   │ CRL Cache  │    │ CRL Fetcher  │
                   │            │    │              │
                   │ - DashMap  │    │ - HTTP GET   │
                   │ - TTL      │    │ - Timeouts   │
                   │ - Auto     │    │ - Retries    │
                   │   cleanup  │    │              │
                   └────────────┘    └──────────────┘
```

### Module Structure

```
crates/radius-proto/src/
├── eap.rs                        # Existing EAP-TLS code
└── revocation/                   # New module (behind "revocation" feature)
    ├── mod.rs                    # Public API and RevocationCheckingVerifier
    ├── crl.rs                    # CRL parsing, validation, serial checking
    ├── cache.rs                  # CRL caching with TTL (DashMap-based)
    ├── fetch.rs                  # HTTP fetching of CRLs
    ├── config.rs                 # RevocationConfig types
    └── error.rs                  # Revocation-specific errors
```

## Implementation Phases

### Phase 1.1: Core Types and Configuration (Week 1, Days 1-2)

**Goal**: Define all data structures, configuration types, and error handling.

**Files**: `revocation/mod.rs`, `revocation/config.rs`, `revocation/error.rs`

**Tasks**:

1. Create `RevocationConfig` struct:

   ```rust
   pub struct RevocationConfig {
       pub check_mode: RevocationCheckMode,
       pub fallback_behavior: FallbackBehavior,
       pub crl_config: CrlConfig,
   }

   pub enum RevocationCheckMode {
       CrlOnly,
       Disabled,
   }

   pub enum FallbackBehavior {
       FailOpen,   // Allow auth on fetch/parse errors
       FailClosed, // Reject auth on fetch/parse errors
   }

   pub struct CrlConfig {
       pub static_crl_paths: Vec<String>,  // Preloaded CRL files
       pub enable_http_fetch: bool,
       pub http_timeout_secs: u64,
       pub cache_ttl_secs: u64,
       pub max_cache_entries: usize,
   }
   ```

2. Create `RevocationError` enum:

   ```rust
   #[derive(Debug, thiserror::Error)]
   pub enum RevocationError {
       #[error("CRL fetch failed: {0}")]
       FetchError(String),

       #[error("CRL parse error: {0}")]
       ParseError(String),

       #[error("Certificate revoked: serial={0}")]
       CertificateRevoked(String),

       #[error("CRL signature invalid")]
       InvalidSignature,

       #[error("CRL expired")]
       CrlExpired,

       #[error("HTTP error: {0}")]
       HttpError(String),
   }
   ```

**Tests**: Configuration serialization/deserialization tests

---

### Phase 1.2: CRL Parsing and Validation (Week 1, Days 3-5)

**Goal**: Parse CRL files and validate their structure and signatures.

**File**: `revocation/crl.rs`

**Tasks**:

1. Implement CRL parsing using `x509-parser`:

   ```rust
   pub struct CrlInfo {
       pub issuer: String,
       pub this_update: chrono::DateTime<chrono::Utc>,
       pub next_update: Option<chrono::DateTime<chrono::Utc>>,
       pub revoked_serials: HashSet<Vec<u8>>,  // Set of revoked serial numbers
       pub signature_algorithm: String,
   }

   pub fn parse_crl(crl_der: &[u8]) -> Result<CrlInfo, RevocationError> {
       // Use x509_parser::revocation_list::CertificateList
       // Extract issuer, validity period, revoked certificates
       // Build HashSet of revoked serial numbers for O(1) lookup
   }
   ```

2. Implement serial number checking:

   ```rust
   pub fn is_certificate_revoked(
       cert_serial: &[u8],
       crl_info: &CrlInfo,
   ) -> bool {
       crl_info.revoked_serials.contains(cert_serial)
   }
   ```

3. Implement CRL validation:

   ```rust
   pub fn validate_crl(
       crl_info: &CrlInfo,
       current_time: chrono::DateTime<chrono::Utc>,
   ) -> Result<(), RevocationError> {
       // Check CRL is not expired
       // Check this_update <= current_time
       // Check next_update > current_time (if present)
   }
   ```

**Tests**:

- Parse valid CRL
- Parse CRL with multiple revoked certs
- Detect expired CRL
- Serial number lookup (revoked and non-revoked)

---

### Phase 1.3: CRL Caching (Week 2, Days 1-2)

**Goal**: Implement efficient caching with TTL to avoid repeated fetches.

**File**: `revocation/cache.rs`

**Tasks**:

1. Implement `CrlCache` using DashMap:

   ```rust
   pub struct CrlCache {
       cache: Arc<DashMap<String, CachedCrl>>,  // Key: CRL distribution point URL
       max_entries: usize,
   }

   struct CachedCrl {
       crl_info: CrlInfo,
       cached_at: Instant,
       ttl: Duration,
   }

   impl CrlCache {
       pub fn new(max_entries: usize) -> Self;

       pub fn get(&self, url: &str) -> Option<CrlInfo>;

       pub fn insert(&self, url: String, crl_info: CrlInfo, ttl: Duration);

       pub fn cleanup_expired(&self);

       pub fn clear(&self);
   }
   ```

2. Implement TTL-based expiration:
   - Check TTL on `get()` and return None if expired
   - Background task to periodically cleanup expired entries

**Tests**:

- Insert and retrieve CRL from cache
- TTL expiration detection
- Max entries enforcement (LRU eviction)
- Concurrent access (multiple threads)

---

### Phase 1.4: CRL HTTP Fetching (Week 2, Days 3-5)

**Goal**: Fetch CRLs from HTTP distribution points with timeouts and retries.

**File**: `revocation/fetch.rs`

**Tasks**:

1. Add `reqwest` dependency (async HTTP client):

   ```toml
   reqwest = { version = "0.12", features = ["blocking"], optional = true }
   url = { version = "2.5", optional = true }
   ```

2. Implement HTTP fetching:

   ```rust
   pub struct CrlFetcher {
       client: reqwest::blocking::Client,
       timeout: Duration,
   }

   impl CrlFetcher {
       pub fn new(timeout_secs: u64) -> Result<Self, RevocationError> {
           let client = reqwest::blocking::Client::builder()
               .timeout(Duration::from_secs(timeout_secs))
               .build()
               .map_err(|e| RevocationError::HttpError(e.to_string()))?;

           Ok(Self { client, timeout: Duration::from_secs(timeout_secs) })
       }

       pub fn fetch_crl(&self, url: &str) -> Result<Vec<u8>, RevocationError> {
           // HTTP GET to CRL distribution point
           // Return raw DER-encoded CRL bytes
           // Handle timeouts, redirects, errors
       }
   }
   ```

3. Extract CRL distribution points from certificates:

   ```rust
   pub fn extract_crl_distribution_points(
       cert: &x509_parser::certificate::X509Certificate
   ) -> Vec<String> {
       // Parse CRL Distribution Points extension (2.5.29.31)
       // Extract HTTP URLs
   }
   ```

**Tests**:

- Mock HTTP server returning valid CRL
- HTTP timeout handling
- HTTP error handling (404, 500)
- Invalid URL handling
- CRL distribution point extraction from cert

---

### Phase 1.5: Integration with EAP-TLS (Week 3, Days 1-3)

**Goal**: Create custom verifier that wraps WebPkiClientVerifier and adds CRL checking.

**File**: `revocation/mod.rs` + modifications to `eap.rs`

**Tasks**:

1. Implement `RevocationCheckingVerifier`:

   ```rust
   pub struct RevocationCheckingVerifier {
       inner: Arc<dyn rustls::server::ClientCertVerifier>,
       crl_cache: Arc<CrlCache>,
       crl_fetcher: Arc<CrlFetcher>,
       config: RevocationConfig,
   }

   impl RevocationCheckingVerifier {
       pub fn new(
           inner_verifier: Arc<dyn rustls::server::ClientCertVerifier>,
           config: RevocationConfig,
       ) -> Result<Self, RevocationError>;

       fn check_certificate_revocation(
           &self,
           cert: &x509_parser::certificate::X509Certificate,
       ) -> Result<(), RevocationError>;
   }

   impl rustls::server::ClientCertVerifier for RevocationCheckingVerifier {
       fn verify_client_cert(
           &self,
           end_entity: &CertificateDer,
           intermediates: &[CertificateDer],
           now: SystemTime,
       ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
           // 1. Call inner verifier (WebPki validation)
           self.inner.verify_client_cert(end_entity, intermediates, now)?;

           // 2. Parse certificate
           let cert = parse_x509_certificate(end_entity.as_ref())?;

           // 3. Check revocation
           self.check_certificate_revocation(&cert)?;

           Ok(rustls::server::ClientCertVerified::assertion())
       }
   }
   ```

2. Modify `build_server_config()` in `eap.rs`:

   ```rust
   #[cfg(feature = "revocation")]
   pub fn build_server_config_with_revocation(
       cert_config: &TlsCertificateConfig,
       revocation_config: RevocationConfig,
   ) -> Result<rustls::ServerConfig, EapError> {
       // Build base config
       // Wrap WebPkiClientVerifier with RevocationCheckingVerifier
       // Return config with revocation checking enabled
   }
   ```

3. Add to `TlsCertificateConfig`:

   ```rust
   pub revocation_config: Option<RevocationConfig>,
   ```

**Tests**:

- Verify revoked certificate is rejected
- Verify valid certificate is accepted
- Verify fallback behavior (fail-open vs fail-closed)
- Verify CRL cache is used (no duplicate fetches)

---

### Phase 1.6: End-to-End Testing (Week 3, Days 4-5)

**Goal**: Comprehensive integration tests with real CRLs and certificates.

**File**: `crates/radius-proto/tests/revocation_integration.rs`

**Tasks**:

1. Generate test PKI:

   ```bash
   # CA certificate
   # Server certificate
   # Client certificate (valid)
   # Client certificate (revoked)
   # CRL with revoked client cert
   ```

2. Integration test scenarios:
   - Valid cert + empty CRL → Accept
   - Revoked cert + CRL → Reject
   - Valid cert + CRL fetch timeout (fail-open) → Accept
   - Valid cert + CRL fetch timeout (fail-closed) → Reject
   - Static CRL file loading
   - HTTP CRL fetching
   - Cache hit performance test

**Tests**: 10+ integration tests covering all scenarios

---

### Phase 1.7: Documentation (Week 4, Days 1-2)

**Goal**: Comprehensive documentation for CRL configuration and usage.

**Files**:

- `docs/docs/protocol/CRL.md`
- `docs/docs/examples/crl-example.md`
- `docs/docs/development/ROADMAP.md` (update)

**Content**:

1. CRL configuration guide
2. Security best practices
3. Troubleshooting common issues
4. Performance tuning (cache TTL, fetch timeouts)
5. Migration from v0.5.0
6. Example configurations

---

## Dependencies to Add

### Workspace `Cargo.toml`

```toml
[workspace.dependencies]
# HTTP client for CRL fetching
reqwest = { version = "0.12", features = ["blocking"] }
url = "2.5"
```

### `radius-proto/Cargo.toml`

```toml
[dependencies]
reqwest = { workspace = true, optional = true }
url = { workspace = true, optional = true }

[features]
revocation = ["tls", "dep:reqwest", "dep:url"]
```

**Rationale**: `reqwest` blocking client avoids async complexity in rustls verifier (which is sync). `url` crate for parsing CRL distribution points.

---

## Testing Strategy

### Unit Tests (~30 tests)

- CRL parsing (valid, invalid, expired)
- Serial number checking
- Cache operations (insert, get, expiry, eviction)
- CRL fetching (success, timeout, errors)
- Configuration validation

### Integration Tests (~10 tests)

- End-to-end revocation checking
- Fail-open vs fail-closed behavior
- Cache performance
- Real PKI with revoked certs

### Performance Tests

- CRL cache hit rate
- CRL fetch latency impact
- Memory usage with large CRLs

---

## Success Criteria

### Week 3 Deliverables

- ✅ CRL parsing and validation working
- ✅ HTTP fetching with timeouts
- ✅ Caching with TTL
- ✅ Custom verifier integrated with EAP-TLS
- ✅ 40+ tests passing
- ✅ Example configurations documented

### Production Readiness Checklist

- ✅ Handles CRLs up to 10 MB
- ✅ Cache prevents repeated fetches (< 1% duplicate requests)
- ✅ Fetch timeouts prevent DoS (5s default)
- ✅ Fail-open and fail-closed modes configurable
- ✅ Works with existing EAP-TLS deployments (backward compatible)
- ✅ Documented security considerations

---

## Security Considerations

1. **CRL Signature Validation**: Currently using `x509-parser` which validates signatures. Ensure this is enforced.

2. **CRL Size Limits**: Enforce max CRL size (10 MB default) to prevent memory exhaustion.

3. **HTTP vs HTTPS**: Support both, but recommend HTTPS for CRL distribution points.

4. **Cache Poisoning**: Only cache CRLs with valid signatures. Use distribution point URL as cache key.

5. **Fail-Open Risk**: Document that fail-open mode reduces security. Recommend fail-closed for high-security environments.

6. **Freshness**: Enforce that CRL `thisUpdate` <= current time and `nextUpdate` > current time.

---

## Future Enhancements (Phase 2: OCSP)

After CRL Phase 1 is complete, Phase 2 will add OCSP support:

- OCSP request building
- OCSP response parsing
- OCSP stapling support
- Prefer OCSP over CRL (configurable)
- OCSP nonce for replay protection

**Estimated Effort**: 2-3 weeks (Phase 2)

---

## Timeline Summary

| Week | Focus | Deliverables |
|------|-------|--------------|
| Week 1 | Core types, CRL parsing | Config types, CRL parser, serial checking |
| Week 2 | Caching, HTTP fetching | Cache with TTL, HTTP CRL fetcher |
| Week 3 | Integration, testing | Custom verifier, integration tests |
| Week 4 | Documentation, polish | Docs, examples, final testing |

**Total**: 3-4 weeks for production-ready CRL implementation

---

*Created*: 2025-12-31
*Author*: Claude Sonnet 4.5
*Status*: Implementation Plan (Ready to Execute)
