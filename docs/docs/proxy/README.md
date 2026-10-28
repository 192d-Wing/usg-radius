# RADIUS Proxy

The usg-radius server includes a full-featured RADIUS proxy implementation for forwarding authentication requests to upstream RADIUS servers, over plain UDP or over RadSec (RFC 6614). Accounting-Request is answered locally and not proxied.

## Overview

The proxy module enables realm-based routing of RADIUS requests to different home server pools. This is essential for organizations that need to:

- Route requests for different domains to different authentication backends
- Load balance requests across multiple RADIUS servers
- Implement failover for high availability
- Create hierarchical RADIUS infrastructure

## Architecture

```
NAS → Proxy Server → Router → Pool (Load Balancer) → Home Servers
                              ↑
                           Realms
```

### Components

1. **Router**: Makes routing decisions based on username realm
2. **Realm**: Pattern matching for username@realm or DOMAIN\username formats
3. **HomeServerPool**: Load balancing across multiple home servers
4. **HomeServer**: Upstream RADIUS server configuration (`transport` `udp` or `radsec`)
5. **ProxyHandler**: Request forwarding and response correlation
6. **ProxyCache**: Tracks in-flight requests using Proxy-State attributes
7. **RetryManager**: Handles timeouts and retry logic
8. **RadSec link** (`proxy/radsec_client.rs`): one persistent TLS connection per `transport: "radsec"` home server, with reconnect and the RFC 6613 watchdog

The proxy components run under the `udp-insecure` NAS listener only; under an inbound `transport: "radsec"` listener the server runs the RadSec accept loop and does not start the proxy.

## Configuration

### Basic Example

```json
{
  "proxy": {
    "enabled": true,
    "cache_ttl": 300,
    "max_outstanding": 1000,
    "proxy_timeout": 30,
    "default_realm": "local",

    "pools": [
      {
        "name": "corporate_pool",
        "strategy": "round_robin",
        "servers": [
          {
            "address": "10.0.1.10:1812",
            "secret": "shared_secret_1",
            "timeout": 30,
            "max_outstanding": 100,
            "name": "corporate-radius-1"
          },
          {
            "address": "10.0.1.11:1812",
            "secret": "shared_secret_2",
            "timeout": 30,
            "max_outstanding": 100,
            "name": "corporate-radius-2"
          }
        ]
      },
      {
        "name": "guest_pool",
        "strategy": "least_outstanding",
        "servers": [
          {
            "address": "10.0.2.10:1812",
            "secret": "guest_secret",
            "timeout": 30,
            "max_outstanding": 100,
            "name": "guest-radius"
          }
        ]
      }
    ],

    "realms": [
      {
        "name": "corporate",
        "match": {
          "type": "suffix",
          "pattern": "corp.example.com"
        },
        "pool": "corporate_pool",
        "strip_realm": true
      },
      {
        "name": "guest",
        "match": {
          "type": "exact",
          "pattern": "GUEST"
        },
        "pool": "guest_pool",
        "strip_realm": true
      }
    ],

    "retry": {
      "max_retries": 3,
      "retry_interval": 5,
      "failover_on_timeout": true
    }
  }
}
```

### RadSec to home servers (RFC 6614)

A home server is reached over RadSec instead of UDP by setting `transport` to
`"radsec"` and giving it a `tls` block. There is no `secret`: RFC 6614 §2.3
fixes the shared secret on a RADIUS/TLS hop to the string `"radsec"`, and the
certificates are what authenticate the hop. Everything the proxy re-keys
between the NAS secret and the home-server secret (User-Password and
Message-Authenticator on the request leg; Response Authenticator, MS-MPPE keys,
Tunnel-Password and Message-Authenticator on the response leg) is keyed by
`"radsec"` on that hop.

```json
{
  "proxy": {
    "enabled": true,
    "pools": [
      {
        "name": "home_radsec",
        "strategy": "failover",
        "servers": [
          {
            "name": "home-radius-1",
            "address": "10.0.1.10:2083",
            "transport": "radsec",
            "tls": {
              "ca_path": "/etc/radius/proxy/home-ca.pem",
              "cert_path": "/etc/radius/proxy/proxy.pem",
              "key_path": "/etc/radius/proxy/proxy.key",
              "server_name": "radius1.home.example.com",
              "revocation": {
                "mode": "crl_only",
                "on_error": "fail_closed",
                "crl": { "static_files": ["/etc/radius/proxy/home-ca.crl"] }
              }
            },
            "timeout": 5,
            "max_outstanding": 200
          }
        ]
      }
    ],
    "health_check": { "enabled": true, "interval": 20, "timeout": 5 }
  }
}
```

A complete file is [`examples/configs/proxy-radsec-upstream.json`](../../../examples/configs/proxy-radsec-upstream.json).

**Keys** (`proxy.pools[].servers[]`):

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `transport` | `"udp"` \| `"radsec"` | `"udp"` | Transport to this home server |
| `secret` | String | none | UDP: required, non-empty. RadSec: must be absent (the hop secret is the fixed `"radsec"`) |
| `tls.ca_path` | String | required for RadSec | PEM CA bundle the home server's certificate must chain to |
| `tls.cert_path` | String | required for RadSec | PEM client certificate chain the proxy presents (leaf first) |
| `tls.key_path` | String | required for RadSec | PEM private key for `cert_path` |
| `tls.server_name` | String | required for RadSec | DNS name or IP literal the home server's certificate must be valid for; also sent as SNI |
| `tls.revocation` | Object | none | CRL/OCSP checking of the home server's certificate — the same block as `eap.tls.revocation` and `radsec.revocation`; needs a binary built with the `revocation` feature |
| `address`, `timeout`, `max_outstanding`, `name` | | as for UDP | `address` is `ip:port` (no default port); `timeout` is also the TCP connect and TLS handshake deadline; `max_outstanding` ≤ 255 for RadSec |

**Validation** (at config load; the server does not start otherwise):

- `transport: "radsec"` needs a binary built with the `tls` cargo feature (the release binary and the container image are).
- A RadSec home server needs a `tls` block with all four paths/names non-empty and a `server_name` that parses as a DNS name or IP address; a `tls` block on a UDP home server is an error.
- `secret` is required for UDP and rejected for RadSec.
- `max_outstanding` must be ≤ 255 for a RadSec home server: one TCP connection carries at most 256 outstanding requests, one Identifier being reserved for the watchdog (RFC 6613 §2.6, §2.6.5).
- `health_check.enabled` must be `true` when any home server uses RadSec: the Status-Server probe is the RFC 6613 §2.6 / RFC 3539 §3.4 watchdog of the connection.
- `tls.revocation` is validated like the other `revocation` blocks (a binary without the `revocation` feature refuses it).

**Behaviour**:

- **One persistent connection per RadSec home server**, opened at startup by a link task and kept open. The TLS client is the same `usg-fips-tls` provider the RadSec listener uses: TLS 1.3 only, ML-KEM-1024-only key exchange, `TLS_AES_256_GCM_SHA384`, session resumption disabled (every reconnect is a full handshake with full certificate and revocation checks), no ALPN. After every handshake the negotiated version, suite and group are re-checked and the connection is dropped if anything is outside the allow-list. A home server that cannot negotiate these parameters never connects; there is no fallback to UDP.
- **Mutual authentication**: the proxy presents `tls.cert_path`; the home server's chain is validated against `tls.ca_path` (RFC 5280, EKU serverAuth) and must be valid for `tls.server_name`. With `tls.revocation` the home server's certificate is also checked against static CRLs, CRL Distribution Points or OCSP, fail-closed by default. A stapled OCSP response is ignored; revocation is decided by the block alone. Note that with `crl.fetch` or an OCSP mode the fetch runs inside the handshake, so the effective handshake deadline is the home server's `timeout` plus the fetch timeout.
- **Framing**: the RADIUS packets are written as-is and delimited by their `Length` field (RFC 6614 §3.4). The connection is closed, and reopened with backoff, when the home server breaks the protocol (RFC 6613 §2.6.4): a `Length` outside 20..=4096, a packet that does not decode, a response whose Response Authenticator fails, or a probe reply whose Response Authenticator or Message-Authenticator fails. A response that matches no outstanding request is discarded and the connection kept.
- **Correlation**: responses are matched by Proxy-State exactly as over UDP; the home server is identified by the connection the response arrived on, not by source address, so a UDP datagram can never answer a request sent over RadSec.
- **Retries** follow RFC 6613 §2.6.1: a request is never retransmitted over the connection it was sent on. If it times out while that connection is still up the retry manager waits for the deadline; if the link is down or has reconnected the request is resent on the new connection. After `retry.max_retries` the NAS receives the signed Access-Reject as today.
- **Reconnect**: on any error, EOF or protocol violation the link reconnects with exponential backoff (500 ms doubling to 30 s, ±25 % jitter; reset once a connection has lived 10 s). While the link is down a forwarded request fails fast (`LinkDown`), stays in the proxy cache and is resent by the retry manager on its next tick; nothing is queued inside the link. Pool selection uses the health state, so a down link is skipped only once probes have marked the server Down.
- **Watchdog**: Status-Server probes travel over the same connection (see [Health Checks](#health-checks)); after two consecutive unanswered probes the link closes the connection and reconnects (RFC 3539 §3.4). There is no TCP keepalive, so this is also how a half-dead peer is detected (`2 × health_check.interval + health_check.timeout`).
- **Identifiers**: the link tracks the Identifiers in flight on the current connection and the probe takes one that is free. NAS Identifiers are otherwise forwarded unchanged (as over UDP), so a request arriving while a probe is pending may still carry the probe's Identifier, and two NASes sending the same Identifier at the same time collide at a home server that deduplicates on Identifier (RFC 6613 §2.6 — a known gap; correlation on the proxy side is by Proxy-State and unaffected).
- **CoA / Disconnect from the home server** down the connection is answered with CoA-NAK / Disconnect-NAK, `Error-Cause` 406 (RFC 6614 §2.5); the proxy does not relay dynamic authorization to the NAS.
- **Logs**: `RadSec link established` (server, address, TLS version, suite, key-exchange group) and `RadSec link lost` (server, address, reason, frames dropped) at `info`. Neither line carries frame bytes or key material.

Keep `health_check.interval` below the home server's TLS idle timeout (FreeRADIUS `idle_timeout`, 30 s in its template): the probe is what keeps the connection warm, and an idle close costs the next request a `retry_interval` of latency.

Interop: `tests/interop/run.sh` scenario 16 drives EAP-TLS and PAP through the proxy to FreeRADIUS 3.2.7 over RadSec (TLS 1.3, ML-KEM-1024, mutual certificates) and checks FreeRADIUS's own log for the connection, the negotiated parameters, the client certificate and the port the requests arrived on; see [INTEROP_TESTING.md](../development/INTEROP_TESTING.md).

## Features

### Realm Matching

Three match types are supported:

1. **Exact**: Exact string match
   - Pattern: `"CORPORATE"`
   - Matches: `CORPORATE\john`
   - Doesn't match: `CORPORATE_LOCAL\john`

2. **Suffix**: Ends with pattern
   - Pattern: `"example.com"`
   - Matches: `user@example.com`, `user@sub.example.com`
   - Doesn't match: `user@example.org`

3. **Regex**: Regular expression match
   - Pattern: `"^.*\\.example\\.com$"`
   - Matches: `user@sub.example.com`
   - Doesn't match: `user@example.com` (no subdomain)

### Username Formats

The proxy supports two standard username formats:

- **Suffix format**: `user@realm` (RFC 2865)
- **Prefix format**: `REALM\user` (Windows domain format)

### Realm Stripping

When `strip_realm` is enabled, the realm is removed before forwarding:

- `user@corp.example.com` → `user`
- `GUEST\john` → `john`

This is useful when the home server doesn't need the realm information.

### Load Balancing Strategies

Four load balancing strategies are available:

#### 1. Round Robin (round_robin)

Distributes requests evenly across all available servers in order.

**Use case**: Equal distribution when all servers have similar capacity

**Example**:

```json
{
  "strategy": "round_robin"
}
```

#### 2. Least Outstanding (least_outstanding)

Sends requests to the server with the fewest pending requests.

**Use case**: Optimal load distribution when servers have different capacities

**Example**:

```json
{
  "strategy": "least_outstanding"
}
```

#### 3. Failover (failover)

Uses the first server, falls back to subsequent servers if unavailable.

**Use case**: Primary/backup server configuration

**Example**:

```json
{
  "strategy": "failover",
  "servers": [
    {
      "address": "primary.example.com:1812",
      "secret": "secret1"
    },
    {
      "address": "backup.example.com:1812",
      "secret": "secret2"
    }
  ]
}
```

#### 4. Random (random)

Randomly selects from available servers.

**Use case**: Simple load distribution with unpredictable patterns

**Example**:

```json
{
  "strategy": "random"
}
```

### Retry and Timeout Handling

The proxy includes automatic retry logic:

```json
{
  "retry": {
    "max_retries": 3,
    "retry_interval": 5,
    "failover_on_timeout": true
  }
}
```

**Parameters**:

- `max_retries`: Maximum number of retry attempts (default: 3)
- `retry_interval`: Seconds between retry checks (default: 5)
- `failover_on_timeout`: Whether to try different server on timeout (default: true)

**Behavior**:

1. Request times out after `proxy_timeout` seconds
2. If `failover_on_timeout` is true, retry with different server from pool
3. After `max_retries` exhausted, send Access-Reject to NAS
4. NAS receives reject with message: "Request timed out after maximum retries"
5. Over a RadSec home server a timed-out request is **not** retransmitted on the connection it was sent on (RFC 6613 §2.6.1); it is resent only if the link is down or has since reconnected, and otherwise waits for the reject above

### Proxy Loop Detection

The proxy implements RFC 2865 loop detection using Proxy-State attributes:

- Maximum 5 Proxy-State attributes allowed
- Exceeding limit triggers ProxyLoop error
- Prevents infinite forwarding loops in proxy chains

## Security Considerations

### Shared Secrets

Each home server has its own shared secret. The proxy:

1. Receives request from NAS (authenticated with NAS secret)
2. Forwards request to home server (authenticated with home server secret)
3. Receives response from home server
4. Recalculates response authenticator with NAS secret
5. Forwards response to NAS

This ensures proper authentication at each hop.

### RadSec Hop

For a `transport: "radsec"` home server the shared secret is the fixed `"radsec"` of RFC 6614 §2.3 and authenticates nothing: anyone on the TLS connection is the home server. The security of that hop is the TLS layer —

- mutual X.509 authentication (the proxy's client certificate, the home server's chain against `tls.ca_path` and `tls.server_name`, optional revocation checking);
- TLS 1.3 with ML-KEM-1024 and AES-256-GCM-SHA384 only, re-checked after every handshake, resumption disabled;
- no fallback to UDP: a link that cannot be established stays down and the NAS gets the signed timeout reject;
- responses attributed to the home server by the authenticated connection, never by source address; the Response Authenticator under `"radsec"` is still verified before any attribute is touched, and a failure closes the connection (RFC 6613 §2.6.4).

Keep the proxy's client key readable by the server process only (`chmod 600`); it is read when the link is built and never logged.

### Request Correlation

Requests are correlated using Proxy-State attributes:

- Unique 16-byte key (timestamp + counter)
- Prevents response spoofing
- Timeout protection via TTL

### Client Authorization

The proxy respects the main server's client authorization:

- NAS must be in authorized clients list
- Per-client secrets supported
- IP-based authorization

## Troubleshooting

### No Response from Home Server

**Symptoms**: Request times out, retry manager sends Access-Reject

**Solutions**:

1. Verify home server address and port
2. Check firewall rules (allow UDP 1812/1813)
3. Verify shared secret matches
4. Check home server is running and responsive

### RadSec Link Not Established

**Symptoms**: No `RadSec link established` line for the home server; `RadSec link lost` or a `warn` with a TLS error repeating with growing intervals; requests to that pool end in the timeout Access-Reject

**Solutions**:

1. The home server must offer TLS 1.3 with the `MLKEM1024` group and `TLS_AES_256_GCM_SHA384` (FreeRADIUS: `tls_min_version = "1.3"`, `ecdh_curve = "MLKEM1024"` in the listener's `tls` block, OpenSSL ≥ 3.5); a "no suitable key share" on the home server means the group is missing
2. Its certificate must chain to `tls.ca_path`, carry EKU serverAuth and be valid for `tls.server_name`
3. It must accept the proxy's client certificate (`tls.cert_path`) and have the proxy as a TLS client with secret `radsec`
4. With `tls.revocation`: the CRL must cover the home server's issuer and be fresh, or the responder reachable; the default policy fails closed
5. Allow TCP 2083 (or the configured port) through the firewall
6. If the link is established but drops every `interval`: the home server's idle timeout is shorter than `health_check.interval`; lower the interval

### Wrong Routing Decisions

**Symptoms**: Requests routed to wrong pool or rejected

**Solutions**:

1. Check realm match patterns
2. Verify realm extraction (check logs for extracted realm)
3. Test regex patterns independently
4. Check default_realm setting

### High Latency

**Symptoms**: Slow authentication responses

**Solutions**:

1. Reduce `proxy_timeout` if home servers respond quickly
2. Use `least_outstanding` strategy for better load distribution
3. Add more home servers to pool
4. Check network latency to home servers

### Cache Full Errors

**Symptoms**: ProxyError::CacheFull in logs

**Solutions**:

1. Increase `max_outstanding` setting
2. Reduce `proxy_timeout` (requests clear faster)
3. Check for slow home servers causing backlog

## Monitoring

### Runtime Statistics API

Get real-time proxy statistics via the `get_proxy_stats()` method:

```rust
if let Some(stats) = server.get_proxy_stats() {
    println!("Total Requests: {}", stats.total_requests);
    println!("Total Responses: {}", stats.total_responses);
    println!("Total Outstanding: {}", stats.total_outstanding);

    // Per-pool statistics
    for pool in &stats.pools {
        println!("Pool {}: {} servers ({} available)",
            pool.name, pool.total_servers, pool.available_servers);

        // Per-server statistics
        for server in &pool.servers {
            println!("  {}: {} req, {} resp, {} outstanding ({})",
                server.name, server.requests_sent,
                server.responses_received, server.outstanding,
                server.state);
        }
    }

    // Export as JSON
    let json = stats.to_json()?;
}
```

**ProxyStats Structure**:

- `total_requests`: Total requests across all pools
- `total_responses`: Total responses across all pools
- `total_outstanding`: Total outstanding requests
- `total_timeouts`: Total timeouts across all servers
- `pools`: Array of pool statistics

**Per-Pool Statistics**:

- Pool name, strategy, server counts
- Total requests/responses/outstanding for the pool
- Array of server statistics

**Per-Server Statistics**:

- Server name, address, state (Up/Down/Dead)
- Requests sent, responses received, timeouts, outstanding
- Time since last response
- Health check statistics (total checks, successes, failures, consecutive counts)

*Available in v0.7.3+*

### Home Server Statistics

Each home server tracks operational statistics:

```rust
pub struct HomeServerStats {
    pub requests_sent: u64,
    pub responses_received: u64,
    pub timeouts: u64,
    pub outstanding: u64,
}
```

### Pool Statistics

Each pool provides aggregate statistics:

```rust
pub struct PoolStats {
    pub total_servers: usize,
    pub available_servers: usize,
    pub servers_with_capacity: usize,
    pub total_requests: u64,
    pub total_responses: u64,
    pub total_outstanding: u64,
}
```

### Logging

The proxy logs routing decisions and errors:

```
INFO  Routing decision: Proxy to corporate_pool
DEBUG Selected home server: corporate-radius-1
INFO  Request forwarded to home server
INFO  Response forwarded to NAS
WARN  Max retries exceeded, sending Access-Reject
INFO  RadSec link established server=home-radius-1 address=10.0.1.10:2083 version=Some(TLSv1_3) suite=Some(TLS13_AES_256_GCM_SHA384) group=Some(MLKEM1024)
INFO  RadSec link lost server=home-radius-1 address=10.0.1.10:2083 reason="closed by peer" dropped_frames=0
```

## Advanced Configuration

### Multiple Realms to Same Pool

```json
{
  "realms": [
    {
      "name": "corp_suffix",
      "match": {"type": "suffix", "pattern": "corp.example.com"},
      "pool": "corporate_pool"
    },
    {
      "name": "corp_prefix",
      "match": {"type": "exact", "pattern": "CORP"},
      "pool": "corporate_pool"
    }
  ]
}
```

### Regex with Subdomains

```json
{
  "match": {
    "type": "regex",
    "pattern": "^.*\\.(us|eu)\\.example\\.com$"
  }
}
```

Matches: `user@office.us.example.com`, `user@dc.eu.example.com`

### Health Checks

Automatic health monitoring using RFC 5997 Status-Server packets:

```json
{
  "health_check": {
    "enabled": true,
    "interval": 30,
    "timeout": 10,
    "failures_before_down": 3,
    "successes_before_up": 2
  }
}
```

**Parameters**:

- `enabled`: Enable health checking (default: true). **Required** (`true`) when any home server uses `transport: "radsec"`: the probe is the RFC 6613 §2.6 watchdog of that connection, and the configuration is rejected otherwise
- `interval`: Health check interval in seconds (default: 30). For RadSec home servers keep it below the home server's TLS idle timeout so the probe keeps the connection warm
- `timeout`: Health check timeout in seconds (default: 10)
- `failures_before_down`: Consecutive failures before marking server Down (default: 3)
- `successes_before_up`: Consecutive successes before marking server Up (default: 2)

**How It Works**:

1. Background task sends Status-Server (RFC 5997) packets at configured intervals, each with a random Request Authenticator and a Message-Authenticator computed under that home server's secret (the fixed `"radsec"` for a RadSec home server). Over UDP each probe uses an ephemeral socket and a random Identifier; over RadSec the probe travels on the home server's persistent TLS connection with an Identifier that is free on that connection
2. Counts the probe as healthy only if the reply carries the same Identifier, its Response Authenticator (and Message-Authenticator, when present) verifies under the home server's secret, and its code is Access-Accept, Accounting-Response (accounting-port home servers) or Access-Reject (which RFC 5997 §4.2 permits). Over UDP the reply must also come from the probed address; over RadSec the TLS peer authentication stands in for that check. Any other datagram is skipped and the probe fails only when its deadline passes without a verified reply
3. Tracks consecutive failures and successes per server
4. Automatically transitions server states: Up ↔ Down ↔ Dead
5. Down/Dead servers can recover automatically after enough successful checks
6. Atomic statistics tracking (lock-free) for all health checks
7. On a RadSec link the probe is also the connection's **application-layer watchdog** (RFC 6613 §2.6, RFC 3539 §3.4, RFC 5997 §4.3): a reply whose Response Authenticator or Message-Authenticator fails closes the connection, and two consecutive unanswered probes close it too; the link then reconnects with backoff. A link that is down fails the probe immediately

**State Transitions**:

- **Up → Down**: After N consecutive health check failures
- **Down → Up**: After M consecutive health check successes
- **Dead → Up**: Dead servers can also recover if health checks succeed

*Available in v0.7.1+*

## Performance

### Benchmarks

Tested configuration:

- 3 home servers in pool
- Round-robin strategy
- 1000 max outstanding requests

Results:

- 5000 req/s sustained throughput
- <2ms proxy overhead
- 99.9% success rate with proper home server capacity

### Tuning Recommendations

**High Throughput**:

```json
{
  "cache_ttl": 300,
  "max_outstanding": 10000,
  "proxy_timeout": 5,
  "retry": {
    "max_retries": 2,
    "retry_interval": 2
  }
}
```

**High Availability**:

```json
{
  "proxy_timeout": 10,
  "retry": {
    "max_retries": 5,
    "retry_interval": 3,
    "failover_on_timeout": true
  }
}
```

## RFC Compliance

The proxy implementation follows:

- **RFC 2865**: RADIUS protocol (Proxy-State handling, User-Password re-encryption per hop)
- **RFC 2548 / RFC 2868 / RFC 3579**: MS-MPPE keys, Tunnel-Password and Message-Authenticator re-keyed per hop
- **RFC 5997**: Status-Server probes to home servers; Status-Server to the proxy answered locally, never forwarded
- **RFC 6614**: RadSec to `transport: "radsec"` home servers (TLS 1.3, mutual certificates, fixed `"radsec"` secret, `Length`-delimited packets, CoA/Disconnect NAK with Error-Cause 406)
- **RFC 6613 / RFC 3539**: connection rules on those links (no retransmission over a connection, close on protocol violation, Status-Server watchdog, Identifier tracking); NAS Identifiers are forwarded unchanged (known gap, RFC 6613 §2.6)

See [RFC-COMPLIANCE.md](../protocol/RFC-COMPLIANCE.md) for the statement of record.

## See Also

- [Configuration Reference](../configuration/server.md)
- [Examples](../examples/)
- [API Documentation](../api/overview.md)
