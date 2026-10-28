# RADIUS Proxy

The usg-radius server includes a full-featured RADIUS proxy implementation for forwarding authentication and accounting requests to upstream RADIUS servers.

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
4. **HomeServer**: Upstream RADIUS server configuration
5. **ProxyHandler**: Request forwarding and response correlation
6. **ProxyCache**: Tracks in-flight requests using Proxy-State attributes
7. **RetryManager**: Handles timeouts and retry logic

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

- `enabled`: Enable health checking (default: true)
- `interval`: Health check interval in seconds (default: 30)
- `timeout`: Health check timeout in seconds (default: 10)
- `failures_before_down`: Consecutive failures before marking server Down (default: 3)
- `successes_before_up`: Consecutive successes before marking server Up (default: 2)

**How It Works**:

1. Background task sends Status-Server (RFC 5997) packets at configured intervals, each with a random Request Authenticator and a Message-Authenticator computed under that home server's secret, from an ephemeral socket per probe
2. Counts the probe as healthy only if the reply comes from the probed address with the same Identifier, its Response Authenticator (and Message-Authenticator, when present) verifies under the home server's secret, and its code is Access-Accept, Accounting-Response (accounting-port home servers) or Access-Reject (which RFC 5997 §4.2 permits); any other datagram is skipped and the probe fails only when its deadline passes without a verified reply
3. Tracks consecutive failures and successes per server
4. Automatically transitions server states: Up ↔ Down ↔ Dead
5. Down/Dead servers can recover automatically after enough successful checks
6. Atomic statistics tracking (lock-free) for all health checks

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

- **RFC 2865**: RADIUS protocol (Proxy-State handling)
- **RFC 2866**: RADIUS Accounting
- **RFC 5997**: Status-Server extension

## See Also

- [Configuration Reference](../configuration/server.md)
- [Examples](../examples/)
- [API Documentation](../api/overview.md)
