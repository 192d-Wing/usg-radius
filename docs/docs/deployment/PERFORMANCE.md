# Performance Guide

This document covers performance characteristics, tuning, and optimization for USG RADIUS.

## Table of Contents

1. [Performance Overview](#performance-overview)
2. [Benchmarking](#benchmarking)
3. [Tuning Guide](#tuning-guide)
4. [Scaling Strategies](#scaling-strategies)
5. [Performance Troubleshooting](#performance-troubleshooting)

---

## Performance Overview

### Baseline Performance (Single Server)

Tested on: AWS c5.2xlarge (8 vCPUs, 16 GB RAM)

| Metric | Simple Auth | PostgreSQL | LDAP | EAP-TLS |
|--------|-------------|------------|------|---------|
| **Throughput** | 50,000 RPS | 25,000 RPS | 20,000 RPS | 15,000 RPS |
| **Latency (P50)** | 0.2 ms | 0.5 ms | 1.0 ms | 2.0 ms |
| **Latency (P99)** | 0.8 ms | 2.5 ms | 5.0 ms | 8.0 ms |
| **Memory** | 50 MB | 100 MB | 80 MB | 120 MB |
| **CPU (8 cores)** | 20% | 45% | 40% | 60% |
| **Cache Hit Rate** | 95% | 92% | 90% | N/A |

### Scaling Across Replicas

The server is stateless, so cluster throughput scales by adding replicas to the Kubernetes
Deployment. Inbound RADIUS traffic is distributed across Ready pods via the Cilium BGP L3
anycast VIP (ECMP at the upstream router). There is no shared-state backend and therefore
no cross-pod consistency window or backend RTT to account for — aggregate throughput is
approximately the per-pod figure above multiplied by the replica count, bounded by the
router's ECMP fan-out and per-flow hashing. See
[HIGH_AVAILABILITY.md](./HIGH_AVAILABILITY.md).

### Comparison with FreeRADIUS

| Feature | FreeRADIUS 3.2 | USG RADIUS v0.6.0 | Improvement |
|---------|----------------|-------------------|-------------|
| Max RPS (PAP) | ~10,000 | ~50,000 | **5x faster** |
| Memory (1M requests) | 250 MB | 100 MB | **2.5x less** |
| P99 Latency | 5ms | 0.8ms | **6x faster** |
| Concurrent Connections | 10,000 | 100,000 | **10x more** |
| Container Size | N/A | 25 MB | Native container support |

---

## Benchmarking

### Running Built-in Benchmarks

```bash
# Compile-time benchmarks (Criterion)
cargo bench --bench radius_server_bench

# Results saved to: target/criterion/
# View HTML report: target/criterion/report/index.html
```

**Example Output**:
```
packet_encode/10_attrs  time: [2.156 µs 2.178 µs 2.201 µs]
packet_decode/10_attrs  time: [1.845 µs 1.862 µs 1.880 µs]
chap_verify/verify_valid time: [8.234 µs 8.301 µs 8.376 µs]
request_cache/is_duplicate_cached time: [125.32 ns 127.89 ns 130.87 ns]
rate_limiter/check_rate_limit time: [234.56 ns 238.91 ns 243.78 ns]
```

### Load Testing

#### Basic Load Test

```bash
cargo run --release --bin radius_load_test -- \
  --server 127.0.0.1:1812 \
  --secret testing123 \
  --clients 100 \
  --duration 60 \
  --rps 100
```

**Example Output**:
```
=== Load Test Results ===
Duration: 60.00s

Requests:
  Sent:     600000
  Received: 599850
  Timeouts: 150
  Errors:   0

Responses:
  Accept:   599850 (100.0%)
  Reject:   0 (0.0%)

Performance:
  RPS:      9997.50
  Success:  99.98%

Throughput:
  Sent:     4.32 Mbps (32400000 bytes)
  Received: 1.28 Mbps (9597600 bytes)

Latency (microseconds):
  Min:  120
  P50:  185
  P95:  312
  P99:  487
  Max:  1250
  Avg:  202.34
```

#### Stress Testing

```bash
# Find maximum RPS capacity
for rps in 100 500 1000 5000 10000 50000; do
  echo "Testing $rps RPS..."
  cargo run --release --bin radius_load_test -- \
    --server 127.0.0.1:1812 \
    --secret testing123 \
    --clients 10 \
    --duration 10 \
    --rps $rps \
    | grep -E "(RPS|Timeouts|P99)"
done
```

### Profiling

#### CPU Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Profile the server
sudo cargo flamegraph --bin usg-radius -- config.json

# Generate interactive flamegraph
# Opens: flamegraph.svg
```

#### Memory Profiling

```bash
# Install valgrind
sudo apt-get install valgrind

# Run with memory profiling
valgrind --tool=massif --massif-out-file=massif.out \
  ./target/release/usg-radius config.json

# Analyze results
ms_print massif.out
```

#### Network Profiling

```bash
# Capture traffic
sudo tcpdump -i lo -w radius.pcap udp port 1812

# Analyze with tshark
tshark -r radius.pcap -q -z io,stat,1

# View in Wireshark
wireshark radius.pcap
```

---

## Tuning Guide

### 1. Operating System Tuning

#### File Descriptors

```bash
# /etc/security/limits.conf
radius soft nofile 65536
radius hard nofile 65536

# Verify
ulimit -n
```

#### Network Buffers

```bash
# /etc/sysctl.conf
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.udp_mem = 8388608 16777216 16777216

# Apply
sudo sysctl -p
```

#### CPU Affinity

```bash
# Pin RADIUS to specific cores for better cache locality
taskset -c 0-7 ./target/release/usg-radius config.json
```

### 2. Application Tuning

#### Request Cache

The server keeps an in-memory request cache for duplicate detection (per pod). Tune its
TTL to the RADIUS retransmit window:

```json
{
  "request_cache_ttl": 60,  // ⚡ Duplicate-detection window, in seconds
  "request_cache_max_entries": 10000
}
```

**Tuning Guidelines**:
- **request_cache_ttl**: match your NAS retransmit/timeout window (commonly 30–60s).
- **request_cache_max_entries**: cap to bound memory; size for your peak concurrent
  in-flight requests per pod.

#### Rate Limiting

```json
{
  "rate_limiting": {
    "per_client_limit": 100,    // ⚡ Requests per second
    "per_client_burst": 200,    // ⚡ Burst capacity
    "global_limit": 10000,      // ⚡ Total RPS
    "global_burst": 20000,
    "max_connections_per_client": 100,  // ⚡ Concurrent connections
    "max_bandwidth_per_client": 10485760,  // 10 MB/s
    "window_duration_secs": 1
  }
}
```

**Guidelines**:
- Set `per_client_limit` to prevent DoS
- Set `global_limit` slightly below max capacity
- `burst` should be 2x `limit` for normal traffic patterns

#### Connection Pooling

##### PostgreSQL

```json
{
  "auth_handler": {
    "type": "postgresql",
    "connection_string": "postgresql://radius:pass@localhost/radiusdb",
    "max_connections": 20,  // ⚡ Tune based on CPU cores
    "min_connections": 5,
    "acquire_timeout_secs": 10,
    "idle_timeout_secs": 300
  }
}
```

**Guidelines**:
- `max_connections` = number of CPU cores × 2-4
- Monitor with: `SELECT count(*) FROM pg_stat_activity;`

##### LDAP

```json
{
  "auth_handler": {
    "type": "ldap",
    "max_connections": 10,  // ⚡ Concurrent LDAP queries
    "acquire_timeout_secs": 10
  }
}
```

**Guidelines**:
- Start with 10, increase if seeing timeouts
- Monitor queue depth via metrics endpoint

### 3. Rust Compiler Optimizations

#### Profile-Guided Optimization (PGO)

```bash
# Step 1: Build with instrumentation
RUSTFLAGS="-Cprofile-generate=/tmp/pgo-data" \
  cargo build --release

# Step 2: Run typical workload
./target/release/usg-radius config.json &
cargo run --bin radius_load_test -- --duration 60
killall usg-radius

# Step 3: Merge profiling data
llvm-profdata merge -o /tmp/pgo-data/merged.profdata /tmp/pgo-data

# Step 4: Build with optimizations
RUSTFLAGS="-Cprofile-use=/tmp/pgo-data/merged.profdata" \
  cargo build --release

# Expected improvement: 10-20% faster
```

#### Link-Time Optimization (LTO)

Already enabled in `Cargo.toml`:
```toml
[profile.release]
opt-level = 3
lto = true          # ⚡ Whole-program optimization
codegen-units = 1   # ⚡ Better optimization, slower compile
strip = true        # ⚡ Smaller binary
```

#### CPU-Specific Optimizations

```bash
# Build for native CPU (uses AVX2, SSE4.2, etc.)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Expected improvement: 5-10% faster
```

### 4. Kubernetes Resource & Replica Tuning

Because the server is stateless, cluster tuning is mostly about right-sizing pods and
choosing a replica count. There is no shared-state backend or UDP load balancer to tune.

#### Resource Requests/Limits

Set CPU/memory requests close to observed steady-state usage (simple auth pods are tiny —
tens of MB) and headroom limits for bursts. Per-pod throughput tracks CPU; see the
[vertical scaling](#vertical-scaling-single-server) table for the per-pod RPS you can expect
at a given CPU allocation.

```yaml
resources:
  requests:
    cpu: "1"
    memory: "128Mi"
  limits:
    cpu: "4"
    memory: "512Mi"
```

#### Replica Count

```bash
kubectl -n radius scale deploy/usg-radius-server --replicas=4
```

Inbound traffic is spread across Ready pods by the Cilium BGP L3 anycast VIP (ECMP at the
router). Add replicas to add throughput; remove them to reclaim capacity. Keep enough
replicas that losing one node still leaves headroom.

#### Node-Level Tuning

Apply the [OS tuning](#1-operating-system-tuning) (file descriptors, UDP buffers) to the
nodes hosting radius pods, since each pod uses the host network path for UDP.

---

## Scaling Strategies

### Vertical Scaling (Single Server)

| Instance Type | vCPUs | RAM | Expected RPS | Use Case |
|---------------|-------|-----|--------------|----------|
| t3.small | 2 | 2 GB | 5,000 | Development |
| t3.medium | 2 | 4 GB | 10,000 | Small deployment |
| c5.large | 2 | 4 GB | 15,000 | Medium deployment |
| c5.xlarge | 4 | 8 GB | 30,000 | Large deployment |
| c5.2xlarge | 8 | 16 GB | 50,000 | Very large deployment |
| c5.4xlarge | 16 | 32 GB | 80,000 | Extreme load |

**Cost vs Performance**:
- Doubling vCPUs increases RPS by ~1.8x
- Memory is rarely the bottleneck (50-200 MB typical)
- Network bandwidth more important than CPU for simple auth

### Horizontal Scaling (Add Replicas)

The server is stateless, so scaling out is simply adding replicas to the Deployment.
Because there is no shared-state backend, scaling is near-linear — the limiting factors are
the upstream router's ECMP fan-out and per-flow hashing, plus per-node NIC/CPU.

```
1 replica  → ~50,000 RPS
2 replicas → ~100,000 RPS
3 replicas → ~150,000 RPS
4 replicas → ~200,000 RPS
```

```bash
kubectl -n radius scale deploy/usg-radius-server --replicas=4
```

**Notes**:
1. Spread replicas across nodes (anti-affinity) so each advertises the VIP and ECMP can
   balance across them.
2. There is no central bottleneck to shard — no shared-state store, no UDP load balancer.
3. Effective per-client distribution depends on the router's per-flow hash; a single NAS's
   traffic may pin to one path.

### Multi-Cluster / Geographic Distribution

```
        ┌──────────────┐
        │   GeoDNS     │
        └───────┬──────┘
                │
    ┌───────────┼───────────┐
    │           │           │
┌───▼────┐  ┌──▼─────┐  ┌──▼─────┐
│ US-East│  │ EU-West│  │ AP-East│
│ Cluster│  │ Cluster│  │ Cluster│
└────────┘  └────────┘  └────────┘
```

Run an independent stateless deployment (its own anycast VIP) per region. Because pods
share no state, regions are fully independent.

**Benefits**:
- Lower latency (NAS devices point at the nearest region's VIP)
- Higher availability (region-level failover)
- No cross-region state replication to manage

**Implementation**:
- Deploy `deploy/overlays/<env>` per cluster with a region-local VIP
- Use GeoDNS or per-region NAS configuration to route to the nearest VIP

---

## Performance Troubleshooting

### Symptom: High Latency

#### Diagnosis

```bash
# Check P99 latency
curl http://localhost:3812/metrics | grep radius_request_duration

# Run load test with detailed output
cargo run --bin radius_load_test -- --verbose
```

#### Causes & Solutions

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Backend Slow** | `curl /health` shows high DB latency | Optimize queries, add indexes, increase pool size |
| **Cache Misses** | Low cache hit rate in metrics | Increase cache TTL, add more memory |
| **Backend Network** | High RTT to PostgreSQL/LDAP | Place backends closer to the cluster |
| **CPU Bound** | `top` shows 100% CPU | Larger CPU limits or add replicas |

### Symptom: Low Throughput

#### Diagnosis

```bash
# Check request rate
watch -n 1 'curl -s http://localhost:3812/metrics | grep radius_requests_total'

# Monitor resource usage
htop
```

#### Causes & Solutions

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Rate Limiting** | Metrics show rejected requests | Increase rate limits in config |
| **Connection Pool Exhausted** | Timeouts in logs | Increase `max_connections` |
| **File Descriptors** | `Too many open files` error | Increase ulimit |
| **Memory** | OOM killer logs | Add more RAM or reduce cache size |
| **Network Bandwidth** | `iftop` shows saturation | Upgrade network or add nodes |

### Symptom: Memory Leak

#### Diagnosis

```bash
# Monitor memory over time
while true; do
  curl -s http://localhost:2812/health | jq '.memory_mb'
  sleep 60
done

# Profile with Valgrind
valgrind --leak-check=full ./target/release/usg-radius config.json
```

#### Causes & Solutions

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Cache Growth** | Memory increases linearly | Set max cache size, cleanup expired entries |
| **Connection Leaks** | Open connections in `lsof` | Check backend connection management |
| **Session Storage** | EAP sessions not cleaned up | Reduce session timeout, enable cleanup |

### Symptom: Backend Timeouts

#### Diagnosis

```bash
# Check backend health
curl http://localhost:2812/health | jq '.backend'

# Test backend directly
# PostgreSQL
psql -U radius -h localhost -d radiusdb -c "SELECT 1;"

# LDAP
ldapsearch -H ldaps://ldap.example.com -D bind_dn -w password -b base_dn "(uid=test)"
```

#### Solutions

1. **Increase timeouts**:
   ```json
   {
     "auth_handler": {
       "connection_timeout_ms": 5000,
       "acquire_timeout_secs": 10
     }
   }
   ```

2. **Add backend redundancy**:
   ```json
   {
     "ldap": {
       "urls": [
         "ldaps://ldap1.example.com:636",
         "ldaps://ldap2.example.com:636"
       ]
     }
   }
   ```

3. **Monitor backend performance**:
   ```bash
   # PostgreSQL slow queries
   SELECT query, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;
   ```

---

## Performance Best Practices

### ✅ Do

1. **Run multiple replicas in production**: spreads load and survives node/pod loss
2. **Use connection pooling**: Reuse connections to backends
3. **Monitor metrics**: Track RPS, latency, cache hit rate
4. **Profile before optimizing**: Measure to find real bottlenecks
5. **Test at scale**: Load test with realistic traffic patterns
6. **Tune cache TTL**: Balance consistency and performance
7. **Use appropriate auth method**: Simple > PostgreSQL > LDAP > EAP-TLS

### ❌ Don't

1. **Don't skip benchmarking**: Assumptions lead to poor design
2. **Don't over-provision**: Start small, scale up based on metrics
3. **Don't disable rate limiting**: Protect against DoS
4. **Don't ignore logs**: Early warnings prevent outages
5. **Don't use DEBUG in production**: Severe performance impact
6. **Don't skip OS tuning**: 10-30% performance gain for free

---

## Performance Monitoring

### Key Metrics to Track

| Metric | Target | Alert Threshold | Action |
|--------|--------|-----------------|--------|
| **RPS** | Varies | <80% capacity | Scale up |
| **P99 Latency** | <5ms | >10ms | Investigate |
| **Cache Hit Rate** | >90% | <80% | Increase TTL |
| **Backend Latency** | <2ms | >5ms | Optimize queries |
| **Memory Usage** | <50% | >80% | Add RAM |
| **CPU Usage** | <70% | >90% | Add cores |
| **Error Rate** | <0.01% | >0.1% | Incident response |

### Grafana Dashboard

Example Prometheus queries:

```promql
# Request rate
rate(radius_requests_total[5m])

# Latency percentiles
histogram_quantile(0.99, rate(radius_request_duration_seconds_bucket[5m]))

# Cache hit rate
radius_cache_hits_total / (radius_cache_hits_total + radius_cache_misses_total)

# Per-pod request rate (split by pod)
sum by (pod) (rate(radius_requests_total[5m]))
```

---

**Next Steps**: See [QUICKSTART.md](./QUICKSTART.md) to deploy and [HIGH_AVAILABILITY.md](./HIGH_AVAILABILITY.md) for the availability and scaling model.
