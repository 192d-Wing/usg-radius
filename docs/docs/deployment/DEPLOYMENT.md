# USG RADIUS Deployment Guide

USG RADIUS is deployed **only** on Kubernetes (k3s or k8s) with the Cilium CNI. The server
runs as a stateless `Deployment`; scaling and availability come from the ReplicaSet plus an
L3 anycast VIP advertised by Cilium's BGP control plane. Compose-based deployments, systemd
units, external load balancers, and bare-metal installs are no longer supported.

This guide covers the server's CLI and configuration. For deployment mechanics see the
canonical reference [`deploy/README.md`](../../../deploy/README.md), the
[Quick Start](./QUICKSTART.md), and [Availability & Scaling](./HIGH_AVAILABILITY.md).

## Table of Contents

- [Command Line Interface](#command-line-interface)
- [Deploying on Kubernetes](#deploying-on-kubernetes)
- [Configuration](#configuration)
- [Security Hardening](#security-hardening)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Command Line Interface

The container image is `usg-radius-server` and the binary inside it is `usg-radius`. The
same binary is used for local development and validation.

### Usage

```text
usg-radius [OPTIONS] [CONFIG]
```

### Arguments

- `CONFIG` - Path to configuration file (default: `config.json`)

### Options

- `-v, --validate` - Validate configuration and exit (doesn't start server)
- `-V, --version` - Print version information and exit
- `-h, --help` - Print help message

### Examples

**Check version:**

```bash
usg-radius --version
```

**Validate configuration:**

```bash
usg-radius --validate /etc/radius/config.json
```

**Output:**

```text
✓ Configuration validated successfully!

Configuration summary:
  Listen: :::1812
  Clients: 4
  Users: 2
  Log level: info
  Strict RFC compliance: true
  Audit log: /var/log/radius/audit.log

Authorized clients:
  ✓ 192.168.1.0/24 - Internal Network
  ✓ 10.0.0.1 - VPN Gateway
  ✓ 172.16.0.0/16 - Wireless Controllers
  ✗ 203.0.113.100 - Remote NAS (disabled for testing)
```

**Start server with a config file:**

```bash
usg-radius /etc/radius/config.json
```

For local development you can run the same binary via Cargo:

```bash
cargo run --release -- --validate config.json
cargo run --release -- config.json
```

---

## Deploying on Kubernetes

The full flow is documented in [`deploy/README.md`](../../../deploy/README.md). In brief:

1. Install Cilium with the provided values
   ([`deploy/cilium/values-k3s.yaml`](../../../deploy/cilium/values-k3s.yaml) or
   [`values-k8s.yaml`](../../../deploy/cilium/values-k8s.yaml)) — these enable DSR mode
   (no SNAT), the BGP control plane, and dual-stack.
2. Build and push the multi-arch image:

   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 \
     -t <registry>/usg-radius-server:<tag> --push .
   ```

3. Edit the overlay (`deploy/overlays/k3s` or `deploy/overlays/k8s`): image, VIP CIDRs,
   BGP ASNs/peers, and the RADIUS config Secret.
4. Apply:

   ```bash
   kubectl apply -k deploy/overlays/k8s    # or deploy/overlays/k3s
   ```

Why the networking settings matter: RADIUS authorizes clients by **source IP**, so the NAS
address must reach the server unchanged. `externalTrafficPolicy: Local` preserves the
source IP and makes Cilium advertise the VIP only from nodes with a Ready pod, and Cilium
**DSR mode (no SNAT)** keeps the original source IP on the load-balanced path. See
[Availability & Scaling](./HIGH_AVAILABILITY.md) for the full model.

### Ports

| Port | Proto | Purpose                | Exposed on VIP |
|------|-------|------------------------|----------------|
| 1812 | UDP   | RADIUS authentication  | yes            |
| 1813 | UDP   | RADIUS accounting      | yes            |
| 2812 | TCP   | health (`/health/*`)   | no (ClusterIP) |
| 3812 | TCP   | metrics (`/metrics`)   | no (ClusterIP) |

Health and metrics endpoints are served by the binary when built with the `observability`
cargo feature.

---

## Configuration

Configuration is supplied as a JSON file, mounted into the pod from a Kubernetes Secret.
Generate strong secrets and never commit them to version control:

```bash
openssl rand -base64 32
```

Validate any config before rolling it out:

```bash
usg-radius --validate config.json
```

**Rate limiting** (per-pod; there is no cluster-wide rate limiting in the stateless model):

```json
{
  "rate_limit_per_client_rps": 100,
  "rate_limit_per_client_burst": 200,
  "rate_limit_global_rps": 1000,
  "rate_limit_global_burst": 2000
}
```

**Hardening options**:

```json
{
  "strict_rfc_compliance": true,
  "request_cache_ttl": 60,
  "audit_log_path": "/var/log/radius/audit.log"
}
```

Secrets can be injected via environment variables referenced in the config (e.g.
`RADIUS_SECRET`), sourced from a Kubernetes Secret.

---

## Security Hardening

### Network Security

- Restrict the VIP at the upstream router / firewall so only legitimate RADIUS clients
  (NAS devices) can reach UDP 1812/1813.
- Keep health (2812) and metrics (3812) endpoints internal (ClusterIP only) — they are not
  exposed on the VIP.
- Deploy in a management network segment; never expose RADIUS to the public internet.
- Use Kubernetes `NetworkPolicy` to limit which namespaces/pods can reach the health and
  metrics ports.

### Application Security

- Enable `strict_rfc_compliance`.
- Tune per-client and global rate limits to mitigate DoS.
- Use unique, strong shared secrets per client; rotate regularly.
- Store all secrets in Kubernetes Secrets (or an external secret manager), not in images.

### Image Security

The image is built on an Iron Bank hardened Alpine base via cargo-chef and is multi-arch
(amd64/arm64). Pin image tags by digest in the overlay and scan images in your registry.

---

## Monitoring

### Health Checks

Kubernetes liveness/readiness probes use the health endpoints on TCP 2812:

```bash
curl http://<pod>:2812/health/live
curl http://<pod>:2812/health/ready
```

Because VIP advertisement is gated on pod readiness, a pod failing readiness both stops
receiving traffic and causes its node to withdraw the anycast route when it was the last
Ready pod there.

### Metrics

Prometheus metrics are exposed on TCP 3812 at `/metrics`:

```bash
curl http://<pod>:3812/metrics
```

An optional Grafana dashboard ships under `deploy/monitoring/`. Key signals to track:
authentication success/failure rate, rate-limit rejections, request latency, and per-pod
CPU/memory.

### Logs

The server emits structured logs to stdout; collect them with your cluster's log pipeline:

```bash
kubectl -n radius logs -f deploy/usg-radius-server
```

---

## Troubleshooting

### Pods not receiving traffic

- Confirm the Service has a dual-stack EXTERNAL-IP: `kubectl -n radius get svc usg-radius-server -o wide`.
- Confirm BGP is up and the VIP is advertised: `cilium bgp peers` and
  `cilium bgp routes advertised ipv4 unicast` / `ipv6 unicast`.
- Confirm at least one node has a Ready radius pod (advertisement is node-selective via
  `externalTrafficPolicy: Local`).

### Authentication failures

- Verify the client's **source IP** matches a configured client CIDR — with ETP=Local +
  DSR the server sees the real NAS IP. If you see a node/pod IP in the logs, DSR/ETP is
  misconfigured (check `cilium/values-*.yaml` and the Service annotation
  `service.cilium.io/forwarding-mode: dsr`).
- Verify the shared secret matches and the user exists in the configured backend.

### Rate limiting

```
Rate limit exceeded for client X.X.X.X
```

Adjust `rate_limit_per_client_rps` (per pod) or investigate a possible DoS. Remember limits
are enforced per pod, so effective per-client capacity scales with replica count and the
router's per-flow hashing.

### Config not found / invalid

Validate and check the mounted Secret:

```bash
usg-radius --validate /etc/radius/config.json
kubectl -n radius describe pod <pod>   # check volume mounts and env
```

---

## Support

- **Documentation**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius
- **Issues**: https://github.com/192d-Cyberspace-Control-Squadron/usg-radius/issues
- **Deployment reference**: [`deploy/README.md`](../../../deploy/README.md)
- **RFC 2865**: https://tools.ietf.org/html/rfc2865
