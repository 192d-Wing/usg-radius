# Quick Start Guide

This guide gets you from zero to a running, stateless USG RADIUS deployment on Kubernetes
(k3s or k8s) with a Cilium BGP L3 anycast VIP. Kubernetes + Cilium is the only supported
deployment path. The canonical reference is [`deploy/README.md`](../../../deploy/README.md).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deploy to Kubernetes](#deploy-to-kubernetes)
3. [Verify](#verify)
4. [Test Authentication](#test-authentication)
5. [Authentication Backends](#authentication-backends)
6. [Next Steps](#next-steps)

---

## Prerequisites

- A **k3s** or **k8s** cluster with the **Cilium** CNI.
- `kubectl` and `cilium` CLIs configured against the cluster.
- A container registry reachable by the cluster, plus `docker buildx` for multi-arch builds.
- An upstream router peering BGP with the nodes (for the anycast VIP), and a VIP CIDR
  (one IPv4 + one IPv6 prefix) you can advertise.
- **Rust 1.75+** only if you want to build/test the binary locally (see
  [installation.md](../getting-started/installation.md)).

---

## Deploy to Kubernetes

### 1. Install Cilium with the provided values

Install (or reconfigure) Cilium using the values for your distribution. These enable
DSR mode (no SNAT), the BGP control plane, and dual-stack:

```bash
helm upgrade --install cilium cilium/cilium -n kube-system \
  -f deploy/cilium/values-k3s.yaml    # or deploy/cilium/values-k8s.yaml
```

See [`deploy/overlays/k3s/README.md`](../../../deploy/overlays/k3s) or
[`deploy/overlays/k8s/README.md`](../../../deploy/overlays/k8s) for distribution-specific
notes.

### 2. Build and push the image (multi-arch)

The image is `usg-radius-server` (binary: `usg-radius`), built with the `observability`
feature for health and metrics endpoints:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t <registry>/usg-radius-server:<tag> --push .
```

### 3. Edit the overlay

In `deploy/overlays/<env>` set the image reference, VIP CIDRs, and BGP ASNs/peers, and
replace the placeholder RADIUS config Secret in `deploy/base/radius-config.secret.yaml`
(clients, secrets, users / auth backend).

### 4. Apply

```bash
kubectl apply -k deploy/overlays/k8s     # or deploy/overlays/k3s
```

---

## Verify

```bash
# Dual-stack VIP assigned (IPv4 + IPv6 EXTERNAL-IP):
kubectl -n radius get svc usg-radius-server -o wide

# BGP is up and the VIP is advertised from pod-bearing nodes:
cilium bgp peers
cilium bgp routes advertised ipv4 unicast
cilium bgp routes advertised ipv6 unicast

# Health (per pod, TCP 2812):
kubectl -n radius port-forward deploy/usg-radius-server 2812:2812
curl http://localhost:2812/health/ready
```

Node-selective advertisement check: cordon and delete the radius pod on one node — that
node withdraws the VIP route while pod-bearing nodes keep advertising it.

---

## Test Authentication

From a host whose source IP matches a configured client, send an Access-Request to the VIP:

```bash
# radtest from freeradius-utils
radtest alice password123 <VIP> 0 testing123

# Expected:
# Received Access-Accept ...
```

Because of `externalTrafficPolicy: Local` + Cilium DSR, the server logs the **real NAS
source IP** (not a node/pod IP), which is what client authorization is matched against.

---

## Authentication Backends

The auth backend is configured in the RADIUS config Secret. Common options:

### PostgreSQL

```json
{
  "auth_handler": {
    "type": "postgresql",
    "connection_string": "postgresql://radius:password@db/radiusdb",
    "users_query": "SELECT password, attributes FROM radius_users WHERE username = $1 AND enabled = true",
    "password_column": "password",
    "password_type": "bcrypt"
  }
}
```

See the schemas in [`examples/postgres_schema.sql`](../../../examples/postgres_schema.sql).

### LDAP / Active Directory

```json
{
  "auth_handler": {
    "type": "ldap",
    "urls": ["ldaps://dc1.example.com:636", "ldaps://dc2.example.com:636"],
    "base_dn": "DC=example,DC=com",
    "bind_dn": "CN=radius,CN=Users,DC=example,DC=com",
    "bind_password": "service_account_password",
    "search_filter": "(&(objectClass=user)(sAMAccountName={username}))",
    "group_attribute": "memberOf",
    "max_connections": 10
  }
}
```

### EAP-TLS (certificate-based)

```json
{
  "auth_handler": {
    "type": "eap",
    "eap_methods": ["TLS"],
    "tls_config": {
      "ca_cert_path": "/etc/radius/certs/ca.pem",
      "server_cert_path": "/etc/radius/certs/server.pem",
      "server_key_path": "/etc/radius/certs/server-key.pem",
      "client_cert_required": true,
      "crl_check_enabled": true,
      "crl_path": "/etc/radius/certs/crl.pem"
    }
  }
}
```

Mount certificates and CRLs as additional Secrets/ConfigMaps in your overlay.

---

## Next Steps

- **Scale**: increase the Deployment's replica count to add throughput — pods are
  stateless and scale independently. See [HIGH_AVAILABILITY.md](./HIGH_AVAILABILITY.md).
- **Observability**: scrape `/metrics` (TCP 3812) with Prometheus; an optional Grafana
  dashboard ships under `deploy/monitoring/`.
- **Migrating from FreeRADIUS**: see [FREERADIUS_MIGRATION.md](./FREERADIUS_MIGRATION.md).
- **Tuning & benchmarking**: see [PERFORMANCE.md](./PERFORMANCE.md).
- **Full deployment reference**: [`deploy/README.md`](../../../deploy/README.md).
