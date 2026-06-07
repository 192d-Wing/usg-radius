# USG RADIUS — Kubernetes deployment (k3s / k8s + Cilium)

This is the **only** supported deployment path. The RADIUS server runs as a
stateless Kubernetes `Deployment`; scaling and availability come from the
ReplicaSet plus an **L3 anycast VIP** advertised by **Cilium's BGP control plane**.
The VIP is **dual-stack (IPv4 + IPv6)**.

> Docker Compose, systemd, and HAProxy deployments have been removed.

## Architecture

```
   NAS / clients (IPv4 + IPv6)
            │  UDP 1812 (auth) / 1813 (acct)  ->  Anycast VIP (one v4 + one v6)
            ▼
   Upstream router  ── ECMP ──┐ (VIP learned via BGP from each Ready node)
            │                 │
   ┌────────┴───────┐  ┌──────┴────────┐   nodes running Cilium BGP
   │ node A (Cilium)│  │ node B (Cilium)│   advertise the VIP only when they
   └───────┬────────┘  └───────┬───────┘   host a Ready radius pod (ETP: Local)
           ▼                   ▼
     usg-radius-server pods (stateless Deployment, dual-stack)
```

### Why these settings matter

- **`externalTrafficPolicy: Local`** (on the LoadBalancer Service) does two things:
  preserves the NAS **source IP** (RADIUS authorizes clients by source IP/CIDR), and
  makes Cilium advertise the VIP **only from nodes with a Ready radius pod** — so a
  drained/failed node withdraws its anycast route automatically.
- **Cilium DSR mode + no SNAT** (`loadBalancer.mode=dsr`, set at Cilium install time
  in `cilium/values-*.yaml`) keeps the original source IP on the LB path. Without it,
  client authorization breaks. The Service also carries
  `service.cilium.io/forwarding-mode: dsr` to pin this per-Service.
- **BGP from every node** with ECMP at the router = true L3 anycast (not active/standby).

## Layout

```
deploy/
  base/                 # namespace, config Secret, Deployment, Services, Cilium IPPool + BGP
  overlays/k3s/         # k3s overlay + install notes
  overlays/k8s/         # full-k8s overlay
  cilium/               # Cilium Helm values (DSR, BGP, dual-stack) for k3s and k8s
  monitoring/           # optional Grafana dashboard
```

## Quick start

1. Install Cilium with the provided values (see the overlay READMEs):
   `overlays/k3s/README.md` or `overlays/k8s/README.md`.
2. Build & push the image (multi-arch):
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 \
     -t <registry>/usg-radius-server:<tag> --push .
   ```
3. Edit the overlay: image, VIP CIDRs, BGP ASNs/peers. Replace the placeholder
   secret in `base/radius-config.secret.yaml`.
4. Deploy:
   ```bash
   kubectl apply -k deploy/overlays/k8s    # or deploy/overlays/k3s
   ```

## Verify

```bash
# Dual-stack VIP assigned:
kubectl -n radius get svc usg-radius-server -o wide      # v4 + v6 EXTERNAL-IP

# BGP up and VIP advertised from the pod-bearing nodes:
cilium bgp peers
cilium bgp routes advertised ipv4 unicast
cilium bgp routes advertised ipv6 unicast

# Source-IP preservation (no SNAT): from an external NAS, send Access-Request to the
# VIP; the configured client (matched by source IP) authenticates and the server log
# shows the real NAS IP — not a node/pod IP.

# Node-selective advertisement: cordon+delete the radius pod on one node; that node
# withdraws the VIP route while pod-bearing nodes keep advertising.
```

## Ports

| Port | Proto | Purpose                  | Exposed on VIP |
|------|-------|--------------------------|----------------|
| 1812 | UDP   | RADIUS authentication    | yes            |
| 1813 | UDP   | RADIUS accounting        | yes            |
| 2812 | TCP   | health (`/health/*`)     | no (ClusterIP) |
| 3812 | TCP   | metrics (`/metrics`)     | no (ClusterIP) |
