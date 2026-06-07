# Availability & Scaling

USG RADIUS achieves availability and horizontal scale through Kubernetes, not through a
shared-state backend. The server is **stateless**: there is no external state store, no
cluster-wide session store, and no distributed rate limiting. Each pod handles requests
independently. This document explains the model; for hands-on deployment steps see the
canonical guide, [`deploy/README.md`](../../../deploy/README.md), and the overlays under
[`deploy/overlays/k3s`](../../../deploy/overlays/k3s) and
[`deploy/overlays/k8s`](../../../deploy/overlays/k8s).

## Table of Contents

1. [Model Overview](#model-overview)
2. [Stateless Pods + ReplicaSet](#stateless-pods--replicaset)
3. [Cilium BGP L3 Anycast VIP](#cilium-bgp-l3-anycast-vip)
4. [Source-IP Preservation (ETP=Local + DSR)](#source-ip-preservation-etplocal--dsr)
5. [Health Checks](#health-checks)
6. [Failure Behavior](#failure-behavior)

## Model Overview

```
            NAS / clients (IPv4 + IPv6)
                     │  UDP 1812 (auth) / 1813 (acct)  ->  Anycast VIP (one v4 + one v6)
                     ▼
            Upstream router  ── ECMP ──┐  (VIP learned via BGP from each Ready node)
                     │                 │
        ┌────────────┴───┐   ┌─────────┴──────┐   nodes advertise the VIP only while
        │ node A (Cilium)│   │ node B (Cilium)│   they host a Ready radius pod
        └────────┬───────┘   └────────┬───────┘
                 ▼                     ▼
          usg-radius-server pods (stateless Deployment, dual-stack)
```

- **No shared state.** Pods do not exchange EAP, accounting, dedup, or rate-limit state.
- **Scale = replicas.** Add capacity by increasing the Deployment's replica count.
- **Availability = anycast.** Every Ready node advertises the same VIP; the router ECMPs
  traffic across them, and unhealthy nodes withdraw their route automatically.

## Stateless Pods + ReplicaSet

The RADIUS server runs as a Kubernetes `Deployment`. The ReplicaSet keeps the desired
number of pods running and reschedules them on node or pod failure.

- **Scaling**: raise `spec.replicas` (or apply an HPA) to add throughput. Each replica is
  independent, so capacity scales close to linearly with replica count, bounded by the
  upstream router's ECMP fan-out and per-flow hashing.
- **Rolling updates**: standard Kubernetes rolling updates apply. Because pods are
  stateless, a pod can be drained, replaced, or rescheduled with no session hand-off.
- **No backend dependency**: there is nothing to provision, secure, or fail over beyond
  the pods themselves.

## Cilium BGP L3 Anycast VIP

The service is exposed on an **L3 anycast VIP** — a single IPv4 address and a single IPv6
address (dual-stack) — advertised by **Cilium's BGP control plane** from every node that
currently hosts a Ready radius pod.

- The VIP, BGP ASNs, and peers are configured in the overlay and Cilium IPPool/BGP
  resources under `deploy/`.
- The upstream router learns the VIP from multiple nodes and load-balances inbound RADIUS
  traffic across them using **ECMP** — this is true L3 anycast, not active/standby.
- Cilium install-time Helm values live in
  [`deploy/cilium/values-k3s.yaml`](../../../deploy/cilium/values-k3s.yaml) and
  [`deploy/cilium/values-k8s.yaml`](../../../deploy/cilium/values-k8s.yaml).

Verify advertisement with:

```bash
cilium bgp peers
cilium bgp routes advertised ipv4 unicast
cilium bgp routes advertised ipv6 unicast
```

## Source-IP Preservation (ETP=Local + DSR)

RADIUS authorizes clients by source IP/CIDR, so the NAS source address **must** reach the
server unchanged. Two settings guarantee this:

- **`externalTrafficPolicy: Local`** on the LoadBalancer Service. This preserves the
  client source IP (no SNAT to a node IP) and makes Cilium advertise the VIP **only from
  nodes that have a Ready radius pod**. A drained or failed node therefore stops attracting
  traffic and withdraws its anycast route automatically.
- **Cilium DSR mode (no SNAT)**, set at Cilium install time in the `cilium/values-*.yaml`
  files and pinned per-Service via `service.cilium.io/forwarding-mode: dsr`. Direct Server
  Return keeps the original source IP on the load-balanced path.

Without these, every request would appear to come from a node/pod IP and client
authorization would break.

## Health Checks

The binary serves health endpoints on **TCP 2812** when built with the `observability`
cargo feature:

```bash
curl http://<pod>:2812/health/live    # liveness: process is running
curl http://<pod>:2812/health/ready   # readiness: pod is ready to serve
```

Kubernetes liveness/readiness probes use these endpoints. Because advertisement is tied to
pod readiness (via `externalTrafficPolicy: Local`), a pod failing its readiness probe both
stops receiving pod traffic and causes its node to withdraw the VIP route if it was the
last Ready pod there.

Prometheus metrics are exposed separately on **TCP 3812** at `/metrics` (also gated behind
the `observability` feature).

## Failure Behavior

| Failure | Result |
|---------|--------|
| One pod crashes | ReplicaSet reschedules it; node withdraws the VIP route if it was the last Ready pod on that node. |
| One node drains/fails | That node stops advertising the VIP; the router ECMPs remaining nodes. |
| Rolling update | Pods are replaced one at a time; readiness gates route advertisement, so no traffic lands on not-yet-ready pods. |
| In-flight multi-round EAP on a failed pod | The exchange restarts on a healthy pod (no shared session state). Keep replica churn low during active EAP. |

## See Also

- [`deploy/README.md`](../../../deploy/README.md) — canonical, step-by-step deployment guide.
- [DEPLOYMENT.md](./DEPLOYMENT.md) — server CLI/config usage.
- [QUICKSTART.md](./QUICKSTART.md) — fastest path to a running cluster.
