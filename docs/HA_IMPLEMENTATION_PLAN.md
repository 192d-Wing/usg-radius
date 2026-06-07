# HA Implementation Plan (Superseded)

**Superseded** — HA via a Redis-compatible shared-state store was removed in favor of
stateless pods scaled by Kubernetes and a Cilium BGP L3 anycast VIP. The shared-state backend, cluster-wide
deduplication, and distributed rate limiting described in earlier revisions of this
plan are no longer part of the project. Availability and scaling now come from running
multiple replicas of a stateless `Deployment` behind a dual-stack (IPv4 + IPv6) L3
anycast VIP advertised by Cilium's BGP control plane. See
[`deploy/README.md`](../deploy/README.md) for the current, canonical deployment guide.
