# Implementation Summary (Superseded)

**Superseded** — HA via a Redis-compatible shared-state store was removed in favor of
stateless pods scaled by Kubernetes and a Cilium BGP L3 anycast VIP. The RADIUS server no longer maintains
shared session state across instances; scaling and availability come from the
Kubernetes Deployment/ReplicaSet and a dual-stack (IPv4 + IPv6) anycast VIP advertised
by Cilium's BGP control plane. See [`deploy/README.md`](../deploy/README.md) for the
current, canonical deployment guide.
