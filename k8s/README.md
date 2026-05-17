# Kubernetes Deployment

K8s-native deployment manifests for `usg-radius`. Targets any conformant cluster
(EKS, GKE, AKS, on-prem k3s/k0s/kubeadm, OpenShift).

## Layout

| File | Purpose |
|---|---|
| `namespace.yaml` | Namespace with Pod Security Admission `restricted` enforcement. |
| `configmap.yaml` | `config.json` mounted read-only at `/etc/radius/config.json`. Secrets are referenced via `${VAR}` and injected from the Secret as env vars. |
| `secret.example.yaml` | Template; generate the real Secret with `kubectl create secret` or an external secret manager. |
| `valkey.yaml` | Single-replica Valkey StatefulSet + headless Service for shared session / cache / rate-limit state. |
| `deployment.yaml` | 2-replica Deployment, distroless-ish hardened pod (`runAsNonRoot`, `readOnlyRootFilesystem`, `drop: [ALL]`), startup/liveness/readiness probes against `/healthz`,`/livez`,`/readyz`, PDB. |
| `service.yaml` | UDP LoadBalancer (1812/1813) with `externalTrafficPolicy: Local`, plus internal ClusterIP for health/metrics scraping. |
| `networkpolicy.yaml` | Default-deny shape: ingress only on RADIUS UDP + health TCP; egress only to DNS + Valkey. |
| `kustomization.yaml` | `kubectl apply -k k8s/` entrypoint. |

## Deployment modes

| Mode | Apply with | When to use |
|---|---|---|
| **BGP VIP (default)** | `kubectl apply -k k8s/` + `kubectl apply -f k8s/metallb.yaml` | Production, multi-node, dual-stack VIPs advertised via MetalLB BGP. |
| **Host network (testing)** | `kubectl apply -k k8s/overlays/hostnet/` | Single-instance testing on a labeled node. No LoadBalancer, no MetalLB. Reach RADIUS at `<node-ip>:1812`. |

For the host-network overlay, first label a node:

```bash
kubectl label node <node-name> usg-radius/host=true
kubectl apply -k k8s/overlays/hostnet/
kubectl get nodes -o wide   # grab the node IP
radtest user pass <node-ip> 1812 <shared-secret>
```

## Quick start

```bash
# 1. Build & push the image
podman build -t ghcr.io/your-org/usg-radius:0.7.0 -f Containerfile .
podman push ghcr.io/your-org/usg-radius:0.7.0

# 2. Create the real Secret (do NOT use secret.example.yaml in prod)
kubectl create namespace usg-radius
kubectl create secret generic usg-radius-secrets -n usg-radius \
  --from-literal=RADIUS_SECRET="$(openssl rand -hex 24)" \
  --from-literal=CLIENT_1_SECRET="$(openssl rand -hex 24)" \
  --from-literal=ADMIN_PASSWORD="$(openssl rand -base64 32)"

# 3. Apply everything except the example secret
kubectl apply -k k8s/

# 4. Verify
kubectl -n usg-radius get pods,svc
kubectl -n usg-radius logs deploy/usg-radius
kubectl -n usg-radius port-forward svc/usg-radius-health 8080:8080
curl http://localhost:8080/healthz
```

## Load balancer selection

RADIUS is UDP; most HTTP ingress controllers cannot front it. Pick based on
environment:

| Environment | Recommendation | Notes |
|---|---|---|
| AWS EKS | **NLB** with `aws-load-balancer-type: "nlb"` | Native UDP, preserves source IP with `externalTrafficPolicy: Local`. |
| GCP GKE | **TCP/UDP Network LB** (default Service type=LoadBalancer) | Supports UDP. Set `externalTrafficPolicy: Local`. |
| Azure AKS | **Standard Load Balancer** (default) | UDP supported; pair with `externalTrafficPolicy: Local`. |
| On-prem / bare metal | **MetalLB** (BGP preferred, L2 fallback) or **kube-vip** | Cheapest UDP LB. BGP scales better than L2. |
| Edge / no LB available | **DaemonSet + `hostNetwork: true`** with a fixed nodeSelector | Simplest fallback; loses Service abstraction; replicas=nodes. |
| OpenShift | **MetalLB operator** or platform LB | Same constraints as bare metal. |

In every case set `externalTrafficPolicy: Local` so the RADIUS server sees the
real NAS/AP source IP — the server matches the source IP against
`clients[].address` to select the correct shared secret. Without it every
packet looks like it came from a node IP and client matching breaks.

## Secret handling — production recommendation

`secret.example.yaml` is for local dev only. For production, use one of:

1. **External Secrets Operator** (recommended) — syncs from AWS Secrets Manager,
   GCP Secret Manager, Azure Key Vault, HashiCorp Vault, etc., into a native
   `Secret` automatically.
2. **Sealed Secrets** (Bitnami) — commit encrypted `SealedSecret` CRDs to git.
3. **Vault CSI driver** — mounts secrets directly as files; no `Secret` object.
4. **Cloud-native CSI driver** (AWS Secrets Store CSI, GCP Secret Manager CSI).

Whichever you pick, the env-var contract in `deployment.yaml` is unchanged:
`RADIUS_SECRET`, `CLIENT_1_SECRET`, `ADMIN_PASSWORD`. Rotate by updating the
secret source and triggering a rolling restart (`kubectl rollout restart`).

## Scaling considerations

- The `ha` feature (compiled in by default) routes EAP session state, request
  cache, and rate-limit counters through Valkey. Without Valkey, only
  `replicas: 1` is safe.
- For EAP/TEAP multi-packet conversations, `externalTrafficPolicy: Local` plus
  a 5-tuple-hashing LB keeps a client's packets pinned to one pod, which
  avoids cross-pod state lookups on the hot path.
- For HA Valkey, replace `valkey.yaml` with the [valkey-operator](https://github.com/valkey-io/valkey-operator)
  or the Bitnami Helm chart in sentinel/cluster mode.

## Observability

- `/healthz`, `/livez`, `/readyz` on port 8080 (used by the probes).
- `/metrics` on port 8080 exposes Prometheus metrics (gated by `ha`, on by
  default). Annotations on the pod template already opt in to standard
  Prometheus scrape discovery. For Prometheus Operator, add a
  `ServiceMonitor` pointing at `usg-radius-health`.
- All logs (including audit events, since `audit_log_path: "stdout"`) go to
  pod stdout in JSON and are picked up by any standard log aggregator.

## What you still need to verify before going to prod

1. **EAP under rolling restart** — bounce a pod mid-handshake and confirm a
   client retries successfully against the surviving pod (validates Valkey
   state sharing).
2. **Source IP preservation** — `tcpdump` on a pod and confirm the source IP
   matches the NAS, not the node.
3. **Secret rotation drill** — rotate `RADIUS_SECRET`, restart, confirm no
   clients are dropped (RADIUS shared-secret rotation is inherently
   disruptive; plan a coordinated window).
4. **PodSecurity** — the namespace enforces `restricted`. If you add sidecars
   or initContainers, they must comply.
