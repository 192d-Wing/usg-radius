# k8s overlay

Deploys the USG RADIUS server on a full Kubernetes cluster with Cilium providing
the L3 anycast VIP.

## Prerequisites

- A dual-stack Kubernetes cluster (IPv4 + IPv6 pod/service CIDRs).
- Cilium installed with kube-proxy replacement, DSR, and the BGP control plane:

  ```bash
  helm repo add cilium https://helm.cilium.io
  helm upgrade --install cilium cilium/cilium --version 1.16.x \
    --namespace kube-system -f deploy/cilium/values-k8s.yaml
  cilium status --wait
  ```

- The container image pushed to a registry your nodes can pull.

## Configure

Edit [kustomization.yaml](kustomization.yaml):

- `images:` — point at your registry/tag for `usg-radius-server`.
- `CiliumLoadBalancerIPPool` blocks — your routed IPv4 + IPv6 VIPs.
- `CiliumBGPClusterConfig` — local ASN and upstream router peer addresses/ASN.

Also replace the placeholder secret/password in
`../../base/radius-config.secret.yaml` (use a SealedSecret / external secrets
operator in production), and prefer LDAP/PostgreSQL auth over local `users`.

## Deploy & verify

```bash
kubectl apply -k deploy/overlays/k8s
kubectl -n radius get svc usg-radius-server -o wide
cilium bgp peers
cilium bgp routes advertised ipv4 unicast
cilium bgp routes advertised ipv6 unicast
```

The upstream router must allow ECMP / BGP multipath for true anycast.
