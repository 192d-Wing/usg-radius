# k3s overlay

Deploys the USG RADIUS server on k3s with Cilium providing the L3 anycast VIP.

## 1. Install k3s without its bundled networking

Cilium must own CNI, service LB, and network policy, so disable k3s's built-ins:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
  --flannel-backend=none \
  --disable-network-policy \
  --disable servelb \
  --disable traefik \
  --cluster-cidr=10.42.0.0/16,fd00:42::/56 \
  --service-cidr=10.43.0.0/16,fd00:43::/112" sh -
```

The dual `--cluster-cidr` / `--service-cidr` values enable dual-stack. Adjust to
your network. On agents, pass the same `--flannel-backend=none` etc.

## 2. Install Cilium

```bash
helm repo add cilium https://helm.cilium.io
helm upgrade --install cilium cilium/cilium --version 1.16.x \
  --namespace kube-system -f deploy/cilium/values-k3s.yaml
cilium status --wait
```

## 3. Set your VIPs / ASNs

Edit [kustomization.yaml](kustomization.yaml): the `CiliumLoadBalancerIPPool` blocks
(IPv4 + IPv6 VIP) and the `CiliumBGPClusterConfig` local ASN + upstream peer
addresses (typically your homelab router running BGP).

## 4. Deploy

```bash
kubectl apply -k deploy/overlays/k3s
```

## 5. Verify

```bash
kubectl -n radius get svc usg-radius-server -o wide   # EXTERNAL-IP shows v4 + v6
cilium bgp peers
cilium bgp routes advertised ipv4 unicast
```

Your router must accept ECMP / BGP multipath so the VIP is learned from every node
running a Ready radius pod.
