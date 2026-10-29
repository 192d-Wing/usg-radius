# Interop test: usg-radius proxy and EAP-TLS / EAP-TEAP home server (with CRL checking) vs FreeRADIUS and eapol_test

```bash
tests/interop/run.sh
```

Builds three images (FreeRADIUS 3.2.7 from the Debian trixie package, eapol_test
from wpa_supplicant 2.12, usg-radius from this checkout), starts FreeRADIUS and
three usg-radius instances (proxy, EAP-TLS / EAP-TEAP home server, and an
EAP-TLS home server whose CRL is forged) on a compose network with fixed host
addresses, runs the checks from the `nas` container and tears down. The proxy
reaches FreeRADIUS twice: over UDP (realm `freeradius.test`) and over RadSec,
RFC 6614 (realm `radsec.test`: TLS 1.3, ML-KEM-1024, mutual certificates, fixed
hop secret `radsec`); `run.sh` proves the second path from the FreeRADIUS and
proxy logs. Exit status 0 means every check passed. Runs from different
worktrees can share one Docker host: each run has its own compose project,
image tag, /24 and run directory, and teardown (also on failure or `^C`)
removes only its own containers, network, volumes and images. See
[docs/docs/development/INTEROP_TESTING.md](../../docs/docs/development/INTEROP_TESTING.md)
for what each check proves, the secrets per hop, how to debug a failure, and
the CI job (`.github/workflows/interop.yml`) that runs this on pull requests,
nightly and on demand.

Topology (`compose.yaml` has the same picture with the secrets):

```
nas 10.77.0.40 --UDP--> usg-proxy 10.77.0.20 --UDP 1812-------------------> freeradius 10.77.0.10  (realm freeradius.test)
                                             --RadSec 2083 (TLS 1.3, mTLS)--> freeradius 10.77.0.10  (realm radsec.test)
                                             --UDP 1812-------------------> usg-home   10.77.0.30  (realm usg.test)
nas 10.77.0.40 --UDP--> usg-home 10.77.0.30 (EAP-TLS / EAP-TEAP home server, accounting on 1813)
```

Layout:

| Path | Role |
|------|------|
| `run.sh` | Host driver (docker, or a running Lima VM with docker). After the `nas` run (89 assertions in 17 scenarios) it checks, from the logs, that usg-home-badcrl refused `ca-wrongkey.crl` for its signature, the proxy's Status-Server probes to every home server, and the RadSec hop: TLS 1.3, `TLS_AES_256_GCM_SHA384`, client certificate `CN=usg-proxy`, `papuser@radsec.test` received on 2083 and never on 1812, `RadSec link established` with `group=Some(MLKEM1024)` on the proxy (13 host-side checks) |
| `gen-certs.sh` | Test PKI → the run directory's `certs/`: CA, server certificates for FreeRADIUS (EAP-TLS and the RadSec listener) and usg-home, the proxy's RadSec client certificate `usg-proxy.crt` (EKU clientAuth), EAP-TLS client certificates, `ca.crl`, which revokes `client-usg-revoked.crt`, and `ca-wrongkey.crl`, which names the CA but is signed by another key |
| `compose.yaml` | Network `$INTEROP_NET.0/24` (default 10.77.0, `run.sh` picks a free 10.77.N per run): freeradius .10 (UDP 1812/1813, RadSec 2083), usg-proxy .20, usg-home .30, usg-home-badcrl .31, nas .40 |
| `.runs/<project>/` | Per-run directory (git-ignored): `certs/`, `net-<prefix>-<pid>/` (configs rendered for the run's /24 — including `sites-radsec` and `proxy.json` — and `compose.env`), `logs/`; deleted after a passing run |
| `freeradius/` | Dockerfile (trixie: OpenSSL 3.5 for ML-KEM; runs `-fxx`, threaded, because TLS sockets need threads), `clients.conf` (UDP client), `sites-radsec` (RFC 6614 listener on 2083 with `ecdh_curve = "MLKEM1024"`, client `usg-proxy-tls` with secret `radsec`), `eap` (mods-available), `authorize` |
| `usg-radius/` | Dockerfile (Debian build of this checkout, features `observability,tls,revocation`), `proxy.json` (realms `freeradius.test` → FreeRADIUS over UDP, `radsec.test` → FreeRADIUS over RadSec with `"transport": "radsec"` and a `tls` block, `usg.test` → usg-home), `home.json` (EAP-TLS with `eap.tls.revocation`, static CRL, fail-closed; EAP-TEAP with `eap.teap_tls`, Basic-Password-Auth user), `home-badcrl.json` (EAP-TLS whose only static CRL is `ca-wrongkey.crl`, fail-closed) |
| `eapol_test/` | Dockerfile, wpa_supplicant `config`, supplicant `*.conf` (`eap-tls-radsec.conf` is the RadSec realm), `run-tests.sh` (the assertions), `retransmit-tests.sh` (scenario 15: a bash NAS that retransmits signed Access-Requests) |
