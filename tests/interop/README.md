# Interop test: usg-radius proxy and EAP-TLS / EAP-TEAP home server (with CRL checking) vs FreeRADIUS and eapol_test

```bash
tests/interop/run.sh
```

Builds three images (FreeRADIUS from the Debian package, eapol_test from
wpa_supplicant 2.12, usg-radius from this checkout), starts FreeRADIUS and three
usg-radius instances (proxy, EAP-TLS / EAP-TEAP home server, and an EAP-TLS home server whose CRL is forged) on a compose network with
fixed host addresses, runs the checks from the `nas` container and tears down. Exit
status 0 means every check passed. Runs from different worktrees can share one
Docker host: each run has its own compose project, image tag, /24 and run
directory, and teardown (also on failure or `^C`) removes only its own
containers, network, volumes and images. See
[docs/docs/development/INTEROP_TESTING.md](../../docs/docs/development/INTEROP_TESTING.md)
for what each check proves, the secrets per hop, how to debug a failure, and
the CI job (`.github/workflows/interop.yml`) that runs this on pull requests,
nightly and on demand.

Layout:

| Path | Role |
|------|------|
| `run.sh` | Host driver (docker, or a running Lima VM with docker) |
| `gen-certs.sh` | Test PKI → the run directory's `certs/`, including `ca.crl`, which revokes `client-usg-revoked.crt`, and `ca-wrongkey.crl`, which names the CA but is signed by another key |
| `compose.yaml` | Network `$INTEROP_NET.0/24` (default 10.77.0, `run.sh` picks a free 10.77.N per run): freeradius .10, usg-proxy .20, usg-home .30, usg-home-badcrl .31, nas .40 |
| `.runs/<project>/` | Per-run directory (git-ignored): `certs/`, `net-<prefix>-<pid>/` (configs rendered for the run's /24 and `compose.env`), `logs/`; deleted after a passing run |
| `freeradius/` | Dockerfile, `clients.conf`, `eap` (mods-available), `authorize` |
| `usg-radius/` | Dockerfile (Debian build of this checkout, features `observability,tls,revocation`), `proxy.json` (realms `freeradius.test` → FreeRADIUS, `usg.test` → usg-home), `home.json` (EAP-TLS with `eap.tls.revocation`, static CRL, fail-closed; EAP-TEAP with `eap.teap_tls`, Basic-Password-Auth user), `home-badcrl.json` (EAP-TLS whose only static CRL is `ca-wrongkey.crl`, fail-closed) |
| `eapol_test/` | Dockerfile, wpa_supplicant `config`, supplicant `*.conf`, `run-tests.sh` (the assertions), `retransmit-tests.sh` (scenario 15: a bash NAS that retransmits signed Access-Requests) |
