# Interop test: usg-radius proxy and EAP-TLS / EAP-TEAP home server (with CRL checking) vs FreeRADIUS and eapol_test

```bash
tests/interop/run.sh
```

Builds three images (FreeRADIUS from the Debian package, eapol_test from
wpa_supplicant 2.12, usg-radius from this checkout), starts FreeRADIUS and two
usg-radius instances (proxy and EAP-TLS / EAP-TEAP home server) on a compose network with
fixed addresses, runs the checks from the `nas` container and tears down. Exit
status 0 means every check passed. See
[docs/docs/development/INTEROP_TESTING.md](../../docs/docs/development/INTEROP_TESTING.md)
for what each check proves, the secrets per hop, how to debug a failure, and
the CI job (`.github/workflows/interop.yml`) that runs this on pull requests,
nightly and on demand.

Layout:

| Path | Role |
|------|------|
| `run.sh` | Host driver (docker, or a running Lima VM with docker) |
| `gen-certs.sh` | Test PKI → `certs/` (git-ignored, regenerated on demand), including `ca.crl`, which revokes `client-usg-revoked.crt` |
| `compose.yaml` | Network 10.77.0.0/24: freeradius .10, usg-proxy .20, usg-home .30, nas .40 |
| `freeradius/` | Dockerfile, `clients.conf`, `eap` (mods-available), `authorize` |
| `usg-radius/` | Dockerfile (Debian build of this checkout, features `observability,tls,revocation`), `proxy.json` (realms `freeradius.test` → FreeRADIUS, `usg.test` → usg-home), `home.json` (EAP-TLS with `eap.tls.revocation`, static CRL, fail-closed; EAP-TEAP with `eap.teap_tls`, Basic-Password-Auth user) |
| `eapol_test/` | Dockerfile, wpa_supplicant `config`, supplicant `*.conf`, `run-tests.sh` (the assertions), `retransmit-tests.sh` (scenario 15: a bash NAS that retransmits signed Access-Requests) |
