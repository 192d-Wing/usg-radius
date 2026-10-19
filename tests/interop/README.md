# Interop test: usg-radius proxy and EAP-TLS home server vs FreeRADIUS and eapol_test

```bash
tests/interop/run.sh
```

Builds three images (FreeRADIUS from the Debian package, eapol_test from
wpa_supplicant 2.11, usg-radius from this checkout), starts FreeRADIUS and two
usg-radius instances (proxy and EAP-TLS home server) on a compose network with
fixed addresses, runs the checks from the `nas` container and tears down. Exit
status 0 means every check passed. See
[docs/docs/development/INTEROP_TESTING.md](../../docs/docs/development/INTEROP_TESTING.md)
for what each check proves, the secrets per hop, and how to debug a failure.

Layout:

| Path | Role |
|------|------|
| `run.sh` | Host driver (docker, or a running Lima VM with docker) |
| `gen-certs.sh` | Test PKI → `certs/` (git-ignored, regenerated on demand) |
| `compose.yaml` | Network 10.77.0.0/24: freeradius .10, usg-proxy .20, usg-home .30, nas .40 |
| `freeradius/` | Dockerfile, `clients.conf`, `eap` (mods-available), `authorize` |
| `usg-radius/` | Dockerfile (Debian build of this checkout), `proxy.json`, `home.json` |
| `eapol_test/` | Dockerfile, wpa_supplicant `config`, supplicant `*.conf`, `run-tests.sh` (the assertions) |
