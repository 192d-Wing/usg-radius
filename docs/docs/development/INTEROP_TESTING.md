# Interoperability test: proxy and EAP-TLS against FreeRADIUS and eapol_test

Everything in `crates/radius-server/src/proxy` and `radius_proto::mppe` is
unit-tested against this codebase's own encoder and decoder. This test closes
the gap: it runs usg-radius against two independent RADIUS implementations and
asserts outcomes those implementations compute on their own.

- **FreeRADIUS 3.2** (Debian package) as the home server behind the usg-radius
  proxy, with EAP-TLS and a PAP user.
- **eapol_test** from wpa_supplicant 2.11 as NAS + supplicant. It derives the
  EAP MSK from its own TLS stack, decrypts the MS-MPPE keys in the
  Access-Accept with *its* shared secret, and fails the run if the two do not
  agree (`MPPE keys OK: 1  mismatch: 0` / `SUCCESS`).
- **radclient** (FreeRADIUS utils) for the PAP checks.

The shared secret differs on every hop, so nothing passes by accident:

```
nas 10.77.0.40 ──[nas-proxy-secret-1]──▶ usg-proxy 10.77.0.20 ──[proxy-freeradius-secret-2]──▶ freeradius 10.77.0.10
nas 10.77.0.40 ──[nas-usghome-secret-3]─▶ usg-home 10.77.0.30   (usg-radius as EAP-TLS home server, no proxy)
```

## Running it

```bash
tests/interop/run.sh
```

Requirements: `docker` with the compose plugin, or (as on a Mac without Docker
Desktop) a running [Lima](https://lima-vm.io) VM that has docker; `run.sh`
finds it and runs `docker` through `limactl shell`. OpenSSL on the host for the
test PKI. The first run builds three images, the usg-radius one from this
checkout (a Debian build with the `observability,tls` features, cached across
runs). Exit status 0 means every check passed; on failure the script prints the
tail of each eapol_test / radclient log and the three servers' logs.

| Variable | Effect |
|----------|--------|
| `KEEP=1` | leave the servers running for manual poking (`docker compose -f tests/interop/compose.yaml down` to stop) |
| `LOGS=1` | print the servers' logs even on success (`LOG_TAIL` lines, default 400) |
| `INTEROP_VERBOSE=1` | on failure, print the complete eapol_test logs instead of the tails |
| `DOCKER="limactl shell myvm docker"` | use an explicit docker CLI |
| `INTEROP_REGEN_CERTS=1` | regenerate `tests/interop/certs/` |

Files are under `tests/interop/`: `compose.yaml`, `gen-certs.sh`, the
FreeRADIUS configuration (`freeradius/`), the two usg-radius configurations
(`usg-radius/proxy.json`, `usg-radius/home.json`), the eapol_test build and
supplicant configs (`eapol_test/`), and `eapol_test/run-tests.sh`, which runs
inside the `nas` container and holds every assertion.

## In CI

The GitHub Actions workflow `.github/workflows/interop.yml` (job **Interop /
FreeRADIUS + eapol_test**) runs `tests/interop/run.sh` on `ubuntu-latest`:

- on every pull request that touches `crates/**`, `tests/interop/**`,
  `Cargo.toml`, `Cargo.lock`, any `Dockerfile` or the workflow itself;
- nightly at 05:23 UTC on the default branch;
- on demand from the Actions tab (`workflow_dispatch`).

The job fails when any assertion fails (`run.sh` exits non-zero as soon as one
check does). On failure it uploads an `interop-logs` artifact holding
`run.log` (the full `run.sh` output: the PASS/FAIL line per assertion, the
eapol_test and radclient summaries and the per-check log tails) and the
complete `freeradius.log`, `usg-proxy.log` and `usg-home.log`.

The three harness images build from public Debian and `rust:*-slim-bookworm`
images, not from the Iron Bank base the shipping `Dockerfile` uses, so the job
needs no registry login and has no public-image fallback: Dependabot and fork
pull requests run the same build as everything else.

Two caches keep the runtime reasonable. The cargo registry and target dir
inside the usg-radius image build are BuildKit cache mounts, saved across runs
with `actions/cache` (keyed on `Cargo.lock`, so dependencies compile once per
lockfile change) and copied into the builder by `buildkit-cache-dance`; the
image layers (apt installs, the wpa_supplicant build, the FreeRADIUS package)
are cached through buildx's `type=gha` backend. The workflow exports
`CARGO_BUILD_JOBS=4` for the 4-vCPU runner; `compose.yaml` passes it to the
image build (default 2).

## What is checked

Fifteen assertions across four scenarios. All pass on the current tree (run
`tests/interop/run.sh`).

### 1 & 2 — EAP-TLS through the proxy to FreeRADIUS

eapol_test authenticates as `eaptls@freeradius.test`; the proxy routes the
realm to FreeRADIUS, which runs the EAP-TLS method and returns MS-MPPE keys
encrypted under the proxy↔home secret. The proxy decrypts them and re-encrypts
under the NAS↔proxy secret (RFC 2548). Proven:

- eapol_test exits 0 and prints `SUCCESS`; EAP-Success arrives through the proxy.
- `MPPE keys OK: 1  mismatch: 0` — the MS-MPPE keys eapol_test decrypted with
  the **NAS** secret equal the MSK it derived from its own TLS stack. This
  exercises the full request leg (Message-Authenticator recomputed for the home
  secret) and the response leg (keys re-encrypted for the NAS), against two
  independent implementations.
- TLS 1.3 is negotiated end to end.

### 3 — PAP through the proxy (request-leg User-Password re-encryption)

- `papuser@freeradius.test` with the correct password gets Access-Accept and
  FreeRADIUS's `Reply-Message` is relayed back: the proxy decrypted
  User-Password under the NAS secret and re-encrypted it under the home secret,
  or FreeRADIUS's PAP compare would have failed.
- A wrong password gets Access-Reject (not a timeout, not an accept).
- Control: the NAS secret presented **directly** to FreeRADIUS is rejected,
  confirming the secrets genuinely differ per hop, so nothing above passed by a
  shared secret.

### 4 — EAP-TLS directly against usg-radius as the home server

eapol_test authenticates as `eaptls@usg.test` straight to usg-radius (no proxy),
validating usg-radius's own EAP endpoint:

- eapol_test exits 0 and prints `SUCCESS`; TLS 1.3 is negotiated.
- `MPPE keys OK: 1  mismatch: 0` — usg-radius's MS-MPPE keys match the peer's
  MSK, validating both the RFC 9190 §2.3 exporter (label
  `EXPORTER_EAP_TLS_Key_Material`, context `0x0D`) and the MS-MPPE encoding.
- The EAP-Key-Name usg-radius sends equals the peer's locally derived
  Session-Id, validating the RFC 9190 §2.5 Method-Id exporter
  (`EXPORTER_EAP_TLS_Method-Id`).

### Server fixes this test drove out

Both were invisible to the unit tests (which drive rustls against a rustls
supplicant) and only appeared against OpenSSL-based peers:

1. **RFC 9190 §2.5 commitment message.** usg-radius's EAP-TLS 1.3 server sent
   EAP-Success immediately after the handshake, skipping the protected success
   indication (a TLS application-data record of one `0x00` octet that the peer
   acknowledges). wpa_supplicant's TLS 1.3 peer derives no MSK without it, so
   scenario 4 failed with `MPPE keys OK: 0  mismatch: 1` and a Session-Id
   mismatch even though the TLS handshake succeeded. Fixed in
   `crates/radius-proto` (`EapTlsServer::write_commitment_record`) and
   `crates/radius-server/src/eap_auth.rs` (the EAP-TLS state machine now sends
   the commitment and sends EAP-Success only on the peer's ACK), with a unit
   test. The EAP-Success Identifier now also echoes the peer's last
   EAP-Response (RFC 3748 §4.2).
2. **Proxy reply source port.** The proxy sent relayed responses and timeout
   rejects from its upstream (home-server) socket, a different source port than
   the NAS sent to. A NAS whose RADIUS socket is `connect()`ed to the proxy
   (eapol_test, most embedded NASes) drops those datagrams. The proxy now
   replies from its listening socket, with unit tests.

## Debugging a failure

`run.sh` prints, on failure, the tail of each eapol_test / radclient log and
the three servers' logs. `INTEROP_VERBOSE=1` prints the full eapol_test logs.
To iterate by hand, `KEEP=1 tests/interop/run.sh` leaves the servers up, then:

```bash
cd tests/interop
docker compose run --rm --no-deps --entrypoint eapol_test nas \
    -c /etc/eapol_test/eap-tls-usg.conf -a 10.77.0.30 -p 1812 \
    -s nas-usghome-secret-3 -r 0 -t 12 -e
```

eapol_test at this debug level prints the TLS version, the decrypted MS-MPPE
keys, the derived PMK/MSK, and `MPPE keys OK: N  mismatch: M`; a mismatch there
isolates the break to the key material rather than the RADIUS transport.
