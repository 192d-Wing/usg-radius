# Interoperability test: proxy, EAP-TLS and EAP-TEAP against FreeRADIUS and eapol_test

Everything in `crates/radius-server/src/proxy` and `radius_proto::mppe` is
unit-tested against this codebase's own encoder and decoder. This test closes
the gap: it runs usg-radius against two independent RADIUS implementations and
asserts outcomes those implementations compute on their own.

- **FreeRADIUS 3.2** (Debian package) as the home server behind the usg-radius
  proxy, with EAP-TLS and a PAP user.
- **eapol_test** from wpa_supplicant 2.12 as NAS + supplicant. It derives the
  EAP MSK from its own TLS stack (and, for TEAP, its own RFC 9930 key
  schedule), decrypts the MS-MPPE keys in the Access-Accept with *its* shared
  secret, and fails the run if the two do not agree (`MPPE keys OK: 1
  mismatch: 0` / `SUCCESS`). 2.12 is the first release whose EAP-TEAP follows
  RFC 9930; see scenario 10 for why 2.11 cannot be used for TEAP.
- **radclient** (FreeRADIUS utils) for the PAP checks.

The shared secret differs on every hop, so nothing passes by accident:

```
nas 10.77.0.40 ──[nas-proxy-secret-1]──▶ usg-proxy 10.77.0.20 ──[proxy-freeradius-secret-2]──▶ freeradius 10.77.0.10
nas 10.77.0.40 ──[nas-usghome-secret-3]─▶ usg-home 10.77.0.30   (usg-radius as EAP-TLS / EAP-TEAP home server, no proxy)
```

## Running it

```bash
tests/interop/run.sh
```

Requirements: `docker` with the compose plugin, or (as on a Mac without Docker
Desktop) a running [Lima](https://lima-vm.io) VM that has docker; `run.sh`
finds it and runs `docker` through `limactl shell`. OpenSSL on the host for the
test PKI. The first run builds three images, the usg-radius one from this
checkout (a Debian build with the `observability,tls,revocation` features, cached across
runs). Exit status 0 means every check passed; on failure the script prints the
tail of each eapol_test / radclient log and the three servers' logs.

| Variable | Effect |
|----------|--------|
| `KEEP=1` | leave the servers running for manual poking; `run.sh` prints the `docker compose ... down` command that stops them |
| `LOGS=1` | print the servers' logs even on success (`LOG_TAIL` lines, default 400) |
| `INTEROP_VERBOSE=1` | on failure, print the complete eapol_test logs instead of the tails |
| `DOCKER="limactl shell myvm docker"` | use an explicit docker CLI |
| `INTEROP_PROJECT=name` | compose project name (default `usg-radius-interop-<path hash>-<pid>`, unique per run) |
| `INTEROP_NET=10.77.5` | the /24 for the compose network (default: the first free `10.77.N`) |
| `INTEROP_REGEN_CERTS=1` | regenerate the certificates of a reused `INTEROP_PROJECT` |

### Concurrent runs

Several worktrees can run `run.sh` at the same time against one Docker host
(the shared Lima VM, say) without seeing each other. Each run gets:

- its own compose project, `usg-radius-interop-<hash of the checkout path>-<pid>`
  unless `INTEROP_PROJECT` is set, so its containers, network and volumes are
  its own;
- its own image tag (`usg-radius-interop/<image>:<project>`), so a run never
  starts another worktree's usg-radius build;
- its own /24. Docker refuses overlapping subnets, so a fixed `10.77.0.0/24`
  would stop a second run. `run.sh` skips the `10.77.N.0/24` networks already
  on the host, starts from a point derived from the project name, and moves to
  the next one if a concurrent run claims the same /24 first. The servers'
  configs and the `nas` container's targets use `.10`/`.20`/`.30`/`.40` in that
  /24; `run.sh` renders `freeradius/` and `usg-radius/` with the prefix
  replaced;
- its own run directory, `tests/interop/.runs/<project>/` (git-ignored):
  `certs/` (the test PKI), `net-<prefix>-<pid>/` (the rendered configs and
  `compose.env`, the values compose interpolates; a file because `limactl
  shell` does not forward the environment) and, at teardown,
  `logs/<service>.log`. `run.sh` writes a new `net-*` directory per subnet
  attempt instead of rewriting files: Lima's virtiofs mount can hand the VM the
  old size of a file rewritten a moment earlier, which truncates it.

No container names and no host ports are fixed: the `nas` container talks to
the servers over the compose network. A future scenario that needs a host port
should publish the container port alone (`"1812/udp"`) and read the ephemeral
host port back with `docker compose -p <project> port <service> 1812/udp`.

Teardown runs on success, failure, `^C` and `SIGTERM`, and removes only this
run's containers (including the `nas` one-off), network, volumes and images.
The run directory is deleted after a passing run and kept, with the server
logs, after a failing or interrupted one; delete `tests/interop/.runs/` at any
time when no run is in progress.

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

Sixty-seven assertions across fourteen scenarios, plus one host-side check in
`run.sh` (§14). All pass on the current tree (run `tests/interop/run.sh`).

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
validating usg-radius's own EAP endpoint. `home.json` enables
`eap.tls.revocation` (mode `crl_only`, `on_error` `fail_closed`, static CRL
`certs/ca.crl`, no fetching), so this success also shows that an unrevoked
certificate passes the CRL check:

- eapol_test exits 0 and prints `SUCCESS`; TLS 1.3 is negotiated.
- `MPPE keys OK: 1  mismatch: 0` — usg-radius's MS-MPPE keys match the peer's
  MSK, validating both the RFC 9190 §2.3 exporter (label
  `EXPORTER_EAP_TLS_Key_Material`, context `0x0D`) and the MS-MPPE encoding.
- The EAP-Key-Name usg-radius sends equals the peer's locally derived
  Session-Id, validating the RFC 9190 §2.5 Method-Id exporter
  (`EXPORTER_EAP_TLS_Method-Id`).

### 5 — Revoked supplicant certificate directly against usg-radius

`gen-certs.sh` issues `client-usg-revoked.crt` (CN `revoked@usg.test`) and a
CRL from the test CA that revokes it (`openssl ca -revoke` / `-gencrl`; the
script checks the CRL lists the certificate's serial). eapol_test authenticates
with it straight to usg-radius:

- eapol_test exits non-zero and prints `FAILURE`, never `SUCCESS`: rustls
  completes chain validation, `RevocationCheckingVerifier` finds the serial in
  the static CRL and the handshake is aborted with
  `invalid peer certificate: Revoked`.
- `EAP: Status notification: completion (param=failure)`: the Access-Reject
  carries an EAP-Failure (RFC 3579 §2.6.3), so the supplicant terminates the
  method on the reject rather than by timeout.

### 6 — EAP-TLS through the proxy to usg-radius as the home server

`proxy.json` routes realm `usg.test` to usg-home (secret
`proxy-usghome-secret-4`; usg-home lists the proxy as a client). The valid
`eaptls@usg.test` goes through the proxy:

- eapol_test exits 0 and prints `SUCCESS`.
- `MPPE keys OK: 1  mismatch: 0` — the MS-MPPE keys usg-home emitted were
  re-encrypted by the proxy under the NAS secret (usg-radius on both legs).

### 7 — Revoked supplicant certificate through the proxy

The same revoked identity through the proxy: `FAILURE`, non-zero exit, and the
EAP-Failure relayed by the proxy (`completion (param=failure)`). Together with
scenario 6 this shows the CRL check is enforced by the home server regardless
of the path the request took.

### 8 — Supplicant-side EAP-TLS fragmentation against usg-radius

`eapol_test/eap-tls-usg-frag.conf` is scenario 4's configuration with
`fragment_size=300`, so wpa_supplicant splits its TLS flights across several
EAP-TLS Responses: the first carries the L and M bits and the TLS Message
Length, the rest the M bit, the last neither (RFC 5216 §2.1.5 / §3.1). The
client Certificate/CertificateVerify/Finished flight (about 1.2 KB with the
P-256 test certificate) becomes five fragments, four of which the server must
acknowledge with an EAP-TLS Request carrying no data before the peer sends the
next one:

- Control: the eapol_test log contains `more fragments will follow`, so the
  supplicant really fragmented (the count of such lines is printed).
- eapol_test exits 0 and prints `SUCCESS`; TLS 1.3 is negotiated.
- `MPPE keys OK: 1  mismatch: 0` after the fragmented flight.

Without the fragment ACK (PR 79) the server answered the first fragment with
Access-Reject + EAP-Failure (`continue_eap_tls: no outbound TLS, handshake
incomplete`); this scenario is the regression test for that.

### 9 — Supplicant-side fragmentation through the proxy

The same configuration through the proxy to usg-home: `SUCCESS`, and the
MS-MPPE keys re-encrypted by the proxy match the supplicant's MSK, so the ACK
round trips survive the proxy hop.

### 10 — EAP-TEAP (RFC 9930) directly against usg-radius: TLS 1.3, Basic-Password-Auth

`home.json` enables EAP-TEAP next to EAP-TLS and gives the TEAP tunnel its own
TLS block (`eap.teap_tls`: the same server certificate, no client certificate),
with the user `teapuser@usg.test` in `users`. `eapol_test/eap-teap-usg.conf`
authenticates with `eap=TEAP`, identity + password, `ca_cert`, `domain_match`
and `phase1="tls_disable_tlsv1_3=0"` (wpa_supplicant disables TLS 1.3 for TEAP
by default). Because usg-home proposes TEAP first, this scenario and the
EAP-TLS ones together also prove RFC 3748 §5.3.1 EAP-Nak method switching:
eapol_test's EAP-TLS configurations answer the TEAP/Start with a Nak for Type
13 and are switched to EAP-TLS. Proven:

- eapol_test exits 0 and prints `SUCCESS`; TLS 1.3 is negotiated for the tunnel.
- `EAP-TEAP: Using TEAP version 1`: the Start carried Version 1 (§3.1).
- `Crypto-Binding TLV: Version 1 Received Version 1 Flags 2 Sub-Type 0`: the
  peer parsed and accepted the server's 76-octet Binding Request (§4.2.13),
  with the MSK Compound-MAC only (no inner EMSK).
- `MAC algorithm: HMAC-SHA384` and no `Compound MAC did not match`: rustls
  negotiated `TLS_AES_256_GCM_SHA384`, so both sides derived the IMCK/CMK with
  the SHA-384 TLS-PRF and the Compound-MAC with HMAC-SHA384 (§6.2, §6.3), and
  the peer's independent computation over the §6.3 BUFFER matched ours.
- `EAP-TEAP: Authentication completed successfully`: the peer saw
  Intermediate-Result (Success), Result (Success) and a valid Crypto-Binding in
  one message and answered in kind (§3.6.6); EAP-Success followed.
- `MPPE keys OK: 1  mismatch: 0`: the MS-MPPE keys equal the MSK eapol_test
  derived itself as TLS-PRF(S-IMCK[1], "Session Key Generating Function") with
  the zero IMSK of Basic-Password-Auth (§6.2.1, §6.4).

wpa_supplicant 2.11 cannot pass this scenario: it derived the
Basic-Password-Auth MSK from S-IMCK[0] (`eap_teap_derive_cmk_basic_pw_auth`,
removed upstream by "EAP-TEAP: Fix S-IMCK derivation based on RFC 7170bis",
2024-12-31) and would report `MPPE keys OK: 0  mismatch: 1` against an
RFC 9930 server even though the Crypto-Binding exchange succeeds. The harness
therefore builds eapol_test from 2.12.

### 11 — EAP-TEAP through the proxy

The same configuration through the proxy to usg-home: `SUCCESS`, Phase 2
completed, and the MS-MPPE keys re-encrypted by the proxy match the
supplicant's TEAP MSK. The TEAP Start, version bits, fragments and Phase 2
messages all survive the proxy hop.

### 12 — EAP-TEAP over TLS 1.2 with a SHA-256 cipher suite

`eapol_test/eap-teap-usg-tls12.conf` leaves TLS 1.3 disabled (wpa_supplicant's
TEAP default) and forces `ECDHE-*-AES128-GCM-SHA256`, so the key schedule runs
with the other hash the server must select from the negotiated suite: `Using
TLS version TLSv1.2`, `MAC algorithm: HMAC-SHA256`, `SUCCESS` and
`MPPE keys OK: 1  mismatch: 0`. Together with scenario 10 this covers both
branches of the cipher-suite-dependent TLS-PRF / HMAC selection.

### 13 — EAP-TEAP with the wrong password

`eapol_test/eap-teap-usg-badpass.conf`: the server answers the
Basic-Password-Auth-Resp with Result (Failure) inside the tunnel
(`EAP-TEAP: Server rejected authentication`), the peer acknowledges with its
own Result (Failure), and the server sends Access-Reject + EAP-Failure
(`completion (param=failure)`): non-zero exit, `FAILURE`, no `MS-MPPE-*` in the
reject.

### 14 — Status-Server (RFC 5997) and the accounting port (RFC 2866)

radclient (FreeRADIUS's client) is the independent implementation here: it
computes the Message-Authenticator on each Status-Server it sends and, before
it prints `Received ...`, verifies the reply's Response Authenticator under
the hop secret and — when the reply carries one — its Message-Authenticator.
A `Received` line therefore proves the Response Authenticator and proves the
Message-Authenticator *if present*; it does not by itself prove one was sent,
so the positive Status-Server cases add a separate check on radclient's `-x`
attribute dump of the reply (`Message-Authenticator = 0x...` after the
`Received` line). The checks:

- Status-Server to the proxy on 1812 → `Received Access-Accept`, and the
  reply carries a Message-Authenticator (RFC 5997 §4.2). That the proxy
  answers this itself rather than forwarding (§4.3) is true by construction —
  Status-Server is dispatched before any routing in `process_request` — and
  is not something radclient can distinguish from a forwarded, re-keyed
  reply; the unit tests cover the dispatch order.
- Status-Server to usg-home on 1812 → `Received Access-Accept`, and the reply
  carries a Message-Authenticator (§4.1, §4.2).
- Status-Server to usg-home on 1813 → `Received Accounting-Response`, and the
  reply carries a Message-Authenticator (§4.2).
- Accounting-Request (Start) to usg-home on 1813 → `Received
  Accounting-Response` from the dedicated accounting socket (RFC 2866 §2).
- Status-Server signed with the wrong secret → `No reply`: silent discard
  (§4.1).
- Access-Request to the accounting port → `No reply` (RFC 2865 §3 discard of
  a code the socket does not serve; RFC 2866 §2 assigns the port).
- Accounting-Request to the authentication port → `No reply`: with a dedicated
  accounting socket (`accounting_port: 1813`, as both interop configs set),
  Code 4 on 1812 is discarded; `"accounting_port": "shared"` restores the old
  single-socket behaviour.

The proxy's own probes are covered from the host side: `proxy.json` runs with
`health_check` enabled, and after the eapol_test/radclient suite `run.sh`
asserts that the proxy's Status-Server probes against FreeRADIUS and against
usg-home succeeded (the `nas` container cannot see the proxy's log, so the
assertion runs on the host). FreeRADIUS answering the probe is the
independent check of what the probe puts on the wire — random Request
Authenticator and a Message-Authenticator under the home secret; the unit
tests in `crates/radius-server/src/proxy/health.rs` additionally run the
probe against a fake home server that verifies the Message-Authenticator and
signs its reply.

### Server fixes this test drove out

All were invisible to the unit tests (which drive rustls against a rustls
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
3. **EAP Access-Rejects carried no EAP-Failure.** When an EAP method failed in
   the handler (here: the revoked certificate aborting the TLS handshake), the
   generic reject path sent a bare Access-Reject; eapol_test logged
   `could not extract EAP-Message from RADIUS message` and scenarios 5/7 could
   only be asserted by exit status. RFC 3579 §2.6.3 requires the EAP-Failure;
   `crates/radius-server/src/server.rs` now attaches it (Identifier echoing the
   peer's last EAP-Response) to every Access-Reject that ends an EAP
   conversation, with a unit test.

## Debugging a failure

`run.sh` prints, on failure, the tail of each eapol_test / radclient log and
the three servers' logs. `INTEROP_VERBOSE=1` prints the full eapol_test logs.
To iterate by hand, `INTEROP_PROJECT=dbg INTEROP_NET=10.77.0 KEEP=1
tests/interop/run.sh` leaves the servers up under a name and addresses you
chose, then:

```bash
cd tests/interop
docker compose -p dbg --env-file .runs/dbg/net-10.77.0-*/compose.env run --rm --no-deps --entrypoint eapol_test nas \
    -c /etc/eapol_test/eap-tls-usg.conf -a 10.77.0.30 -p 1812 \
    -s nas-usghome-secret-3 -r 0 -t 12 -e
```

eapol_test at this debug level prints the TLS version, the decrypted MS-MPPE
keys, the derived PMK/MSK, and `MPPE keys OK: N  mismatch: M`; a mismatch there
isolates the break to the key material rather than the RADIUS transport.
