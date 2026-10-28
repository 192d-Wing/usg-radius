#!/usr/bin/env bash
# Interop test driver. Generates the test PKI, builds the three images, starts
# FreeRADIUS and both usg-radius instances, runs the checks in the `nas`
# container (eapol_test + radclient) and tears everything down.
#
#   tests/interop/run.sh            # build, run, tear down; exit 0 iff all checks pass
#   KEEP=1 tests/interop/run.sh     # leave the servers running afterwards
#   LOGS=1 tests/interop/run.sh     # always print the servers' logs
#   DOCKER="limactl shell myvm docker" tests/interop/run.sh   # explicit docker CLI
#
# Needs `docker` with the compose plugin. Without a docker CLI on PATH, a running
# Lima instance (limactl) that has docker is used, which works because Lima
# mounts the home directory at the same path inside the VM.
set -euo pipefail
cd "$(dirname "$0")"

if [[ -z "${DOCKER:-}" ]]; then
    if command -v docker >/dev/null 2>&1; then
        DOCKER=docker
    elif command -v limactl >/dev/null 2>&1; then
        inst=${LIMA_INSTANCE:-}
        if [[ -z "$inst" ]]; then
            # First running instance that actually has docker.
            for candidate in $(limactl list -f '{{.Name}} {{.Status}}' 2>/dev/null | awk '$2 == "Running" {print $1}'); do
                if limactl shell "$candidate" -- sh -c 'command -v docker >/dev/null 2>&1'; then
                    inst=$candidate; break
                fi
            done
        fi
        [[ -n "$inst" ]] || { echo "run.sh: no docker CLI and no running Lima instance with docker (set LIMA_INSTANCE)" >&2; exit 2; }
        echo "run.sh: using docker in Lima instance '$inst'"
        DOCKER="limactl shell $inst docker"
    else
        echo "run.sh: need docker (or a running Lima VM with docker)" >&2
        exit 2
    fi
fi
compose() { ${DOCKER} compose -f "$PWD/compose.yaml" "$@"; }

./gen-certs.sh

cleanup() {
    status=$?
    if [[ $status -ne 0 || -n "${LOGS:-}" ]]; then
        echo; echo "===== server logs (freeradius, usg-proxy, usg-home) ====="
        compose logs --no-color --tail="${LOG_TAIL:-400}" freeradius usg-proxy usg-home || true
    fi
    if [[ -z "${KEEP:-}" ]]; then
        compose --profile test down --remove-orphans --timeout 2 >/dev/null 2>&1 || true
    else
        echo "KEEP set: containers left running (compose -f $PWD/compose.yaml down to stop)"
    fi
    exit $status
}
trap cleanup EXIT

echo "== building images"
compose --profile test build
echo "== starting FreeRADIUS, usg-radius proxy, usg-radius home"
# --force-recreate: a fresh container per run, so the probe check below reads
# this run's proxy log and not a kept container's earlier lines.
compose up -d --force-recreate freeradius usg-proxy usg-home
echo "== running checks in the nas container"
compose run --rm --no-deps nas

# The proxy's own RFC 5997 probes against real home servers: proxy.json enables
# health checks, so usg-proxy sends a signed Status-Server to FreeRADIUS and to
# usg-home every 5 s, and to FreeRADIUS again inside the RadSec connection (the
# RFC 5997 probe is the application-layer watchdog of that TCP/TLS link). The only observable is the
# proxy's debug line, which the nas container cannot see, so it is scraped from
# the proxy's log here. Polled for up to 20 s in case the last probe interval
# has not elapsed yet.
echo "== checking the proxy's Status-Server probes were answered by all three home servers"
probe_answered() { # <home server name>: the proxy logged a verified reply from it
    # Captured first, then grepped: with pipefail a grep -q that exits early would
    # SIGPIPE the compose/ssh pipeline and turn a match into a failure.
    local log
    log=$(compose logs --no-color usg-proxy 2>/dev/null | perl -pe 's/\e\[[0-9;]*m//g') || true
    grep -q "Status-Server check successful.*server=$1" <<<"$log"
}
for home in freeradius freeradius-radsec usg-home; do
    i=0
    until probe_answered "$home"; do
        i=$((i + 1))
        if [[ $i -ge 20 ]]; then
            echo "FAIL  usg-proxy log has no 'Status-Server check successful' line for server=$home" >&2
            echo "      (the proxy's RFC 5997 probe was not answered, or its reply failed verification)" >&2
            exit 1
        fi
        sleep 1
    done
    echo "PASS  proxy Status-Server probe answered by $home"
done

# RadSec hop proof (scenario 15 ran through it, but the nas container only sees
# UDP). Both logs are captured first, then grepped, for the pipefail reason above.
echo "== checking the RadSec hop from the FreeRADIUS and proxy logs"
strip_ansi() { perl -pe 's/\e\[[0-9;]*m//g'; }
fr_log=$(compose logs --no-color freeradius 2>/dev/null | strip_ansi) || true
proxy_log=$(compose logs --no-color usg-proxy 2>/dev/null | strip_ansi) || true
host_check() { # <description> <command...>: PASS, or FAIL and exit 1
    local desc=$1; shift
    if "$@" >/dev/null 2>&1; then echo "PASS  $desc"; else echo "FAIL  $desc" >&2; exit 1; fi
}
absent() { ! grep -qx "$1" <<<"$2"; }                     # <line> <text>: line not in text
link_established() { # <proxy log>: one line has both the message and the server field
    grep "RadSec link established" <<<"$1" | grep -q "server=freeradius-radsec"
}
# The same line carries the negotiated key-exchange group as rustls renders
# `Option<NamedGroup>` in Debug: `group=Some(MLKEM1024)` (an unknown code point
# would render `NamedGroup(0x...)`). ML-KEM-1024 is the only group the proxy
# offers, so anything else here means the FIPS/PQ gate did not run.
link_negotiated_mlkem1024() { # <proxy log>
    grep "RadSec link established" <<<"$1" | grep "server=freeradius-radsec" \
        | grep -q 'group=Some(MLKEM1024)'
}
# FreeRADIUS (-fxx) logs one block per accepted TLS connection: the handshake
# summary, the TLS-Session-* and TLS-Client-Cert-* attributes it derived, then
# "(TLS) RADIUS/TLS - Connection Established".
host_check "FreeRADIUS accepted a RADIUS/TLS connection from the proxy (RFC 6614 2.3)" \
    grep -q 'RADIUS/TLS - Connection Established' <<<"$fr_log"
host_check "FreeRADIUS negotiated TLS 1.3 on it" \
    grep -q 'TLS-Session-Version = "TLS 1.3"' <<<"$fr_log"
host_check "FreeRADIUS negotiated TLS_AES_256_GCM_SHA384 on it (the only suite the proxy offers)" \
    grep -q 'TLS-Session-Cipher-Suite = "TLS_AES_256_GCM_SHA384"' <<<"$fr_log"
host_check "FreeRADIUS verified the proxy's client certificate (subject CN=usg-proxy)" \
    grep -q 'TLS-Client-Cert-Subject.*CN=usg-proxy' <<<"$fr_log"
# Per request FreeRADIUS logs "(N) Received Access-Request Id I from
# 10.77.0.20:P to ADDR:PORT length L" followed by "(N)   Attr = value" lines, N
# being its request counter (ADDR is 10.77.0.10 for the UDP socket and 0.0.0.0
# for the TLS listener bound to *). Map the counters that arrived on 2083 and on
# 1812 to the User-Names seen under them, and require papuser@radsec.test to
# appear only under a 2083 one. `compose logs` prefixes each line with the
# container name, so nothing is anchored to the start of the line.
requests_for() { # <port>: User-Names of the requests FreeRADIUS received on that port
    awk -v port="$1" '
        match($0, /\([0-9]+\) Received Access-Request Id [0-9]+ from [0-9.]+:[0-9]+ to [0-9.]+:[0-9]+ length/) {
            n = substr($0, RSTART + 1, index(substr($0, RSTART), ")") - 2)
            on_port[n] = (substr($0, RSTART, RLENGTH) ~ (":" port " length$"))
        }
        match($0, /\([0-9]+\)   User-Name = "/) {
            n = substr($0, RSTART + 1, index(substr($0, RSTART), ")") - 2)
            if (on_port[n]) { sub(/^.*User-Name = "/, ""); sub(/".*$/, ""); print }
        }' <<<"$fr_log"
}
on_2083=$(requests_for 2083)
on_1812=$(requests_for 1812)
host_check "papuser@radsec.test reached FreeRADIUS on port 2083 (over the RadSec connection)" \
    grep -qx 'papuser@radsec.test' <<<"$on_2083"
host_check "papuser@radsec.test never reached FreeRADIUS on UDP 1812 (fail closed, no UDP fallback)" \
    absent "papuser@radsec.test" "$on_1812"
host_check "control: papuser@freeradius.test still arrives on UDP 1812" \
    grep -qx 'papuser@freeradius.test' <<<"$on_1812"
host_check "usg-proxy logged the RadSec link to freeradius-radsec as established" \
    link_established "$proxy_log"
host_check "usg-proxy negotiated ML-KEM-1024 on that link (group=Some(MLKEM1024), FIPS 203)" \
    link_negotiated_mlkem1024 "$proxy_log"
