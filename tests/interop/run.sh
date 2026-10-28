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
# usg-home every 5 s. The only observable is the proxy's debug line, which the
# nas container cannot see, so it is scraped from the proxy's log here. Polled
# for up to 20 s in case the last probe interval has not elapsed yet.
echo "== checking the proxy's Status-Server probes were answered by both home servers"
probe_answered() { # <home server name>: the proxy logged a verified reply from it
    # Captured first, then grepped: with pipefail a grep -q that exits early would
    # SIGPIPE the compose/ssh pipeline and turn a match into a failure.
    local log
    log=$(compose logs --no-color usg-proxy 2>/dev/null | perl -pe 's/\e\[[0-9;]*m//g') || true
    grep -q "Status-Server check successful.*server=$1" <<<"$log"
}
for home in freeradius usg-home; do
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
