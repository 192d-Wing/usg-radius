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
compose up -d freeradius usg-proxy usg-home
echo "== running checks in the nas container"
compose run --rm --no-deps nas
