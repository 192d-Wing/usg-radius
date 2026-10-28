#!/usr/bin/env bash
# Interop test driver. Generates the test PKI, builds the three images, starts
# FreeRADIUS and the usg-radius instances (proxy, home, home with a forged CRL), runs the checks in the `nas`
# container (eapol_test + radclient) and tears everything down.
#
#   tests/interop/run.sh            # build, run, tear down; exit 0 iff all checks pass
#   KEEP=1 tests/interop/run.sh     # leave the servers running afterwards
#   LOGS=1 tests/interop/run.sh     # always print the servers' logs
#   DOCKER="limactl shell myvm docker" tests/interop/run.sh   # explicit docker CLI
#
# Runs are isolated, so several worktrees can run this at once on one Docker
# host: each run has its own compose project (INTEROP_PROJECT, default
# usg-radius-interop-<hash of this directory>-<pid>), its own /24 on the
# Docker host (INTEROP_NET, default the first free 10.77.N), its own image tag
# and its own run directory (.runs/<project>: certs, rendered configs, logs).
# Teardown, also on failure or interrupt, removes that project's containers,
# network, volumes and images and nothing else. The run directory is deleted
# after a passing run and kept (with the server logs) otherwise.
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

INTEROP_PROJECT=${INTEROP_PROJECT:-usg-radius-interop-$(printf '%08x' "$(printf %s "$PWD" | cksum | cut -d' ' -f1)")-$$}
RUN_DIR=$PWD/.runs/$INTEROP_PROJECT
# Compose reads the per-run values from an env file rather than the
# environment, which `limactl shell` does not forward into the VM. Files the VM
# reads are written once and never rewritten: Lima's virtiofs mount can serve
# the old size of a file rewritten a moment earlier, which truncates it.
write_env() { # write_env <file>
    ENV_FILE=$1
    mkdir -p "$(dirname "$ENV_FILE")"
    printf 'INTEROP_PROJECT=%s\nINTEROP_CERTS=%s\nINTEROP_CONF=%s\nINTEROP_NET=%s\n' \
        "$INTEROP_PROJECT" "$RUN_DIR/certs" "${NET_DIR:-.}" "${INTEROP_NET:-10.77.0}" > "$ENV_FILE"
}
write_env "$RUN_DIR/build.env"
compose() { ${DOCKER} compose -p "$INTEROP_PROJECT" --env-file "$ENV_FILE" -f "$PWD/compose.yaml" "$@"; }
echo "run.sh: compose project $INTEROP_PROJECT, run directory $RUN_DIR"

./gen-certs.sh "$RUN_DIR/certs"

cleanup() {
    status=$?
    trap '' INT TERM HUP # a second ^C must not cut the teardown short
    mkdir -p "$RUN_DIR/logs"
    for service in freeradius usg-proxy usg-home usg-home-badcrl; do
        compose logs --no-color --timestamps "$service" > "$RUN_DIR/logs/$service.log" 2>&1 || true
    done
    if [[ $status -ne 0 || -n "${LOGS:-}" ]]; then
        echo; echo "===== server logs (freeradius, usg-proxy, usg-home, usg-home-badcrl) ====="
        compose logs --no-color --tail="${LOG_TAIL:-400}" freeradius usg-proxy usg-home usg-home-badcrl || true
    fi
    if [[ -z "${KEEP:-}" ]]; then
        compose --profile test down --remove-orphans --volumes --rmi all --timeout 2 >/dev/null 2>&1 || true
        if [[ $status -eq 0 ]]; then
            rm -rf "$RUN_DIR"
        else
            echo "run directory kept: $RUN_DIR (certs, configs, logs/)"
        fi
    else
        echo "KEEP set: containers left running in project $INTEROP_PROJECT (network ${INTEROP_NET:-none}.0/24). Stop with:"
        echo "  ${DOCKER} compose -p $INTEROP_PROJECT --env-file $ENV_FILE -f $PWD/compose.yaml --profile test down --volumes --rmi all"
    fi
    exit $status
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

echo "== building images"
compose --profile test build
echo "== starting FreeRADIUS, usg-radius proxy, usg-radius home (and home with a forged CRL)"
# The servers' configs hold the addresses, so they are rendered for the /24
# this run gets, into a new directory per attempt (net-<prefix>-<pid>/, with
# its compose.env). Docker refuses a subnet that overlaps an existing network,
# which is what makes the claim safe against a concurrent run: skip the /24s
# already in use, start from a point derived from the project name, and move on
# if another run takes the same one first.
render_configs() {
    local f
    find freeradius usg-radius -type f | while IFS= read -r f; do
        mkdir -p "$NET_DIR/$(dirname "$f")"
        sed "s/10\.77\.0\./$INTEROP_NET./g" "$f" > "$NET_DIR/$f"
    done
    chmod -R a+rX "$RUN_DIR"
}
if [[ -n "${INTEROP_NET:-}" ]]; then
    candidates=("$INTEROP_NET")
else
    # shellcheck disable=SC2046 # one argument per network ID
    in_use=" $(${DOCKER} network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' $(${DOCKER} network ls -q) 2>/dev/null | tr '\n' ' ') "
    start=$(( $(printf %s "$INTEROP_PROJECT" | cksum | cut -d' ' -f1) % 256 ))
    candidates=()
    for ((k = 0; k < 256 && ${#candidates[@]} < 16; k++)); do
        n=$(( (start + k) % 256 ))
        [[ $in_use == *" 10.77.$n.0/24 "* ]] || candidates+=("10.77.$n")
    done
fi
started=
for INTEROP_NET in ${candidates[@]+"${candidates[@]}"}; do
    NET_DIR=$RUN_DIR/net-$INTEROP_NET-$$ # new even when INTEROP_PROJECT is reused
    render_configs
    write_env "$NET_DIR/compose.env"
    # --force-recreate: a fresh container per run even with a reused
    # INTEROP_PROJECT, so the probe check below reads this run's proxy log.
    if out=$(compose up -d --force-recreate freeradius usg-proxy usg-home usg-home-badcrl 2>&1); then
        echo "$out"; started=1; break
    fi
    if ! grep -qi 'overlaps' <<<"$out"; then echo "$out" >&2; exit 1; fi
    echo "run.sh: $INTEROP_NET.0/24 is taken, trying the next one"
    compose down --remove-orphans --timeout 2 >/dev/null 2>&1 || true
done
[[ -n "$started" ]] || { echo "run.sh: no free 10.77.N.0/24 for the compose network (set INTEROP_NET)" >&2; exit 1; }
echo "run.sh: network $INTEROP_NET.0/24"
echo "== running checks in the nas container"
compose run --rm --no-deps nas

# Scenario 16's reason, from the server side: usg-home-badcrl must have refused
# the forged CRL because its signature does not verify with the CA key, not
# for some other reason (unreadable file, bad ca_path) that also ends in an
# EAP-Failure. Scraped from its log, which the nas container cannot see.
echo "== checking usg-home-badcrl rejected the CRL for its signature"
badcrl_log=$(compose logs --no-color usg-home-badcrl 2>/dev/null | perl -pe 's/\e\[[0-9;]*m//g') || true
if grep -q "ca-wrongkey.crl: CRL from .*: signature does not verify with the issuer's key" <<<"$badcrl_log"; then
    echo "PASS  usg-home-badcrl logged the CRL signature failure (RFC 5280 6.3.3)"
else
    echo "FAIL  usg-home-badcrl log has no 'signature does not verify with the issuer's key' line for ca-wrongkey.crl" >&2
    exit 1
fi

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
