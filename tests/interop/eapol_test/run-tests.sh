#!/bin/sh
# Runs inside the `nas` container. Drives eapol_test (wpa_supplicant) and
# radclient (FreeRADIUS) against the proxy and the two home servers and asserts
# the outcomes. Exit status 0 only if every check passed.
set -u

PROXY=${PROXY:-10.77.0.20}
USG_HOME=${USG_HOME:-10.77.0.30}
FREERADIUS=${FREERADIUS:-10.77.0.10}
NAS_PROXY_SECRET=${NAS_PROXY_SECRET:-nas-proxy-secret-1}
NAS_USGHOME_SECRET=${NAS_USGHOME_SECRET:-nas-usghome-secret-3}
LOGDIR=${LOGDIR:-/tmp/interop}
mkdir -p "$LOGDIR"

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
check() { # check <description> <command...>: run quietly, PASS/FAIL on exit status
    desc=$1; shift
    if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}
section() { printf '\n== %s ==\n' "$*"; }

# Status-Server probe until a server answers (up to ~30 s).
wait_ready() { # wait_ready <name> <ip> <secret>
    i=0
    while [ $i -lt 30 ]; do
        if printf 'Message-Authenticator = 0x00\n' |
            radclient -t 1 -r 1 "$2" status "$3" >/dev/null 2>&1; then
            echo "ready: $1 ($2)"; return 0
        fi
        i=$((i + 1)); sleep 1
    done
    echo "ERROR: $1 ($2) did not answer Status-Server within 30 s"; return 1
}

# Lines worth keeping from an eapol_test run: outcome, TLS version, key material.
summarize_eapol() {
    grep -E '^(SUCCESS|FAILURE)$|MPPE keys OK|Using TLS version|EAP: Status notification|EAP-Key-Name|PMK mismatch|MS-MPPE-(Send|Recv)-Key|EAP-TLS: Derived key|PMK from (EAPOL|AS)|RADIUS message: code=' "$1" |
        sed 's/^/    /'
}

section "readiness"
wait_ready usg-proxy "$PROXY" "$NAS_PROXY_SECRET" || exit 2
wait_ready usg-home "$USG_HOME" "$NAS_USGHOME_SECRET" || exit 2
# FreeRADIUS only accepts the proxy as a client; probe it through nothing and
# just give it a moment to finish starting (the proxy test below covers it).
sleep 1

# ---------------------------------------------------------------------------
section "1+2. EAP-TLS: eapol_test -> usg-radius proxy -> FreeRADIUS"
LOG=$LOGDIR/eap-tls-via-proxy.log
eapol_test -c /etc/eapol_test/eap-tls-freeradius.conf -a "$PROXY" -p 1812 \
    -s "$NAS_PROXY_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS" grep -qx 'SUCCESS' "$LOG"
check "EAP-Success received through the proxy" grep -q 'EAP: Status notification: completion (param=success)' "$LOG"
check "MS-MPPE keys decrypted with the NAS secret match the supplicant MSK (MPPE keys OK: 1  mismatch: 0)" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"
check "no PMK mismatch reported" sh -c "! grep -q 'PMK mismatch' '$LOG'"
tlsver=$(grep -o 'Using TLS version [^ ]*' "$LOG" | tail -1)
echo "    negotiated with FreeRADIUS: ${tlsver:-unknown}"

# ---------------------------------------------------------------------------
section "3. PAP: radclient -> usg-radius proxy -> FreeRADIUS (User-Password re-keyed)"
LOG=$LOGDIR/pap-via-proxy.log
printf 'User-Name = "papuser@freeradius.test"\nUser-Password = "pap-password-123"\nNAS-Identifier = "interop-nas"\nMessage-Authenticator = 0x00\n' |
    radclient -x -t 3 -r 1 "$PROXY" auth "$NAS_PROXY_SECRET" >"$LOG" 2>&1
rc=$?
grep -E 'Received|Reply-Message|Sent|No reply' "$LOG" | sed 's/^/    /'
check "radclient exit status 0 (rc=$rc)" test "$rc" -eq 0
check "Access-Accept received" grep -q 'Received Access-Accept' "$LOG"
check "FreeRADIUS Reply-Message relayed" grep -q 'PAP via usg-radius proxy OK' "$LOG"

LOG=$LOGDIR/pap-wrong-password-via-proxy.log
printf 'User-Name = "papuser@freeradius.test"\nUser-Password = "not-the-password"\nNAS-Identifier = "interop-nas"\nMessage-Authenticator = 0x00\n' |
    radclient -x -t 3 -r 1 "$PROXY" auth "$NAS_PROXY_SECRET" >"$LOG" 2>&1
grep -E 'Received|No reply' "$LOG" | sed 's/^/    /'
check "wrong password: Access-Reject received (not a timeout, not an accept)" grep -q 'Received Access-Reject' "$LOG"

LOG=$LOGDIR/pap-direct-with-nas-secret.log
printf 'User-Name = "papuser@freeradius.test"\nUser-Password = "pap-password-123"\nNAS-Identifier = "interop-nas"\nMessage-Authenticator = 0x00\n' |
    radclient -x -t 2 -r 1 "$FREERADIUS" auth "$NAS_PROXY_SECRET" >"$LOG" 2>&1
check "control: NAS secret is not accepted by FreeRADIUS directly (secrets really differ per hop)" \
    sh -c "! grep -q 'Received Access-Accept' '$LOG'"

# ---------------------------------------------------------------------------
section "4. EAP-TLS: eapol_test -> usg-radius as home server (no proxy, TLS 1.3)"
LOG=$LOGDIR/eap-tls-usg-home.log
eapol_test -c /etc/eapol_test/eap-tls-usg.conf -a "$USG_HOME" -p 1812 \
    -s "$NAS_USGHOME_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS" grep -qx 'SUCCESS' "$LOG"
check "TLS 1.3 negotiated" grep -q 'Using TLS version TLSv1.3' "$LOG"
check "MS-MPPE keys from usg-radius match the supplicant MSK (RFC 9190 exporter)" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"
check "EAP-Key-Name from usg-radius matches the supplicant's Session-Id (Method-Id exporter)" \
    grep -q 'Locally derived EAP Session-Id matches EAP-Key-Name from server' "$LOG"

# ---------------------------------------------------------------------------
section "result"
if [ "$failures" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "$failures CHECK(S) FAILED"
    if [ -n "${INTEROP_VERBOSE:-}" ]; then
        for f in "$LOGDIR"/*.log; do echo "----- $f"; cat "$f"; done
    else
        for f in "$LOGDIR"/*.log; do echo "----- $f (tail)"; tail -40 "$f"; done
    fi
fi
exit "$failures"
