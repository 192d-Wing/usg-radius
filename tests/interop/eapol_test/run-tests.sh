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

# Lines worth keeping from an eapol_test run: outcome, TLS version, key material,
# and for TEAP the version, Compound MAC algorithm and Phase 2 outcome.
summarize_eapol() {
    grep -E '^(SUCCESS|FAILURE)$|MPPE keys OK|Using TLS version|EAP: Status notification|EAP-Key-Name|PMK mismatch|MS-MPPE-(Send|Recv)-Key|EAP-TLS: Derived key|PMK from (EAPOL|AS)|RADIUS message: code=|EAP-TEAP: (Using TEAP version|TLS cipher suite|MAC algorithm|Crypto-Binding TLV: Version|Authentication completed|Server rejected|Result:|Intermediate Result:|No username|.*did not match|Invalid)' "$1" |
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
section "4. EAP-TLS: eapol_test -> usg-radius as home server (no proxy, TLS 1.3, CRL-checked)"
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
# usg-home enforces certs/ca.crl (fail-closed), so this success also shows the
# unrevoked certificate passes the CRL check; scenario 5 shows the revoked one fails.

# ---------------------------------------------------------------------------
section "5. EAP-TLS: revoked supplicant certificate -> usg-radius home server (CRL, fail-closed)"
LOG=$LOGDIR/eap-tls-revoked-usg-home.log
eapol_test -c /etc/eapol_test/eap-tls-usg-revoked.conf -a "$USG_HOME" -p 1812 \
    -s "$NAS_USGHOME_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status non-zero (rc=$rc)" test "$rc" -ne 0
check "eapol_test printed FAILURE, not SUCCESS" sh -c "grep -qx 'FAILURE' '$LOG' && ! grep -qx 'SUCCESS' '$LOG'"
check "EAP-Failure received (rejected, not timed out)" grep -q 'EAP: Status notification: completion (param=failure)' "$LOG"

# ---------------------------------------------------------------------------
section "6. EAP-TLS: eapol_test -> usg-radius proxy -> usg-radius home server (valid certificate)"
LOG=$LOGDIR/eap-tls-usg-home-via-proxy.log
eapol_test -c /etc/eapol_test/eap-tls-usg.conf -a "$PROXY" -p 1812 \
    -s "$NAS_PROXY_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS" grep -qx 'SUCCESS' "$LOG"
check "MS-MPPE keys re-keyed by the proxy match the supplicant MSK (MPPE keys OK: 1  mismatch: 0)" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"

# ---------------------------------------------------------------------------
section "7. EAP-TLS: revoked supplicant certificate -> usg-radius proxy -> usg-radius home server"
LOG=$LOGDIR/eap-tls-revoked-via-proxy.log
eapol_test -c /etc/eapol_test/eap-tls-usg-revoked.conf -a "$PROXY" -p 1812 \
    -s "$NAS_PROXY_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status non-zero (rc=$rc)" test "$rc" -ne 0
check "eapol_test printed FAILURE, not SUCCESS" sh -c "grep -qx 'FAILURE' '$LOG' && ! grep -qx 'SUCCESS' '$LOG'"
check "EAP-Failure relayed through the proxy (rejected, not timed out)" grep -q 'EAP: Status notification: completion (param=failure)' "$LOG"

# ---------------------------------------------------------------------------
section "8. EAP-TLS: supplicant-side fragmentation (fragment_size=300) -> usg-radius home server"
LOG=$LOGDIR/eap-tls-frag-usg-home.log
eapol_test -c /etc/eapol_test/eap-tls-usg-frag.conf -a "$USG_HOME" -p 1812 \
    -s "$NAS_USGHOME_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
grep -c 'more fragments will follow' "$LOG" | sed 's/^/    supplicant fragments that needed an ACK: /'
check "control: the supplicant really fragmented (logged a fragment with more to follow)" \
    grep -q 'more fragments will follow' "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS (every non-final fragment was ACKed, RFC 5216 2.1.5)" grep -qx 'SUCCESS' "$LOG"
check "TLS 1.3 negotiated" grep -q 'Using TLS version TLSv1.3' "$LOG"
check "MS-MPPE keys match the supplicant MSK after a fragmented client flight" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"

# ---------------------------------------------------------------------------
section "9. EAP-TLS: supplicant-side fragmentation -> usg-radius proxy -> usg-radius home server"
LOG=$LOGDIR/eap-tls-frag-via-proxy.log
eapol_test -c /etc/eapol_test/eap-tls-usg-frag.conf -a "$PROXY" -p 1812 \
    -s "$NAS_PROXY_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "control: the supplicant really fragmented" grep -q 'more fragments will follow' "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS (fragment ACKs relayed by the proxy)" grep -qx 'SUCCESS' "$LOG"
check "MS-MPPE keys re-keyed by the proxy match the supplicant MSK" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"

# ---------------------------------------------------------------------------
section "10. EAP-TEAP (RFC 9930): eapol_test -> usg-radius home server (TLS 1.3, Basic-Password-Auth, SHA-384)"
LOG=$LOGDIR/eap-teap-usg-home.log
eapol_test -c /etc/eapol_test/eap-teap-usg.conf -a "$USG_HOME" -p 1812 \
    -s "$NAS_USGHOME_SECRET" -r 0 -t 15 >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS" grep -qx 'SUCCESS' "$LOG"
check "TLS 1.3 negotiated for the TEAP tunnel" grep -q 'Using TLS version TLSv1.3' "$LOG"
check "TEAP version 1 negotiated (RFC 9930 3.1)" grep -q 'EAP-TEAP: Using TEAP version 1' "$LOG"
check "server Crypto-Binding TLV accepted: Version 1, Received Version 1, Flags 2 (MSK), Sub-Type 0 (RFC 9930 4.2.13)" \
    grep -q 'EAP-TEAP: Crypto-Binding TLV: Version 1 Received Version 1 Flags 2 Sub-Type 0' "$LOG"
check "Compound MAC computed with HMAC-SHA384 for TLS_AES_256_GCM_SHA384 (RFC 9930 6.3)" \
    grep -q 'EAP-TEAP: MAC algorithm: HMAC-SHA384' "$LOG"
check "no Compound MAC mismatch" sh -c "! grep -q 'Compound MAC did not match' '$LOG'"
check "peer completed Phase 2 (Result and Intermediate-Result Success after a verified Crypto-Binding)" \
    grep -q 'EAP-TEAP: Authentication completed successfully' "$LOG"
check "EAP-Success received" grep -q 'EAP: Status notification: completion (param=success)' "$LOG"
check "MS-MPPE keys from usg-radius match the supplicant TEAP MSK (RFC 9930 6.4, S-IMCK[1] from the zero IMSK)" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"

# ---------------------------------------------------------------------------
section "11. EAP-TEAP: eapol_test -> usg-radius proxy -> usg-radius home server"
LOG=$LOGDIR/eap-teap-via-proxy.log
eapol_test -c /etc/eapol_test/eap-teap-usg.conf -a "$PROXY" -p 1812 \
    -s "$NAS_PROXY_SECRET" -r 0 -t 15 >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS" grep -qx 'SUCCESS' "$LOG"
check "peer completed Phase 2 through the proxy" grep -q 'EAP-TEAP: Authentication completed successfully' "$LOG"
check "MS-MPPE keys re-keyed by the proxy match the supplicant TEAP MSK" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"

# ---------------------------------------------------------------------------
section "12. EAP-TEAP: TLS 1.2 with AES-128-GCM-SHA256 -> usg-radius home server (SHA-256 key schedule)"
LOG=$LOGDIR/eap-teap-tls12-usg-home.log
eapol_test -c /etc/eapol_test/eap-teap-usg-tls12.conf -a "$USG_HOME" -p 1812 \
    -s "$NAS_USGHOME_SECRET" -r 0 -t 15 >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS" grep -qx 'SUCCESS' "$LOG"
check "TLS 1.2 negotiated for the TEAP tunnel" grep -q 'Using TLS version TLSv1.2' "$LOG"
check "Compound MAC computed with HMAC-SHA256 for an AES-128-GCM-SHA256 suite (RFC 9930 6.3)" \
    grep -q 'EAP-TEAP: MAC algorithm: HMAC-SHA256' "$LOG"
check "MS-MPPE keys match the supplicant TEAP MSK (SHA-256 TLS-PRF)" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"

# ---------------------------------------------------------------------------
section "13. EAP-TEAP: wrong password -> usg-radius home server (protected failure, RFC 9930 3.6.6)"
LOG=$LOGDIR/eap-teap-badpass-usg-home.log
eapol_test -c /etc/eapol_test/eap-teap-usg-badpass.conf -a "$USG_HOME" -p 1812 \
    -s "$NAS_USGHOME_SECRET" -r 0 -t 15 >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status non-zero (rc=$rc)" test "$rc" -ne 0
check "eapol_test printed FAILURE, not SUCCESS" sh -c "grep -qx 'FAILURE' '$LOG' && ! grep -qx 'SUCCESS' '$LOG'"
check "peer saw the server's Result TLV (Failure) inside the tunnel" grep -q 'EAP-TEAP: Server rejected authentication' "$LOG"
check "EAP-Failure received (rejected, not timed out)" grep -q 'EAP: Status notification: completion (param=failure)' "$LOG"
check "no key material was emitted" sh -c "! grep -q 'MS-MPPE-' '$LOG'"

# ---------------------------------------------------------------------------
section "14. Status-Server (RFC 5997) and the accounting port (RFC 2866)"
# radclient signs the Status-Server with the secret and verifies both the
# Response Authenticator and the reply's Message-Authenticator before it prints
# "Received ...", so the positive checks also cover the reply's authenticators.
# reply_has_ma proves the reply actually carries one: radclient -x prints the
# reply's attributes after the "Received ..." line (the request's own
# "Message-Authenticator = 0x00" is printed before it).
reply_has_ma() { sed -n '/Received /,$p' "$1" | grep -q 'Message-Authenticator = 0x'; }
ss() { printf 'Message-Authenticator = 0x00\n' | radclient -x -t 3 -r 1 "$1" status "$2"; }
LOG=$LOGDIR/status-server-proxy.log;      ss "$PROXY:1812"    "$NAS_PROXY_SECRET"   >"$LOG" 2>&1
check "Status-Server to the proxy (1812): Access-Accept (RFC 5997 4.2)" grep -q 'Received Access-Accept' "$LOG"
check "Status-Server to the proxy (1812): the reply carries a Message-Authenticator radclient verified (RFC 5997 5, RFC 2869 5.14)" reply_has_ma "$LOG"
LOG=$LOGDIR/status-server-home-auth.log;  ss "$USG_HOME:1812" "$NAS_USGHOME_SECRET" >"$LOG" 2>&1
check "Status-Server to usg-home 1812: Access-Accept (RFC 5997 4.2)" grep -q 'Received Access-Accept' "$LOG"
check "Status-Server to usg-home 1812: the reply carries a Message-Authenticator radclient verified (RFC 5997 5, RFC 2869 5.14)" reply_has_ma "$LOG"
LOG=$LOGDIR/status-server-home-acct.log;  ss "$USG_HOME:1813" "$NAS_USGHOME_SECRET" >"$LOG" 2>&1
check "Status-Server to usg-home 1813: Accounting-Response (RFC 5997 4.2)" grep -q 'Received Accounting-Response' "$LOG"
check "Status-Server to usg-home 1813: the reply carries a Message-Authenticator radclient verified (RFC 5997 5, RFC 2869 5.14)" reply_has_ma "$LOG"
LOG=$LOGDIR/acct-start-home-1813.log
printf 'Acct-Status-Type = Start\nAcct-Session-Id = "interop-acct-0001"\nUser-Name = "teapuser@usg.test"\nNAS-Identifier = "interop-nas"\n' |
    radclient -x -t 3 -r 1 "$USG_HOME:1813" acct "$NAS_USGHOME_SECRET" >"$LOG" 2>&1
check "Accounting-Request Start to usg-home 1813: Accounting-Response (RFC 2866)" grep -q 'Received Accounting-Response' "$LOG"
LOG=$LOGDIR/status-server-wrong-secret.log; ss "$USG_HOME:1812" "not-the-secret" >"$LOG" 2>&1
check "Status-Server with the wrong secret: silently discarded (RFC 5997 4.1)" grep -q 'No reply' "$LOG"
LOG=$LOGDIR/access-request-on-1813.log
printf 'User-Name = "teapuser@usg.test"\nUser-Password = "teap-password-456"\nNAS-Identifier = "interop-nas"\nMessage-Authenticator = 0x00\n' |
    radclient -x -t 2 -r 1 "$USG_HOME:1813" auth "$NAS_USGHOME_SECRET" >"$LOG" 2>&1
check "Access-Request to the accounting port: silently discarded (accounting has its own port, RFC 2866 2)" grep -q 'No reply' "$LOG"
LOG=$LOGDIR/acct-start-on-1812.log
printf 'Acct-Status-Type = Start\nAcct-Session-Id = "interop-acct-0002"\nUser-Name = "teapuser@usg.test"\nNAS-Identifier = "interop-nas"\n' |
    radclient -x -t 2 -r 1 "$USG_HOME:1812" acct "$NAS_USGHOME_SECRET" >"$LOG" 2>&1
check "Accounting-Request to the authentication port with a dedicated accounting socket: silently discarded" grep -q 'No reply' "$LOG"

# ---------------------------------------------------------------------------
section "15. EAP-TLS and PAP: eapol_test/radclient -> usg-radius proxy -> FreeRADIUS over RadSec (RFC 6614)"
# Realm radsec.test goes to the same FreeRADIUS as scenarios 1-3, but over the
# proxy's persistent TLS 1.3 connection to 10.77.0.10:2083 (mutual certificates,
# ML-KEM-1024) instead of UDP 1812. The hop secret is the fixed "radsec" (RFC
# 6614 2.3), so the proxy re-keys User-Password, the MS-MPPE keys and both
# authenticators between nas-proxy-secret-1 and "radsec". The nas container sees
# only the UDP side; run.sh proves from the logs that the requests arrived on
# port 2083 over TLS 1.3 / TLS_AES_256_GCM_SHA384 and never on 1812.
LOG=$LOGDIR/eap-tls-via-proxy-radsec.log
eapol_test -c /etc/eapol_test/eap-tls-radsec.conf -a "$PROXY" -p 1812 \
    -s "$NAS_PROXY_SECRET" -r 0 -t 15 -e >"$LOG" 2>&1
rc=$?
summarize_eapol "$LOG"
check "eapol_test exit status 0 (rc=$rc)" test "$rc" -eq 0
check "eapol_test printed SUCCESS" grep -qx 'SUCCESS' "$LOG"
check "EAP-Success received through the proxy over RadSec" grep -q 'EAP: Status notification: completion (param=success)' "$LOG"
check "MS-MPPE keys re-keyed from the RadSec hop to the NAS secret match the supplicant MSK (MPPE keys OK: 1  mismatch: 0)" \
    grep -q 'MPPE keys OK: 1  mismatch: 0' "$LOG"
check "no PMK mismatch reported" sh -c "! grep -q 'PMK mismatch' '$LOG'"

LOG=$LOGDIR/pap-via-proxy-radsec.log
printf 'User-Name = "papuser@radsec.test"\nUser-Password = "pap-password-123"\nNAS-Identifier = "interop-nas"\nMessage-Authenticator = 0x00\n' |
    radclient -x -t 3 -r 1 "$PROXY" auth "$NAS_PROXY_SECRET" >"$LOG" 2>&1
rc=$?
grep -E 'Received|Reply-Message|Sent|No reply' "$LOG" | sed 's/^/    /'
check "radclient exit status 0 (rc=$rc)" test "$rc" -eq 0
check "Access-Accept received (User-Password re-encrypted to the RadSec secret, RFC 6614 2.3)" grep -q 'Received Access-Accept' "$LOG"
check "FreeRADIUS Reply-Message from the RadSec realm relayed" grep -q 'PAP via usg-radius proxy over RadSec OK' "$LOG"

LOG=$LOGDIR/pap-wrong-password-via-proxy-radsec.log
printf 'User-Name = "papuser@radsec.test"\nUser-Password = "not-the-password"\nNAS-Identifier = "interop-nas"\nMessage-Authenticator = 0x00\n' |
    radclient -x -t 3 -r 1 "$PROXY" auth "$NAS_PROXY_SECRET" >"$LOG" 2>&1
grep -E 'Received|No reply' "$LOG" | sed 's/^/    /'
check "wrong password over RadSec: Access-Reject received (not a timeout, not an accept)" grep -q 'Received Access-Reject' "$LOG"

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
