#!/bin/bash
# Scenario 15, run by run-tests.sh: a NAS retransmission of an Access-Request
# gets the cached reply (RFC 5080 §2.2.2). radclient and eapol_test never
# resend a request that was answered, so this NAS is bash itself: it builds
# and signs each Access-Request (openssl for MD5 / HMAC-MD5) and sends it
# twice from one /dev/udp socket, a true retransmission (same source port,
# RADIUS Identifier, Request Authenticator and bytes). Prints PASS/FAIL lines
# like run-tests.sh and exits with the number of failed checks.
set -u

SERVER=${USG_HOME:-10.77.0.30}
SECRET=${NAS_USGHOME_SECRET:-nas-usghome-secret-3}
USER_NAME=teapuser@usg.test
NAS_ID=interop-nas
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
check() { # check <description> <command...>
    desc=$1; shift
    if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

hex() { printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'; }
unhex() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
attr() { printf '%02x%02x%s' "$1" $((${#2} / 2 + 2)) "$2"; } # attr <type> <hex value>
random_hex() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }

# access_request <id> <request authenticator hex> <attributes hex>: an
# Access-Request whose last attribute is a Message-Authenticator (RFC 3579
# §3.2) computed with the NAS secret. The secret goes on openssl's command
# line, visible in the process list: acceptable only for this throwaway
# interop secret, never a pattern for a real one.
access_request() {
    local attrs="$3$(attr 80 00000000000000000000000000000000)"
    local pkt
    pkt=$(printf '01%02x%04x%s%s' "$1" $((20 + ${#attrs} / 2)) "$2" "$attrs")
    local mac
    mac=$(unhex "$pkt" | openssl dgst -md5 -mac HMAC -macopt "key:$SECRET" | awk '{print $NF}')
    printf '%s%s' "${pkt:0:$((${#pkt} - 32))}" "$mac"
}

# send_twice <packet hex> <name>: send the packet twice over one socket and
# store each reply's hex in $WORK/<name>.1 and $WORK/<name>.2 (empty when
# no reply came within 3 s).
send_twice() {
    unhex "$1" >"$WORK/$2.req"
    exec 3<>"/dev/udp/$SERVER/1812"
    for n in 1 2; do
        dd if="$WORK/$2.req" bs=4096 count=1 status=none >&3
        timeout 3 dd bs=4096 count=1 status=none <&3 | od -An -tx1 -v | tr -d ' \n' >"$WORK/$2.$n"
    done
    exec 3<&-
}

# find_attr <reply hex> <type hex>: value of the first such attribute.
find_attr() {
    local r=$1 i=40 t l
    while [ "$i" -lt "${#r}" ]; do
        t=${r:$i:2}; l=$((16#${r:$((i + 2)):2}))
        if [ "$t" = "$2" ]; then printf '%s' "${r:$((i + 4)):$((l * 2 - 4))}"; return 0; fi
        i=$((i + l * 2))
    done
    return 1
}

# response_auth_ok <reply hex> <request authenticator hex>: RFC 2865 §3
# Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret).
response_auth_ok() {
    local r=$1
    local want
    want=$({ unhex "${r:0:8}$2${r:40}"; printf '%s' "$SECRET"; } | openssl dgst -md5 | awk '{print $NF}')
    [ "${r:8:32}" = "$want" ]
}

# message_auth_ok <reply hex> <request authenticator hex>: RFC 3579 §3.2 /
# RFC 2869 §5.14: HMAC-MD5 under the secret over the reply with the Request
# Authenticator in the header and its Message-Authenticator value zeroed.
message_auth_ok() {
    local r=$1 i=40 t l mac=
    local zeroed=${r:0:8}$2
    while [ "$i" -lt "${#r}" ]; do
        t=${r:$i:2}; l=$((16#${r:$((i + 2)):2}))
        if [ "$t" = 50 ]; then
            mac=${r:$((i + 4)):32}
            zeroed+=${r:$i:4}00000000000000000000000000000000
        else
            zeroed+=${r:$i:$((l * 2))}
        fi
        i=$((i + l * 2))
    done
    [ -n "$mac" ] || return 1
    local want
    want=$(unhex "$zeroed" | openssl dgst -md5 -mac HMAC -macopt "key:$SECRET" | awk '{print $NF}')
    [ "$mac" = "$want" ]
}

same_reply() { [ -s "$WORK/$1.1" ] && cmp -s "$WORK/$1.1" "$WORK/$1.2"; }
code_is() { [ "$(head -c 2 "$WORK/$1.1")" = "$2" ]; }

common=$(attr 1 "$(hex "$USER_NAME")")$(attr 32 "$(hex "$NAS_ID")")

# 1) EAP-Response/Identity (Identifier 7): starts a conversation. The reply
#    is an Access-Challenge with a fresh random State, so an identical second
#    reply can only be the cached one, not a second processing.
eap_identity=$(printf '0207%04x01%s' $((5 + ${#USER_NAME})) "$(hex "$USER_NAME")")
auth1=$(random_hex 16)
send_twice "$(access_request 90 "$auth1" "$common$(attr 79 "$eap_identity")")" identity
r1=$(cat "$WORK/identity.1")
state=$(find_attr "$r1" 18 || true)
eap=$(find_attr "$r1" 4f || true)
check "Identity Response: Access-Challenge" code_is identity 0b
check "Access-Challenge Response Authenticator verifies (RFC 2865 3)" response_auth_ok "$r1" "$auth1"
check "Access-Challenge Message-Authenticator verifies (RFC 3579 3.2)" message_auth_ok "$r1" "$auth1"
check "State is 16 octets (opaque CSPRNG value, not the User-Name)" sh -c "[ ${#state} -eq 32 ] && ! printf '%s' '$state' | grep -q '$(hex teapuser)'"
check "retransmitted Identity Response: the identical Access-Challenge, same random State (RFC 5080 2.2.2)" same_reply identity

# 2) EAP-Nak (RFC 3748 §5.3.1) offering no method, answering the outstanding
#    Request: the conversation ends in Access-Reject + EAP-Failure. Its
#    retransmission must get that final reply again, not a reject for a
#    conversation that no longer exists.
eap_id=${eap:2:2}
auth2=$(random_hex 16)
send_twice "$(access_request 91 "$auth2" "$common$(attr 24 "$state")$(attr 79 "02${eap_id}00060300")")" nak
r2=$(cat "$WORK/nak.1")
check "Nak answering the outstanding Request ends the conversation: Access-Reject" code_is nak 03
check "Access-Reject carries EAP-Failure with the Nak's Identifier (RFC 3579 2.6.3)" \
    sh -c "[ '$(find_attr "$r2" 4f || true)' = '04${eap_id}0004' ]"
check "Access-Reject Response Authenticator verifies" response_auth_ok "$r2" "$auth2"
check "Access-Reject Message-Authenticator verifies (RFC 3579 3.2)" message_auth_ok "$r2" "$auth2"
check "retransmitted final Access-Request: the identical Access-Reject (RFC 5080 2.2.2)" same_reply nak

exit "$failures"
