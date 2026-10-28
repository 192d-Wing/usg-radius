#!/usr/bin/env sh
# Generate the throw-away test PKI for the interop run: one CA, two RADIUS
# server certificates (FreeRADIUS home server, usg-radius home server; the
# FreeRADIUS one also serves its RadSec listener), one RadSec client certificate
# for the usg-radius proxy (usg-proxy, EKU clientAuth), three EAP-TLS client
# certificates whose CN is the EAP identity each run uses, a CRL from the CA
# that revokes one of them (client-usg-revoked), and a forged CRL
# (ca-wrongkey.crl) that names the CA as issuer and revokes nothing but is
# signed by a different key.
#
#   gen-certs.sh [out-dir]    # default tests/interop/certs/; run.sh passes .runs/<project>/certs
#
# Everything lands in the output directory (git-ignored) with mode 0644: the
# files are bind-mounted read-only into containers that run as unprivileged
# users (freerad, radius), and nothing here is a real secret.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/certs}
mkdir -p "$out" && out=$(cd "$out" && pwd)
days=${INTEROP_CERT_DAYS:-30}

# usg-proxy.crt and ca-wrongkey.crl are the newest files in the set: a certs/
# dir from before either was added is regenerated instead of reused.
if [ -s "$out/ca.crt" ] && [ -s "$out/usg-proxy.crt" ] && [ -s "$out/ca-wrongkey.crl" ] \
    && [ -z "${INTEROP_REGEN_CERTS:-}" ]; then
    echo "gen-certs: reusing $out (set INTEROP_REGEN_CERTS=1 to regenerate)"
    exit 0
fi

rm -rf "$out"
mkdir -p "$out"
cd "$out"

# openssl req -x509 -subj ... needs an extension file for SAN/EKU; write it once.
cat > ext.cnf <<'CNF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[server]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, 1.3.6.1.5.5.7.3.13
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:${ENV::SAN_DNS}

[client]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, 1.3.6.1.5.5.7.3.14
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

# CA (ECDSA P-256; both FreeRADIUS/OpenSSL and rustls accept it).
SAN_DNS=ca openssl ecparam -name prime256v1 -genkey -noout -out ca.key
SAN_DNS=ca openssl req -new -x509 -key ca.key -out ca.crt -days "$days" \
    -subj "/C=US/O=usg-radius interop/CN=usg-radius interop test CA" \
    -config ext.cnf -extensions ca

issue() { # issue <name> <subject CN> <section>
    name=$1 cn=$2 section=$3
    openssl ecparam -name prime256v1 -genkey -noout -out "$name.key"
    openssl req -new -key "$name.key" -out "$name.csr" \
        -subj "/C=US/O=usg-radius interop/CN=$cn"
    SAN_DNS=$cn openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out "$name.crt" -days "$days" \
        -extfile ext.cnf -extensions "$section"
    rm -f "$name.csr"
}

# Server certificates (SAN = the compose service name).
issue freeradius-server freeradius server
issue usg-home-server   usg-home   server

# RadSec client certificate for the proxy -> FreeRADIUS hop (RFC 6614 section
# 2.3: mutual TLS). FreeRADIUS checks the chain against ca.crt, not the CN.
issue usg-proxy usg-proxy client

# Client certificates: CN must equal the EAP identity. usg-radius checks that
# (EapTlsServer::verify_peer_identity); FreeRADIUS does not by default.
issue client-freeradius eaptls@freeradius.test client
issue client-usg        eaptls@usg.test        client
issue client-usg-revoked revoked@usg.test      client

# CRL: revoke client-usg-revoked. `openssl ca` needs a database and config even
# for a CA whose certificates were issued with `openssl x509 -req`; it records
# the revocation in index.txt and signs the CRL with the CA key. usg-home loads
# it as a static CRL file (eap.tls.revocation.crl.static_files).
cat > crl.cnf <<CNF
[ca]
default_ca = interop_ca

[interop_ca]
database = $out/index.txt
new_certs_dir = $out
certificate = $out/ca.crt
private_key = $out/ca.key
serial = $out/ca.srl
crlnumber = $out/crlnumber
default_md = sha256
default_crl_days = $days
policy = any_policy
unique_subject = no

[any_policy]
commonName = supplied
CNF
: > index.txt
echo 01 > crlnumber
openssl ca -config crl.cnf -revoke client-usg-revoked.crt -crl_reason keyCompromise 2>/dev/null
openssl ca -config crl.cnf -gencrl -out ca.crl 2>/dev/null
openssl crl -in ca.crl -noout -text | grep -q "Serial Number: $(openssl x509 -in client-usg-revoked.crt -noout -serial | cut -d= -f2)" \
    || { echo "gen-certs: CRL does not list client-usg-revoked" >&2; exit 1; }

# Forged CRL: same issuer Name as the CA, empty revocation list, a higher
# crlNumber, signed by an unrelated key. Without signature verification it
# would vouch for every certificate (including client-usg-revoked); usg-home-
# badcrl loads it and must reject even the valid supplicant (fail-closed).
openssl ecparam -name prime256v1 -genkey -noout -out wrongkey.key
SAN_DNS=ca openssl req -new -x509 -key wrongkey.key -out wrongkey.crt -days "$days" \
    -subj "/C=US/O=usg-radius interop/CN=usg-radius interop test CA" \
    -config ext.cnf -extensions ca
sed -e "s#^certificate = .*#certificate = $out/wrongkey.crt#" \
    -e "s#^private_key = .*#private_key = $out/wrongkey.key#" \
    -e "s#^database = .*#database = $out/wrongkey-index.txt#" crl.cnf > wrongkey.cnf
: > wrongkey-index.txt
echo 10 > crlnumber
openssl ca -config wrongkey.cnf -gencrl -out ca-wrongkey.crl 2>/dev/null
[ "$(openssl crl -in ca-wrongkey.crl -noout -issuer)" = "$(openssl x509 -in ca.crt -noout -subject | sed 's/^subject=/issuer=/')" ] \
    || { echo "gen-certs: forged CRL does not name the CA as issuer" >&2; exit 1; }
# `openssl crl -CAfile` reports the signature check as a "verify OK" or
# "verify failure" line, but its exit status differs by version (OpenSSL 3.0
# exits 0 on "verify failure", 3.5+ exits 1), so read the line, not the status.
crl_verify_result() { # crl_verify_result <crl>: prints OK, failure or the openssl error
    openssl crl -in "$1" -CAfile ca.crt -noout 2>&1 |
        sed -n -e 's/^verify OK$/OK/p' -e 's/^verify failure$/failure/p' | head -n 1
}
[ "$(crl_verify_result ca.crl)" = OK ] \
    || { echo "gen-certs: ca.crl does not verify with the CA key" >&2; exit 1; }
[ "$(crl_verify_result ca-wrongkey.crl)" = failure ] \
    || { echo "gen-certs: forged CRL verifies with the CA key (or could not be checked)" >&2; exit 1; }

rm -f ext.cnf crl.cnf wrongkey.cnf ca.srl index.txt index.txt.* wrongkey-index.txt wrongkey-index.txt.* \
    crlnumber crlnumber.old wrongkey.key wrongkey.crt
chmod 0644 ./*
echo "gen-certs: wrote test PKI to $out"
ls -1 "$out"
