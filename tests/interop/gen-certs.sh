#!/usr/bin/env sh
# Generate the throw-away test PKI for the interop run: one CA, two RADIUS
# server certificates (FreeRADIUS home server, usg-radius home server), three
# EAP-TLS client certificates whose CN is the EAP identity each run uses, and a
# CRL from the CA that revokes one of them (client-usg-revoked).
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

if [ -s "$out/ca.crt" ] && [ -z "${INTEROP_REGEN_CERTS:-}" ]; then
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

rm -f ext.cnf crl.cnf ca.srl index.txt index.txt.* crlnumber crlnumber.old
chmod 0644 ./*
echo "gen-certs: wrote test PKI to $out"
ls -1 "$out"
