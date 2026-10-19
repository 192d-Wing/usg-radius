#!/usr/bin/env sh
# Generate the throw-away test PKI for the interop run: one CA, two RADIUS
# server certificates (FreeRADIUS home server, usg-radius home server) and two
# EAP-TLS client certificates whose CN is the EAP identity each run uses.
#
# Everything lands in tests/interop/certs/ (git-ignored) with mode 0644: the
# files are bind-mounted read-only into containers that run as unprivileged
# users (freerad, radius), and nothing here is a real secret.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out="$here/certs"
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

rm -f ext.cnf ca.srl
chmod 0644 ./*
echo "gen-certs: wrote test PKI to $out"
ls -1 "$out"
