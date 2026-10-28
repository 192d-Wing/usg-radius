#!/usr/bin/env sh
# Regenerate the OpenSSL OCSP known-answer fixtures used by
# crates/radius-proto/src/revocation/ocsp.rs (tests::openssl_*).
#
# One ECDSA P-256 CA, a leaf (serial 00A5C3, top bit set), and a delegated
# responder (id-kp-OCSPSigning + id-pkix-ocsp-nocheck). `openssl ocsp` builds a
# SHA-256 CertID request for the leaf and answers it three ways: signed by the
# CA (good), signed by the delegated responder (good), and signed by the CA
# with the leaf marked revoked. A second, RSA-2048 CA covers the RSA
# signature encodings: an OCSP response and a CRL (revoking its leaf) signed
# with PKCS#1 v1.5 and with PSS. Everything is valid for ~100 years so the
# fixtures do not expire; the keys are discarded.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

cat > ext.cnf <<'CNF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash

[leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth

[responder]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
noCheck = ignored
CNF

days=36500
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.pem -days $days \
    -subj "/O=usg-radius/CN=usg-radius OCSP KAT CA" -config ext.cnf -extensions ca

issue() { # issue <name> <CN> <serial> <section>
    openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
    openssl req -new -key "$1.key" -out "$1.csr" -subj "/O=usg-radius/CN=$2"
    openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -set_serial "$3" \
        -days $days -out "$1.pem" -extfile ext.cnf -extensions "$4"
}
issue leaf "kat@usg.test" 0x00A5C3 leaf
issue responder "usg-radius OCSP KAT responder" 0x77 responder

expiry=21250101000000Z
printf 'V\t%s\t\tA5C3\tunknown\t/O=usg-radius/CN=kat@usg.test\n' $expiry > good.txt
printf 'R\t%s\t260101000000Z,keyCompromise\tA5C3\tunknown\t/O=usg-radius/CN=kat@usg.test\n' $expiry > revoked.txt

openssl ocsp -issuer ca.pem -sha256 -cert leaf.pem -no_nonce -reqout req.der
answer() { # answer <index> <signer> <out>
    openssl ocsp -index "$1" -rsigner "$2.pem" -rkey "$2.key" -CA ca.pem \
        -reqin req.der -respout "$here/$3" -ndays $days
}
answer good.txt ca resp-ca-good.der
answer good.txt responder resp-delegated-good.der
answer revoked.txt ca resp-ca-revoked.der

# RSA CA, leaf, OCSP responses and CRLs (PKCS#1 v1.5 and PSS, SHA-256).
openssl genrsa -out rsa-ca.key 2048 2>/dev/null
openssl req -new -x509 -key rsa-ca.key -out rsa-ca.pem -days $days -sha256 \
    -subj "/O=usg-radius/CN=usg-radius RSA KAT CA" -config ext.cnf -extensions ca
openssl genrsa -out rsa-leaf.key 2048 2>/dev/null
openssl req -new -key rsa-leaf.key -out rsa-leaf.csr -subj "/O=usg-radius/CN=rsa@usg.test"
openssl x509 -req -in rsa-leaf.csr -CA rsa-ca.pem -CAkey rsa-ca.key -set_serial 0x5A5A \
    -days $days -sha256 -out rsa-leaf.pem -extfile ext.cnf -extensions leaf
printf 'R\t%s\t260101000000Z,keyCompromise\t5A5A\tunknown\t/O=usg-radius/CN=rsa@usg.test\n' $expiry > rsa-index.txt
openssl ocsp -issuer rsa-ca.pem -sha256 -cert rsa-leaf.pem -no_nonce -reqout rsa-req.der
openssl ocsp -index rsa-index.txt -rsigner rsa-ca.pem -rkey rsa-ca.key -CA rsa-ca.pem \
    -reqin rsa-req.der -respout "$here/resp-rsa-revoked.der" -ndays $days -rmd sha256
openssl ocsp -index rsa-index.txt -rsigner rsa-ca.pem -rkey rsa-ca.key -CA rsa-ca.pem \
    -reqin rsa-req.der -respout "$here/resp-rsa-pss-revoked.der" -ndays $days -rmd sha256 \
    -rsigopt rsa_padding_mode:pss -rsigopt rsa_pss_saltlen:32
cat > rsa-crl.cnf <<CNF
[ca]
default_ca = kat
[kat]
database = $tmp/rsa-index.txt
certificate = $tmp/rsa-ca.pem
private_key = $tmp/rsa-ca.key
crlnumber = $tmp/rsa-crlnumber
default_md = sha256
default_crl_days = $days
CNF
echo 01 > rsa-crlnumber
openssl ca -config rsa-crl.cnf -gencrl -out rsa.crl 2>/dev/null
openssl ca -config rsa-crl.cnf -gencrl -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -out rsa-pss.crl 2>/dev/null
openssl crl -in rsa.crl -outform DER -out "$here/crl-rsa.der"
openssl crl -in rsa-pss.crl -outform DER -out "$here/crl-rsa-pss.der"

for c in ca leaf responder rsa-ca rsa-leaf; do openssl x509 -in $c.pem -outform DER -out "$here/$c.der"; done
cp req.der "$here/req.der"
echo "wrote OCSP fixtures to $here"
