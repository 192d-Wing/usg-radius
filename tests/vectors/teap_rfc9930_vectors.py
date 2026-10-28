#!/usr/bin/env python3
"""Known-answer vectors for the EAP-TEAP (RFC 9930, formerly RFC 7170) key
schedule and Crypto-Binding TLV, written from the RFC text with only the
Python standard library. It shares no code with the Rust implementation; the
Rust tests in crates/radius-proto/src/eap/eap_teap.rs pin its output.

    python3 -I tests/vectors/teap_rfc9930_vectors.py          # print vectors
    python3 -I tests/vectors/teap_rfc9930_vectors.py --rust   # as Rust consts

References (RFC 9930 section numbers):
  6.1  session_key_seed = TLS-Exporter("EXPORTER: teap session key seed", , 40)
  6.2.1  IMSK[j] = 32 zero octets when the inner method yields no MSK/EMSK
         (Basic-Password-Auth)
  6.2.2  S-IMCK[0] = session_key_seed
         IMCK[j]  = first 60 octets of TLS-PRF(S-IMCK[j-1],
                    "Inner Methods Compound Keys", IMSK[j])
         S-IMCK[j] = IMCK[j][0..40], CMK[j] = IMCK[j][40..60]
  6.3  Compound MAC = first 20 octets of MAC(CMK[n], BUFFER), MAC being the
       HMAC of the TLS cipher suite's hash; BUFFER = Crypto-Binding TLV with
       both MAC fields zeroed || 0x37 || server Outer TLVs || peer Outer TLVs
  6.4  MSK  = first 64 octets of TLS-PRF(S-IMCK[n], "Session Key Generating Function")
       EMSK = first 64 octets of TLS-PRF(S-IMCK[n], "Extended Session Key Generating Function")
  4.2.13  Crypto-Binding TLV layout (Length 76), request nonce LSB 0,
          response nonce = request nonce with LSB set to 1
The TLS-PRF is RFC 5246 §5: PRF(secret, label, seed) = P_<hash>(secret, label | seed).
"""
import hashlib
import hmac
import sys

TEAP_EAP_TYPE = 0x37
TLV_CRYPTO_BINDING = 12
TLV_MANDATORY = 0x8000


def p_hash(hash_name, secret, label_and_seed, length):
    """RFC 5246 §5 P_<hash>: A(0) = seed, A(i) = HMAC(secret, A(i-1)),
    output = HMAC(secret, A(1)|seed) | HMAC(secret, A(2)|seed) | ..."""
    out = b""
    a = label_and_seed
    while len(out) < length:
        a = hmac.new(secret, a, hash_name).digest()
        out += hmac.new(secret, a + label_and_seed, hash_name).digest()
    return out[:length]


def tls_prf(hash_name, secret, label, seed, length):
    return p_hash(hash_name, secret, label.encode("ascii") + seed, length)


def self_check():
    """P_SHA256 vector published on the IETF TLS list (also in Go's crypto/tls
    and mbedTLS test suites): proves this script's PRF before it is trusted."""
    secret = bytes.fromhex("9bbe436ba940f017b17652849a71db35")
    seed = bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c")
    out = tls_prf("sha256", secret, "test label", seed, 100)
    expected = (
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
        "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
        "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701"
        "87347b66"
    )
    assert out.hex() == expected, "P_SHA256 self-check failed"


def crypto_binding_tlv(version, received_version, flags, sub_type, nonce, emsk_mac, msk_mac):
    """RFC 9930 §4.2.13, Length 76: Reserved, Version, Received-Ver,
    Flags<<4|Sub-Type, Nonce[32], EMSK Compound-MAC[20], MSK Compound-MAC[20]."""
    assert len(nonce) == 32 and len(emsk_mac) == 20 and len(msk_mac) == 20
    value = bytes([0, version, received_version, (flags << 4) | sub_type]) + nonce + emsk_mac + msk_mac
    assert len(value) == 76
    return (TLV_MANDATORY | TLV_CRYPTO_BINDING).to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def compound_mac(hash_name, cmk, tlv_zeroed, server_outer=b"", peer_outer=b""):
    buffer = tlv_zeroed + bytes([TEAP_EAP_TYPE]) + server_outer + peer_outer
    return hmac.new(cmk, buffer, hash_name).digest()[:20], buffer


def vectors(hash_name):
    session_key_seed = bytes(range(40))           # S-IMCK[0]
    imsk = bytes(32)                               # Basic-Password-Auth: no inner MSK
    request_nonce = bytes(range(0xA0, 0xC0))[:-1] + bytes([0xBE])  # LSB of last octet 0
    assert request_nonce[-1] & 1 == 0
    response_nonce = request_nonce[:-1] + bytes([request_nonce[-1] | 1])

    imck = tls_prf(hash_name, session_key_seed, "Inner Methods Compound Keys", imsk, 60)
    s_imck, cmk = imck[:40], imck[40:]

    flags_msk = 2  # only the MSK Compound-MAC is present (no inner EMSK)
    zero20 = bytes(20)
    req_zeroed = crypto_binding_tlv(1, 1, flags_msk, 0, request_nonce, zero20, zero20)
    req_mac, req_buffer = compound_mac(hash_name, cmk, req_zeroed)
    request_tlv = crypto_binding_tlv(1, 1, flags_msk, 0, request_nonce, zero20, req_mac)

    resp_zeroed = crypto_binding_tlv(1, 1, flags_msk, 1, response_nonce, zero20, zero20)
    resp_mac, _ = compound_mac(hash_name, cmk, resp_zeroed)
    response_tlv = crypto_binding_tlv(1, 1, flags_msk, 1, response_nonce, zero20, resp_mac)

    msk = tls_prf(hash_name, s_imck, "Session Key Generating Function", b"", 64)
    emsk = tls_prf(hash_name, s_imck, "Extended Session Key Generating Function", b"", 64)
    return {
        "session_key_seed": session_key_seed,
        "imck": imck,
        "s_imck": s_imck,
        "cmk": cmk,
        "request_buffer": req_buffer,
        "request_tlv": request_tlv,
        "response_tlv": response_tlv,
        "msk": msk,
        "emsk": emsk,
    }


def main():
    self_check()
    rust = "--rust" in sys.argv[1:]
    for hash_name in ("sha256", "sha384"):
        v = vectors(hash_name)
        if rust:
            print(f"    // TLS cipher suite hash {hash_name.upper()}; generated by tests/vectors/teap_rfc9930_vectors.py")
            for k, val in v.items():
                print(f"    const {hash_name.upper()}_{k.upper()}: &str = \"{val.hex()}\";")
        else:
            print(f"== {hash_name}")
            for k, val in v.items():
                print(f"{k:18} ({len(val):3}) {val.hex()}")


if __name__ == "__main__":
    main()
