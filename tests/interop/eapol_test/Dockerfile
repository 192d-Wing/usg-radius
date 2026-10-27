# NAS + supplicant for the interop test: eapol_test from wpa_supplicant 2.12
# (w1.fi), plus radclient from freeradius-utils for the PAP checks and the
# Status-Server readiness probes. 2.12 is the first release whose EAP-TEAP
# follows RFC 9930 (its ChangeLog: "protocol changes based on RFC 9930"); 2.11
# derived the Basic-Password-Auth MSK from S-IMCK[0] instead of S-IMCK[1] and
# would report an MS-MPPE key mismatch against an RFC 9930 server. Debian bookworm's OpenSSL 3.0 does not add a
# hybrid ML-KEM key share, so the TLS 1.3 ClientHello fits in one EAP fragment.
FROM debian:bookworm-slim AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev libnl-3-dev libnl-genl-3-dev \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ARG WPA_VERSION=2.12
ARG WPA_SHA256=08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6
RUN curl -fsSL -o wpa.tar.gz "https://w1.fi/releases/wpa_supplicant-${WPA_VERSION}.tar.gz" \
    && echo "${WPA_SHA256}  wpa.tar.gz" | sha256sum -c - \
    && tar xzf wpa.tar.gz --strip-components=1 && rm wpa.tar.gz
COPY config .config
RUN cd wpa_supplicant && cp ../.config .config && make -j"$(nproc)" eapol_test \
    && install -m 0755 eapol_test /usr/local/bin/eapol_test

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libnl-3-200 libnl-genl-3-200 freeradius-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/eapol_test /usr/local/bin/eapol_test
COPY run-tests.sh /usr/local/bin/run-tests.sh
COPY *.conf /etc/eapol_test/
RUN chmod 0755 /usr/local/bin/run-tests.sh && eapol_test 2>&1 | head -1
ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
