# FreeRADIUS home server for the interop test, from the Debian package (3.2.x).
# Debian's package builds for amd64 and arm64, which the official
# freeradius/freeradius-server images do not (amd64 only), so this runs on
# Apple-silicon hosts too. The package's postinst generates its own bootstrap
# certificates; the interop run ignores them and uses tests/interop/certs/.
#
# trixie, not bookworm: the RadSec listener (sites-radsec) must negotiate the
# ML-KEM-1024-only key exchange the usg-radius proxy offers, and that needs
# OpenSSL 3.5 (trixie ships 3.5 and freeradius 3.2.7). bookworm's OpenSSL 3.0
# has no ML-KEM groups at all. The eapol_test image stays on bookworm (see its
# Dockerfile for why).
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        freeradius freeradius-utils openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && freeradius -v | head -1 \
    && openssl list -tls-groups | grep -qw MLKEM1024
# Interop configuration is bind-mounted over the package defaults at run time:
#   clients.conf, mods-available/eap, mods-config/files/authorize,
#   sites-enabled/radsec, certs.
# -fxx -l stdout: foreground, full debug (level 2, every attribute FreeRADIUS
# saw and sent) to stdout, so the compose logs show it. Not -X: -X is -fxx plus
# single-threaded, and FreeRADIUS refuses TLS sockets without threads
# ("Threading must be enabled for TLS sockets"). The per-request lines are the
# same as under -X, prefixed with the request number, e.g. "(N) Received
# Access-Request Id I from 10.77.0.20:P to 0.0.0.0:2083 length L" (the TLS
# listener is bound to *, so its address prints as 0.0.0.0; UDP prints
# 10.77.0.10:1812).
ENTRYPOINT ["freeradius"]
CMD ["-fxx", "-l", "stdout", "-d", "/etc/freeradius/3.0"]
