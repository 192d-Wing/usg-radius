# FreeRADIUS home server for the interop test, from the Debian package (3.2.x).
# Debian's package builds for amd64 and arm64, which the official
# freeradius/freeradius-server images do not (amd64 only), so this runs on
# Apple-silicon hosts too. The package's postinst generates its own bootstrap
# certificates; the interop run ignores them and uses tests/interop/certs/.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        freeradius freeradius-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && freeradius -v | head -1
# Interop configuration is bind-mounted over the package defaults at run time:
#   clients.conf, mods-available/eap, mods-config/files/authorize, certs.
# -X: single-threaded full debug to stdout, so the compose logs show every
# attribute FreeRADIUS saw and sent.
ENTRYPOINT ["freeradius"]
CMD ["-X", "-d", "/etc/freeradius/3.0"]
