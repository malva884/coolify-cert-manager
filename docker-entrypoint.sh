#!/bin/sh
set -e

CERTS="${CERTS_DIR:-/proxy/certs}"
DYNAMIC="${DYNAMIC_DIR:-/proxy/dynamic}"

mkdir -p "$CERTS" "$DYNAMIC"
# Le directory puntano a bind mount sull'host: rendile scrivibili da www-data.
# Traefik gira come root, quindi continua a leggerle senza problemi.
chown -R www-data:www-data "$CERTS" "$DYNAMIC" 2>/dev/null || true

exec "$@"
