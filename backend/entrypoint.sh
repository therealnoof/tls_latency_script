#!/bin/sh
set -e

CERT_DIR="/etc/nginx/certs"

# Generate self-signed cert if none exists
if [ ! -f "$CERT_DIR/server.crt" ]; then
    echo "Generating self-signed certificate..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -days 365 \
        -subj "/CN=tls-latency-backend"
    echo "Certificate generated."
fi

echo "Starting nginx..."
exec nginx -g 'daemon off;'
