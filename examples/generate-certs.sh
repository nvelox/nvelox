#!/bin/bash
# Generate self-signed TLS certificates for testing.
set -e

CERT_DIR="examples/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$CERT_DIR/server-key.pem" \
  -out "$CERT_DIR/server.pem" \
  -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

echo "Certificates generated in $CERT_DIR/"
echo "  - $CERT_DIR/server.pem"
echo "  - $CERT_DIR/server-key.pem"
