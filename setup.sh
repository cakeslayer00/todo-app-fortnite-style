#!/bin/bash
set -e

SECRETS_DIR="secrets/backend"
PRIVATE_KEY="$SECRETS_DIR/private_key.pem"
PUBLIC_KEY="$SECRETS_DIR/public_key.pem"

mkdir -p "$SECRETS_DIR"

if [ -f "$PRIVATE_KEY" ] && [ -f "$PUBLIC_KEY" ]; then
    echo "Keys already exist in $SECRETS_DIR. Skipping generation."
    exit 0
fi

echo "Generating RSA keys..."

# Generate private key in PKCS#8 format (Java standard for RSA)
TEMP_PRIVATE_KEY=$(mktemp)
openssl genrsa -out "$TEMP_PRIVATE_KEY" 2048
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in "$TEMP_PRIVATE_KEY" -out "$PRIVATE_KEY"
rm "$TEMP_PRIVATE_KEY"

# Generate public key in X.509 format (Java standard for RSA)
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

# Set permissions
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo "Secrets generated successfully in $SECRETS_DIR"