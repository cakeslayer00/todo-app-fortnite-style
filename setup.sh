#!/bin/bash
mkdir -p secrets/backend

# Generate PKCS#8 private key directly
openssl genpkey -algorithm RSA -out secrets/backend/private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -in secrets/backend/private_key.pem -pubout -out secrets/backend/public_key.pem

echo "Secrets generated successfully"