#!/bin/bash
mkdir -p secrets/backend

# PKCS#8
openssl genpkey -algorithm RSA -out services/backend/src/main/resources/private_key.pem -pkeyopt rsa_keygen_bits:2048

openssl rsa -in services/backend/src/main/resources/private_key.pem -pubout -out services/backend/src/main/resources/public_key.pem

echo "Secrets generated successfully"