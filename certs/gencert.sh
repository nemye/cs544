#!/bin/bash

set -e  # Stop on error

CERT_DIR="certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "Generating CA private key and certificate..."
openssl ecparam -genkey -name prime256v1 -out ca_key.pem
openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 365 \
  -subj "/C=US/ST=CO/O=me/CN=me-ca" -out ca_cert.pem

# Server certificate -------------------------------------------------------
echo "Generating server private key..."
openssl ecparam -genkey -name prime256v1 -out server_key.pem

openssl req -new -key server_key.pem -out server_csr.pem \
  -config server_cert.conf

echo "Signing server certificate with CA..."
openssl x509 -req -in server_csr.pem -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -out server_cert.pem -days 365 -sha256 \
  -extfile server_cert.conf -extensions req_ext

# Client certificate -------------------------------------------------------
echo "Generating client private key..."
openssl ecparam -genkey -name prime256v1 -out client_key.pem

openssl req -new -key client_key.pem -out client_csr.pem \
  -config client_cert.conf

echo "Signing client certificate with CA..."
openssl x509 -req -in client_csr.pem -CA ca_cert.pem -CAkey ca_key.pem \
  -CAcreateserial -out client_cert.pem -days 365 -sha256 \
  -extfile client_cert.conf -extensions req_ext

echo "All certificates generated in '$CERT_DIR':"
ls -1 "$PWD"

rm server_csr.pem client_csr.pem

