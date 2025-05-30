#!/bin/bash
./msquic/artifacts/bin/linux/x64_Release_quictls/quicsample -server \
-cert_file:./certs/quic_certificate.pem -key_file:./certs/quic_private_key.pem