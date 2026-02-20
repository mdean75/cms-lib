#!/usr/bin/env bash
#
# testdata/regen.sh -- Regenerates OpenSSL interop test fixtures for cms-lib.
#
# Requires OpenSSL 3.0 or later. Run from any directory; the script always
# operates inside its own directory. Private keys are deleted after the
# fixtures are generated so that only public artifacts are committed.
#
# Usage:
#   bash testdata/regen.sh
#
set -euo pipefail

cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# Clean up any previous run.
# ---------------------------------------------------------------------------
rm -f rsa.key.pem rsa_ca.cert.pem
rm -f ec.key.pem  ec_ca.cert.pem
rm -f signed_attached_rsa_sha256.der
rm -f signed_detached_rsa_sha256.der
rm -f signed_attached_ec_sha256.der

# ---------------------------------------------------------------------------
# Generate keys and self-signed CA certificates.
# ---------------------------------------------------------------------------
echo "Generating RSA 2048 key and self-signed certificate..."
openssl req -x509 \
    -newkey rsa:2048 \
    -keyout rsa.key.pem \
    -out rsa_ca.cert.pem \
    -days 36500 \
    -nodes \
    -subj "/CN=cms-lib-test-rsa-ca"

echo "Generating ECDSA P-256 key and self-signed certificate..."
openssl req -x509 \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:P-256 \
    -keyout ec.key.pem \
    -out ec_ca.cert.pem \
    -days 36500 \
    -nodes \
    -subj "/CN=cms-lib-test-ec-ca"

# ---------------------------------------------------------------------------
# Create test content.
# ---------------------------------------------------------------------------
echo "Creating test content..."
printf 'Hello, cms-lib OpenSSL interop fixture.\n' > content.bin

# ---------------------------------------------------------------------------
# Sign fixtures.
# ---------------------------------------------------------------------------
echo "Signing with RSA PKCS1v15 SHA-256 (attached)..."
# -nodetach embeds the content in the SignedData (opaque/attached form).
openssl cms -sign \
    -in content.bin \
    -out signed_attached_rsa_sha256.der \
    -outform DER \
    -signer rsa_ca.cert.pem \
    -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach -md sha256 \
    -keyopt rsa_padding_mode:pkcs1

echo "Signing with RSA PKCS1v15 SHA-256 (detached)..."
# Without -nodetach, OpenSSL produces a detached signature by default.
openssl cms -sign \
    -in content.bin \
    -out signed_detached_rsa_sha256.der \
    -outform DER \
    -signer rsa_ca.cert.pem \
    -inkey rsa.key.pem \
    -binary -nosmimecap -md sha256 \
    -keyopt rsa_padding_mode:pkcs1

echo "Signing with ECDSA P-256 SHA-256 (attached)..."
openssl cms -sign \
    -in content.bin \
    -out signed_attached_ec_sha256.der \
    -outform DER \
    -signer ec_ca.cert.pem \
    -inkey ec.key.pem \
    -binary -nosmimecap -nodetach -md sha256

# ---------------------------------------------------------------------------
# Verify each fixture with OpenSSL (smoke-test the generator itself).
# ---------------------------------------------------------------------------
echo "Verifying fixtures with OpenSSL..."

openssl cms -verify \
    -in signed_attached_rsa_sha256.der -inform DER \
    -noverify -out /dev/null
echo "  signed_attached_rsa_sha256.der: OK"

openssl cms -verify \
    -in signed_detached_rsa_sha256.der -inform DER \
    -noverify -binary -content content.bin -out /dev/null
echo "  signed_detached_rsa_sha256.der: OK"

openssl cms -verify \
    -in signed_attached_ec_sha256.der -inform DER \
    -noverify -out /dev/null
echo "  signed_attached_ec_sha256.der: OK"

# ---------------------------------------------------------------------------
# Remove private keys — not committed to the repository.
# ---------------------------------------------------------------------------
echo "Removing private keys..."
rm -f rsa.key.pem ec.key.pem

echo ""
echo "Done. Generated fixtures:"
ls -lh ./*.der ./*.pem ./content.bin
