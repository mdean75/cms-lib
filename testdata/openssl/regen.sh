#!/usr/bin/env bash
#
# testdata/openssl/regen.sh -- Regenerates OpenSSL interop test fixtures for cms-lib.
#
# Requires OpenSSL 3.0 or later. Run from any directory; the script always
# operates relative to its own location. Private keys are deleted after the
# fixtures are generated so that only public artifacts are committed.
#
# Usage:
#   bash testdata/openssl/regen.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIGNED_DIR="$SCRIPT_DIR/signed"
CONTENT="$SCRIPT_DIR/../../testdata/content.bin"

cd "$SIGNED_DIR"

# ---------------------------------------------------------------------------
# Clean up any previous run.
# ---------------------------------------------------------------------------
rm -f rsa.key.pem rsa_ca.cert.pem
rm -f ec_p256.key.pem ec_p256_ca.cert.pem
rm -f ec_p384.key.pem ec_p384_ca.cert.pem
rm -f ec_p521.key.pem ec_p521_ca.cert.pem
rm -f attached_rsa_pkcs1_sha256.der
rm -f detached_rsa_pkcs1_sha256.der
rm -f attached_rsa_pss_sha256.der
rm -f attached_rsa_pss_sha384.der
rm -f attached_rsa_pss_sha512.der
rm -f attached_ec_p256_sha256.der
rm -f detached_ec_p256_sha256.der
rm -f attached_ec_p384_sha384.der
rm -f attached_ec_p521_sha512.der

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
    -keyout ec_p256.key.pem \
    -out ec_p256_ca.cert.pem \
    -days 36500 \
    -nodes \
    -subj "/CN=cms-lib-test-ec-p256-ca"

echo "Generating ECDSA P-384 key and self-signed certificate..."
openssl req -x509 \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:P-384 \
    -keyout ec_p384.key.pem \
    -out ec_p384_ca.cert.pem \
    -days 36500 \
    -nodes \
    -subj "/CN=cms-lib-test-ec-p384-ca"

echo "Generating ECDSA P-521 key and self-signed certificate..."
openssl req -x509 \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:P-521 \
    -keyout ec_p521.key.pem \
    -out ec_p521_ca.cert.pem \
    -days 36500 \
    -nodes \
    -subj "/CN=cms-lib-test-ec-p521-ca"

# ---------------------------------------------------------------------------
# Sign fixtures — RSA PKCS1v15.
# ---------------------------------------------------------------------------
echo "Signing with RSA PKCS1v15 SHA-256 (attached)..."
# -nodetach embeds the content in the SignedData (opaque/attached form).
openssl cms -sign \
    -in "$CONTENT" \
    -out attached_rsa_pkcs1_sha256.der \
    -outform DER \
    -signer rsa_ca.cert.pem \
    -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach -md sha256 \
    -keyopt rsa_padding_mode:pkcs1

echo "Signing with RSA PKCS1v15 SHA-256 (detached)..."
# Without -nodetach, OpenSSL produces a detached signature by default.
openssl cms -sign \
    -in "$CONTENT" \
    -out detached_rsa_pkcs1_sha256.der \
    -outform DER \
    -signer rsa_ca.cert.pem \
    -inkey rsa.key.pem \
    -binary -nosmimecap -md sha256 \
    -keyopt rsa_padding_mode:pkcs1

# ---------------------------------------------------------------------------
# Sign fixtures — RSA-PSS.
# saltLen is set to the hash output size per RFC 4055 §3.1 recommendation.
# ---------------------------------------------------------------------------
echo "Signing with RSA-PSS SHA-256 (attached, saltLen=32)..."
openssl cms -sign \
    -in "$CONTENT" \
    -out attached_rsa_pss_sha256.der \
    -outform DER \
    -signer rsa_ca.cert.pem \
    -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach \
    -md sha256 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:32

echo "Signing with RSA-PSS SHA-384 (attached, saltLen=48)..."
openssl cms -sign \
    -in "$CONTENT" \
    -out attached_rsa_pss_sha384.der \
    -outform DER \
    -signer rsa_ca.cert.pem \
    -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach \
    -md sha384 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:48

echo "Signing with RSA-PSS SHA-512 (attached, saltLen=64)..."
openssl cms -sign \
    -in "$CONTENT" \
    -out attached_rsa_pss_sha512.der \
    -outform DER \
    -signer rsa_ca.cert.pem \
    -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach \
    -md sha512 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:64

# ---------------------------------------------------------------------------
# Sign fixtures — ECDSA.
# ---------------------------------------------------------------------------
echo "Signing with ECDSA P-256 SHA-256 (attached)..."
openssl cms -sign \
    -in "$CONTENT" \
    -out attached_ec_p256_sha256.der \
    -outform DER \
    -signer ec_p256_ca.cert.pem \
    -inkey ec_p256.key.pem \
    -binary -nosmimecap -nodetach -md sha256

echo "Signing with ECDSA P-256 SHA-256 (detached)..."
openssl cms -sign \
    -in "$CONTENT" \
    -out detached_ec_p256_sha256.der \
    -outform DER \
    -signer ec_p256_ca.cert.pem \
    -inkey ec_p256.key.pem \
    -binary -nosmimecap -md sha256

echo "Signing with ECDSA P-384 SHA-384 (attached)..."
openssl cms -sign \
    -in "$CONTENT" \
    -out attached_ec_p384_sha384.der \
    -outform DER \
    -signer ec_p384_ca.cert.pem \
    -inkey ec_p384.key.pem \
    -binary -nosmimecap -nodetach -md sha384

echo "Signing with ECDSA P-521 SHA-512 (attached)..."
openssl cms -sign \
    -in "$CONTENT" \
    -out attached_ec_p521_sha512.der \
    -outform DER \
    -signer ec_p521_ca.cert.pem \
    -inkey ec_p521.key.pem \
    -binary -nosmimecap -nodetach -md sha512

# ---------------------------------------------------------------------------
# Verify each fixture with OpenSSL (smoke-test the generator itself).
# ---------------------------------------------------------------------------
echo "Verifying fixtures with OpenSSL..."

openssl cms -verify \
    -in attached_rsa_pkcs1_sha256.der -inform DER \
    -noverify -out /dev/null
echo "  attached_rsa_pkcs1_sha256.der: OK"

openssl cms -verify \
    -in detached_rsa_pkcs1_sha256.der -inform DER \
    -noverify -binary -content "$CONTENT" -out /dev/null
echo "  detached_rsa_pkcs1_sha256.der: OK"

openssl cms -verify \
    -in attached_rsa_pss_sha256.der -inform DER \
    -noverify -out /dev/null
echo "  attached_rsa_pss_sha256.der: OK"

openssl cms -verify \
    -in attached_rsa_pss_sha384.der -inform DER \
    -noverify -out /dev/null
echo "  attached_rsa_pss_sha384.der: OK"

openssl cms -verify \
    -in attached_rsa_pss_sha512.der -inform DER \
    -noverify -out /dev/null
echo "  attached_rsa_pss_sha512.der: OK"

openssl cms -verify \
    -in attached_ec_p256_sha256.der -inform DER \
    -noverify -out /dev/null
echo "  attached_ec_p256_sha256.der: OK"

openssl cms -verify \
    -in detached_ec_p256_sha256.der -inform DER \
    -noverify -binary -content "$CONTENT" -out /dev/null
echo "  detached_ec_p256_sha256.der: OK"

openssl cms -verify \
    -in attached_ec_p384_sha384.der -inform DER \
    -noverify -out /dev/null
echo "  attached_ec_p384_sha384.der: OK"

openssl cms -verify \
    -in attached_ec_p521_sha512.der -inform DER \
    -noverify -out /dev/null
echo "  attached_ec_p521_sha512.der: OK"

# ---------------------------------------------------------------------------
# Remove private keys — not committed to the repository.
# ---------------------------------------------------------------------------
echo "Removing private keys..."
rm -f rsa.key.pem ec_p256.key.pem ec_p384.key.pem ec_p521.key.pem

echo ""
echo "Done. Generated fixtures:"
ls -lh ./*.der ./*.pem
