#!/usr/bin/env bash
#
# testdata/openssl/regen.sh -- Regenerates OpenSSL interop test fixtures for cms-lib.
#
# Requires OpenSSL 3.0 or later. Run from any directory; the script always
# operates relative to its own location. Signer private keys are deleted after
# the fixtures are generated. Recipient private keys are kept — they are
# committed to the repository so that decryption tests can run without
# regenerating keys.
#
# Usage:
#   bash testdata/openssl/regen.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIGNED_DIR="$SCRIPT_DIR/signed"
ENVELOPED_DIR="$SCRIPT_DIR/enveloped"
CONTENT="$SCRIPT_DIR/../../testdata/content.bin"

# ===========================================================================
# SignedData fixtures
# ===========================================================================

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
# Verify each SignedData fixture with OpenSSL.
# ---------------------------------------------------------------------------
echo "Verifying SignedData fixtures with OpenSSL..."

for f in attached_rsa_pkcs1_sha256.der attached_rsa_pss_sha256.der \
          attached_rsa_pss_sha384.der attached_rsa_pss_sha512.der \
          attached_ec_p256_sha256.der attached_ec_p384_sha384.der \
          attached_ec_p521_sha512.der; do
    openssl cms -verify -in "$f" -inform DER -noverify -out /dev/null
    echo "  $f: OK"
done

for f in detached_rsa_pkcs1_sha256.der detached_ec_p256_sha256.der; do
    openssl cms -verify -in "$f" -inform DER \
        -noverify -binary -content "$CONTENT" -out /dev/null
    echo "  $f: OK"
done

# ---------------------------------------------------------------------------
# Remove signer private keys — not committed to the repository.
# ---------------------------------------------------------------------------
echo "Removing signer private keys..."
rm -f rsa.key.pem ec_p256.key.pem ec_p384.key.pem ec_p521.key.pem

echo ""
echo "SignedData fixtures:"
ls -lh ./*.der ./*.pem

# ===========================================================================
# EnvelopedData fixtures
# ===========================================================================

cd "$ENVELOPED_DIR"

# ---------------------------------------------------------------------------
# Clean up any previous run.
# ---------------------------------------------------------------------------
rm -f rsa_recip.key.pem rsa_recip.cert.pem
rm -f ec_p256_recip.key.pem ec_p256_recip.cert.pem
rm -f rsa_oaep_sha1_aes256cbc.der
rm -f rsa_oaep_sha256_aes256cbc.der
rm -f rsa_oaep_sha1_aes128cbc.der
rm -f ec_p256_aes256cbc.der

# ---------------------------------------------------------------------------
# Generate recipient key pairs.
# These keys ARE committed to the repository — they are test-only keys,
# not secrets, and are needed for decryption tests to run without regen.
# ---------------------------------------------------------------------------
echo "Generating RSA 2048 recipient key and certificate..."
openssl req -x509 \
    -newkey rsa:2048 \
    -keyout rsa_recip.key.pem \
    -out rsa_recip.cert.pem \
    -days 36500 \
    -nodes \
    -subj "/CN=cms-lib-test-rsa-recip"

echo "Generating ECDSA P-256 recipient key and certificate..."
openssl req -x509 \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:P-256 \
    -keyout ec_p256_recip.key.pem \
    -out ec_p256_recip.cert.pem \
    -days 36500 \
    -nodes \
    -subj "/CN=cms-lib-test-ec-p256-recip"

# ---------------------------------------------------------------------------
# Generate EnvelopedData fixtures — RSA-OAEP key transport.
#
# SHA-1 variants: OpenSSL's default OAEP hash. The library hardcodes SHA-256
# in tryDecryptKTRI, so these fixtures are expected to fail decryption with
# the current implementation. They document the limitation and serve as a
# test target if the library is later updated to read the OAEP hash from
# the AlgorithmIdentifier parameters.
#
# SHA-256 variant: explicit -keyopt rsa_oaep_md:sha256. This is the variant
# the library can decrypt today and is the primary RSA interop test.
# ---------------------------------------------------------------------------
echo "Encrypting with RSA-OAEP SHA-1 (default) + AES-256-CBC..."
openssl cms -encrypt \
    -in "$CONTENT" \
    -out rsa_oaep_sha1_aes256cbc.der \
    -outform DER \
    -recip rsa_recip.cert.pem \
    -aes-256-cbc \
    -keyopt rsa_padding_mode:oaep

echo "Encrypting with RSA-OAEP SHA-256 (explicit) + AES-256-CBC..."
openssl cms -encrypt \
    -in "$CONTENT" \
    -out rsa_oaep_sha256_aes256cbc.der \
    -outform DER \
    -recip rsa_recip.cert.pem \
    -aes-256-cbc \
    -keyopt rsa_padding_mode:oaep \
    -keyopt rsa_oaep_md:sha256

echo "Encrypting with RSA-OAEP SHA-1 (default) + AES-128-CBC..."
openssl cms -encrypt \
    -in "$CONTENT" \
    -out rsa_oaep_sha1_aes128cbc.der \
    -outform DER \
    -recip rsa_recip.cert.pem \
    -aes-128-cbc \
    -keyopt rsa_padding_mode:oaep

# ---------------------------------------------------------------------------
# Generate EnvelopedData fixtures — ECDH key agreement.
# ---------------------------------------------------------------------------
echo "Encrypting with ECDH P-256 + AES-256-CBC..."
openssl cms -encrypt \
    -in "$CONTENT" \
    -out ec_p256_aes256cbc.der \
    -outform DER \
    -recip ec_p256_recip.cert.pem \
    -aes-256-cbc

# ---------------------------------------------------------------------------
# Smoke-test each fixture by decrypting with OpenSSL.
# ---------------------------------------------------------------------------
echo "Verifying EnvelopedData fixtures with OpenSSL..."

for f in rsa_oaep_sha1_aes256cbc.der rsa_oaep_sha256_aes256cbc.der \
          rsa_oaep_sha1_aes128cbc.der; do
    openssl cms -decrypt \
        -in "$f" -inform DER \
        -recip rsa_recip.cert.pem \
        -inkey rsa_recip.key.pem \
        -out /dev/null
    echo "  $f: OK"
done

openssl cms -decrypt \
    -in ec_p256_aes256cbc.der -inform DER \
    -recip ec_p256_recip.cert.pem \
    -inkey ec_p256_recip.key.pem \
    -out /dev/null
echo "  ec_p256_aes256cbc.der: OK"

# Recipient private keys are intentionally kept — see note above.

echo ""
echo "EnvelopedData fixtures:"
ls -lh ./*.der ./*.pem
