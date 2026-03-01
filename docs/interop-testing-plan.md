# Interop Testing Plan

This document defines the expanded interoperability test suite for `cms-lib`. It
covers the complete set of fixtures to generate, the external tools needed to
generate them, the edge cases that expose real-world compatibility problems, and
the test code structure that ties everything together.

---

## 1. Goals and Principles

A CMS library is only as useful as its ability to exchange messages with the
implementations it will encounter in production. The two most important external
implementations are:

- **OpenSSL** — the de facto reference on Linux/macOS, used by most system-level
  tooling, TLS stacks, and S/MIME clients.
- **Bouncy Castle** — the dominant Java/Android implementation, used by PDF
  signing (iText, Apache PDFBox), enterprise PKI, and any JVM-based application.

Testing has two independent directions for each tool:

- **Inbound**: the external tool generates a message; our library parses and
  verifies/decrypts it. Covered by static fixtures committed to `testdata/`.
- **Outbound**: our library generates a message; the external tool verifies or
  decrypts it. Covered by dynamic round-trip tests that skip when the tool is
  absent.

Static fixtures are always preferred for the inbound direction because they run
on any machine without installing external tools, and they capture a specific
encoding that can be inspected and reasoned about.

---

## 2. Infrastructure

### 2.1 Testdata Directory Layout

```
testdata/
├── content.bin                        # shared plaintext for all fixtures
│
├── openssl/
│   ├── regen.sh                       # generates all OpenSSL fixtures
│   ├── signed/                        # SignedData fixtures
│   │   ├── rsa_ca.cert.pem
│   │   ├── ec_p256_ca.cert.pem
│   │   ├── ec_p384_ca.cert.pem
│   │   ├── ec_p521_ca.cert.pem
│   │   ├── attached_rsa_pkcs1_sha256.der
│   │   ├── detached_rsa_pkcs1_sha256.der
│   │   ├── attached_ec_p256_sha256.der
│   │   ├── detached_ec_p256_sha256.der
│   │   ├── attached_rsa_pss_sha256.der
│   │   ├── attached_rsa_pss_sha384.der
│   │   ├── attached_rsa_pss_sha512.der
│   │   ├── attached_ec_p384_sha384.der
│   │   └── attached_ec_p521_sha512.der
│   └── enveloped/                     # EnvelopedData fixtures
│       ├── rsa_recip.cert.pem
│       ├── rsa_recip.key.pem          # committed test key — not a secret
│       ├── ec_p256_recip.cert.pem
│       ├── ec_p256_recip.key.pem
│       ├── rsa_oaep_aes256cbc.der
│       ├── rsa_oaep_aes128cbc.der
│       └── ec_p256_aes256cbc.der
│
├── bc/
│   ├── regen.sh                       # downloads BC jar and runs CMSGenerator
│   ├── CMSGenerator.groovy            # Groovy fixture generator
│   ├── signed/
│   │   ├── rsa_signer.cert.pem
│   │   ├── ec_p256_signer.cert.pem
│   │   ├── ed25519_signer.cert.pem
│   │   ├── attached_rsa_pkcs1_sha256.der
│   │   ├── attached_rsa_pss_sha256.der
│   │   ├── attached_rsa_pss_sha384.der
│   │   ├── attached_ec_p256_sha256.der
│   │   ├── attached_ec_p384_sha384.der
│   │   ├── attached_ed25519.der
│   │   └── detached_rsa_pkcs1_sha256.der
│   └── enveloped/
│       ├── rsa_recip.cert.pem
│       ├── rsa_recip.key.pem
│       ├── ec_p256_recip.cert.pem
│       ├── ec_p256_recip.key.pem
│       ├── rsa_oaep_sha256_aes256cbc.der
│       └── ec_p256_aes256cbc.der
│
└── edge_cases/
    ├── gen.go                         # Go program that hand-crafts edge-case DER
    ├── sha256_null_params.der         # SHA-256 AlgID with explicit NULL
    ├── rsa_pss_trailer_explicit.der   # RSA-PSS with trailerField=1 explicit
    ├── rsa_pss_all_defaults.der       # RSA-PSS with all optional fields present
    ├── empty_certificates_set.der     # certificates [0] {}  present but empty
    ├── ber_indefinite_outer.der       # BER: outer SEQUENCE with indefinite length
    ├── ber_long_form_lengths.der      # BER: short values with long-form length encoding
    └── ber_constructed_octet.der      # BER: eContent as CONSTRUCTED OCTET STRING
```

The existing `testdata/` layout (flat `regen.sh`, flat `.der` files) will be
migrated into this structure. The interop test files will be updated to reference
the new paths.

### 2.2 Regen Script Strategy

Each regen script is independent and idempotent:

| Script | Requires | Produces |
|--------|----------|----------|
| `testdata/openssl/regen.sh` | OpenSSL 3.2+ | All `openssl/` fixtures |
| `testdata/bc/regen.sh` | JDK 21+ + internet (Maven Central) | All `bc/` fixtures |
| `testdata/edge_cases/gen.go` | Go 1.24+ | All `edge_cases/` fixtures |

Private keys committed to `testdata/` are short-lived test-only keys. They are
not secrets and must never be used in any other context. RSA keys in `testdata/`
use 2048 bits; EC keys use the appropriate curve for the fixture.

### 2.3 Test File Organization

| Test file | Covers |
|-----------|--------|
| `interop_openssl_signed_test.go` | Parse + verify all OpenSSL SignedData fixtures |
| `interop_openssl_enveloped_test.go` | Decrypt all OpenSSL EnvelopedData fixtures |
| `interop_bc_signed_test.go` | Parse + verify all BC SignedData fixtures |
| `interop_bc_enveloped_test.go` | Decrypt all BC EnvelopedData fixtures |
| `interop_edge_cases_test.go` | Parse all hand-crafted edge-case fixtures |
| `roundtrip_test.go` | (extended) Library → OpenSSL verify/decrypt; Library → BC verify/decrypt |

All `interop_*_test.go` files are package `cms` (white-box), require no external
tools, and are part of the normal `go test` run. All round-trip tests skip when
the required tool is not in PATH.

---

## 3. OpenSSL — Expanded Coverage

### 3.1 SignedData: Additional Static Fixtures

The following fixtures are added to `testdata/openssl/signed/`. Each is a DER
ContentInfo wrapping SignedData. The corresponding `regen.sh` commands are shown.

#### RSA-PSS — SHA-256, SHA-384, SHA-512

```bash
# RSA-PSS SHA-256, saltLen = 32 (= hash output size, the RFC 4055 recommendation)
openssl cms -sign \
    -in content.bin -out attached_rsa_pss_sha256.der -outform DER \
    -signer rsa_ca.cert.pem -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach \
    -md sha256 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:32

# RSA-PSS SHA-384, saltLen = 48
openssl cms -sign \
    -in content.bin -out attached_rsa_pss_sha384.der -outform DER \
    -signer rsa_ca.cert.pem -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach \
    -md sha384 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:48

# RSA-PSS SHA-512, saltLen = 64
openssl cms -sign \
    -in content.bin -out attached_rsa_pss_sha512.der -outform DER \
    -signer rsa_ca.cert.pem -inkey rsa.key.pem \
    -binary -nosmimecap -nodetach \
    -md sha512 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:64
```

**Why these matter**: OpenSSL encodes RSA-PSS parameters differently from
Bouncy Castle (see §4.4). Having all three variants as static fixtures ensures
our PSS parameter parser handles each hash/saltLen combination correctly.

#### ECDSA — P-384 and P-521

```bash
# New: P-384 key + self-signed cert
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
    -keyout ec_p384.key.pem -out ec_p384_ca.cert.pem \
    -days 36500 -nodes -subj "/CN=cms-lib-test-ec-p384-ca"

# New: P-521 key + self-signed cert
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-521 \
    -keyout ec_p521.key.pem -out ec_p521_ca.cert.pem \
    -days 36500 -nodes -subj "/CN=cms-lib-test-ec-p521-ca"

openssl cms -sign \
    -in content.bin -out attached_ec_p384_sha384.der -outform DER \
    -signer ec_p384_ca.cert.pem -inkey ec_p384.key.pem \
    -binary -nosmimecap -nodetach -md sha384

openssl cms -sign \
    -in content.bin -out attached_ec_p521_sha512.der -outform DER \
    -signer ec_p521_ca.cert.pem -inkey ec_p521.key.pem \
    -binary -nosmimecap -nodetach -md sha512
```

#### ECDSA — Detached P-256

```bash
openssl cms -sign \
    -in content.bin -out detached_ec_p256_sha256.der -outform DER \
    -signer ec_p256_ca.cert.pem -inkey ec_p256.key.pem \
    -binary -nosmimecap -md sha256
```

#### Ed25519 — Static Fixture via Python

OpenSSL 3.0/3.1 `cms -sign` is broken for Ed25519 (produces empty output). A
Python script using the `cryptography` package is used instead, since it wraps
OpenSSL 3.x at the C level where Ed25519 CMS works. This is noted in the regen
script and in a comment in the test.

```python
# testdata/openssl/gen_ed25519.py  (requires: pip install cryptography)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ...
from cryptography.hazmat.primitives.serialization import pkcs7
# generate key, self-signed cert, sign content.bin, write DER
```

### 3.2 SignedData: Expanded Dynamic Round-Trip Tests

Added to `roundtrip_test.go`, skipped when `openssl` is not in PATH:

| Test case | Key / Hash | Mode |
|-----------|------------|------|
| RSA-PSS SHA-384 attached | RSA 2048 | attached |
| RSA-PSS SHA-512 attached | RSA 2048 | attached |
| ECDSA P-384 SHA-384 attached | P-384 | attached |
| ECDSA P-521 SHA-512 attached | P-521 | attached |
| ECDSA P-256 SHA-256 detached | P-256 | detached |
| ECDSA P-384 SHA-384 detached | P-384 | detached |

Each follows the existing pattern: library signs → write to temp file →
`openssl cms -verify -in <file> -noverify`.

### 3.3 EnvelopedData: New Static Fixtures

Recipient key pairs for EnvelopedData testing are committed to the repository.
These are throwaway test keys, not production material.

```bash
# Generate RSA recipient key + self-signed cert
openssl req -x509 -newkey rsa:2048 \
    -keyout rsa_recip.key.pem -out rsa_recip.cert.pem \
    -days 36500 -nodes -subj "/CN=cms-lib-test-rsa-recip"

# Generate EC P-256 recipient key + cert
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout ec_p256_recip.key.pem -out ec_p256_recip.cert.pem \
    -days 36500 -nodes -subj "/CN=cms-lib-test-ec-recip"

# Fixture 1: RSA-OAEP (SHA-256) + AES-256-CBC
# Note: OpenSSL 3.x default for -encrypt is AES-256-CBC.
# -keyopt rsa_padding_mode:oaep selects OAEP; OpenSSL uses SHA-1 for the OAEP
# hash by default. We accept any OAEP hash in decryption.
openssl cms -encrypt \
    -in content.bin -out rsa_oaep_aes256cbc.der -outform DER \
    -recip rsa_recip.cert.pem \
    -aes-256-cbc -keyopt rsa_padding_mode:oaep

# Fixture 2: RSA-OAEP + AES-128-CBC
openssl cms -encrypt \
    -in content.bin -out rsa_oaep_aes128cbc.der -outform DER \
    -recip rsa_recip.cert.pem \
    -aes-128-cbc -keyopt rsa_padding_mode:oaep

# Fixture 3: ECDH P-256 + AES-256-CBC
openssl cms -encrypt \
    -in content.bin -out ec_p256_aes256cbc.der -outform DER \
    -recip ec_p256_recip.cert.pem \
    -aes-256-cbc
```

**Important note on OAEP hash**: OpenSSL uses SHA-1 as the OAEP hash by
default when `-keyopt rsa_padding_mode:oaep` is set without `-keyopt
rsa_oaep_md:sha256`. Our `tryDecryptKTRI` currently hardcodes `sha256.New()`.
The static fixture with OpenSSL's default SHA-1 OAEP will expose this
limitation. The test must either:

- Document the fixture as "expected to fail" (acceptable if SHA-1 OAEP is out
  of scope), or
- Drive a fix to parse the OAEP AlgorithmIdentifier parameters and select the
  correct hash dynamically.

This is a known gap; the test documents it explicitly.

### 3.4 EnvelopedData: New Dynamic Round-Trip Tests

Added to a new `roundtrip_enveloped_test.go`, skipped when `openssl` is absent:

**Outbound (library → OpenSSL decrypt)**:
```bash
openssl cms -decrypt -in <file> -inform DER \
    -recip rsa_recip.cert.pem -inkey rsa_recip.key.pem -out /dev/null
```

| Test case | Cipher | Recipient |
|-----------|--------|-----------|
| RSA-OAEP + AES-256-GCM attached | AES-256-GCM | RSA |
| RSA-OAEP + AES-256-CBC attached | AES-256-CBC | RSA |
| RSA-OAEP + AES-128-CBC attached | AES-128-CBC | RSA |
| ECDH P-256 + AES-256-GCM attached | AES-256-GCM | EC P-256 |

Note: OpenSSL 3.2+ supports AES-GCM in CMS. The round-trip test must check
the OpenSSL version and skip GCM cases on older versions.

**Inbound (OpenSSL → library decrypt)**: already covered by the static fixtures
above, loaded via `interop_openssl_enveloped_test.go`.

### 3.5 DigestedData: OpenSSL Round-Trip

OpenSSL supports DigestedData via `openssl cms -digest_create` and
`openssl cms -digest_verify`. Coverage is limited (SHA-256 only; no SHA-384/512
flags in all versions), but a basic round-trip in each direction is worth having.

```bash
# Outbound: library → openssl
openssl cms -digest_verify -in <file> -inform DER -content content.bin \
    -md sha256 -noverify

# Static fixture:
openssl cms -digest_create -in content.bin -out digested_sha256.der \
    -outform DER -md sha256
```

---

## 4. Bouncy Castle — New Coverage

### 4.1 Setup

Bouncy Castle fixtures are generated by a Groovy script using `@Grab` to pull
the BC jars from Maven Central. This requires only `groovy` (or `groovysh`) and
internet access at fixture generation time, with no Maven or Gradle build system.

```bash
# testdata/bc/regen.sh
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v groovy >/dev/null 2>&1 || { echo "groovy not found" >&2; exit 1; }
groovy CMSGenerator.groovy
```

The Groovy script generates keys in memory, writes `*.cert.pem` files (for test
trust anchors) and `*.der` files (the CMS messages). Private keys are not
written to disk.

The BC version is pinned in the `@Grab` annotation:
```groovy
@Grab('org.bouncycastle:bcpkix-jdk18on:1.79')
@Grab('org.bouncycastle:bcprov-jdk18on:1.79')
```

### 4.2 BC SignedData Fixtures

| Fixture file | Algorithm | Notes |
|---|---|---|
| `attached_rsa_pkcs1_sha256.der` | RSA PKCS1v15 SHA-256 | BC uses `sha256WithRSAEncryption` OID |
| `detached_rsa_pkcs1_sha256.der` | RSA PKCS1v15 SHA-256 detached | |
| `attached_rsa_pss_sha256.der` | RSA-PSS SHA-256 | BC PSS param encoding; see §4.4 |
| `attached_rsa_pss_sha384.der` | RSA-PSS SHA-384 | |
| `attached_ec_p256_sha256.der` | ECDSA P-256 SHA-256 | |
| `attached_ec_p384_sha384.der` | ECDSA P-384 SHA-384 | |
| `attached_ed25519.der` | Ed25519 | BC supports this; OpenSSL CLI does not |
| `attached_rsa_pkcs1_with_chain.der` | RSA PKCS1v15 SHA-256 | `certificates` field has full chain |
| `attached_rsa_pkcs1_no_certs.der` | RSA PKCS1v15 SHA-256 | `certificates` field absent |

### 4.3 BC EnvelopedData Fixtures

| Fixture file | Key transport | Cipher | Notes |
|---|---|---|---|
| `rsa_oaep_sha256_aes256cbc.der` | RSA-OAEP SHA-256 | AES-256-CBC | BC explicit OAEP params |
| `ec_p256_aes256cbc.der` | ECDH P-256 | AES-256-CBC | BC KARI encoding |

### 4.4 Bouncy Castle Encoding Differences

These are the specific ways BC produces valid-but-different ASN.1 compared to
OpenSSL. Each is a real compatibility surface that has caused bugs in other CMS
libraries.

#### RSA-PSS AlgorithmIdentifier parameters

OpenSSL encodes RSA-PSS parameters including only `hashAlgorithm` and
`saltLength` when using non-default values, omitting `trailerField`:

```
SEQUENCE {                          -- RSASSA-PSS-params
  [0] AlgorithmIdentifier sha-256
  [1] AlgorithmIdentifier MGF1-sha-256
  [2] INTEGER 32                   -- saltLength
}
```

Bouncy Castle includes all four fields explicitly, even when they are the
default value:

```
SEQUENCE {                          -- RSASSA-PSS-params
  [0] AlgorithmIdentifier sha-256
  [1] AlgorithmIdentifier MGF1-sha-256
  [2] INTEGER 32                   -- saltLength
  [3] INTEGER 1                    -- trailerField (explicit DEFAULT)
}
```

The library parser must accept both. It must also handle the case where
`hashAlgorithm` is absent (implying SHA-1) even when the actual signing hash is
something else — this would fail signature verification, but the parse must not
panic.

#### RSA signatureAlgorithm OID

- BC uses `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) — the combined OID.
- OpenSSL uses `rsaEncryption` (1.2.840.113549.1.1.1) — the base OID.

Both are RFC-compliant. The library already handles both via `isRSAPKCS1OID`.
The BC fixture confirms continued correctness.

#### SHA-2 digest AlgorithmIdentifier with explicit NULL parameters

BC includes `parameters: NULL` in the digest algorithm AlgorithmIdentifier for
SHA-256:

```
AlgorithmIdentifier {
  algorithm: 2.16.840.1.101.3.4.2.1   -- id-sha256
  parameters: NULL                      -- explicit; RFC 5754 says SHOULD be absent
}
```

RFC 5754 §2 says parameters for SHA-2 algorithms SHOULD be absent, but a
receiver MUST accept either form. The BC fixtures will include this encoding.
The library must not fail parsing or verification when NULL is present.

#### Ed25519: signatureAlgorithm parameters field

RFC 8419 §2 requires that Ed25519 `signatureAlgorithm` parameters MUST be
absent. BC follows this correctly. If any other implementation includes a NULL or
other value here, the library should either ignore it or reject it — document
which behavior is chosen.

#### ECDH originator key encoding

BC uses uncompressed point format (0x04 prefix) for the ephemeral originator
key, same as our library. This should interoperate cleanly. The fixture
confirms it.

---

## 5. Edge Cases and Non-Standard Encodings

These fixtures are hand-crafted in `testdata/edge_cases/gen.go`. They represent
technically valid CMS/ASN.1 that implementations sometimes produce but that a
naive parser may reject. Each is a `SignedData` (attached, RSA PKCS1v15 SHA-256)
unless otherwise noted, signed by the same key as the `openssl/signed/` fixtures
to reuse the trust anchors.

### 5.1 SHA-256 DigestAlgorithm with Explicit NULL Parameters

**File**: `sha256_null_params.der`

The `digestAlgorithms` SET contains `{ sha256, NULL }` instead of `{ sha256 }`.
RFC 5754 says parameters SHOULD be absent, but MUST be accepted when present.

This encoding appears in:
- Some versions of Bouncy Castle
- Some PKCS#11 hardware tokens
- Older implementations that copy the AlgorithmIdentifier format from RSA
  (where NULL is required)

The test verifies that `ParseSignedData` + `Verify` succeed.

### 5.2 RSA-PSS with trailerField Explicit

**File**: `rsa_pss_trailer_explicit.der`

RSASSA-PSS-params has `trailerField [3] INTEGER 1` explicitly present. The
default is `1` so this is redundant but legal. This is Bouncy Castle's default
encoding. The test verifies `Verify` succeeds.

### 5.3 RSA-PSS with All Optional Fields Present and Explicit

**File**: `rsa_pss_all_defaults_present.der`

All four RSASSA-PSS-params fields present with their explicit (non-default)
values: `hashAlgorithm = sha256`, `maskGenAlgorithm = MGF1-sha256`,
`saltLength = 32`, `trailerField = 1`. Tests that the parser does not treat the
presence of all fields as an error.

### 5.4 RSA-PSS with Non-Standard Salt Length

**File**: `rsa_pss_saltlen_20.der`

`saltLength = 20` (the SHA-1 default) used with SHA-256 signing. The PSS spec
allows any non-negative salt length. This is not recommended but is legal. The
test verifies: `Verify` succeeds (the library passes the explicit saltLength to
the RSA-PSS verifier rather than substituting the hash output size).

### 5.5 Empty `certificates` SET vs Absent

**File**: `empty_certificates_set.der`

The `certificates [0] IMPLICIT CertificateSet` field is present but contains an
empty SET `{  }`. This differs from the field being entirely absent. Both must
parse successfully. The library should treat an empty set the same as absent.

### 5.6 `certificates` with Extra Unrelated Certificate

**File**: `extra_cert_in_bag.der`

The `certificates` field contains the signer certificate plus one additional
unrelated certificate (a different self-signed CA). The test verifies that
`Verify` succeeds (extra certs are ignored, not treated as error), and that
`Signers()` returns only the actual signer.

### 5.7 BER — Indefinite Length on Outer SEQUENCE

**File**: `ber_indefinite_outer.der`

The outermost `ContentInfo SEQUENCE` is encoded with BER indefinite length:
`30 80 ... 00 00`. The library calls `ber.Normalize` before parsing, so this
must succeed. Tests the end-to-end path: `ParseSignedData(FromBytes(der))`.

### 5.8 BER — Non-Minimal Length Encoding

**File**: `ber_long_form_lengths.der`

Several inner TLVs use long-form length encoding for values short enough to use
short form (e.g., `81 05` instead of `05`). This must normalize successfully.

### 5.9 BER — Constructed (Chunked) OCTET STRING for eContent

**File**: `ber_constructed_octet.der`

The `eContent OCTET STRING` inside `EncapsulatedContentInfo` is encoded as a
BER constructed OCTET STRING: `24 80 04 05 hello 04 06  world 00 00`. The BER
normalizer must flatten this into a single primitive OCTET STRING. If the
normalizer passes through the constructed form, the signature will fail to verify
because the digest is computed over the content bytes, not the TLV structure.

This encoding appears in some HSM and smartcard implementations.

### 5.10 Multiple SignerInfos with Overlapping DigestAlgorithms

**File**: `multi_signer_dedup.der`

Two `SignerInfo` entries both use SHA-256. The `digestAlgorithms` SET in
`SignedData` must contain SHA-256 exactly once (per RFC 5652 §5.1 — SET OF
means no duplicates in DER). This fixture is generated by our library (which
deduplicates correctly) and verified by OpenSSL to confirm the encoding is
accepted. The test confirms `Signers()` returns two entries.

### 5.11 Counter-Signature from OpenSSL

**File**: `openssl/signed/countersig_rsa_sha256.der`

A SignedData where the primary SignerInfo has an `id-countersignature` unsigned
attribute added by OpenSSL:

```bash
openssl cms -resign -in attached_rsa_pkcs1_sha256.der -inform DER \
    -signer rsa_ca.cert.pem -inkey rsa.key.pem \
    -out countersig_rsa_sha256.der -outform DER -nodetach
```

The test verifies that `Verify` on the outer message succeeds and that the
embedded counter-signature can be extracted and is structurally valid.

### 5.12 Large Serial Number in IssuerAndSerialNumber

**File**: `large_serial_number.der`

The signer certificate has a 20-byte (160-bit) serial number with the high bit
set. This tests integer encoding: the DER encoding of the serial in
`IssuerAndSerialNumber` must include a leading zero byte to keep it positive.
Both `matchRIDTocert` and the certificate's own `SerialNumber` field must
compare equal.

### 5.13 ECDH — Compressed Ephemeral Public Key

**File**: `ec_ecdh_compressed_originator.der`

An `EnvelopedData` where the originator ephemeral key in the KARI is encoded
using compressed point format (0x02/0x03 prefix) rather than uncompressed
(0x04). Go's `crypto/ecdh.Curve.NewPublicKey` accepts both. This fixture
confirms the `parseOriginatorPublicKey` path handles compressed keys.

### 5.14 SignedData with SubjectKeyIdentifier (Version 3)

**File**: `sid_ski_version3.der`

A `SignerInfo` that uses a `SubjectKeyIdentifier` as the signer identifier
instead of `IssuerAndSerialNumber`. This requires `SignedData.version = 3` per
RFC 5652 §5.1. The fixture is generated by our library using
`WithSignerIdentifier(SubjectKeyIdentifier)` and then verified by OpenSSL
as a round-trip fixture.

---

## 6. Complete Test Matrix

### 6.1 SignedData Inbound (external → library)

| Generator | Key | Hash | Mode | Fixture file | Notes |
|-----------|-----|------|------|-------------|-------|
| OpenSSL | RSA 2048 PKCS1v15 | SHA-256 | attached | `openssl/signed/attached_rsa_pkcs1_sha256.der` | existing |
| OpenSSL | RSA 2048 PKCS1v15 | SHA-256 | detached | `openssl/signed/detached_rsa_pkcs1_sha256.der` | existing |
| OpenSSL | ECDSA P-256 | SHA-256 | attached | `openssl/signed/attached_ec_p256_sha256.der` | existing |
| OpenSSL | ECDSA P-256 | SHA-256 | detached | `openssl/signed/detached_ec_p256_sha256.der` | new |
| OpenSSL | RSA 2048 PSS | SHA-256 | attached | `openssl/signed/attached_rsa_pss_sha256.der` | new |
| OpenSSL | RSA 2048 PSS | SHA-384 | attached | `openssl/signed/attached_rsa_pss_sha384.der` | new |
| OpenSSL | RSA 2048 PSS | SHA-512 | attached | `openssl/signed/attached_rsa_pss_sha512.der` | new |
| OpenSSL | ECDSA P-384 | SHA-384 | attached | `openssl/signed/attached_ec_p384_sha384.der` | new |
| OpenSSL | ECDSA P-521 | SHA-512 | attached | `openssl/signed/attached_ec_p521_sha512.der` | new |
| OpenSSL | RSA 2048 PKCS1v15 | SHA-256 | attached | `openssl/signed/countersig_rsa_sha256.der` | new; counter-sig |
| Python/cryptography | Ed25519 | SHA-512 | attached | `openssl/signed/attached_ed25519.der` | new |
| BC | RSA PKCS1v15 | SHA-256 | attached | `bc/signed/attached_rsa_pkcs1_sha256.der` | new; combined OID |
| BC | RSA PKCS1v15 | SHA-256 | detached | `bc/signed/detached_rsa_pkcs1_sha256.der` | new |
| BC | RSA PSS | SHA-256 | attached | `bc/signed/attached_rsa_pss_sha256.der` | new; trailerField explicit |
| BC | RSA PSS | SHA-384 | attached | `bc/signed/attached_rsa_pss_sha384.der` | new |
| BC | ECDSA P-256 | SHA-256 | attached | `bc/signed/attached_ec_p256_sha256.der` | new; NULL params |
| BC | ECDSA P-384 | SHA-384 | attached | `bc/signed/attached_ec_p384_sha384.der` | new |
| BC | Ed25519 | — | attached | `bc/signed/attached_ed25519.der` | new |
| BC | RSA PKCS1v15 | SHA-256 | attached | `bc/signed/attached_rsa_pkcs1_with_chain.der` | new; chain in bag |
| BC | RSA PKCS1v15 | SHA-256 | attached | `bc/signed/attached_rsa_pkcs1_no_certs.der` | new; certs absent |
| Hand-crafted | RSA PKCS1v15 | SHA-256 | attached | `edge_cases/sha256_null_params.der` | new; NULL in algID |
| Hand-crafted | RSA PSS | SHA-256 | attached | `edge_cases/rsa_pss_trailer_explicit.der` | new |
| Hand-crafted | RSA PSS | SHA-256 | attached | `edge_cases/rsa_pss_all_defaults_present.der` | new |
| Hand-crafted | RSA PSS | SHA-256 | attached | `edge_cases/rsa_pss_saltlen_20.der` | new; non-std saltLen |
| Hand-crafted | RSA PKCS1v15 | SHA-256 | attached | `edge_cases/empty_certificates_set.der` | new |
| Hand-crafted | RSA PKCS1v15 | SHA-256 | attached | `edge_cases/extra_cert_in_bag.der` | new |
| Hand-crafted | RSA PKCS1v15 | SHA-256 | attached | `edge_cases/ber_indefinite_outer.der` | new; BER |
| Hand-crafted | RSA PKCS1v15 | SHA-256 | attached | `edge_cases/ber_long_form_lengths.der` | new; BER |
| Hand-crafted | RSA PKCS1v15 | SHA-256 | attached | `edge_cases/ber_constructed_octet.der` | new; BER |
| Hand-crafted | RSA PKCS1v15 | SHA-256 | attached | `edge_cases/large_serial_number.der` | new |

### 6.2 SignedData Outbound (library → external verify)

All in `roundtrip_test.go`, skipped when `openssl` absent:

| Key | Hash | Mode | Verifier |
|-----|------|------|----------|
| RSA 2048 PKCS1v15 | SHA-256 | attached | OpenSSL |
| RSA 2048 PKCS1v15 | SHA-256 | detached | OpenSSL |
| RSA 2048 PSS | SHA-256 | attached | OpenSSL |
| RSA 2048 PSS | SHA-384 | attached | OpenSSL |
| RSA 2048 PSS | SHA-512 | attached | OpenSSL |
| RSA 2048 PSS | SHA-256 | detached | OpenSSL |
| ECDSA P-256 | SHA-256 | attached | OpenSSL |
| ECDSA P-256 | SHA-256 | detached | OpenSSL |
| ECDSA P-384 | SHA-384 | attached | OpenSSL |
| ECDSA P-521 | SHA-512 | attached | OpenSSL |

Ed25519 is intentionally excluded: OpenSSL 3.0.x `cms -verify` with Ed25519
fails due to a known defect. The library's own `TestSignVerify_Ed25519*` tests
cover correctness independently.

### 6.3 EnvelopedData Inbound (external → library)

| Generator | Key transport | Cipher | Fixture |
|-----------|--------------|--------|---------|
| OpenSSL | RSA-OAEP (SHA-1) | AES-256-CBC | `openssl/enveloped/rsa_oaep_aes256cbc.der` |
| OpenSSL | RSA-OAEP (SHA-1) | AES-128-CBC | `openssl/enveloped/rsa_oaep_aes128cbc.der` |
| OpenSSL | ECDH P-256 | AES-256-CBC | `openssl/enveloped/ec_p256_aes256cbc.der` |
| BC | RSA-OAEP (SHA-256) | AES-256-CBC | `bc/enveloped/rsa_oaep_sha256_aes256cbc.der` |
| BC | ECDH P-256 | AES-256-CBC | `bc/enveloped/ec_p256_aes256cbc.der` |
| Hand-crafted | ECDH P-256 | AES-256-GCM | `edge_cases/ec_ecdh_compressed_originator.der` |

The OpenSSL RSA-OAEP fixture uses SHA-1 for the OAEP hash (OpenSSL's default).
If the library decryption path is hardcoded to SHA-256 for OAEP, this test is
marked as `expectedFail: true` with a comment documenting the limitation and
linking to the relevant `tryDecryptKTRI` line. This documents the behavior
rather than hiding it.

### 6.4 EnvelopedData Outbound (library → external decrypt)

All in `roundtrip_enveloped_test.go`, skipped when `openssl` absent:

| Cipher | Recipient key | OpenSSL decrypt flags |
|--------|--------------|----------------------|
| AES-256-GCM | RSA-OAEP | `-recip cert.pem -inkey key.pem` |
| AES-256-CBC | RSA-OAEP | same |
| AES-128-CBC | RSA-OAEP | same |
| AES-256-GCM | ECDH P-256 | same |

Note: AES-GCM decryption by OpenSSL requires OpenSSL 3.2+. The test detects
the version with `openssl version` and skips GCM cases on older versions.

---

## 7. Implementation Order

1. **Migrate existing flat testdata/ to the new subdirectory layout** — rename
   existing files, update `interop_test.go` and `roundtrip_test.go` paths.

2. **Expand `openssl/regen.sh`** — add all new SignedData fixtures from §3.1.
   Regenerate and commit.

3. **Expand `interop_openssl_signed_test.go`** — add test cases for new fixtures.

4. **Add `openssl/regen.sh` EnvelopedData section** — add the EnvelopedData
   fixtures from §3.3. Commit keys and DER files.

5. **Add `interop_openssl_enveloped_test.go`** — parse + decrypt each fixture.
   Handle the OAEP SHA-1 case explicitly.

6. **Add `roundtrip_enveloped_test.go`** — outbound EnvelopedData round-trips.

7. **Write `testdata/edge_cases/gen.go`** — generates all edge-case DER files.
   Run it, commit output.

8. **Add `interop_edge_cases_test.go`** — parse and verify each edge-case
   fixture.

9. **Write `testdata/bc/CMSGenerator.groovy`** and `bc/regen.sh` — generate BC
   fixtures, commit output.

10. **Add `interop_bc_signed_test.go` and `interop_bc_enveloped_test.go`**.

11. **Expand `roundtrip_test.go`** with the new outbound SignedData cases from
    §3.2.
