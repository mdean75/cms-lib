# Remaining Work Plan — Phases 8A through 8D

## Overview

This document covers all remaining implementation work for `github.com/mdean75/cms`.
Each phase is independent and can be implemented in any order, though Phase 8D
(AuthenticatedData) has the most overlap with Phase 8C (EncryptedData) and benefits
from being done last.

| Phase | Feature | Complexity | New Files |
|---|---|---|---|
| 8A | `ParsedSignedData.Signers()` | Low | None |
| 8B | `DigestedData` (RFC 5652 §7) | Low | 2 |
| 8C | `EncryptedData` (RFC 5652 §8) | Low | 2 |
| 8D | `AuthenticatedData` (RFC 5652 §9) | High | 2 |

---

## Phase 8A — `ParsedSignedData.Signers()`

### Context

The original implementation plan included `Signers()` as a `ParsedSignedData`
introspection method, alongside `Certificates()` and `CRLs()`. It was never
implemented. It allows callers to enumerate which certificates signed a message
and inspect the algorithms used, without calling `Verify()`.

### Files to Modify

| File | Change |
|---|---|
| `signeddata.go` | Add exported `SignerInfo` type and `Signers()` method |

No new files, no new OIDs, no new ASN.1 structures.

### Public API

```go
// SignerInfo describes a single signer extracted from a parsed CMS SignedData.
// It provides the resolved certificate and algorithm identifiers without
// exposing raw ASN.1 types.
type SignerInfo struct {
    // Version is the SignerInfo syntax version: 1 for IssuerAndSerialNumber,
    // 3 for SubjectKeyIdentifier.
    Version int

    // Certificate is the signing certificate matched from the certificates
    // embedded in the SignedData. Nil if the certificate is not embedded in
    // the message (which is valid; callers may have it out of band).
    Certificate *x509.Certificate

    // DigestAlgorithm is the AlgorithmIdentifier for the message digest used
    // by this signer.
    DigestAlgorithm pkix.AlgorithmIdentifier

    // SignatureAlgorithm is the AlgorithmIdentifier for the signature algorithm,
    // including any algorithm-specific parameters (e.g., RSASSA-PSS-params).
    SignatureAlgorithm pkix.AlgorithmIdentifier

    // Signature is the raw signature bytes from the SignerInfo. For ECDSA this
    // is a DER-encoded Ecdsa-Sig-Value; for RSA it is the raw modular result.
    Signature []byte
}

// Signers returns a summary of each SignerInfo in the parsed SignedData.
// Certificates are matched from the embedded certificates field by
// IssuerAndSerialNumber (version 1) or SubjectKeyIdentifier (version 3).
// If no matching certificate is embedded, Certificate is nil.
func (p *ParsedSignedData) Signers() []SignerInfo
```

### Implementation Notes

- Iterate `p.signedData.SignerInfos` (the internal `[]pkiasn1.SignerInfo`)
- For each, attempt to find the signer certificate using the same logic as
  `findSignerCert` (already exists in `signeddata.go`)
- Do not return an error if the cert is absent — set `Certificate: nil` and
  continue; callers wanting strict cert presence use `Verify()`
- `DigestAlgorithm` and `SignatureAlgorithm` are copied directly from the internal
  `pkiasn1.SignerInfo` fields
- `Signature` is copied from `pkiasn1.SignerInfo.Signature`

### Test Cases (`signeddata_test.go` additions)

1. Single RSA signer — `Signers()` returns one entry with non-nil Certificate
2. Single ECDSA signer
3. Multiple signers — correct count, correct certs matched
4. Signer with SubjectKeyIdentifier — cert matched correctly
5. No embedded certificate — `Certificate` is nil, other fields populated

---

## Phase 8B — `DigestedData` (RFC 5652 §7)

### Context

`DigestedData` provides content integrity via a hash digest, with no signatures
and no recipients. It is the simplest CMS content type: a content plus its digest.
Callers use it to detect accidental corruption, not to authenticate a sender.

Per RFC 5652 §7.1:
```asn1
DigestedData ::= SEQUENCE {
  version    CMSVersion,
  digestAlgorithm  DigestAlgorithmIdentifier,
  encapContentInfo EncapsulatedContentInfo,
  digest     Digest }

Digest ::= OCTET STRING
```

### Files to Create

| File | Purpose |
|---|---|
| `digesteddata.go` | `Digester` builder, `ParsedDigestedData`, digest and verify logic |
| `digesteddata_test.go` | Round-trip and verification tests |

### Files to Modify

| File | Change |
|---|---|
| `internal/asn1/cms.go` | Add `DigestedData` struct |

No new OIDs required. All digest algorithm OIDs are already in `oid.go`.

### New ASN.1 Structure (`internal/asn1/cms.go`)

```go
// DigestedData represents the CMS DigestedData content type as defined in
// RFC 5652, section 7.1. It provides content integrity via a message digest
// with no cryptographic signature or recipients.
type DigestedData struct {
    // Version is 0 when EContentType is id-data; 2 for all other content types.
    Version int
    // DigestAlgorithm identifies the hash algorithm used to compute Digest.
    DigestAlgorithm pkix.AlgorithmIdentifier
    // EncapContentInfo holds the content being digested.
    EncapContentInfo EncapsulatedContentInfo
    // Digest is the computed hash of the encapsulated content OCTET STRING value.
    Digest []byte
}
```

### Public API

```go
// Digester builds a CMS DigestedData message using a fluent builder API.
// Builder methods accumulate configuration and errors; Digest reports all
// configuration errors at once.
type Digester struct { /* unexported */ }

// NewDigester returns a new Digester with default settings:
//   - SHA-256 digest algorithm
//   - Attached content
//   - id-data content type
//   - 64 MiB attached content size limit
func NewDigester() *Digester

// WithHash sets the digest algorithm. Defaults to SHA-256. Must be in the
// library allow-list (SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512).
func (d *Digester) WithHash(h crypto.Hash) *Digester

// WithContentType sets a custom eContentType OID. Default is id-data.
// A non-id-data type sets DigestedData version to 2 per RFC 5652 §7.1.
func (d *Digester) WithContentType(oid asn1.ObjectIdentifier) *Digester

// WithDetachedContent omits eContent from the output; callers must supply
// content separately during verification.
func (d *Digester) WithDetachedContent() *Digester

// WithMaxContentSize sets the maximum attached content size. Defaults to
// DefaultMaxAttachedSize (64 MiB). Has no effect in detached mode.
func (d *Digester) WithMaxContentSize(maxBytes int64) *Digester

// Digest reads content from r, computes the CMS DigestedData, and returns
// the DER-encoded ContentInfo. All builder configuration errors are reported here.
func (d *Digester) Digest(r io.Reader) ([]byte, error)


// ParsedDigestedData wraps a parsed DigestedData for verification.
type ParsedDigestedData struct { /* unexported */ }

// ParseDigestedData parses a DER-encoded CMS ContentInfo wrapping DigestedData.
func ParseDigestedData(r io.Reader) (*ParsedDigestedData, error)

// IsDetached reports whether eContent is absent from the EncapsulatedContentInfo.
func (p *ParsedDigestedData) IsDetached() bool

// Content returns an io.Reader over the encapsulated content OCTET STRING value.
// Returns ErrDetachedContentMismatch if the DigestedData is detached.
func (p *ParsedDigestedData) Content() (io.Reader, error)

// Verify recomputes the hash of the embedded content and compares it to the
// stored Digest. Returns ErrDetachedContentMismatch if called on a detached
// DigestedData; use VerifyDetached instead.
func (p *ParsedDigestedData) Verify() error

// VerifyDetached recomputes the hash of externally provided content and
// compares it to the stored Digest.
// Returns ErrDetachedContentMismatch if the DigestedData is not detached.
func (p *ParsedDigestedData) VerifyDetached(content io.Reader) error
```

### `Digest()` Workflow

1. Validate: hash is in allow-list (delegated to `newHash`)
2. Read and buffer content (up to `maxSize`)
3. Compute `digest = hashAlg.New().Write(content).Sum(nil)`
4. Build `EncapsulatedContentInfo` (same logic as `buildECI` in `signeddata.go`):
   - Attached: eContent = `[0] EXPLICIT { OCTET STRING { content } }`
   - Detached: eContent absent
5. Determine version: `id-data` → 0, any other OID → 2
6. Marshal `ContentInfo { OIDDigestedData, [0] EXPLICIT { DigestedData } }` → DER

**Digest input rule (RFC 5652 §7.2):** The hash is computed over the value octets
of eContent, i.e., the raw content bytes — not the OCTET STRING TLV, not the `[0]`
wrapper. This is identical to the content-digest computation in SignedData.

### `Verify()` / `VerifyDetached()` Workflow

1. Parse `DigestAlgorithm` → `crypto.Hash` via `hashFromOID`
2. Obtain content bytes (from embedded eContent, or from caller argument)
3. Recompute `computed = hashAlg.Hash(content)`
4. Compare `computed` to `p.digestedData.Digest` byte-for-byte
5. Return `CodeInvalidSignature` if mismatch, nil on success

### Error Mapping

| Condition | Error Code |
|---|---|
| Unsupported or absent hash algorithm | `CodeUnsupportedAlgorithm` |
| Digest mismatch | `CodeInvalidSignature` |
| ASN.1 parse error | `CodeParse` |
| Content exceeds size limit | `CodePayloadTooLarge` |
| Detached/attached mismatch | `CodeDetachedContentMismatch` |
| Wrong ContentType OID | `CodeParse` |

### Test Cases (`digesteddata_test.go`)

1. SHA-256 + attached content → Verify passes
2. SHA-384 + attached content → Verify passes
3. SHA-512 + attached content → Verify passes
4. Detached mode → VerifyDetached passes; Verify returns ErrDetachedContentMismatch
5. Attached mode → Verify passes; VerifyDetached returns ErrDetachedContentMismatch
6. Content() returns correct bytes
7. Tampered digest → Verify returns ErrInvalidSignature
8. Tampered content (Verify with wrong data) → ErrInvalidSignature
9. Empty content (0 bytes)
10. Custom content type → version 2 in output
11. Payload too large → ErrPayloadTooLarge
12. ParseDigestedData with wrong ContentType OID → ErrParse

---

## Phase 8C — `EncryptedData` (RFC 5652 §8)

### Context

`EncryptedData` provides symmetric encryption with no recipients or key management.
The symmetric key is supplied directly by the caller on both encryption and
decryption. It is suitable for protecting data at rest when the key is managed
separately (e.g., derived from a password or stored in a key management system).

Per RFC 5652 §8.1:
```asn1
EncryptedData ::= SEQUENCE {
  version              CMSVersion,
  encryptedContentInfo EncryptedContentInfo,
  unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
```

`EncryptedContentInfo` is already defined and shared with `EnvelopedData`.
Version is always 0.

### Files to Create

| File | Purpose |
|---|---|
| `encrypteddata.go` | `SymmetricEncryptor` builder, `ParsedEncryptedData`, helpers |
| `encrypteddata_test.go` | Round-trip tests for all algorithm combinations |

### Files to Modify

| File | Change |
|---|---|
| `internal/asn1/cms.go` | Add `EncryptedData` struct |

No new OIDs required. All content encryption OIDs are already in `oid.go`.
`encryptContent` and `decryptContent` in `envelopeddata.go` can be reused directly.

### New ASN.1 Structure (`internal/asn1/cms.go`)

```go
// EncryptedData represents the CMS EncryptedData content type as defined in
// RFC 5652, section 8.1. It provides symmetric encryption with no recipient
// key management — the content encryption key is provided directly by the caller.
// Version is always 0. UnprotectedAttrs is not used in this implementation.
type EncryptedData struct {
    // Version is always 0.
    Version int
    // EncryptedContentInfo holds the encrypted content and algorithm parameters.
    EncryptedContentInfo EncryptedContentInfo
}
```

### Public API

```go
// SymmetricEncryptor builds a CMS EncryptedData message using a fluent builder
// API. The caller supplies the symmetric key directly. Builder methods accumulate
// configuration and errors; Encrypt reports all configuration errors at once.
type SymmetricEncryptor struct { /* unexported */ }

// NewSymmetricEncryptor returns a new SymmetricEncryptor with default settings:
//   - AES-256-GCM content encryption
//   - id-data content type
//   - 64 MiB content size limit
func NewSymmetricEncryptor() *SymmetricEncryptor

// WithKey sets the symmetric content encryption key. Must be 16 bytes (AES-128)
// or 32 bytes (AES-256). Required.
func (se *SymmetricEncryptor) WithKey(key []byte) *SymmetricEncryptor

// WithContentEncryption sets the symmetric cipher. Defaults to AES256GCM.
// The key length must match the algorithm: 16 bytes for AES-128, 32 for AES-256.
func (se *SymmetricEncryptor) WithContentEncryption(alg ContentEncryptionAlgorithm) *SymmetricEncryptor

// WithContentType sets a custom content type OID in EncryptedContentInfo.
// Default is id-data.
func (se *SymmetricEncryptor) WithContentType(oid asn1.ObjectIdentifier) *SymmetricEncryptor

// WithMaxContentSize sets the maximum content size. Defaults to DefaultMaxAttachedSize.
func (se *SymmetricEncryptor) WithMaxContentSize(maxBytes int64) *SymmetricEncryptor

// Encrypt reads plaintext from r, encrypts it with the configured key and
// algorithm, and returns the DER-encoded ContentInfo wrapping EncryptedData.
func (se *SymmetricEncryptor) Encrypt(r io.Reader) ([]byte, error)


// ParsedEncryptedData wraps a parsed EncryptedData for decryption.
type ParsedEncryptedData struct { /* unexported */ }

// ParseEncryptedData parses a DER-encoded CMS ContentInfo wrapping EncryptedData.
func ParseEncryptedData(r io.Reader) (*ParsedEncryptedData, error)

// Decrypt decrypts the content using the supplied symmetric key and returns
// the plaintext. The key must match the algorithm used during encryption.
func (p *ParsedEncryptedData) Decrypt(key []byte) ([]byte, error)
```

### Key Validation in `WithKey` and `Encrypt()`

The key length is validated against the configured algorithm in `validate()`:
- `AES128GCM` or `AES128CBC` → key must be exactly 16 bytes
- `AES256GCM` or `AES256CBC` → key must be exactly 32 bytes
- Mismatch → `CodeInvalidConfiguration`

### `Encrypt()` Workflow

1. Validate: key present, key length matches algorithm
2. Read and buffer content (up to `maxSize`)
3. Generate a random nonce/IV; encrypt content with the provided key:
   - Reuse internal logic from `envelopeddata.go` but with the caller-supplied key
   - AES-GCM: 12-byte nonce, `GCMParameters{Nonce}` in algID params
   - AES-CBC: 16-byte IV, raw OCTET STRING in algID params
4. Build `EncryptedContentInfo` with the ciphertext in `[0] IMPLICIT`
5. Marshal `ContentInfo { OIDEncryptedData, [0] EXPLICIT { EncryptedData } }` → DER

**Implementation note:** `encryptContent` in `envelopeddata.go` generates both the
key and IV randomly. For `SymmetricEncryptor`, split this into two helpers:
`encryptWithKey(plaintext []byte, alg ContentEncryptionAlgorithm, key []byte)` that
accepts an existing key, and `generateIV(alg)` for the random IV. Alternatively,
add a `encryptContentWithKey` helper that accepts a pre-existing key — the logic
is identical to `encryptContent` minus the random key generation step.

### `Decrypt()` Workflow

1. Parse `ContentEncryptionAlgorithm` OID from `EncryptedContentInfo`
2. Validate key length matches algorithm (return `CodeInvalidConfiguration` if not)
3. Decrypt ciphertext using the key: reuse `decryptContent` from `envelopeddata.go`
4. Return plaintext bytes

### Error Mapping

| Condition | Error Code |
|---|---|
| Nil or absent key in builder | `CodeInvalidConfiguration` |
| Key length mismatches algorithm | `CodeInvalidConfiguration` |
| AES-GCM auth tag mismatch | `CodeInvalidSignature` |
| AES-CBC bad padding | `CodeInvalidSignature` |
| Wrong content type OID in parse | `CodeParse` |
| ASN.1 parse error | `CodeParse` |
| Content exceeds size limit | `CodePayloadTooLarge` |

### Test Cases (`encrypteddata_test.go`)

1. AES-256-GCM with 32-byte key (default)
2. AES-128-GCM with 16-byte key
3. AES-256-CBC with 32-byte key
4. AES-128-CBC with 16-byte key
5. Wrong key (correct length, wrong bytes) → AES-GCM auth tag failure → `ErrInvalidSignature`
6. Wrong key length → `ErrInvalidConfiguration`
7. Nil key → `ErrInvalidConfiguration`
8. Empty content (0 bytes)
9. Payload too large → `ErrPayloadTooLarge`
10. ParseEncryptedData on wrong ContentType → `ErrParse`
11. Key length mismatches algorithm (16-byte key with AES256GCM) → `ErrInvalidConfiguration`

---

## Phase 8D — `AuthenticatedData` (RFC 5652 §9)

### Context

`AuthenticatedData` provides MAC-based authentication without encryption. The content
is in plaintext; only the MAC key is protected for recipients using the same key
transport and key agreement mechanisms as `EnvelopedData`. Unlike `SignedData`, which
uses asymmetric signatures, `AuthenticatedData` uses a symmetric HMAC, making it
faster but requiring the verifier to know which recipient they are (they must decrypt
the MAC key before verifying).

Per RFC 5652 §9.1:
```asn1
AuthenticatedData ::= SEQUENCE {
  version          CMSVersion,
  originatorInfo   [0] IMPLICIT OriginatorInfo OPTIONAL,
  recipientInfos   RecipientInfos,
  macAlgorithm     MessageAuthenticationCodeAlgorithm,
  digestAlgorithm  [1] DigestAlgorithmIdentifier OPTIONAL,
  encapContentInfo EncapsulatedContentInfo,
  authAttrs        [2] IMPLICIT AuthAttributes OPTIONAL,
  mac              MessageAuthenticationCode,
  unauthAttrs      [3] IMPLICIT UnauthAttributes OPTIONAL }
```

This implementation:
- Does **not** support `originatorInfo` or `unauthAttrs`
- Always includes `authAttrs` (with mandatory `content-type` and `message-digest`)
- When `authAttrs` are present, `digestAlgorithm` MUST also be present (per RFC 5652 §9.2)
- Reuses `KeyTransRecipientInfo` (RSA-OAEP) and `KeyAgreeRecipientInfo` (ECDH) from
  `envelopeddata.go` verbatim

### Files to Create

| File | Purpose |
|---|---|
| `authenticateddata.go` | `Authenticator` builder, `ParsedAuthenticatedData`, HMAC logic |
| `authenticateddata_test.go` | Round-trip and verification tests |

### Files to Modify

| File | Change |
|---|---|
| `internal/asn1/cms.go` | Add `AuthenticatedData` struct |
| `internal/asn1/oid.go` | Add HMAC OIDs |

### New OIDs (`internal/asn1/oid.go`)

```go
// HMAC algorithm OIDs for AuthenticatedData (RFC 3370 §3.1).
var (
    // OIDMACAlgorithmHMACSHA256 identifies HMAC with SHA-256.
    OIDMACAlgorithmHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

    // OIDMACAlgorithmHMACSHA384 identifies HMAC with SHA-384.
    OIDMACAlgorithmHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}

    // OIDMACAlgorithmHMACSHA512 identifies HMAC with SHA-512.
    OIDMACAlgorithmHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
)
```

The `digestAlgorithm` field (when present) reuses the existing SHA-2 digest OIDs
(`OIDDigestAlgorithmSHA256/384/512`).

### New ASN.1 Structure (`internal/asn1/cms.go`)

```go
// AuthenticatedData represents the CMS AuthenticatedData content type as defined
// in RFC 5652, section 9.1. It provides MAC-based message authentication for one
// or more recipients. OriginatorInfo and UnauthAttrs are not used in this
// implementation.
type AuthenticatedData struct {
    // Version is 0 when all RecipientInfos are KeyTransRecipientInfo v0 and the
    // content type is id-data; 1 for other KTRI configurations; 2 when any KARI
    // is present.
    Version int
    // RecipientInfos is the SET of per-recipient MAC key transport or key
    // agreement information. Reuses the same types as EnvelopedData.
    RecipientInfos []asn1.RawValue `asn1:"set"`
    // MACAlgorithm identifies the HMAC algorithm (HMAC-SHA256/384/512).
    MACAlgorithm pkix.AlgorithmIdentifier
    // DigestAlgorithm identifies the hash used to compute the message-digest
    // authAttr. MUST be present when AuthAttrs are present (RFC 5652 §9.2).
    DigestAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
    // EncapContentInfo holds the plaintext content being authenticated.
    EncapContentInfo EncapsulatedContentInfo
    // AuthAttrs is the optional [2] IMPLICIT SET of authenticated attributes.
    // When present, the MAC is computed over DER(authAttrs), not the content.
    // content-type and message-digest MUST be present when AuthAttrs is non-empty.
    AuthAttrs asn1.RawValue `asn1:"optional,tag:2"`
    // MAC is the computed HMAC value over the authenticated attributes (or
    // directly over content if AuthAttrs is absent).
    MAC []byte
    // UnauthAttrs is omitted in this implementation.
}
```

### Public API

```go
// MACAlgorithm identifies the HMAC algorithm used in AuthenticatedData.
type MACAlgorithm int

const (
    // HMACSHA256 selects HMAC with SHA-256. This is the default.
    HMACSHA256 MACAlgorithm = iota
    // HMACSHA384 selects HMAC with SHA-384.
    HMACSHA384
    // HMACSHA512 selects HMAC with SHA-512.
    HMACSHA512
)

// Authenticator builds a CMS AuthenticatedData message using a fluent builder
// API. The MAC key is generated internally and distributed to recipients using
// the same RSA-OAEP / ECDH mechanisms as Encryptor. Builder methods accumulate
// configuration and errors; Authenticate reports all configuration errors at once.
type Authenticator struct { /* unexported */ }

// NewAuthenticator returns a new Authenticator with default settings:
//   - HMAC-SHA256 MAC algorithm
//   - id-data content type
//   - 64 MiB content size limit
func NewAuthenticator() *Authenticator

// WithRecipient adds a recipient certificate for MAC key delivery. Auto-selects
// RSA-OAEP (RSA key) or ECDH ephemeral-static (EC key). At least one recipient
// is required. Same validation rules as Encryptor.WithRecipient.
func (a *Authenticator) WithRecipient(cert *x509.Certificate) *Authenticator

// WithMACAlgorithm sets the HMAC algorithm. Defaults to HMACSHA256.
func (a *Authenticator) WithMACAlgorithm(alg MACAlgorithm) *Authenticator

// WithContentType sets a custom eContentType OID. Default is id-data.
func (a *Authenticator) WithContentType(oid asn1.ObjectIdentifier) *Authenticator

// WithMaxContentSize sets the maximum content size. Defaults to DefaultMaxAttachedSize.
func (a *Authenticator) WithMaxContentSize(maxBytes int64) *Authenticator

// Authenticate reads content from r, generates a random MAC key, distributes it
// to all configured recipients, computes the HMAC, and returns the DER-encoded
// ContentInfo wrapping AuthenticatedData.
func (a *Authenticator) Authenticate(r io.Reader) ([]byte, error)


// ParsedAuthenticatedData wraps a parsed AuthenticatedData for verification.
type ParsedAuthenticatedData struct { /* unexported */ }

// ParseAuthenticatedData parses a DER-encoded CMS ContentInfo wrapping
// AuthenticatedData.
func ParseAuthenticatedData(r io.Reader) (*ParsedAuthenticatedData, error)

// Content returns an io.Reader over the plaintext encapsulated content.
// AuthenticatedData content is never detached in this implementation.
func (p *ParsedAuthenticatedData) Content() (io.Reader, error)

// VerifyMAC decrypts the MAC key using the provided private key and certificate,
// then verifies the HMAC against the encapsulated content. Returns
// ErrMissingCertificate if no matching RecipientInfo is found.
func (p *ParsedAuthenticatedData) VerifyMAC(key crypto.PrivateKey, cert *x509.Certificate) error
```

### HMAC Key Size

The MAC key length is determined by the chosen `MACAlgorithm`:
- `HMACSHA256` → 32-byte key (matches SHA-256 output length, per SP 800-107 guidance)
- `HMACSHA384` → 48-byte key
- `HMACSHA512` → 64-byte key

This ensures the key is at least as long as the hash output, which is the standard
practice for HMAC key length.

### `Authenticate()` Workflow

1. Validate: ≥1 recipient, algorithm valid; no config errors
2. Read and buffer content (up to `maxSize`)
3. Generate random MAC key (`macKeyLen` bytes)
4. Compute `messageDigest = digestAlg.Hash(content)` (same hash family as the HMAC)
5. Build `authAttrs` SET with two mandatory attributes:
   - `id-contentType` → eContentType OID
   - `id-messageDigest` → messageDigest bytes
6. DER-encode `authAttrs` as a SET (using `marshalAttributes`); this is the exact same
   pattern as `signedAttrs` in `signeddata.go`
7. Compute `mac = HMAC(macKey, DER(authAttrs))` with the [2] IMPLICIT wire tag
   replaced by the EXPLICIT SET tag (0x31) before hashing — same substitution used
   for `signedAttrs` digest in `SignedData`
8. For each recipient, encrypt the MAC key (same code paths as `EnvelopedData`):
   - RSA key → `buildRSARecipientInfo(cert, macKey)`
   - EC key → `buildECDHRecipientInfo(cert, macKey)`
9. Determine version (see Version Rules below)
10. Marshal `ContentInfo { OIDAuthenticatedData, [0] EXPLICIT { AuthenticatedData } }` → DER

**AuthAttrs wire encoding:** On the wire, `authAttrs` uses IMPLICIT tag [2] (0xA2).
Store the DER SET bytes and retag from 0x31 → 0xA2 before encoding (same pattern as
`retagAsImplicit0` / `retagAsImplicit1` in `signeddata.go`).

**MAC input:** The MAC is computed over the DER-encoded `authAttrs` re-tagged as an
EXPLICIT SET (0x31), not the [2] IMPLICIT wire form. This is symmetric with the
`signedAttrs` digest computation in `SignedData`.

### `VerifyMAC()` Workflow

1. Decrypt MAC key from matching `RecipientInfo`:
   - Reuse `tryDecryptKTRI` / `tryDecryptKARI` from `envelopeddata.go`
2. Extract content bytes from `encapContentInfo`
3. Reconstruct `authAttrs` for MAC verification:
   - Retag `[2]` → SET (0x31) on the stored wire bytes (same as `retagAsSet` in signeddata.go)
   - Compute `expected = HMAC(macKey, DER(authAttrs with SET tag))`
   - Compare `expected` to `p.authenticatedData.MAC` using `subtle.ConstantTimeCompare`
4. Validate `authAttrs` content (same as `validateSignedAttrs` in `signeddata.go`):
   - Recompute `messageDigest = digestAlg.Hash(content)`
   - Verify stored message-digest attribute matches
   - Verify content-type attribute matches `encapContentInfo.EContentType`
5. Return nil on success; `CodeInvalidSignature` on MAC or digest mismatch

**Constant-time comparison:** Use `crypto/subtle.ConstantTimeCompare` for the MAC
comparison to prevent timing attacks.

### MAC Algorithm → OID and Hash Mapping

| `MACAlgorithm` | OID | Hash (for HMAC key + digest) |
|---|---|---|
| `HMACSHA256` | `1.2.840.113549.2.9` | SHA-256 |
| `HMACSHA384` | `1.2.840.113549.2.10` | SHA-384 |
| `HMACSHA512` | `1.2.840.113549.2.11` | SHA-512 |

The `digestAlgorithm` field (when present) uses the same SHA-2 OID as the HMAC
hash. For `HMACSHA256`, `digestAlgorithm` is `id-sha256`.

### Version Rules (RFC 5652 §9.1)

| Scenario | Version |
|---|---|
| All KTRI v0, eContentType is id-data | 0 |
| All KTRI v0, eContentType is not id-data | 1 |
| Any KARI present | 2 |

### AuthAttrs vs. Content-Only MAC

This implementation always uses `authAttrs` (with mandatory content-type and
message-digest). This is the safer and more interoperable choice:
- Without `authAttrs`, the MAC covers only the raw content bytes with no content-type
  binding, which allows type confusion attacks.
- RFC 5652 §9.2 requires `authAttrs` when content type is not id-data.
- Including `authAttrs` always avoids having to handle both cases in the verifier.

### Internal Helpers

| Helper | Purpose |
|---|---|
| `macKeyLenForAlg(alg MACAlgorithm) int` | Returns MAC key byte length (32/48/64) |
| `macAlgID(alg MACAlgorithm) pkix.AlgorithmIdentifier` | Builds HMAC AlgorithmIdentifier |
| `hmacOIDToHash(oid) (crypto.Hash, error)` | Maps HMAC OID back to crypto.Hash for verification |
| `retagAsImplicit2(setBytes []byte) []byte` | 0x31 → 0xA2 for authAttrs wire encoding |
| `buildAuthAttrs(digest []byte, contentType asn1.ObjectIdentifier) ([]pkiasn1.Attribute, error)` | Constructs authAttrs slice |

The `buildRSARecipientInfo` and `buildECDHRecipientInfo` functions from
`envelopeddata.go` are called directly — no changes needed there.

### Error Mapping

| Condition | Error Code |
|---|---|
| No recipients set | `CodeInvalidConfiguration` |
| Nil cert in `WithRecipient` | `CodeInvalidConfiguration` |
| Unsupported key type in cert | `CodeUnsupportedAlgorithm` |
| No matching RecipientInfo | `CodeMissingCertificate` |
| HMAC verification fails | `CodeInvalidSignature` |
| Message-digest authAttr mismatch | `CodeInvalidSignature` |
| Content-type authAttr mismatch | `CodeContentTypeMismatch` |
| RSA-OAEP MAC key decryption failure | `CodeInvalidSignature` |
| AES key unwrap failure | `CodeInvalidSignature` |
| ASN.1 parse error | `CodeParse` |
| Content exceeds size limit | `CodePayloadTooLarge` |

### Test Cases (`authenticateddata_test.go`)

1. RSA recipient + HMAC-SHA256 → VerifyMAC passes
2. RSA recipient + HMAC-SHA384 → VerifyMAC passes
3. RSA recipient + HMAC-SHA512 → VerifyMAC passes
4. EC P-256 recipient + HMAC-SHA256 → VerifyMAC passes
5. EC P-384 recipient + HMAC-SHA256 → VerifyMAC passes
6. Multiple recipients (1 RSA + 1 EC) — both can VerifyMAC independently
7. Wrong private key (cert not in RecipientInfos) → `ErrMissingCertificate`
8. Correct key but tampered MAC bytes → `ErrInvalidSignature`
9. Correct key but tampered content → message-digest mismatch → `ErrInvalidSignature`
10. Empty content (0 bytes)
11. Content exceeds size limit → `ErrPayloadTooLarge`
12. No recipients in builder → `ErrInvalidConfiguration`
13. Nil cert in `WithRecipient` → `ErrInvalidConfiguration`
14. Unsupported key type (Ed25519 cert) → `ErrUnsupportedAlgorithm`
15. ParseAuthenticatedData with wrong ContentType OID → `ErrParse`
16. Custom content type → version 1 in output (RSA KTRI)

---

## Verification Commands

```bash
go test ./...                                 # all tests pass
go test -run TestSigners ./...                # Phase 8A
go test -run TestDigest ./...                 # Phase 8B
go test -run TestSymmetricEncrypt ./...       # Phase 8C
go test -run TestAuthenticate ./...           # Phase 8D
go vet ./...
golangci-lint run                             # cognitive complexity ≤ 15
```
