# Phase 7 — EnvelopedData Implementation Plan

## Context

Phase 7 adds the `EnvelopedData` CMS content type (RFC 5652 §6), which provides
encryption for one or more recipients. The implementation plan specifies two key
transport mechanisms — RSA-OAEP and ECDH — plus AES-GCM and AES-CBC content
encryption. This follows the same builder + parser pattern established by
`SignedData` in Phases 2–3.

---

## Files to Create

| File | Purpose |
|---|---|
| `envelopeddata.go` | `Encryptor` builder, `ParsedEnvelopedData`, all crypto helpers |
| `envelopeddata_test.go` | Round-trip tests for every algorithm combination |

## Files to Modify

| File | Change |
|---|---|
| `internal/asn1/cms.go` | Add `EnvelopedData`, `KeyTransRecipientInfo`, `KeyAgreeRecipientInfo`, `RecipientEncryptedKey`, `EncryptedContentInfo` |
| `internal/asn1/pkix.go` | Add `RSAOAEPParams`, `GCMParameters`, `OriginatorPublicKey` |
| `internal/asn1/oid.go` | Add OIDs for RSAES-OAEP, AES content encryption, AES key wrap, ECDH schemes |

---

## Public API

```go
// ContentEncryptionAlgorithm identifies the symmetric cipher used for content.
// AES-GCM (authenticated) is preferred over AES-CBC.
type ContentEncryptionAlgorithm int

const (
    AES256GCM  ContentEncryptionAlgorithm = iota // default
    AES128GCM
    AES128CBC
    AES256CBC
)

// Encryptor builds a CMS EnvelopedData using a fluent builder API.
type Encryptor struct { /* unexported */ }

func NewEncryptor() *Encryptor
func (e *Encryptor) WithRecipient(cert *x509.Certificate) *Encryptor
func (e *Encryptor) WithContentEncryption(alg ContentEncryptionAlgorithm) *Encryptor
func (e *Encryptor) WithMaxContentSize(maxBytes int64) *Encryptor
func (e *Encryptor) Encrypt(r io.Reader) ([]byte, error)

// ParsedEnvelopedData wraps a parsed EnvelopedData for decryption.
type ParsedEnvelopedData struct { /* unexported */ }

func ParseEnvelopedData(r io.Reader) (*ParsedEnvelopedData, error)

// Decrypt finds the RecipientInfo matching cert, decrypts the CEK, and returns
// the plaintext. Returns ErrMissingCertificate if no matching recipient is found.
func (p *ParsedEnvelopedData) Decrypt(key crypto.PrivateKey, cert *x509.Certificate) ([]byte, error)
```

**Key transport auto-selection** (no separate builder option):
- Recipient has RSA public key → `KeyTransRecipientInfo` (RSA-OAEP / SHA-256 hash)
- Recipient has EC public key → `KeyAgreeRecipientInfo` (ECDH ephemeral-static)

---

## New OIDs (`internal/asn1/oid.go`)

```
// Key Transport
OIDKeyTransportRSAOAEP    = 1.2.840.113549.1.1.7

// Content Encryption (RFC 3565 / NIST AES)
OIDContentEncryptionAES128CBC = 2.16.840.1.101.3.4.1.2
OIDContentEncryptionAES256CBC = 2.16.840.1.101.3.4.1.42
OIDContentEncryptionAES128GCM = 2.16.840.1.101.3.4.1.6
OIDContentEncryptionAES256GCM = 2.16.840.1.101.3.4.1.46

// Key Wrap (RFC 3565)
OIDKeyWrapAES128 = 2.16.840.1.101.3.4.1.5
OIDKeyWrapAES256 = 2.16.840.1.101.3.4.1.45

// ECDH Key Agreement (RFC 5753)
OIDKeyAgreeECDHSHA256 = 1.3.132.1.11.1  // dhSinglePass-stdDH-sha256kdf-scheme
OIDKeyAgreeECDHSHA384 = 1.3.132.1.11.2  // dhSinglePass-stdDH-sha384kdf-scheme
OIDKeyAgreeECDHSHA512 = 1.3.132.1.11.3  // dhSinglePass-stdDH-sha512kdf-scheme
```

---

## New ASN.1 Structures

### `internal/asn1/cms.go`

```go
// EnvelopedData (RFC 5652 §6.1)
type EnvelopedData struct {
    Version              int
    RecipientInfos       []asn1.RawValue `asn1:"set"`
    EncryptedContentInfo EncryptedContentInfo
}

// EncryptedContentInfo (RFC 5652 §6.1)
type EncryptedContentInfo struct {
    ContentType                asn1.ObjectIdentifier
    ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"` // [0] IMPLICIT
}

// KeyTransRecipientInfo (RFC 5652 §6.2.1) — RSA-OAEP key transport
type KeyTransRecipientInfo struct {
    Version                int           // 0 = IssuerAndSerialNumber
    RID                    asn1.RawValue // IssuerAndSerialNumber SEQUENCE
    KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedKey           []byte
}

// KeyAgreeRecipientInfo (RFC 5652 §6.2.2) — ECDH ephemeral-static
type KeyAgreeRecipientInfo struct {
    Version                int
    Originator             asn1.RawValue          `asn1:"explicit,tag:0"`
    UKM                    []byte                 `asn1:"optional,explicit,tag:1"`
    KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
    RecipientEncryptedKeys []RecipientEncryptedKey
}

// RecipientEncryptedKey (RFC 5652 §6.2.2)
type RecipientEncryptedKey struct {
    RID          asn1.RawValue // IssuerAndSerialNumber
    EncryptedKey []byte
}
```

### `internal/asn1/pkix.go`

```go
// RSAOAEPParams (RFC 4055 §3.1)
type RSAOAEPParams struct {
    HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:0"`
    MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1"`
}

// GCMParameters (RFC 5084 §3.2)
type GCMParameters struct {
    Nonce  []byte
    ICVLen int `asn1:"optional"` // DEFAULT 12; omit when 12
}

// OriginatorPublicKey (RFC 5652 §6.2.2) — ephemeral EC key in KARI
type OriginatorPublicKey struct {
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}
```

---

## Encryption Workflow (`Encrypt`)

1. Validate accumulated errors; require ≥1 recipient
2. Read and buffer content (capped at `maxContentSize`)
3. Generate random CEK (16 or 32 bytes depending on algorithm)
4. Encrypt content → `(ciphertext, algID)`:
   - AES-GCM: 12-byte random nonce; algID params = `GCMParameters{Nonce}`
   - AES-CBC: 16-byte random IV; algID params = raw OCTET STRING (IV)
5. For each recipient:
   - RSA → `buildRSARecipientInfo`: OAEP-encrypt CEK → `KeyTransRecipientInfo` (version 0)
   - EC → `buildECDHRecipientInfo`: generate ephemeral key, ECDH, X9.63 KDF, AES Key Wrap CEK → `KeyAgreeRecipientInfo` (version 3)
6. Set `EnvelopedData.Version`: 0 if all KTRI v0; 2 if any KARI present
7. Marshal `ContentInfo { OIDEnvelopedData, [0] EnvelopedData }` → DER

## Decryption Workflow (`Decrypt`)

1. Iterate `RecipientInfos`:
   - Tag 0x30 (SEQUENCE) → `KeyTransRecipientInfo`; match by IssuerAndSerialNumber
   - Tag 0xA1 (`[1]` context) → `KeyAgreeRecipientInfo`; search `RecipientEncryptedKeys`
2. Recover CEK:
   - RSA: `rsa.DecryptOAEP(sha256, rand, rsaPriv, encryptedKey, nil)`
   - EC: parse ephemeral pub from Originator → ECDH → X9.63 KDF → AES Key Unwrap
3. Decrypt content using recovered CEK and `EncryptedContentInfo.ContentEncryptionAlgorithm`
4. Return plaintext bytes

---

## Internal Helpers (unexported, in `envelopeddata.go`)

| Helper | RFC reference |
|---|---|
| `aesKeyWrap(kek, cek []byte) ([]byte, error)` | RFC 3394 |
| `aesKeyUnwrap(kek, wrapped []byte) ([]byte, error)` | RFC 3394 |
| `x963KDF(Z []byte, keydatalen int, sharedInfo []byte) ([]byte, error)` | ANS X9.63 / SP 800-56A |
| `encryptContent(plaintext, alg)` → `(cek, ciphertext, algID, err)` | AES-GCM / AES-CBC |
| `decryptContent(ciphertext, algID, cek)` → `([]byte, error)` | AES-GCM / AES-CBC |
| `buildRSARecipientInfo(cert, cek)` → `asn1.RawValue` | RFC 5652 §6.2.1 |
| `buildECDHRecipientInfo(cert, cek)` → `asn1.RawValue` | RFC 5753 |
| `issuerAndSerial(cert)` → `IssuerAndSerialNumber` | reuse from signeddata.go |

---

## ECDH Details (RFC 5753)

**Algorithm OID selection by curve:**
- P-256 → `dhSinglePass-stdDH-sha256kdf-scheme` (1.3.132.1.11.1)
- P-384 → `dhSinglePass-stdDH-sha384kdf-scheme` (1.3.132.1.11.2)
- P-521 → `dhSinglePass-stdDH-sha512kdf-scheme` (1.3.132.1.11.3)

**KARI key encryption algorithm params:** nested `AlgorithmIdentifier` for the
key wrap — `aes128-wrap` for 16-byte CEK, `aes256-wrap` for 32-byte CEK.

**X9.63 KDF:** `Hash(Z || Counter || OtherInfo)` where `OtherInfo` is the
concatenation of the key wrap AlgorithmIdentifier DER encoding and a 4-byte
big-endian keydatalen in bits.

**Go ECDH:** `crypto/ecdh` (Go 1.20+); `*ecdsa.PrivateKey` converts via `.ECDH()`.

**Wire encoding of Originator in KARI:**
- `originatorKey [2] OriginatorPublicKey` — IMPLICIT tag replaces SEQUENCE tag (0x30 → 0xA2)
- Wrapped in `[0] EXPLICIT`: `A0 <len> <A2-tagged-bytes>`

---

## EnvelopedData Version Rules (RFC 5652 §6.1)

| Scenario | Version |
|---|---|
| All KTRI with IssuerAndSerialNumber | 0 |
| Any KARI present | 2 |

---

## Error Mapping

| Condition | Error Code |
|---|---|
| No recipients set | `CodeInvalidConfiguration` |
| Nil cert in `WithRecipient` | `CodeInvalidConfiguration` |
| Unsupported key type | `CodeUnsupportedAlgorithm` |
| No matching RecipientInfo | `CodeMissingCertificate` |
| RSA-OAEP or AES-GCM failure | `CodeInvalidSignature` |
| Bad AES-CBC padding | `CodeInvalidSignature` |
| ASN.1 parse error | `CodeParse` |
| Content exceeds size limit | `CodePayloadTooLarge` |

---

## Test Cases (`envelopeddata_test.go`)

1. RSA-OAEP + AES-256-GCM (default)
2. RSA-OAEP + AES-128-GCM
3. RSA-OAEP + AES-256-CBC
4. RSA-OAEP + AES-128-CBC
5. ECDSA P-256 recipient + AES-256-GCM (ECDH)
6. ECDSA P-384 recipient + AES-256-GCM (ECDH)
7. Multiple recipients (1 RSA + 1 EC) — both decrypt correctly
8. Wrong private key → error (`MissingCertificate` or decryption failure)
9. Empty plaintext (0 bytes)
10. Builder: no recipients → `ErrInvalidConfiguration`
11. Builder: nil cert → `ErrInvalidConfiguration`
