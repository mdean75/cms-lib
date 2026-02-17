# CMS Library Implementation Plan

## Finalized Design Decisions

| Concern | Decision |
|---|---|
| Module | `github.com/mdean75/cms`, Go 1.23.2 |
| API pattern | Builder + functional options, unified `io.Reader` interface |
| RSA-PKCS1v15 | Included for signing interoperability |
| Algorithms | Modern only (see Algorithm Support section) |
| Chain validation | Configurable via functional options |
| BER→DER | Custom implementation; handles 0-byte payload edge case |
| Package layout | Sub-packages where concerns are distinct |
| Errors | Typed errors with `Unwrap()` support |
| SignedData scope | Full: attached/detached, multi-signer, countersignatures, auth/unauth attributes, RFC 3161 timestamps |
| Interop testing | OpenSSL-generated fixtures |

---

## Package Structure

```
github.com/mdean75/cms/
│
├── cms.go              # Package doc, top-level types, FromBytes helper
├── errors.go           # All exported error types
├── signeddata.go       # SignedData Signer builder + ParsedSignedData
├── algorithm.go        # Algorithm definitions, OID mapping, allow-list
│
├── ber/
│   ├── ber.go          # BER→DER normalizer
│   └── ber_test.go     # Edge case table tests (0-byte payload, indefinite-length, etc.)
│
└── internal/
    ├── asn1/
    │   ├── cms.go      # CMS ASN.1 struct definitions (ContentInfo, SignedData, SignerInfo, etc.)
    │   ├── pkix.go     # Supplemental PKIX types not in crypto/x509/pkix
    │   └── oid.go      # All OID constants
    └── timestamp/
        └── timestamp.go  # RFC 3161 TSA client (used by signeddata.go)
```

**Rationale:**
- `ber/` is exported — useful standalone and deserves its own import path and test surface
- `internal/asn1/` and `internal/timestamp/` are implementation details; callers never construct raw ASN.1 structs
- No `signeddata/` sub-package — at the module level, `cms` *is* the package name, so `cms.NewSigner()` reads naturally
- Future content types (`envelopeddata.go`, etc.) follow the same flat-in-root pattern

---

## Algorithm Support

### Signing

| Algorithm | OID | Notes |
|---|---|---|
| RSA-PKCS1v15 | `sha*WithRSAEncryption` | Included for interop |
| RSA-PSS | `id-RSASSA-PSS` | Preferred RSA variant; RSASSA-PSS-params MUST be explicit in AlgorithmIdentifier (RFC 4056) |
| ECDSA | `ecdsa-with-SHA*` | P-256, P-384, P-521; signature value must be DER-encoded `Ecdsa-Sig-Value { r INTEGER, s INTEGER }` |
| Ed25519 | `id-Ed25519` | digestAlgorithm MUST be id-sha512 regardless of caller input; signatureAlgorithm parameters MUST be absent (RFC 8419) |

### Hashing

SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512

### Symmetric (for EnvelopedData, future)

AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC

### Key Transport / Agreement (for EnvelopedData, future)

RSA-OAEP, ECDH

### Explicitly Excluded

SHA-1, MD5, MD2, DES, 3DES, RC2, RC4, RSA-PKCS1v15 encryption

---

## Error Design

```go
// errors.go

type ErrorCode int

const (
    CodeParse                  ErrorCode = iota // malformed ASN.1 or CMS structure
    CodeBERConversion                           // BER→DER normalization failure
    CodeUnsupportedAlgorithm                    // algorithm not in allow-list
    CodeInvalidSignature                        // signature math failed
    CodeCertificateChain                        // x509 chain validation failure
    CodeMissingCertificate                      // signer cert not found in message
    CodeTimestamp                               // RFC 3161 TSA error
    CodeCounterSignature                        // counter-signature specific failure
    CodeVersionMismatch                         // SignedData or SignerInfo version indicates unsupported capability
    CodeAttributeInvalid                        // mandatory attribute missing or value fails validation
    CodeContentTypeMismatch                     // content-type attribute does not match eContentType
    CodePKCS7Format                             // parser detected PKCS #7 format instead of CMS
    CodeDetachedContentMismatch                 // Verify called on detached sig, or VerifyDetached called on attached sig
    CodePayloadTooLarge                         // attached content exceeds configured size limit
    CodeInvalidConfiguration                    // builder configuration is invalid (nil cert, nil key, conflicting options, etc.)
)

type Error struct {
    Code    ErrorCode
    Message string
    Cause   error     // wraps underlying stdlib or external error
}

func (e *Error) Error() string { ... }
func (e *Error) Unwrap() error { return e.Cause }

// Sentinel variables for errors.Is() checks
var (
    ErrParse                  = &Error{Code: CodeParse}
    ErrBERConversion          = &Error{Code: CodeBERConversion}
    ErrUnsupportedAlgorithm   = &Error{Code: CodeUnsupportedAlgorithm}
    ErrInvalidSignature       = &Error{Code: CodeInvalidSignature}
    ErrCertificateChain       = &Error{Code: CodeCertificateChain}
    ErrMissingCertificate     = &Error{Code: CodeMissingCertificate}
    ErrTimestamp              = &Error{Code: CodeTimestamp}
    ErrCounterSignature       = &Error{Code: CodeCounterSignature}
    ErrVersionMismatch        = &Error{Code: CodeVersionMismatch}
    ErrAttributeInvalid       = &Error{Code: CodeAttributeInvalid}
    ErrContentTypeMismatch    = &Error{Code: CodeContentTypeMismatch}
    ErrPKCS7Format            = &Error{Code: CodePKCS7Format}
    ErrDetachedContentMismatch = &Error{Code: CodeDetachedContentMismatch}
    ErrPayloadTooLarge         = &Error{Code: CodePayloadTooLarge}
    ErrInvalidConfiguration    = &Error{Code: CodeInvalidConfiguration}
)
```

Callers can use `errors.Is(err, cms.ErrInvalidSignature)` or type-assert to `*cms.Error` to inspect `Code` and `Cause`.

### Builder Error Accumulation

Builder methods (e.g., `WithCertificate`, `WithPrivateKey`) accumulate validation
errors internally rather than returning them immediately, preserving the fluent chain.
When `Sign()` is called, all accumulated errors are reported at once using
`errors.Join()`, so each individual failure remains inspectable:

```go
result, err := cms.NewSigner().
    WithCertificate(nil).   // error stored: "certificate is nil"
    WithPrivateKey(nil).    // error stored: "private key is nil"
    Sign(r)

// err is a joined error — both failures are visible
errors.Is(err, cms.ErrInvalidConfiguration) // true
// err.Error() → "certificate is nil\nprivate key is nil"
```

Each joined error is a `*cms.Error` with `Code: CodeInvalidConfiguration`.
All accumulated errors are reported; the caller does not need to fix one at a time.

---

## API Design

### Convenience Helpers

```go
// cms.go

// FromBytes wraps a []byte as an io.Reader for use with the unified interface.
func FromBytes(b []byte) io.Reader

// UnlimitedAttachedSize disables the attached content size limit.
// Use with caution: attached content is fully buffered in memory during Sign().
const UnlimitedAttachedSize int64 = -1

// DefaultMaxAttachedSize is the default maximum size for attached content (64 MiB).
const DefaultMaxAttachedSize int64 = 64 * 1024 * 1024

// SignerIdentifierType controls how the signer's certificate is identified in SignerInfo.
type SignerIdentifierType int

const (
    // IssuerAndSerialNumber identifies the signer by issuer DN and certificate serial number.
    // Results in SignerInfo version 1. This is the default and most widely compatible form.
    IssuerAndSerialNumber SignerIdentifierType = iota
    // SubjectKeyIdentifier identifies the signer by the subjectKeyIdentifier extension value.
    // Results in SignerInfo version 3.
    SubjectKeyIdentifier
)
```

### Signing

```go
// signeddata.go

type Signer struct { /* unexported */ }

func NewSigner() *Signer

// Builder methods — all return *Signer for chaining

// WithCertificate sets the signing certificate. Required.
func (s *Signer) WithCertificate(cert *x509.Certificate) *Signer

// WithPrivateKey sets the private key used for signing. Required.
func (s *Signer) WithPrivateKey(key crypto.Signer) *Signer

// WithHash sets the digest algorithm. Ignored for Ed25519 (forced to SHA-512 per RFC 8419).
// Defaults to SHA-256.
func (s *Signer) WithHash(h crypto.Hash) *Signer

// WithDetachedContent produces a detached signature (eContent absent in output).
// Default is attached. For large payloads, detached is strongly preferred.
func (s *Signer) WithDetachedContent() *Signer

// WithSignerIdentifier controls whether IssuerAndSerialNumber or SubjectKeyIdentifier
// is used in SignerInfo. Default is IssuerAndSerialNumber (SignerInfo v1).
func (s *Signer) WithSignerIdentifier(t SignerIdentifierType) *Signer

// WithContentType sets a custom eContentType OID in EncapsulatedContentInfo.
// Default is id-data (1.2.840.113549.1.7.1).
// Setting a non-id-data type triggers SignedData version 3 automatically.
// The content-type signed attribute will be set to match this value.
func (s *Signer) WithContentType(oid asn1.ObjectIdentifier) *Signer

// AddCertificate adds an extra certificate to the CertificateSet (e.g., chain certs).
func (s *Signer) AddCertificate(cert *x509.Certificate) *Signer

// AddAuthenticatedAttribute adds a custom signed attribute.
// content-type and message-digest are always added automatically; callers
// MUST NOT add these manually.
func (s *Signer) AddAuthenticatedAttribute(oid asn1.ObjectIdentifier, val interface{}) *Signer

// AddUnauthenticatedAttribute adds a custom unsigned attribute.
func (s *Signer) AddUnauthenticatedAttribute(oid asn1.ObjectIdentifier, val interface{}) *Signer

// WithTimestamp requests an RFC 3161 timestamp from the given TSA URL and embeds
// it as an unsigned attribute after signing.
func (s *Signer) WithTimestamp(tsaURL string) *Signer

// WithMaxAttachedContentSize sets the maximum content size for attached signatures.
// If the content read from the io.Reader exceeds this limit, Sign() fails fast
// with ErrPayloadTooLarge without buffering the full content. Default is
// DefaultMaxAttachedSize (64 MiB). Set to UnlimitedAttachedSize to disable.
// Has no effect when WithDetachedContent() is set (detached mode never buffers).
func (s *Signer) WithMaxAttachedContentSize(maxBytes int64) *Signer

// Sign reads content from r, computes the CMS SignedData, and returns DER-encoded output.
// For attached signatures, content is buffered in memory up to the configured size limit.
// For detached signatures, content is streamed with no buffering.
func (s *Signer) Sign(r io.Reader) ([]byte, error)
```

### Parsing & Verification

```go
// signeddata.go

// ParseSignedData parses a BER- or DER-encoded CMS ContentInfo containing SignedData.
// BER input is normalized to DER transparently. If PKCS #7 format is detected,
// ErrPKCS7Format is returned with a descriptive message.
func ParseSignedData(r io.Reader) (*ParsedSignedData, error)

type ParsedSignedData struct { /* unexported */ }

// IsDetached reports whether the SignedData has no encapsulated content (eContent absent).
// A detached SignedData must be verified with VerifyDetached.
// Note: IsDetached() == false does not imply non-empty content; a signed 0-byte payload
// will have IsDetached() == false with Content() returning an empty reader.
func (p *ParsedSignedData) IsDetached() bool

// Content returns an io.Reader over the encapsulated content.
// Returns an empty reader (not an error) for a signed 0-byte payload.
// Returns ErrDetachedContentMismatch if IsDetached() is true.
func (p *ParsedSignedData) Content() (io.Reader, error)

// Functional options for verification behavior
type VerifyOption func(*verifyConfig)

func WithSystemTrustStore() VerifyOption
func WithTrustRoots(pool *x509.CertPool) VerifyOption
func WithVerifyOptions(opts x509.VerifyOptions) VerifyOption  // full control
func WithNoChainValidation() VerifyOption     // raw signature math only
func WithVerifyTime(t time.Time) VerifyOption

// Verify verifies all SignerInfos in an attached-content SignedData.
// Returns ErrDetachedContentMismatch if called on a detached SignedData.
// Verification independently recomputes all digests; originator-provided
// digest values are never trusted directly.
func (p *ParsedSignedData) Verify(opts ...VerifyOption) error

// VerifyDetached verifies all SignerInfos using the provided external content.
// Returns ErrDetachedContentMismatch if called on an attached SignedData.
func (p *ParsedSignedData) VerifyDetached(content io.Reader, opts ...VerifyOption) error

// Introspection
func (p *ParsedSignedData) Signers() []*SignerInfo
func (p *ParsedSignedData) Certificates() []*x509.Certificate
func (p *ParsedSignedData) CRLs() []*pkix.CertificateList
```

### Counter-signing

```go
// signeddata.go

type CounterSigner struct { /* unexported */ }

func NewCounterSigner() *CounterSigner

// Builder methods — all return *CounterSigner for chaining
func (cs *CounterSigner) WithCertificate(cert *x509.Certificate) *CounterSigner
func (cs *CounterSigner) WithPrivateKey(key crypto.Signer) *CounterSigner
func (cs *CounterSigner) WithHash(h crypto.Hash) *CounterSigner
func (cs *CounterSigner) AddCertificate(cert *x509.Certificate) *CounterSigner

// CounterSign reads an existing DER-encoded SignedData from r, appends a
// countersignature (OID 1.2.840.113549.1.9.6) as an unsigned attribute on each
// SignerInfo, and returns the updated DER-encoded SignedData.
// A counter-signature signs the Signature bytes of the target SignerInfo,
// not the original content.
func (cs *CounterSigner) CounterSign(r io.Reader) ([]byte, error)
```

### BER Utility

```go
// package ber

// Normalize converts BER-encoded ASN.1 to canonical DER.
// Handles indefinite-length encoding, including the 0-byte content edge case.
// Preserves already-DER-encoded substructures (e.g., signedAttrs within a BER
// outer wrapper) so that signed attribute digest values remain valid.
func Normalize(r io.Reader) ([]byte, error)
```

---

## Critical Implementation Notes

These are correctness requirements derived from RFC 5652 that must be implemented
precisely. Errors here produce output that is structurally valid but cryptographically
wrong, causing silent failures or rejections by Bouncy Castle and OpenSSL.

### Signing Process

**1. Mandatory signed attributes (auto-injected)**

When any `signedAttrs` are present (including when the caller adds custom attributes),
the library MUST automatically inject:
- `id-contentType` (OID 1.2.840.113549.1.9.3): value is the `eContentType` OID
- `id-messageDigest` (OID 1.2.840.113549.1.9.4): value is the computed content digest

Callers MUST NOT add these manually via `AddAuthenticatedAttribute`. If they attempt
to, Sign() should return ErrAttributeInvalid.

**2. signedAttrs DER encoding rule for digest computation**

The RFC mandates that signedAttrs be DER encoded even if the outer structure is BER.
Additionally, the digest is computed over a re-encoded form of signedAttrs:
- The wire encoding uses IMPLICIT tag `[0]`
- The digest input uses EXPLICIT `SET OF` tag (0x31)
- These are different byte sequences — the digest is computed over the SET-tagged form,
  not what appears on the wire

This re-encoding step is mandatory and must be tested explicitly.

**3. Digest computation rules — two distinct cases**

- signedAttrs **absent**: digest input is the raw value octets of `eContent` ONLY.
  Tag and length bytes are excluded. This allows streaming without knowing content
  length in advance.
- signedAttrs **present**: digest input is the DER encoding of `SignedAttributes`
  with the EXPLICIT SET tag substituted for the IMPLICIT [0] tag.

**4. Version number computation**

SignedData version MUST be computed as follows (highest applicable rule wins):
- **v5**: certificates or CRLs contain an "other" type
- **v4**: certificates contain a v2 attribute certificate
- **v3**: certificates contain a v1 attribute certificate, OR any SignerInfo is v3,
  OR `eContentType` ≠ `id-data`
- **v1**: all other cases

SignerInfo version:
- **v1**: SignerIdentifier uses IssuerAndSerialNumber
- **v3**: SignerIdentifier uses SubjectKeyIdentifier

**5. DigestAlgorithmIdentifiers SET**

The `digestAlgorithms` field in SignedData is a SET containing the digest algorithm
of every SignerInfo. When multiple signers use different algorithms, all must appear.
Duplicates must be deduplicated.

**6. RSA-PSS AlgorithmIdentifier**

Per RFC 4056, `signatureAlgorithm` for RSA-PSS MUST include `RSASSA-PSS-params`
explicitly. An absent parameters field is invalid and will be rejected by Bouncy
Castle. Parameters must be consistent with the certificate's key parameters.

**7. ECDSA signature encoding**

Go's `crypto/ecdsa.Sign()` returns raw `(r, s)` big.Int values. CMS requires the
signature value to be the DER encoding of:
```asn1
Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
```
This marshaling must be applied before storing the signature. The inverse (unmarshal
before verification) must be applied when verifying received ECDSA signatures.

**8. Ed25519 special handling (RFC 8419)**

Ed25519 performs internal hashing and does not use a separate digest step. However,
CMS still requires:
- `digestAlgorithm` in SignerInfo MUST be `id-sha512`, regardless of caller input
- `signatureAlgorithm` parameters field MUST be absent
- `WithHash()` is ignored for Ed25519; the library sets `id-sha512` automatically

### Verification Process

**9. Independent digest recomputation**

The verifier MUST independently recompute the content digest. The `message-digest`
attribute value from the originator is used only for comparison — it is never trusted
directly. RFC 5652 is explicit: "The recipient MUST NOT rely on any message digest
values computed by the originator."

Verification steps in order:
1. Independently compute digest of content (or of signedAttrs, per the two-case rule above)
2. Compare computed digest to the `message-digest` attribute value
3. Verify `content-type` attribute value matches `eContentType`
4. Verify the cryptographic signature over the DER-encoded signedAttrs

Steps 2 and 3 must be checked even if step 4 passes.

**10. Attribute validation**

During verification, if signedAttrs are present:
- `content-type` attribute MUST be present and MUST match `eContentType`
- `message-digest` attribute MUST be present and MUST match the computed digest

Failure returns `ErrAttributeInvalid` or `ErrContentTypeMismatch` as appropriate.

### 0-Byte Payload vs. Detached Signature

These two cases are structurally distinct in RFC 5652 and must never be conflated:

- **Detached signature**: `eContent` field is **absent** from `EncapsulatedContentInfo`
- **Signed 0-byte payload**: `eContent` field is **present** but contains a zero-length OCTET STRING

The BER encoding of a 0-byte `eContent` with indefinite-length is:
```
A0 80          -- [0] EXPLICIT, indefinite length
  04 80        -- OCTET STRING, indefinite length
  00 00        -- end-of-contents for OCTET STRING
00 00          -- end-of-contents for [0]
```

Many BER parsers incorrectly drop this field entirely, treating a 0-byte attached
signature as detached. Our normalizer MUST preserve the presence of `eContent` even
when its value is empty, converting the above to:
```
A0 02          -- [0] EXPLICIT, 2 bytes
  04 00        -- OCTET STRING, 0 bytes
```

API behavior:
- `IsDetached()` returns `true` only when `eContent` is absent; never for a 0-byte payload
- `Content()` returns an empty `io.Reader` (not an error) for a 0-byte payload
- `Verify()` and `VerifyDetached()` return `ErrDetachedContentMismatch` if called on the wrong form

### Attached Content Size Limit

Attached signatures buffer the entire content in memory. To prevent unbounded memory
usage, `Sign()` enforces a configurable limit:

- Default limit: 64 MiB (`DefaultMaxAttachedSize`)
- Fail-fast: the content `io.Reader` is read with a size-tracking wrapper; `Sign()`
  returns `ErrPayloadTooLarge` as soon as the limit is exceeded, without buffering
  further
- To disable: `WithMaxAttachedContentSize(cms.UnlimitedAttachedSize)`
- Detached mode is unaffected; streaming proceeds with no buffering regardless of size

For payloads that may exceed the limit, callers should prefer `WithDetachedContent()`.

### BER→DER Mixed Encoding

Within a BER-encoded CMS message, `signedAttrs` may legitimately be DER-encoded
already (the RFC mandates it). The normalizer must not blindly re-encode fields that
are already canonical DER. Specifically, when converting a BER outer structure:
- The `signedAttrs` bytes must be preserved verbatim for use in digest verification
- Re-encoding the outer structure must not alter the `signedAttrs` content

### PKCS #7 Backward Compatibility

CMS and PKCS #7 differ in how non-`id-data` content is encapsulated:
- **CMS**: the content is always wrapped in an OCTET STRING
- **PKCS #7**: the content is encoded directly as the native ASN.1 type (not wrapped)

This changes the digest computation for non-`id-data` types. `ParseSignedData`
should detect this condition and return `ErrPKCS7Format` with a clear message
rather than producing a silent verification failure. Bouncy Castle can emit both
formats depending on configuration.

---

## BER→DER Edge Cases

The following cases must be covered by the `ber` package test suite:

1. Indefinite-length outer wrapper (`0x80` length byte)
2. Nested indefinite-length containers
3. **0-byte OCTET STRING with indefinite-length encoding** — presence must be preserved,
   not dropped (the core known-breakage case)
4. Constructed string types that DER requires to be primitive
5. Non-canonical boolean (`0x01` true instead of required `0xFF`)
6. Redundant leading zero bytes in integer encoding
7. Non-minimal length encoding (e.g., two-byte length where one byte suffices)
8. Mixed DER-within-BER: signedAttrs DER-encoded inside a BER outer structure —
   normalizer must preserve signedAttrs bytes exactly

---

## Implementation Phases

### Phase 1 — Foundation
- `internal/asn1/`: all CMS ASN.1 struct definitions and OID constants
- `ber/`: BER→DER normalizer with full edge case test suite, including 0-byte
  payload and mixed DER-within-BER preservation
- `errors.go`: complete error type definitions

### Phase 2 — SignedData Core
- `signeddata.go`: `Signer` builder, `Sign()` with attached and detached modes
- Auto-injection of mandatory signed attributes (content-type, message-digest)
- Correct signedAttrs re-encoding for digest computation (IMPLICIT [0] → EXPLICIT SET)
- Version number computation for SignedData and SignerInfo
- `ParseSignedData()` with BER normalization and PKCS #7 detection
- `Verify()` / `VerifyDetached()` with independent digest recomputation and attribute validation
- All chain validation options via functional options
- Algorithm allow-list enforcement in `algorithm.go`
- Attached content size limit with fail-fast behavior
- `IsDetached()` / `Content()` with correct 0-byte vs detached distinction

### Phase 3 — SignedData Extended
- `WithSignerIdentifier()` — SubjectKeyIdentifier support, with version bump to SignerInfo v3
- `WithContentType()` — custom eContentType with version bump to SignedData v3
- Authenticated and unauthenticated attributes
- Multiple signers with DigestAlgorithms SET union computation
- Counter-signatures (signs SignerInfo.Signature bytes, not content)
- Certificate inclusion and chain building
- CRL embedding and `CRLs()` introspection method

### Phase 4 — Algorithm Hardening
- ECDSA: DER encoding/decoding of `Ecdsa-Sig-Value` on sign and verify
- RSA-PSS: explicit `RSASSA-PSS-params` in AlgorithmIdentifier
- Ed25519: forced `id-sha512` digestAlgorithm, absent signature params

### Phase 5 — Timestamps
- `internal/timestamp/`: RFC 3161 TSA client
- `WithTimestamp()` on `Signer`
- Timestamp verification during `Verify()`

### Phase 6 — Interop & Hardening
- OpenSSL-generated test fixtures for all SignedData variants
- Cross-platform verification: Windows PKCS7 (indefinite-length BER), Java BouncyCastle
- Explicit round-trip tests: sign with this library, verify with OpenSSL and BC; sign
  with OpenSSL and BC, verify with this library
- Fuzz testing on `ParseSignedData` and `ber.Normalize`

### Phase 7+ — Additional Content Types
- `EnvelopedData` (encryption for one or more recipients)
- `AuthenticatedData`
- `DigestedData` / `EncryptedData`
