# CMS Library — Design Decisions

This document records design choices that diverge from, extend, or improve upon the
reference implementation ([`github/smimesign/ietf-cms`][ref]). It is intended to
support internal security review and provide rationale for any questions raised during
a corporate security audit.

[ref]: https://github.com/github/smimesign/tree/main/ietf-cms

---

## DD-001 — `SignerInfo` signed/unsigned attributes stored as `asn1.RawValue`

**RFC reference:** RFC 5652 §5.3, §5.4

**Reference implementation:**
```go
// smimesign
SignedAttrs   Attributes `asn1:"optional,tag:0"`        // []Attribute
UnsignedAttrs Attributes `asn1:"set,optional,tag:1"`    // []Attribute
```

**This implementation:**
```go
SignedAttrs   asn1.RawValue `asn1:"optional,tag:0"`
UnsignedAttrs asn1.RawValue `asn1:"optional,set,tag:1"`
```

**Rationale:**

RFC 5652 §5.4 requires that the message digest be computed over the `signedAttrs`
field re-encoded with an explicit SET tag (0x31), not the `[0] IMPLICIT` wire form
(0xA0) used for transmission. Using `asn1.RawValue` gives direct, byte-level access
to the exact encoding as received off the wire. The re-tagging is then a single byte
substitution (`0xA0 → 0x31`) with no risk of altering the content.

The reference implementation parses attributes into a typed `[]Attribute` slice on
unmarshal and then re-encodes them in separate `MarshaledForSigning()` /
`MarshaledForVerification()` methods for digest computation. This introduces two
risks that our approach eliminates:

1. **Round-trip re-encoding divergence.** Re-marshaling a parsed attribute set can
   produce byte sequences that differ from the original (e.g., due to attribute
   ordering, integer encoding, or string type choices). If any byte changes, the
   computed digest will not match the signature.

2. **BER interop fragility.** A sender using BER (permitted by RFC 5652 for the
   outer structure) may produce non-canonical attribute encodings. Parsing and
   re-marshaling normalises those bytes, potentially breaking verification of an
   otherwise valid message.

**Security posture:** Storing raw bytes and verifying over exactly what was
transmitted is the more conservative, lower-risk design. It eliminates an entire
class of re-encoding bugs that have historically caused signature verification
failures in CMS implementations.

---

## DD-002 — `SignedData` certificate and CRL sets include `set` tag

**RFC reference:** RFC 5652 §5.1

**Reference implementation:**
```go
// smimesign
Certificates []asn1.RawValue `asn1:"optional,set,tag:0"`
CRLs         []asn1.RawValue `asn1:"optional,set,tag:1"`
```

**This implementation (after correction, see history below):**
```go
Certificates []asn1.RawValue `asn1:"optional,set,tag:0"`
CRLs         []asn1.RawValue `asn1:"optional,set,tag:1"`
```

The RFC defines both fields as `SET OF` under an IMPLICIT context tag:

```
certificates [0] IMPLICIT CertificateSet    OPTIONAL  -- SET OF CertificateChoices
crls         [1] IMPLICIT RevocationInfoChoices OPTIONAL  -- SET OF RevocationInfoChoice
```

Per X.690 §11.6, DER requires elements of a `SET OF` to be sorted by their encoded
values. The `set` struct tag in Go's `encoding/asn1` enables this sorting during
marshaling.

**History:** An early version of this library omitted `set` from both fields, which
produced output with certificates and CRLs in insertion order rather than DER
canonical order. No functional or interoperability impact was observed (no real-world
CMS parser enforces SET ordering for these fields), but the output was technically
non-conformant DER. The tags were corrected to match the reference implementation and
the RFC.

---

## DD-003 — `WithoutCertificates` option for out-of-band certificate delivery

**RFC reference:** RFC 5652 §5.1 — `certificates` field is `OPTIONAL`

**Reference implementation:** No equivalent; certificates are always embedded.

**This implementation:** `WithoutCertificates()` `SignerOption`; `WithExternalCertificates()` `VerifyOption`

**Rationale:**

Some deployment patterns exchange certificates out of band — for example, long-lived
bidirectional gRPC streams where the signing certificate is negotiated once at
connection setup and then reused for many messages. Embedding the certificate in
every message is wasteful and may expose certificate metadata unnecessarily.

Because the RFC makes the `certificates` field OPTIONAL, omitting it produces a
fully conformant CMS SignedData structure. The `SignerIdentifier` in each
`SignerInfo` (either `IssuerAndSerialNumber` or `SubjectKeyIdentifier`) uniquely
identifies the signing certificate; the verifier needs only to supply the correct
certificate at verify time.

`WithExternalCertificates` accepts a variadic list of certificates and merges them
with any embedded certificates for both signer identification (matching the
`SignerIdentifier`) and chain building (as intermediates). Passing multiple
certificates is safe because lookup is by `SignerIdentifier` match, not by position.
This supports **certificate rotation** in long-lived connections: during the
transition window where messages signed by both old and new certificates may be
in flight, the verifier passes both certificates; the library selects the correct
one per message based on the `SignerIdentifier` in each `SignerInfo`.

**Pruning recommendation:** Retain a superseded certificate in the external store
until its `NotAfter` has passed. Once expired, the library's chain validation will
reject any message signed with it regardless, so natural expiry doubles as the
safe pruning signal.

**Security considerations:** The verifier is responsible for establishing trust in
the externally supplied certificate (e.g., via `WithTrustRoots`). Supplying an
untrusted certificate via `WithExternalCertificates` alone does not grant it
implicit trust — chain validation still applies unless explicitly disabled with
`WithNoChainValidation`.

**Encoding note:** When certificates are excluded, the `Certificates` field in the
internal `SignedData` struct stays `nil`. The `asn1:"optional"` struct tag causes
`encoding/asn1.Marshal` to omit the field entirely from the DER output — no tag, no
length bytes. This is the correct DER encoding for an absent OPTIONAL field per
X.690. By contrast, the reference implementation's `ClearCertificates()` sets the
slice to `[]asn1.RawValue{}` (empty, non-nil), which produces an empty
`[0] CONSTRUCTED` tag (`A0 00`) on the wire — a present-but-empty SET. While most
parsers tolerate this, it is semantically incorrect: an OPTIONAL field that is not
provided should be absent, not encoded as an empty container.

---

## DD-004 — RSA-PSS as default RSA signature algorithm

**RFC reference:** RFC 4056, RFC 8017

**Reference implementation:** Uses `sha*WithRSAEncryption` (PKCS1v15) OIDs by
default, inferred from the public key algorithm.

**This implementation:** Defaults to RSASSA-PSS for all RSA keys. PKCS1v15 is
available via `WithRSAPKCS1()`.

**Rationale:**

RSASSA-PSS is the modern, provably secure RSA signature scheme. PKCS1v15 is
deterministic and its security relies on properties of the hash function and RSA key
size in ways that PSS does not. NIST SP 800-131A Rev. 2 and RFC 8702 both recommend
PSS for new applications. The `WithRSAPKCS1()` escape hatch is provided for
interoperability with legacy systems that require PKCS1v15.

**Security consideration flagged for review:** The default salt length is set equal
to the hash output length (e.g., 32 bytes for SHA-256), following RFC 4055 §3.1
guidance. Some implementations use `sLen = hLen` while others use `sLen = emLen - hLen - 2`
(maximum salt). The chosen value is conservative and interoperable.

---

## DD-005 — Digest algorithm selection for ECDSA keys

**RFC reference:** NIST SP 800-57 Part 1, RFC 5652 §5.3

**Reference implementation:** `digestAlgorithmForPublicKey(pub crypto.PublicKey)` is
designed to select SHA-384 for P-384 keys and SHA-512 for P-521 keys via a type
assertion to `*ecdsa.PublicKey`. However, the caller passes the `[]byte` result of
`x509.MarshalPKIXPublicKey(signer.Public())` as the `pub` argument. Because
`crypto.PublicKey` is a type alias for `any`, the `[]byte` satisfies the interface
at compile time. At runtime, the type assertion `pub.(*ecdsa.PublicKey)` always fails
because the dynamic type is `[]byte`, not `*ecdsa.PublicKey`. The P-384 and P-521
branches are dead code, and SHA-256 is returned for all key types.

This is not a correctness issue — SHA-256 produces valid CMS signatures with any
ECDSA key — but it means the NIST-recommended digest-to-key strength pairings
(P-384/SHA-384, P-521/SHA-512) are never applied despite the code's intent.

**This implementation:** `hashForKey(key crypto.Signer, requested crypto.Hash, explicit bool)`
operates on the actual `crypto.Signer` interface. It forces SHA-512 for Ed25519
(per RFC 8419). For ECDSA keys, when the caller has not explicitly called `WithHash`,
the digest algorithm is auto-selected to match the curve's security level:

| Curve | Auto-selected digest |
|-------|---------------------|
| P-256 | SHA-256             |
| P-384 | SHA-384             |
| P-521 | SHA-512             |

`WithHash` continues to override the auto-selected value for callers who need a
specific digest. This differs from the reference implementation where the
auto-selection was intended but never works due to the type assertion bug.

```go
// Auto-selects SHA-384 for P-384 key:
signer, _ := cms.NewSigner(cert, key)

// Explicit override still works:
signer, _ := cms.NewSigner(cert, key, cms.WithHash(crypto.SHA256))
```

Because the hash selection operates on real types (never serialized bytes), the type
dispatch is always correct — the class of bug present in the reference cannot occur.
