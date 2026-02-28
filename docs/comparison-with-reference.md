# cms-lib: Design Differences from the Reference Implementation

**Reference:** [`github/smimesign/ietf-cms`](https://github.com/github/smimesign/tree/main/ietf-cms)

This document describes where `cms-lib` diverges from the reference implementation,
why those choices were made, and what functional or performance improvements result.
It is written for a technical audience familiar with CMS/PKCS #7.

---

## Overview

Both libraries implement RFC 5652 Cryptographic Message Syntax in Go. The reference
(`smimesign/ietf-cms`) is a correct, minimal implementation originally written to
support the `smimesign` signing tool. `cms-lib` was built from the ground up with a
broader feature set, a different API model, and several correctness and performance
improvements.

The reference exposes two layers: a top-level `cms` package with convenience
functions (`Sign`, `SignDetached`, `NewSignedData`, `ParseSignedData`) and a lower-
level `protocol` package containing the raw ASN.1 structs. The examples below use
the top-level `cms` package, which is the intended public API.

---

## 1. API Model: Immutable Builder vs. Mutable Struct

### Reference

The reference `SignedData` struct is a mutable message object — content is baked
into it at construction time via `NewSignedData(data)`. A new struct must be created
for each message. Configuration (detached, certificate stripping) is applied by
mutating the struct before calling `ToDER()`:

```go
import cms "github.com/github/smimesign/ietf-cms"

chain := []*x509.Certificate{leafCert, intermediateCert}

// Convenience path — one call but no room for options:
der, err := cms.Sign(content, chain, privateKey)

// Or the step-by-step form, which enables post-build mutations:
sd, err := cms.NewSignedData(content)  // content baked in here
err = sd.Sign(chain, privateKey)
der, err = sd.ToDER()
```

Because `NewSignedData` takes a `[]byte`, a new `SignedData` must be constructed for
every message. There is no reusable signing configuration object.

### cms-lib

`cms-lib` separates the signing configuration from the content. A `Signer` holds
only key material and options; content flows through it at call time. `Sign` is safe
for concurrent use — no synchronization required:

```go
import cms "github.com/mdean75/cms-lib"

// Construct once at startup
signer, err := cms.NewSigner(leafCert, privateKey,
    cms.AddCertificate(intermediateCert),
)

// Call Sign from as many goroutines as needed — same signer, different content
der, err := signer.Sign(bytes.NewReader(content))
der2, err := signer.Sign(bytes.NewReader(otherContent))
```

**Practical difference:** A single `Signer` can be constructed once and reused
concurrently across all goroutines (e.g., one per active gRPC stream) with no
locking required.

---

## 2. Certificate Exclusion: `WithoutCertificates()`

### Reference

The top-level `cms.Sign()` convenience function always embeds the full chain. There
is no way to prevent this when using `Sign()`. Using the step-by-step form, you can
call `SetCertificates` with an empty slice before calling `ToDER()` to exclude them:

```go
sd, err := cms.NewSignedData(content)
err = sd.Sign(chain, privateKey)    // Sign() adds certs from chain...
err = sd.SetCertificates(nil)       // ...strip them before encoding
der, err = sd.ToDER()               // serialized once, without certificates
```

Because `SetCertificates` is called before `ToDER()`, there is no double-
serialization — the struct is only encoded to DER once. However, the certificate
list is still allocated and populated internally during `Sign()` and then discarded.
The caller must also remember the extra step; forgetting it silently embeds
certificates in the output.

### cms-lib

`WithoutCertificates()` is a construction-time option. The library **never allocates
or populates the certificate list** in the first place:

```go
signer, err := cms.NewSigner(leafCert, privateKey,
    cms.WithoutCertificates(),
)
der, err := signer.Sign(bytes.NewReader(content))
```

**Performance:** No allocation, deduplication, or `asn1.RawValue` wrapping is done
for the certificate set. The zero-cert path is not an afterthought — it is a
first-class construction-time decision. In the reference, even when you call
`SetCertificates(nil)` before encoding, the certificate deduplication work inside
`Sign()` has already happened and is simply thrown away.

**Ergonomics:** In the reference, excluding certificates is a two-step sequence
(`Sign` then `SetCertificates`) that must be applied to every new `SignedData`
instance. With `cms-lib`, the intent is expressed once at `NewSigner` construction
time and applies automatically to every subsequent `Sign` call with no additional
steps.

**Correctness:** RFC 5652 §5.1 defines `certificates` as `OPTIONAL`. Omitting it
produces a fully conformant CMS SignedData. The `SignerIdentifier` in each
`SignerInfo` (issuer+serial or SKI) is sufficient for the verifier to locate the
correct certificate by other means.

**Encoding difference:** The reference's `ClearCertificates()` sets the internal
slice to `[]asn1.RawValue{}` (empty, non-nil). Go's `encoding/asn1` marshals this
as an **empty `[0] CONSTRUCTED`** tag on the wire (`A0 00` — 2 bytes), meaning
"certificates field is present but contains zero items." In `cms-lib`, when
`WithoutCertificates()` is set, `Certificates` stays `nil`, which the `optional`
struct tag causes to be **completely absent** from the encoding — no tag, no length,
no bytes. This is the correct encoding for an OPTIONAL field that is not present per
ASN.1 DER rules. The difference is 2 bytes in the output and, more importantly,
avoids the semantic ambiguity of an empty SET where the field should simply be absent.

---

## 3. Signer Identifier Type: SubjectKeyIdentifier Support

### Reference

Only `IssuerAndSerialNumber` is supported as the `SignerIdentifier` (SignerInfo
version 1). The SID is always built from the leaf certificate's issuer DN and serial
number. There is no option to select a different form.

### cms-lib

`WithSignerIdentifier()` allows choosing between the two forms defined in RFC 5652:

```go
// Default: IssuerAndSerialNumber (SignerInfo version 1)
signer, err := cms.NewSigner(cert, key)

// Opt in to SubjectKeyIdentifier (SignerInfo version 3)
signer, err := cms.NewSigner(cert, key,
    cms.WithSignerIdentifier(cms.SubjectKeyIdentifier),
)
```

**How it works:** The SKI byte string is read from `cert.SubjectKeyId` (populated
from the X.509v3 Subject Key Identifier extension) and encoded as an
`[0] IMPLICIT OCTET STRING` in the `SID` field. SignerInfo version is set to 3 per
RFC 5652 §5.3. On verification, the library matches against `cert.SubjectKeyId` in
the candidate certificate pool.

**Why it matters:**
- SKI-based identification is shorter on the wire (typically 20–22 bytes vs.
  50–100+ bytes for a full issuer DN and serial number).
- SKI is stable across certificate renewals when the same key pair is reused — the
  identifier is derived from the public key, not the issuer or serial.
- RFC 5652 defines SKI as the preferred form for version 3 content types.

**Validation:** `NewSigner` returns `ErrInvalidConfiguration` if
`WithSignerIdentifier(SubjectKeyIdentifier)` is set but the certificate has no
`SubjectKeyId` extension, rather than silently producing a SID the verifier cannot
match.

---

## 4. Out-of-Band Certificate Delivery with `WithExternalCertificates()`

### Reference

`Verify` searches only the certificates embedded in the `SignedData`. There is no
mechanism to supply certificates that were not included in the message:

```go
opts := x509.VerifyOptions{Roots: trustedPool}
chains, err := sd.Verify(opts)
// chains is [][][]*x509.Certificate — one verified chain per signer
```

Messages without embedded certificates cannot be verified.

### cms-lib

`WithExternalCertificates()` is a `VerifyOption` that supplies certificates at
verify time. They are merged with any embedded certificates for both signer
identification and chain building:

```go
parsed, err := cms.ParseSignedData(bytes.NewReader(der))

// Standard verify (certs embedded in message):
err = parsed.Verify(cms.WithTrustRoots(trustedPool))

// OOB verify (certs supplied by caller):
err = parsed.Verify(
    cms.WithExternalCertificates(peerCert),
    cms.WithTrustRoots(trustedPool),
)
```

**Certificate rotation in long-lived connections:** Lookup is by `SignerIdentifier`
match, not position, so multiple certificates for the same peer can be passed
simultaneously. This supports a rolling rotation window where messages signed by
both the old and new certificate may be in flight at the same time:

```go
err = parsed.Verify(
    cms.WithExternalCertificates(oldCert, newCert),
    cms.WithTrustRoots(trustedPool),
)
// Library selects the correct cert for each message based on SignerIdentifier
```

---

## 5. BER Input Normalization

### Reference
Does its own BER-to-DER conversion via an internal `BER2DER` function before parsing.

### cms-lib
Uses a dedicated `ber.Normalize` package (in `cms-lib/ber`) that handles:
- Indefinite-length encodings
- Constructed primitive types (e.g., constructed OCTET STRING used by some
  implementations for `eContent`)
- Correct re-encoding to DER

`ParseSignedData` transparently accepts BER or DER input; callers do not need to
know or care which encoding they received.

---

## 6. Multiple Signers via `WithAdditionalSigner()`

### Reference
Multiple signers are supported by calling `sd.Sign(chain, signer)` multiple times
on the same `SignedData` struct before serialization.

### cms-lib
Additional signers are declared at construction time:

```go
signer2, _ := cms.NewSigner(cert2, key2, cms.WithHash(crypto.SHA384))
signer1, _ := cms.NewSigner(cert1, key1,
    cms.WithAdditionalSigner(signer2),
)
der, _ := signer1.Sign(bytes.NewReader(payload))
// produces SignedData with two SignerInfos; DigestAlgorithms deduplicated automatically
```

---

## 7. RFC 3161 Timestamp Support

### Reference
The reference has a `timestamp` sub-package, but it is not integrated into the
signing flow. There is no built-in `Sign`-time timestamp embedding.

### cms-lib
`WithTimestamp(tsaURL)` fetches a timestamp token from a TSA after signing and
embeds it as an `id-aa-signatureTimeStampToken` unsigned attribute on each
`SignerInfo`. The token is verified automatically during `Verify` / `VerifyDetached`
by checking the `MessageImprint` against `hash(signature_bytes)`.

```go
signer, _ := cms.NewSigner(cert, key,
    cms.WithTimestamp("https://freetsa.org/tsr"),
)
```

---

## 8. Counter-Signature Support

### Reference
No built-in counter-signature support.

### cms-lib
`CounterSigner` appends a counter-signature (RFC 5652 §11.4) to every `SignerInfo`
in an existing CMS message. The counter-signature signs the target `SignerInfo`'s
`Signature` bytes — providing a notarization-style attestation that the signature
existed at a point in time.

```go
cs, _ := cms.NewCounterSigner(csCert, csKey)
countersignedDER, _ := cs.CounterSign(bytes.NewReader(originalDER))
```

---

## 9. SignedAttrs Handling: Raw Bytes vs. Typed Parse

### Reference
Signed attributes are parsed into a typed `[]Attribute` slice on unmarshal. To
compute the signature digest, the attributes are re-encoded via
`MarshaledForVerification()`, which re-marshals the parsed slice and patches the
outer tag byte.

### cms-lib
Signed and unsigned attributes are stored as `asn1.RawValue` — the exact wire bytes
are preserved without parsing. The digest is computed by a direct in-place byte
re-tag (`0xA0 → 0x31`) on the stored bytes, with no re-encoding step.

**Why this matters:**
- Eliminates a class of bugs where re-encoding a parsed attribute set produces bytes
  that differ from the original (attribute ordering shifts, string type
  normalisation, etc.), which would invalidate an otherwise correct signature.
- Allows correct verification of messages from BER-encoding implementations where
  attribute encodings are non-canonical and would be altered by a parse-and-re-
  marshal cycle.

---

## 10. Digest Algorithm Selection for ECDSA Keys

### Reference

`AddSignerInfo` selects the digest algorithm via:
```go
pub, err := x509.MarshalPKIXPublicKey(signer.Public())   // pub is []byte
digestAlgorithmID := digestAlgorithmForPublicKey(pub)     // expects crypto.PublicKey
```

`digestAlgorithmForPublicKey` is designed to return SHA-384 for P-384 and SHA-512 for
P-521 via a `pub.(*ecdsa.PublicKey)` type assertion. However, `pub` is the `[]byte`
output of `MarshalPKIXPublicKey`, not the actual key object. Because
`crypto.PublicKey` is `any`, the code compiles, but the type assertion always fails
at runtime. The function unconditionally returns SHA-256 for all key types — the
curve-specific branches are dead code.

This produces valid CMS (SHA-256 works with any ECDSA curve) but does not achieve the
NIST-recommended digest-to-key strength pairings (P-384/SHA-384, P-521/SHA-512).
The digest algorithm is not configurable.

### cms-lib

`hashForKey` operates on the actual `crypto.Signer` interface — never on serialized
bytes — so the type dispatch is always correct. When the caller does not explicitly
call `WithHash`, the digest algorithm is auto-selected to match the ECDSA curve's
security level:

| Curve | Auto-selected digest |
|-------|---------------------|
| P-256 | SHA-256             |
| P-384 | SHA-384             |
| P-521 | SHA-512             |

```go
// P-384 key: auto-selects SHA-384
signer, _ := cms.NewSigner(cert, key)

// Explicit override still honoured:
signer, _ := cms.NewSigner(cert, key, cms.WithHash(crypto.SHA256))
```

The class of bug present in the reference (passing serialized bytes where a typed key
is expected) cannot occur because the library never operates on `[]byte`
representations of public keys during algorithm selection.

---

## 11. Certificate-Key Pair Validation

### Reference

`AddSignerInfo` receives a `chain []*x509.Certificate` and discovers the leaf
certificate by iterating the chain and comparing serialized public keys:

```go
pub, err := x509.MarshalPKIXPublicKey(signer.Public())
for _, cert := range chain {
    certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
    if bytes.Equal(pub, certPub) { /* found leaf */ }
}
```

If no certificate in the chain matches the signer's public key, the function returns
an error. This provides implicit validation but only at signing time, not at
construction time.

### cms-lib

`NewSigner` validates the certificate-key pair at construction time by comparing
serialized public keys via `x509.MarshalPKIXPublicKey`. A mismatch returns
`ErrInvalidConfiguration` immediately — before the caller can attempt to sign:

```go
signer, err := cms.NewSigner(cert, wrongKey)
// err: "certificate public key does not match private key"
```

**Why this matters:** The reference defers validation to `AddSignerInfo`, which runs
inside `Sign()`. A misconfigured caller discovers the mismatch only when they attempt
to produce output. With `cms-lib`, the error surfaces at construction time with a
clear message, making it easy to diagnose during initialization rather than in a
production signing path.

---

## 12. Certificate Chain Embedding

### Reference

The `Sign` function accepts a `chain []*x509.Certificate` containing the leaf and
any intermediates. All certificates in the chain are embedded in the output:

```go
chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}
der, err := cms.Sign(content, chain, privateKey)
```

### cms-lib

`NewSigner` takes only the leaf certificate. Additional certificates (intermediates,
root) are added via `AddCertificate` (one at a time) or `AddCertificateChain`
(variadic, for an entire chain):

```go
signer, _ := cms.NewSigner(leafCert, key,
    cms.AddCertificateChain(intermediateCert, rootCert),
)
```

**Functional equivalence:** Both approaches embed the same certificates in the
output `SignedData.Certificates` field. The certificates are purely transport — they
have no effect on digest computation, signature, or `SignerIdentifier` selection.

**Design difference:** Separating the leaf from the chain makes the roles explicit:
the leaf is the signing certificate (used for `SignerIdentifier` and key operations),
while chain certificates are informational payloads for the verifier. The reference
conflates these roles in a single slice and must discover the leaf by key comparison.

---

## 13. EnvelopedData and EncryptedData Support

### Reference

The reference implements only `SignedData`. There is no support for `EnvelopedData`
(RFC 5652 §6) or `EncryptedData` (RFC 5652 §8). Applications needing encryption must
use a separate library or implement the CMS encryption types themselves.

### cms-lib

`cms-lib` implements all three core CMS content types:

| Content Type | RFC 5652 Section | Purpose |
|---|---|---|
| `SignedData` | §5 | Integrity and authenticity — payload is plaintext, signature proves origin and detects tampering |
| `EnvelopedData` | §6 | Confidentiality with per-recipient key management — payload is encrypted, each recipient's public key wraps the CEK |
| `EncryptedData` | §8 | Confidentiality with a pre-shared symmetric key — simpler than `EnvelopedData` when both parties already share a secret |

**EnvelopedData** (`Encryptor` builder):

```go
enc := cms.NewEncryptor().
    WithRecipient(recipientCert).
    WithContentEncryption(cms.AES256GCM)
ciphertext, err := enc.Encrypt(bytes.NewReader(plaintext))

// Recipient decrypts:
parsed, err := cms.ParseEnvelopedData(bytes.NewReader(ciphertext))
plaintext, err := parsed.Decrypt(recipientKey, recipientCert)
```

Features:
- RSA-OAEP key transport (`KeyTransRecipientInfo`)
- ECDH ephemeral-static key agreement (`KeyAgreeRecipientInfo`) with X9.63 KDF and
  AES key wrap
- AES-128/256 in both GCM and CBC modes
- Multi-recipient support (each recipient gets their own wrapped CEK)

**EncryptedData** (`SymmetricEncryptor` builder):

```go
enc := cms.NewSymmetricEncryptor().
    WithKey(sharedKey).
    WithContentEncryption(cms.AES256GCM)
ciphertext, err := enc.Encrypt(bytes.NewReader(plaintext))

// Recipient decrypts with the same key:
parsed, err := cms.ParseEncryptedData(bytes.NewReader(ciphertext))
plaintext, err := parsed.Decrypt(sharedKey)
```

**When to combine content types:** CMS content types are composable. A common pattern
is sign-then-encrypt: produce a `SignedData`, then encrypt the signed blob as
`EnvelopedData`. The recipient decrypts first, then verifies the signature. This
provides both confidentiality and authenticity in a single envelope.

---

## Summary Table

| Feature | Reference (`smimesign/ietf-cms`) | `cms-lib` |
|---|---|---|
| API model | Mutable message struct per content | Immutable builder, concurrent-safe |
| Signer reuse | New struct per message | One `Signer`, unlimited reuse |
| Certificate exclusion | `SetCertificates(nil)` before `ToDER()`; certs still allocated during `Sign()` | `WithoutCertificates()` at construction; certs never allocated |
| Cert exclusion ergonomics | Two steps per message instance | Declared once at construction, applies to all `Sign()` calls |
| Signer identifier | IssuerAndSerialNumber only | IssuerAndSerialNumber or SubjectKeyIdentifier |
| OOB cert verification | Not supported | `WithExternalCertificates()` |
| Cert rotation support | Not supported | Multi-cert `WithExternalCertificates()` |
| BER input | Internal `BER2DER` | Dedicated `ber.Normalize` package |
| Multiple signers | Repeated `sd.Sign()` calls | `WithAdditionalSigner()` at construction |
| RFC 3161 timestamps | Sub-package only, not integrated | `WithTimestamp(tsaURL)`, auto-verified |
| Counter-signatures | Not supported | `CounterSigner` type |
| SignedAttrs encoding | Typed parse + re-marshal | Raw bytes, in-place re-tag |
| ECDSA digest selection | Always SHA-256 (curve-specific code unreachable) | Auto-selects by curve (P-384→SHA-384, P-521→SHA-512); `WithHash` overrides |
| Cert-key validation | Implicit at signing time (key-to-chain match) | Explicit at construction time (`NewSigner`) |
| Chain embedding | Single `chain` slice; leaf discovered by key comparison | Leaf explicit in `NewSigner`; chain via `AddCertificateChain` |
| EnvelopedData | Not implemented | RSA-OAEP key transport, ECDH key agreement, AES-GCM/CBC |
| EncryptedData | Not implemented | Pre-shared key encryption, AES-GCM/CBC |

