# CMS Library — Future Features

Planned enhancements to revisit in future development cycles.

---

## FF-001 — Auto-select ECDSA digest algorithm by curve

**Status:** Done

**Summary:** Automatically select the NIST-recommended digest algorithm based on
the ECDSA curve when the caller does not explicitly call `WithHash`:

| Curve | Default digest (current) | Proposed default |
|-------|--------------------------|------------------|
| P-256 | SHA-256                  | SHA-256 (no change) |
| P-384 | SHA-256                  | SHA-384 |
| P-521 | SHA-256                  | SHA-512 |

`WithHash` would continue to override the auto-selected value for callers who need
a specific digest.

**Motivation:** NIST SP 800-57 Part 1 recommends matching the hash strength to the
key strength. A P-384 key provides 192-bit security, but SHA-256 provides only
128-bit collision resistance — the hash is the weakest link. The reference
implementation (`smimesign/ietf-cms`) intended to auto-select but has a bug that
prevents it (see DD-005 in `design-decisions.md`).

**Implementation notes:**
- Add a `hashExplicit bool` field to `Signer` (similar to the existing
  `familyExplicit`). `WithHash` sets it to `true`.
- In `hashForKey`, when `hashExplicit` is `false` and the key is `*ecdsa.PublicKey`,
  inspect `ecKey.Curve` and return the matched hash.
- When `hashExplicit` is `true`, honour the caller's choice unconditionally.
- Update tests for P-384 and P-521 to verify auto-selection and explicit override.

**Risk:** Low. SHA-384 and SHA-512 are universally supported by any system that
supports P-384 and P-521. No interop issues expected.

---

## FF-002 — Validate certificate-key pair at construction time

**Status:** Done

**Summary:** `NewSigner` should verify that the certificate's public key matches
the provided private key at construction time, returning `ErrInvalidConfiguration`
on mismatch.

**Current behaviour:** `NewSigner(cert, key)` accepts any cert/key combination
without validation. A mismatched pair produces a `Signer` that generates CMS
messages where the `SignerIdentifier` points to a certificate whose public key
does not match the signature. The error surfaces only at verify time as a
confusing signature verification failure.

**Motivation:** The reference implementation (`AddSignerInfo`) discovers the leaf
certificate by comparing serialized public keys from the chain against the signer
key. Our API takes the cert directly, which is simpler but removes that implicit
validation. An explicit check at construction time would fail fast with a clear
error message.

**Implementation notes:**
- In `NewSigner`, after nil checks, compare `cert.PublicKey` against `key.Public()`
  using `x509.MarshalPKIXPublicKey` on both and `bytes.Equal`. This handles all
  key types uniformly without type-switching.
- Accumulate the error into the existing `errs` slice so it is reported alongside
  any other configuration errors.
- Add tests for mismatched RSA cert + ECDSA key, same-type but different key pair,
  and correct pair (no error).

**Risk:** Low. This is a fail-fast validation that prevents misconfiguration. No
impact on valid usage.

---

## FF-003 — `AddCertificateChain` convenience option

**Status:** Done

**Summary:** Add a variadic `AddCertificateChain` option that embeds multiple
certificates (typically intermediates and/or root) in a single call:

```go
signer, _ := cms.NewSigner(leaf, key,
    cms.AddCertificateChain(intermediate, root),
)
```

**Current behaviour:** Callers must use one `AddCertificate` call per extra cert.
This is functionally complete but verbose when embedding a multi-cert chain.

**Design notes:**
- The extra certs are purely transport — they are embedded in
  `SignedData.Certificates` for the verifier's chain-building benefit but have
  no effect on digest computation, signature, or `SignerIdentifier` selection.
  This matches the reference implementation's behaviour.
- The name `AddCertificateChain` was chosen over `AddCertificates` (too visually
  close to `AddCertificate`) and `AddCAChain`/`AddTrustedCA` (implies a trust
  relationship that does not exist at signing time — trust is the verifier's
  concern, not the signer's).
- The implementation does not need to validate chain ordering or that the certs
  form a valid path. They are appended to `s.extraCerts` identically to
  `AddCertificate`.
- `AddCertificate` remains available for adding a single cert.

**Implementation notes:**
- Add `AddCertificateChain(certs ...*x509.Certificate) SigningOption` in
  `options.go`. Loop over `certs`, nil-check each, append to `s.extraCerts`.
- Add a test that signs with a 3-cert chain (leaf + intermediate + root),
  verifies, and confirms all certs appear in the parsed `SignedData`.

**Risk:** None. Pure convenience wrapper over existing functionality.
