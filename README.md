# cms

A Go implementation of [RFC 5652 Cryptographic Message Syntax (CMS)](https://www.rfc-editor.org/rfc/rfc5652).

```
go get github.com/mdean75/cms
```

## Contents

- [Signing and Verifying](#signing-and-verifying)
  - [Sign a message](#sign-a-message)
  - [Verify a signature](#verify-a-signature)
  - [Detached signatures](#detached-signatures)
  - [Multiple signers](#multiple-signers)
  - [Counter-signatures](#counter-signatures)
- [Encrypting and Decrypting (EnvelopedData)](#encrypting-and-decrypting-envelopeddata)
- [Symmetric Encryption (EncryptedData)](#symmetric-encryption-encrypteddata)
- [Digest-Only Messages (DigestedData)](#digest-only-messages-digesteddata)
- [MAC Authentication (AuthenticatedData)](#mac-authentication-authenticateddata)
- [Error Handling](#error-handling)

---

## Signing and Verifying

### Sign a message

`NewSigner` returns a builder. Call builder methods to configure, then call `Sign`
with an `io.Reader` over the content.

```go
import (
    "crypto/x509"
    "github.com/mdean75/cms"
)

func signMessage(cert *x509.Certificate, key crypto.Signer, content []byte) ([]byte, error) {
    return cms.NewSigner().
        WithCertificate(cert).
        WithPrivateKey(key).
        Sign(cms.FromBytes(content))
}
```

`Sign` returns a DER-encoded `ContentInfo` wrapping a `SignedData` structure.
The signed content is embedded (attached) by default.

**Common options:**

| Method | Effect |
|---|---|
| `WithHash(crypto.SHA384)` | Use SHA-384 instead of the default SHA-256 |
| `WithRSAPKCS1()` | Use RSA PKCS#1 v1.5 instead of the default RSA-PSS |
| `WithDetachedContent()` | Omit the content from the output (see [detached signatures](#detached-signatures)) |
| `WithSignerIdentifier(cms.SubjectKeyIdentifier)` | Identify the signer by SKI instead of issuer/serial |
| `AddCertificate(cert)` | Embed additional certificates (e.g. intermediates) |
| `WithTimestamp(tsaURL)` | Request an RFC 3161 timestamp from a TSA |
| `WithMaxAttachedContentSize(n)` | Override the default 64 MiB content size limit |

### Verify a signature

Parse the DER bytes with `ParseSignedData`, then call `Verify`.

```go
func verifyMessage(der []byte, roots *x509.CertPool) ([]byte, error) {
    psd, err := cms.ParseSignedData(cms.FromBytes(der))
    if err != nil {
        return nil, err
    }

    if err := psd.Verify(cms.WithTrustRoots(roots)); err != nil {
        return nil, err
    }

    r, err := psd.Content()
    if err != nil {
        return nil, err
    }
    return io.ReadAll(r)
}
```

**Verification options:**

| Option | Effect |
|---|---|
| `WithTrustRoots(pool)` | Validate the certificate chain against the provided CA pool |
| `WithSystemTrustStore()` | Validate against the OS system trust store |
| `WithVerifyOptions(x509.VerifyOptions{...})` | Full control over chain validation |
| `WithNoChainValidation()` | Skip certificate chain checking entirely |
| `WithVerifyTime(t)` | Use a fixed reference time for certificate validity |

### Detached signatures

When signing, call `WithDetachedContent()`. The returned DER contains no embedded
content. Pass the original content to `VerifyDetached`.

```go
// Sign — content is not embedded in the output
der, err := cms.NewSigner().
    WithCertificate(cert).
    WithPrivateKey(key).
    WithDetachedContent().
    Sign(cms.FromBytes(content))

// Verify — supply the original content separately
psd, err := cms.ParseSignedData(cms.FromBytes(der))
if err != nil { ... }

err = psd.VerifyDetached(cms.FromBytes(content), cms.WithTrustRoots(roots))
```

### Multiple signers

Add additional signers with `WithAdditionalSigner`. Each signer is configured
independently with its own certificate, key, and algorithm options.

```go
signer1 := cms.NewSigner().
    WithCertificate(cert1).
    WithPrivateKey(key1)

signer2 := cms.NewSigner().
    WithCertificate(cert2).
    WithPrivateKey(key2).
    WithHash(crypto.SHA384)

der, err := signer1.
    WithAdditionalSigner(signer2).
    Sign(cms.FromBytes(content))
```

`Verify` and `VerifyDetached` check every `SignerInfo` in the structure. All
must pass for the call to succeed.

### Counter-signatures

A counter-signature signs an existing `SignerInfo` signature value, providing a
witnessed-at timestamp without a TSA.

```go
// counter is applied to every SignerInfo in the parsed ContentInfo
updated, err := cms.NewCounterSigner().
    WithCertificate(counterCert).
    WithPrivateKey(counterKey).
    CounterSign(cms.FromBytes(der))
```

`CounterSign` returns a new DER-encoded `ContentInfo` with the counter-signature
embedded as an unsigned attribute in each `SignerInfo`.

---

## Encrypting and Decrypting (EnvelopedData)

`EnvelopedData` encrypts content for one or more recipients. The content
encryption key is wrapped using the recipient's public key (RSA-OAEP for RSA
keys, ECDH ephemeral-static for EC keys).

```go
// Encrypt for a recipient
der, err := cms.NewEncryptor().
    WithRecipient(recipientCert).   // RSA or EC cert; add more for multiple recipients
    Encrypt(cms.FromBytes(content))

// Decrypt as the recipient
ped, err := cms.ParseEnvelopedData(cms.FromBytes(der))
if err != nil { ... }

plaintext, err := ped.Decrypt(privateKey, recipientCert)
```

The default content encryption algorithm is AES-256-GCM. Use
`WithContentEncryption` to select a different cipher:

```go
cms.NewEncryptor().
    WithRecipient(cert).
    WithContentEncryption(cms.AES128GCM).
    Encrypt(r)
```

Available algorithms: `AES256GCM` (default), `AES128GCM`, `AES128CBC`, `AES256CBC`.

---

## Symmetric Encryption (EncryptedData)

`EncryptedData` encrypts content with a caller-supplied symmetric key. Unlike
`EnvelopedData` there are no recipients — key distribution is handled out of band.

```go
key := make([]byte, 32) // 32-byte key for AES-256
if _, err := io.ReadFull(rand.Reader, key); err != nil { ... }

// Encrypt
der, err := cms.NewSymmetricEncryptor().
    WithKey(key).
    Encrypt(cms.FromBytes(content))

// Decrypt
ped, err := cms.ParseEncryptedData(cms.FromBytes(der))
if err != nil { ... }

plaintext, err := ped.Decrypt(key)
```

---

## Digest-Only Messages (DigestedData)

`DigestedData` wraps content with a hash but provides no confidentiality or
authentication. It is useful for integrity checking when the verifier already
trusts the channel.

```go
// Create
der, err := cms.NewDigester().
    Digest(cms.FromBytes(content))

// Verify (attached — content is embedded)
pdd, err := cms.ParseDigestedData(cms.FromBytes(der))
if err != nil { ... }

if err := pdd.Verify(); err != nil { ... }

r, err := pdd.Content()

// Verify (detached)
pdd, err := cms.ParseDigestedData(cms.FromBytes(der))
err = pdd.VerifyDetached(cms.FromBytes(content))
```

---

## MAC Authentication (AuthenticatedData)

`AuthenticatedData` computes an HMAC over the content and encrypts the MAC key
for one or more recipients (RSA-OAEP or ECDH, same as `EnvelopedData`).

```go
// Authenticate
der, err := cms.NewAuthenticator().
    WithRecipient(recipientCert).
    Authenticate(cms.FromBytes(content))

// Verify
pad, err := cms.ParseAuthenticatedData(cms.FromBytes(der))
if err != nil { ... }

if err := pad.VerifyMAC(privateKey, recipientCert); err != nil { ... }

r, err := pad.Content()
```

Default MAC algorithm is HMAC-SHA256. Use `WithMACAlgorithm` to select
`cms.HMACSHA384` or `cms.HMACSHA512`.

---

## Error Handling

All errors are `*cms.Error` values carrying a `Code`, a human-readable `Message`,
and an optional `Cause`. Use `errors.Is` to match against sentinel errors:

```go
if errors.Is(err, cms.ErrInvalidSignature) {
    // signature check failed
}
if errors.Is(err, cms.ErrMissingCertificate) {
    // no matching certificate found in the message
}
```

Builder methods do not return errors. Validation failures (missing certificate,
unsupported key type, etc.) are accumulated and returned together by the terminal
method (`Sign`, `Encrypt`, `Digest`, `Authenticate`, `CounterSign`):

```go
_, err := cms.NewSigner().
    WithCertificate(nil).  // invalid — accumulated
    WithPrivateKey(nil).   // invalid — accumulated
    Sign(r)
// err contains both failures via errors.Join
```

**Sentinel errors:**

| Sentinel | Meaning |
|---|---|
| `ErrParse` | Malformed ASN.1 input |
| `ErrBERConversion` | BER→DER normalisation failure |
| `ErrUnsupportedAlgorithm` | Algorithm OID not supported |
| `ErrInvalidSignature` | Cryptographic verification failed |
| `ErrCertificateChain` | Certificate chain validation failed |
| `ErrMissingCertificate` | Required certificate not found |
| `ErrTimestamp` | RFC 3161 timestamp error |
| `ErrCounterSignature` | Counter-signature error |
| `ErrVersionMismatch` | CMS version field mismatch |
| `ErrAttributeInvalid` | Signed or authenticated attribute invalid |
| `ErrContentTypeMismatch` | ContentInfo OID does not match structure |
| `ErrPKCS7Format` | PKCS#7 construct not supported |
| `ErrDetachedContentMismatch` | Detached content does not match digest |
| `ErrPayloadTooLarge` | Content exceeds configured size limit |
| `ErrInvalidConfiguration` | Builder configured incorrectly |
