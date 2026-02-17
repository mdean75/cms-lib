# CMS Package Planning

## Package Name Decision

**Chosen Name:** `cms`

### Rationale

We selected `cms` as the package name for the following reasons:

1. **Direct RFC Mapping** - CMS (Cryptographic Message Syntax) is the official name for RFC 5652, making it immediately recognizable to developers familiar with the standard

2. **Idiomatic Go** - Short, lowercase package names are preferred in Go (following the pattern of existing crypto packages like `tls`, `aes`, `rsa`)

3. **Ecosystem Alignment** - Industry-standard libraries (like Bouncy Castle) use "CMS" as the canonical name, making our package easier to discover and understand

4. **Future-Proof** - While initially focusing on signing/verification (SignedData), the name accommodates potential expansion to other CMS content types (EnvelopedData, DigestedData, etc.) without requiring a rename

5. **Avoids Confusion** - Steers clear of `pkcs7` (the predecessor to CMS), which has multiple existing but incomplete implementations in the Go ecosystem

### Names Considered and Rejected

- `pkcs7` - Avoided due to multiple existing projects with this name and because CMS (RFC 5652) is technically the successor to PKCS #7
- `msgsign` - Too specific; would be limiting if we expand beyond signing
- `sigdata` - While aligned with SignedData terminology, doesn't capture the broader CMS scope
- `msgenv` - Emphasized enveloping, which isn't our initial focus
- `secmsg` - Too generic and doesn't reference the standard

## RFC 5652 Overview

### What is CMS?

RFC 5652 defines the Cryptographic Message Syntax (CMS), a comprehensive framework for cryptographically protecting messages. CMS is the successor to PKCS #7 and provides standardized methods for:

- Digital signatures
- Message encryption
- Message authentication
- Key transport and agreement

### Core Content Types Defined

RFC 5652 specifies six primary content types:

1. **Data** - Raw encapsulated content with no cryptographic protection

2. **SignedData** - Digitally signed content
   - Supports multiple signers
   - Can include signer certificates
   - Supports both attached and detached signatures
   - Allows for countersignatures

3. **EnvelopedData** - Encrypted content for one or more recipients
   - Supports multiple recipients with different keys
   - Includes key transport and key agreement mechanisms
   - Recipient information is included in the structure

4. **DigestedData** - Content with a message digest
   - Provides data integrity without confidentiality
   - Single digest algorithm applied to content

5. **EncryptedData** - Encrypted content with pre-shared key
   - Unlike EnvelopedData, no recipient information
   - Assumes key is already known to recipient

6. **AuthenticatedData** - MAC-authenticated content
   - Provides authentication without encryption
   - Introduced in RFC 5652 (not in original PKCS #7)

### Key Operations

**Signing Operations:**
- Create signatures over arbitrary data
- Support for detached and attached signatures
- Multiple concurrent signers
- Authenticated and unauthenticated attributes
- Countersignatures

**Verification Operations:**
- Verify signatures using X.509 certificates
- Certificate chain validation
- Support for certificate revocation lists (CRLs)
- Timestamp verification

**Encryption Operations:**
- Encrypt data for multiple recipients
- Key transport (RSA, etc.)
- Key agreement (Diffie-Hellman, ECDH)
- Content encryption with symmetric algorithms

**Additional Capabilities:**
- Nesting (e.g., signing encrypted data, encrypting signed data)
- Certificate and CRL handling
- Algorithm flexibility through ASN.1 encoding

## Go Standard Library Analysis

### What Go Provides

The Go standard library includes robust cryptographic primitives:

**Crypto Packages:**
- `crypto` - Common cryptographic constants and interfaces
- `crypto/x509` - X.509 certificate parsing, creation, and validation
- `crypto/rsa` - RSA encryption and signing
- `crypto/ecdsa` - Elliptic curve digital signatures
- `crypto/ed25519` - Ed25519 signatures
- `crypto/sha256`, `crypto/sha512` - Hash functions
- `crypto/aes` - AES encryption
- `crypto/rand` - Cryptographic random number generation

**Supporting Packages:**
- `encoding/asn1` - ASN.1 encoding/decoding
- `crypto/x509/pkix` - X.509 PKI structures

**Key Interfaces:**
- `crypto.Signer` - Generic signing interface
- `crypto.Decrypter` - Generic decryption interface
- `crypto.SignerOpts` - Signing options

### What Go Does NOT Provide

**Missing CMS/PKCS #7 Implementation:**

Go's standard library has **no native support** for:
- CMS/PKCS #7 data structures
- SignedData content type
- EnvelopedData content type
- Any other CMS content types
- CMS message creation or parsing
- CMS signature verification workflows

**Specific Gaps:**
1. No ASN.1 structures for CMS content types
2. No helpers for creating SignedData with certificates
3. No verification of detached signatures
4. No support for authenticated/unauthenticated attributes
5. No countersignature support
6. No envelope encryption for multiple recipients
7. No integration between signing and X.509 certificate chains

### Existing Third-Party Implementations

Several fragmented implementations exist but with limitations:

- **cloudflare/cfssl/crypto/pkcs7** - Subset implementation for packaging certificates/CRLs only
- **github/smimesign/ietf-cms** - Focused on S/MIME use cases
- **Various pkcs7 packages** - Incomplete, unmaintained, or specialized (e.g., GOST crypto)

**Common Issues:**
- Incomplete RFC 5652 coverage
- Focus on specific use cases (S/MIME, Authenticode)
- Inconsistent APIs
- Limited maintenance
- No comprehensive solution

## Opportunity

The `cms` package fills a significant gap in Go's cryptographic ecosystem by providing:

1. **Standards Compliance** - Full RFC 5652 implementation
2. **Idiomatic Go API** - Leveraging existing `crypto` interfaces
3. **Interoperability** - Compatible with other CMS implementations (OpenSSL, Bouncy Castle, etc.)
4. **Completeness** - Not limited to a single use case

### Initial Focus: SignedData

While RFC 5652 defines multiple content types, the initial implementation will focus on **SignedData** for signing and verification operations, as this is:
- The most commonly needed CMS functionality
- Well-defined with clear use cases
- Foundation for understanding CMS structure
- Immediately useful for code signing, document signing, etc.

Future expansion can add EnvelopedData, AuthenticatedData, and other content types as needed.

## Next Steps

1. Define API surface for SignedData operations
2. Design ASN.1 structures matching RFC 5652
3. Implement signing with detached/attached signatures
4. Implement verification with certificate chain validation
5. Add comprehensive test suite with interoperability tests
6. Document usage examples
