// Package cms implements the Cryptographic Message Syntax as defined in RFC 5652.
//
// It supports all five CMS content types:
//
//   - [SignedData]: sign and verify content using RSA (PKCS#1 v1.5 and PSS),
//     ECDSA, or Ed25519; supports attached and detached signatures, multiple
//     signers, counter-signatures, CRL embedding, and RFC 3161 timestamps.
//   - [EnvelopedData]: encrypt content for one or more recipients using
//     RSA-OAEP or ECDH ephemeral-static key agreement; content is encrypted
//     with AES-GCM or AES-CBC.
//   - [EncryptedData]: encrypt content with a caller-supplied symmetric key
//     when key distribution is handled out of band.
//   - [DigestedData]: wrap content with a cryptographic hash for integrity
//     checking without a signature or encryption.
//   - [AuthenticatedData]: compute an HMAC over content and deliver the MAC
//     key to recipients via RSA-OAEP or ECDH.
//
// All six content-type constructors use the functional options pattern: pass
// options as variadic arguments to NewXxx, which validates configuration
// immediately and returns an error. The returned value is then safe for
// concurrent calls to the terminal method (Sign, CounterSign, Encrypt, Digest,
// or Authenticate), which produces a DER-encoded ContentInfo.
//
// The corresponding ParseXxx function returns a parsed result whose Verify or
// Decrypt method checks the cryptographic output.
//
// The package accepts both DER and BER input. BER is transparently converted
// to DER before parsing, so messages produced by Windows CryptoAPI, Java
// Bouncy Castle, and other implementations that emit BER are handled correctly.
//
// The [ber] sub-package exposes the BER-to-DER converter directly for callers
// that need it outside of a CMS context.
package cms
