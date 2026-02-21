package pkiasn1

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// ContentInfo is the top-level CMS wrapper structure as defined in RFC 5652,
// section 3. It associates a content type OID with the content itself.
type ContentInfo struct {
	// ContentType identifies the type of the encapsulated content.
	ContentType asn1.ObjectIdentifier
	// Content holds the DER encoding of the content, wrapped in an explicit [0] tag.
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData represents the CMS SignedData content type as defined in RFC 5652,
// section 5.1. It is the primary structure for digitally signed messages.
type SignedData struct {
	// Version is the syntax version number. The value is determined by the
	// content and features used; see RFC 5652 section 5.1 for version rules.
	Version int
	// DigestAlgorithms is the SET of digest algorithm identifiers used by all
	// SignerInfos. Must contain every algorithm used across all signers.
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	// EncapContentInfo holds the signed content and its type OID.
	EncapContentInfo EncapsulatedContentInfo
	// Certificates is an optional SET of certificate choices for chain building.
	// Encoded with IMPLICIT tag [0].
	Certificates []asn1.RawValue `asn1:"optional,tag:0"`
	// CRLs is an optional SET of revocation information choices.
	// Encoded with IMPLICIT tag [1].
	CRLs []asn1.RawValue `asn1:"optional,tag:1"`
	// SignerInfos is the SET of per-signer signature information structures.
	SignerInfos []SignerInfo `asn1:"set"`
}

// EncapsulatedContentInfo holds the content being signed and its type identifier,
// as defined in RFC 5652, section 5.2.
//
// When EContent is absent (zero-value RawValue), the signature is detached and
// the content exists outside this structure. When EContent is present but contains
// a zero-length OCTET STRING, the signature covers a 0-byte payload. These two
// cases are structurally distinct and must never be conflated.
type EncapsulatedContentInfo struct {
	// EContentType identifies the content type of the encapsulated content.
	EContentType asn1.ObjectIdentifier
	// EContent holds the content as an OCTET STRING, wrapped in an explicit [0] tag.
	// Absence indicates a detached signature. Presence with a zero-length OCTET
	// STRING indicates a signed 0-byte payload.
	EContent asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// IsDetached reports whether the EncapsulatedContentInfo represents a detached
// signature, meaning EContent is absent from the encoding.
func (e *EncapsulatedContentInfo) IsDetached() bool {
	return len(e.EContent.FullBytes) == 0
}

// SignerInfo holds the per-signer signature information as defined in RFC 5652,
// section 5.3.
type SignerInfo struct {
	// Version is the syntax version for this SignerInfo. Version 1 is used with
	// IssuerAndSerialNumber; version 3 is used with SubjectKeyIdentifier.
	Version int
	// SID is the SignerIdentifier, which is a CHOICE between IssuerAndSerialNumber
	// (SEQUENCE) and SubjectKeyIdentifier ([0] IMPLICIT OCTET STRING). Stored as a
	// RawValue to allow inspection of the tag for CHOICE disambiguation.
	SID asn1.RawValue
	// DigestAlgorithm identifies the digest algorithm used to compute the message
	// digest over the content or signed attributes.
	DigestAlgorithm pkix.AlgorithmIdentifier
	// SignedAttrs is the optional SET of signed attributes, encoded with IMPLICIT
	// tag [0]. When present, the digest is computed over a re-encoding of this
	// field with an EXPLICIT SET tag (0x31), not over the [0]-tagged wire form.
	// Per RFC 5652, SignedAttrs MUST be DER encoded even if the outer structure is BER.
	SignedAttrs asn1.RawValue `asn1:"optional,tag:0"`
	// SignatureAlgorithm identifies the signature algorithm and any associated
	// parameters. For RSASSA-PSS, the RSASSA-PSS-params structure MUST be present.
	SignatureAlgorithm pkix.AlgorithmIdentifier
	// Signature is the result of the signature computation, encoded as an OCTET STRING.
	// For ECDSA, this is the DER encoding of Ecdsa-Sig-Value { r INTEGER, s INTEGER }.
	Signature []byte
	// UnsignedAttrs is the optional SET of unsigned attributes, encoded with IMPLICIT
	// tag [1]. Counter-signatures and RFC 3161 timestamp tokens appear here.
	UnsignedAttrs asn1.RawValue `asn1:"optional,tag:1"`
}

// Attribute represents a single CMS attribute as defined in RFC 5652, section 5.3.
// An attribute associates an OID with one or more values encoded as a SET.
type Attribute struct {
	// Type identifies the attribute.
	Type asn1.ObjectIdentifier
	// Values holds the raw DER encoding of the SET OF attribute values. The content
	// is parsed according to the specific attribute type.
	Values asn1.RawValue `asn1:"set"`
}

// RawAttributes is a SET OF Attribute as it appears on the wire.
type RawAttributes []Attribute

// EnvelopedData represents the CMS EnvelopedData content type as defined in
// RFC 5652, section 6.1. It provides encrypted content for one or more recipients.
// OriginatorInfo and UnprotectedAttrs are not used in this implementation.
type EnvelopedData struct {
	// Version is the syntax version number, determined by recipient types used.
	Version int
	// RecipientInfos is the SET of per-recipient key transport or key agreement
	// information. Each element is a CHOICE encoded as a RawValue.
	RecipientInfos []asn1.RawValue `asn1:"set"`
	// EncryptedContentInfo holds the encrypted content and algorithm parameters.
	EncryptedContentInfo EncryptedContentInfo
}

// EncryptedContentInfo holds the encrypted content and the algorithm used to
// encrypt it, as defined in RFC 5652, section 6.1.
type EncryptedContentInfo struct {
	// ContentType identifies the type of the encrypted content.
	ContentType asn1.ObjectIdentifier
	// ContentEncryptionAlgorithm identifies the symmetric cipher and its parameters.
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	// EncryptedContent is the ciphertext, encoded as an IMPLICIT [0] OCTET STRING.
	// When absent, the encrypted content is provided by other means.
	EncryptedContent asn1.RawValue `asn1:"optional,tag:0"`
}

// KeyTransRecipientInfo carries key transport information for RSA-OAEP recipients,
// as defined in RFC 5652, section 6.2.1. Version 0 is used with IssuerAndSerialNumber.
type KeyTransRecipientInfo struct {
	// Version is 0 when RID is IssuerAndSerialNumber, 2 when SubjectKeyIdentifier.
	Version int
	// RID is the RecipientIdentifier CHOICE, stored as a RawValue for disambiguation.
	RID asn1.RawValue
	// KeyEncryptionAlgorithm identifies the key encryption algorithm (e.g., RSA-OAEP).
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	// EncryptedKey is the content-encryption key encrypted for this recipient.
	EncryptedKey []byte
}

// KeyAgreeRecipientInfo carries key agreement information for ECDH recipients,
// as defined in RFC 5652, section 6.2.2. Version is always 3.
type KeyAgreeRecipientInfo struct {
	// Version is always 3.
	Version int
	// Originator is [0] EXPLICIT CHOICE carrying the ephemeral public key.
	// The inner value is an OriginatorPublicKey encoded as [1] IMPLICIT.
	Originator asn1.RawValue `asn1:"explicit,tag:0"`
	// UKM is the optional UserKeyingMaterial, encoded as [1] EXPLICIT OCTET STRING.
	UKM []byte `asn1:"optional,explicit,tag:1"`
	// KeyEncryptionAlgorithm identifies the key agreement + key wrap algorithm.
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	// RecipientEncryptedKeys is the SEQUENCE OF per-recipient encrypted CEKs.
	RecipientEncryptedKeys []RecipientEncryptedKey `asn1:"sequence"`
}

// RecipientEncryptedKey pairs a recipient identifier with the wrapped CEK,
// as defined in RFC 5652, section 6.2.2.
type RecipientEncryptedKey struct {
	// RID is the KeyAgreeRecipientIdentifier CHOICE (IssuerAndSerialNumber).
	RID asn1.RawValue
	// EncryptedKey is the CEK wrapped with the key-agreement key.
	EncryptedKey []byte
}

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
