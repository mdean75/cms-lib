package pkiasn1

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// IssuerAndSerialNumber identifies a certificate by its issuer distinguished name
// and serial number, as defined in RFC 5652, section 10.2.4.
type IssuerAndSerialNumber struct {
	// Issuer is the DER encoding of the certificate issuer's distinguished name.
	Issuer asn1.RawValue
	// SerialNumber is the certificate serial number.
	SerialNumber *big.Int
}

// RSAPSSParams holds the algorithm parameters for the RSASSA-PSS signature algorithm
// as defined in RFC 4055, section 3.1. Per RFC 4056, these parameters MUST be
// present in the signatureAlgorithm AlgorithmIdentifier when id-RSASSA-PSS is used.
type RSAPSSParams struct {
	// HashAlgorithm identifies the hash algorithm. Defaults to SHA-1 per RFC 4055
	// but MUST be set explicitly since SHA-1 is excluded from this library's
	// allow-list.
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:0"`

	// MaskGenAlgorithm identifies the mask generation function. The standard
	// value is MGF1 (OID 1.2.840.113549.1.1.8) with parameters identifying
	// the hash algorithm used by MGF1.
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1"`

	// SaltLength is the length in bytes of the salt. Defaults to 20 per RFC 4055.
	// This library uses a salt length equal to the hash output length.
	SaltLength int `asn1:"explicit,optional,tag:2"`

	// TrailerField identifies the trailer field. The only supported value is 1
	// (trailerFieldBC), which is also the default.
	TrailerField int `asn1:"explicit,optional,tag:3"`
}

// EcdsaSigValue is the DER structure for an ECDSA signature value as defined in
// RFC 3279, section 2.2.3. Go's crypto/ecdsa package produces raw (r, s) integers
// that must be marshaled into this structure before storing in a CMS SignedData,
// and unmarshaled from this structure before verification.
type EcdsaSigValue struct {
	R *big.Int
	S *big.Int
}

// RSAOAEPParams holds the algorithm parameters for RSAES-OAEP as defined in
// RFC 4055, section 3.1. When SHA-256 is used for both hash and MGF1, these
// parameters explicitly override the SHA-1 defaults.
type RSAOAEPParams struct {
	// HashAlgorithm identifies the hash function. Defaults to SHA-1 per RFC 4055;
	// this library always sets it explicitly to a stronger hash.
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:0"`

	// MaskGenAlgorithm identifies the mask generation function. The standard
	// value is MGF1 with parameters identifying the hash used by MGF1.
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1"`
}

// GCMParameters holds the algorithm parameters for AES in GCM mode as defined
// in RFC 5084, section 3.2. The nonce (initialization vector) is mandatory;
// ICVLen (authentication tag length in bytes) defaults to 16 and is omitted
// when it equals that default.
type GCMParameters struct {
	// Nonce is the 12-byte initialization vector for AES-GCM.
	Nonce []byte

	// ICVLen is the authentication tag length in bytes. When omitted (zero),
	// the default value of 16 applies per RFC 5084.
	ICVLen int `asn1:"optional"`
}

// OriginatorPublicKey carries the ephemeral EC public key used in ECDH key
// agreement (KeyAgreeRecipientInfo), as defined in RFC 5652, section 6.2.2.
type OriginatorPublicKey struct {
	// Algorithm identifies the public key algorithm and its parameters (e.g.,
	// the named EC curve OID for an EC key).
	Algorithm pkix.AlgorithmIdentifier

	// PublicKey is the DER bit string encoding of the public key.
	PublicKey asn1.BitString
}
