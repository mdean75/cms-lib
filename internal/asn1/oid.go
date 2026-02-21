// Package pkiasn1 defines the ASN.1 wire-format types and OID constants for
// the Cryptographic Message Syntax as specified in RFC 5652.
package pkiasn1

import "encoding/asn1"

// Content type OIDs defined in RFC 5652, section 3.
var (
	// OIDData identifies raw encapsulated content with no cryptographic protection.
	OIDData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// OIDSignedData identifies the SignedData content type.
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// OIDEnvelopedData identifies the EnvelopedData content type.
	OIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}

	// OIDDigestedData identifies the DigestedData content type.
	OIDDigestedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}

	// OIDEncryptedData identifies the EncryptedData content type.
	OIDEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	// OIDAuthenticatedData identifies the AuthenticatedData content type.
	OIDAuthenticatedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 2}
)

// Signed attribute OIDs defined in RFC 5652, section 11, and PKCS #9.
var (
	// OIDAttributeContentType identifies the content-type signed attribute.
	// This attribute is mandatory whenever any signed attributes are present.
	OIDAttributeContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

	// OIDAttributeMessageDigest identifies the message-digest signed attribute.
	// This attribute is mandatory whenever any signed attributes are present.
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// OIDAttributeSigningTime identifies the signing-time signed attribute.
	OIDAttributeSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// OIDAttributeCounterSign identifies the countersignature unsigned attribute.
	// A counter-signature signs the Signature bytes of a SignerInfo, not the content.
	OIDAttributeCounterSign = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}

	// OIDAttributeTimeStampToken identifies the RFC 3161 timestamp token unsigned
	// attribute as defined in RFC 3161, section 3.3.
	OIDAttributeTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

// Digest algorithm OIDs from NIST (FIPS 180-4 and FIPS 202).
var (
	// OIDDigestAlgorithmSHA256 identifies the SHA-256 digest algorithm.
	OIDDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// OIDDigestAlgorithmSHA384 identifies the SHA-384 digest algorithm.
	OIDDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}

	// OIDDigestAlgorithmSHA512 identifies the SHA-512 digest algorithm.
	OIDDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// OIDDigestAlgorithmSHA3_256 identifies the SHA3-256 digest algorithm (RFC 8702).
	OIDDigestAlgorithmSHA3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}

	// OIDDigestAlgorithmSHA3_384 identifies the SHA3-384 digest algorithm (RFC 8702).
	OIDDigestAlgorithmSHA3_384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}

	// OIDDigestAlgorithmSHA3_512 identifies the SHA3-512 digest algorithm (RFC 8702).
	OIDDigestAlgorithmSHA3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
)

// Signature algorithm OIDs for RSA, ECDSA, and EdDSA.
var (
	// OIDSignatureAlgorithmRSA identifies the base RSA algorithm (rsaEncryption).
	// Some CMS implementations (including OpenSSL) use this OID as the
	// signatureAlgorithm in SignerInfo rather than the sha*WithRSAEncryption
	// OIDs, relying on the separate DigestAlgorithm field for the hash.
	OIDSignatureAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// OIDSignatureAlgorithmSHA256WithRSA identifies RSA PKCS1v15 with SHA-256.
	OIDSignatureAlgorithmSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

	// OIDSignatureAlgorithmSHA384WithRSA identifies RSA PKCS1v15 with SHA-384.
	OIDSignatureAlgorithmSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}

	// OIDSignatureAlgorithmSHA512WithRSA identifies RSA PKCS1v15 with SHA-512.
	OIDSignatureAlgorithmSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// OIDSignatureAlgorithmRSAPSS identifies the RSASSA-PSS signature algorithm.
	// Per RFC 4056, the RSASSA-PSS-params structure MUST be present in the
	// AlgorithmIdentifier parameters field when this OID is used.
	OIDSignatureAlgorithmRSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

	// OIDSignatureAlgorithmECDSAWithSHA256 identifies ECDSA with SHA-256.
	OIDSignatureAlgorithmECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	// OIDSignatureAlgorithmECDSAWithSHA384 identifies ECDSA with SHA-384.
	OIDSignatureAlgorithmECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}

	// OIDSignatureAlgorithmECDSAWithSHA512 identifies ECDSA with SHA-512.
	OIDSignatureAlgorithmECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// OIDSignatureAlgorithmEd25519 identifies the Ed25519 signature algorithm
	// as defined in RFC 8419. The parameters field MUST be absent.
	OIDSignatureAlgorithmEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// RSA-PSS support OIDs defined in RFC 4055.
var (
	// OIDMGF1 identifies the MGF1 mask generation function used in RSASSA-PSS.
	OIDMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// RFC 3161 Time-Stamp Protocol OIDs.
var (
	// OIDTSTInfo identifies the TSTInfo content type embedded in a timestamp token.
	OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// Key transport OIDs for EnvelopedData (RFC 3447 / RFC 4055).
var (
	// OIDKeyTransportRSAOAEP identifies the RSAES-OAEP key encryption algorithm.
	OIDKeyTransportRSAOAEP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
)

// Content encryption OIDs for EnvelopedData (RFC 3565 / NIST).
var (
	// OIDContentEncryptionAES128CBC identifies AES-128 in CBC mode.
	OIDContentEncryptionAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}

	// OIDContentEncryptionAES256CBC identifies AES-256 in CBC mode.
	OIDContentEncryptionAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	// OIDContentEncryptionAES128GCM identifies AES-128 in GCM mode.
	OIDContentEncryptionAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}

	// OIDContentEncryptionAES256GCM identifies AES-256 in GCM mode.
	OIDContentEncryptionAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

// Key wrap OIDs for EnvelopedData (RFC 3565).
var (
	// OIDKeyWrapAES128 identifies the AES-128 key wrap algorithm.
	OIDKeyWrapAES128 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 5}

	// OIDKeyWrapAES256 identifies the AES-256 key wrap algorithm.
	OIDKeyWrapAES256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}
)

// ECDH key agreement OIDs for EnvelopedData (RFC 5753).
var (
	// OIDKeyAgreeECDHSHA256 identifies the dhSinglePass-stdDH-sha256kdf-scheme.
	OIDKeyAgreeECDHSHA256 = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}

	// OIDKeyAgreeECDHSHA384 identifies the dhSinglePass-stdDH-sha384kdf-scheme.
	OIDKeyAgreeECDHSHA384 = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 2}

	// OIDKeyAgreeECDHSHA512 identifies the dhSinglePass-stdDH-sha512kdf-scheme.
	OIDKeyAgreeECDHSHA512 = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 3}
)

// EC public key OID (RFC 5480).
var (
	// OIDECPublicKey identifies the EC public key algorithm.
	OIDECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// HMAC algorithm OIDs for AuthenticatedData (RFC 3370 §3.1).
var (
	// OIDMACAlgorithmHMACSHA256 identifies HMAC with SHA-256.
	OIDMACAlgorithmHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

	// OIDMACAlgorithmHMACSHA384 identifies HMAC with SHA-384.
	OIDMACAlgorithmHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}

	// OIDMACAlgorithmHMACSHA512 identifies HMAC with SHA-512.
	OIDMACAlgorithmHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
)

// EC named curve OIDs (RFC 5480).
var (
	// OIDNamedCurveP256 identifies the P-256 elliptic curve.
	OIDNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}

	// OIDNamedCurveP384 identifies the P-384 elliptic curve.
	OIDNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}

	// OIDNamedCurveP521 identifies the P-521 elliptic curve.
	OIDNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)
