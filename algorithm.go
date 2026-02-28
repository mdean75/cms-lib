package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"

	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// signatureFamily groups signing algorithms into mutually exclusive families
// so that key-type and algorithm compatibility can be validated uniformly.
type signatureFamily int

const (
	familyRSAPKCS1 signatureFamily = iota
	familyRSAPSS
	familyECDSA
	familyEd25519
)

// allowedHashes is the set of digest algorithms accepted by this library.
// SHA-1, MD5, and all other deprecated algorithms are excluded.
var allowedHashes = map[crypto.Hash]bool{
	crypto.SHA256:     true,
	crypto.SHA384:     true,
	crypto.SHA512:     true,
	crypto.SHA3_256:   true,
	crypto.SHA3_384:   true,
	crypto.SHA3_512:   true,
}

// hashToOID maps a crypto.Hash to its digest algorithm OID.
// Only hashes in allowedHashes are mapped.
var hashToOID = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA256:   pkiasn1.OIDDigestAlgorithmSHA256,
	crypto.SHA384:   pkiasn1.OIDDigestAlgorithmSHA384,
	crypto.SHA512:   pkiasn1.OIDDigestAlgorithmSHA512,
	crypto.SHA3_256: pkiasn1.OIDDigestAlgorithmSHA3_256,
	crypto.SHA3_384: pkiasn1.OIDDigestAlgorithmSHA3_384,
	crypto.SHA3_512: pkiasn1.OIDDigestAlgorithmSHA3_512,
}

// oidToHash maps a digest algorithm OID back to a crypto.Hash for verification.
var oidToHash = map[string]crypto.Hash{
	pkiasn1.OIDDigestAlgorithmSHA256.String():   crypto.SHA256,
	pkiasn1.OIDDigestAlgorithmSHA384.String():   crypto.SHA384,
	pkiasn1.OIDDigestAlgorithmSHA512.String():   crypto.SHA512,
	pkiasn1.OIDDigestAlgorithmSHA3_256.String(): crypto.SHA3_256,
	pkiasn1.OIDDigestAlgorithmSHA3_384.String(): crypto.SHA3_384,
	pkiasn1.OIDDigestAlgorithmSHA3_512.String(): crypto.SHA3_512,
}

// digestAlgID returns the pkix.AlgorithmIdentifier for the given hash.
// The parameters field is omitted (NULL absent) per RFC 5754 for SHA-2 and
// RFC 8702 for SHA-3. Returns an error if h is not in the allow-list.
func digestAlgID(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	oid, ok := hashToOID[h]
	if !ok {
		return pkix.AlgorithmIdentifier{}, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("digest algorithm %v is not supported", h))
	}
	return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
}

// hashOIDAlgID returns an AlgorithmIdentifier for the given OID without
// additional parameters. Used for digest algorithms within RSA-PSS params.
func hashOIDAlgID(oid asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{Algorithm: oid}
}

// newHash returns a hash.Hash for the given crypto.Hash.
// Returns an error if h is not available or not in the allow-list.
func newHash(h crypto.Hash) (hash.Hash, error) {
	if !allowedHashes[h] {
		return nil, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("digest algorithm %v is not supported", h))
	}
	if !h.Available() {
		return nil, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("digest algorithm %v is not available in this build", h))
	}
	return h.New(), nil
}

// hashForKey returns the effective crypto.Hash for a given key type and the
// caller-requested hash. For Ed25519 the hash is forced to SHA-512 per RFC 8419
// regardless of what the caller specified. For ECDSA, when the hash was not
// explicitly chosen, the hash is auto-selected to match the curve's security
// level: P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512.
func hashForKey(key crypto.Signer, requested crypto.Hash, explicit bool) crypto.Hash {
	switch pub := key.Public().(type) {
	case ed25519.PublicKey:
		return crypto.SHA512
	case *ecdsa.PublicKey:
		if !explicit {
			return hashForCurve(pub)
		}
		return requested
	default:
		return requested
	}
}

// hashForCurve returns the digest algorithm that matches the ECDSA curve's
// security level: P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512.
// Falls back to SHA-256 for unrecognized curves.
func hashForCurve(pub *ecdsa.PublicKey) crypto.Hash {
	switch pub.Curve.Params().BitSize {
	case 384:
		return crypto.SHA384
	case 521:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// signatureAlgID returns the pkix.AlgorithmIdentifier for the signature algorithm
// appropriate for the given key and hash. For RSA-PSS the RSASSA-PSS-params
// structure is included. For Ed25519 the parameters field is absent per RFC 8419.
func signatureAlgID(key crypto.Signer, h crypto.Hash, family signatureFamily) (pkix.AlgorithmIdentifier, error) {
	switch family {
	case familyRSAPKCS1:
		return rsaPKCS1AlgID(h)
	case familyRSAPSS:
		return rsaPSSAlgID(h)
	case familyECDSA:
		return ecdsaAlgID(h)
	case familyEd25519:
		return pkix.AlgorithmIdentifier{Algorithm: pkiasn1.OIDSignatureAlgorithmEd25519}, nil
	default:
		return pkix.AlgorithmIdentifier{}, newError(CodeUnsupportedAlgorithm, "unknown signature algorithm family")
	}
}

// rsaPKCS1AlgID returns the AlgorithmIdentifier for RSA PKCS1v15 with the given hash.
func rsaPKCS1AlgID(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	var oid asn1.ObjectIdentifier
	switch h {
	case crypto.SHA256:
		oid = pkiasn1.OIDSignatureAlgorithmSHA256WithRSA
	case crypto.SHA384:
		oid = pkiasn1.OIDSignatureAlgorithmSHA384WithRSA
	case crypto.SHA512:
		oid = pkiasn1.OIDSignatureAlgorithmSHA512WithRSA
	default:
		return pkix.AlgorithmIdentifier{}, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("RSA PKCS1v15 does not support hash %v", h))
	}
	return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
}

// rsaPSSAlgID returns the AlgorithmIdentifier for RSASSA-PSS with the given hash.
// The RSASSA-PSS-params structure is always included per RFC 4056.
func rsaPSSAlgID(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	hashOID, ok := hashToOID[h]
	if !ok {
		return pkix.AlgorithmIdentifier{}, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("RSA-PSS does not support hash %v", h))
	}

	saltLen, err := saltLengthForHash(h)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}

	params := pkiasn1.RSAPSSParams{
		HashAlgorithm:    hashOIDAlgID(hashOID),
		MaskGenAlgorithm: mgf1AlgID(hashOID),
		SaltLength:       saltLen,
		TrailerField:     1,
	}

	rawParams, err := asn1.Marshal(params)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, wrapError(CodeParse,
			"failed to marshal RSA-PSS params", err)
	}

	return pkix.AlgorithmIdentifier{
		Algorithm:  pkiasn1.OIDSignatureAlgorithmRSAPSS,
		Parameters: asn1.RawValue{FullBytes: rawParams},
	}, nil
}

// mgf1AlgID returns the AlgorithmIdentifier for MGF1 using the given hash OID.
func mgf1AlgID(hashOID asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	// MGF1 params is an AlgorithmIdentifier for the hash
	innerParams, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: hashOID})
	return pkix.AlgorithmIdentifier{
		Algorithm:  pkiasn1.OIDMGF1,
		Parameters: asn1.RawValue{FullBytes: innerParams},
	}
}

// saltLengthForHash returns the salt length equal to the hash output length,
// which is the recommended practice for RSA-PSS.
func saltLengthForHash(h crypto.Hash) (int, error) {
	switch h {
	case crypto.SHA256:
		return sha256.Size, nil
	case crypto.SHA384:
		return sha512.Size384, nil
	case crypto.SHA512:
		return sha512.Size, nil
	default:
		return 0, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("no salt length defined for hash %v", h))
	}
}

// ecdsaAlgID returns the AlgorithmIdentifier for ECDSA with the given hash.
func ecdsaAlgID(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	var oid asn1.ObjectIdentifier
	switch h {
	case crypto.SHA256:
		oid = pkiasn1.OIDSignatureAlgorithmECDSAWithSHA256
	case crypto.SHA384:
		oid = pkiasn1.OIDSignatureAlgorithmECDSAWithSHA384
	case crypto.SHA512:
		oid = pkiasn1.OIDSignatureAlgorithmECDSAWithSHA512
	default:
		return pkix.AlgorithmIdentifier{}, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("ECDSA does not support hash %v", h))
	}
	return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
}

// detectFamily returns the signatureFamily for the public key type in key.
// Returns an error if the key type is unsupported.
func detectFamily(key crypto.Signer) (signatureFamily, error) {
	switch key.Public().(type) {
	case *rsa.PublicKey:
		// Default to RSA-PSS; callers may override to PKCS1v15 via option.
		// detectFamily is only used when no explicit family is provided.
		return familyRSAPSS, nil
	case *ecdsa.PublicKey:
		return familyECDSA, nil
	case ed25519.PublicKey:
		return familyEd25519, nil
	default:
		return 0, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported key type %T", key.Public()))
	}
}


// hashFromOID returns the crypto.Hash for the given digest algorithm OID.
// Returns an error if the OID is not in the allow-list.
func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	h, ok := oidToHash[oid.String()]
	if !ok {
		return 0, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unrecognized or unsupported digest algorithm OID %s", oid))
	}
	return h, nil
}
