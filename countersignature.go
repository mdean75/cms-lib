package cms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"

	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// CounterSigner appends a counter-signature to every SignerInfo in an existing
// CMS SignedData. A counter-signature signs the Signature bytes of the target
// SignerInfo (not the original content), as defined in RFC 5652, section 11.4.
// Construct it with NewCounterSigner; CounterSign is safe for concurrent use
// once constructed.
type CounterSigner struct {
	cert           *x509.Certificate
	key            crypto.Signer
	hash           crypto.Hash
	family         signatureFamily
	familyExplicit bool
	sidType        SignerIdentifierType
	extraCerts     []*x509.Certificate
}

// NewCounterSigner constructs a CounterSigner with the given certificate and
// private key. Defaults: SHA-256 digest, IssuerAndSerialNumber signer identifier.
// All configuration errors (nil cert, nil key, invalid options) are reported
// together. CounterSign is safe for concurrent use once NewCounterSigner returns
// successfully.
func NewCounterSigner(cert *x509.Certificate, key crypto.Signer, opts ...SigningOption) (*CounterSigner, error) {
	var errs []error
	if cert == nil {
		errs = append(errs, newConfigError("certificate is nil"))
	}
	if key == nil {
		errs = append(errs, newConfigError("private key is nil"))
	}

	cs := &CounterSigner{
		cert: cert,
		key:  key,
		hash: crypto.SHA256,
	}

	for _, opt := range opts {
		if err := opt.applyToCounterSigner(cs); err != nil {
			errs = append(errs, err)
		}
	}

	if err := joinErrors(errs); err != nil {
		return nil, err
	}
	return cs, nil
}

// CounterSign reads a DER-encoded CMS ContentInfo from r, appends a counter-
// signature as an unsigned attribute (id-countersignature, OID 1.2.840.113549.1.9.6)
// on every SignerInfo, and returns the updated DER-encoded ContentInfo.
func (cs *CounterSigner) CounterSign(r io.Reader) ([]byte, error) {
	// Parse the existing SignedData.
	psd, err := ParseSignedData(r)
	if err != nil {
		return nil, err
	}

	sd := psd.signedData

	// Build a counter-signature for each target SignerInfo.
	for i, targetSI := range sd.SignerInfos {
		counterSI, csErr := cs.buildCounterSigFor(targetSI)
		if csErr != nil {
			return nil, wrapError(CodeCounterSignature,
				fmt.Sprintf("building counter-signature for SignerInfo[%d]", i), csErr)
		}

		// Marshal the counter-signature SignerInfo as a DER value.
		siBytes, marshalErr := asn1.Marshal(counterSI)
		if marshalErr != nil {
			return nil, wrapError(CodeParse, "marshal counter-signature SignerInfo", marshalErr)
		}

		// Add as unsigned attribute, merging with any existing unsigned attrs.
		merged, mergeErr := mergeUnsignedAttr(
			sd.SignerInfos[i].UnsignedAttrs,
			pkiasn1.OIDAttributeCounterSign,
			siBytes,
		)
		if mergeErr != nil {
			return nil, mergeErr
		}
		sd.SignerInfos[i].UnsignedAttrs = merged
	}

	// Add the counter-signer's certificate (and any extra certs) to the set.
	allNewCerts := append([]*x509.Certificate{cs.cert}, cs.extraCerts...)
	for _, cert := range allNewCerts {
		k := string(cert.Raw)
		alreadyPresent := false
		for _, existing := range psd.certs {
			if string(existing.Raw) == k {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			sd.Certificates = append(sd.Certificates, asn1.RawValue{FullBytes: cert.Raw})
		}
	}

	return marshalContentInfo(sd)
}

// buildCounterSigFor constructs the SignerInfo that counter-signs targetSI.
// The counter-signature signs targetSI.Signature with signed attributes where
// content-type is id-data and message-digest is hash(targetSI.Signature).
func (cs *CounterSigner) buildCounterSigFor(targetSI pkiasn1.SignerInfo) (pkiasn1.SignerInfo, error) {
	effectiveHash := hashForKey(cs.key, cs.hash)

	family := cs.family
	if !cs.familyExplicit {
		var err error
		family, err = detectFamily(cs.key)
		if err != nil {
			return pkiasn1.SignerInfo{}, err
		}
	}

	// Compute digest over the target SignerInfo's Signature bytes.
	h, err := newHash(effectiveHash)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}
	h.Write(targetSI.Signature)
	digest := h.Sum(nil)

	// Build signedAttrs; content-type is id-data per RFC 5652 §11.4.
	signedAttrs, err := cs.buildCounterSignedAttrs(digest)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	signedAttrsBytes, err := marshalAttributes(signedAttrs)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	// Compute digest over signedAttrs for signature input.
	h2, err := newHash(effectiveHash)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}
	h2.Write(signedAttrsBytes)
	signedAttrsDigest := h2.Sum(nil)

	// Produce the cryptographic signature.
	sig, err := cs.sign(signedAttrsDigest, effectiveHash, family)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	return cs.buildSignerInfo(effectiveHash, family, signedAttrsBytes, sig)
}

// buildCounterSignedAttrs returns the mandatory signed attributes for a counter-
// signature: content-type (always id-data) and message-digest.
func (cs *CounterSigner) buildCounterSignedAttrs(digest []byte) ([]pkiasn1.Attribute, error) {
	ctVal, err := asn1.Marshal(pkiasn1.OIDData)
	if err != nil {
		return nil, wrapError(CodeParse, "marshal content-type attribute", err)
	}
	mdVal, err := asn1.Marshal(digest)
	if err != nil {
		return nil, wrapError(CodeParse, "marshal message-digest attribute", err)
	}
	return []pkiasn1.Attribute{
		{
			Type:   pkiasn1.OIDAttributeContentType,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(ctVal)},
		},
		{
			Type:   pkiasn1.OIDAttributeMessageDigest,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(mdVal)},
		},
	}, nil
}

// sign computes the cryptographic signature for the counter-signer.
func (cs *CounterSigner) sign(digest []byte, h crypto.Hash, family signatureFamily) ([]byte, error) {
	switch family {
	case familyRSAPKCS1:
		return cs.key.Sign(rand.Reader, digest, h)

	case familyRSAPSS:
		saltSize, err := saltLengthForHash(h)
		if err != nil {
			return nil, err
		}
		return cs.key.Sign(rand.Reader, digest, &rsa.PSSOptions{
			SaltLength: saltSize,
			Hash:       h,
		})

	case familyECDSA:
		sig, err := cs.key.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, wrapError(CodeInvalidSignature, "ECDSA counter-signing failed", err)
		}
		return sig, nil

	case familyEd25519:
		sig, err := cs.key.Sign(rand.Reader, digest, crypto.Hash(0))
		if err != nil {
			return nil, wrapError(CodeInvalidSignature, "Ed25519 counter-signing failed", err)
		}
		return sig, nil

	default:
		return nil, newError(CodeUnsupportedAlgorithm, "unknown signature family")
	}
}

// buildSignerInfo assembles the SignerInfo for the counter-signature.
func (cs *CounterSigner) buildSignerInfo(h crypto.Hash, family signatureFamily, signedAttrsBytes, sig []byte) (pkiasn1.SignerInfo, error) {
	digestAlg, err := digestAlgID(h)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	sigAlg, err := signatureAlgID(cs.key, h, family)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	sid, version, err := buildSignerID(cs.cert, cs.sidType)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	return pkiasn1.SignerInfo{
		Version:            version,
		SID:                sid,
		DigestAlgorithm:    digestAlg,
		SignedAttrs:        asn1.RawValue{FullBytes: retagAsImplicit0(signedAttrsBytes)},
		SignatureAlgorithm: sigAlg,
		Signature:          sig,
	}, nil
}

// mergeUnsignedAttr adds attrType=valBytes as a new unsigned attribute, merging
// with any existing unsigned attributes in existing. Returns the updated [1]
// IMPLICIT encoded bytes.
func mergeUnsignedAttr(existing asn1.RawValue, attrType asn1.ObjectIdentifier, valBytes []byte) (asn1.RawValue, error) {
	newAttr := pkiasn1.Attribute{
		Type:   attrType,
		Values: asn1.RawValue{FullBytes: mustMarshalSet(valBytes)},
	}

	var attrs pkiasn1.RawAttributes

	if len(existing.FullBytes) > 0 {
		// Retag [1] IMPLICIT (0xA1) → SET (0x31) for parsing.
		setBytes := make([]byte, len(existing.FullBytes))
		copy(setBytes, existing.FullBytes)
		setBytes[0] = setTagByte

		if _, err := asn1.UnmarshalWithParams(setBytes, &attrs, "set"); err != nil {
			return asn1.RawValue{}, wrapError(CodeParse, "parsing existing unsigned attributes", err)
		}
	}

	attrs = append(attrs, newAttr)

	encoded, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeParse, "marshal updated unsigned attributes", err)
	}

	return asn1.RawValue{FullBytes: retagAsImplicit1(encoded)}, nil
}
