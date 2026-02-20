package cms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"

	pkiasn1 "github.com/mdean75/cms/internal/asn1"
)

// CounterSigner appends a counter-signature to every SignerInfo in an existing
// CMS SignedData. A counter-signature signs the Signature bytes of the target
// SignerInfo (not the original content), as defined in RFC 5652, section 11.4.
// Builder methods accumulate configuration and errors; CounterSign reports all
// configuration errors at once.
type CounterSigner struct {
	cert           *x509.Certificate
	key            crypto.Signer
	hash           crypto.Hash
	family         signatureFamily
	familyExplicit bool
	sidType        SignerIdentifierType
	extraCerts     []*x509.Certificate
	errs           []error
}

// NewCounterSigner returns a new CounterSigner with default settings:
//   - SHA-256 digest
//   - IssuerAndSerialNumber signer identifier
func NewCounterSigner() *CounterSigner {
	return &CounterSigner{
		hash: crypto.SHA256,
	}
}

// WithCertificate sets the counter-signing certificate. Required.
func (cs *CounterSigner) WithCertificate(cert *x509.Certificate) *CounterSigner {
	if cert == nil {
		cs.errs = append(cs.errs, newConfigError("certificate is nil"))
		return cs
	}
	cs.cert = cert
	return cs
}

// WithPrivateKey sets the private key used for counter-signing. Required.
func (cs *CounterSigner) WithPrivateKey(key crypto.Signer) *CounterSigner {
	if key == nil {
		cs.errs = append(cs.errs, newConfigError("private key is nil"))
		return cs
	}
	cs.key = key
	return cs
}

// WithHash sets the digest algorithm. For Ed25519, this is ignored; SHA-512
// is always used per RFC 8419. Defaults to SHA-256.
func (cs *CounterSigner) WithHash(h crypto.Hash) *CounterSigner {
	cs.hash = h
	return cs
}

// WithRSAPKCS1 selects RSA PKCS1v15 as the signature algorithm. By default
// RSA keys use RSA-PSS. This option has no effect for non-RSA keys.
func (cs *CounterSigner) WithRSAPKCS1() *CounterSigner {
	cs.family = familyRSAPKCS1
	cs.familyExplicit = true
	return cs
}

// WithSignerIdentifier controls how the counter-signer's certificate is
// identified in its SignerInfo. Default is IssuerAndSerialNumber.
func (cs *CounterSigner) WithSignerIdentifier(t SignerIdentifierType) *CounterSigner {
	cs.sidType = t
	return cs
}

// AddCertificate adds an extra certificate to the SignedData CertificateSet.
func (cs *CounterSigner) AddCertificate(cert *x509.Certificate) *CounterSigner {
	if cert == nil {
		cs.errs = append(cs.errs, newConfigError("extra certificate is nil"))
		return cs
	}
	cs.extraCerts = append(cs.extraCerts, cert)
	return cs
}

// CounterSign reads a DER-encoded CMS ContentInfo from r, appends a counter-
// signature as an unsigned attribute (id-countersignature, OID 1.2.840.113549.1.9.6)
// on every SignerInfo, and returns the updated DER-encoded ContentInfo.
func (cs *CounterSigner) CounterSign(r io.Reader) ([]byte, error) {
	if err := cs.validate(); err != nil {
		return nil, err
	}

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

// validate checks that all required fields are set and no configuration errors
// accumulated.
func (cs *CounterSigner) validate() error {
	var errs []error
	errs = append(errs, cs.errs...)
	if cs.cert == nil && len(cs.errs) == 0 {
		errs = append(errs, newConfigError("certificate is required"))
	}
	if cs.key == nil && len(cs.errs) == 0 {
		errs = append(errs, newConfigError("private key is required"))
	}
	return joinErrors(errs)
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
