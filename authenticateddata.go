package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"

	pkiasn1 "github.com/mdean75/cms/internal/asn1"
)

// MACAlgorithm identifies the HMAC algorithm used in AuthenticatedData.
type MACAlgorithm int

const (
	// HMACSHA256 selects HMAC with SHA-256. This is the default.
	HMACSHA256 MACAlgorithm = iota
	// HMACSHA384 selects HMAC with SHA-384.
	HMACSHA384
	// HMACSHA512 selects HMAC with SHA-512.
	HMACSHA512
)

// Authenticator builds a CMS AuthenticatedData message using a fluent builder
// API. The MAC key is generated internally and distributed to recipients using
// the same RSA-OAEP / ECDH mechanisms as Encryptor. Builder methods accumulate
// configuration and errors; Authenticate reports all configuration errors at once.
// Authenticator methods are not safe for concurrent use; Authenticate is safe
// for concurrent use once the builder is fully configured.
type Authenticator struct {
	recipients  []*x509.Certificate
	macAlg      MACAlgorithm
	contentType asn1.ObjectIdentifier
	maxSize     int64
	errs        []error
}

// NewAuthenticator returns a new Authenticator with default settings:
//   - HMAC-SHA256 MAC algorithm
//   - id-data content type
//   - 64 MiB content size limit
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		macAlg:      HMACSHA256,
		contentType: pkiasn1.OIDData,
		maxSize:     DefaultMaxAttachedSize,
	}
}

// WithRecipient adds a recipient certificate for MAC key delivery. Auto-selects
// RSA-OAEP (RSA key) or ECDH ephemeral-static (EC key). At least one recipient
// is required.
func (a *Authenticator) WithRecipient(cert *x509.Certificate) *Authenticator {
	if cert == nil {
		a.errs = append(a.errs, newConfigError("recipient certificate is nil"))
		return a
	}
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		// supported
	default:
		a.errs = append(a.errs, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported recipient public key type %T", cert.PublicKey)))
		return a
	}
	a.recipients = append(a.recipients, cert)
	return a
}

// WithMACAlgorithm sets the HMAC algorithm. Defaults to HMACSHA256.
func (a *Authenticator) WithMACAlgorithm(alg MACAlgorithm) *Authenticator {
	a.macAlg = alg
	return a
}

// WithContentType sets a custom eContentType OID. Default is id-data.
func (a *Authenticator) WithContentType(oid asn1.ObjectIdentifier) *Authenticator {
	if len(oid) == 0 {
		a.errs = append(a.errs, newConfigError("content type OID is empty"))
		return a
	}
	a.contentType = oid
	return a
}

// WithMaxContentSize sets the maximum content size. Defaults to DefaultMaxAttachedSize.
func (a *Authenticator) WithMaxContentSize(maxBytes int64) *Authenticator {
	a.maxSize = maxBytes
	return a
}

// Authenticate reads content from r, generates a random MAC key, distributes
// it to all configured recipients, computes the HMAC, and returns the
// DER-encoded ContentInfo wrapping AuthenticatedData.
// All builder configuration errors are reported here.
func (a *Authenticator) Authenticate(r io.Reader) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}

	content, err := a.readContent(r)
	if err != nil {
		return nil, err
	}

	// Generate random MAC key.
	macKey := make([]byte, macKeyLenForAlg(a.macAlg))
	if _, err := rand.Read(macKey); err != nil {
		return nil, wrapError(CodeParse, "generating MAC key", err)
	}

	h := hashForMACAlg(a.macAlg)

	// Compute content digest for the message-digest authAttr.
	hw, err := newHash(h)
	if err != nil {
		return nil, err
	}
	hw.Write(content)
	digest := hw.Sum(nil)

	// Build and DER-encode authAttrs as a SET (0x31 tagged).
	attrs, err := buildMACAuthAttrs(digest, a.contentType)
	if err != nil {
		return nil, err
	}
	authAttrsBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	// HMAC is computed over the SET-tagged authAttrs bytes (RFC 5652 §9.2).
	mac, err := computeHMAC(macKey, authAttrsBytes, h)
	if err != nil {
		return nil, err
	}

	// Build EncapsulatedContentInfo with attached content.
	eci, err := buildAttachedECI(content, a.contentType)
	if err != nil {
		return nil, err
	}

	// Encrypt MAC key for each recipient.
	recipInfos, hasKARI, err := a.buildRecipientInfos(macKey)
	if err != nil {
		return nil, err
	}

	macAlgID, err := macAlgIDFromEnum(a.macAlg)
	if err != nil {
		return nil, err
	}
	digestAlg, err := digestAlgID(h)
	if err != nil {
		return nil, err
	}

	// Version rules per RFC 5652 §9.1.
	version := authenticatedDataVersion(hasKARI, a.contentType)

	ad := pkiasn1.AuthenticatedData{
		Version:          version,
		RecipientInfos:   recipInfos,
		MACAlgorithm:     macAlgID,
		DigestAlgorithm:  digestAlg,
		EncapContentInfo: eci,
		// Wire-encode authAttrs with [2] IMPLICIT tag (0xA2).
		AuthAttrs: asn1.RawValue{FullBytes: retagAsImplicit2(authAttrsBytes)},
		MAC:       mac,
	}

	return marshalAuthenticatedDataCI(ad)
}

// validate checks that all accumulated configuration errors are nil and that
// at least one recipient is configured.
func (a *Authenticator) validate() error {
	var errs []error
	errs = append(errs, a.errs...)
	if len(a.recipients) == 0 && len(a.errs) == 0 {
		errs = append(errs, newConfigError("at least one recipient is required"))
	}
	return joinErrors(errs)
}

// readContent reads all content from r, enforcing the size limit.
func (a *Authenticator) readContent(r io.Reader) ([]byte, error) {
	if a.maxSize == UnlimitedAttachedSize {
		return io.ReadAll(r)
	}
	lr := io.LimitReader(r, a.maxSize+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, wrapError(CodeParse, "reading content", err)
	}
	if int64(len(buf)) > a.maxSize {
		return nil, newError(CodePayloadTooLarge,
			fmt.Sprintf("content exceeds limit of %d bytes; increase limit with WithMaxContentSize", a.maxSize))
	}
	return buf, nil
}

// buildRecipientInfos encrypts macKey for all configured recipients and returns
// the encoded RecipientInfo slice and whether any KARI was produced.
func (a *Authenticator) buildRecipientInfos(macKey []byte) ([]asn1.RawValue, bool, error) {
	var recipInfos []asn1.RawValue
	hasKARI := false
	for _, cert := range a.recipients {
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
			ri, err := buildRSARecipientInfo(cert, macKey)
			if err != nil {
				return nil, false, err
			}
			recipInfos = append(recipInfos, ri)
		case *ecdsa.PublicKey:
			ri, err := buildECDHRecipientInfo(cert, macKey)
			if err != nil {
				return nil, false, err
			}
			recipInfos = append(recipInfos, ri)
			hasKARI = true
		}
	}
	return recipInfos, hasKARI, nil
}

// ParsedAuthenticatedData wraps a parsed AuthenticatedData for verification.
type ParsedAuthenticatedData struct {
	authenticatedData pkiasn1.AuthenticatedData
}

// ParseAuthenticatedData parses a DER-encoded CMS ContentInfo wrapping
// AuthenticatedData.
func ParseAuthenticatedData(r io.Reader) (*ParsedAuthenticatedData, error) {
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapError(CodeParse, "reading AuthenticatedData input", err)
	}

	var ci pkiasn1.ContentInfo
	rest, err := asn1.Unmarshal(input, &ci)
	if err != nil {
		return nil, wrapError(CodeParse, "parsing ContentInfo", err)
	}
	if len(rest) > 0 {
		return nil, newError(CodeParse, "trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(pkiasn1.OIDAuthenticatedData) {
		return nil, newError(CodeParse,
			fmt.Sprintf("expected AuthenticatedData content type OID %s, got %s",
				pkiasn1.OIDAuthenticatedData, ci.ContentType))
	}

	// ci.Content.Bytes holds the inner bytes of the [0] EXPLICIT wrapper.
	var ad pkiasn1.AuthenticatedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ad); err != nil {
		return nil, wrapError(CodeParse, "parsing AuthenticatedData structure", err)
	}

	return &ParsedAuthenticatedData{authenticatedData: ad}, nil
}

// Content returns an io.Reader over the plaintext encapsulated content.
func (p *ParsedAuthenticatedData) Content() (io.Reader, error) {
	raw := p.authenticatedData.EncapContentInfo.EContent
	if len(raw.FullBytes) == 0 {
		return nil, newError(CodeParse, "AuthenticatedData has no encapsulated content")
	}
	// EContent is [0] EXPLICIT OCTET STRING. raw.Bytes contains the OCTET STRING TLV.
	var octetString []byte
	if _, err := asn1.Unmarshal(raw.Bytes, &octetString); err != nil {
		return nil, wrapError(CodeParse, "parsing eContent OCTET STRING", err)
	}
	return bytes.NewReader(octetString), nil
}

// VerifyMAC decrypts the MAC key using the provided private key and certificate,
// then verifies the HMAC against the encapsulated content. Returns
// ErrMissingCertificate if no matching RecipientInfo is found.
func (p *ParsedAuthenticatedData) VerifyMAC(key crypto.PrivateKey, cert *x509.Certificate) error {
	macKey, err := p.decryptMACKey(key, cert)
	if err != nil {
		return err
	}

	h, err := hmacOIDToHash(p.authenticatedData.MACAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	authAttrsWire := p.authenticatedData.AuthAttrs
	if len(authAttrsWire.FullBytes) == 0 {
		return newError(CodeAttributeInvalid, "AuthAttrs is absent; cannot verify MAC")
	}

	// Retag [2] IMPLICIT (0xA2) → SET (0x31) for HMAC computation.
	setBytes := retagAsSet(authAttrsWire.FullBytes)

	expectedMAC, err := computeHMAC(macKey, setBytes, h)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expectedMAC, p.authenticatedData.MAC) != 1 {
		return newError(CodeInvalidSignature, "AuthenticatedData MAC verification failed")
	}

	// Verify authAttrs: content-type and message-digest.
	contentBytes, err := p.extractContentBytes()
	if err != nil {
		return err
	}

	hw, err := newHash(h)
	if err != nil {
		return err
	}
	hw.Write(contentBytes)
	computed := hw.Sum(nil)

	return validateSignedAttrs(setBytes, computed,
		p.authenticatedData.EncapContentInfo.EContentType)
}

// decryptMACKey iterates RecipientInfos and decrypts the MAC key for the
// matching recipient.
func (p *ParsedAuthenticatedData) decryptMACKey(key crypto.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	for _, ri := range p.authenticatedData.RecipientInfos {
		if len(ri.FullBytes) == 0 {
			continue
		}
		tag := ri.FullBytes[0]
		switch tag {
		case 0x30:
			mk, err := tryDecryptKTRI(ri, key, cert)
			if err != nil || mk != nil {
				return mk, err
			}
		case 0xA1:
			mk, err := tryDecryptKARI(ri, key, cert)
			if err != nil || mk != nil {
				return mk, err
			}
		}
	}
	return nil, newError(CodeMissingCertificate,
		"no RecipientInfo found matching the provided certificate")
}

// extractContentBytes returns the raw content bytes from EncapContentInfo.
func (p *ParsedAuthenticatedData) extractContentBytes() ([]byte, error) {
	r, err := p.Content()
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// --- Internal helpers ---

// authenticatedDataVersion returns the AuthenticatedData version per RFC 5652 §9.1.
func authenticatedDataVersion(hasKARI bool, contentType asn1.ObjectIdentifier) int {
	if hasKARI {
		return 2
	}
	if !contentType.Equal(pkiasn1.OIDData) {
		return 1
	}
	return 0
}

// macKeyLenForAlg returns the MAC key byte length for alg.
// Key length equals the hash output size per SP 800-107 guidance.
func macKeyLenForAlg(alg MACAlgorithm) int {
	switch alg {
	case HMACSHA384:
		return 48
	case HMACSHA512:
		return 64
	default: // HMACSHA256
		return 32
	}
}

// hashForMACAlg returns the crypto.Hash for the given MACAlgorithm.
func hashForMACAlg(alg MACAlgorithm) crypto.Hash {
	switch alg {
	case HMACSHA384:
		return crypto.SHA384
	case HMACSHA512:
		return crypto.SHA512
	default: // HMACSHA256
		return crypto.SHA256
	}
}

// macAlgIDFromEnum returns the pkix.AlgorithmIdentifier for alg.
func macAlgIDFromEnum(alg MACAlgorithm) (pkix.AlgorithmIdentifier, error) {
	switch alg {
	case HMACSHA256:
		return pkix.AlgorithmIdentifier{Algorithm: pkiasn1.OIDMACAlgorithmHMACSHA256}, nil
	case HMACSHA384:
		return pkix.AlgorithmIdentifier{Algorithm: pkiasn1.OIDMACAlgorithmHMACSHA384}, nil
	case HMACSHA512:
		return pkix.AlgorithmIdentifier{Algorithm: pkiasn1.OIDMACAlgorithmHMACSHA512}, nil
	default:
		return pkix.AlgorithmIdentifier{}, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unknown MAC algorithm %d", alg))
	}
}

// hmacOIDToHash maps a MAC algorithm OID to a crypto.Hash.
func hmacOIDToHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(pkiasn1.OIDMACAlgorithmHMACSHA256):
		return crypto.SHA256, nil
	case oid.Equal(pkiasn1.OIDMACAlgorithmHMACSHA384):
		return crypto.SHA384, nil
	case oid.Equal(pkiasn1.OIDMACAlgorithmHMACSHA512):
		return crypto.SHA512, nil
	default:
		return 0, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unrecognized MAC algorithm OID %s", oid))
	}
}

// computeHMAC computes HMAC-h over data using key.
func computeHMAC(key, data []byte, h crypto.Hash) ([]byte, error) {
	if _, err := newHash(h); err != nil {
		return nil, err
	}
	mac := hmac.New(h.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// buildMACAuthAttrs returns the mandatory authenticated attributes for
// AuthenticatedData: content-type and message-digest.
func buildMACAuthAttrs(digest []byte, contentType asn1.ObjectIdentifier) ([]pkiasn1.Attribute, error) {
	ctVal, err := asn1.Marshal(contentType)
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

// buildAttachedECI constructs an EncapsulatedContentInfo with attached content.
func buildAttachedECI(content []byte, contentType asn1.ObjectIdentifier) (pkiasn1.EncapsulatedContentInfo, error) {
	octetString, err := asn1.Marshal(content)
	if err != nil {
		return pkiasn1.EncapsulatedContentInfo{}, wrapError(CodeParse, "marshal eContent OCTET STRING", err)
	}
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      octetString,
	})
	if err != nil {
		return pkiasn1.EncapsulatedContentInfo{}, wrapError(CodeParse, "marshal eContent [0] wrapper", err)
	}
	return pkiasn1.EncapsulatedContentInfo{
		EContentType: contentType,
		EContent:     asn1.RawValue{FullBytes: explicit0},
	}, nil
}

// retagAsImplicit2 replaces the outermost SET tag (0x31) with IMPLICIT [2]
// CONSTRUCTED (0xA2) for wire encoding of AuthAttrs.
func retagAsImplicit2(setBytes []byte) []byte {
	if len(setBytes) == 0 {
		return setBytes
	}
	out := make([]byte, len(setBytes))
	copy(out, setBytes)
	out[0] = 0xA2
	return out
}

// marshalAuthenticatedDataCI wraps AuthenticatedData in a ContentInfo and
// returns DER bytes.
func marshalAuthenticatedDataCI(ad pkiasn1.AuthenticatedData) ([]byte, error) {
	adBytes, err := asn1.Marshal(ad)
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling AuthenticatedData", err)
	}
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      adBytes,
	})
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling ContentInfo [0] wrapper for AuthenticatedData", err)
	}
	ci := pkiasn1.ContentInfo{
		ContentType: pkiasn1.OIDAuthenticatedData,
		Content:     asn1.RawValue{FullBytes: explicit0},
	}
	return asn1.Marshal(ci)
}
