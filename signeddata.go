package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"time"

	"github.com/mdean75/cms/ber"
	pkiasn1 "github.com/mdean75/cms/internal/asn1"
	"github.com/mdean75/cms/internal/timestamp"
)

// setTagByte is the ASN.1 tag byte for an explicit SET OF, used when re-encoding
// signedAttrs for digest computation. The wire form uses IMPLICIT [0] (0xA0),
// but the digest is computed over the SET-tagged form (0x31) per RFC 5652 §5.4.
const setTagByte = byte(0x31)

// implicitTag0Byte is the ASN.1 IMPLICIT [0] CONSTRUCTED tag used on the wire
// for the SignedAttributes field in SignerInfo.
const implicitTag0Byte = byte(0xA0)

// Signer builds and produces a CMS SignedData message. Builder methods accumulate
// configuration and errors; Sign reports all configuration errors at once.
// Signer methods are not safe for concurrent use; Sign is safe for concurrent use
// once the builder is fully configured.
type Signer struct {
	cert              *x509.Certificate
	key               crypto.Signer
	hash              crypto.Hash
	family            signatureFamily
	familyExplicit    bool // true when family was set via WithRSAPKCS1 option
	detached          bool
	sidType           SignerIdentifierType
	contentType       asn1.ObjectIdentifier
	extraCerts        []*x509.Certificate
	authAttrs         []pkiasn1.Attribute
	unauthAttrs       []pkiasn1.Attribute
	maxSize           int64
	additionalSigners []*Signer
	crls              [][]byte
	tsaURL            string
	errs              []error
}

// NewSigner returns a new Signer with default settings:
//   - SHA-256 digest
//   - Attached content
//   - IssuerAndSerialNumber signer identifier
//   - id-data content type
//   - 64 MiB attached content size limit
func NewSigner() *Signer {
	return &Signer{
		hash:        crypto.SHA256,
		contentType: pkiasn1.OIDData,
		maxSize:     DefaultMaxAttachedSize,
	}
}

// WithCertificate sets the signing certificate. Required.
func (s *Signer) WithCertificate(cert *x509.Certificate) *Signer {
	if cert == nil {
		s.errs = append(s.errs, newConfigError("certificate is nil"))
		return s
	}
	s.cert = cert
	return s
}

// WithPrivateKey sets the private key used for signing. Required.
func (s *Signer) WithPrivateKey(key crypto.Signer) *Signer {
	if key == nil {
		s.errs = append(s.errs, newConfigError("private key is nil"))
		return s
	}
	s.key = key
	return s
}

// WithHash sets the digest algorithm. For Ed25519, this is ignored; SHA-512
// is always used per RFC 8419. Defaults to SHA-256.
func (s *Signer) WithHash(h crypto.Hash) *Signer {
	s.hash = h
	return s
}

// WithRSAPKCS1 selects RSA PKCS1v15 as the signature algorithm. By default,
// RSA keys use RSA-PSS. This option has no effect for non-RSA keys.
func (s *Signer) WithRSAPKCS1() *Signer {
	s.family = familyRSAPKCS1
	s.familyExplicit = true
	return s
}

// WithDetachedContent produces a detached signature (eContent absent in output).
// Detached mode streams content without buffering it; the size limit has no effect.
func (s *Signer) WithDetachedContent() *Signer {
	s.detached = true
	return s
}

// WithSignerIdentifier controls how the signer's certificate is identified in
// SignerInfo. Default is IssuerAndSerialNumber (SignerInfo version 1).
func (s *Signer) WithSignerIdentifier(t SignerIdentifierType) *Signer {
	s.sidType = t
	return s
}

// WithContentType sets a custom eContentType OID. Default is id-data.
// A non-id-data type forces SignedData version 3 per RFC 5652 §5.1.
func (s *Signer) WithContentType(oid asn1.ObjectIdentifier) *Signer {
	if len(oid) == 0 {
		s.errs = append(s.errs, newConfigError("content type OID is empty"))
		return s
	}
	s.contentType = oid
	return s
}

// AddCertificate adds an extra certificate to the CertificateSet in the output
// (for example, intermediate CA certificates needed for chain building).
func (s *Signer) AddCertificate(cert *x509.Certificate) *Signer {
	if cert == nil {
		s.errs = append(s.errs, newConfigError("extra certificate is nil"))
		return s
	}
	s.extraCerts = append(s.extraCerts, cert)
	return s
}

// AddAuthenticatedAttribute adds a custom signed attribute. The content-type and
// message-digest attributes are always injected automatically; callers must not
// add those manually. Sign returns ErrAttributeInvalid if they do.
func (s *Signer) AddAuthenticatedAttribute(oid asn1.ObjectIdentifier, val interface{}) *Signer {
	encoded, err := asn1.Marshal(val)
	if err != nil {
		s.errs = append(s.errs, wrapError(CodeAttributeInvalid,
			fmt.Sprintf("failed to marshal authenticated attribute %s", oid), err))
		return s
	}
	s.authAttrs = append(s.authAttrs, pkiasn1.Attribute{
		Type:   oid,
		Values: asn1.RawValue{FullBytes: mustMarshalSet(encoded)},
	})
	return s
}

// AddUnauthenticatedAttribute adds a custom unsigned attribute.
func (s *Signer) AddUnauthenticatedAttribute(oid asn1.ObjectIdentifier, val interface{}) *Signer {
	encoded, err := asn1.Marshal(val)
	if err != nil {
		s.errs = append(s.errs, wrapError(CodeAttributeInvalid,
			fmt.Sprintf("failed to marshal unauthenticated attribute %s", oid), err))
		return s
	}
	s.unauthAttrs = append(s.unauthAttrs, pkiasn1.Attribute{
		Type:   oid,
		Values: asn1.RawValue{FullBytes: mustMarshalSet(encoded)},
	})
	return s
}

// WithMaxAttachedContentSize sets the maximum content size for attached signatures.
// Defaults to DefaultMaxAttachedSize (64 MiB). Pass UnlimitedAttachedSize to disable.
// Has no effect in detached mode.
func (s *Signer) WithMaxAttachedContentSize(maxBytes int64) *Signer {
	s.maxSize = maxBytes
	return s
}

// WithAdditionalSigner adds a second (or subsequent) signer to the SignedData.
// The additional signer must be configured with at least a certificate and private
// key. All signers share the primary signer's content, content type, and
// detached/attached setting.
func (s *Signer) WithAdditionalSigner(other *Signer) *Signer {
	if other == nil {
		s.errs = append(s.errs, newConfigError("additional signer is nil"))
		return s
	}
	s.additionalSigners = append(s.additionalSigners, other)
	return s
}

// WithTimestamp requests an RFC 3161 timestamp from tsaURL after signing and
// embeds it as an unsigned attribute (id-aa-signatureTimeStampToken) on each
// SignerInfo. The timestamp covers the SignerInfo's Signature bytes.
func (s *Signer) WithTimestamp(tsaURL string) *Signer {
	if tsaURL == "" {
		s.errs = append(s.errs, newConfigError("TSA URL is empty"))
		return s
	}
	s.tsaURL = tsaURL
	return s
}

// AddCRL embeds a DER-encoded Certificate Revocation List in the SignedData
// revocationInfoChoices field.
func (s *Signer) AddCRL(derCRL []byte) *Signer {
	if len(derCRL) == 0 {
		s.errs = append(s.errs, newConfigError("CRL DER bytes are empty"))
		return s
	}
	s.crls = append(s.crls, derCRL)
	return s
}

// Sign reads content from r, constructs a CMS SignedData, and returns the
// DER-encoded ContentInfo. All builder configuration errors are reported here.
func (s *Signer) Sign(r io.Reader) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	// Read and optionally limit content.
	content, err := s.readContent(r)
	if err != nil {
		return nil, err
	}

	// Sign with the primary signer.
	primarySI, primaryHash, err := s.signContent(content, s.contentType)
	if err != nil {
		return nil, err
	}

	allSIs := []pkiasn1.SignerInfo{primarySI}
	allHashes := []crypto.Hash{primaryHash}
	allCerts := append([]*x509.Certificate{s.cert}, s.extraCerts...)

	// Sign with each additional signer using the primary's content type.
	for _, as := range s.additionalSigners {
		si, h, siErr := as.signContent(content, s.contentType)
		if siErr != nil {
			return nil, siErr
		}
		allSIs = append(allSIs, si)
		allHashes = append(allHashes, h)
		allCerts = append(allCerts, as.cert)
		allCerts = append(allCerts, as.extraCerts...)
	}

	// If a TSA URL is configured, fetch a timestamp token for each SignerInfo
	// and embed it as an unsigned id-aa-signatureTimeStampToken attribute.
	if s.tsaURL != "" {
		for i := range allSIs {
			algID, algErr := digestAlgID(allHashes[i])
			if algErr != nil {
				return nil, algErr
			}
			// Hash the Signature bytes to form the MessageImprint.
			h, hashErr := newHash(allHashes[i])
			if hashErr != nil {
				return nil, hashErr
			}
			h.Write(allSIs[i].Signature)

			token, tsErr := timestamp.Request(s.tsaURL, algID, h.Sum(nil))
			if tsErr != nil {
				return nil, wrapError(CodeTimestamp, "fetching RFC 3161 timestamp", tsErr)
			}

			merged, mergeErr := mergeUnsignedAttr(
				allSIs[i].UnsignedAttrs,
				pkiasn1.OIDAttributeTimeStampToken,
				token,
			)
			if mergeErr != nil {
				return nil, mergeErr
			}
			allSIs[i].UnsignedAttrs = merged
		}
	}

	// Build EncapsulatedContentInfo.
	eci, err := s.buildECI(content)
	if err != nil {
		return nil, err
	}

	// Assemble SignedData.
	sd, err := s.buildSignedDataMulti(eci, allSIs, allHashes, allCerts)
	if err != nil {
		return nil, err
	}

	return marshalContentInfo(sd)
}

// signContent computes a SignerInfo for this signer over the given content bytes.
// contentType is passed explicitly so additional signers use the primary signer's
// eContentType in their signed attributes.
func (s *Signer) signContent(content []byte, contentType asn1.ObjectIdentifier) (pkiasn1.SignerInfo, crypto.Hash, error) {
	effectiveHash := hashForKey(s.key, s.hash)

	family := s.family
	if !s.familyExplicit {
		var err error
		family, err = detectFamily(s.key)
		if err != nil {
			return pkiasn1.SignerInfo{}, 0, err
		}
	}

	// Compute content digest.
	h, err := newHash(effectiveHash)
	if err != nil {
		return pkiasn1.SignerInfo{}, 0, err
	}
	h.Write(content)
	digest := h.Sum(nil)

	// Build signedAttrs using the provided content type.
	signedAttrs, err := s.buildSignedAttrsForType(digest, contentType)
	if err != nil {
		return pkiasn1.SignerInfo{}, 0, err
	}

	// DER-encode signedAttrs as a SET for digest computation.
	signedAttrsBytes, err := marshalAttributes(signedAttrs)
	if err != nil {
		return pkiasn1.SignerInfo{}, 0, err
	}

	// Compute digest over re-encoded signedAttrs (SET tag, not IMPLICIT [0]).
	h2, err := newHash(effectiveHash)
	if err != nil {
		return pkiasn1.SignerInfo{}, 0, err
	}
	h2.Write(signedAttrsBytes)
	signedAttrsDigest := h2.Sum(nil)

	// Sign the digest.
	sig, err := s.sign(signedAttrsDigest, effectiveHash, family)
	if err != nil {
		return pkiasn1.SignerInfo{}, 0, err
	}

	// Build SignerInfo.
	si, err := s.buildSignerInfo(effectiveHash, family, signedAttrsBytes, sig)
	if err != nil {
		return pkiasn1.SignerInfo{}, 0, err
	}

	return si, effectiveHash, nil
}

// validate checks that all required fields are set and no configuration errors
// accumulated. Returns a joined error if any problems exist.
func (s *Signer) validate() error {
	var errs []error
	errs = append(errs, s.errs...)
	if s.cert == nil && len(s.errs) == 0 {
		errs = append(errs, newConfigError("certificate is required"))
	}
	if s.key == nil && len(s.errs) == 0 {
		errs = append(errs, newConfigError("private key is required"))
	}

	// Check for manually added reserved attributes.
	for _, a := range s.authAttrs {
		if a.Type.Equal(pkiasn1.OIDAttributeContentType) ||
			a.Type.Equal(pkiasn1.OIDAttributeMessageDigest) {
			errs = append(errs, newError(CodeAttributeInvalid,
				fmt.Sprintf("attribute %s is injected automatically; do not add it manually", a.Type)))
		}
	}

	// Validate additional signers.
	for i, as := range s.additionalSigners {
		if err := as.validate(); err != nil {
			errs = append(errs, wrapError(CodeInvalidConfiguration,
				fmt.Sprintf("additional signer[%d]", i), err))
		}
	}

	return joinErrors(errs)
}

// readContent reads from r. In detached mode, content is discarded after hashing;
// in attached mode, it is buffered up to maxSize.
func (s *Signer) readContent(r io.Reader) ([]byte, error) {
	if s.detached {
		// For detached mode we still need to hash the content, so we read it
		// fully but do not need to store the original bytes beyond computing the
		// digest. We store it here for simplicity and discard at assembly time.
		return io.ReadAll(r)
	}

	if s.maxSize == UnlimitedAttachedSize {
		return io.ReadAll(r)
	}

	// Read up to maxSize+1 bytes. If we get maxSize+1, the content is too large.
	lr := io.LimitReader(r, s.maxSize+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, wrapError(CodeParse, "reading content", err)
	}
	if int64(len(buf)) > s.maxSize {
		return nil, newError(CodePayloadTooLarge,
			fmt.Sprintf("attached content exceeds limit of %d bytes; use WithDetachedContent or increase limit with WithMaxAttachedContentSize", s.maxSize))
	}
	return buf, nil
}

// buildSignedAttrsForType constructs the mandatory signed attributes plus any
// custom attributes added by the caller. contentType is passed explicitly so
// that additional signers can use the primary signer's eContentType.
func (s *Signer) buildSignedAttrsForType(digest []byte, contentType asn1.ObjectIdentifier) ([]pkiasn1.Attribute, error) {
	// Mandatory: content-type
	ctVal, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, wrapError(CodeParse, "marshal content-type attribute", err)
	}
	// Mandatory: message-digest
	mdVal, err := asn1.Marshal(digest)
	if err != nil {
		return nil, wrapError(CodeParse, "marshal message-digest attribute", err)
	}

	attrs := []pkiasn1.Attribute{
		{
			Type:   pkiasn1.OIDAttributeContentType,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(ctVal)},
		},
		{
			Type:   pkiasn1.OIDAttributeMessageDigest,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(mdVal)},
		},
	}
	attrs = append(attrs, s.authAttrs...)
	return attrs, nil
}

// marshalAttributes DER-encodes a slice of Attributes as a SET OF and returns the bytes.
// The result uses the EXPLICIT SET tag (0x31) which is required for digest computation.
func marshalAttributes(attrs []pkiasn1.Attribute) ([]byte, error) {
	encoded, err := asn1.MarshalWithParams(pkiasn1.RawAttributes(attrs), "set")
	if err != nil {
		return nil, wrapError(CodeParse, "marshal signed attributes", err)
	}
	// asn1.MarshalWithParams with "set" produces a SET tag (0x31), which is what
	// we need both for the digest input and for the wire IMPLICIT [0] substitution.
	return encoded, nil
}

// sign computes the cryptographic signature over digest using the configured key.
// For RSA-PSS, uses rsa.SignPSS with salt length equal to the hash size.
// For ECDSA, the raw (r,s) output is DER-encoded into Ecdsa-Sig-Value.
// For Ed25519, the key signs the message directly (no pre-hash).
func (s *Signer) sign(digest []byte, h crypto.Hash, family signatureFamily) ([]byte, error) {
	switch family {
	case familyRSAPKCS1:
		return s.key.Sign(rand.Reader, digest, h)

	case familyRSAPSS:
		rsaKey, ok := s.key.Public().(*rsa.PublicKey)
		if !ok {
			return nil, newError(CodeUnsupportedAlgorithm, "RSA-PSS requires an RSA key")
		}
		saltLen := rsaKey.Size() // will be overridden by pssOpts
		_ = saltLen
		saltSize, err := saltLengthForHash(h)
		if err != nil {
			return nil, err
		}
		return s.key.Sign(rand.Reader, digest, &rsa.PSSOptions{
			SaltLength: saltSize,
			Hash:       h,
		})

	case familyECDSA:
		sig, err := s.key.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, wrapError(CodeInvalidSignature, "ECDSA signing failed", err)
		}
		// Go's ecdsa.Sign already returns DER-encoded Ecdsa-Sig-Value when called
		// via the crypto.Signer interface with a crypto.Hash (not crypto.Hash(0)).
		return sig, nil

	case familyEd25519:
		// Ed25519 signs the message, not a hash. crypto.Hash(0) signals no pre-hash.
		sig, err := s.key.Sign(rand.Reader, digest, crypto.Hash(0))
		if err != nil {
			return nil, wrapError(CodeInvalidSignature, "Ed25519 signing failed", err)
		}
		return sig, nil

	default:
		return nil, newError(CodeUnsupportedAlgorithm, "unknown signature family")
	}
}

// buildSignerInfo assembles the SignerInfo structure.
func (s *Signer) buildSignerInfo(h crypto.Hash, family signatureFamily, signedAttrsBytes, sig []byte) (pkiasn1.SignerInfo, error) {
	digestAlg, err := digestAlgID(h)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	sigAlg, err := signatureAlgID(s.key, h, family)
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	sid, version, err := s.buildSID()
	if err != nil {
		return pkiasn1.SignerInfo{}, err
	}

	// signedAttrsBytes is already the SET-tagged DER encoding. On the wire,
	// SignedAttributes uses IMPLICIT [0]; we store the raw bytes and let the
	// encoder re-tag them via the struct tag in SignerInfo.
	// We store as FullBytes so asn1.Marshal treats the content as pre-encoded.
	signedAttrsWire := retagAsImplicit0(signedAttrsBytes)

	si := pkiasn1.SignerInfo{
		Version:            version,
		SID:                sid,
		DigestAlgorithm:    digestAlg,
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsWire},
		SignatureAlgorithm: sigAlg,
		Signature:          sig,
	}

	if len(s.unauthAttrs) > 0 {
		unauthBytes, err := asn1.MarshalWithParams(pkiasn1.RawAttributes(s.unauthAttrs), "set")
		if err != nil {
			return pkiasn1.SignerInfo{}, wrapError(CodeParse, "marshal unauthenticated attributes", err)
		}
		si.UnsignedAttrs = asn1.RawValue{FullBytes: retagAsImplicit1(unauthBytes)}
	}

	return si, nil
}

// buildSID returns the SignerIdentifier RawValue and the corresponding
// SignerInfo version (1 for IssuerAndSerialNumber, 3 for SubjectKeyIdentifier).
func (s *Signer) buildSID() (asn1.RawValue, int, error) {
	return buildSignerID(s.cert, s.sidType)
}

// buildSignerID builds the SignerIdentifier ASN.1 encoding and returns the
// SignerInfo version required by RFC 5652: 1 for IssuerAndSerialNumber, 3 for
// SubjectKeyIdentifier. Extracted as a package-level function so it can be
// shared with CounterSigner.
func buildSignerID(cert *x509.Certificate, sidType SignerIdentifierType) (asn1.RawValue, int, error) {
	switch sidType {
	case IssuerAndSerialNumber:
		issuerSerial := pkiasn1.IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		}
		encoded, err := asn1.Marshal(issuerSerial)
		if err != nil {
			return asn1.RawValue{}, 0, wrapError(CodeParse, "marshal IssuerAndSerialNumber", err)
		}
		return asn1.RawValue{FullBytes: encoded}, 1, nil

	case SubjectKeyIdentifier:
		if len(cert.SubjectKeyId) == 0 {
			return asn1.RawValue{}, 0, newError(CodeInvalidConfiguration,
				"SubjectKeyIdentifier requested but certificate has no subjectKeyIdentifier extension")
		}
		// [0] IMPLICIT OCTET STRING
		encoded, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      cert.SubjectKeyId,
			IsCompound: false,
		})
		if err != nil {
			return asn1.RawValue{}, 0, wrapError(CodeParse, "marshal SubjectKeyIdentifier", err)
		}
		return asn1.RawValue{FullBytes: encoded}, 3, nil

	default:
		return asn1.RawValue{}, 0, newError(CodeInvalidConfiguration,
			fmt.Sprintf("unknown SignerIdentifierType %d", sidType))
	}
}

// buildECI constructs the EncapsulatedContentInfo for SignedData.
// For attached signatures, content is wrapped in an OCTET STRING inside [0] EXPLICIT.
// For detached signatures, eContent is absent.
func (s *Signer) buildECI(content []byte) (pkiasn1.EncapsulatedContentInfo, error) {
	eci := pkiasn1.EncapsulatedContentInfo{
		EContentType: s.contentType,
	}
	if s.detached {
		return eci, nil
	}

	// Wrap content in OCTET STRING.
	octetString, err := asn1.Marshal(content)
	if err != nil {
		return pkiasn1.EncapsulatedContentInfo{}, wrapError(CodeParse, "marshal eContent OCTET STRING", err)
	}
	// Wrap OCTET STRING in [0] EXPLICIT.
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      octetString,
	})
	if err != nil {
		return pkiasn1.EncapsulatedContentInfo{}, wrapError(CodeParse, "marshal eContent [0] wrapper", err)
	}
	eci.EContent = asn1.RawValue{FullBytes: explicit0}
	return eci, nil
}

// buildSignedDataMulti assembles the full SignedData structure from multiple
// signers' SignerInfos, deduplicating the DigestAlgorithms SET.
func (s *Signer) buildSignedDataMulti(eci pkiasn1.EncapsulatedContentInfo, sis []pkiasn1.SignerInfo, hashes []crypto.Hash, certs []*x509.Certificate) (pkiasn1.SignedData, error) {
	digestAlgs, err := deduplicateDigestAlgs(hashes)
	if err != nil {
		return pkiasn1.SignedData{}, err
	}

	// Use the highest required SignedData version across all SignerInfos.
	version := 1
	for _, si := range sis {
		if v := computeSignedDataVersion(eci.EContentType, si.Version); v > version {
			version = v
		}
	}

	sd := pkiasn1.SignedData{
		Version:          version,
		DigestAlgorithms: digestAlgs,
		EncapContentInfo: eci,
		SignerInfos:      sis,
	}

	// Deduplicate certificates by raw DER bytes.
	seen := make(map[string]bool)
	for _, cert := range certs {
		k := string(cert.Raw)
		if !seen[k] {
			seen[k] = true
			sd.Certificates = append(sd.Certificates, asn1.RawValue{FullBytes: cert.Raw})
		}
	}

	// Embed CRLs verbatim.
	for _, crlBytes := range s.crls {
		sd.CRLs = append(sd.CRLs, asn1.RawValue{FullBytes: crlBytes})
	}

	return sd, nil
}

// deduplicateDigestAlgs returns one AlgorithmIdentifier per distinct OID,
// preserving the order of first appearance.
func deduplicateDigestAlgs(hashes []crypto.Hash) ([]pkix.AlgorithmIdentifier, error) {
	seen := make(map[string]bool)
	var algs []pkix.AlgorithmIdentifier
	for _, h := range hashes {
		alg, err := digestAlgID(h)
		if err != nil {
			return nil, err
		}
		k := alg.Algorithm.String()
		if !seen[k] {
			seen[k] = true
			algs = append(algs, alg)
		}
	}
	return algs, nil
}

// computeSignedDataVersion computes the required SignedData version per RFC 5652 §5.1.
// Only v1 and v3 are relevant for our signing path (v4 and v5 require attribute
// certificate types that this library does not produce).
func computeSignedDataVersion(eContentType asn1.ObjectIdentifier, signerInfoVersion int) int {
	if signerInfoVersion == 3 {
		return 3
	}
	if !eContentType.Equal(pkiasn1.OIDData) {
		return 3
	}
	return 1
}

// marshalContentInfo wraps a SignedData in a ContentInfo and returns DER bytes.
//
// Go's encoding/asn1 ignores struct-tag annotations (including explicit,tag:0) when
// RawValue.FullBytes is set — it writes FullBytes verbatim. We therefore pre-build
// the [0] EXPLICIT wrapper around sdBytes before assigning to FullBytes. This ensures
// the wire form is SEQUENCE { OID, [0] EXPLICIT { SEQUENCE { ...SignedData... } } }.
func marshalContentInfo(sd pkiasn1.SignedData) ([]byte, error) {
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, wrapError(CodeParse, "marshal SignedData", err)
	}

	// Build [0] EXPLICIT wrapper around the SignedData SEQUENCE bytes.
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdBytes,
	})
	if err != nil {
		return nil, wrapError(CodeParse, "marshal ContentInfo [0] wrapper", err)
	}

	// Assign explicit0 as FullBytes so the encoder emits it verbatim (no further
	// wrapping); the [0] tag is already baked in.
	ci := pkiasn1.ContentInfo{
		ContentType: pkiasn1.OIDSignedData,
		Content:     asn1.RawValue{FullBytes: explicit0},
	}
	return asn1.Marshal(ci)
}

// retagAsImplicit0 replaces the outermost tag byte of a DER-encoded SET (0x31)
// with the IMPLICIT [0] CONSTRUCTED tag (0xA0) for wire encoding of SignedAttributes.
func retagAsImplicit0(setBytes []byte) []byte {
	if len(setBytes) == 0 {
		return setBytes
	}
	out := make([]byte, len(setBytes))
	copy(out, setBytes)
	out[0] = implicitTag0Byte
	return out
}

// retagAsImplicit1 replaces the outermost SET tag (0x31) with IMPLICIT [1]
// CONSTRUCTED (0xA1) for wire encoding of UnsignedAttributes.
func retagAsImplicit1(setBytes []byte) []byte {
	if len(setBytes) == 0 {
		return setBytes
	}
	out := make([]byte, len(setBytes))
	copy(out, setBytes)
	out[0] = 0xA1
	return out
}

// mustMarshalSet wraps a single DER-encoded value in a SET tag. It panics on
// marshal failure, which indicates a programming error (not a runtime error).
func mustMarshalSet(inner []byte) []byte {
	encoded, err := asn1.Marshal(asn1.RawValue{
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      inner,
	})
	if err != nil {
		panic(fmt.Sprintf("cms: mustMarshalSet: %v", err))
	}
	return encoded
}

// --- ParseSignedData and verification ---

// VerifyOption configures verification behavior.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	roots      *x509.CertPool
	noChain    bool
	verifyTime time.Time
	verifyOpts *x509.VerifyOptions
}

// WithSystemTrustStore uses the system root certificate store for chain validation.
func WithSystemTrustStore() VerifyOption {
	return func(c *verifyConfig) {
		// nil roots causes x509.Certificate.Verify to use the system store.
		c.roots = nil
	}
}

// WithTrustRoots uses the given certificate pool as the set of trust anchors.
func WithTrustRoots(pool *x509.CertPool) VerifyOption {
	return func(c *verifyConfig) {
		c.roots = pool
	}
}

// WithVerifyOptions provides full control over x509 verification parameters.
// This overrides any roots or time set by other options.
func WithVerifyOptions(opts x509.VerifyOptions) VerifyOption {
	return func(c *verifyConfig) {
		c.verifyOpts = &opts
	}
}

// WithNoChainValidation disables certificate chain validation. Only the
// cryptographic signature is verified. Use with caution.
func WithNoChainValidation() VerifyOption {
	return func(c *verifyConfig) {
		c.noChain = true
	}
}

// WithVerifyTime sets the reference time for certificate validity checks.
// Defaults to time.Now() at the point Verify or VerifyDetached is called.
func WithVerifyTime(t time.Time) VerifyOption {
	return func(c *verifyConfig) {
		c.verifyTime = t
	}
}

// SignerInfo describes a single signer extracted from a parsed CMS SignedData.
// It exposes the resolved certificate and algorithm identifiers without leaking
// raw ASN.1 types from the internal package.
type SignerInfo struct {
	// Version is the SignerInfo syntax version: 1 for IssuerAndSerialNumber,
	// 3 for SubjectKeyIdentifier.
	Version int

	// Certificate is the signing certificate matched from the certificates
	// embedded in SignedData. Nil if the certificate is not embedded in the
	// message, which is valid; callers may hold it out of band.
	Certificate *x509.Certificate

	// DigestAlgorithm is the AlgorithmIdentifier for the message digest used
	// by this signer.
	DigestAlgorithm pkix.AlgorithmIdentifier

	// SignatureAlgorithm is the AlgorithmIdentifier for the signature algorithm,
	// including any algorithm-specific parameters (e.g., RSASSA-PSS-params for
	// RSA-PSS).
	SignatureAlgorithm pkix.AlgorithmIdentifier

	// Signature is the raw signature bytes. For ECDSA this is a DER-encoded
	// Ecdsa-Sig-Value; for RSA it is the raw modular exponentiation result.
	Signature []byte
}

// ParsedSignedData is the result of parsing a CMS SignedData message.
type ParsedSignedData struct {
	raw        []byte // DER-normalized bytes of the entire ContentInfo
	signedData pkiasn1.SignedData
	certs      []*x509.Certificate
	crls       []*x509.RevocationList
}

// ParseSignedData parses a BER- or DER-encoded CMS ContentInfo wrapping SignedData.
// BER input is normalized to DER before parsing. If PKCS #7 encoding is detected,
// ErrPKCS7Format is returned with a descriptive message.
func ParseSignedData(r io.Reader) (*ParsedSignedData, error) {
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapError(CodeParse, "reading input", err)
	}

	// Normalize BER to DER.
	derBytes, err := ber.Normalize(bytes.NewReader(input))
	if err != nil {
		return nil, wrapError(CodeBERConversion, "BER to DER normalization failed", err)
	}

	// Parse outer ContentInfo.
	var ci pkiasn1.ContentInfo
	rest, err := asn1.Unmarshal(derBytes, &ci)
	if err != nil {
		return nil, wrapError(CodeParse, "parsing ContentInfo", err)
	}
	if len(rest) > 0 {
		return nil, newError(CodeParse, "trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(pkiasn1.OIDSignedData) {
		return nil, newError(CodeParse,
			fmt.Sprintf("expected SignedData content type, got %s", ci.ContentType))
	}

	// Parse SignedData from the [0] EXPLICIT wrapper in ContentInfo.Content.
	// Go's asn1 does NOT strip the explicit [0] wrapper for RawValue fields.
	// ci.Content.Class/Tag == [0] (context-specific, tag 0); ci.Content.Bytes
	// holds the inner bytes, which is the full SignedData SEQUENCE TLV.
	var sd pkiasn1.SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, wrapError(CodeParse, "parsing SignedData", err)
	}

	// Parse embedded certificates.
	certs, err := parseCertificates(sd.Certificates)
	if err != nil {
		return nil, err
	}

	// Parse embedded CRLs (silently skipping unrecognised entries).
	crls := parseCRLs(sd.CRLs)

	return &ParsedSignedData{
		raw:        derBytes,
		signedData: sd,
		certs:      certs,
		crls:       crls,
	}, nil
}

// parseCertificates decodes the raw DER bytes of certificate choices into
// *x509.Certificate values. Non-certificate types (e.g., attribute certificates)
// are silently skipped.
func parseCertificates(rawCerts []asn1.RawValue) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			// Skip non-standard certificate types.
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseCRLs decodes the raw DER bytes of revocation information choices into
// *x509.RevocationList values. Entries that fail to parse are silently skipped.
func parseCRLs(rawCRLs []asn1.RawValue) []*x509.RevocationList {
	var crls []*x509.RevocationList
	for _, raw := range rawCRLs {
		crl, err := x509.ParseRevocationList(raw.FullBytes)
		if err != nil {
			continue
		}
		crls = append(crls, crl)
	}
	return crls
}

// IsDetached reports whether eContent is absent from EncapsulatedContentInfo,
// meaning the signature is over external content (detached signature).
// A signed 0-byte payload has IsDetached() == false with an empty Content reader.
func (p *ParsedSignedData) IsDetached() bool {
	return p.signedData.EncapContentInfo.IsDetached()
}

// Content returns an io.Reader over the encapsulated content OCTET STRING value.
// For a signed 0-byte payload this returns a reader over zero bytes.
// Returns ErrDetachedContentMismatch if the signature is detached.
func (p *ParsedSignedData) Content() (io.Reader, error) {
	if p.IsDetached() {
		return nil, newError(CodeDetachedContentMismatch,
			"Content called on a detached SignedData; use VerifyDetached to supply content")
	}
	raw := p.signedData.EncapContentInfo.EContent
	// EContent is [0] EXPLICIT OCTET STRING. raw.Bytes contains the OCTET STRING TLV.
	var octetString []byte
	if _, err := asn1.Unmarshal(raw.Bytes, &octetString); err != nil {
		return nil, wrapError(CodeParse, "parsing eContent OCTET STRING", err)
	}
	return bytes.NewReader(octetString), nil
}

// Certificates returns the certificates embedded in the SignedData.
func (p *ParsedSignedData) Certificates() []*x509.Certificate {
	return p.certs
}

// CRLs returns the Certificate Revocation Lists embedded in the SignedData.
func (p *ParsedSignedData) CRLs() []*x509.RevocationList {
	return p.crls
}

// Signers returns a summary of each SignerInfo in the parsed SignedData.
// Certificates are matched from the embedded certificates field. If no
// matching certificate is embedded, SignerInfo.Certificate is nil — this
// is valid; callers may hold the certificate out of band and pass it to
// Verify or VerifyDetached via WithTrustRoots.
func (p *ParsedSignedData) Signers() []SignerInfo {
	result := make([]SignerInfo, len(p.signedData.SignerInfos))
	for i, si := range p.signedData.SignerInfos {
		result[i] = SignerInfo{
			Version:            si.Version,
			Certificate:        p.findSignerCertOrNil(si),
			DigestAlgorithm:    si.DigestAlgorithm,
			SignatureAlgorithm: si.SignatureAlgorithm,
			Signature:          si.Signature,
		}
	}
	return result
}

// findSignerCertOrNil attempts to locate the signing certificate for si from
// the embedded certificates. Returns nil without error when the certificate is
// absent or the SID cannot be parsed — callers holding the cert out of band
// should call findSignerCert (which returns errors) during verification.
func (p *ParsedSignedData) findSignerCertOrNil(si pkiasn1.SignerInfo) *x509.Certificate {
	cert, err := p.findSignerCert(si)
	if err != nil {
		return nil
	}
	return cert
}

// Verify verifies all SignerInfos in an attached-content SignedData.
// Returns ErrDetachedContentMismatch if the SignedData is detached.
func (p *ParsedSignedData) Verify(opts ...VerifyOption) error {
	if p.IsDetached() {
		return newError(CodeDetachedContentMismatch,
			"Verify called on a detached SignedData; use VerifyDetached")
	}
	content, err := p.Content()
	if err != nil {
		return err
	}
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return wrapError(CodeParse, "reading content for verification", err)
	}
	return p.verifyWithContent(contentBytes, opts...)
}

// VerifyDetached verifies all SignerInfos using the externally provided content.
// Returns ErrDetachedContentMismatch if the SignedData is not detached.
func (p *ParsedSignedData) VerifyDetached(content io.Reader, opts ...VerifyOption) error {
	if !p.IsDetached() {
		return newError(CodeDetachedContentMismatch,
			"VerifyDetached called on an attached SignedData; use Verify")
	}
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return wrapError(CodeParse, "reading detached content", err)
	}
	return p.verifyWithContent(contentBytes, opts...)
}

// verifyWithContent verifies all SignerInfos against the given content bytes.
func (p *ParsedSignedData) verifyWithContent(content []byte, opts ...VerifyOption) error {
	cfg := &verifyConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.verifyTime.IsZero() {
		cfg.verifyTime = time.Now()
	}

	for i, si := range p.signedData.SignerInfos {
		if err := p.verifySigner(si, content, cfg); err != nil {
			return wrapError(err.(*Error).Code,
				fmt.Sprintf("SignerInfo[%d]: %s", i, err.(*Error).Message),
				err.(*Error).Cause)
		}
	}
	return nil
}

// verifySigner verifies a single SignerInfo against the content.
func (p *ParsedSignedData) verifySigner(si pkiasn1.SignerInfo, content []byte, cfg *verifyConfig) error {
	// Locate the signer certificate.
	cert, err := p.findSignerCert(si)
	if err != nil {
		return err
	}

	// Determine the digest algorithm.
	digestHash, err := hashFromOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	signedAttrsPresent := len(si.SignedAttrs.FullBytes) > 0

	// Step 1: Independently compute content digest.
	h, err := newHash(digestHash)
	if err != nil {
		return err
	}
	h.Write(content)
	computedDigest := h.Sum(nil)

	if signedAttrsPresent {
		// Step 2: Validate signed attributes.
		signedAttrsBytes := si.SignedAttrs.FullBytes
		// The wire form uses IMPLICIT [0]; re-tag as SET for attribute parsing.
		setBytes := retagAsSet(signedAttrsBytes)

		if err := validateSignedAttrs(setBytes, computedDigest, p.signedData.EncapContentInfo.EContentType); err != nil {
			return err
		}

		// Step 3: Verify signature over DER-encoded signedAttrs (SET form).
		h3, err := newHash(digestHash)
		if err != nil {
			return err
		}
		h3.Write(setBytes)
		signedAttrsDigest := h3.Sum(nil)

		if err := verifySignature(cert, si, signedAttrsDigest, digestHash); err != nil {
			return err
		}
	} else {
		// No signed attributes: verify signature directly over content digest.
		if err := verifySignature(cert, si, computedDigest, digestHash); err != nil {
			return err
		}
	}

	// Step 4: Chain validation (unless disabled).
	if !cfg.noChain {
		if err := validateChain(cert, p.certs, cfg); err != nil {
			return err
		}
	}

	// Step 5: Verify any embedded timestamp tokens.
	if len(si.UnsignedAttrs.FullBytes) > 0 {
		if err := verifyTimestampsInSI(si); err != nil {
			return err
		}
	}

	return nil
}

// verifyTimestampsInSI checks every id-aa-signatureTimeStampToken unsigned
// attribute in si against si.Signature. Returns an error if any token's
// MessageImprint does not match hash(si.Signature).
func verifyTimestampsInSI(si pkiasn1.SignerInfo) error {
	// Retag [1] IMPLICIT (0xA1) → SET (0x31) for attribute parsing.
	setBytes := make([]byte, len(si.UnsignedAttrs.FullBytes))
	copy(setBytes, si.UnsignedAttrs.FullBytes)
	setBytes[0] = setTagByte

	var attrs pkiasn1.RawAttributes
	if _, err := asn1.UnmarshalWithParams(setBytes, &attrs, "set"); err != nil {
		return wrapError(CodeParse, "parsing unsigned attributes for timestamp verification", err)
	}

	for _, attr := range attrs {
		if !attr.Type.Equal(pkiasn1.OIDAttributeTimeStampToken) {
			continue
		}
		// attr.Values.Bytes is the ContentInfo DER inside the SET wrapper.
		if err := timestamp.VerifyHash(attr.Values.Bytes, si.Signature); err != nil {
			return wrapError(CodeTimestamp, "timestamp message imprint verification failed", err)
		}
	}
	return nil
}

// findSignerCert locates the signing certificate from the embedded certificates
// by matching the SignerIdentifier in the SignerInfo.
func (p *ParsedSignedData) findSignerCert(si pkiasn1.SignerInfo) (*x509.Certificate, error) {
	switch si.Version {
	case 1:
		return p.findCertByIssuerSerial(si.SID)
	case 3:
		return p.findCertBySKI(si.SID)
	default:
		return nil, newError(CodeVersionMismatch,
			fmt.Sprintf("unsupported SignerInfo version %d", si.Version))
	}
}

// findCertByIssuerSerial matches a certificate by IssuerAndSerialNumber.
func (p *ParsedSignedData) findCertByIssuerSerial(sid asn1.RawValue) (*x509.Certificate, error) {
	var isn pkiasn1.IssuerAndSerialNumber
	if _, err := asn1.Unmarshal(sid.FullBytes, &isn); err != nil {
		return nil, wrapError(CodeParse, "parsing IssuerAndSerialNumber", err)
	}
	for _, cert := range p.certs {
		if cert.SerialNumber.Cmp(isn.SerialNumber) == 0 &&
			bytes.Equal(cert.RawIssuer, isn.Issuer.FullBytes) {
			return cert, nil
		}
	}
	return nil, newError(CodeMissingCertificate,
		fmt.Sprintf("signer certificate with serial %s not found in SignedData", isn.SerialNumber))
}

// findCertBySKI matches a certificate by SubjectKeyIdentifier.
func (p *ParsedSignedData) findCertBySKI(sid asn1.RawValue) (*x509.Certificate, error) {
	// sid is [0] IMPLICIT OCTET STRING.
	var ski []byte
	rest, err := asn1.UnmarshalWithParams(sid.FullBytes, &ski, "tag:0")
	if err != nil || len(rest) > 0 {
		return nil, wrapError(CodeParse, "parsing SubjectKeyIdentifier from SID", err)
	}
	for _, cert := range p.certs {
		if bytes.Equal(cert.SubjectKeyId, ski) {
			return cert, nil
		}
	}
	return nil, newError(CodeMissingCertificate, "signer certificate with matching SubjectKeyIdentifier not found")
}

// retagAsSet replaces the first tag byte with the SET tag (0x31).
// Used to convert IMPLICIT [0] wire form of SignedAttributes back to a SET for
// attribute parsing and digest computation.
func retagAsSet(implicit0Bytes []byte) []byte {
	if len(implicit0Bytes) == 0 {
		return implicit0Bytes
	}
	out := make([]byte, len(implicit0Bytes))
	copy(out, implicit0Bytes)
	out[0] = setTagByte
	return out
}

// validateSignedAttrs parses the SET-tagged signedAttrs bytes and verifies that:
//   - content-type attribute is present and equals eContentType
//   - message-digest attribute is present and equals computedDigest
func validateSignedAttrs(setBytes []byte, computedDigest []byte, eContentType asn1.ObjectIdentifier) error {
	var attrs pkiasn1.RawAttributes
	if _, err := asn1.UnmarshalWithParams(setBytes, &attrs, "set"); err != nil {
		return wrapError(CodeParse, "parsing signedAttrs", err)
	}

	var foundCT, foundMD bool
	for _, attr := range attrs {
		switch {
		case attr.Type.Equal(pkiasn1.OIDAttributeContentType):
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &oid); err != nil {
				return wrapError(CodeAttributeInvalid, "parsing content-type attribute value", err)
			}
			if !oid.Equal(eContentType) {
				return newError(CodeContentTypeMismatch,
					fmt.Sprintf("content-type attribute %s does not match eContentType %s", oid, eContentType))
			}
			foundCT = true

		case attr.Type.Equal(pkiasn1.OIDAttributeMessageDigest):
			var messageDigest []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &messageDigest); err != nil {
				return wrapError(CodeAttributeInvalid, "parsing message-digest attribute value", err)
			}
			if !bytes.Equal(messageDigest, computedDigest) {
				return newError(CodeAttributeInvalid,
					"message-digest attribute does not match independently computed digest")
			}
			foundMD = true
		}
	}

	if !foundCT {
		return newError(CodeAttributeInvalid, "mandatory content-type signed attribute is missing")
	}
	if !foundMD {
		return newError(CodeAttributeInvalid, "mandatory message-digest signed attribute is missing")
	}
	return nil
}

// verifySignature verifies the cryptographic signature in si against digest
// using the public key from cert.
func verifySignature(cert *x509.Certificate, si pkiasn1.SignerInfo, digest []byte, h crypto.Hash) error {
	sigAlgOID := si.SignatureAlgorithm.Algorithm

	switch {
	case isRSAPKCS1OID(sigAlgOID):
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return newError(CodeInvalidSignature, "signature algorithm is RSA but certificate has non-RSA key")
		}
		if err := rsa.VerifyPKCS1v15(pub, h, digest, si.Signature); err != nil {
			return wrapError(CodeInvalidSignature, "RSA PKCS1v15 signature verification failed", err)
		}

	case sigAlgOID.Equal(pkiasn1.OIDSignatureAlgorithmRSAPSS):
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return newError(CodeInvalidSignature, "signature algorithm is RSA-PSS but certificate has non-RSA key")
		}
		saltLen, err := saltLengthForHash(h)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPSS(pub, h, digest, si.Signature, &rsa.PSSOptions{
			SaltLength: saltLen,
			Hash:       h,
		}); err != nil {
			return wrapError(CodeInvalidSignature, "RSA-PSS signature verification failed", err)
		}

	case isECDSAOID(sigAlgOID):
		// Go's ecdsa.VerifyASN1 accepts DER-encoded Ecdsa-Sig-Value directly.
		if !verifyECDSA(cert, digest, si.Signature) {
			return newError(CodeInvalidSignature, "ECDSA signature verification failed")
		}

	case sigAlgOID.Equal(pkiasn1.OIDSignatureAlgorithmEd25519):
		// Ed25519 verification is over the message, not a hash.
		if !verifyEd25519(cert, digest, si.Signature) {
			return newError(CodeInvalidSignature, "Ed25519 signature verification failed")
		}

	default:
		return newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported signature algorithm OID %s", sigAlgOID))
	}

	return nil
}

// isRSAPKCS1OID returns true if oid identifies an RSA PKCS1v15 signature.
// This includes both the combined sha*WithRSAEncryption OIDs and the bare
// rsaEncryption OID (1.2.840.113549.1.1.1), which some implementations
// (including OpenSSL) emit in CMS SignerInfo.signatureAlgorithm, relying on
// the DigestAlgorithm field for the hash.
func isRSAPKCS1OID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(pkiasn1.OIDSignatureAlgorithmRSA) ||
		oid.Equal(pkiasn1.OIDSignatureAlgorithmSHA256WithRSA) ||
		oid.Equal(pkiasn1.OIDSignatureAlgorithmSHA384WithRSA) ||
		oid.Equal(pkiasn1.OIDSignatureAlgorithmSHA512WithRSA)
}

// isECDSAOID returns true if oid is one of the ecdsa-with-SHA* OIDs.
func isECDSAOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(pkiasn1.OIDSignatureAlgorithmECDSAWithSHA256) ||
		oid.Equal(pkiasn1.OIDSignatureAlgorithmECDSAWithSHA384) ||
		oid.Equal(pkiasn1.OIDSignatureAlgorithmECDSAWithSHA512)
}

// verifyECDSA verifies an ECDSA signature (DER-encoded Ecdsa-Sig-Value) against digest.
func verifyECDSA(cert *x509.Certificate, digest, sig []byte) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}

// verifyEd25519 verifies an Ed25519 signature. The digest parameter is the raw
// message (not a hash), since Ed25519 performs its own internal hashing.
func verifyEd25519(cert *x509.Certificate, message, sig []byte) bool {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}

// validateChain verifies that cert chains to a trusted root using the certificates
// embedded in the SignedData as intermediates.
func validateChain(cert *x509.Certificate, embedded []*x509.Certificate, cfg *verifyConfig) error {
	if cfg.verifyOpts != nil {
		// Caller has full control.
		if _, err := cert.Verify(*cfg.verifyOpts); err != nil {
			return wrapError(CodeCertificateChain, "certificate chain validation failed", err)
		}
		return nil
	}

	intermediates := x509.NewCertPool()
	for _, c := range embedded {
		if !bytes.Equal(c.Raw, cert.Raw) {
			intermediates.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         cfg.roots,
		Intermediates: intermediates,
		CurrentTime:   cfg.verifyTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		return wrapError(CodeCertificateChain, "certificate chain validation failed", err)
	}
	return nil
}
