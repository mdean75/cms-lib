package cms

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"

	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// Digester builds a CMS DigestedData message using a fluent builder API.
// Builder methods accumulate configuration and errors; Digest reports all
// configuration errors at once. Digester methods are not safe for concurrent
// use; Digest is safe for concurrent use once the builder is fully configured.
type Digester struct {
	hash        crypto.Hash
	contentType asn1.ObjectIdentifier
	detached    bool
	maxSize     int64
	errs        []error
}

// NewDigester returns a new Digester with default settings:
//   - SHA-256 digest algorithm
//   - Attached content
//   - id-data content type
//   - 64 MiB content size limit
func NewDigester() *Digester {
	return &Digester{
		hash:        crypto.SHA256,
		contentType: pkiasn1.OIDData,
		maxSize:     DefaultMaxAttachedSize,
	}
}

// WithHash sets the digest algorithm. Defaults to SHA-256. Must be in the
// library allow-list (SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512).
func (d *Digester) WithHash(h crypto.Hash) *Digester {
	d.hash = h
	return d
}

// WithContentType sets a custom eContentType OID. Default is id-data.
// A non-id-data type sets DigestedData version to 2 per RFC 5652 §7.1.
func (d *Digester) WithContentType(oid asn1.ObjectIdentifier) *Digester {
	if len(oid) == 0 {
		d.errs = append(d.errs, newConfigError("content type OID is empty"))
		return d
	}
	d.contentType = oid
	return d
}

// WithDetachedContent omits eContent from the output; callers must supply
// content separately during verification via VerifyDetached.
func (d *Digester) WithDetachedContent() *Digester {
	d.detached = true
	return d
}

// WithMaxContentSize sets the maximum attached content size. Defaults to
// DefaultMaxAttachedSize (64 MiB). Pass UnlimitedAttachedSize to disable.
// Has no effect in detached mode.
func (d *Digester) WithMaxContentSize(maxBytes int64) *Digester {
	d.maxSize = maxBytes
	return d
}

// Digest reads content from r, computes the CMS DigestedData, and returns
// the DER-encoded ContentInfo. All builder configuration errors are reported here.
func (d *Digester) Digest(r io.Reader) ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}

	content, err := d.readContent(r)
	if err != nil {
		return nil, err
	}

	// Compute digest over the raw content bytes (RFC 5652 §7.2).
	hw, err := newHash(d.hash)
	if err != nil {
		return nil, err
	}
	hw.Write(content)
	digest := hw.Sum(nil)

	eci, err := d.buildECI(content)
	if err != nil {
		return nil, err
	}

	digestAlg, err := digestAlgID(d.hash)
	if err != nil {
		return nil, err
	}

	// Version 0 for id-data, 2 for any other content type (RFC 5652 §7.1).
	version := 0
	if !d.contentType.Equal(pkiasn1.OIDData) {
		version = 2
	}

	dd := pkiasn1.DigestedData{
		Version:          version,
		DigestAlgorithm:  digestAlg,
		EncapContentInfo: eci,
		Digest:           digest,
	}

	return marshalDigestedDataCI(dd)
}

// validate checks that accumulated errors are nil and the hash algorithm is supported.
func (d *Digester) validate() error {
	var errs []error
	errs = append(errs, d.errs...)
	if _, err := newHash(d.hash); err != nil {
		errs = append(errs, err)
	}
	return joinErrors(errs)
}

// readContent reads all content from r, enforcing the size limit in attached mode.
// In detached mode the limit has no effect.
func (d *Digester) readContent(r io.Reader) ([]byte, error) {
	if d.detached || d.maxSize == UnlimitedAttachedSize {
		return io.ReadAll(r)
	}
	lr := io.LimitReader(r, d.maxSize+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, wrapError(CodeParse, "reading content", err)
	}
	if int64(len(buf)) > d.maxSize {
		return nil, newError(CodePayloadTooLarge,
			fmt.Sprintf("content exceeds limit of %d bytes; increase limit with WithMaxContentSize", d.maxSize))
	}
	return buf, nil
}

// buildECI constructs the EncapsulatedContentInfo for DigestedData.
// For attached mode, content is wrapped in OCTET STRING inside [0] EXPLICIT.
// For detached mode, eContent is absent.
func (d *Digester) buildECI(content []byte) (pkiasn1.EncapsulatedContentInfo, error) {
	eci := pkiasn1.EncapsulatedContentInfo{
		EContentType: d.contentType,
	}
	if d.detached {
		return eci, nil
	}
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
	eci.EContent = asn1.RawValue{FullBytes: explicit0}
	return eci, nil
}

// marshalDigestedDataCI wraps DigestedData in a ContentInfo and returns DER bytes.
func marshalDigestedDataCI(dd pkiasn1.DigestedData) ([]byte, error) {
	ddBytes, err := asn1.Marshal(dd)
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling DigestedData", err)
	}
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      ddBytes,
	})
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling ContentInfo [0] wrapper for DigestedData", err)
	}
	ci := pkiasn1.ContentInfo{
		ContentType: pkiasn1.OIDDigestedData,
		Content:     asn1.RawValue{FullBytes: explicit0},
	}
	return asn1.Marshal(ci)
}

// ParsedDigestedData wraps a parsed DigestedData for verification.
type ParsedDigestedData struct {
	digestedData pkiasn1.DigestedData
}

// ParseDigestedData parses a DER-encoded CMS ContentInfo wrapping DigestedData.
func ParseDigestedData(r io.Reader) (*ParsedDigestedData, error) {
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapError(CodeParse, "reading DigestedData input", err)
	}

	var ci pkiasn1.ContentInfo
	rest, err := asn1.Unmarshal(input, &ci)
	if err != nil {
		return nil, wrapError(CodeParse, "parsing ContentInfo", err)
	}
	if len(rest) > 0 {
		return nil, newError(CodeParse, "trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(pkiasn1.OIDDigestedData) {
		return nil, newError(CodeParse,
			fmt.Sprintf("expected DigestedData content type OID %s, got %s",
				pkiasn1.OIDDigestedData, ci.ContentType))
	}

	// ci.Content.Bytes holds the inner bytes of the [0] EXPLICIT wrapper,
	// which is the full DigestedData SEQUENCE TLV.
	var dd pkiasn1.DigestedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &dd); err != nil {
		return nil, wrapError(CodeParse, "parsing DigestedData structure", err)
	}

	return &ParsedDigestedData{digestedData: dd}, nil
}

// IsDetached reports whether eContent is absent from the EncapsulatedContentInfo.
func (p *ParsedDigestedData) IsDetached() bool {
	return p.digestedData.EncapContentInfo.IsDetached()
}

// Content returns an io.Reader over the encapsulated content OCTET STRING value.
// Returns ErrDetachedContentMismatch if the DigestedData is detached.
func (p *ParsedDigestedData) Content() (io.Reader, error) {
	if p.IsDetached() {
		return nil, newError(CodeDetachedContentMismatch,
			"Content called on a detached DigestedData; use VerifyDetached to supply content")
	}
	raw := p.digestedData.EncapContentInfo.EContent
	// EContent is [0] EXPLICIT OCTET STRING. raw.Bytes contains the OCTET STRING TLV.
	var octetString []byte
	if _, err := asn1.Unmarshal(raw.Bytes, &octetString); err != nil {
		return nil, wrapError(CodeParse, "parsing eContent OCTET STRING", err)
	}
	return bytes.NewReader(octetString), nil
}

// Verify recomputes the hash of the embedded content and compares it to the
// stored Digest. Returns ErrDetachedContentMismatch if called on a detached
// DigestedData; use VerifyDetached instead.
func (p *ParsedDigestedData) Verify() error {
	if p.IsDetached() {
		return newError(CodeDetachedContentMismatch,
			"Verify called on a detached DigestedData; use VerifyDetached and supply the content")
	}
	r, err := p.Content()
	if err != nil {
		return err
	}
	content, err := io.ReadAll(r)
	if err != nil {
		return wrapError(CodeParse, "reading eContent for verification", err)
	}
	return p.verifyDigest(content)
}

// VerifyDetached recomputes the hash of externally provided content and
// compares it to the stored Digest.
// Returns ErrDetachedContentMismatch if the DigestedData is not detached.
func (p *ParsedDigestedData) VerifyDetached(content io.Reader) error {
	if !p.IsDetached() {
		return newError(CodeDetachedContentMismatch,
			"VerifyDetached called on an attached DigestedData; use Verify instead")
	}
	buf, err := io.ReadAll(content)
	if err != nil {
		return wrapError(CodeParse, "reading detached content for verification", err)
	}
	return p.verifyDigest(buf)
}

// verifyDigest recomputes the hash over content and compares it to the stored Digest.
func (p *ParsedDigestedData) verifyDigest(content []byte) error {
	h, err := hashFromOID(p.digestedData.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	hw, err := newHash(h)
	if err != nil {
		return err
	}
	hw.Write(content)
	computed := hw.Sum(nil)
	if !bytes.Equal(computed, p.digestedData.Digest) {
		return newError(CodeInvalidSignature, "DigestedData digest mismatch: content has been modified")
	}
	return nil
}
