package cms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"

	pkiasn1 "github.com/mdean75/cms/internal/asn1"
)

// SymmetricEncryptor builds a CMS EncryptedData message using a fluent builder
// API. The caller supplies the symmetric key directly. Builder methods accumulate
// configuration and errors; Encrypt reports all configuration errors at once.
// SymmetricEncryptor methods are not safe for concurrent use; Encrypt is safe
// for concurrent use once the builder is fully configured.
type SymmetricEncryptor struct {
	key         []byte
	contentAlg  ContentEncryptionAlgorithm
	contentType asn1.ObjectIdentifier
	maxSize     int64
	errs        []error
}

// NewSymmetricEncryptor returns a new SymmetricEncryptor with default settings:
//   - AES-256-GCM content encryption
//   - id-data content type
//   - 64 MiB content size limit
func NewSymmetricEncryptor() *SymmetricEncryptor {
	return &SymmetricEncryptor{
		contentAlg:  AES256GCM,
		contentType: pkiasn1.OIDData,
		maxSize:     DefaultMaxAttachedSize,
	}
}

// WithKey sets the symmetric content encryption key. Must be 16 bytes (AES-128)
// or 32 bytes (AES-256) — the exact length depends on WithContentEncryption.
// Required.
func (se *SymmetricEncryptor) WithKey(key []byte) *SymmetricEncryptor {
	if len(key) == 0 {
		se.errs = append(se.errs, newConfigError("key must not be empty"))
		return se
	}
	se.key = key
	return se
}

// WithContentEncryption sets the symmetric cipher. Defaults to AES256GCM.
// The key length must match: 16 bytes for AES-128, 32 bytes for AES-256.
func (se *SymmetricEncryptor) WithContentEncryption(alg ContentEncryptionAlgorithm) *SymmetricEncryptor {
	se.contentAlg = alg
	return se
}

// WithContentType sets a custom content type OID in EncryptedContentInfo.
// Default is id-data.
func (se *SymmetricEncryptor) WithContentType(oid asn1.ObjectIdentifier) *SymmetricEncryptor {
	if len(oid) == 0 {
		se.errs = append(se.errs, newConfigError("content type OID is empty"))
		return se
	}
	se.contentType = oid
	return se
}

// WithMaxContentSize sets the maximum content size in bytes. Defaults to
// DefaultMaxAttachedSize (64 MiB). Pass UnlimitedAttachedSize to disable.
func (se *SymmetricEncryptor) WithMaxContentSize(maxBytes int64) *SymmetricEncryptor {
	se.maxSize = maxBytes
	return se
}

// Encrypt reads plaintext from r, encrypts it with the configured key and
// algorithm, and returns the DER-encoded ContentInfo wrapping EncryptedData.
// All builder configuration errors are reported here.
func (se *SymmetricEncryptor) Encrypt(r io.Reader) ([]byte, error) {
	if err := se.validate(); err != nil {
		return nil, err
	}

	content, err := se.readContent(r)
	if err != nil {
		return nil, err
	}

	ciphertext, encAlgID, err := encryptWithKey(content, se.contentAlg, se.key)
	if err != nil {
		return nil, err
	}

	eci := pkiasn1.EncryptedContentInfo{
		ContentType:                se.contentType,
		ContentEncryptionAlgorithm: encAlgID,
		EncryptedContent:           asn1.RawValue{Bytes: ciphertext, Tag: 0, Class: asn1.ClassContextSpecific},
	}
	ed := pkiasn1.EncryptedData{
		Version:              0,
		EncryptedContentInfo: eci,
	}

	return marshalEncryptedDataCI(ed)
}

// validate checks that all accumulated configuration errors are nil and that
// the key is present with the correct length for the chosen algorithm.
func (se *SymmetricEncryptor) validate() error {
	var errs []error
	errs = append(errs, se.errs...)
	if se.key == nil && len(se.errs) == 0 {
		errs = append(errs, newConfigError("key is required"))
	} else if se.key != nil {
		if err := validateSymKey(se.key, se.contentAlg); err != nil {
			errs = append(errs, err)
		}
	}
	return joinErrors(errs)
}

// readContent reads all content from r, enforcing the size limit.
func (se *SymmetricEncryptor) readContent(r io.Reader) ([]byte, error) {
	if se.maxSize == UnlimitedAttachedSize {
		return io.ReadAll(r)
	}
	lr := io.LimitReader(r, se.maxSize+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, wrapError(CodeParse, "reading content", err)
	}
	if int64(len(buf)) > se.maxSize {
		return nil, newError(CodePayloadTooLarge,
			fmt.Sprintf("content exceeds limit of %d bytes; increase limit with WithMaxContentSize", se.maxSize))
	}
	return buf, nil
}

// ParsedEncryptedData wraps a parsed EncryptedData for decryption.
type ParsedEncryptedData struct {
	encryptedData pkiasn1.EncryptedData
}

// ParseEncryptedData parses a DER-encoded CMS ContentInfo wrapping EncryptedData.
func ParseEncryptedData(r io.Reader) (*ParsedEncryptedData, error) {
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapError(CodeParse, "reading EncryptedData input", err)
	}

	var ci pkiasn1.ContentInfo
	rest, err := asn1.Unmarshal(input, &ci)
	if err != nil {
		return nil, wrapError(CodeParse, "parsing ContentInfo", err)
	}
	if len(rest) > 0 {
		return nil, newError(CodeParse, "trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(pkiasn1.OIDEncryptedData) {
		return nil, newError(CodeParse,
			fmt.Sprintf("expected EncryptedData content type OID %s, got %s",
				pkiasn1.OIDEncryptedData, ci.ContentType))
	}

	// ci.Content.Bytes holds the inner bytes of the [0] EXPLICIT wrapper,
	// which is the full EncryptedData SEQUENCE TLV.
	var ed pkiasn1.EncryptedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, wrapError(CodeParse, "parsing EncryptedData structure", err)
	}

	return &ParsedEncryptedData{encryptedData: ed}, nil
}

// Decrypt decrypts the content using the supplied symmetric key and returns
// the plaintext. The key must match the algorithm used during encryption.
func (p *ParsedEncryptedData) Decrypt(key []byte) ([]byte, error) {
	alg, err := contentEncAlgFromOID(p.encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if err := validateSymKey(key, alg); err != nil {
		return nil, err
	}
	return decryptContent(p.encryptedData.EncryptedContentInfo, key)
}

// --- Internal helpers ---

// validateSymKey checks that key has the correct length for alg.
func validateSymKey(key []byte, alg ContentEncryptionAlgorithm) error {
	want := symKeyLen(alg)
	if len(key) != want {
		return newConfigError(
			fmt.Sprintf("key length %d is incorrect for algorithm (expected %d bytes)", len(key), want))
	}
	return nil
}

// symKeyLen returns the required key length in bytes for alg.
func symKeyLen(alg ContentEncryptionAlgorithm) int {
	switch alg {
	case AES128GCM, AES128CBC:
		return 16
	default: // AES256GCM, AES256CBC
		return 32
	}
}

// contentEncAlgFromOID maps a content encryption OID to a ContentEncryptionAlgorithm.
func contentEncAlgFromOID(oid asn1.ObjectIdentifier) (ContentEncryptionAlgorithm, error) {
	switch {
	case oid.Equal(pkiasn1.OIDContentEncryptionAES256GCM):
		return AES256GCM, nil
	case oid.Equal(pkiasn1.OIDContentEncryptionAES128GCM):
		return AES128GCM, nil
	case oid.Equal(pkiasn1.OIDContentEncryptionAES256CBC):
		return AES256CBC, nil
	case oid.Equal(pkiasn1.OIDContentEncryptionAES128CBC):
		return AES128CBC, nil
	default:
		return 0, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported content encryption algorithm OID %s", oid))
	}
}

// encryptWithKey encrypts plaintext using the provided key and algorithm.
// The key length must already be validated to match alg.
func encryptWithKey(plaintext []byte, alg ContentEncryptionAlgorithm, key []byte) (ciphertext []byte, algID pkix.AlgorithmIdentifier, err error) {
	switch alg {
	case AES256GCM, AES128GCM:
		return encryptAESGCMWithKey(plaintext, key)
	case AES256CBC, AES128CBC:
		return encryptAESCBCWithKey(plaintext, key)
	default:
		return nil, pkix.AlgorithmIdentifier{},
			newError(CodeUnsupportedAlgorithm, fmt.Sprintf("unsupported content encryption algorithm %d", alg))
	}
}

// encryptAESGCMWithKey encrypts plaintext with AES-GCM using the provided key
// and a fresh random nonce.
func encryptAESGCMWithKey(plaintext, key []byte) (ciphertext []byte, algID pkix.AlgorithmIdentifier, err error) {
	nonce := make([]byte, gcmNonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "generating AES-GCM nonce", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "creating AES cipher", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "creating AES-GCM cipher", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	params := pkiasn1.GCMParameters{Nonce: nonce}
	rawParams, err := asn1.Marshal(params)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "marshaling GCM parameters", err)
	}

	oid := pkiasn1.OIDContentEncryptionAES256GCM
	if len(key) == 16 {
		oid = pkiasn1.OIDContentEncryptionAES128GCM
	}
	algID = pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: rawParams},
	}
	return ciphertext, algID, nil
}

// encryptAESCBCWithKey encrypts plaintext with AES-CBC (PKCS#7 padded) using the
// provided key and a fresh random IV.
func encryptAESCBCWithKey(plaintext, key []byte) (ciphertext []byte, algID pkix.AlgorithmIdentifier, err error) {
	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "generating AES-CBC IV", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "creating AES cipher", err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	rawIV, err := asn1.Marshal(iv)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "marshaling AES-CBC IV", err)
	}

	oid := pkiasn1.OIDContentEncryptionAES256CBC
	if len(key) == 16 {
		oid = pkiasn1.OIDContentEncryptionAES128CBC
	}
	algID = pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: rawIV},
	}
	return ciphertext, algID, nil
}

// marshalEncryptedDataCI wraps EncryptedData in a ContentInfo and returns DER bytes.
func marshalEncryptedDataCI(ed pkiasn1.EncryptedData) ([]byte, error) {
	edBytes, err := asn1.Marshal(ed)
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling EncryptedData", err)
	}
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      edBytes,
	})
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling ContentInfo [0] wrapper for EncryptedData", err)
	}
	ci := pkiasn1.ContentInfo{
		ContentType: pkiasn1.OIDEncryptedData,
		Content:     asn1.RawValue{FullBytes: explicit0},
	}
	return asn1.Marshal(ci)
}
