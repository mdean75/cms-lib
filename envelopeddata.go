package cms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	pkiasn1 "github.com/mdean75/cms/internal/asn1"
)

// kdfHash is the hash.Hash interface used by the X9.63 KDF.
type kdfHash = hash.Hash

// ContentEncryptionAlgorithm identifies the symmetric cipher used to encrypt
// EnvelopedData content.
type ContentEncryptionAlgorithm int

const (
	// AES256GCM selects AES-256 in GCM mode. This is the default.
	AES256GCM ContentEncryptionAlgorithm = iota
	// AES128GCM selects AES-128 in GCM mode.
	AES128GCM
	// AES128CBC selects AES-128 in CBC mode with PKCS#7 padding.
	AES128CBC
	// AES256CBC selects AES-256 in CBC mode with PKCS#7 padding.
	AES256CBC
)

// gcmNonceSize is the standard 12-byte nonce for AES-GCM per RFC 5084.
const gcmNonceSize = 12

// gcmTagSize is the standard 16-byte authentication tag for AES-GCM.
const gcmTagSize = 16

// Encryptor builds a CMS EnvelopedData message using a fluent builder API.
// Builder methods accumulate configuration and errors; Encrypt reports all
// configuration errors at once. Encryptor methods are not safe for concurrent
// use; Encrypt is safe for concurrent use once the builder is fully configured.
type Encryptor struct {
	recipients []*x509.Certificate
	contentAlg ContentEncryptionAlgorithm
	maxSize    int64
	errs       []error
}

// NewEncryptor returns a new Encryptor with default settings:
//   - AES-256-GCM content encryption
//   - 64 MiB content size limit
func NewEncryptor() *Encryptor {
	return &Encryptor{
		contentAlg: AES256GCM,
		maxSize:    DefaultMaxAttachedSize,
	}
}

// WithRecipient adds a recipient certificate. The key transport or key
// agreement algorithm is auto-selected from the certificate's public key type:
// RSA keys use RSA-OAEP; EC keys use ECDH ephemeral-static. At least one
// recipient is required before calling Encrypt.
func (e *Encryptor) WithRecipient(cert *x509.Certificate) *Encryptor {
	if cert == nil {
		e.errs = append(e.errs, newConfigError("recipient certificate is nil"))
		return e
	}
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		// supported
	default:
		e.errs = append(e.errs, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported recipient public key type %T", cert.PublicKey)))
		return e
	}
	e.recipients = append(e.recipients, cert)
	return e
}

// WithContentEncryption sets the symmetric cipher for content encryption.
// Defaults to AES256GCM.
func (e *Encryptor) WithContentEncryption(alg ContentEncryptionAlgorithm) *Encryptor {
	e.contentAlg = alg
	return e
}

// WithMaxContentSize sets the maximum content size in bytes. Defaults to
// DefaultMaxAttachedSize (64 MiB). Pass UnlimitedAttachedSize to disable.
func (e *Encryptor) WithMaxContentSize(maxBytes int64) *Encryptor {
	e.maxSize = maxBytes
	return e
}

// Encrypt reads plaintext from r, encrypts it for all configured recipients,
// and returns the DER-encoded CMS ContentInfo wrapping EnvelopedData.
// All builder configuration errors are reported here.
func (e *Encryptor) Encrypt(r io.Reader) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}

	plaintext, err := e.readContent(r)
	if err != nil {
		return nil, err
	}

	cek, ciphertext, encAlgID, err := encryptContent(plaintext, e.contentAlg)
	if err != nil {
		return nil, err
	}

	var recipInfos []asn1.RawValue
	hasKARI := false

	for _, cert := range e.recipients {
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
			ri, riErr := buildRSARecipientInfo(cert, cek)
			if riErr != nil {
				return nil, riErr
			}
			recipInfos = append(recipInfos, ri)

		case *ecdsa.PublicKey:
			ri, riErr := buildECDHRecipientInfo(cert, cek)
			if riErr != nil {
				return nil, riErr
			}
			recipInfos = append(recipInfos, ri)
			hasKARI = true
		}
	}

	version := 0
	if hasKARI {
		version = 2
	}

	eci := pkiasn1.EncryptedContentInfo{
		ContentType:                pkiasn1.OIDData,
		ContentEncryptionAlgorithm: encAlgID,
		EncryptedContent:           asn1.RawValue{Bytes: ciphertext, Tag: 0, Class: asn1.ClassContextSpecific},
	}

	ed := pkiasn1.EnvelopedData{
		Version:              version,
		RecipientInfos:       recipInfos,
		EncryptedContentInfo: eci,
	}

	return marshalEnvelopedDataCI(ed)
}

// validate checks builder state and returns a joined error for all problems.
func (e *Encryptor) validate() error {
	var errs []error
	errs = append(errs, e.errs...)
	if len(e.recipients) == 0 && len(e.errs) == 0 {
		errs = append(errs, newConfigError("at least one recipient is required"))
	}
	return joinErrors(errs)
}

// readContent reads r up to maxSize bytes.
func (e *Encryptor) readContent(r io.Reader) ([]byte, error) {
	if e.maxSize == UnlimitedAttachedSize {
		return io.ReadAll(r)
	}
	lr := io.LimitReader(r, e.maxSize+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, wrapError(CodeParse, "reading content for encryption", err)
	}
	if int64(len(buf)) > e.maxSize {
		return nil, newError(CodePayloadTooLarge,
			fmt.Sprintf("content exceeds encryption size limit of %d bytes", e.maxSize))
	}
	return buf, nil
}

// ParsedEnvelopedData wraps a parsed EnvelopedData structure for decryption.
type ParsedEnvelopedData struct {
	envelopedData pkiasn1.EnvelopedData
}

// ParseEnvelopedData parses a DER-encoded CMS ContentInfo wrapping EnvelopedData.
func ParseEnvelopedData(r io.Reader) (*ParsedEnvelopedData, error) {
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapError(CodeParse, "reading EnvelopedData input", err)
	}

	var ci pkiasn1.ContentInfo
	rest, err := asn1.Unmarshal(input, &ci)
	if err != nil {
		return nil, wrapError(CodeParse, "parsing ContentInfo", err)
	}
	if len(rest) > 0 {
		return nil, newError(CodeParse, "trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(pkiasn1.OIDEnvelopedData) {
		return nil, newError(CodeParse,
			fmt.Sprintf("expected EnvelopedData content type, got %s", ci.ContentType))
	}

	var ed pkiasn1.EnvelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, wrapError(CodeParse, "parsing EnvelopedData", err)
	}

	return &ParsedEnvelopedData{envelopedData: ed}, nil
}

// Decrypt finds the RecipientInfo matching cert, decrypts the content encryption
// key using key, then decrypts and returns the plaintext content.
// Returns ErrMissingCertificate if no matching RecipientInfo is found.
func (p *ParsedEnvelopedData) Decrypt(key crypto.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	cek, err := p.decryptCEK(key, cert)
	if err != nil {
		return nil, err
	}
	return decryptContent(p.envelopedData.EncryptedContentInfo, cek)
}

// decryptCEK iterates RecipientInfos and decrypts the CEK for the matching recipient.
func (p *ParsedEnvelopedData) decryptCEK(key crypto.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	for _, ri := range p.envelopedData.RecipientInfos {
		// SEQUENCE (0x30) → KeyTransRecipientInfo
		// [1] CONSTRUCTED (0xA1) → KeyAgreeRecipientInfo
		if len(ri.FullBytes) == 0 {
			continue
		}
		tag := ri.FullBytes[0]

		switch {
		case tag == 0x30:
			cek, err := tryDecryptKTRI(ri, key, cert)
			if err != nil || cek != nil {
				return cek, err
			}

		case tag == 0xA1:
			cek, err := tryDecryptKARI(ri, key, cert)
			if err != nil || cek != nil {
				return cek, err
			}
		}
	}
	return nil, newError(CodeMissingCertificate,
		"no RecipientInfo found matching the provided certificate")
}

// tryDecryptKTRI attempts to decrypt the CEK from a KeyTransRecipientInfo.
// Returns (nil, nil) if the RID does not match cert.
func tryDecryptKTRI(ri asn1.RawValue, key crypto.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	var ktri pkiasn1.KeyTransRecipientInfo
	if _, err := asn1.Unmarshal(ri.FullBytes, &ktri); err != nil {
		return nil, wrapError(CodeParse, "parsing KeyTransRecipientInfo", err)
	}

	if !matchRIDTocert(ktri.RID, cert) {
		return nil, nil
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, newError(CodeInvalidSignature,
			"KeyTransRecipientInfo found but private key is not RSA")
	}

	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ktri.EncryptedKey, nil)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "RSA-OAEP CEK decryption failed", err)
	}
	return cek, nil
}

// tryDecryptKARI attempts to decrypt the CEK from a KeyAgreeRecipientInfo.
// Returns (nil, nil) if no RecipientEncryptedKey matches cert.
func tryDecryptKARI(ri asn1.RawValue, key crypto.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	// Retag [1] → SEQUENCE so asn1.Unmarshal can parse KeyAgreeRecipientInfo.
	retagged := make([]byte, len(ri.FullBytes))
	copy(retagged, ri.FullBytes)
	retagged[0] = 0x30

	var kari pkiasn1.KeyAgreeRecipientInfo
	if _, err := asn1.Unmarshal(retagged, &kari); err != nil {
		return nil, wrapError(CodeParse, "parsing KeyAgreeRecipientInfo", err)
	}

	// Find matching RecipientEncryptedKey.
	var encryptedKey []byte
	for _, rek := range kari.RecipientEncryptedKeys {
		if matchRIDTocert(rek.RID, cert) {
			encryptedKey = rek.EncryptedKey
			break
		}
	}
	if encryptedKey == nil {
		return nil, nil
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, newError(CodeInvalidSignature,
			"KeyAgreeRecipientInfo found but private key is not ECDSA")
	}

	// Parse the ephemeral originator public key from Originator [0] EXPLICIT.
	// kari.Originator.Bytes contains the inner content of the [0] EXPLICIT wrapper.
	// The inner value is [1] IMPLICIT OriginatorPublicKey.
	ephemeralPub, err := parseOriginatorPublicKey(kari.Originator)
	if err != nil {
		return nil, err
	}

	// Determine key wrap OID from KeyEncryptionAlgorithm parameters.
	keyWrapOID, err := keyWrapOIDFromKEA(kari.KeyEncryptionAlgorithm)
	if err != nil {
		return nil, err
	}

	// Determine KEK length from key wrap OID.
	kekLen, err := kekLengthForWrapOID(keyWrapOID)
	if err != nil {
		return nil, err
	}

	// Compute ECDH shared secret.
	recipPriv, err := ecKey.ECDH()
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "converting ECDSA private key to ECDH", err)
	}
	sharedSecret, err := recipPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "ECDH key agreement failed", err)
	}

	// Derive KEK using X9.63 KDF.
	kek, err := x963KDF(sharedSecret, kekLen, kari.KeyEncryptionAlgorithm)
	if err != nil {
		return nil, err
	}

	// Unwrap CEK.
	cek, err := aesKeyUnwrap(kek, encryptedKey)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "AES key unwrap failed", err)
	}
	return cek, nil
}

// matchRIDTocert returns true if the RecipientIdentifier RawValue matches cert.
// Supports IssuerAndSerialNumber (SEQUENCE, tag 0x30).
func matchRIDTocert(rid asn1.RawValue, cert *x509.Certificate) bool {
	if len(rid.FullBytes) == 0 {
		return false
	}
	// IssuerAndSerialNumber is a SEQUENCE (0x30).
	if rid.FullBytes[0] != 0x30 {
		return false
	}
	var isn pkiasn1.IssuerAndSerialNumber
	if _, err := asn1.Unmarshal(rid.FullBytes, &isn); err != nil {
		return false
	}
	return cert.SerialNumber.Cmp(isn.SerialNumber) == 0 &&
		issuerRawEqual(isn.Issuer.FullBytes, cert.RawIssuer)
}

// issuerRawEqual compares two DER-encoded issuer distinguished names.
func issuerRawEqual(a, b []byte) bool {
	if len(a) == len(b) {
		eq := true
		for i := range a {
			if a[i] != b[i] {
				eq = false
				break
			}
		}
		return eq
	}
	return false
}

// encryptContent generates a random CEK, encrypts plaintext with the chosen
// algorithm, and returns the CEK, ciphertext, and AlgorithmIdentifier.
func encryptContent(plaintext []byte, alg ContentEncryptionAlgorithm) (cek, ciphertext []byte, algID pkix.AlgorithmIdentifier, err error) {
	switch alg {
	case AES256GCM:
		return encryptAESGCM(plaintext, 32)
	case AES128GCM:
		return encryptAESGCM(plaintext, 16)
	case AES256CBC:
		return encryptAESCBC(plaintext, 32)
	case AES128CBC:
		return encryptAESCBC(plaintext, 16)
	default:
		return nil, nil, pkix.AlgorithmIdentifier{},
			newError(CodeUnsupportedAlgorithm, fmt.Sprintf("unsupported content encryption algorithm %d", alg))
	}
}

// encryptAESGCM encrypts plaintext with AES-GCM using a fresh random CEK and nonce.
func encryptAESGCM(plaintext []byte, keyLen int) (cek, ciphertext []byte, algID pkix.AlgorithmIdentifier, err error) {
	cek = make([]byte, keyLen)
	if _, err = rand.Read(cek); err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "generating AES-GCM key", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "generating AES-GCM nonce", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "creating AES cipher", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "creating AES-GCM cipher", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	params := pkiasn1.GCMParameters{Nonce: nonce}
	rawParams, err := asn1.Marshal(params)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "marshaling GCM parameters", err)
	}

	oid := pkiasn1.OIDContentEncryptionAES256GCM
	if keyLen == 16 {
		oid = pkiasn1.OIDContentEncryptionAES128GCM
	}
	algID = pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: rawParams},
	}
	return cek, ciphertext, algID, nil
}

// encryptAESCBC encrypts plaintext with AES-CBC (PKCS#7 padded) using a fresh
// random CEK and IV.
func encryptAESCBC(plaintext []byte, keyLen int) (cek, ciphertext []byte, algID pkix.AlgorithmIdentifier, err error) {
	cek = make([]byte, keyLen)
	if _, err = rand.Read(cek); err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "generating AES-CBC key", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "generating AES-CBC IV", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "creating AES cipher", err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// IV is encoded as OCTET STRING parameter.
	rawIV, err := asn1.Marshal(iv)
	if err != nil {
		return nil, nil, pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "marshaling AES-CBC IV", err)
	}

	oid := pkiasn1.OIDContentEncryptionAES256CBC
	if keyLen == 16 {
		oid = pkiasn1.OIDContentEncryptionAES128CBC
	}
	algID = pkix.AlgorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{FullBytes: rawIV},
	}
	return cek, ciphertext, algID, nil
}

// decryptContent decrypts the ciphertext in eci using cek.
func decryptContent(eci pkiasn1.EncryptedContentInfo, cek []byte) ([]byte, error) {
	ciphertext := eci.EncryptedContent.Bytes
	algOID := eci.ContentEncryptionAlgorithm.Algorithm

	switch {
	case algOID.Equal(pkiasn1.OIDContentEncryptionAES128GCM) ||
		algOID.Equal(pkiasn1.OIDContentEncryptionAES256GCM):
		return decryptAESGCM(ciphertext, cek, eci.ContentEncryptionAlgorithm)

	case algOID.Equal(pkiasn1.OIDContentEncryptionAES128CBC) ||
		algOID.Equal(pkiasn1.OIDContentEncryptionAES256CBC):
		return decryptAESCBC(ciphertext, cek, eci.ContentEncryptionAlgorithm)

	default:
		return nil, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported content encryption algorithm OID %s", algOID))
	}
}

// decryptAESGCM decrypts AES-GCM ciphertext.
func decryptAESGCM(ciphertext, cek []byte, algID pkix.AlgorithmIdentifier) ([]byte, error) {
	var params pkiasn1.GCMParameters
	if _, err := asn1.Unmarshal(algID.Parameters.FullBytes, &params); err != nil {
		return nil, wrapError(CodeParse, "parsing GCM parameters", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "creating AES cipher for GCM decryption", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "creating AES-GCM cipher", err)
	}

	plaintext, err := gcm.Open(nil, params.Nonce, ciphertext, nil)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "AES-GCM authentication tag verification failed", err)
	}
	return plaintext, nil
}

// decryptAESCBC decrypts AES-CBC ciphertext and removes PKCS#7 padding.
func decryptAESCBC(ciphertext, cek []byte, algID pkix.AlgorithmIdentifier) ([]byte, error) {
	var iv []byte
	if _, err := asn1.Unmarshal(algID.Parameters.FullBytes, &iv); err != nil {
		return nil, wrapError(CodeParse, "parsing AES-CBC IV", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, newError(CodeParse,
			fmt.Sprintf("AES-CBC IV must be %d bytes, got %d", aes.BlockSize, len(iv)))
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, newError(CodeInvalidSignature,
			"AES-CBC ciphertext length is not a multiple of block size")
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "creating AES cipher for CBC decryption", err)
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "removing PKCS#7 padding", err)
	}
	return unpadded, nil
}

// buildRSARecipientInfo builds a KeyTransRecipientInfo for an RSA recipient.
func buildRSARecipientInfo(cert *x509.Certificate, cek []byte) (asn1.RawValue, error) {
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return asn1.RawValue{}, newError(CodeUnsupportedAlgorithm, "recipient has non-RSA key")
	}

	encCEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, cek, nil)
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeInvalidSignature, "RSA-OAEP CEK encryption failed", err)
	}

	rid, err := marshalIssuerSerial(cert)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build RSA-OAEP AlgorithmIdentifier with SHA-256 parameters.
	oaepAlgID, err := rsaOAEPAlgID()
	if err != nil {
		return asn1.RawValue{}, err
	}

	ktri := pkiasn1.KeyTransRecipientInfo{
		Version:                0,
		RID:                    asn1.RawValue{FullBytes: rid},
		KeyEncryptionAlgorithm: oaepAlgID,
		EncryptedKey:           encCEK,
	}

	der, err := asn1.Marshal(ktri)
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeParse, "marshaling KeyTransRecipientInfo", err)
	}
	return asn1.RawValue{FullBytes: der}, nil
}

// buildECDHRecipientInfo builds a KeyAgreeRecipientInfo for an EC recipient.
func buildECDHRecipientInfo(cert *x509.Certificate, cek []byte) (asn1.RawValue, error) {
	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return asn1.RawValue{}, newError(CodeUnsupportedAlgorithm, "recipient has non-ECDSA key")
	}

	// Convert recipient public key to crypto/ecdh.
	recipPub, err := ecPub.ECDH()
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeUnsupportedAlgorithm,
			"converting recipient ECDSA public key to ECDH", err)
	}

	// Generate ephemeral key on the same curve.
	ephemPriv, err := recipPub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeParse, "generating ephemeral ECDH key", err)
	}

	// Compute shared secret.
	sharedSecret, err := ephemPriv.ECDH(recipPub)
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeParse, "computing ECDH shared secret", err)
	}

	// Choose key agreement OID and key wrap OID based on curve.
	kaOID, kwOID, err := ecdhOIDsForCurve(recipPub.Curve())
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Determine KEK length for the key wrap algorithm.
	kekLen, err := kekLengthForWrapOID(kwOID)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build KeyEncryptionAlgorithm: kaOID with nested key wrap AlgID as params.
	keaAlgID, err := ecdhKEAAlgID(kaOID, kwOID)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Derive KEK using X9.63 KDF.
	kek, err := x963KDF(sharedSecret, kekLen, keaAlgID)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Wrap CEK.
	wrappedCEK, err := aesKeyWrap(kek, cek)
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeParse, "AES key wrap of CEK failed", err)
	}

	// Build IssuerAndSerialNumber RID.
	ridBytes, err := marshalIssuerSerial(cert)
	if err != nil {
		return asn1.RawValue{}, err
	}

	rek := pkiasn1.RecipientEncryptedKey{
		RID:          asn1.RawValue{FullBytes: ridBytes},
		EncryptedKey: wrappedCEK,
	}

	// Encode the ephemeral public key as an OriginatorPublicKey.
	originatorBytes, err := marshalOriginatorPublicKey(ephemPriv.PublicKey(), recipPub.Curve())
	if err != nil {
		return asn1.RawValue{}, err
	}

	kari := pkiasn1.KeyAgreeRecipientInfo{
		Version:                3,
		Originator:             asn1.RawValue{FullBytes: originatorBytes},
		KeyEncryptionAlgorithm: keaAlgID,
		RecipientEncryptedKeys: []pkiasn1.RecipientEncryptedKey{rek},
	}

	// Marshal KARI as SEQUENCE first, then retag as [1] CONSTRUCTED.
	der, err := asn1.Marshal(kari)
	if err != nil {
		return asn1.RawValue{}, wrapError(CodeParse, "marshaling KeyAgreeRecipientInfo", err)
	}
	// Retag SEQUENCE (0x30) → [1] CONSTRUCTED (0xA1).
	der[0] = 0xA1
	return asn1.RawValue{FullBytes: der}, nil
}

// marshalOriginatorPublicKey encodes the ephemeral public key as the [0] EXPLICIT
// Originator field content expected by KeyAgreeRecipientInfo.
//
// RFC 5652 §6.2.2: Originator is [0] EXPLICIT CHOICE; the OriginatorPublicKey
// alternative is [1] IMPLICIT SubjectPublicKeyInfo-like structure.
// We build: [0] EXPLICIT { [1] IMPLICIT { AlgorithmIdentifier, BIT STRING } }
func marshalOriginatorPublicKey(pub *ecdh.PublicKey, curve ecdh.Curve) ([]byte, error) {
	curveOID, err := curveToOID(curve)
	if err != nil {
		return nil, err
	}

	curveOIDBytes, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling curve OID for originator key", err)
	}

	opk := pkiasn1.OriginatorPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  pkiasn1.OIDECPublicKey,
			Parameters: asn1.RawValue{FullBytes: curveOIDBytes},
		},
		PublicKey: asn1.BitString{Bytes: pub.Bytes(), BitLength: len(pub.Bytes()) * 8},
	}

	opkBytes, err := asn1.Marshal(opk)
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling OriginatorPublicKey", err)
	}
	// Retag SEQUENCE (0x30) → [1] CONSTRUCTED (0xA1) for the OriginatorPublicKey choice.
	opkBytes[0] = 0xA1

	// Wrap in [0] EXPLICIT for the Originator field.
	wrapped, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      opkBytes,
	})
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling Originator [0] EXPLICIT wrapper", err)
	}
	return wrapped, nil
}

// parseOriginatorPublicKey extracts the ephemeral *ecdh.PublicKey from the
// Originator RawValue in a KeyAgreeRecipientInfo.
//
// originator.Bytes contains the inner bytes of [0] EXPLICIT, which is the
// [1] CONSTRUCTED OriginatorPublicKey { AlgorithmIdentifier, BIT STRING }.
func parseOriginatorPublicKey(originator asn1.RawValue) (*ecdh.PublicKey, error) {
	// originator is the [0] EXPLICIT wrapper; its Bytes contain [1] IMPLICIT opk.
	inner := originator.Bytes
	if len(inner) == 0 {
		return nil, newError(CodeParse, "Originator field is empty")
	}

	// Retag [1] CONSTRUCTED (0xA1) → SEQUENCE (0x30) for OriginatorPublicKey.
	retagged := make([]byte, len(inner))
	copy(retagged, inner)
	retagged[0] = 0x30

	var opk pkiasn1.OriginatorPublicKey
	if _, err := asn1.Unmarshal(retagged, &opk); err != nil {
		return nil, wrapError(CodeParse, "parsing OriginatorPublicKey", err)
	}

	// Determine curve from algorithm parameters OID.
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(opk.Algorithm.Parameters.FullBytes, &curveOID); err != nil {
		return nil, wrapError(CodeParse, "parsing EC curve OID from OriginatorPublicKey", err)
	}

	curve, err := oidToCurve(curveOID)
	if err != nil {
		return nil, err
	}

	pub, err := curve.NewPublicKey(opk.PublicKey.Bytes)
	if err != nil {
		return nil, wrapError(CodeParse, "parsing ephemeral EC public key bytes", err)
	}
	return pub, nil
}

// marshalIssuerSerial returns the DER encoding of IssuerAndSerialNumber for cert.
func marshalIssuerSerial(cert *x509.Certificate) ([]byte, error) {
	isn := pkiasn1.IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	}
	der, err := asn1.Marshal(isn)
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling IssuerAndSerialNumber", err)
	}
	return der, nil
}

// rsaOAEPAlgID returns the AlgorithmIdentifier for RSA-OAEP with SHA-256 per RFC 4055.
func rsaOAEPAlgID() (pkix.AlgorithmIdentifier, error) {
	hashAlgID := pkix.AlgorithmIdentifier{Algorithm: pkiasn1.OIDDigestAlgorithmSHA256}
	mgf := pkix.AlgorithmIdentifier{
		Algorithm:  pkiasn1.OIDMGF1,
		Parameters: asn1.RawValue{FullBytes: marshalAlgID(hashAlgID)},
	}

	params := struct {
		Hash pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
		MGF  pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	}{
		Hash: hashAlgID,
		MGF:  mgf,
	}
	rawParams, err := asn1.Marshal(params)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "marshaling RSAES-OAEP params", err)
	}

	return pkix.AlgorithmIdentifier{
		Algorithm:  pkiasn1.OIDKeyTransportRSAOAEP,
		Parameters: asn1.RawValue{FullBytes: rawParams},
	}, nil
}

// marshalAlgID marshals an AlgorithmIdentifier, panicking on error (programming error).
func marshalAlgID(algID pkix.AlgorithmIdentifier) []byte {
	b, err := asn1.Marshal(algID)
	if err != nil {
		panic(fmt.Sprintf("cms: marshalAlgID: %v", err))
	}
	return b
}

// ecdhKEAAlgID builds the KeyEncryptionAlgorithm AlgorithmIdentifier for ECDH.
// The parameters field contains the key wrap AlgorithmIdentifier.
func ecdhKEAAlgID(kaOID, kwOID asn1.ObjectIdentifier) (pkix.AlgorithmIdentifier, error) {
	kwAlgID := pkix.AlgorithmIdentifier{Algorithm: kwOID}
	kwBytes, err := asn1.Marshal(kwAlgID)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, wrapError(CodeParse, "marshaling key wrap AlgID", err)
	}
	return pkix.AlgorithmIdentifier{
		Algorithm:  kaOID,
		Parameters: asn1.RawValue{FullBytes: kwBytes},
	}, nil
}

// ecdhOIDsForCurve returns the key agreement OID and key wrap OID for an ECDH curve.
func ecdhOIDsForCurve(curve ecdh.Curve) (kaOID, kwOID asn1.ObjectIdentifier, err error) {
	switch curve {
	case ecdh.P256():
		return pkiasn1.OIDKeyAgreeECDHSHA256, pkiasn1.OIDKeyWrapAES128, nil
	case ecdh.P384():
		return pkiasn1.OIDKeyAgreeECDHSHA384, pkiasn1.OIDKeyWrapAES256, nil
	case ecdh.P521():
		return pkiasn1.OIDKeyAgreeECDHSHA512, pkiasn1.OIDKeyWrapAES256, nil
	default:
		return nil, nil, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported ECDH curve %v", curve))
	}
}

// keyWrapOIDFromKEA extracts the key wrap OID from the KeyEncryptionAlgorithm params.
func keyWrapOIDFromKEA(keaAlgID pkix.AlgorithmIdentifier) (asn1.ObjectIdentifier, error) {
	var kwAlgID pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(keaAlgID.Parameters.FullBytes, &kwAlgID); err != nil {
		return nil, wrapError(CodeParse, "parsing key wrap AlgID from KARI KeyEncryptionAlgorithm", err)
	}
	return kwAlgID.Algorithm, nil
}

// kekLengthForWrapOID returns the KEK length in bytes for the given key wrap OID.
func kekLengthForWrapOID(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(pkiasn1.OIDKeyWrapAES128):
		return 16, nil
	case oid.Equal(pkiasn1.OIDKeyWrapAES256):
		return 32, nil
	default:
		return 0, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported key wrap OID %s", oid))
	}
}

// curveToOID maps an ecdh.Curve to its named curve OID.
func curveToOID(curve ecdh.Curve) (asn1.ObjectIdentifier, error) {
	switch curve {
	case ecdh.P256():
		return pkiasn1.OIDNamedCurveP256, nil
	case ecdh.P384():
		return pkiasn1.OIDNamedCurveP384, nil
	case ecdh.P521():
		return pkiasn1.OIDNamedCurveP521, nil
	default:
		return nil, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported EC curve %v", curve))
	}
}

// oidToCurve maps a named curve OID to an ecdh.Curve.
func oidToCurve(oid asn1.ObjectIdentifier) (ecdh.Curve, error) {
	switch {
	case oid.Equal(pkiasn1.OIDNamedCurveP256):
		return ecdh.P256(), nil
	case oid.Equal(pkiasn1.OIDNamedCurveP384):
		return ecdh.P384(), nil
	case oid.Equal(pkiasn1.OIDNamedCurveP521):
		return ecdh.P521(), nil
	default:
		return nil, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported EC curve OID %s", oid))
	}
}

// x963KDF implements the ANS X9.63 / SP 800-56A key derivation function.
// Z is the shared secret, keydatalen is the desired output length in bytes.
// algID is the key-agreement AlgorithmIdentifier; its OID is used as AlgorithmID
// in the OtherInfo structure.
//
// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
// AlgorithmID = key wrap OID DER bytes
// PartyUInfo = PartyVInfo = empty (not used)
// SuppPubInfo = 4-byte big-endian bit-length of KEK
func x963KDF(z []byte, keydatalen int, algID pkix.AlgorithmIdentifier) ([]byte, error) {
	// Extract key wrap OID from parameters; use it as AlgorithmID in OtherInfo.
	kwOID, err := keyWrapOIDFromKEA(algID)
	if err != nil {
		return nil, err
	}
	algorithmIDBytes, err := asn1.Marshal(kwOID)
	if err != nil {
		return nil, wrapError(CodeParse, "encoding key wrap OID for X9.63 KDF", err)
	}

	// SuppPubInfo: 4-byte big-endian encoding of keydatalen in bits.
	suppPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(suppPubInfo, uint32(keydatalen*8))

	// Determine hash function from key agreement OID.
	h, hLen, err := kdfHashForKAOID(algID.Algorithm)
	if err != nil {
		return nil, err
	}

	var result []byte
	for counter := uint32(1); len(result) < keydatalen; counter++ {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)

		h.Reset()
		h.Write(z)
		h.Write(counterBytes)
		h.Write(algorithmIDBytes)
		// PartyUInfo and PartyVInfo: each is a 4-byte zero length + empty value
		h.Write([]byte{0, 0, 0, 0}) // PartyUInfo length = 0
		h.Write([]byte{0, 0, 0, 0}) // PartyVInfo length = 0
		h.Write(suppPubInfo)
		result = append(result, h.Sum(nil)...)
		_ = hLen
	}

	return result[:keydatalen], nil
}

// kdfHashForKAOID returns the hash.Hash and output size for the given ECDH OID.
func kdfHashForKAOID(oid asn1.ObjectIdentifier) (kdfHash, int, error) {
	switch {
	case oid.Equal(pkiasn1.OIDKeyAgreeECDHSHA256):
		return sha256.New(), sha256.Size, nil
	case oid.Equal(pkiasn1.OIDKeyAgreeECDHSHA384):
		return sha512.New384(), sha512.Size384, nil
	case oid.Equal(pkiasn1.OIDKeyAgreeECDHSHA512):
		return sha512.New(), sha512.Size, nil
	default:
		return nil, 0, newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported key agreement OID for KDF: %s", oid))
	}
}

// aesKeyWrap implements RFC 3394 AES key wrap.
// kek must be 16 or 32 bytes; cek must be a multiple of 8 bytes.
func aesKeyWrap(kek, cek []byte) ([]byte, error) {
	if len(cek)%8 != 0 {
		return nil, newError(CodeParse, "AES key wrap: CEK length must be a multiple of 8 bytes")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, wrapError(CodeParse, "AES key wrap: creating cipher", err)
	}

	n := len(cek) / 8
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], cek[i*8:])
	}

	// Initial value.
	a := make([]byte, 8)
	for i := range a {
		a[i] = 0xA6
	}

	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i + 1)
			for k := 7; k >= 0; k-- {
				a[k] = buf[k] ^ byte(t)
				t >>= 8
			}
			copy(r[i], buf[8:])
		}
	}

	wrapped := make([]byte, 8*(n+1))
	copy(wrapped[:8], a)
	for i, ri := range r {
		copy(wrapped[8*(i+1):], ri)
	}
	return wrapped, nil
}

// aesKeyUnwrap implements RFC 3394 AES key unwrap.
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, newError(CodeInvalidSignature, "AES key unwrap: invalid wrapped key length")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, wrapError(CodeInvalidSignature, "AES key unwrap: creating cipher", err)
	}

	n := len(wrapped)/8 - 1
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], wrapped[8*(i+1):])
	}

	a := make([]byte, 8)
	copy(a, wrapped[:8])

	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			tmp := make([]byte, 8)
			copy(tmp, a)
			for k := 7; k >= 0; k-- {
				tmp[k] ^= byte(t)
				t >>= 8
			}
			copy(buf[:8], tmp)
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}

	// Verify integrity check value.
	for _, v := range a {
		if v != 0xA6 {
			return nil, newError(CodeInvalidSignature,
				"AES key unwrap: integrity check failed (wrong KEK or corrupted data)")
		}
	}

	cek := make([]byte, n*8)
	for i, ri := range r {
		copy(cek[i*8:], ri)
	}
	return cek, nil
}

// pkcs7Pad pads plaintext to a multiple of blockSize using PKCS#7.
func pkcs7Pad(plaintext []byte, blockSize int) []byte {
	pad := blockSize - len(plaintext)%blockSize
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding from plaintext.
func pkcs7Unpad(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, newError(CodeInvalidSignature, "PKCS#7 unpad: empty input")
	}
	pad := int(plaintext[len(plaintext)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, newError(CodeInvalidSignature,
			fmt.Sprintf("PKCS#7 unpad: invalid padding byte %d", pad))
	}
	if len(plaintext) < pad {
		return nil, newError(CodeInvalidSignature, "PKCS#7 unpad: padding exceeds data length")
	}
	for _, b := range plaintext[len(plaintext)-pad:] {
		if int(b) != pad {
			return nil, newError(CodeInvalidSignature, "PKCS#7 unpad: inconsistent padding bytes")
		}
	}
	return plaintext[:len(plaintext)-pad], nil
}

// marshalEnvelopedDataCI wraps EnvelopedData in a ContentInfo and returns DER bytes.
func marshalEnvelopedDataCI(ed pkiasn1.EnvelopedData) ([]byte, error) {
	edBytes, err := asn1.Marshal(ed)
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling EnvelopedData", err)
	}

	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      edBytes,
	})
	if err != nil {
		return nil, wrapError(CodeParse, "marshaling ContentInfo [0] wrapper for EnvelopedData", err)
	}

	ci := pkiasn1.ContentInfo{
		ContentType: pkiasn1.OIDEnvelopedData,
		Content:     asn1.RawValue{FullBytes: explicit0},
	}
	return asn1.Marshal(ci)
}

