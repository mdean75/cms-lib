package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test certificate helpers ---

// generateSelfSignedRSA generates an RSA self-signed certificate for testing.
func generateSelfSignedRSA(t *testing.T, bits int) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return selfSigned(t, key.Public(), key, pkix.Name{CommonName: "test-rsa"}), key
}

// generateSelfSignedECDSA generates an ECDSA self-signed certificate for testing.
func generateSelfSignedECDSA(t *testing.T, curve elliptic.Curve) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return selfSigned(t, key.Public(), key, pkix.Name{CommonName: "test-ecdsa"}), key
}

// generateSelfSignedEd25519 generates an Ed25519 self-signed certificate for testing.
func generateSelfSignedEd25519(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return selfSigned(t, pub, priv, pkix.Name{CommonName: "test-ed25519"}), priv
}

// selfSigned creates a minimal self-signed certificate.
func selfSigned(t *testing.T, pub crypto.PublicKey, signer crypto.Signer, subject pkix.Name) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// --- Round-trip tests ---

func TestSignVerify_RSAPSSAttached(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	content := []byte("hello, cms")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithHash(crypto.SHA256).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)
	require.NotEmpty(t, der)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	err = parsed.Verify(WithTrustRoots(pool))
	require.NoError(t, err)

	assert.False(t, parsed.IsDetached())
	r, err := parsed.Content()
	require.NoError(t, err)
	var got bytes.Buffer
	_, err = got.ReadFrom(r)
	require.NoError(t, err)
	assert.Equal(t, content, got.Bytes())
}

func TestSignVerify_RSAPKCS1Attached(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	content := []byte("pkcs1v15 test")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithRSAPKCS1().
		WithHash(crypto.SHA256).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

func TestSignVerify_ECDSAAttached(t *testing.T) {
	cert, key := generateSelfSignedECDSA(t, elliptic.P256())
	content := []byte("ecdsa test")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithHash(crypto.SHA256).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

func TestSignVerify_Ed25519Attached(t *testing.T) {
	cert, key := generateSelfSignedEd25519(t)
	content := []byte("ed25519 test")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

func TestSignVerify_Detached(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	content := []byte("detached signature test")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithDetachedContent().
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	assert.True(t, parsed.IsDetached())

	// Content() must fail on a detached SignedData.
	_, err = parsed.Content()
	assert.True(t, errors.Is(err, ErrDetachedContentMismatch))

	// Verify() must also fail on a detached SignedData.
	err = parsed.Verify()
	assert.True(t, errors.Is(err, ErrDetachedContentMismatch))

	// VerifyDetached with the correct content must succeed.
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.VerifyDetached(bytes.NewReader(content), WithTrustRoots(pool)))
}

func TestSignVerify_ZeroBytePayload(t *testing.T) {
	// A signed 0-byte payload must be preserved as present (not treated as detached).
	cert, key := generateSelfSignedRSA(t, 2048)

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader([]byte{}))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	assert.False(t, parsed.IsDetached(),
		"signed 0-byte payload must not be treated as detached")

	r, err := parsed.Content()
	require.NoError(t, err)
	var got bytes.Buffer
	_, err = got.ReadFrom(r)
	require.NoError(t, err)
	assert.Equal(t, []byte{}, got.Bytes(),
		"content of a 0-byte payload must be empty, not nil")

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

func TestSignVerify_VerifyDetachedOnAttached(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	content := []byte("attached")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	err = parsed.VerifyDetached(bytes.NewReader(content))
	assert.True(t, errors.Is(err, ErrDetachedContentMismatch))
}

// --- Builder validation tests ---

func TestSigner_NilCertificateError(t *testing.T) {
	_, err := NewSigner().
		WithCertificate(nil).
		WithPrivateKey(dummyKey(t)).
		Sign(bytes.NewReader([]byte("x")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration))
}

func TestSigner_NilKeyError(t *testing.T) {
	cert, _ := generateSelfSignedRSA(t, 2048)
	_, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(nil).
		Sign(bytes.NewReader([]byte("x")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration))
}

func TestSigner_MultipleConfigErrors(t *testing.T) {
	// Both nil cert and nil key should be reported together.
	_, err := NewSigner().
		WithCertificate(nil).
		WithPrivateKey(nil).
		Sign(bytes.NewReader([]byte("x")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration))
	assert.Contains(t, err.Error(), "certificate is nil")
	assert.Contains(t, err.Error(), "private key is nil")
}

func TestSigner_ReservedAttributeRejected(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	oidMessageDigest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	_, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		AddAuthenticatedAttribute(oidMessageDigest, []byte("fake")).
		Sign(bytes.NewReader([]byte("x")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAttributeInvalid))
}

// --- Size limit tests ---

func TestSigner_PayloadTooLarge(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	// Set a 10-byte limit and provide 11 bytes.
	_, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithMaxAttachedContentSize(10).
		Sign(bytes.NewReader(make([]byte, 11)))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPayloadTooLarge))
}

func TestSigner_PayloadAtLimit(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	// Exactly at limit must succeed.
	_, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithMaxAttachedContentSize(10).
		Sign(bytes.NewReader(make([]byte, 10)))
	require.NoError(t, err)
}

func TestSigner_UnlimitedSize(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	// Unlimiteds must not be rejected even for large content.
	content := make([]byte, 1024*1024) // 1 MiB
	_, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithMaxAttachedContentSize(UnlimitedAttachedSize).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)
}

// --- SubjectKeyIdentifier variant ---

func TestSignVerify_SubjectKeyIdentifier(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithSignerIdentifier(SubjectKeyIdentifier).
		Sign(bytes.NewReader([]byte("ski test")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

// --- Chain validation options ---

func TestVerify_NoChainValidation(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	content := []byte("no chain")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	// Self-signed cert would fail chain validation with a real trust store;
	// WithNoChainValidation should allow it to pass with math-only verification.
	require.NoError(t, parsed.Verify(WithNoChainValidation()))
}

func TestVerify_WrongTrustRoot(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	otherCert, _ := generateSelfSignedRSA(t, 2048)

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader([]byte("trust root test")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	// Using a pool that does not contain the signing cert's issuer must fail.
	pool := x509.NewCertPool()
	pool.AddCert(otherCert)
	err = parsed.Verify(WithTrustRoots(pool))
	assert.True(t, errors.Is(err, ErrCertificateChain))
}

// --- Tampered content detection ---

func TestVerify_TamperedContent(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	original := []byte("original content")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithDetachedContent().
		Sign(bytes.NewReader(original))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	tampered := []byte("tampered content")
	err = parsed.VerifyDetached(bytes.NewReader(tampered), WithNoChainValidation())
	assert.True(t, errors.Is(err, ErrAttributeInvalid),
		"tampered content must produce a message-digest mismatch error")
}

// --- ECDSA curve variants ---

func TestSignVerify_ECDSAP384(t *testing.T) {
	cert, key := generateSelfSignedECDSA(t, elliptic.P384())

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithHash(crypto.SHA384).
		Sign(bytes.NewReader([]byte("p384")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

func TestSignVerify_ECDSAP521(t *testing.T) {
	cert, key := generateSelfSignedECDSA(t, elliptic.P521())

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithHash(crypto.SHA512).
		Sign(bytes.NewReader([]byte("p521")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

// --- Ed25519 hash override ---

func TestSignVerify_Ed25519HashIgnored(t *testing.T) {
	// Even when WithHash(SHA256) is specified for Ed25519, the library must
	// override it to SHA-512 per RFC 8419 without returning an error.
	cert, key := generateSelfSignedEd25519(t)

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithHash(crypto.SHA256). // must be silently overridden for Ed25519
		Sign(bytes.NewReader([]byte("ed25519 hash override")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

// --- Custom authenticated attributes ---

func TestSignVerify_CustomAuthenticatedAttribute(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		AddAuthenticatedAttribute(customOID, "custom-value").
		Sign(bytes.NewReader([]byte("custom attr test")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

// --- Verify time ---

func TestVerify_ExpiredCertificate(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader([]byte("expired cert")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	// Verifying at a time outside the certificate's validity window must fail.
	pastTime := cert.NotBefore.Add(-time.Hour)
	err = parsed.Verify(WithTrustRoots(pool), WithVerifyTime(pastTime))
	assert.True(t, errors.Is(err, ErrCertificateChain),
		"verification at a time before certificate NotBefore must fail chain validation")
}

// --- ParseSignedData errors ---

func TestParseSignedData_EmptyInput(t *testing.T) {
	_, err := ParseSignedData(bytes.NewReader(nil))
	require.Error(t, err)
}

func TestParseSignedData_GarbageInput(t *testing.T) {
	_, err := ParseSignedData(bytes.NewReader([]byte{0xFF, 0xFE, 0xFD}))
	require.Error(t, err)
}

// --- Benchmark ---

var benchSignResult []byte

func BenchmarkSign_RSAPSSAttached(b *testing.B) {
	cert, key := benchRSACert(b)
	content := make([]byte, 1024)

	signer := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key)

	var r []byte
	for b.Loop() {
		var err error
		r, err = signer.Sign(bytes.NewReader(content))
		if err != nil {
			b.Fatal(err)
		}
	}
	benchSignResult = r
}

func benchRSACert(b *testing.B) (*x509.Certificate, *rsa.PrivateKey) {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3, 4, 5},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	return cert, key
}

// dummyKey returns a minimal crypto.Signer for use in builder error tests.
func dummyKey(t *testing.T) crypto.Signer {
	t.Helper()
	_, key := generateSelfSignedRSA(t, 2048)
	return key
}

// --- WithContentType ---

func TestSignVerify_WithContentType(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	customOID := asn1.ObjectIdentifier{1, 2, 3, 99, 1}
	content := []byte("custom content type")

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithContentType(customOID).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

func TestSigner_EmptyContentTypeOIDError(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	_, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithContentType(asn1.ObjectIdentifier{}).
		Sign(bytes.NewReader([]byte("x")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration))
}

// --- AddCertificate ---

func TestSignVerify_AddCertificate(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	extra, _ := generateSelfSignedRSA(t, 2048)

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		AddCertificate(extra).
		Sign(bytes.NewReader([]byte("extra cert")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	// Both the signing cert and the extra cert must be embedded.
	assert.Len(t, parsed.Certificates(), 2)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

// --- AddUnauthenticatedAttribute ---

func TestSignVerify_AddUnauthenticatedAttribute(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	customOID := asn1.ObjectIdentifier{1, 2, 3, 99, 2}

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		AddUnauthenticatedAttribute(customOID, "unauth-value").
		Sign(bytes.NewReader([]byte("unauth attr test")))
	require.NoError(t, err)

	// Unsigned attrs do not affect signature validity.
	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

// --- Multiple signers ---

func TestSignVerify_MultipleSigners(t *testing.T) {
	cert1, key1 := generateSelfSignedRSA(t, 2048)
	cert2, key2 := generateSelfSignedECDSA(t, elliptic.P256())
	content := []byte("multi-signer content")

	second := NewSigner().
		WithCertificate(cert2).
		WithPrivateKey(key2).
		WithHash(crypto.SHA256)

	der, err := NewSigner().
		WithCertificate(cert1).
		WithPrivateKey(key1).
		WithAdditionalSigner(second).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	// Both certificates must be embedded.
	assert.Len(t, parsed.Certificates(), 2)

	// Verification must succeed for both signers.
	pool := x509.NewCertPool()
	pool.AddCert(cert1)
	pool.AddCert(cert2)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

func TestSigner_NilAdditionalSignerError(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	_, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		WithAdditionalSigner(nil).
		Sign(bytes.NewReader([]byte("x")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration))
}

// --- CRL embedding ---

func TestSignVerify_CRLEmbedding(t *testing.T) {
	// Need a CA cert with KeyUsageCRLSign to issue the CRL.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{9, 8, 7, 6, 5},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	cert, key := generateSelfSignedRSA(t, 2048)

	// Generate a minimal CRL signed by the CA.
	crlTemplate := &x509.RevocationList{
		Number: big.NewInt(1),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)
	_ = caCert

	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		AddCRL(crlBytes).
		Sign(bytes.NewReader([]byte("crl test")))
	require.NoError(t, err)

	parsed, err := ParseSignedData(bytes.NewReader(der))
	require.NoError(t, err)

	crls := parsed.CRLs()
	assert.Len(t, crls, 1)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))
}

// --- CounterSign ---

func TestCounterSign_RSAPSSAttached(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	content := []byte("counter-sign test")

	// Produce the original SignedData.
	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader(content))
	require.NoError(t, err)

	// Counter-sign with a second key.
	csCert, csKey := generateSelfSignedRSA(t, 2048)
	counterDER, err := NewCounterSigner().
		WithCertificate(csCert).
		WithPrivateKey(csKey).
		CounterSign(bytes.NewReader(der))
	require.NoError(t, err)
	require.NotEmpty(t, counterDER)

	// The result must still parse and verify as a normal SignedData.
	parsed, err := ParseSignedData(bytes.NewReader(counterDER))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	require.NoError(t, parsed.Verify(WithTrustRoots(pool)))

	// The counter-signer's cert must be embedded.
	certFound := false
	for _, c := range parsed.Certificates() {
		if bytes.Equal(c.Raw, csCert.Raw) {
			certFound = true
			break
		}
	}
	assert.True(t, certFound, "counter-signer certificate must be embedded in SignedData")
}

func TestCounterSign_NilCertError(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader([]byte("x")))
	require.NoError(t, err)

	_, err = NewCounterSigner().
		WithCertificate(nil).
		WithPrivateKey(dummyKey(t)).
		CounterSign(bytes.NewReader(der))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration))
}
