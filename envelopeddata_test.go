package cms

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptDecrypt_RSA covers RSA-OAEP key transport with all content
// encryption algorithm variants.
func TestEncryptDecrypt_RSA(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	plaintext := []byte("hello enveloped world")

	tests := []struct {
		name string
		alg  ContentEncryptionAlgorithm
	}{
		{"RSA-OAEP + AES-256-GCM (default)", AES256GCM},
		{"RSA-OAEP + AES-128-GCM", AES128GCM},
		{"RSA-OAEP + AES-256-CBC", AES256CBC},
		{"RSA-OAEP + AES-128-CBC", AES128CBC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := NewEncryptor().
				WithRecipient(cert).
				WithContentEncryption(tt.alg).
				Encrypt(bytes.NewReader(plaintext))
			require.NoError(t, err)
			require.NotEmpty(t, der)

			parsed, err := ParseEnvelopedData(bytes.NewReader(der))
			require.NoError(t, err)

			got, err := parsed.Decrypt(key, cert)
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

// TestEncryptDecrypt_ECDH covers ECDH ephemeral-static key agreement for P-256
// and P-384 recipient keys.
func TestEncryptDecrypt_ECDH(t *testing.T) {
	plaintext := []byte("ecdh encrypted content")

	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"ECDH P-256 + AES-256-GCM", elliptic.P256()},
		{"ECDH P-384 + AES-256-GCM", elliptic.P384()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key := generateSelfSignedECDSA(t, tt.curve)

			der, err := NewEncryptor().
				WithRecipient(cert).
				WithContentEncryption(AES256GCM).
				Encrypt(bytes.NewReader(plaintext))
			require.NoError(t, err)
			require.NotEmpty(t, der)

			parsed, err := ParseEnvelopedData(bytes.NewReader(der))
			require.NoError(t, err)

			got, err := parsed.Decrypt(key, cert)
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

// TestEncryptDecrypt_MultipleRecipients verifies that both an RSA and an EC
// recipient can independently decrypt the same EnvelopedData.
func TestEncryptDecrypt_MultipleRecipients(t *testing.T) {
	rsaCert, rsaKey := generateSelfSignedRSA(t, 2048)
	ecCert, ecKey := generateSelfSignedECDSA(t, elliptic.P256())
	plaintext := []byte("multi-recipient message")

	der, err := NewEncryptor().
		WithRecipient(rsaCert).
		WithRecipient(ecCert).
		WithContentEncryption(AES256GCM).
		Encrypt(bytes.NewReader(plaintext))
	require.NoError(t, err)

	// RSA recipient decrypts.
	parsed, err := ParseEnvelopedData(bytes.NewReader(der))
	require.NoError(t, err)
	got, err := parsed.Decrypt(rsaKey, rsaCert)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// EC recipient also decrypts the same ciphertext.
	parsed2, err := ParseEnvelopedData(bytes.NewReader(der))
	require.NoError(t, err)
	got2, err := parsed2.Decrypt(ecKey, ecCert)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got2)
}

// TestDecrypt_WrongKey verifies that using the wrong private key causes
// a decryption failure rather than silently returning garbage.
func TestDecrypt_WrongKey(t *testing.T) {
	cert, _ := generateSelfSignedRSA(t, 2048)
	wrongCert, wrongKey := generateSelfSignedRSA(t, 2048)

	der, err := NewEncryptor().
		WithRecipient(cert).
		Encrypt(bytes.NewReader([]byte("secret")))
	require.NoError(t, err)

	parsed, err := ParseEnvelopedData(bytes.NewReader(der))
	require.NoError(t, err)

	// Wrong cert → no matching RecipientInfo.
	_, err = parsed.Decrypt(wrongKey, wrongCert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingCertificate),
		"expected ErrMissingCertificate, got %v", err)
}

// TestDecrypt_WrongKeyECDH verifies wrong-cert behaviour for ECDH recipients.
func TestDecrypt_WrongKeyECDH(t *testing.T) {
	cert, _ := generateSelfSignedECDSA(t, elliptic.P256())
	wrongCert, wrongKey := generateSelfSignedECDSA(t, elliptic.P256())

	der, err := NewEncryptor().
		WithRecipient(cert).
		Encrypt(bytes.NewReader([]byte("secret")))
	require.NoError(t, err)

	parsed, err := ParseEnvelopedData(bytes.NewReader(der))
	require.NoError(t, err)

	_, err = parsed.Decrypt(wrongKey, wrongCert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingCertificate),
		"expected ErrMissingCertificate, got %v", err)
}

// TestEncryptDecrypt_EmptyContent verifies that 0-byte plaintext round-trips
// correctly for both GCM and CBC modes.
func TestEncryptDecrypt_EmptyContent(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	for _, alg := range []ContentEncryptionAlgorithm{AES256GCM, AES256CBC} {
		der, err := NewEncryptor().
			WithRecipient(cert).
			WithContentEncryption(alg).
			Encrypt(bytes.NewReader(nil))
		require.NoError(t, err)

		parsed, err := ParseEnvelopedData(bytes.NewReader(der))
		require.NoError(t, err)

		got, err := parsed.Decrypt(key, cert)
		require.NoError(t, err)
		assert.Empty(t, got)
	}
}

// TestEncrypt_PayloadTooLarge verifies that content exceeding the limit is rejected.
func TestEncrypt_PayloadTooLarge(t *testing.T) {
	cert, _ := generateSelfSignedRSA(t, 2048)

	// 11 bytes with a 10-byte limit.
	payload := strings.Repeat("x", 11)
	_, err := NewEncryptor().
		WithRecipient(cert).
		WithMaxContentSize(10).
		Encrypt(strings.NewReader(payload))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPayloadTooLarge))
}

// TestEncryptor_BuilderErrors verifies that configuration errors are accumulated
// and reported by Encrypt.
func TestEncryptor_BuilderErrors(t *testing.T) {
	tests := []struct {
		name    string
		build   func() *Encryptor
		wantErr bool
		errMsg  string
	}{
		{
			name: "nil certificate",
			build: func() *Encryptor {
				return NewEncryptor().WithRecipient(nil)
			},
			wantErr: true,
			errMsg:  "certificate is nil",
		},
		{
			name: "no recipients",
			build: func() *Encryptor {
				return NewEncryptor()
			},
			wantErr: true,
			errMsg:  "at least one recipient is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.build().Encrypt(bytes.NewReader([]byte("data")))
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidConfiguration))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestEncryptor_UnsupportedKeyType verifies that a certificate with an
// unsupported public key type is rejected at WithRecipient time.
func TestEncryptor_UnsupportedKeyType(t *testing.T) {
	// Ed25519 certificate — unsupported for key transport.
	cert, _ := generateSelfSignedEd25519(t)
	_, err := NewEncryptor().
		WithRecipient(cert).
		Encrypt(bytes.NewReader([]byte("data")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupportedAlgorithm))
}

// TestEncryptDecrypt_Defaults verifies that NewEncryptor defaults (AES-256-GCM)
// produce a working round-trip without explicit algorithm selection.
func TestEncryptDecrypt_Defaults(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	plaintext := []byte("default algorithm test")

	der, err := NewEncryptor().
		WithRecipient(cert).
		Encrypt(bytes.NewReader(plaintext))
	require.NoError(t, err)

	parsed, err := ParseEnvelopedData(bytes.NewReader(der))
	require.NoError(t, err)

	got, err := parsed.Decrypt(key, cert)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestParseEnvelopedData_WrongContentType verifies that parsing data with a
// mismatched ContentType OID returns a CodeParse error.
func TestParseEnvelopedData_WrongContentType(t *testing.T) {
	// Use a SignedData DER as wrong-type input.
	cert, key := generateSelfSignedRSA(t, 2048)
	der, err := NewSigner().
		WithCertificate(cert).
		WithPrivateKey(key).
		Sign(bytes.NewReader([]byte("signed not enveloped")))
	require.NoError(t, err)

	_, err = ParseEnvelopedData(bytes.NewReader(der))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrParse))
}

// BenchmarkEncrypt benchmarks a single RSA-OAEP + AES-256-GCM Encrypt call.
// Certificate generation happens in TestMain-style setup via a sub-test.
var benchEnvelopedResult []byte

func BenchmarkEncrypt_RSAOAEP_AES256GCM(b *testing.B) {
	t := &testing.T{}
	cert, _ := generateSelfSignedRSA(t, 2048)

	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	enc := NewEncryptor().
		WithRecipient(cert).
		WithContentEncryption(AES256GCM)

	var (
		result []byte
		err    error
	)
	for b.Loop() {
		result, err = enc.Encrypt(bytes.NewReader(plaintext))
		if err != nil {
			b.Fatal(err)
		}
	}
	benchEnvelopedResult = result
}
