package cms

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// TestSymmetricEncrypt_RoundTrip verifies that Encrypt and Decrypt round-trip
// correctly for all supported algorithm and key length combinations.
func TestSymmetricEncrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		alg     ContentEncryptionAlgorithm
		keyLen  int
		content []byte
	}{
		{"AES-256-GCM default", AES256GCM, 32, []byte("hello world")},
		{"AES-128-GCM", AES128GCM, 16, []byte("hello world")},
		{"AES-256-CBC", AES256CBC, 32, []byte("hello world")},
		{"AES-128-CBC", AES128CBC, 16, []byte("hello world")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x42}, tt.keyLen)

			der, err := NewSymmetricEncryptor().
				WithKey(key).
				WithContentEncryption(tt.alg).
				Encrypt(FromBytes(tt.content))
			require.NoError(t, err)

			p, err := ParseEncryptedData(FromBytes(der))
			require.NoError(t, err)

			plaintext, err := p.Decrypt(key)
			require.NoError(t, err)
			assert.Equal(t, tt.content, plaintext)
		})
	}
}

// TestSymmetricEncrypt_WrongKey verifies that decryption with an incorrect key
// (correct length, wrong bytes) returns ErrInvalidSignature for AES-GCM.
func TestSymmetricEncrypt_WrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	wrongKey := bytes.Repeat([]byte{0x02}, 32)
	content := []byte("secret content")

	der, err := NewSymmetricEncryptor().
		WithKey(key).
		Encrypt(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseEncryptedData(FromBytes(der))
	require.NoError(t, err)

	_, err = p.Decrypt(wrongKey)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

// TestSymmetricEncrypt_WrongKeyLength verifies that Decrypt returns
// ErrInvalidConfiguration when the supplied key length does not match
// the algorithm recorded in the EncryptedData.
func TestSymmetricEncrypt_WrongKeyLength(t *testing.T) {
	key32 := bytes.Repeat([]byte{0x42}, 32)
	content := []byte("content")

	// Encrypt with AES-256-GCM (expects 32-byte key).
	der, err := NewSymmetricEncryptor().
		WithKey(key32).
		Encrypt(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseEncryptedData(FromBytes(der))
	require.NoError(t, err)

	// Attempt to decrypt with a 16-byte key.
	_, err = p.Decrypt(bytes.Repeat([]byte{0x42}, 16))
	require.ErrorIs(t, err, ErrInvalidConfiguration)
}

// TestSymmetricEncrypt_NilKey verifies that Encrypt returns ErrInvalidConfiguration
// when no key is provided.
func TestSymmetricEncrypt_NilKey(t *testing.T) {
	_, err := NewSymmetricEncryptor().Encrypt(FromBytes([]byte("content")))
	require.ErrorIs(t, err, ErrInvalidConfiguration)
}

// TestSymmetricEncrypt_EmptyContent verifies that a zero-byte payload encrypts
// and decrypts correctly.
func TestSymmetricEncrypt_EmptyContent(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)

	der, err := NewSymmetricEncryptor().
		WithKey(key).
		Encrypt(FromBytes([]byte{}))
	require.NoError(t, err)

	p, err := ParseEncryptedData(FromBytes(der))
	require.NoError(t, err)

	plaintext, err := p.Decrypt(key)
	require.NoError(t, err)
	assert.Empty(t, plaintext)
}

// TestSymmetricEncrypt_PayloadTooLarge verifies that Encrypt returns
// ErrPayloadTooLarge when content exceeds the configured size limit.
func TestSymmetricEncrypt_PayloadTooLarge(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	content := bytes.Repeat([]byte("A"), 100)

	_, err := NewSymmetricEncryptor().
		WithKey(key).
		WithMaxContentSize(50).
		Encrypt(FromBytes(content))
	require.ErrorIs(t, err, ErrPayloadTooLarge)
}

// TestSymmetricEncrypt_ParseWrongContentType verifies that ParseEncryptedData
// returns ErrParse when the ContentInfo does not wrap an EncryptedData OID.
func TestSymmetricEncrypt_ParseWrongContentType(t *testing.T) {
	rsaCert, rsaKey := generateSelfSignedRSA(t, 2048)
	der, err := NewSigner().
		WithCertificate(rsaCert).
		WithPrivateKey(rsaKey).
		Sign(FromBytes([]byte("content")))
	require.NoError(t, err)

	_, err = ParseEncryptedData(FromBytes(der))
	require.ErrorIs(t, err, ErrParse)
}

// TestSymmetricEncrypt_KeyLengthMismatchBuilder verifies that the builder
// returns ErrInvalidConfiguration when the key length does not match the
// configured algorithm.
func TestSymmetricEncrypt_KeyLengthMismatchBuilder(t *testing.T) {
	// 16-byte key with AES-256-GCM (needs 32 bytes).
	key16 := bytes.Repeat([]byte{0x01}, 16)

	_, err := NewSymmetricEncryptor().
		WithKey(key16).
		WithContentEncryption(AES256GCM).
		Encrypt(FromBytes([]byte("content")))
	require.ErrorIs(t, err, ErrInvalidConfiguration)
}

// TestSymmetricEncrypt_CustomContentType verifies that a custom content type OID
// is preserved in the EncryptedContentInfo.
func TestSymmetricEncrypt_CustomContentType(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	content := []byte("custom type content")
	customOID := pkiasn1.OIDSignedData // arbitrary non-id-data OID

	der, err := NewSymmetricEncryptor().
		WithKey(key).
		WithContentType(customOID).
		Encrypt(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseEncryptedData(FromBytes(der))
	require.NoError(t, err)

	assert.True(t, p.encryptedData.EncryptedContentInfo.ContentType.Equal(customOID),
		"content type in EncryptedContentInfo should be the custom OID")

	plaintext, err := p.Decrypt(key)
	require.NoError(t, err)
	assert.Equal(t, content, plaintext)
}

// TestSymmetricEncrypt_BuilderEmptyOID verifies that an empty content type OID
// accumulates a configuration error.
func TestSymmetricEncrypt_BuilderEmptyOID(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)

	_, err := NewSymmetricEncryptor().
		WithKey(key).
		WithContentType(asn1.ObjectIdentifier{}).
		Encrypt(FromBytes([]byte("content")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration),
		"expected ErrInvalidConfiguration, got: %v", err)
}

// TestSymmetricEncrypt_WithKeyNilAccumulates verifies that WithKey(nil) accumulates
// a configuration error that is reported at Encrypt time.
func TestSymmetricEncrypt_WithKeyNilAccumulates(t *testing.T) {
	_, err := NewSymmetricEncryptor().
		WithKey(nil).
		Encrypt(FromBytes([]byte("content")))
	require.ErrorIs(t, err, ErrInvalidConfiguration)
}
