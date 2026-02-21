package cms

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkiasn1 "github.com/mdean75/cms/internal/asn1"
)

// TestAuthenticate_RSA_RoundTrip verifies that Authenticate and VerifyMAC
// round-trip correctly for all HMAC algorithm variants with an RSA recipient.
func TestAuthenticate_RSA_RoundTrip(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	plaintext := []byte("authenticated content")

	tests := []struct {
		name string
		alg  MACAlgorithm
	}{
		{"RSA + HMAC-SHA256", HMACSHA256},
		{"RSA + HMAC-SHA384", HMACSHA384},
		{"RSA + HMAC-SHA512", HMACSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := NewAuthenticator().
				WithRecipient(cert).
				WithMACAlgorithm(tt.alg).
				Authenticate(FromBytes(plaintext))
			require.NoError(t, err)
			require.NotEmpty(t, der)

			parsed, err := ParseAuthenticatedData(FromBytes(der))
			require.NoError(t, err)

			require.NoError(t, parsed.VerifyMAC(key, cert))

			r, err := parsed.Content()
			require.NoError(t, err)
			got, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

// TestAuthenticate_ECDH_RoundTrip verifies that Authenticate and VerifyMAC
// round-trip correctly for P-256 and P-384 EC recipients.
func TestAuthenticate_ECDH_RoundTrip(t *testing.T) {
	plaintext := []byte("ecdh authenticated content")

	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"ECDH P-256 + HMAC-SHA256", elliptic.P256()},
		{"ECDH P-384 + HMAC-SHA256", elliptic.P384()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key := generateSelfSignedECDSA(t, tt.curve)

			der, err := NewAuthenticator().
				WithRecipient(cert).
				Authenticate(FromBytes(plaintext))
			require.NoError(t, err)
			require.NotEmpty(t, der)

			parsed, err := ParseAuthenticatedData(FromBytes(der))
			require.NoError(t, err)

			require.NoError(t, parsed.VerifyMAC(key, cert))
		})
	}
}

// TestAuthenticate_MultiRecipient verifies that multiple recipients (one RSA,
// one EC) can each independently verify the MAC.
func TestAuthenticate_MultiRecipient(t *testing.T) {
	rsaCert, rsaKey := generateSelfSignedRSA(t, 2048)
	ecCert, ecKey := generateSelfSignedECDSA(t, elliptic.P256())
	plaintext := []byte("multi-recipient authenticated content")

	der, err := NewAuthenticator().
		WithRecipient(rsaCert).
		WithRecipient(ecCert).
		Authenticate(FromBytes(plaintext))
	require.NoError(t, err)

	parsed, err := ParseAuthenticatedData(FromBytes(der))
	require.NoError(t, err)

	require.NoError(t, parsed.VerifyMAC(rsaKey, rsaCert), "RSA recipient should verify")
	require.NoError(t, parsed.VerifyMAC(ecKey, ecCert), "EC recipient should verify")
}

// TestAuthenticate_WrongKey verifies that VerifyMAC returns ErrMissingCertificate
// when the certificate is not present in any RecipientInfo.
func TestAuthenticate_WrongKey(t *testing.T) {
	cert, _ := generateSelfSignedRSA(t, 2048)
	// A completely different cert/key pair — not added as a recipient.
	wrongCert, wrongKey := generateSelfSignedRSA(t, 2048)

	der, err := NewAuthenticator().
		WithRecipient(cert).
		Authenticate(FromBytes([]byte("content")))
	require.NoError(t, err)

	parsed, err := ParseAuthenticatedData(FromBytes(der))
	require.NoError(t, err)

	err = parsed.VerifyMAC(wrongKey, wrongCert)
	require.ErrorIs(t, err, ErrMissingCertificate)
}

// TestAuthenticate_TamperedMAC verifies that VerifyMAC returns ErrInvalidSignature
// when the MAC bytes have been corrupted.
func TestAuthenticate_TamperedMAC(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	der, err := NewAuthenticator().
		WithRecipient(cert).
		Authenticate(FromBytes([]byte("original content")))
	require.NoError(t, err)

	// Flip the last byte of the DER to corrupt the MAC.
	der[len(der)-1] ^= 0xFF

	// Parsing may succeed or fail depending on where the corruption lands.
	parsed, err := ParseAuthenticatedData(FromBytes(der))
	if err != nil {
		require.ErrorIs(t, err, ErrParse)
		return
	}

	err = parsed.VerifyMAC(key, cert)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

// TestAuthenticate_TamperedContent verifies that VerifyMAC returns
// ErrInvalidSignature when the encapsulated content has been tampered with
// (content digest in message-digest authAttr no longer matches the content).
func TestAuthenticate_TamperedContent(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	der, err := NewAuthenticator().
		WithRecipient(cert).
		Authenticate(FromBytes([]byte("original content")))
	require.NoError(t, err)

	// Re-parse so we can manipulate the struct.
	parsed, err := ParseAuthenticatedData(FromBytes(der))
	require.NoError(t, err)

	// Replace eContent with different bytes, keeping the original authAttrs
	// (which still carry the digest of "original content"). Re-encode the
	// modified structure through DER so RawValue.Bytes fields are populated.
	tampered := []byte("tampered content !!")
	eci, err := buildAttachedECI(tampered, pkiasn1.OIDData)
	require.NoError(t, err)
	parsed.authenticatedData.EncapContentInfo = eci

	reencoded, err := marshalAuthenticatedDataCI(parsed.authenticatedData)
	require.NoError(t, err)

	reparsed, err := ParseAuthenticatedData(FromBytes(reencoded))
	require.NoError(t, err)

	err = reparsed.VerifyMAC(key, cert)
	require.ErrorIs(t, err, ErrAttributeInvalid)
}

// TestAuthenticate_EmptyContent verifies that a zero-byte payload authenticates
// and verifies correctly.
func TestAuthenticate_EmptyContent(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)

	der, err := NewAuthenticator().
		WithRecipient(cert).
		Authenticate(FromBytes([]byte{}))
	require.NoError(t, err)

	parsed, err := ParseAuthenticatedData(FromBytes(der))
	require.NoError(t, err)

	require.NoError(t, parsed.VerifyMAC(key, cert))

	r, err := parsed.Content()
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestAuthenticate_PayloadTooLarge verifies that Authenticate returns
// ErrPayloadTooLarge when content exceeds the configured size limit.
func TestAuthenticate_PayloadTooLarge(t *testing.T) {
	cert, _ := generateSelfSignedRSA(t, 2048)
	content := bytes.Repeat([]byte("A"), 100)

	_, err := NewAuthenticator().
		WithRecipient(cert).
		WithMaxContentSize(50).
		Authenticate(FromBytes(content))
	require.ErrorIs(t, err, ErrPayloadTooLarge)
}

// TestAuthenticate_NoRecipients verifies that Authenticate returns
// ErrInvalidConfiguration when no recipients are configured.
func TestAuthenticate_NoRecipients(t *testing.T) {
	_, err := NewAuthenticator().Authenticate(FromBytes([]byte("content")))
	require.ErrorIs(t, err, ErrInvalidConfiguration)
}

// TestAuthenticate_NilCert verifies that WithRecipient(nil) accumulates a
// configuration error reported at Authenticate time.
func TestAuthenticate_NilCert(t *testing.T) {
	_, err := NewAuthenticator().
		WithRecipient(nil).
		Authenticate(FromBytes([]byte("content")))
	require.ErrorIs(t, err, ErrInvalidConfiguration)
}

// TestAuthenticate_UnsupportedKeyType verifies that WithRecipient returns
// ErrUnsupportedAlgorithm for a certificate with an Ed25519 public key.
func TestAuthenticate_UnsupportedKeyType(t *testing.T) {
	edCert, _ := generateSelfSignedEd25519(t)

	_, err := NewAuthenticator().
		WithRecipient(edCert).
		Authenticate(FromBytes([]byte("content")))
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// TestAuthenticate_ParseWrongContentType verifies that ParseAuthenticatedData
// returns ErrParse when the ContentInfo does not wrap an AuthenticatedData OID.
func TestAuthenticate_ParseWrongContentType(t *testing.T) {
	rsaCert, rsaKey := generateSelfSignedRSA(t, 2048)
	der, err := NewSigner().
		WithCertificate(rsaCert).
		WithPrivateKey(rsaKey).
		Sign(FromBytes([]byte("content")))
	require.NoError(t, err)

	_, err = ParseAuthenticatedData(FromBytes(der))
	require.ErrorIs(t, err, ErrParse)
}

// TestAuthenticate_CustomContentType verifies that a custom eContentType OID
// results in version 1 in the AuthenticatedData output (RSA KTRI + non-id-data).
func TestAuthenticate_CustomContentType(t *testing.T) {
	cert, key := generateSelfSignedRSA(t, 2048)
	customOID := pkiasn1.OIDSignedData // arbitrary non-id-data OID
	content := []byte("custom type content")

	der, err := NewAuthenticator().
		WithRecipient(cert).
		WithContentType(customOID).
		Authenticate(FromBytes(content))
	require.NoError(t, err)

	parsed, err := ParseAuthenticatedData(FromBytes(der))
	require.NoError(t, err)

	assert.Equal(t, 1, parsed.authenticatedData.Version,
		"version should be 1 for KTRI + non-id-data content type")
	assert.True(t, parsed.authenticatedData.EncapContentInfo.EContentType.Equal(customOID),
		"eContentType should be the custom OID")

	require.NoError(t, parsed.VerifyMAC(key, cert))
}

// TestAuthenticate_ECDHVersion verifies that AuthenticatedData version is 2
// when any recipient uses KARI (EC key).
func TestAuthenticate_ECDHVersion(t *testing.T) {
	cert, key := generateSelfSignedECDSA(t, elliptic.P256())

	der, err := NewAuthenticator().
		WithRecipient(cert).
		Authenticate(FromBytes([]byte("content")))
	require.NoError(t, err)

	parsed, err := ParseAuthenticatedData(FromBytes(der))
	require.NoError(t, err)

	assert.Equal(t, 2, parsed.authenticatedData.Version,
		"version should be 2 when any KARI recipient is present")

	require.NoError(t, parsed.VerifyMAC(key, cert))
}

// TestAuthenticate_EmptyOID verifies that WithContentType(empty) accumulates a
// configuration error.
func TestAuthenticate_EmptyOID(t *testing.T) {
	cert, _ := generateSelfSignedRSA(t, 2048)

	_, err := NewAuthenticator().
		WithRecipient(cert).
		WithContentType(asn1.ObjectIdentifier{}).
		Authenticate(FromBytes([]byte("content")))
	require.ErrorIs(t, err, ErrInvalidConfiguration)
}

