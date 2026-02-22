package cms

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// TestDigest_AttachedHashAlgorithms verifies that Digest() and Verify() round-trip
// correctly for each supported hash algorithm with attached content.
func TestDigest_AttachedHashAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA-256", crypto.SHA256},
		{"SHA-384", crypto.SHA384},
		{"SHA-512", crypto.SHA512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := []byte("hello world")
			der, err := NewDigester().
				WithHash(tt.hash).
				Digest(FromBytes(content))
			require.NoError(t, err)

			p, err := ParseDigestedData(FromBytes(der))
			require.NoError(t, err)
			require.NoError(t, p.Verify())
		})
	}
}

// TestDigest_DetachedMode verifies that detached DigestedData round-trips correctly
// and that calling Verify (without content) returns ErrDetachedContentMismatch.
func TestDigest_DetachedMode(t *testing.T) {
	content := []byte("hello world")

	der, err := NewDigester().
		WithDetachedContent().
		Digest(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)

	require.True(t, p.IsDetached())
	require.NoError(t, p.VerifyDetached(FromBytes(content)))
	require.ErrorIs(t, p.Verify(), ErrDetachedContentMismatch)
}

// TestDigest_AttachedVerifyDetachedReturnsError verifies that VerifyDetached
// returns ErrDetachedContentMismatch when called on attached DigestedData.
func TestDigest_AttachedVerifyDetachedReturnsError(t *testing.T) {
	content := []byte("hello world")

	der, err := NewDigester().Digest(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)

	require.False(t, p.IsDetached())
	require.NoError(t, p.Verify())
	require.ErrorIs(t, p.VerifyDetached(FromBytes(content)), ErrDetachedContentMismatch)
}

// TestDigest_ContentReturnsCorrectBytes verifies that Content() returns the
// original content bytes exactly.
func TestDigest_ContentReturnsCorrectBytes(t *testing.T) {
	content := []byte("test content bytes")

	der, err := NewDigester().Digest(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)

	r, err := p.Content()
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	assert.Equal(t, content, buf.Bytes())
}

// TestDigest_ContentOnDetachedReturnsError verifies that Content() returns
// ErrDetachedContentMismatch when called on a detached DigestedData.
func TestDigest_ContentOnDetachedReturnsError(t *testing.T) {
	content := []byte("hello")
	der, err := NewDigester().WithDetachedContent().Digest(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)

	_, err = p.Content()
	require.ErrorIs(t, err, ErrDetachedContentMismatch)
}

// TestDigest_TamperedDigest verifies that modifying the stored Digest bytes
// causes Verify to return ErrInvalidSignature.
func TestDigest_TamperedDigest(t *testing.T) {
	content := []byte("authentic content")
	der, err := NewDigester().Digest(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)

	// Flip all digest bytes to corrupt it.
	for i := range p.digestedData.Digest {
		p.digestedData.Digest[i] ^= 0xFF
	}

	require.ErrorIs(t, p.Verify(), ErrInvalidSignature)
}

// TestDigest_WrongDetachedContent verifies that VerifyDetached returns
// ErrInvalidSignature when provided content does not match the stored digest.
func TestDigest_WrongDetachedContent(t *testing.T) {
	content := []byte("original content")

	der, err := NewDigester().WithDetachedContent().Digest(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)

	err = p.VerifyDetached(FromBytes([]byte("tampered content")))
	require.ErrorIs(t, err, ErrInvalidSignature)
}

// TestDigest_EmptyContent verifies that DigestedData handles a zero-byte payload.
func TestDigest_EmptyContent(t *testing.T) {
	der, err := NewDigester().Digest(FromBytes([]byte{}))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)
	require.NoError(t, p.Verify())

	r, err := p.Content()
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	assert.Empty(t, buf.Bytes())
}

// TestDigest_CustomContentType verifies that a non-id-data content type results
// in DigestedData version 2 per RFC 5652 §7.1.
func TestDigest_CustomContentType(t *testing.T) {
	customOID := pkiasn1.OIDSignedData // any non-id-data OID
	content := []byte("custom type content")

	der, err := NewDigester().
		WithContentType(customOID).
		Digest(FromBytes(content))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)

	assert.Equal(t, 2, p.digestedData.Version,
		"version should be 2 for non-id-data content type")
	require.NoError(t, p.Verify())
}

// TestDigest_PayloadTooLarge verifies that content exceeding the configured limit
// causes Digest to return ErrPayloadTooLarge.
func TestDigest_PayloadTooLarge(t *testing.T) {
	content := bytes.Repeat([]byte("A"), 100)

	_, err := NewDigester().
		WithMaxContentSize(50).
		Digest(FromBytes(content))
	require.ErrorIs(t, err, ErrPayloadTooLarge)
}

// TestDigest_ParseWrongContentType verifies that ParseDigestedData returns ErrParse
// when the ContentInfo does not wrap a DigestedData OID.
func TestDigest_ParseWrongContentType(t *testing.T) {
	// Build a SignedData ContentInfo and try to parse it as DigestedData.
	rsaCert, rsaKey := generateSelfSignedRSA(t, 2048)
	der, err := NewSigner().
		WithCertificate(rsaCert).
		WithPrivateKey(rsaKey).
		Sign(FromBytes([]byte("content")))
	require.NoError(t, err)

	_, err = ParseDigestedData(FromBytes(der))
	require.ErrorIs(t, err, ErrParse)
}

// TestDigest_BuilderErrors verifies that configuration errors are accumulated
// and reported together at Digest time.
func TestDigest_BuilderErrors(t *testing.T) {
	tests := []struct {
		name    string
		build   func() *Digester
		wantMsg string
	}{
		{
			name: "empty content type OID",
			build: func() *Digester {
				return NewDigester().WithContentType(asn1.ObjectIdentifier{})
			},
			wantMsg: "content type OID is empty",
		},
		{
			name: "unsupported hash algorithm",
			build: func() *Digester {
				return NewDigester().WithHash(crypto.MD5)
			},
			wantMsg: "not supported",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.build().Digest(FromBytes([]byte("content")))
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidConfiguration) || errors.Is(err, ErrUnsupportedAlgorithm),
				"expected config or unsupported algorithm error, got: %v", err)
			assert.True(t, strings.Contains(err.Error(), tt.wantMsg),
				"expected message to contain %q, got: %v", tt.wantMsg, err)
		})
	}
}

// TestDigest_DefaultVersion verifies that id-data content type produces version 0.
func TestDigest_DefaultVersion(t *testing.T) {
	der, err := NewDigester().Digest(FromBytes([]byte("content")))
	require.NoError(t, err)

	p, err := ParseDigestedData(FromBytes(der))
	require.NoError(t, err)
	assert.Equal(t, 0, p.digestedData.Version, "id-data content type should produce version 0")
}
