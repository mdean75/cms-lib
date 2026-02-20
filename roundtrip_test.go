package cms

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRoundTrip_LibraryOutputVerifiedByOpenSSL signs content with this library
// and verifies the resulting DER with "openssl cms -verify". It exercises the
// reverse direction of TestInterop_OpenSSL (which parses OpenSSL output with
// this library). The test is skipped when openssl is not found in PATH.
//
// Note: Ed25519 is intentionally excluded. OpenSSL 3.0.x has a known defect
// where "openssl cms -sign" with an Ed25519 key exits non-zero and produces
// empty output, meaning OpenSSL itself cannot interop-test Ed25519 CMS on
// this platform. The library's own round-trip tests (TestSignVerify_Ed25519*)
// cover Ed25519 correctness independently.
func TestRoundTrip_LibraryOutputVerifiedByOpenSSL(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH; skipping reverse round-trip tests")
	}

	content := []byte("round-trip interop test content")

	tests := []struct {
		name     string
		detached bool
		sign     func(t *testing.T) []byte
	}{
		{
			name: "RSA PKCS1v15 attached SHA-256",
			sign: func(t *testing.T) []byte {
				cert, key := generateSelfSignedRSA(t, 2048)
				der, err := NewSigner().
					WithCertificate(cert).
					WithPrivateKey(key).
					WithRSAPKCS1().
					WithHash(crypto.SHA256).
					Sign(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
		{
			name: "RSA-PSS attached SHA-256",
			sign: func(t *testing.T) []byte {
				cert, key := generateSelfSignedRSA(t, 2048)
				der, err := NewSigner().
					WithCertificate(cert).
					WithPrivateKey(key).
					WithHash(crypto.SHA256).
					Sign(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
		{
			name: "ECDSA P-256 attached SHA-256",
			sign: func(t *testing.T) []byte {
				cert, key := generateSelfSignedECDSA(t, elliptic.P256())
				der, err := NewSigner().
					WithCertificate(cert).
					WithPrivateKey(key).
					WithHash(crypto.SHA256).
					Sign(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
		{
			name:     "RSA PKCS1v15 detached SHA-256",
			detached: true,
			sign: func(t *testing.T) []byte {
				cert, key := generateSelfSignedRSA(t, 2048)
				der, err := NewSigner().
					WithCertificate(cert).
					WithPrivateKey(key).
					WithRSAPKCS1().
					WithHash(crypto.SHA256).
					WithDetachedContent().
					Sign(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
		{
			name:     "RSA-PSS detached SHA-256",
			detached: true,
			sign: func(t *testing.T) []byte {
				cert, key := generateSelfSignedRSA(t, 2048)
				der, err := NewSigner().
					WithCertificate(cert).
					WithPrivateKey(key).
					WithHash(crypto.SHA256).
					WithDetachedContent().
					Sign(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der := tt.sign(t)

			dir := t.TempDir()
			sigFile := filepath.Join(dir, "signed.der")
			require.NoError(t, os.WriteFile(sigFile, der, 0o600))

			args := []string{
				"cms", "-verify",
				"-in", sigFile, "-inform", "DER",
				"-noverify",
				"-out", os.DevNull,
			}
			if tt.detached {
				contentFile := filepath.Join(dir, "content.bin")
				require.NoError(t, os.WriteFile(contentFile, content, 0o600))
				args = append(args, "-binary", "-content", contentFile)
			}

			cmd := exec.Command(opensslPath, args...)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "openssl cms -verify failed:\n%s", out)
		})
	}
}
