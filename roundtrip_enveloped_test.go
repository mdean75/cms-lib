package cms

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRoundTrip_EnvelopedData_LibraryOutputDecryptedByOpenSSL encrypts content
// with this library and decrypts the resulting DER with "openssl cms -decrypt".
// It exercises the outbound EnvelopedData direction (library → OpenSSL).
// The test is skipped when openssl is not found in PATH.
//
// AES-GCM cases are skipped on OpenSSL < 3.2 because GCM support in
// cms -decrypt was added in that release.
func TestRoundTrip_EnvelopedData_LibraryOutputDecryptedByOpenSSL(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH; skipping enveloped round-trip tests")
	}

	opensslSupportsGCM := opensslVersionAtLeast(t, opensslPath, 3, 2, 0)

	rsaRecipCert := parseFixtureCert(t, "testdata/openssl/enveloped/rsa_recip.cert.pem")
	ecP256RecipCert := parseFixtureCert(t, "testdata/openssl/enveloped/ec_p256_recip.cert.pem")

	content, err := os.ReadFile("testdata/content.bin")
	require.NoError(t, err)

	// Paths to fixture key files used by openssl -decrypt.
	const (
		rsaKeyPath   = "testdata/openssl/enveloped/rsa_recip.key.pem"
		rsaCertPath  = "testdata/openssl/enveloped/rsa_recip.cert.pem"
		ecKeyPath    = "testdata/openssl/enveloped/ec_p256_recip.key.pem"
		ecCertPath   = "testdata/openssl/enveloped/ec_p256_recip.cert.pem"
	)

	tests := []struct {
		name        string
		certPath    string
		keyPath     string
		skipIfNoGCM bool
		encrypt     func(t *testing.T) []byte
	}{
		{
			name:        "RSA-OAEP AES-256-GCM",
			certPath:    rsaCertPath,
			keyPath:     rsaKeyPath,
			skipIfNoGCM: true,
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				der, err := NewEncryptor().
					WithRecipient(rsaRecipCert).
					WithContentEncryption(AES256GCM).
					Encrypt(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
		{
			name:     "RSA-OAEP AES-256-CBC",
			certPath: rsaCertPath,
			keyPath:  rsaKeyPath,
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				der, err := NewEncryptor().
					WithRecipient(rsaRecipCert).
					WithContentEncryption(AES256CBC).
					Encrypt(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
		{
			name:     "RSA-OAEP AES-128-CBC",
			certPath: rsaCertPath,
			keyPath:  rsaKeyPath,
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				der, err := NewEncryptor().
					WithRecipient(rsaRecipCert).
					WithContentEncryption(AES128CBC).
					Encrypt(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
		{
			name:        "ECDH P-256 AES-256-GCM",
			certPath:    ecCertPath,
			keyPath:     ecKeyPath,
			skipIfNoGCM: true,
			encrypt: func(t *testing.T) []byte {
				t.Helper()
				der, err := NewEncryptor().
					WithRecipient(ecP256RecipCert).
					WithContentEncryption(AES256GCM).
					Encrypt(bytes.NewReader(content))
				require.NoError(t, err)
				return der
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipIfNoGCM && !opensslSupportsGCM {
				t.Skip("OpenSSL < 3.2: AES-GCM CMS decrypt not supported")
			}

			der := tt.encrypt(t)

			dir := t.TempDir()
			cmsFile := filepath.Join(dir, "enveloped.der")
			outFile := filepath.Join(dir, "plaintext.bin")
			require.NoError(t, os.WriteFile(cmsFile, der, 0o600))

			cmd := exec.Command(opensslPath,
				"cms", "-decrypt",
				"-in", cmsFile, "-inform", "DER",
				"-recip", tt.certPath,
				"-inkey", tt.keyPath,
				"-out", outFile,
			)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "openssl cms -decrypt failed:\n%s", out)

			got, err := os.ReadFile(outFile)
			require.NoError(t, err)
			require.Equal(t, content, got, "decrypted content mismatch")
		})
	}
}

// opensslVersionAtLeast returns true when the openssl binary reports a version
// >= major.minor.patch. It returns false (without failing the test) if the
// version string cannot be parsed.
func opensslVersionAtLeast(t *testing.T, opensslPath string, major, minor, patch int) bool {
	t.Helper()
	out, err := exec.Command(opensslPath, "version").Output()
	if err != nil {
		return false
	}
	// Expected format: "OpenSSL X.Y.Z ..."
	// LibreSSL uses independent version numbers and does not support all features
	// (e.g. AES-GCM CMS decrypt) that the equivalent OpenSSL release does.
	fields := strings.Fields(string(out))
	if len(fields) < 2 || fields[0] != "OpenSSL" {
		return false
	}
	parts := strings.SplitN(fields[1], ".", 3)
	if len(parts) < 3 {
		return false
	}
	// Strip any non-numeric suffix from the patch component (e.g. "0a" → "0").
	patchStr := strings.TrimRight(parts[2], "abcdefghijklmnopqrstuvwxyz")
	got := [3]int{}
	var parseErr error
	got[0], parseErr = strconv.Atoi(parts[0])
	if parseErr != nil {
		return false
	}
	got[1], parseErr = strconv.Atoi(parts[1])
	if parseErr != nil {
		return false
	}
	got[2], parseErr = strconv.Atoi(patchStr)
	if parseErr != nil {
		return false
	}
	want := [3]int{major, minor, patch}
	for i := range got {
		if got[i] > want[i] {
			return true
		}
		if got[i] < want[i] {
			return false
		}
	}
	return true // equal
}

