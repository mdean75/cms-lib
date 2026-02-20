package cms

import (
	"bytes"
	"os"
	"testing"
)

var fuzzParseSignedDataSink *ParsedSignedData

// FuzzParseSignedData verifies that ParseSignedData never panics on arbitrary
// input. The seeded corpus consists of the OpenSSL-generated interop fixtures
// from testdata/, which provide structurally valid starting points for the
// fuzzer to mutate. Seeds that cannot be read (e.g. before running
// testdata/regen.sh) are silently skipped.
func FuzzParseSignedData(f *testing.F) {
	for _, name := range []string{
		"testdata/signed_attached_rsa_sha256.der",
		"testdata/signed_detached_rsa_sha256.der",
		"testdata/signed_attached_ec_sha256.der",
	} {
		if data, err := os.ReadFile(name); err == nil {
			f.Add(data)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		psd, err := ParseSignedData(bytes.NewReader(data))
		if err != nil {
			return
		}
		fuzzParseSignedDataSink = psd

		// Exercise the verification code path as well; any returned error is
		// acceptable. WithNoChainValidation avoids the need for a trust store.
		if psd.IsDetached() {
			_ = psd.VerifyDetached(bytes.NewReader(nil), WithNoChainValidation())
		} else {
			_ = psd.Verify(WithNoChainValidation())
		}
	})
}
