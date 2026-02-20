package ber

import (
	"bytes"
	"testing"
)

var fuzzNormalizeSink []byte

// FuzzNormalize verifies two properties of Normalize on arbitrary input:
//  1. Crash safety: Normalize never panics, even on malformed BER.
//  2. Idempotency: Normalize(Normalize(x)) == Normalize(x) whenever the first
//     call succeeds. Since DER is a strict canonical subset of BER, applying
//     Normalize to already-canonical DER must be a no-op.
func FuzzNormalize(f *testing.F) {
	// Seed corpus: simple DER and BER structures covering various ASN.1 types.
	f.Add([]byte{0x30, 0x00})                           // empty SEQUENCE
	f.Add([]byte{0x04, 0x00})                           // empty OCTET STRING
	f.Add([]byte{0x01, 0x01, 0xFF})                     // BOOLEAN TRUE
	f.Add([]byte{0x02, 0x01, 0x01})                     // INTEGER 1
	f.Add([]byte{0x04, 0x05, 'h', 'e', 'l', 'l', 'o'}) // OCTET STRING "hello"
	// BER indefinite-length SEQUENCE containing a BOOLEAN TRUE element.
	f.Add([]byte{0x30, 0x80, 0x01, 0x01, 0xFF, 0x00, 0x00})
	// Non-canonical BOOLEAN: BER allows any non-zero byte for TRUE.
	f.Add([]byte{0x01, 0x01, 0x01})
	// INTEGER with redundant leading zero byte (BER-legal; DER strips it).
	f.Add([]byte{0x02, 0x02, 0x00, 0x01})
	// Nested SEQUENCE with an OCTET STRING child.
	f.Add([]byte{0x30, 0x07, 0x04, 0x05, 'h', 'e', 'l', 'l', 'o'})

	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := Normalize(bytes.NewReader(data))
		if err != nil {
			// Invalid or unsupported BER is expected to fail; the crash-safety
			// property is that Normalize never panics on malformed input.
			return
		}
		fuzzNormalizeSink = result

		// Idempotency: applying Normalize to its own DER output must succeed
		// and produce identical bytes, since DER is already canonical.
		result2, err2 := Normalize(bytes.NewReader(result))
		if err2 != nil {
			t.Fatalf("Normalize succeeded on input but failed on its own DER output: %v", err2)
		}
		if !bytes.Equal(result, result2) {
			t.Fatalf("Normalize is not idempotent: first and second outputs differ")
		}
	})
}
