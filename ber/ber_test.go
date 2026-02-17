package ber

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		// --- Definite-length inputs that are already valid DER ---
		{
			name:  "already DER: simple INTEGER",
			input: []byte{0x02, 0x01, 0x01},
			want:  []byte{0x02, 0x01, 0x01},
		},
		{
			name:  "already DER: SEQUENCE with nested elements",
			input: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02},
			want:  []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02},
		},
		{
			name:  "already DER: empty SEQUENCE",
			input: []byte{0x30, 0x00},
			want:  []byte{0x30, 0x00},
		},

		// --- Indefinite-length encoding ---
		{
			name: "indefinite-length SEQUENCE with content",
			input: []byte{
				0x30, 0x80, // SEQUENCE, indefinite length
				0x02, 0x01, 0x2A, // INTEGER 42
				0x00, 0x00, // end-of-contents
			},
			want: []byte{
				0x30, 0x03, // SEQUENCE, length 3
				0x02, 0x01, 0x2A, // INTEGER 42
			},
		},
		{
			// Critical edge case: a zero-length value with indefinite encoding must
			// be preserved as a present-but-empty element, not dropped. In CMS
			// SignedData this distinguishes a signed 0-byte payload from a detached
			// signature where the eContent field is absent entirely.
			name: "indefinite-length OCTET STRING with zero-length content (0-byte payload)",
			input: []byte{
				0x04, 0x80, // OCTET STRING, indefinite length
				0x00, 0x00, // end-of-contents
			},
			want: []byte{
				0x04, 0x00, // OCTET STRING, length 0
			},
		},
		{
			// CMS eContent field: [0] EXPLICIT wrapping a zero-length OCTET STRING.
			// This is the exact BER encoding produced for a signed 0-byte payload.
			name: "indefinite-length explicit [0] wrapping zero-length OCTET STRING",
			input: []byte{
				0xA0, 0x80, // [0] EXPLICIT, indefinite length
				0x04, 0x80, // OCTET STRING, indefinite length
				0x00, 0x00, // end-of-contents for OCTET STRING
				0x00, 0x00, // end-of-contents for [0]
			},
			want: []byte{
				0xA0, 0x02, // [0] EXPLICIT, length 2
				0x04, 0x00, // OCTET STRING, length 0
			},
		},
		{
			name: "nested indefinite-length containers",
			input: []byte{
				0x30, 0x80, // SEQUENCE, indefinite
				0x30, 0x80, // nested SEQUENCE, indefinite
				0x02, 0x01, 0x07, // INTEGER 7
				0x00, 0x00, // end-of-contents inner
				0x00, 0x00, // end-of-contents outer
			},
			want: []byte{
				0x30, 0x05, // SEQUENCE, length 5
				0x30, 0x03, // nested SEQUENCE, length 3
				0x02, 0x01, 0x07, // INTEGER 7
			},
		},

		// --- Constructed primitive types ---
		{
			name: "constructed OCTET STRING flattened to primitive",
			input: []byte{
				0x24, 0x08, // constructed OCTET STRING, length 8
				0x04, 0x03, 0x01, 0x02, 0x03, // OCTET STRING chunk 1
				0x04, 0x01, 0x04, // OCTET STRING chunk 2
			},
			want: []byte{
				0x04, 0x04, // primitive OCTET STRING, length 4
				0x01, 0x02, 0x03, 0x04, // concatenated value
			},
		},
		{
			// Per X.690 section 8.6, BIT STRING chunks each begin with an unused-bits
			// byte. The last chunk's unused-bits byte becomes the result's unused-bits
			// byte; data bytes from all chunks are concatenated after it.
			// Chunk 1: unused=0x00, data=0xAB,0xCD
			// Chunk 2: unused=0x00, data=(empty)
			// Result: unused=0x00, data=0xAB,0xCD → 3 value bytes total.
			name: "constructed BIT STRING flattened to primitive",
			input: []byte{
				0x23, 0x08, // constructed BIT STRING, length 8
				0x03, 0x03, 0x00, 0xAB, 0xCD, // BIT STRING chunk 1: unused=0, data=0xAB,0xCD
				0x03, 0x01, 0x00, // BIT STRING chunk 2: unused=0, data=(empty)
			},
			want: []byte{
				0x03, 0x03, // primitive BIT STRING, length 3
				0x00, 0xAB, 0xCD, // unused-bits=0, data=0xAB,0xCD
			},
		},

		// --- Non-canonical BOOLEAN ---
		{
			name:  "BOOLEAN TRUE normalized from 0x01 to 0xFF",
			input: []byte{0x01, 0x01, 0x01},
			want:  []byte{0x01, 0x01, 0xFF},
		},
		{
			name:  "BOOLEAN TRUE normalized from arbitrary non-zero to 0xFF",
			input: []byte{0x01, 0x01, 0x42},
			want:  []byte{0x01, 0x01, 0xFF},
		},
		{
			name:  "BOOLEAN FALSE preserved as 0x00",
			input: []byte{0x01, 0x01, 0x00},
			want:  []byte{0x01, 0x01, 0x00},
		},
		{
			name:  "BOOLEAN TRUE already canonical 0xFF",
			input: []byte{0x01, 0x01, 0xFF},
			want:  []byte{0x01, 0x01, 0xFF},
		},

		// --- Non-minimal INTEGER encoding ---
		{
			name:  "INTEGER with redundant leading zero byte removed",
			input: []byte{0x02, 0x03, 0x00, 0x00, 0x01},
			want:  []byte{0x02, 0x01, 0x01},
		},
		{
			name:  "INTEGER with single redundant zero preserved as single byte",
			input: []byte{0x02, 0x02, 0x00, 0x7F},
			want:  []byte{0x02, 0x01, 0x7F},
		},
		{
			name: "INTEGER sign byte preserved: 0x00 required before 0x80",
			// 0x0080 = 128; the leading 0x00 is necessary as a sign byte.
			input: []byte{0x02, 0x02, 0x00, 0x80},
			want:  []byte{0x02, 0x02, 0x00, 0x80},
		},
		{
			name:  "INTEGER zero value preserved",
			input: []byte{0x02, 0x01, 0x00},
			want:  []byte{0x02, 0x01, 0x00},
		},
		{
			name:  "INTEGER negative value sign byte preserved",
			input: []byte{0x02, 0x01, 0xFF}, // -1
			want:  []byte{0x02, 0x01, 0xFF},
		},

		// --- Non-minimal length encoding ---
		{
			name: "two-byte length encoding normalized to one byte",
			// 0x81 0x03 means long-form 1 byte = 3; should be short-form 0x03.
			input: []byte{0x04, 0x81, 0x03, 0x01, 0x02, 0x03},
			want:  []byte{0x04, 0x03, 0x01, 0x02, 0x03},
		},

		// --- Mixed DER-within-BER: outer indefinite, inner already DER ---
		{
			// This models a real CMS message where the outer SEQUENCE uses BER
			// indefinite length but the signedAttrs SET is already DER-encoded.
			// The inner content bytes must be preserved verbatim.
			name: "outer indefinite-length with inner DER-encoded SET preserved",
			input: []byte{
				0x30, 0x80, // outer SEQUENCE, indefinite
				0x31, 0x06, // SET (signedAttrs), definite DER — must be preserved
				0x02, 0x01, 0x01, // INTEGER 1
				0x02, 0x01, 0x02, // INTEGER 2
				0x00, 0x00, // end-of-contents for outer SEQUENCE
			},
			want: []byte{
				0x30, 0x08, // outer SEQUENCE, definite
				0x31, 0x06, // SET preserved exactly as-is
				0x02, 0x01, 0x01,
				0x02, 0x01, 0x02,
			},
		},

		// --- Error cases ---
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "truncated element",
			input:   []byte{0x02, 0x05, 0x01},
			wantErr: true,
		},
		{
			name:    "missing end-of-contents for indefinite-length element",
			input:   []byte{0x30, 0x80, 0x02, 0x01, 0x01},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Normalize(bytes.NewReader(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestNormalize_ZeroBytePayloadDistinction verifies the critical invariant that
// a zero-length value with indefinite encoding is never collapsed to absence.
// This is the primary edge case where known BER implementations fail.
func TestNormalize_ZeroBytePayloadDistinction(t *testing.T) {
	// BER encoding of eContent = [0] EXPLICIT OCTET STRING (0 bytes), indefinite length.
	// This is what a Windows CryptoAPI or certain JVM implementations produce for a
	// CMS SignedData over a 0-byte payload.
	berInput := []byte{
		0xA0, 0x80, // [0] EXPLICIT, indefinite
		0x04, 0x80, // OCTET STRING, indefinite
		0x00, 0x00, // end-of-contents OCTET STRING
		0x00, 0x00, // end-of-contents [0]
	}

	got, err := Normalize(bytes.NewReader(berInput))
	require.NoError(t, err)

	// The normalized output must contain a present [0] with a zero-length OCTET STRING.
	wantDER := []byte{
		0xA0, 0x02, // [0] EXPLICIT, length 2
		0x04, 0x00, // OCTET STRING, length 0
	}
	assert.Equal(t, wantDER, got, "zero-byte payload must be preserved as present; must not be treated as absent (detached signature)")

	// Confirm the result is distinct from an absent field (nil/empty output).
	assert.NotEmpty(t, got, "normalized output must not be empty for a 0-byte payload")
}

var benchResult []byte

func BenchmarkNormalize(b *testing.B) {
	// Construct a moderately complex BER input: a SEQUENCE with indefinite length
	// containing several INTEGER elements.
	input := buildBenchmarkInput()

	var r []byte
	for b.Loop() {
		var err error
		r, err = Normalize(bytes.NewReader(input))
		if err != nil {
			b.Fatal(err)
		}
	}
	benchResult = r
}

// buildBenchmarkInput constructs a BER-encoded SEQUENCE with indefinite length
// containing 20 INTEGER elements.
func buildBenchmarkInput() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x30, 0x80}) // SEQUENCE, indefinite
	for i := range 20 {
		buf.Write([]byte{0x02, 0x01, byte(i + 1)})
	}
	buf.Write([]byte{0x00, 0x00}) // end-of-contents
	return buf.Bytes()
}
