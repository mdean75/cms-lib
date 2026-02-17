package cms

import (
	"bytes"
	"io"
)

// FromBytes wraps a byte slice as an io.Reader for use with Sign, ParseSignedData,
// and other functions that accept io.Reader.
func FromBytes(b []byte) io.Reader {
	return bytes.NewReader(b)
}

// SignerIdentifierType controls how the signer's certificate is identified in
// the SignerInfo structure of a CMS SignedData message.
type SignerIdentifierType int

const (
	// IssuerAndSerialNumber identifies the signer by issuer distinguished name and
	// certificate serial number. This produces SignerInfo version 1 and is the most
	// widely compatible form. This is the default.
	IssuerAndSerialNumber SignerIdentifierType = iota

	// SubjectKeyIdentifier identifies the signer by the value of the certificate's
	// subjectKeyIdentifier extension. This produces SignerInfo version 3.
	SubjectKeyIdentifier
)

// DefaultMaxAttachedSize is the default maximum content size in bytes for attached
// signatures (64 MiB). Sign returns ErrPayloadTooLarge if this limit is exceeded.
// Use WithMaxAttachedContentSize to override.
const DefaultMaxAttachedSize int64 = 64 * 1024 * 1024

// UnlimitedAttachedSize disables the attached content size limit when passed to
// WithMaxAttachedContentSize. Use with caution: attached content is fully buffered
// in memory during Sign.
const UnlimitedAttachedSize int64 = -1
