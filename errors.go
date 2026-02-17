/*
Package cms implements the Cryptographic Message Syntax as defined in RFC 5652.

It provides signing, verification, and parsing of CMS SignedData messages with
support for RSA (PKCS1v15 and PSS), ECDSA, and Ed25519 signing algorithms.
Messages produced by this package are interoperable with other CMS implementations
including OpenSSL and Java Bouncy Castle.
*/
package cms

import "errors"

// ErrorCode identifies the category of a CMS error.
type ErrorCode int

const (
	// CodeParse indicates a malformed ASN.1 structure or invalid CMS content.
	CodeParse ErrorCode = iota
	// CodeBERConversion indicates a failure during BER to DER normalization.
	CodeBERConversion
	// CodeUnsupportedAlgorithm indicates an algorithm that is not in the allow-list.
	CodeUnsupportedAlgorithm
	// CodeInvalidSignature indicates the cryptographic signature verification failed.
	CodeInvalidSignature
	// CodeCertificateChain indicates an X.509 certificate chain validation failure.
	CodeCertificateChain
	// CodeMissingCertificate indicates the signer certificate was not found in the message.
	CodeMissingCertificate
	// CodeTimestamp indicates an RFC 3161 timestamp authority error.
	CodeTimestamp
	// CodeCounterSignature indicates a counter-signature specific failure.
	CodeCounterSignature
	// CodeVersionMismatch indicates the SignedData or SignerInfo version field
	// represents an unsupported capability.
	CodeVersionMismatch
	// CodeAttributeInvalid indicates a mandatory signed attribute is missing or
	// its value fails validation.
	CodeAttributeInvalid
	// CodeContentTypeMismatch indicates the content-type signed attribute does not
	// match the eContentType in EncapsulatedContentInfo.
	CodeContentTypeMismatch
	// CodePKCS7Format indicates the parser detected PKCS #7 format instead of CMS.
	// These formats differ in how non-id-data content types are encapsulated.
	CodePKCS7Format
	// CodeDetachedContentMismatch indicates Verify was called on a detached signature
	// or VerifyDetached was called on an attached signature.
	CodeDetachedContentMismatch
	// CodePayloadTooLarge indicates the attached content exceeds the configured size limit.
	CodePayloadTooLarge
	// CodeInvalidConfiguration indicates the builder configuration is invalid, such as
	// a nil certificate or private key. Multiple configuration errors are joined
	// using errors.Join.
	CodeInvalidConfiguration
)

// Error is the error type returned by all cms operations. It implements the error
// interface and supports error chain inspection via errors.Is and errors.As.
type Error struct {
	// Code identifies the category of this error.
	Code ErrorCode
	// Message is a human-readable description of the error.
	Message string
	// Cause is the underlying error that triggered this error, if any.
	Cause error
}

// Error returns a string representation of the error, including the cause if present.
func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap returns the underlying cause of the error, enabling errors.Is and errors.As
// to traverse the error chain.
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is reports whether the target matches this error by comparing error codes. This
// enables errors.Is(err, cms.ErrInvalidSignature) to match any *Error with the
// same code, regardless of message or cause.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Sentinel errors for use with errors.Is. Each sentinel represents an error category.
// Errors returned by this package carry descriptive messages and causes; sentinels
// are used only for category matching.
var (
	// ErrParse is returned when a CMS or ASN.1 structure cannot be parsed.
	ErrParse = &Error{Code: CodeParse}

	// ErrBERConversion is returned when BER to DER normalization fails.
	ErrBERConversion = &Error{Code: CodeBERConversion}

	// ErrUnsupportedAlgorithm is returned when a message uses an algorithm not
	// in the allow-list.
	ErrUnsupportedAlgorithm = &Error{Code: CodeUnsupportedAlgorithm}

	// ErrInvalidSignature is returned when cryptographic signature verification fails.
	ErrInvalidSignature = &Error{Code: CodeInvalidSignature}

	// ErrCertificateChain is returned when X.509 chain validation fails.
	ErrCertificateChain = &Error{Code: CodeCertificateChain}

	// ErrMissingCertificate is returned when the signer certificate is not present
	// in the SignedData certificates field.
	ErrMissingCertificate = &Error{Code: CodeMissingCertificate}

	// ErrTimestamp is returned when RFC 3161 timestamp operations fail.
	ErrTimestamp = &Error{Code: CodeTimestamp}

	// ErrCounterSignature is returned for counter-signature specific failures.
	ErrCounterSignature = &Error{Code: CodeCounterSignature}

	// ErrVersionMismatch is returned when a SignedData or SignerInfo version field
	// indicates an unsupported capability.
	ErrVersionMismatch = &Error{Code: CodeVersionMismatch}

	// ErrAttributeInvalid is returned when a mandatory signed attribute is missing
	// or its value fails validation.
	ErrAttributeInvalid = &Error{Code: CodeAttributeInvalid}

	// ErrContentTypeMismatch is returned when the content-type signed attribute
	// does not match the eContentType in EncapsulatedContentInfo.
	ErrContentTypeMismatch = &Error{Code: CodeContentTypeMismatch}

	// ErrPKCS7Format is returned when the parser detects PKCS #7 format rather than
	// CMS format. The two formats differ in how non-id-data content is encapsulated.
	ErrPKCS7Format = &Error{Code: CodePKCS7Format}

	// ErrDetachedContentMismatch is returned when Verify is called on a detached
	// signature or VerifyDetached is called on an attached signature.
	ErrDetachedContentMismatch = &Error{Code: CodeDetachedContentMismatch}

	// ErrPayloadTooLarge is returned when attached content exceeds the configured
	// size limit. Use WithDetachedContent or increase the limit with
	// WithMaxAttachedContentSize.
	ErrPayloadTooLarge = &Error{Code: CodePayloadTooLarge}

	// ErrInvalidConfiguration is returned when the builder configuration is invalid.
	// When multiple configuration errors exist, they are joined using errors.Join so
	// that each failure is individually inspectable.
	ErrInvalidConfiguration = &Error{Code: CodeInvalidConfiguration}
)

// newError creates a new Error with the given code and message.
func newError(code ErrorCode, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

// wrapError creates a new Error with the given code and message, wrapping cause.
func wrapError(code ErrorCode, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, Cause: cause}
}

// newConfigError creates a new CodeInvalidConfiguration Error with the given message.
func newConfigError(msg string) *Error {
	return &Error{Code: CodeInvalidConfiguration, Message: msg}
}

// joinErrors returns a joined error from the provided slice, or nil if empty.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}
