package cms

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// SignerOption configures a Signer. Options that apply only to Signer (not
// CounterSigner) implement this interface. Pass them to NewSigner.
type SignerOption interface {
	applyToSigner(*Signer) error
}

// SigningOption configures both Signer and CounterSigner. Because SigningOption
// embeds SignerOption, a SigningOption value satisfies SignerOption and can be
// passed to NewSigner. Pass SigningOption values to either NewSigner or
// NewCounterSigner.
type SigningOption interface {
	SignerOption
	applyToCounterSigner(*CounterSigner) error
}

// signerOption is a concrete SignerOption backed by a single function.
type signerOption struct {
	f func(*Signer) error
}

func (o *signerOption) applyToSigner(s *Signer) error {
	return o.f(s)
}

// signingOption is a concrete SigningOption backed by two functions, one for
// each receiver type.
type signingOption struct {
	signerFn  func(*Signer) error
	counterFn func(*CounterSigner) error
}

func (o *signingOption) applyToSigner(s *Signer) error {
	return o.signerFn(s)
}

func (o *signingOption) applyToCounterSigner(cs *CounterSigner) error {
	return o.counterFn(cs)
}

// --- Options returning SigningOption (accepted by both NewSigner and NewCounterSigner) ---

// WithHash sets the digest algorithm. For Ed25519, the library always uses
// SHA-512 per RFC 8419 regardless of this setting. Defaults to SHA-256.
func WithHash(h crypto.Hash) SigningOption {
	return &signingOption{
		signerFn:  func(s *Signer) error { s.hash = h; return nil },
		counterFn: func(cs *CounterSigner) error { cs.hash = h; return nil },
	}
}

// WithRSAPKCS1 selects RSA PKCS1v15 as the signature algorithm. By default,
// RSA keys use RSA-PSS. This option has no effect for non-RSA keys.
func WithRSAPKCS1() SigningOption {
	return &signingOption{
		signerFn: func(s *Signer) error {
			s.family = familyRSAPKCS1
			s.familyExplicit = true
			return nil
		},
		counterFn: func(cs *CounterSigner) error {
			cs.family = familyRSAPKCS1
			cs.familyExplicit = true
			return nil
		},
	}
}

// WithSignerIdentifier controls how the signer's certificate is identified in
// SignerInfo. Default is IssuerAndSerialNumber (SignerInfo version 1).
func WithSignerIdentifier(t SignerIdentifierType) SigningOption {
	return &signingOption{
		signerFn:  func(s *Signer) error { s.sidType = t; return nil },
		counterFn: func(cs *CounterSigner) error { cs.sidType = t; return nil },
	}
}

// AddCertificate adds an extra certificate to the CertificateSet in the output
// (for example, intermediate CA certificates needed for chain building).
func AddCertificate(cert *x509.Certificate) SigningOption {
	return &signingOption{
		signerFn: func(s *Signer) error {
			if cert == nil {
				return newConfigError("extra certificate is nil")
			}
			s.extraCerts = append(s.extraCerts, cert)
			return nil
		},
		counterFn: func(cs *CounterSigner) error {
			if cert == nil {
				return newConfigError("extra certificate is nil")
			}
			cs.extraCerts = append(cs.extraCerts, cert)
			return nil
		},
	}
}

// --- Options returning SignerOption (accepted by NewSigner only) ---

// WithDetachedContent produces a detached signature (eContent absent in output).
// Detached mode streams content without buffering it; the size limit has no effect.
func WithDetachedContent() SignerOption {
	return &signerOption{f: func(s *Signer) error {
		s.detached = true
		return nil
	}}
}

// WithContentType sets a custom eContentType OID. Default is id-data.
// A non-id-data type forces SignedData version 3 per RFC 5652 §5.1.
func WithContentType(oid asn1.ObjectIdentifier) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		if len(oid) == 0 {
			return newConfigError("content type OID is empty")
		}
		s.contentType = oid
		return nil
	}}
}

// WithMaxAttachedContentSize sets the maximum content size for attached signatures.
// Defaults to DefaultMaxAttachedSize (64 MiB). Pass UnlimitedAttachedSize to disable.
// Has no effect in detached mode.
func WithMaxAttachedContentSize(maxBytes int64) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		s.maxSize = maxBytes
		return nil
	}}
}

// WithAdditionalSigner adds a second (or subsequent) signer to the SignedData.
// The additional signer must have been successfully constructed via NewSigner.
// All signers share the primary signer's content, content type, and
// detached/attached setting.
func WithAdditionalSigner(other *Signer) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		if other == nil {
			return newConfigError("additional signer is nil")
		}
		s.additionalSigners = append(s.additionalSigners, other)
		return nil
	}}
}

// AddAuthenticatedAttribute adds a custom signed attribute. The content-type and
// message-digest attributes are always injected automatically; callers must not
// add those manually. NewSigner returns ErrAttributeInvalid if they do.
func AddAuthenticatedAttribute(oid asn1.ObjectIdentifier, val any) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		if oid.Equal(pkiasn1.OIDAttributeContentType) || oid.Equal(pkiasn1.OIDAttributeMessageDigest) {
			return newError(CodeAttributeInvalid,
				fmt.Sprintf("attribute %s is injected automatically; do not add it manually", oid))
		}
		encoded, err := asn1.Marshal(val)
		if err != nil {
			return wrapError(CodeAttributeInvalid,
				fmt.Sprintf("failed to marshal authenticated attribute %s", oid), err)
		}
		s.authAttrs = append(s.authAttrs, pkiasn1.Attribute{
			Type:   oid,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(encoded)},
		})
		return nil
	}}
}

// AddUnauthenticatedAttribute adds a custom unsigned attribute.
func AddUnauthenticatedAttribute(oid asn1.ObjectIdentifier, val any) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		encoded, err := asn1.Marshal(val)
		if err != nil {
			return wrapError(CodeAttributeInvalid,
				fmt.Sprintf("failed to marshal unauthenticated attribute %s", oid), err)
		}
		s.unauthAttrs = append(s.unauthAttrs, pkiasn1.Attribute{
			Type:   oid,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(encoded)},
		})
		return nil
	}}
}

// AddCRL embeds a DER-encoded Certificate Revocation List in the SignedData
// revocationInfoChoices field.
func AddCRL(derCRL []byte) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		if len(derCRL) == 0 {
			return newConfigError("CRL DER bytes are empty")
		}
		s.crls = append(s.crls, derCRL)
		return nil
	}}
}

// WithTimestamp requests an RFC 3161 timestamp from tsaURL after signing and
// embeds it as an unsigned attribute (id-aa-signatureTimeStampToken) on each
// SignerInfo. The timestamp covers the SignerInfo's Signature bytes.
func WithTimestamp(tsaURL string) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		if tsaURL == "" {
			return newConfigError("TSA URL is empty")
		}
		s.tsaURL = tsaURL
		return nil
	}}
}
