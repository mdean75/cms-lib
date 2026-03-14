package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// --- Option interfaces for Signer and CounterSigner ---

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

// --- Option interfaces for Encryptor, SymmetricEncryptor, Digester, Authenticator ---

// EncryptorOption configures an Encryptor. Pass to NewEncryptor.
type EncryptorOption interface {
	applyEncryptor(*Encryptor) error
}

// SymmetricEncryptorOption configures a SymmetricEncryptor. Pass to NewSymmetricEncryptor.
type SymmetricEncryptorOption interface {
	applySymmetricEncryptor(*SymmetricEncryptor) error
}

// DigesterOption configures a Digester. Pass to NewDigester.
type DigesterOption interface {
	applyDigester(*Digester) error
}

// AuthenticatorOption configures an Authenticator. Pass to NewAuthenticator.
type AuthenticatorOption interface {
	applyAuthenticator(*Authenticator) error
}

// --- Combined option interfaces ---

// HashOption applies to NewSigner, NewCounterSigner, and NewDigester.
type HashOption interface {
	SigningOption
	DigesterOption
}

// DetachedOption applies to NewSigner and NewDigester.
type DetachedOption interface {
	SignerOption
	DigesterOption
}

// ContentTypeOption applies to NewSigner, NewSymmetricEncryptor, NewDigester,
// and NewAuthenticator.
type ContentTypeOption interface {
	SignerOption
	SymmetricEncryptorOption
	DigesterOption
	AuthenticatorOption
}

// RecipientOption applies to NewEncryptor and NewAuthenticator.
type RecipientOption interface {
	EncryptorOption
	AuthenticatorOption
}

// ContentEncryptionOption applies to NewEncryptor and NewSymmetricEncryptor.
type ContentEncryptionOption interface {
	EncryptorOption
	SymmetricEncryptorOption
}

// ContentSizeOption applies to NewEncryptor, NewSymmetricEncryptor, NewDigester,
// and NewAuthenticator.
type ContentSizeOption interface {
	EncryptorOption
	SymmetricEncryptorOption
	DigesterOption
	AuthenticatorOption
}

// --- Concrete types for Signer/CounterSigner options ---

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

// --- Concrete types for combined options ---

// hashOpt implements HashOption (SigningOption + DigesterOption).
type hashOpt struct{ h crypto.Hash }

func (o *hashOpt) applyToSigner(s *Signer) error {
	s.hash = o.h
	s.hashExplicit = true
	return nil
}

func (o *hashOpt) applyToCounterSigner(cs *CounterSigner) error {
	cs.hash = o.h
	cs.hashExplicit = true
	return nil
}

func (o *hashOpt) applyDigester(d *Digester) error {
	d.hash = o.h
	return nil
}

// detachedOpt implements DetachedOption (SignerOption + DigesterOption).
type detachedOpt struct{}

func (o *detachedOpt) applyToSigner(s *Signer) error {
	s.detached = true
	return nil
}

func (o *detachedOpt) applyDigester(d *Digester) error {
	d.detached = true
	return nil
}

// contentTypeOpt implements ContentTypeOption.
type contentTypeOpt struct{ oid asn1.ObjectIdentifier }

func (o *contentTypeOpt) applyToSigner(s *Signer) error {
	if len(o.oid) == 0 {
		return newConfigError("content type OID is empty")
	}
	s.contentType = o.oid
	return nil
}

func (o *contentTypeOpt) applySymmetricEncryptor(se *SymmetricEncryptor) error {
	if len(o.oid) == 0 {
		return newConfigError("content type OID is empty")
	}
	se.contentType = o.oid
	return nil
}

func (o *contentTypeOpt) applyDigester(d *Digester) error {
	if len(o.oid) == 0 {
		return newConfigError("content type OID is empty")
	}
	d.contentType = o.oid
	return nil
}

func (o *contentTypeOpt) applyAuthenticator(a *Authenticator) error {
	if len(o.oid) == 0 {
		return newConfigError("content type OID is empty")
	}
	a.contentType = o.oid
	return nil
}

// recipientOpt implements RecipientOption (EncryptorOption + AuthenticatorOption).
type recipientOpt struct{ cert *x509.Certificate }

func (o *recipientOpt) applyEncryptor(e *Encryptor) error {
	if o.cert == nil {
		return newConfigError("recipient certificate is nil")
	}
	switch o.cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		// supported
	default:
		return newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported recipient public key type %T", o.cert.PublicKey))
	}
	e.recipients = append(e.recipients, o.cert)
	return nil
}

func (o *recipientOpt) applyAuthenticator(a *Authenticator) error {
	if o.cert == nil {
		return newConfigError("recipient certificate is nil")
	}
	switch o.cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		// supported
	default:
		return newError(CodeUnsupportedAlgorithm,
			fmt.Sprintf("unsupported recipient public key type %T", o.cert.PublicKey))
	}
	a.recipients = append(a.recipients, o.cert)
	return nil
}

// contentEncryptionOpt implements ContentEncryptionOption.
type contentEncryptionOpt struct{ alg ContentEncryptionAlgorithm }

func (o *contentEncryptionOpt) applyEncryptor(e *Encryptor) error {
	e.contentAlg = o.alg
	return nil
}

func (o *contentEncryptionOpt) applySymmetricEncryptor(se *SymmetricEncryptor) error {
	se.contentAlg = o.alg
	return nil
}

// keyOpt implements SymmetricEncryptorOption.
type keyOpt struct{ key []byte }

func (o *keyOpt) applySymmetricEncryptor(se *SymmetricEncryptor) error {
	if len(o.key) == 0 {
		return newConfigError("key must not be empty")
	}
	se.key = o.key
	return nil
}

// macAlgOpt implements AuthenticatorOption.
type macAlgOpt struct{ alg MACAlgorithm }

func (o *macAlgOpt) applyAuthenticator(a *Authenticator) error {
	a.macAlg = o.alg
	return nil
}

// contentSizeOpt implements ContentSizeOption.
type contentSizeOpt struct{ maxBytes int64 }

func (o *contentSizeOpt) applyEncryptor(e *Encryptor) error {
	e.maxSize = o.maxBytes
	return nil
}

func (o *contentSizeOpt) applySymmetricEncryptor(se *SymmetricEncryptor) error {
	se.maxSize = o.maxBytes
	return nil
}

func (o *contentSizeOpt) applyDigester(d *Digester) error {
	d.maxSize = o.maxBytes
	return nil
}

func (o *contentSizeOpt) applyAuthenticator(a *Authenticator) error {
	a.maxSize = o.maxBytes
	return nil
}

// --- Options returning SigningOption (accepted by both NewSigner and NewCounterSigner) ---

// WithHash sets the digest algorithm. For Ed25519, the library always uses
// SHA-512 per RFC 8419 regardless of this setting. Defaults to SHA-256.
// Also accepted by NewDigester.
func WithHash(h crypto.Hash) HashOption {
	return &hashOpt{h: h}
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

// AddCertificateChain adds multiple certificates to the CertificateSet in the
// output. This is a convenience for embedding an entire certificate chain
// (typically intermediates and/or root CA) in a single call. The certificates
// are purely transport for the verifier's chain-building benefit — they have no
// effect on the signing operation itself.
func AddCertificateChain(certs ...*x509.Certificate) SigningOption {
	return &signingOption{
		signerFn: func(s *Signer) error {
			for i, cert := range certs {
				if cert == nil {
					return newConfigError(fmt.Sprintf("certificate at index %d in chain is nil", i))
				}
				s.extraCerts = append(s.extraCerts, cert)
			}
			return nil
		},
		counterFn: func(cs *CounterSigner) error {
			for i, cert := range certs {
				if cert == nil {
					return newConfigError(fmt.Sprintf("certificate at index %d in chain is nil", i))
				}
				cs.extraCerts = append(cs.extraCerts, cert)
			}
			return nil
		},
	}
}

// --- Options returning SignerOption (accepted by NewSigner only) ---

// WithDetachedContent produces a detached signature or digest (eContent absent
// in output). Also accepted by NewDigester.
func WithDetachedContent() DetachedOption {
	return &detachedOpt{}
}

// WithContentType sets a custom eContentType OID. Default is id-data.
// A non-id-data type forces SignedData version 3 per RFC 5652 §5.1.
// Also accepted by NewSymmetricEncryptor, NewDigester, and NewAuthenticator.
func WithContentType(oid asn1.ObjectIdentifier) ContentTypeOption {
	return &contentTypeOpt{oid: oid}
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

// AddAuthenticatedAttribute adds a custom signed attribute. The content-type,
// message-digest, and signing-time attributes are managed by the library;
// callers must not add those manually. For signing-time, use WithSigningTimeFunc
// instead. NewSigner returns ErrAttributeInvalid if any reserved attribute is
// provided.
func AddAuthenticatedAttribute(oid asn1.ObjectIdentifier, val any) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		if oid.Equal(pkiasn1.OIDAttributeContentType) ||
			oid.Equal(pkiasn1.OIDAttributeMessageDigest) ||
			oid.Equal(pkiasn1.OIDAttributeSigningTime) {
			return newError(CodeAttributeInvalid,
				fmt.Sprintf("attribute %s is managed by the library; do not add it manually", oid))
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

// WithSigningTimeFunc sets a clock function called at each Sign() invocation to
// embed an id-signingTime authenticated attribute (RFC 5652 §11.3). Pass
// time.Now to use the system clock:
//
//	cms.NewSigner(cert, key, cms.WithSigningTimeFunc(time.Now))
//
// The clock is called inside Sign(), so each call captures the time at the
// moment of signing rather than at signer construction time. If not configured,
// no signing-time attribute is included.
//
// Note: id-signingTime carries the time claimed by the signer and is not
// cryptographically bound to a trusted source. For a verifiable trusted
// timestamp, use WithTimestamp instead.
func WithSigningTimeFunc(clock func() time.Time) SignerOption {
	return &signerOption{f: func(s *Signer) error {
		if clock == nil {
			return newConfigError("WithSigningTimeFunc: clock function must not be nil")
		}
		s.clockFn = clock
		return nil
	}}
}

// WithoutCertificates omits all certificates from the SignedData output. Use
// this when certificates are delivered out of band. The Certificates field in
// RFC 5652 SignedData is OPTIONAL, so the output is a valid CMS message.
// Any certificates added via AddCertificate are silently ignored.
func WithoutCertificates() SignerOption {
	return &signerOption{f: func(s *Signer) error {
		s.noCerts = true
		return nil
	}}
}

// --- Options for Encryptor, SymmetricEncryptor, Digester, Authenticator ---

// WithRecipient adds a recipient certificate for key delivery. Auto-selects
// RSA-OAEP (RSA key) or ECDH ephemeral-static (EC key). At least one recipient
// is required for NewEncryptor and NewAuthenticator.
func WithRecipient(cert *x509.Certificate) RecipientOption {
	return &recipientOpt{cert: cert}
}

// WithContentEncryption sets the symmetric cipher for content encryption.
// Applies to NewEncryptor and NewSymmetricEncryptor. Defaults to AES256GCM.
func WithContentEncryption(alg ContentEncryptionAlgorithm) ContentEncryptionOption {
	return &contentEncryptionOpt{alg: alg}
}

// WithKey sets the symmetric content encryption key for NewSymmetricEncryptor.
// Must be 16 bytes (AES-128) or 32 bytes (AES-256). Required.
func WithKey(key []byte) SymmetricEncryptorOption {
	return &keyOpt{key: key}
}

// WithMACAlgorithm sets the HMAC algorithm for NewAuthenticator.
// Defaults to HMACSHA256.
func WithMACAlgorithm(alg MACAlgorithm) AuthenticatorOption {
	return &macAlgOpt{alg: alg}
}

// WithMaxContentSize sets the maximum content size in bytes for NewEncryptor,
// NewSymmetricEncryptor, NewDigester, and NewAuthenticator. Defaults to
// DefaultMaxAttachedSize (64 MiB). Pass UnlimitedAttachedSize to disable.
func WithMaxContentSize(maxBytes int64) ContentSizeOption {
	return &contentSizeOpt{maxBytes: maxBytes}
}
