package timestamp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// buildTestToken constructs a minimal but structurally valid timestamp token
// DER without using the cms package (to avoid a circular import). The token
// wraps a TSTInfo in a SignedData with eContentType id-ct-TSTInfo.
func buildTestToken(t *testing.T, sigBytes []byte) []byte {
	t.Helper()

	// Compute SHA-256 of sigBytes.
	digest := sha256.Sum256(sigBytes)

	tst := TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3},
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: pkiasn1.OIDDigestAlgorithmSHA256,
			},
			HashedMessage: digest[:],
		},
		SerialNumber: big.NewInt(1),
		GenTime:      time.Now().UTC().Truncate(time.Second),
	}

	tstDER, err := asn1.Marshal(tst)
	require.NoError(t, err)

	// Wrap TSTInfo DER in an OCTET STRING.
	octetString, err := asn1.Marshal(tstDER)
	require.NoError(t, err)

	// Wrap OCTET STRING in [0] EXPLICIT for eContent.
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      octetString,
	})
	require.NoError(t, err)

	// Build a minimal SignedData (no actual signature needed for ParseTSTInfo tests).
	algID := pkix.AlgorithmIdentifier{Algorithm: pkiasn1.OIDDigestAlgorithmSHA256}
	algIDDER, err := asn1.Marshal(algID)
	require.NoError(t, err)

	// Use a dummy self-signed cert + key for the SignerInfo.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-tsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)

	// Build IssuerAndSerialNumber for SignerInfo SID.
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	type issuerAndSerial struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	sidDER, err := asn1.Marshal(issuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	require.NoError(t, err)

	// Sign the TSTInfo OCTET STRING (which is what eContent contains).
	h := crypto.SHA256.New()
	h.Write(octetString)
	sigAlgID := pkix.AlgorithmIdentifier{Algorithm: pkiasn1.OIDSignatureAlgorithmSHA256WithRSA}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	require.NoError(t, err)

	// Assemble SignerInfo.
	type signerInfo struct {
		Version            int
		SID                asn1.RawValue
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
	}
	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: sidDER},
		DigestAlgorithm:    algID,
		SignatureAlgorithm: sigAlgID,
		Signature:          sig,
	}

	// Build SignedData.
	sd := pkiasn1.SignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{algID},
		EncapContentInfo: pkiasn1.EncapsulatedContentInfo{
			EContentType: pkiasn1.OIDTSTInfo,
			EContent:     asn1.RawValue{FullBytes: explicit0},
		},
		SignerInfos: []pkiasn1.SignerInfo{
			{
				Version:            si.Version,
				SID:                si.SID,
				DigestAlgorithm:    si.DigestAlgorithm,
				SignatureAlgorithm: si.SignatureAlgorithm,
				Signature:          si.Signature,
			},
		},
	}
	// Add cert.
	sd.Certificates = append(sd.Certificates, asn1.RawValue{FullBytes: certDER})

	_ = algIDDER // used via algID above

	sdDER, err := asn1.Marshal(sd)
	require.NoError(t, err)

	// Wrap SignedData in [0] EXPLICIT for ContentInfo.
	sdExplicit, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdDER,
	})
	require.NoError(t, err)

	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	ci := contentInfo{
		ContentType: pkiasn1.OIDSignedData,
		Content:     asn1.RawValue{FullBytes: sdExplicit},
	}
	ciDER, err := asn1.Marshal(ci)
	require.NoError(t, err)
	return ciDER
}

func TestParseTSTInfo(t *testing.T) {
	sigBytes := []byte("signature bytes to timestamp")
	token := buildTestToken(t, sigBytes)

	tst, err := ParseTSTInfo(token)
	require.NoError(t, err)
	require.NotNil(t, tst)

	assert.Equal(t, 1, tst.Version)
	assert.Equal(t, pkiasn1.OIDDigestAlgorithmSHA256, tst.MessageImprint.HashAlgorithm.Algorithm)

	// HashedMessage must equal SHA-256(sigBytes).
	expected := sha256.Sum256(sigBytes)
	assert.Equal(t, expected[:], tst.MessageImprint.HashedMessage)
}

func TestVerifyHash_Valid(t *testing.T) {
	sigBytes := []byte("the signature bytes")
	token := buildTestToken(t, sigBytes)

	err := VerifyHash(token, sigBytes)
	require.NoError(t, err)
}

func TestVerifyHash_Tampered(t *testing.T) {
	sigBytes := []byte("original signature bytes")
	token := buildTestToken(t, sigBytes)

	err := VerifyHash(token, []byte("tampered signature bytes"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestParseTSTInfo_InvalidDER(t *testing.T) {
	_, err := ParseTSTInfo([]byte{0xFF, 0xFE, 0xFD})
	require.Error(t, err)
}

func TestHashForAlgorithm_Unsupported(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 99}
	_, err := hashForAlgorithm(unknownOID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}
