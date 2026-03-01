//go:build ignore

// gen.go generates the edge-case DER fixtures for cms-lib interop testing.
// Run from the module root:
//
//	go run testdata/edge_cases/gen.go
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	cms "github.com/mdean75/cms-lib"
	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

const outDir = "testdata/edge_cases"

func main() {
	content := readFile("testdata/content.bin")

	// Primary signing key + self-signed cert.
	key, cert := generateRSACert(big.NewInt(1))
	writePEM(outDir+"/rsa_signer.cert.pem", "CERTIFICATE", cert.Raw)

	// A second unrelated cert for the extra_cert_in_bag fixture.
	_, extraCert := generateRSACert(big.NewInt(2))

	// Baseline: PKCS1v15 SHA-256 attached SignedData (most fixtures derive from this).
	pkcs1Signer := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1()))
	baseline := mustSign(pkcs1Signer, content)
	baseSD := parseSD(baseline)

	// Baseline PSS signed DER.  Our library encodes all four RSASSA-PSS-params
	// fields including trailerField=1, so pssBaseline serves for both PSS fixtures
	// that only differ in the presence/absence of individual param fields.
	pssSigner := must2(cms.NewSigner(cert, key))
	pssBaseline := mustSign(pssSigner, content)

	genSHA256NullParams(baseSD, content)
	write(outDir+"/rsa_pss_trailer_explicit.der", pssBaseline)
	write(outDir+"/rsa_pss_all_defaults_present.der", pssBaseline)
	genRSAPSSSaltLen20(key, cert, content)
	genEmptyCertificatesSet(baseSD)
	genExtraCertInBag(cert, key, extraCert, content)
	genBERIndefiniteOuter(baseline)
	genBERLongFormLengths(baseline)
	genBERConstructedOctet(baseSD, content)
	genMultiSignerDedup(cert, key, content)
	genLargeSerialNumber(key, content)

	log.Println("Edge-case fixtures written to", outDir)
}

// ---------------------------------------------------------------------------
// Fixture generators
// ---------------------------------------------------------------------------

// genSHA256NullParams produces a PKCS1v15 SHA-256 SignedData where the
// digestAlgorithm AlgorithmIdentifier carries an explicit NULL parameters
// field. RFC 5754 §2 says parameters SHOULD be absent, but a receiver MUST
// accept NULL when present. Bouncy Castle and some PKCS#11 tokens use this.
func genSHA256NullParams(sd pkiasn1.SignedData, _ []byte) {
	nullParam := asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal}

	for i := range sd.DigestAlgorithms {
		sd.DigestAlgorithms[i].Parameters = nullParam
	}
	for i := range sd.SignerInfos {
		sd.SignerInfos[i].DigestAlgorithm.Parameters = nullParam
	}

	write(outDir+"/sha256_null_params.der", wrapSD(sd))
}

// genRSAPSSSaltLen20 creates an RSA-PSS SHA-256 signature with saltLength=20.
// RFC 4055 allows any non-negative salt length. This fixture tests that our
// verifier uses the saltLength value from the RSASSA-PSS-params rather than
// hardcoding the hash output size.
func genRSAPSSSaltLen20(key *rsa.PrivateKey, cert *x509.Certificate, content []byte) {
	const saltLen = 20

	// Compute content digest.
	h := sha256.New()
	h.Write(content)
	contentDigest := h.Sum(nil)

	// Build signedAttrs: content-type + message-digest.
	ctVal, _ := asn1.Marshal(pkiasn1.OIDData)
	mdVal, _ := asn1.Marshal(contentDigest)
	signedAttrs := []pkiasn1.Attribute{
		{
			Type:   pkiasn1.OIDAttributeContentType,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(ctVal)},
		},
		{
			Type:   pkiasn1.OIDAttributeMessageDigest,
			Values: asn1.RawValue{FullBytes: mustMarshalSet(mdVal)},
		},
	}
	signedAttrsBytes := mustMarshalAttrSet(signedAttrs)

	// Sign over SET-tagged signedAttrs with PSS saltLen=20.
	h2 := sha256.New()
	h2.Write(signedAttrsBytes)
	attrsDigest := h2.Sum(nil)

	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, attrsDigest,
		&rsa.PSSOptions{SaltLength: saltLen, Hash: crypto.SHA256})
	must(err)

	// Build RSASSA-PSS-params with SaltLength=20.
	hashOID := pkiasn1.OIDDigestAlgorithmSHA256
	params := pkiasn1.RSAPSSParams{
		HashAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: hashOID},
		MaskGenAlgorithm: mgf1AlgID(hashOID),
		SaltLength:       saltLen,
		TrailerField:     1,
	}
	rawParams, _ := asn1.Marshal(params)

	sigAlgID := pkix.AlgorithmIdentifier{
		Algorithm:  pkiasn1.OIDSignatureAlgorithmRSAPSS,
		Parameters: asn1.RawValue{FullBytes: rawParams},
	}

	// Build SignerInfo using IssuerAndSerialNumber.
	isn := pkiasn1.IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	}
	isnDER, _ := asn1.Marshal(isn)

	si := pkiasn1.SignerInfo{
		Version:           1,
		SID:               asn1.RawValue{FullBytes: isnDER},
		DigestAlgorithm:   pkix.AlgorithmIdentifier{Algorithm: hashOID},
		SignedAttrs:       asn1.RawValue{FullBytes: signedAttrsBytes},
		SignatureAlgorithm: sigAlgID,
		Signature:         sig,
	}
	// Re-tag SignedAttrs to IMPLICIT [0] for the wire form.
	si.SignedAttrs.FullBytes[0] = 0xA0

	// Build SignedData.
	certDER := asn1.RawValue{FullBytes: cert.Raw}
	eContentDER, _ := asn1.Marshal(content)
	eContentWrapper, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      eContentDER,
	})
	sd := pkiasn1.SignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: hashOID}},
		EncapContentInfo: pkiasn1.EncapsulatedContentInfo{
			EContentType: pkiasn1.OIDData,
			EContent:     asn1.RawValue{FullBytes: eContentWrapper},
		},
		Certificates: []asn1.RawValue{certDER},
		SignerInfos:  []pkiasn1.SignerInfo{si},
	}

	write(outDir+"/rsa_pss_saltlen_20.der", wrapSD(sd))
}

// genEmptyCertificatesSet produces a SignedData where the certificates [0]
// field is present but contains an empty SET. RFC 5652 allows this; it must
// not be confused with the field being absent.
func genEmptyCertificatesSet(sd pkiasn1.SignedData) {
	// Use a local struct that omits "optional" from the Certificates field so
	// an empty slice marshals as A0 00 instead of being omitted.
	type sdEmptyCerts struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		EncapContentInfo pkiasn1.EncapsulatedContentInfo
		Certificates     []asn1.RawValue `asn1:"set,tag:0"` // no "optional"
		SignerInfos      []pkiasn1.SignerInfo `asn1:"set"`
	}
	empty := sdEmptyCerts{
		Version:          sd.Version,
		DigestAlgorithms: sd.DigestAlgorithms,
		EncapContentInfo: sd.EncapContentInfo,
		Certificates:     []asn1.RawValue{}, // present but empty
		SignerInfos:      sd.SignerInfos,
	}

	sdBytes, _ := asn1.Marshal(empty)
	explicit0, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdBytes,
	})
	ci := pkiasn1.ContentInfo{
		ContentType: pkiasn1.OIDSignedData,
		Content:     asn1.RawValue{FullBytes: explicit0},
	}
	ciDER, _ := asn1.Marshal(ci)
	write(outDir+"/empty_certificates_set.der", ciDER)
}

// genExtraCertInBag signs content and includes an extra unrelated certificate
// in the certificates bag. The verifier should succeed and ignore the extra cert.
func genExtraCertInBag(cert *x509.Certificate, key *rsa.PrivateKey, extra *x509.Certificate, content []byte) {
	s := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1(), cms.AddCertificate(extra)))
	write(outDir+"/extra_cert_in_bag.der", mustSign(s, content))
}

// genBERIndefiniteOuter wraps the outermost ContentInfo SEQUENCE in BER
// indefinite-length encoding. The BER normalizer must convert this to DER
// before the structure is parsed.
func genBERIndefiniteOuter(der []byte) {
	tag, content, _ := parseTLV(der)
	// 30 80 [content bytes] 00 00
	result := []byte{tag, 0x80}
	result = append(result, content...)
	result = append(result, 0x00, 0x00)
	write(outDir+"/ber_indefinite_outer.der", result)
}

// genBERLongFormLengths produces the ContentInfo with a non-minimal (padded)
// outer length encoding. DER requires the shortest form; BER allows leading
// zero bytes in the multi-byte length. The BER normalizer must strip the
// extra byte.
func genBERLongFormLengths(der []byte) {
	if der[0] != 0x30 {
		log.Fatal("expected SEQUENCE tag")
	}
	if der[1]&0x80 == 0 {
		log.Fatal("expected multi-byte length for ContentInfo")
	}
	nBytes := int(der[1] & 0x7F)
	lenBytes := der[2 : 2+nBytes]
	rest := der[2+nBytes:]

	// Insert one extra leading zero into the length: e.g., 82 01 F4 → 83 00 01 F4
	newLen := make([]byte, 1+nBytes)
	newLen[0] = 0x00
	copy(newLen[1:], lenBytes)

	result := []byte{0x30, byte(0x80 | (nBytes + 1))}
	result = append(result, newLen...)
	result = append(result, rest...)
	write(outDir+"/ber_long_form_lengths.der", result)
}

// genBERConstructedOctet produces a SignedData where the eContent OCTET STRING
// uses BER constructed encoding (tag 0x24), chunked into two halves. The BER
// normalizer must flatten this to a single primitive OCTET STRING before
// digest verification.
func genBERConstructedOctet(sd pkiasn1.SignedData, content []byte) {
	// Split content into two equal chunks.
	mid := len(content) / 2
	chunk1, _ := asn1.Marshal(content[:mid])
	chunk2, _ := asn1.Marshal(content[mid:])

	// Build CONSTRUCTED OCTET STRING (tag 0x24 = OCTET STRING | CONSTRUCTED).
	inner := append(chunk1, chunk2...)
	constructed := append([]byte{0x24, byte(len(inner))}, inner...)

	// Build the [0] EXPLICIT wrapper containing the constructed OCTET STRING and
	// assign it to EContent.FullBytes directly. asn1.Marshal ignores struct tag
	// annotations (including explicit,tag:0) when FullBytes is non-empty, so we
	// must pre-build the complete wrapper here.
	outerWrapper, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      constructed,
	})
	sd.EncapContentInfo.EContent = asn1.RawValue{FullBytes: outerWrapper}

	write(outDir+"/ber_constructed_octet.der", wrapSD(sd))
}

// genMultiSignerDedup uses our library's WithAdditionalSigner option to create
// a SignedData with two SignerInfos that both use SHA-256. The digestAlgorithms
// SET must contain SHA-256 exactly once (RFC 5652 deduplication).
func genMultiSignerDedup(cert *x509.Certificate, key *rsa.PrivateKey, content []byte) {
	s2 := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1()))
	s := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1(),
		cms.WithAdditionalSigner(s2)))
	write(outDir+"/multi_signer_dedup.der", mustSign(s, content))
}

// genLargeSerialNumber generates a certificate with a 20-byte (160-bit)
// serial number where the high bit is set, requiring a leading zero byte in
// the DER INTEGER encoding. The IssuerAndSerialNumber in the SignerInfo must
// encode and match the same value.
func genLargeSerialNumber(key *rsa.PrivateKey, content []byte) {
	// 20-byte serial with high bit set: requires leading 0x00 in DER INTEGER.
	serialBytes := make([]byte, 20)
	serialBytes[0] = 0xFF // high bit set
	serialBytes[19] = 0x42
	serial := new(big.Int).SetBytes(serialBytes)

	_, largeCert := generateRSACertWithSerial(key, serial)
	s := must2(cms.NewSigner(largeCert, key, cms.WithRSAPKCS1()))
	write(outDir+"/large_serial_number.der", mustSign(s, content))
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// wrapSD marshals a SignedData into a ContentInfo DER encoding.
func wrapSD(sd pkiasn1.SignedData) []byte {
	sdBytes, err := asn1.Marshal(sd)
	must(err)
	explicit0, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdBytes,
	})
	must(err)
	ci := pkiasn1.ContentInfo{
		ContentType: pkiasn1.OIDSignedData,
		Content:     asn1.RawValue{FullBytes: explicit0},
	}
	ciDER, err := asn1.Marshal(ci)
	must(err)
	return ciDER
}

// parseSD parses a DER ContentInfo+SignedData and returns the SignedData struct.
func parseSD(der []byte) pkiasn1.SignedData {
	var ci pkiasn1.ContentInfo
	_, err := asn1.Unmarshal(der, &ci)
	must(err)
	var sd pkiasn1.SignedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	must(err)
	return sd
}

// parseTLV returns the tag byte, content bytes, and remaining bytes from a
// DER/BER TLV at the start of b.
func parseTLV(b []byte) (tag byte, content, rest []byte) {
	tag = b[0]
	if b[1] < 0x80 {
		l := int(b[1])
		return tag, b[2 : 2+l], b[2+l:]
	}
	n := int(b[1] & 0x7F)
	l := 0
	for i := 0; i < n; i++ {
		l = (l << 8) | int(b[2+i])
	}
	start := 2 + n
	return tag, b[start : start+l], b[start+l:]
}

// mustMarshalAttrSet marshals a slice of Attributes as a DER SET (tag 0x31).
func mustMarshalAttrSet(attrs []pkiasn1.Attribute) []byte {
	var parts []byte
	for _, attr := range attrs {
		b, err := asn1.Marshal(attr)
		must(err)
		parts = append(parts, b...)
	}
	result := []byte{0x31, byte(len(parts))}
	return append(result, parts...)
}

// mustMarshalSet wraps DER bytes in a SET TLV (tag 0x31).
func mustMarshalSet(inner []byte) []byte {
	result := []byte{0x31, byte(len(inner))}
	return append(result, inner...)
}

// mgf1AlgID builds a MGF1 AlgorithmIdentifier with the given hash OID.
func mgf1AlgID(hashOID asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	inner, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: hashOID})
	return pkix.AlgorithmIdentifier{
		Algorithm:  pkiasn1.OIDMGF1,
		Parameters: asn1.RawValue{FullBytes: inner},
	}
}

// generateRSACert generates a fresh RSA-2048 key and self-signed certificate
// with the given serial number.
func generateRSACert(serial *big.Int) (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	return key, selfSignedCert(key, serial)
}

// generateRSACertWithSerial creates a self-signed certificate for an existing
// key using the provided serial number.
func generateRSACertWithSerial(key *rsa.PrivateKey, serial *big.Int) (*rsa.PrivateKey, *x509.Certificate) {
	return key, selfSignedCert(key, serial)
}

// selfSignedCert issues a self-signed X.509 certificate for key.
func selfSignedCert(key *rsa.PrivateKey, serial *big.Int) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "cms-lib-edge-case"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	cert, err := x509.ParseCertificate(certDER)
	must(err)
	return cert
}

// mustSigner is an alias for must2 for Signer construction.
func must2[T any](v T, err error) T {
	must(err)
	return v
}

// mustSign signs content and returns the DER bytes, fataling on error.
func mustSign(s *cms.Signer, content []byte) []byte {
	der, err := s.Sign(bytes.NewReader(content))
	must(err)
	return der
}

func readFile(path string) []byte {
	b, err := os.ReadFile(path)
	must(err)
	return b
}

func write(path string, data []byte) {
	must(os.WriteFile(path, data, 0o644))
	log.Printf("  wrote %s (%d bytes)", path, len(data))
}

func writePEM(path, typ string, der []byte) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: typ, Bytes: der}))
	log.Printf("  wrote %s", path)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
