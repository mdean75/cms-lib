//go:build ignore

// gen.go generates BC-compatible CMS fixtures for cms-lib interop testing.
// It produces the same ASN.1 encoding choices that Bouncy Castle uses:
//   - digestAlgorithm AlgorithmIdentifier includes explicit NULL parameters
//   - RSA PKCS1v15 signatureAlgorithm uses sha256WithRSAEncryption OID
//   - RSA-PSS params include trailerField=1 explicitly
//
// Run from the module root:
//
//	go run testdata/bc/gen.go
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

const (
	signedDir   = "testdata/bc/signed"
	envelopedDir = "testdata/bc/enveloped"
)

var nullParam = asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal}

func main() {
	content := readFile("testdata/content.bin")

	// RSA key pair + self-signed cert.
	rsaKey, rsaCert := genRSACert(big.NewInt(1))
	writePEM(signedDir+"/rsa_signer.cert.pem", "CERTIFICATE", rsaCert.Raw)

	// ECDSA P-256 key pair + self-signed cert.
	ecP256Key, ecP256Cert := genECCert(elliptic.P256(), big.NewInt(2))
	writePEM(signedDir+"/ec_p256_signer.cert.pem", "CERTIFICATE", ecP256Cert.Raw)

	// ECDSA P-384 key pair (used only for attached_ec_p384_sha384.der fixture).
	ecP384Key, ecP384Cert := genECCert(elliptic.P384(), big.NewInt(3))
	writePEM(signedDir+"/ec_p384_signer.cert.pem", "CERTIFICATE", ecP384Cert.Raw)

	// Ed25519 key pair + self-signed cert.
	ed25519PubKey, ed25519PrivKey, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	ed25519Cert := selfSignedEd25519Cert(ed25519PubKey, ed25519PrivKey, big.NewInt(4))
	writePEM(signedDir+"/ed25519_signer.cert.pem", "CERTIFICATE", ed25519Cert.Raw)

	// Extra cert for the with-chain fixture.
	_, extraCert := genRSACert(big.NewInt(99))

	// RSA recipient key for EnvelopedData fixtures.
	rsaRecipKey, rsaRecipCert := genRSACert(big.NewInt(10))
	writePEM(envelopedDir+"/rsa_recip.cert.pem", "CERTIFICATE", rsaRecipCert.Raw)
	writePKCS8(envelopedDir+"/rsa_recip.key.pem", rsaRecipKey)

	// EC P-256 recipient for ECDH EnvelopedData fixture.
	ecRecipKey, ecRecipCert := genECCert(elliptic.P256(), big.NewInt(11))
	writePEM(envelopedDir+"/ec_p256_recip.cert.pem", "CERTIFICATE", ecRecipCert.Raw)
	writePKCS8(envelopedDir+"/ec_p256_recip.key.pem", ecRecipKey)

	// ----- SignedData fixtures -----

	// 1. attached_rsa_pkcs1_sha256.der
	// BC uses sha256WithRSAEncryption (1.2.840.113549.1.1.11) as signatureAlgorithm
	// and includes NULL params in digestAlgorithm.
	genRSAPKCS1Attached(rsaKey, rsaCert, content, signedDir+"/attached_rsa_pkcs1_sha256.der")

	// 2. detached_rsa_pkcs1_sha256.der
	genRSAPKCS1Detached(rsaKey, rsaCert, content, signedDir+"/detached_rsa_pkcs1_sha256.der")

	// 3. attached_rsa_pss_sha256.der
	// BC includes trailerField=1 explicitly (our library already does).
	// Also adds NULL to digestAlgorithm.
	genRSAPSSAttached(rsaKey, rsaCert, content, crypto.SHA256, signedDir+"/attached_rsa_pss_sha256.der")

	// 4. attached_rsa_pss_sha384.der
	genRSAPSSAttached(rsaKey, rsaCert, content, crypto.SHA384, signedDir+"/attached_rsa_pss_sha384.der")

	// 5. attached_ec_p256_sha256.der
	genECDSAAttached(ecP256Key, ecP256Cert, content, signedDir+"/attached_ec_p256_sha256.der")

	// 6. attached_ec_p384_sha384.der
	genECDSAAttached(ecP384Key, ecP384Cert, content, signedDir+"/attached_ec_p384_sha384.der")

	// 7. attached_ed25519.der
	genEd25519Attached(ed25519PrivKey, ed25519Cert, content, signedDir+"/attached_ed25519.der")

	// 8. attached_rsa_pkcs1_with_chain.der — certificates bag has signer + extra cert.
	genRSAPKCS1WithChain(rsaKey, rsaCert, extraCert, content, signedDir+"/attached_rsa_pkcs1_with_chain.der")

	// 9. attached_rsa_pkcs1_no_certs.der — certificates field absent.
	genRSAPKCS1NoCerts(rsaKey, rsaCert, content, signedDir+"/attached_rsa_pkcs1_no_certs.der")

	// ----- EnvelopedData fixtures -----

	// 10. rsa_oaep_sha256_aes256cbc.der
	// BC uses RSA-OAEP with SHA-256 (explicit in RSAESOAEPParams) + AES-256-CBC.
	// Our library also uses SHA-256 OAEP + AES-256-CBC so no post-processing needed.
	genRSAOAEPEnveloped(rsaRecipCert, content, envelopedDir+"/rsa_oaep_sha256_aes256cbc.der")

	// 11. ec_p256_aes256cbc.der
	genECDHEnveloped(ecRecipCert, content, envelopedDir+"/ec_p256_aes256cbc.der")

	log.Println("BC-compatible fixtures written to", signedDir, "and", envelopedDir)
}

// ---------------------------------------------------------------------------
// SignedData generators
// ---------------------------------------------------------------------------

// genRSAPKCS1Attached signs with RSA PKCS1v15 and post-processes to use
// sha256WithRSAEncryption OID and NULL digestAlgorithm params (BC style).
func genRSAPKCS1Attached(key *rsa.PrivateKey, cert *x509.Certificate, content []byte, path string) {
	s := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1()))
	der := mustSign(s, content)
	write(path, bcStylePKCS1(parseSD(der)))
}

// genRSAPKCS1Detached signs detached with RSA PKCS1v15 (BC style).
func genRSAPKCS1Detached(key *rsa.PrivateKey, cert *x509.Certificate, content []byte, path string) {
	s := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1(), cms.WithDetachedContent()))
	der := mustSign(s, content)
	write(path, bcStylePKCS1(parseSD(der)))
}

// bcStylePKCS1 post-processes a PKCS1v15 SHA-256 SignedData to use the BC
// encoding: sha256WithRSAEncryption OID for signatureAlgorithm, NULL params
// in digestAlgorithm.
func bcStylePKCS1(sd pkiasn1.SignedData) []byte {
	addNullParams(&sd)
	for i := range sd.SignerInfos {
		sd.SignerInfos[i].SignatureAlgorithm = pkix.AlgorithmIdentifier{
			Algorithm: pkiasn1.OIDSignatureAlgorithmSHA256WithRSA,
		}
	}
	return wrapSD(sd)
}

// genRSAPSSAttached signs with RSA-PSS and adds NULL params to digestAlgorithm.
func genRSAPSSAttached(key *rsa.PrivateKey, cert *x509.Certificate, content []byte, h crypto.Hash, path string) {
	var opt cms.SigningOption
	switch h {
	case crypto.SHA384:
		opt = cms.WithHash(crypto.SHA384)
	case crypto.SHA512:
		opt = cms.WithHash(crypto.SHA512)
	default:
		opt = cms.WithHash(crypto.SHA256)
	}
	s := must2(cms.NewSigner(cert, key, opt))
	der := mustSign(s, content)
	sd := parseSD(der)
	addNullParams(&sd)
	write(path, wrapSD(sd))
}

// genECDSAAttached signs with ECDSA and adds NULL params to digestAlgorithm.
func genECDSAAttached(key *ecdsa.PrivateKey, cert *x509.Certificate, content []byte, path string) {
	s := must2(cms.NewSigner(cert, key))
	der := mustSign(s, content)
	sd := parseSD(der)
	addNullParams(&sd)
	write(path, wrapSD(sd))
}

// genEd25519Attached signs with Ed25519 (no BC-specific quirks needed).
func genEd25519Attached(key ed25519.PrivateKey, cert *x509.Certificate, content []byte, path string) {
	s := must2(cms.NewSigner(cert, key))
	der := mustSign(s, content)
	write(path, der)
}

// genRSAPKCS1WithChain includes an extra unrelated cert in the certificates bag.
func genRSAPKCS1WithChain(key *rsa.PrivateKey, cert *x509.Certificate, extra *x509.Certificate, content []byte, path string) {
	s := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1(), cms.AddCertificate(extra)))
	der := mustSign(s, content)
	write(path, bcStylePKCS1(parseSD(der)))
}

// genRSAPKCS1NoCerts signs without including any certificates in the bag.
func genRSAPKCS1NoCerts(key *rsa.PrivateKey, cert *x509.Certificate, content []byte, path string) {
	s := must2(cms.NewSigner(cert, key, cms.WithRSAPKCS1(), cms.WithoutCertificates()))
	der := mustSign(s, content)
	write(path, bcStylePKCS1(parseSD(der)))
}

// addNullParams adds explicit NULL parameters to all digestAlgorithm entries
// in the SignedData, simulating Bouncy Castle's encoding style.
func addNullParams(sd *pkiasn1.SignedData) {
	for i := range sd.DigestAlgorithms {
		sd.DigestAlgorithms[i].Parameters = nullParam
	}
	for i := range sd.SignerInfos {
		sd.SignerInfos[i].DigestAlgorithm.Parameters = nullParam
	}
}

// ---------------------------------------------------------------------------
// EnvelopedData generators
// ---------------------------------------------------------------------------

// genRSAOAEPEnveloped encrypts content for the RSA recipient using AES-256-CBC.
func genRSAOAEPEnveloped(recipCert *x509.Certificate, content []byte, path string) {
	enc := must2(cms.NewEncryptor(cms.WithRecipient(recipCert), cms.WithContentEncryption(cms.AES256CBC)))
	der, err := enc.Encrypt(bytes.NewReader(content))
	must(err)
	write(path, der)
}

// genECDHEnveloped encrypts content for the ECDH P-256 recipient using AES-256-CBC.
func genECDHEnveloped(recipCert *x509.Certificate, content []byte, path string) {
	enc := must2(cms.NewEncryptor(cms.WithRecipient(recipCert), cms.WithContentEncryption(cms.AES256CBC)))
	der, err := enc.Encrypt(bytes.NewReader(content))
	must(err)
	write(path, der)
}

// ---------------------------------------------------------------------------
// Key and certificate generation
// ---------------------------------------------------------------------------

func genRSACert(serial *big.Int) (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	return key, selfSignedRSACert(key, serial)
}

func genECCert(curve elliptic.Curve, serial *big.Int) (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	must(err)
	return key, selfSignedECCert(key, serial)
}

func selfSignedRSACert(key *rsa.PrivateKey, serial *big.Int) *x509.Certificate {
	tmpl := certTemplate(serial)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	cert, err := x509.ParseCertificate(certDER)
	must(err)
	return cert
}

func selfSignedECCert(key *ecdsa.PrivateKey, serial *big.Int) *x509.Certificate {
	tmpl := certTemplate(serial)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	cert, err := x509.ParseCertificate(certDER)
	must(err)
	return cert
}

func selfSignedEd25519Cert(pub ed25519.PublicKey, priv ed25519.PrivateKey, serial *big.Int) *x509.Certificate {
	tmpl := certTemplate(serial)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	must(err)
	cert, err := x509.ParseCertificate(certDER)
	must(err)
	return cert
}

func certTemplate(serial *big.Int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "cms-lib-bc-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	}
}

// ---------------------------------------------------------------------------
// ASN.1 helpers (mirrors edge_cases/gen.go)
// ---------------------------------------------------------------------------

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

func parseSD(der []byte) pkiasn1.SignedData {
	var ci pkiasn1.ContentInfo
	_, err := asn1.Unmarshal(der, &ci)
	must(err)
	var sd pkiasn1.SignedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	must(err)
	return sd
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

func mustSign(s *cms.Signer, content []byte) []byte {
	der, err := s.Sign(bytes.NewReader(content))
	must(err)
	return der
}

func must2[T any](v T, err error) T {
	must(err)
	return v
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

func writePKCS8(path string, key crypto.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	log.Printf("  wrote %s", path)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
