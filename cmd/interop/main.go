// Command example demonstrates signing a payload with CMS SignedData using a
// three-level PKI hierarchy (root CA → intermediate CA → leaf).
//
// Usage:
//
//	go run . [-identifier isn|ski] [-embed=true|false]
//
// Flags:
//
//	-identifier  signer identifier type: isn (IssuerAndSerialNumber, default)
//	             or ski (SubjectKeyIdentifier — requires SKI extension in cert)
//	-embed       embed the leaf cert in the signed payload (default true);
//	             false produces a bare signature with no certs in the payload
//
// All cert files are always written to disk regardless of -embed:
//
//	root_ca.pem        trust anchor (deliver to verifiers out-of-band)
//	intermediate_ca.pem  chain cert  (deliver to verifiers out-of-band)
//	leaf.pem           signer cert  (only needed by verifiers when -embed=false)
//	signed.der         the CMS SignedData payload
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by RFC 5280 §4.2.1.2 for SKI computation
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	cms "github.com/mdean75/cms-lib"
)

const (
	signedFile       = "signed.der"
	rootCAFile       = "root_ca.pem"
	intermediateFile = "intermediate_ca.pem"
	leafFile         = "leaf.pem"
)

func main() {
	identifier := flag.String("identifier", "isn", "signer identifier: isn or ski")
	embed := flag.Bool("embed", true, "embed leaf cert in the signed payload")
	flag.Parse()

	if *identifier != "isn" && *identifier != "ski" {
		log.Fatalf("-identifier must be 'isn' or 'ski', got %q", *identifier)
	}

	rootCert, intermCert, leafCert, leafKey, err := generatePKIHierarchy()
	if err != nil {
		log.Fatalf("generate PKI hierarchy: %v", err)
	}

	payload := []byte("Hello, CMS! This message has been signed.")

	// Build signer options from flags.
	var signerOpts []cms.SignerOption
	if *identifier == "ski" {
		signerOpts = append(signerOpts, cms.WithSignerIdentifier(cms.SubjectKeyIdentifier))
	}
	if !*embed {
		signerOpts = append(signerOpts, cms.WithoutCertificates())
	}

	signer, err := cms.NewSigner(leafCert, leafKey, signerOpts...)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	der, err := signer.Sign(bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("sign: %v", err)
	}

	// Always write all cert files — verifiers may need them regardless of mode.
	writeFile(signedFile, der)
	writePEM(rootCAFile, rootCert.Raw)
	writePEM(intermediateFile, intermCert.Raw)
	writePEM(leafFile, leafCert.Raw)

	embedDesc := "leaf cert embedded"
	if !*embed {
		embedDesc = "no certs embedded"
	}
	fmt.Println("PKI hierarchy:  Root CA → Intermediate CA → Leaf")
	fmt.Printf("Identifier:     %s\n", *identifier)
	fmt.Printf("Signed payload  %d bytes (%s) → %s\n", len(der), embedDesc, signedFile)
	fmt.Printf("Certs written:  %s  %s  %s\n", rootCAFile, intermediateFile, leafFile)

	// --- Verify (library) ---
	parsed, err := cms.ParseSignedData(bytes.NewReader(der))
	if err != nil {
		log.Fatalf("parse signed data: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// The intermediate is never embedded; always supply it out-of-band.
	// When embed=false the leaf is also absent and must be supplied too.
	externalCerts := []cms.VerifyOption{cms.WithTrustRoots(rootPool)}
	if *embed {
		externalCerts = append(externalCerts, cms.WithExternalCertificates(intermCert))
	} else {
		externalCerts = append(externalCerts, cms.WithExternalCertificates(leafCert, intermCert))
	}

	if err := parsed.Verify(externalCerts...); err != nil {
		log.Fatalf("verify: %v", err)
	}

	r, err := parsed.Content()
	if err != nil {
		log.Fatalf("read content: %v", err)
	}
	msg, err := io.ReadAll(r)
	if err != nil {
		log.Fatalf("read message: %v", err)
	}

	fmt.Printf("Library verified message: %s\n", msg)

	// Print the equivalent commands for the other verifiers.
	flags := ""
	if !*embed {
		flags = " --no-embed"
	}
	fmt.Printf("\nVerify with:\n")
	fmt.Printf("  OpenSSL:        ./verify.sh%s\n", flags)
	fmt.Printf("  Bouncy Castle:  groovy verify_bc.groovy%s\n", flags)
	fmt.Printf("  pkcs7 (ISN only): go run ../verify-pkcs7/ -identifier %s -embed=%v\n", *identifier, *embed)
}

// generatePKIHierarchy builds a three-level PKI:
//   - Root CA (self-signed, MaxPathLen=1)
//   - Intermediate CA (signed by root, MaxPathLen=0)
//   - Leaf signing cert (signed by intermediate)
//
// All certs include the SubjectKeyIdentifier extension (RFC 5280 §4.2.1.2).
func generatePKIHierarchy() (rootCert, intermCert, leafCert *x509.Certificate, leafKey *ecdsa.PrivateKey, err error) {
	// Root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate root key: %w", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CMS Example Root CA"},
		SubjectKeyId:          ecSKI(&rootKey.PublicKey),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create root CA: %w", err)
	}
	rootCert, err = x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse root CA: %w", err)
	}

	// Intermediate CA — signed by root
	intermKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	intermTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "CMS Example Intermediate CA"},
		SubjectKeyId:          ecSKI(&intermKey.PublicKey),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermDER, err := x509.CreateCertificate(rand.Reader, intermTmpl, rootCert, &intermKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create intermediate CA: %w", err)
	}
	intermCert, err = x509.ParseCertificate(intermDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse intermediate CA: %w", err)
	}

	// Leaf cert — signed by intermediate
	leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "CMS Example Signer"},
		SubjectKeyId: ecSKI(&leafKey.PublicKey),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermCert, &leafKey.PublicKey, intermKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create leaf cert: %w", err)
	}
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	return rootCert, intermCert, leafCert, leafKey, nil
}

// ecSKI returns the Subject Key Identifier for an ECDSA public key.
// Per RFC 5280 §4.2.1.2, the SKI is the SHA-1 hash of the BIT STRING value
// of the subjectPublicKey field — for ECDSA that is the uncompressed point.
// SHA-1 is non-negotiable here: it is required by the RFC, not a security choice.
func ecSKI(pub *ecdsa.PublicKey) []byte {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		// Only fails for invalid keys, which cannot happen for freshly generated ones.
		panic("ecSKI: " + err.Error())
	}
	h := sha1.Sum(ecdhPub.Bytes()) //nolint:gosec // SHA-1 required by RFC 5280 §4.2.1.2
	return h[:]
}

func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}

func writePEM(path string, derBytes []byte) {
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	writeFile(path, b)
}
