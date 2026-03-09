// Command verify-pkcs7 verifies a CMS SignedData file produced by the interop
// program using github.com/mozilla-services/pkcs7 (import path go.mozilla.org/pkcs7)
// and prints the recovered message.
//
// Usage (run from cmd/interop/ after 'go run .'):
//
//	go run ../verify-pkcs7/ [-identifier isn|ski] [-embed=true|false]
//
// Flags:
//
//	-identifier  signer identifier used when signing: isn or ski (default "isn")
//	             Note: go.mozilla.org/pkcs7 only supports isn; ski will exit with
//	             an explanatory error rather than a cryptic library panic.
//	-embed       leaf cert is embedded in the payload (default true);
//	             false causes the leaf cert to be loaded from leaf.pem
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"go.mozilla.org/pkcs7"
)

func main() {
	identifier := flag.String("identifier", "isn", "signer identifier used when signing: isn or ski")
	embed := flag.Bool("embed", true, "leaf cert is embedded in the signed payload")
	flag.Parse()

	// Fail fast: the pkcs7 library only supports IssuerAndSerialNumber.
	if *identifier == "ski" {
		log.Fatalf("go.mozilla.org/pkcs7 does not support SubjectKeyIdentifier signer " +
			"identifiers; re-sign with -identifier isn or use a different verifier")
	}

	const (
		signedPath = "signed.der"
		rootCAPath = "root_ca.pem"
		intermPath = "intermediate_ca.pem"
		leafPath   = "leaf.pem"
	)

	der, err := os.ReadFile(signedPath)
	if err != nil {
		log.Fatalf("read %s: %v", signedPath, err)
	}

	fmt.Printf("Verifying %s with go.mozilla.org/pkcs7 (identifier=%s embed=%v)...\n",
		signedPath, *identifier, *embed)

	p7, err := pkcs7.Parse(der)
	if err != nil {
		log.Fatalf("parse: %v", err)
	}

	// The intermediate CA is never embedded; always load it out-of-band.
	// When embed=false the leaf cert is also absent and must be loaded too.
	oob := []string{intermPath}
	if !*embed {
		oob = append([]string{leafPath}, oob...)
	}
	for _, path := range oob {
		cert, err := loadCertPEM(path)
		if err != nil {
			log.Fatalf("load %s: %v", path, err)
		}
		p7.Certificates = append(p7.Certificates, cert)
	}

	rootCA, err := loadCertPEM(rootCAPath)
	if err != nil {
		log.Fatalf("load %s: %v", rootCAPath, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCA)

	if err := p7.VerifyWithChain(pool); err != nil {
		log.Fatalf("verify: %v", err)
	}

	signer := p7.GetOnlySigner()
	if signer != nil {
		fmt.Printf("Signature valid — signer: %s\n", signer.Subject.CommonName)
	}
	fmt.Printf("Verified message: %s\n", p7.Content)
}

// loadCertPEM reads a PEM-encoded certificate file and returns the first certificate.
func loadCertPEM(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}
