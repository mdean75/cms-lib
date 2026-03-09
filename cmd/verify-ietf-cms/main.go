// Command verify-ietf-cms verifies a CMS SignedData file produced by the interop
// program using github.com/smimesign/ietf-cms and prints the recovered message.
//
// Known limitations of github.com/smimesign/ietf-cms:
//
//   - SubjectKeyIdentifier signer identifiers always fail. The library's
//     FindCertificate method compares the raw SKI bytes from the SignerInfo SID
//     against cert.Extensions[n].Value, which is a DER-encoded OCTET STRING and
//     therefore includes a tag+length prefix. The correct comparison target is
//     cert.SubjectKeyId. This is a bug in the library.
//
// Usage (run from cmd/interop/ after 'go run .'):
//
//	go run ../verify-ietf-cms/ [-identifier isn|ski] [-embed=true|false]
//
// Flags:
//
//	-identifier  signer identifier used when signing: isn or ski (default "isn")
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

	cms "github.com/smimesign/ietf-cms"
)

func main() {
	identifier := flag.String("identifier", "isn", "signer identifier used when signing: isn or ski")
	embed := flag.Bool("embed", true, "leaf cert is embedded in the signed payload")
	flag.Parse()

	// Fail fast: SKI verification is broken in this library due to a comparison
	// bug in FindCertificate (compares raw SKI bytes against DER-encoded ext.Value).
	if *identifier == "ski" {
		log.Fatalf("github.com/smimesign/ietf-cms SKI support is broken: FindCertificate " +
			"compares raw SKI bytes against cert.Extensions[n].Value (a DER OCTET STRING " +
			"with tag+length prefix) instead of cert.SubjectKeyId")
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

	fmt.Printf("Verifying %s with github.com/smimesign/ietf-cms (identifier=%s embed=%v)...\n",
		signedPath, *identifier, *embed)

	sd, err := cms.ParseSignedData(der)
	if err != nil {
		log.Fatalf("parse: %v", err)
	}

	// The intermediate CA is never embedded; always load it out-of-band.
	// When embed=false the leaf cert is also absent and must be loaded too.
	// SetCertificates writes back to the parsed structure, which Verify() reads
	// via psd.X509Certificates(), so out-of-band certs are visible to FindCertificate.
	oobPaths := []string{intermPath}
	if !*embed {
		oobPaths = append([]string{leafPath}, oobPaths...)
	}
	existing, err := sd.GetCertificates()
	if err != nil {
		log.Fatalf("get certificates: %v", err)
	}
	for _, path := range oobPaths {
		cert, err := loadCertPEM(path)
		if err != nil {
			log.Fatalf("load %s: %v", path, err)
		}
		existing = append(existing, cert)
	}
	sd.SetCertificates(existing)

	rootCA, err := loadCertPEM(rootCAPath)
	if err != nil {
		log.Fatalf("load %s: %v", rootCAPath, err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCA)

	chains, err := sd.Verify(x509.VerifyOptions{Roots: rootPool})
	if err != nil {
		log.Fatalf("verify: %v", err)
	}

	// chains is [][][]*x509.Certificate — one entry per signer, each a verified chain.
	if len(chains) > 0 && len(chains[0]) > 0 {
		signerCert := chains[0][0][0]
		fmt.Printf("Signature valid — signer: %s\n", signerCert.Subject.CommonName)
	}
	content, err := sd.GetData()
	if err != nil {
		log.Fatalf("get data: %v", err)
	}
	fmt.Printf("Verified message: %s\n", content)
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
