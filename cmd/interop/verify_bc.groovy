#!/usr/bin/env groovy
// verify_bc.groovy — verifies signed.der using Bouncy Castle CMS and prints the
// recovered message.
//
// Usage:
//   groovy verify_bc.groovy [--no-embed]
//
// Flags:
//   --embed      leaf cert is embedded in the payload (default)
//   --no-embed   leaf cert is not embedded; loaded from leaf.pem out-of-band
//
// Run from cmd/interop/ after 'go run . [-identifier isn|ski] [-embed=true|false]'
// Note: Bouncy Castle handles both ISN and SKI signer identifiers transparently.
//
// Requires: groovy and Java in PATH. Bouncy Castle JARs are fetched automatically
// via Grape (Groovy's built-in dependency manager) on first run.

@GrabConfig(systemClassLoader = true)
@Grab('org.bouncycastle:bcprov-jdk18on:1.80')
@Grab('org.bouncycastle:bcpkix-jdk18on:1.80')

import java.security.Security
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.util.CollectionStore

Security.addProvider(new BouncyCastleProvider())

// --- parse arguments ---
def argList = (args ?: []) as List
def embed   = !argList.contains('--no-embed')

if (argList.any { it != '--embed' && it != '--no-embed' }) {
    System.err.println "Usage: groovy verify_bc.groovy [--embed|--no-embed]"
    System.exit(1)
}

// --- required files ---
def signedFile       = new File('signed.der')
def rootCAFile       = new File('root_ca.pem')
def intermediateFile = new File('intermediate_ca.pem')
def leafFile         = new File('leaf.pem')

def required = [signedFile, rootCAFile, intermediateFile]
if (!embed) required << leafFile

for (f in required) {
    if (!f.exists()) {
        System.err.println "error: ${f.name} not found — run 'go run .' first"
        System.exit(1)
    }
}

// --- load certs from disk ---
def converter = new JcaX509CertificateConverter().setProvider('BC')

def parsePEM = { File f ->
    def p = new PEMParser(new StringReader(f.text))
    def h = (X509CertificateHolder) p.readObject()
    p.close()
    [holder: h, cert: converter.getCertificate(h)]
}

def root  = parsePEM(rootCAFile)
def interm = parsePEM(intermediateFile)
def leaf  = embed ? null : parsePEM(leafFile)

// --- verify ---
println "Verifying signed.der with Bouncy Castle (embed=${embed})..."

def cmsSignedData   = new CMSSignedData(signedFile.bytes)
def embeddedStore   = cmsSignedData.getCertificates()
def signerInfos     = cmsSignedData.getSignerInfos()
def verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder().setProvider('BC')

boolean allValid = true

for (SignerInformation signer : signerInfos.getSigners()) {
    // Find the leaf cert via the signer identifier (ISN or SKI — BC handles both).
    // Check the embedded cert bag first; if empty, fall back to the out-of-band file.
    def matches = embeddedStore.getMatches(signer.getSID())
    if (matches.isEmpty() && !embed) {
        matches = new CollectionStore([leaf.holder]).getMatches(signer.getSID())
    }
    if (matches.isEmpty()) {
        System.err.println "No certificate found for signer SID: ${signer.getSID()}"
        allValid = false
        continue
    }

    def leafCert = converter.getCertificate(matches.iterator().next())

    // Cryptographic signature verification.
    if (signer.verify(verifierBuilder.build(leafCert))) {
        println "Signature valid — signer: ${leafCert.subjectX500Principal}"
    } else {
        System.err.println "Signature INVALID — signer: ${leafCert.subjectX500Principal}"
        allValid = false
        continue
    }

    // PKIX chain validation: [leaf, intermediate] → root CA trust anchor.
    try {
        def certFactory = CertificateFactory.getInstance("X.509", "BC")
        def certPath    = certFactory.generateCertPath([leafCert, interm.cert])

        def trustAnchor = new TrustAnchor(root.cert, null)
        def pkixParams  = new PKIXParameters(Collections.singleton(trustAnchor))
        pkixParams.revocationEnabled = false

        CertPathValidator.getInstance("PKIX", "BC").validate(certPath, pkixParams)
        println "Chain valid — leaf → intermediate CA → root CA"
    } catch (Exception e) {
        System.err.println "Chain validation FAILED — ${e.message}"
        allValid = false
    }
}

if (!allValid) {
    System.err.println "Verification FAILED"
    System.exit(1)
}

def content = (byte[]) cmsSignedData.getSignedContent().getContent()
println "Verified message: ${new String(content, 'UTF-8')}"
println "Verification successful."
