#!/usr/bin/env groovy
// CMSGenerator.groovy — regenerate BC-compatible CMS test fixtures using actual
// Bouncy Castle. Intended to be run via testdata/bc/regen-docker.sh, which
// downloads the BC JARs and passes them on the classpath automatically:
//
//   testdata/bc/regen-docker.sh
//
// To run locally without Docker, download bcprov-jdk18on, bcpkix-jdk18on, and
// bcutil-jdk18on from Maven Central and run:
//   groovy -cp "bcprov-jdk18on-1.80.jar:bcpkix-jdk18on-1.80.jar:bcutil-jdk18on-1.80.jar" \
//     testdata/bc/CMSGenerator.groovy
//
// BC version is controlled by BC_VERSION in regen-docker.sh.

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSAlgorithm
import org.bouncycastle.cms.CMSEnvelopedDataGenerator
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder

// ─── Bootstrap ────────────────────────────────────────────────────────────────

Security.addProvider(new BouncyCastleProvider())

if (!new File("testdata/content.bin").exists()) {
    System.err.println("ERROR: Run this script from the repository root.")
    System.exit(1)
}

// ─── Constants ────────────────────────────────────────────────────────────────

final SIGNED_DIR    = "testdata/bc/signed"
final ENVELOPED_DIR = "testdata/bc/enveloped"
final content       = new File("testdata/content.bin").bytes
final notBefore     = new Date(System.currentTimeMillis() - 3_600_000L)
final notAfter      = new Date(notBefore.time + 100L * 365 * 24 * 3600 * 1000)
final subject       = new X500Name("CN=cms-lib-bc-test")
final keyUsage      = new KeyUsage(
    KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement
)

// ─── Key pair generation ───────────────────────────────────────────────────────

def rsaKpg = KeyPairGenerator.getInstance("RSA", "BC")
rsaKpg.initialize(2048)

def p256Kpg = KeyPairGenerator.getInstance("EC", "BC")
p256Kpg.initialize(new ECGenParameterSpec("P-256"))

def p384Kpg = KeyPairGenerator.getInstance("EC", "BC")
p384Kpg.initialize(new ECGenParameterSpec("P-384"))

def ed25519Kpg = KeyPairGenerator.getInstance("Ed25519", "BC")

def rsaKP      = rsaKpg.generateKeyPair()
def ecP256KP   = p256Kpg.generateKeyPair()
def ecP384KP   = p384Kpg.generateKeyPair()
def ed25519KP  = ed25519Kpg.generateKeyPair()
def extraKP    = rsaKpg.generateKeyPair()   // extra cert for the with-chain fixture
def rsaRecipKP = rsaKpg.generateKeyPair()
def ecRecipKP  = p256Kpg.generateKeyPair()

// ─── Certificate creation ──────────────────────────────────────────────────────

def makeCert = { KeyPair kp, String sigAlg, BigInteger serial ->
    def builder = new JcaX509v3CertificateBuilder(
        subject, serial, notBefore, notAfter, subject, kp.public
    )
    builder.addExtension(Extension.keyUsage, false, keyUsage)
    def signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(kp.private)
    new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
}

def rsaCert      = makeCert(rsaKP,      "SHA256withRSA",   BigInteger.ONE)
def ecP256Cert   = makeCert(ecP256KP,   "SHA256withECDSA", BigInteger.valueOf(2))
def ecP384Cert   = makeCert(ecP384KP,   "SHA384withECDSA", BigInteger.valueOf(3))
def ed25519Cert  = makeCert(ed25519KP,  "Ed25519",         BigInteger.valueOf(4))
def extraCert    = makeCert(extraKP,    "SHA256withRSA",   BigInteger.valueOf(99))
def rsaRecipCert = makeCert(rsaRecipKP, "SHA256withRSA",   BigInteger.valueOf(10))
def ecRecipCert  = makeCert(ecRecipKP,  "SHA256withECDSA", BigInteger.valueOf(11))

// ─── I/O helpers ───────────────────────────────────────────────────────────────

def writeDER = { String path, byte[] der ->
    new File(path).bytes = der
    println "  wrote $path (${der.length} bytes)"
}

def writeCertPEM = { String path, X509Certificate cert ->
    new File(path).withWriter { w ->
        def pw = new JcaPEMWriter(w)
        pw.writeObject(cert)
        pw.close()
    }
    println "  wrote $path"
}

def writeKeyPEM = { String path, def key ->
    new File(path).withWriter { w ->
        def pw = new JcaPEMWriter(w)
        pw.writeObject(new JcaPKCS8Generator(key, null))
        pw.close()
    }
    println "  wrote $path"
}

// ─── Write PEM files ───────────────────────────────────────────────────────────

writeCertPEM("$SIGNED_DIR/rsa_signer.cert.pem",      rsaCert)
writeCertPEM("$SIGNED_DIR/ec_p256_signer.cert.pem",  ecP256Cert)
writeCertPEM("$SIGNED_DIR/ec_p384_signer.cert.pem",  ecP384Cert)
writeCertPEM("$SIGNED_DIR/ed25519_signer.cert.pem",  ed25519Cert)

writeCertPEM("$ENVELOPED_DIR/rsa_recip.cert.pem",    rsaRecipCert)
writeKeyPEM( "$ENVELOPED_DIR/rsa_recip.key.pem",     rsaRecipKP.private)
writeCertPEM("$ENVELOPED_DIR/ec_p256_recip.cert.pem", ecRecipCert)
writeKeyPEM( "$ENVELOPED_DIR/ec_p256_recip.key.pem", ecRecipKP.private)

// ─── SignedData generator ──────────────────────────────────────────────────────
//
// BC naturally produces the encoding choices the Go interop tests expect:
//   - digestAlgorithm AlgorithmIdentifier with explicit NULL parameters
//   - RSA PKCS1v15 signatureAlgorithm uses sha256WithRSAEncryption OID
//   - RSA-PSS RSASSA-PSS-params include trailerField=1 explicitly
// No post-processing is needed here (unlike the Go gen.go simulator).

def signedData = { KeyPair kp, X509Certificate cert, String sigAlg,
                   byte[] data, boolean attach,
                   List extraCerts = [], boolean noCerts = false ->
    def gen = new CMSSignedDataGenerator()
    def digestProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
    def contentSigner  = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(kp.private)
    gen.addSignerInfoGenerator(
        new JcaSignerInfoGeneratorBuilder(digestProvider).build(contentSigner, cert)
    )
    if (!noCerts) {
        gen.addCertificates(new JcaCertStore([cert] + extraCerts))
    }
    gen.generate(new CMSProcessableByteArray(data), attach).encoded
}

// ─── Write SignedData fixtures ─────────────────────────────────────────────────

// 1. attached_rsa_pkcs1_sha256.der
writeDER("$SIGNED_DIR/attached_rsa_pkcs1_sha256.der",
    signedData(rsaKP, rsaCert, "SHA256withRSA", content, true))

// 2. detached_rsa_pkcs1_sha256.der
writeDER("$SIGNED_DIR/detached_rsa_pkcs1_sha256.der",
    signedData(rsaKP, rsaCert, "SHA256withRSA", content, false))

// 3. attached_rsa_pss_sha256.der — SHA256withRSAandMGF1 encodes trailerField=1 explicitly
writeDER("$SIGNED_DIR/attached_rsa_pss_sha256.der",
    signedData(rsaKP, rsaCert, "SHA256withRSAandMGF1", content, true))

// 4. attached_rsa_pss_sha384.der
writeDER("$SIGNED_DIR/attached_rsa_pss_sha384.der",
    signedData(rsaKP, rsaCert, "SHA384withRSAandMGF1", content, true))

// 5. attached_ec_p256_sha256.der
writeDER("$SIGNED_DIR/attached_ec_p256_sha256.der",
    signedData(ecP256KP, ecP256Cert, "SHA256withECDSA", content, true))

// 6. attached_ec_p384_sha384.der
writeDER("$SIGNED_DIR/attached_ec_p384_sha384.der",
    signedData(ecP384KP, ecP384Cert, "SHA384withECDSA", content, true))

// 7. attached_ed25519.der
writeDER("$SIGNED_DIR/attached_ed25519.der",
    signedData(ed25519KP, ed25519Cert, "Ed25519", content, true))

// 8. attached_rsa_pkcs1_with_chain.der — certificates bag: signer cert + extra cert
writeDER("$SIGNED_DIR/attached_rsa_pkcs1_with_chain.der",
    signedData(rsaKP, rsaCert, "SHA256withRSA", content, true, [extraCert]))

// 9. attached_rsa_pkcs1_no_certs.der — certificates field absent
writeDER("$SIGNED_DIR/attached_rsa_pkcs1_no_certs.der",
    signedData(rsaKP, rsaCert, "SHA256withRSA", content, true, [], true))

// ─── EnvelopedData generators ──────────────────────────────────────────────────

// 10. rsa_oaep_sha256_aes256cbc.der
//     RSA-OAEP with explicit RSAESOAEPParams (SHA-256 hash + SHA-256 MGF1) + AES-256-CBC
def rsaOAEPEnveloped = { X509Certificate recipCert, byte[] data ->
    // Build RSAESOAEPParams using BC ASN.1 classes (avoids javax.crypto.spec).
    def sha256algId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)
    def mgf1sha256algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256algId)
    def oaepParams = new RSAESOAEPparams(sha256algId, mgf1sha256algId, RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM)
    def rsaOAEPAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, oaepParams)
    def recipGen = new JceKeyTransRecipientInfoGenerator(recipCert, rsaOAEPAlgId).setProvider("BC")
    def envGen   = new CMSEnvelopedDataGenerator()
    envGen.addRecipientInfoGenerator(recipGen)
    def encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
        .setProvider("BC").build()
    envGen.generate(new CMSProcessableByteArray(data), encryptor).encoded
}

// 11. ec_p256_aes256cbc.der
//     Ephemeral-static ECDH-SHA256KDF with AES-128-WRAP key wrap + AES-256-CBC content
def ecdhEnveloped = { X509Certificate recipCert, byte[] data ->
    def ephemeralKP = p256Kpg.generateKeyPair()
    def recipGen = new JceKeyAgreeRecipientInfoGenerator(
        CMSAlgorithm.ECDH_SHA256KDF,
        ephemeralKP.private,
        ephemeralKP.public,
        CMSAlgorithm.AES128_WRAP
    ).setProvider("BC")
    recipGen.addRecipient(recipCert)
    def envGen    = new CMSEnvelopedDataGenerator()
    envGen.addRecipientInfoGenerator(recipGen)
    def encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
        .setProvider("BC").build()
    envGen.generate(new CMSProcessableByteArray(data), encryptor).encoded
}

writeDER("$ENVELOPED_DIR/rsa_oaep_sha256_aes256cbc.der", rsaOAEPEnveloped(rsaRecipCert, content))
writeDER("$ENVELOPED_DIR/ec_p256_aes256cbc.der",          ecdhEnveloped(ecRecipCert, content))

println "BC-compatible fixtures written to $SIGNED_DIR and $ENVELOPED_DIR"
