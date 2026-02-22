/*
Package timestamp implements the RFC 3161 Time-Stamp Protocol client and token
parsing utilities used by the cms package.
*/
package timestamp

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	pkiasn1 "github.com/mdean75/cms-lib/internal/asn1"
)

// PKI status codes from RFC 3161, section 2.4.2.
const (
	statusGranted         = 0
	statusGrantedWithMods = 1
)

// MessageImprint contains the digest algorithm and the pre-computed hash of
// the data to be timestamped, as defined in RFC 3161, section 2.4.1.
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampReq is the request structure sent to a TSA, as defined in
// RFC 3161, section 2.4.1.
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
}

// TimeStampResp is the response returned by a TSA, as defined in
// RFC 3161, section 2.4.2.
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo carries the TSA's response status, as defined in
// RFC 3161, section 2.4.2.
type PKIStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// TSTInfo is the content of a timestamp token's SignedData, as defined in
// RFC 3161, section 2.4.2. It binds the MessageImprint to a specific point
// in time (GenTime) using the TSA's signature.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// Accuracy represents the accuracy of a TSTInfo GeneralizedTime value, as
// defined in RFC 3161, section 2.4.2.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:1"`
	Micros  int `asn1:"optional,tag:2"`
}

// Request sends an RFC 3161 timestamp request to tsaURL. algID is the hash
// algorithm identifier and digest is the pre-computed hash of the data to
// timestamp. It returns the raw DER timestamp token (ContentInfo wrapping
// SignedData with eContentType id-ct-TSTInfo).
func Request(tsaURL string, algID pkix.AlgorithmIdentifier, digest []byte) ([]byte, error) {
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: algID,
			HashedMessage: digest,
		},
		CertReq: true,
	}

	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal timestamp request: %w", err)
	}

	resp, err := http.Post(tsaURL, "application/timestamp-query", bytes.NewReader(reqDER)) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("timestamp request to %s: %w", tsaURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TSA returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading timestamp response: %w", err)
	}

	var tsResp TimeStampResp
	if _, err := asn1.Unmarshal(body, &tsResp); err != nil {
		return nil, fmt.Errorf("parse timestamp response: %w", err)
	}

	if tsResp.Status.Status != statusGranted && tsResp.Status.Status != statusGrantedWithMods {
		return nil, fmt.Errorf("TSA rejected request with status %d", tsResp.Status.Status)
	}

	if len(tsResp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("TSA response contains no timestamp token")
	}

	return tsResp.TimeStampToken.FullBytes, nil
}

// ParseTSTInfo parses the TSTInfo from a raw DER timestamp token. The token
// is a ContentInfo wrapping a SignedData whose eContentType is id-ct-TSTInfo
// and whose eContent is an OCTET STRING containing the DER-encoded TSTInfo.
func ParseTSTInfo(tokenDER []byte) (*TSTInfo, error) {
	// Parse the outer ContentInfo. ci.Content.Bytes = inner SignedData SEQUENCE TLV.
	var ci pkiasn1.ContentInfo
	if _, err := asn1.Unmarshal(tokenDER, &ci); err != nil {
		return nil, fmt.Errorf("parse timestamp token ContentInfo: %w", err)
	}

	// Parse the SignedData.
	var sd pkiasn1.SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("parse timestamp token SignedData: %w", err)
	}

	if !sd.EncapContentInfo.EContentType.Equal(pkiasn1.OIDTSTInfo) {
		return nil, fmt.Errorf("timestamp token eContentType is not id-ct-TSTInfo: %s",
			sd.EncapContentInfo.EContentType)
	}

	// EContent.Bytes = inner bytes of [0] EXPLICIT = OCTET STRING { TSTInfo DER }.
	var tstDER []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &tstDER); err != nil {
		return nil, fmt.Errorf("parse TSTInfo OCTET STRING: %w", err)
	}

	var tst TSTInfo
	if _, err := asn1.Unmarshal(tstDER, &tst); err != nil {
		return nil, fmt.Errorf("parse TSTInfo: %w", err)
	}

	return &tst, nil
}

// VerifyHash verifies that a timestamp token covers sigBytes by checking that
// hash(sigBytes), computed using the algorithm identified in the TSTInfo
// MessageImprint, matches the HashedMessage in that MessageImprint.
func VerifyHash(tokenDER, sigBytes []byte) error {
	tst, err := ParseTSTInfo(tokenDER)
	if err != nil {
		return err
	}

	h, err := hashForAlgorithm(tst.MessageImprint.HashAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	hw := h.New()
	hw.Write(sigBytes)
	computed := hw.Sum(nil)

	if !bytes.Equal(computed, tst.MessageImprint.HashedMessage) {
		return fmt.Errorf("timestamp message imprint does not match signature bytes")
	}

	return nil
}

// hashForAlgorithm returns the crypto.Hash for the given digest algorithm OID.
// Only the algorithms in the cms allow-list are supported.
func hashForAlgorithm(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(pkiasn1.OIDDigestAlgorithmSHA256):
		return crypto.SHA256, nil
	case oid.Equal(pkiasn1.OIDDigestAlgorithmSHA384):
		return crypto.SHA384, nil
	case oid.Equal(pkiasn1.OIDDigestAlgorithmSHA512):
		return crypto.SHA512, nil
	case oid.Equal(pkiasn1.OIDDigestAlgorithmSHA3_256):
		return crypto.SHA3_256, nil
	case oid.Equal(pkiasn1.OIDDigestAlgorithmSHA3_384):
		return crypto.SHA3_384, nil
	case oid.Equal(pkiasn1.OIDDigestAlgorithmSHA3_512):
		return crypto.SHA3_512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm in timestamp token: %s", oid)
	}
}
