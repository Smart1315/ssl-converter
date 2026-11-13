package tools

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"crypto/x509"
	"crypto/x509/pkix"
)

var oidCMSData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
var oidCMSMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
type cmsEncapsulatedContent struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
type cmsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	Encapsulated     cmsEncapsulatedContent
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	RevocationLists  asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}
type cmsSignerInfo struct {
	Version              int
	SignerIdentifier     asn1.RawValue
	DigestAlgorithm      pkix.AlgorithmIdentifier
	SignedAttributes     asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm   pkix.AlgorithmIdentifier
	EncryptedDigest      []byte
	UnsignedAttributes   asn1.RawValue `asn1:"optional,tag:1"`
}
type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}
type cmsIssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

func inspectCMS(encoded, detached []byte) (Result, error) {
	encoded = normalizeDER(encoded)
	var contentInfo cmsContentInfo
	if rest, err := asn1.Unmarshal(encoded, &contentInfo); err != nil || len(rest) != 0 { return Result{}, fmt.Errorf("유효한 CMS ContentInfo가 아닙니다") }
	if !contentInfo.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) { return Result{}, fmt.Errorf("CMS SignedData 구조가 아닙니다") }
	var signed cmsSignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signed); err != nil { return Result{}, err }
	content := detached
	if signed.Encapsulated.Content.FullBytes != nil {
		var octets asn1.RawValue
		if _, err := asn1.Unmarshal(signed.Encapsulated.Content.Bytes, &octets); err == nil && octets.Tag == asn1.TagOctetString { content = octets.Bytes }
	}
	if len(content) == 0 { return Result{}, fmt.Errorf("분리 서명에는 원본 content 파일이 필요합니다") }
	certificates := parseCMSCertificates(signed.Certificates)
	rows := make([]Row, 0, len(signed.SignerInfos))
	for _, signer := range signed.SignerInfos {
		certificate := findSignerCertificate(signer.SignerIdentifier, certificates)
		if certificate == nil { rows = append(rows, Row{Label: "서명자", Value: "인증서 없음"}); continue }
		payload, valid := cmsSignedPayload(signer, content)
		if !valid { rows = append(rows, Row{Label: certificate.Subject.String(), Value: "messageDigest 불일치"}); continue }
		valid = verifyCMSSignature(certificate.PublicKey, signer.SignatureAlgorithm.Algorithm, signer.DigestAlgorithm.Algorithm, payload, signer.EncryptedDigest)
		state := "무효"; if valid { state = "유효" }
		rows = append(rows, Row{Label: certificate.Subject.String(), Value: state})
	}
	if len(rows) == 0 { return Result{}, fmt.Errorf("CMS 서명자를 찾을 수 없습니다") }
	return Result{Messages: []string{"CMS 서명 값만 확인했습니다. 인증서 체인 신뢰성은 별도로 검증해야 합니다."}, Sections: []Section{{Title: "PKCS#7 / CMS", Level: "info", Rows: rows}}}, nil
}

func parseCMSCertificates(raw asn1.RawValue) []*x509.Certificate {
	var certificates []*x509.Certificate
	content := raw.Bytes
	for len(content) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(content, &value)
		if err != nil || len(rest) == len(content) { break }
		content = rest
		if value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence {
			if certificate, err := x509.ParseCertificate(value.FullBytes); err == nil { certificates = append(certificates, certificate) }
		}
	}
	return certificates
}

func findSignerCertificate(sid asn1.RawValue, certificates []*x509.Certificate) *x509.Certificate {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, certificate := range certificates { if subtle.ConstantTimeCompare(certificate.SubjectKeyId, sid.Bytes) == 1 { return certificate } }
		return nil
	}
	var issuerSerial cmsIssuerSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &issuerSerial); err != nil || issuerSerial.Serial == nil { return nil }
	for _, certificate := range certificates {
		if certificate.SerialNumber.Cmp(issuerSerial.Serial) == 0 && string(certificate.RawIssuer) == string(issuerSerial.Issuer.FullBytes) { return certificate }
	}
	return nil
}

func cmsSignedPayload(signer cmsSignerInfo, content []byte) ([]byte, bool) {
	hashID := signer.DigestAlgorithm.Algorithm
	hash, ok := cmsDigest(hashID, content)
	if !ok { return nil, false }
	if signer.SignedAttributes.FullBytes == nil { return hash, true }
	attrs := signer.SignedAttributes.Bytes
	var messageDigest []byte
	for len(attrs) > 0 {
		var attribute cmsAttribute
		rest, err := asn1.Unmarshal(attrs, &attribute)
		if err != nil || len(rest) == len(attrs) { return nil, false }
		attrs = rest
		if attribute.Type.Equal(oidCMSMessageDigest) && len(attribute.Values) > 0 { messageDigest = attribute.Values[0].Bytes }
	}
	if len(messageDigest) == 0 || subtle.ConstantTimeCompare(messageDigest, hash) != 1 { return nil, false }
	setDER := append([]byte(nil), signer.SignedAttributes.FullBytes...)
	if len(setDER) == 0 || setDER[0] != 0xa0 { return nil, false }
	setDER[0] = 0x31
	signedHash, supported := cmsDigest(hashID, setDER)
	return signedHash, supported
}

func verifyCMSSignature(publicKey any, signatureOID, digestOID asn1.ObjectIdentifier, digest, signature []byte) bool {
	hash, supported := cmsHashType(digestOID)
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return supported && rsa.VerifyPKCS1v15(key, hash, digest, signature) == nil
	case *ecdsa.PublicKey:
		var pair struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &pair); err != nil || pair.R == nil || pair.S == nil { return false }
		return ecdsa.Verify(key, digest, pair.R, pair.S)
	case ed25519.PublicKey:
		return ed25519.Verify(key, digest, signature)
	default:
		_ = signatureOID
		return false
	}
}

func cmsDigest(oid asn1.ObjectIdentifier, data []byte) ([]byte, bool) {
	hash, typ := cmsHashType(oid)
	switch hash { case crypto.SHA1: sum := sha1.Sum(data); return sum[:], true; case crypto.SHA256: sum := sha256.Sum256(data); return sum[:], true; case crypto.SHA384: sum := sha512.Sum384(data); return sum[:], true; case crypto.SHA512: sum := sha512.Sum512(data); return sum[:], true; default: return nil, typ }
}
func cmsHashType(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch { case oid.Equal(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}): return crypto.SHA1, true; case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}): return crypto.SHA256, true; case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}): return crypto.SHA384, true; case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}): return crypto.SHA512, true; default: return 0, false }
}

var _ = strings.Builder{}
var _ = oidCMSData
