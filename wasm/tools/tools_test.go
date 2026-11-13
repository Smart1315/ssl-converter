package tools

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"sslconverter/cert"
	"golang.org/x/crypto/ocsp"
)

func TestCSRGenerationDecodeIssueAndMatch(t *testing.T) {
	caCert, caKey, caPEM, caKeyPEM := testCA(t)
	generated, err := Execute("csr", map[string]string{"commonName": "service.example.test", "keyType": "RSA", "keyBits": "2048", "san": "service.example.test,192.0.2.10"}, nil)
	if err != nil { t.Fatal(err) }
	csrPEM := artifact(t, generated, "request.csr").Content
	if _, err = Execute("csr-decode", map[string]string{"text": csrPEM}, nil); err != nil { t.Fatal(err) }

	issued, err := Execute("issue", map[string]string{"text": csrPEM, "caText": caPEM + caKeyPEM}, nil)
	if err != nil { t.Fatal(err) }
	issuedPEM := artifact(t, issued, "issued-certificate.pem").Content
	block, _ := pem.Decode([]byte(issuedPEM))
	if block == nil { t.Fatal("issued certificate is not PEM") }
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil { t.Fatal(err) }
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 { t.Fatal("issued leaf unexpectedly has CA authority") }
	if err = leaf.CheckSignatureFrom(caCert); err != nil { t.Fatal(err) }

	matched, err := Execute("match", map[string]string{"text": issuedPEM + artifact(t, generated, "private-key.pem").Content, "csrText": csrPEM}, nil)
	if err != nil { t.Fatal(err) }
	if !strings.Contains(matched.Sections[0].Rows[0].Value, "일치") { t.Fatalf("expected certificate/key match: %+v", matched.Sections) }
	if !strings.Contains(matched.Sections[0].Rows[1].Value, "일치") { t.Fatalf("expected certificate/CSR match: %+v", matched.Sections) }

	_ = caKey
}

func TestGeneratesSelfSignedRootCA(t *testing.T) {
	result, err := Execute("self-signed", map[string]string{"commonName": "local Test CA", "keyType": "EC", "isCa": "true"}, nil)
	if err != nil { t.Fatal(err) }
	block, _ := pem.Decode([]byte(artifact(t, result, "certificate.pem").Content))
	if block == nil { t.Fatal("self-signed CA certificate is not PEM") }
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil { t.Fatal(err) }
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil { t.Fatal("certificate is not a valid self-signed CA") }
}

func TestCRLOCSPASN1AndCertificateCompare(t *testing.T) {
	caCert, caKey, caPEM, _ := testCA(t)
	now := time.Now().Truncate(time.Second)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(3), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(77), RevocationTime: now}},
	}, caCert, caKey)
	if err != nil { t.Fatal(err) }
	crlResult, err := Execute("crl", map[string]string{"text": base64.StdEncoding.EncodeToString(crlDER)}, map[string][]cert.InputSource{
		"issuerFiles": {{Name: "issuer.pem", Data: []byte(caPEM)}},
	})
	if err != nil { t.Fatal(err) }
	if !hasRow(crlResult, "폐기 일련번호", "77") || !hasRow(crlResult, "서명 검증", "유효") { t.Fatalf("CRL result missing revocation/signature: %+v", crlResult) }

	responseDER, err := ocsp.CreateResponse(caCert, caCert, ocsp.Response{
		SerialNumber: big.NewInt(77), Status: ocsp.Good, ThisUpdate: now, NextUpdate: now.Add(time.Hour),
	}, caKey)
	if err != nil { t.Fatal(err) }
	ocspResult, err := Execute("ocsp", map[string]string{"text": base64.StdEncoding.EncodeToString(responseDER)}, map[string][]cert.InputSource{
		"issuerFiles": {{Name: "issuer.pem", Data: []byte(caPEM)}},
	})
	if err != nil { t.Fatal(err) }
	if !hasRow(ocspResult, "인증서 상태", "good") { t.Fatalf("unexpected OCSP result: %+v", ocspResult) }

	integerDER, err := asn1.Marshal(big.NewInt(123))
	if err != nil { t.Fatal(err) }
	asnResult, err := Execute("asn1", map[string]string{"text": base64.StdEncoding.EncodeToString(integerDER)}, nil)
	if err != nil { t.Fatal(err) }
	if asnResult.Tree == nil { t.Fatal("ASN.1 tree is empty") }

	generated, err := Execute("csr", map[string]string{"commonName": "compare.example.test", "keyType": "EC"}, nil)
	if err != nil { t.Fatal(err) }
	issued, err := Execute("issue", map[string]string{"text": artifact(t, generated, "request.csr").Content, "caText": caPEM + testPrivateKeyPEM(t, caKey)}, nil)
	if err != nil { t.Fatal(err) }
	compared, err := Execute("compare", map[string]string{"text": caPEM, "textB": artifact(t, issued, "issued-certificate.pem").Content}, nil)
	if err != nil { t.Fatal(err) }
	if len(compared.Sections) != 1 || len(compared.Sections[0].Rows) == 0 { t.Fatal("certificate comparison result is empty") }
}

func TestCMSVerifiesAttachedSignature(t *testing.T) {
	certificate, key, _, _ := testCA(t)
	content := []byte("signed content")
	digest := sha256.Sum256(content)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil { t.Fatal(err) }
	sidDER, err := asn1.Marshal(cmsIssuerSerial{Issuer: asn1.RawValue{FullBytes: certificate.RawIssuer}, Serial: certificate.SerialNumber})
	if err != nil { t.Fatal(err) }
	var sid asn1.RawValue
	if _, err = asn1.Unmarshal(sidDER, &sid); err != nil { t.Fatal(err) }
	octets, err := asn1.Marshal(content)
	if err != nil { t.Fatal(err) }
	signed := cmsSignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}},
		Encapsulated: cmsEncapsulatedContent{ContentType: oidCMSData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octets}},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certificate.Raw},
		SignerInfos: []cmsSignerInfo{{
			Version: 1, SignerIdentifier: sid,
			DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}},
			EncryptedDigest: signature,
		}},
	}
	signedDER, err := asn1.Marshal(signed)
	if err != nil { t.Fatal(err) }
	contentInfo := cmsContentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedDER}}
	encoded, err := asn1.Marshal(contentInfo)
	if err != nil { t.Fatal(err) }
	result, err := inspectCMS(encoded, nil)
	if err != nil { t.Fatal(err) }
	if !hasRow(result, "CN=Test CA", "유효") { t.Fatalf("CMS signature was not verified: %+v", result) }
}

func testCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { t.Fatal(err) }
	now := time.Now().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil { t.Fatal(err) }
	certificate, err := x509.ParseCertificate(der)
	if err != nil { t.Fatal(err) }
	return certificate, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), testPrivateKeyPEM(t, key)
}

func testPrivateKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil { t.Fatal(err) }
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func artifact(t *testing.T, result Result, name string) Artifact {
	t.Helper()
	for _, file := range result.Files { if file.Name == name { return file } }
	t.Fatalf("artifact %q not found", name)
	return Artifact{}
}

func hasRow(result Result, label, value string) bool {
	for _, section := range result.Sections { for _, row := range section.Rows { if row.Label == label && strings.Contains(row.Value, value) { return true } } }
	return false
}
