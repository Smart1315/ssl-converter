package tools

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"sslconverter/cert"
	"golang.org/x/crypto/ocsp"
)

func Execute(name string, fields map[string]string, uploads map[string][]cert.InputSource) (Result, error) {
	switch name {
	case "csr": return generateCSR(fields)
	case "self-signed": return generateSelfSigned(fields)
	case "csr-decode": return decodeCSR(input(fields, uploads, "text", "files"))
	case "issue": return issue(fields, uploads)
	case "match": return match(fields, uploads)
	case "crl": return inspectCRL(input(fields, uploads, "text", "files"), fields, uploads)
	case "ocsp": return inspectOCSP(input(fields, uploads, "text", "files"), fields, uploads)
	case "asn1": return inspectASN1(input(fields, uploads, "text", "files"))
	case "compare": return compareCertificates(input(fields, uploads, "text", "files"), input(fields, uploads, "textB", "filesB"))
	case "cms": return inspectCMS(input(fields, uploads, "text", "files"), input(fields, uploads, "contentText", "contentFiles"))
	default: return Result{}, fmt.Errorf("알 수 없는 도구입니다: %s", name)
	}
}

func generateCSR(fields map[string]string) (Result, error) {
	commonName := strings.TrimSpace(fields["commonName"])
	if commonName == "" { return Result{}, fmt.Errorf("공통 이름(CN)을 입력하세요.") }
	keyType := strings.ToUpper(fields["keyType"])
	var key crypto.Signer
	switch keyType {
	case "", "RSA":
		bits := 2048
		if fields["keyBits"] != "" { parsed, err := strconv.Atoi(fields["keyBits"]); if err != nil { return Result{}, fmt.Errorf("RSA 키 길이가 올바르지 않습니다.") }; bits = parsed }
		if bits < 2048 || bits > 4096 || bits%256 != 0 { return Result{}, fmt.Errorf("RSA 키 길이는 2048~4096비트 범위여야 합니다.") }
		rsaKey, err := rsa.GenerateKey(rand.Reader, bits); if err != nil { return Result{}, err }; key = rsaKey; keyType = "RSA"
	case "EC", "ECDSA":
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); if err != nil { return Result{}, err }; key = ecKey; keyType = "EC"
	default: return Result{}, fmt.Errorf("키 알고리즘은 RSA 또는 EC여야 합니다.")
	}
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	for _, entry := range strings.Split(fields["san"], ",") {
		name := strings.TrimSpace(entry); if name == "" { continue }
		if ip := net.ParseIP(name); ip != nil { request.IPAddresses = append(request.IPAddresses, ip) } else { request.DNSNames = append(request.DNSNames, name) }
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, request, key); if err != nil { return Result{}, err }
	keyDER, err := x509.MarshalPKCS8PrivateKey(key); if err != nil { return Result{}, err }
	return Result{Messages: []string{"개인키는 암호화되지 않은 PKCS#8 PEM입니다. 안전한 위치에 저장하세요."},
		Files: []Artifact{{Name: "request.csr", Content: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))},
			{Name: "private-key.pem", Content: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}},
		Sections: []Section{section("CSR", "생성", "키 알고리즘", keyType)},
	}, nil
}

func generateSelfSigned(fields map[string]string) (Result, error) {
	commonName := strings.TrimSpace(fields["commonName"])
	if commonName == "" { return Result{}, fmt.Errorf("공통 이름(CN)을 입력하세요.") }
	keyType := strings.ToUpper(fields["keyType"])
	var key crypto.Signer
	switch keyType {
	case "", "RSA":
		bits := 2048
		if fields["keyBits"] != "" { parsed, err := strconv.Atoi(fields["keyBits"]); if err != nil { return Result{}, fmt.Errorf("RSA 키 길이가 올바르지 않습니다.") }; bits = parsed }
		if bits < 2048 || bits > 4096 || bits%256 != 0 { return Result{}, fmt.Errorf("RSA 키 길이는 2048~4096비트 범위여야 합니다.") }
		rsaKey, err := rsa.GenerateKey(rand.Reader, bits); if err != nil { return Result{}, err }; key = rsaKey; keyType = "RSA"
	case "EC", "ECDSA":
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); if err != nil { return Result{}, err }; key = ecKey; keyType = "EC"
	default:
		return Result{}, fmt.Errorf("키 알고리즘은 RSA 또는 EC여야 합니다.")
	}
	isCA := strings.EqualFold(fields["isCa"], "true")
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159)); if err != nil { return Result{}, err }; serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-5*time.Minute), NotAfter: now.Add(365*24*time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	for _, entry := range strings.Split(fields["san"], ",") {
		name := strings.TrimSpace(entry); if name == "" { continue }
		if ip := net.ParseIP(name); ip != nil { template.IPAddresses = append(template.IPAddresses, ip) } else { template.DNSNames = append(template.DNSNames, name) }
	}
	if isCA { template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature } else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		if keyType == "RSA" { template.KeyUsage |= x509.KeyUsageKeyEncipherment }
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key); if err != nil { return Result{}, err }
	keyDER, err := x509.MarshalPKCS8PrivateKey(key); if err != nil { return Result{}, err }
	label := "자체 서명 인증서"; if isCA { label = "사설 CA" }
	return Result{Messages: []string{"자체 서명 인증서입니다. 개인키는 암호화되지 않은 PKCS#8 PEM으로 제공됩니다."},
		Sections: []Section{section(label, "ok", "주체", template.Subject.String(), "키 알고리즘", keyType, "유효 기간", template.NotAfter.String())},
		Files: []Artifact{{Name: "certificate.pem", Content: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))},
			{Name: "private-key.pem", Content: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}},
	}, nil
}

func decodeCSR(data []byte) (Result, error) {
	request, err := parseCSR(data); if err != nil { return Result{}, err }
	if err := request.CheckSignature(); err != nil { return Result{}, fmt.Errorf("CSR 서명이 유효하지 않습니다: %w", err) }
	san := append(append([]string{}, request.DNSNames...), ipStrings(request.IPAddresses)...)
	return Result{Sections: []Section{section("인증서 서명 요청", "info", "주체", request.Subject.String(), "공개키 알고리즘", request.PublicKeyAlgorithm.String(), "SAN", strings.Join(san, ", "), "서명", "유효")}}, nil
}

func issue(fields map[string]string, uploads map[string][]cert.InputSource) (Result, error) {
	request, err := parseCSR(input(fields, uploads, "text", "files")); if err != nil { return Result{}, err }
	if err := request.CheckSignature(); err != nil { return Result{}, fmt.Errorf("CSR 서명이 유효하지 않습니다: %w", err) }
	ca, err := parseInputs(uploads["caFiles"], fields["caText"], fields["caPassword"]); if err != nil { return Result{}, err }
	if len(ca.Certificates()) == 0 || len(ca.PrivateKeys()) == 0 { return Result{}, fmt.Errorf("CA 인증서와 CA 개인키를 모두 입력하세요.") }
	caCert, caKey := ca.Certificates()[0], ca.PrivateKeys()[0]
	if !caCert.IsCA || caCert.KeyUsage != 0 && caCert.KeyUsage&x509.KeyUsageCertSign == 0 { return Result{}, fmt.Errorf("인증서에 CA 및 keyCertSign 권한이 없습니다.") }
	if !keyMatches(caKey, caCert) { return Result{}, fmt.Errorf("CA 인증서와 개인키가 서로 맞지 않습니다.") }
	days := 365
	if fields["days"] != "" { days, err = strconv.Atoi(fields["days"]); if err != nil { return Result{}, fmt.Errorf("유효기간이 올바르지 않습니다.") } }
	if days < 1 || days > 825 { return Result{}, fmt.Errorf("유효기간은 1~825일 범위여야 합니다.") }
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159)); if err != nil { return Result{}, err }; serial.Add(serial, big.NewInt(1))
	now := time.Now()
	var extraExtensions []pkix.Extension
	for _, extension := range request.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) { extraExtensions = append(extraExtensions, extension) }
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if request.PublicKeyAlgorithm == x509.RSA { keyUsage |= x509.KeyUsageKeyEncipherment }
	template := &x509.Certificate{SerialNumber: serial, Subject: request.Subject, NotBefore: now.Add(-5*time.Minute), NotAfter: now.Add(time.Duration(days)*24*time.Hour), DNSNames: request.DNSNames, IPAddresses: request.IPAddresses, EmailAddresses: request.EmailAddresses, URIs: request.URIs, ExtraExtensions: extraExtensions, BasicConstraintsValid: true, KeyUsage: keyUsage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, request.PublicKey, caKey); if err != nil { return Result{}, err }
	issued, err := x509.ParseCertificate(der); if err != nil { return Result{}, err }
	return Result{Messages: []string{"발급된 인증서는 입력한 CA 개인키로 서명했습니다."}, Sections: []Section{section("발급 결과", "ok", "주체", issued.Subject.String(), "발급자", issued.Issuer.String(), "만료", issued.NotAfter.String())}, Files: []Artifact{{Name: "issued-certificate.pem", Content: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}}, nil
}

func match(fields map[string]string, uploads map[string][]cert.InputSource) (Result, error) {
	parsed, err := parseInputs(uploads["files"], fields["text"], fields["password"]); if err != nil { return Result{}, err }
	rows := []Row{}
	for _, certificate := range parsed.Certificates() { for _, key := range parsed.PrivateKeys() { rows = append(rows, Row{Label: "인증서 ↔ 개인키", Value: matchText(keyMatches(key, certificate))}) } }
	if fields["csrText"] != "" { request, parseErr := parseCSR([]byte(fields["csrText"])); if parseErr != nil { return Result{}, parseErr }; for _, certificate := range parsed.Certificates() { rows = append(rows, Row{Label: "인증서 ↔ CSR", Value: matchText(publicKeysEqual(certificate.PublicKey, request.PublicKey))}) } }
	if len(rows) == 0 { return Result{}, fmt.Errorf("비교할 인증서와 개인키 또는 CSR을 입력하세요.") }
	return Result{Sections: []Section{{Title: "짝 확인", Level: "info", Rows: rows}}}, nil
}

func inspectCRL(data []byte, fields map[string]string, uploads map[string][]cert.InputSource) (Result, error) {
	data = normalizeDER(data)
	list, err := x509.ParseRevocationList(data); if err != nil { return Result{}, err }
	rows := []Row{{Label: "발급자", Value: list.Issuer.String()}, {Label: "발급일", Value: list.ThisUpdate.String()}, {Label: "다음 갱신", Value: list.NextUpdate.String()}, {Label: "폐기 인증서 수", Value: strconv.Itoa(len(list.RevokedCertificateEntries))}}
	issuer, err := parseInputs(uploads["issuerFiles"], fields["issuerText"], ""); if err != nil { return Result{}, err }
	if len(issuer.Certificates()) > 0 { if err = list.CheckSignatureFrom(issuer.Certificates()[0]); err != nil { rows = append(rows, Row{Label: "서명 검증", Value: "무��: " + err.Error()}) } else { rows = append(rows, Row{Label: "서명 검증", Value: "유효"}) } }
	for i, revoked := range list.RevokedCertificateEntries {
		if i >= 100 { rows = append(rows, Row{Label: "목록", Value: "처음 100개 항목만 표시했습니다."}); break }
		rows = append(rows, Row{Label: "폐기 일련번호", Value: revoked.SerialNumber.String() + " (" + revoked.RevocationTime.String() + ")"})
	}
	return Result{Sections: []Section{{Title: "인증서 폐기 목록", Level: "info", Rows: rows}}}, nil
}

func inspectOCSP(data []byte, fields map[string]string, uploads map[string][]cert.InputSource) (Result, error) {
	data = normalizeDER(data)
	issuer, err := parseInputs(uploads["issuerFiles"], fields["issuerText"], ""); if err != nil { return Result{}, err }
	var issuerCert *x509.Certificate; if len(issuer.Certificates()) > 0 { issuerCert = issuer.Certificates()[0] }
	response, err := ocsp.ParseResponse(data, issuerCert); if err != nil { return Result{}, err }
	status := map[int]string{ocsp.Good: "good", ocsp.Revoked: "revoked", ocsp.Unknown: "unknown"}[response.Status]
	return Result{Sections: []Section{{Title: "OCSP 응답", Level: "info", Rows: []Row{{Label: "인증서 상태", Value: status}, {Label: "일련번호", Value: response.SerialNumber.String()}, {Label: "응답 시각", Value: response.ThisUpdate.String()}, {Label: "다음 갱신", Value: response.NextUpdate.String()}, {Label: "서명 검증", Value: map[bool]string{true: "발급자 인증서로 검증됨", false: "발급자 인증서가 없어 검증하지 않음"}[issuerCert != nil]}}}}}, nil
}

func compareCertificates(aData, bData []byte) (Result, error) {
	a, err := x509.ParseCertificate(normalizeDER(aData)); if err != nil { return Result{}, err }; b, err := x509.ParseCertificate(normalizeDER(bData)); if err != nil { return Result{}, err }
	return Result{Sections: []Section{{Title: "인증서 비교", Level: "info", Rows: []Row{{Label: "주체", Value: compareValue(a.Subject.String(), b.Subject.String())}, {Label: "발급자", Value: compareValue(a.Issuer.String(), b.Issuer.String())}, {Label: "유효 시작", Value: compareValue(a.NotBefore.String(), b.NotBefore.String())}, {Label: "유효 만료", Value: compareValue(a.NotAfter.String(), b.NotAfter.String())}, {Label: "공개키 알고리즘", Value: compareValue(a.PublicKeyAlgorithm.String(), b.PublicKeyAlgorithm.String())}, {Label: "SAN", Value: compareValue(strings.Join(append(a.DNSNames, ipStrings(a.IPAddresses)...), ", "), strings.Join(append(b.DNSNames, ipStrings(b.IPAddresses)...), ", "))}}}}}, nil
}

func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(normalizeDER(data))
}

func normalizeDER(data []byte) []byte {
	data = bytes.TrimSpace(data)
	if block, _ := pem.Decode(data); block != nil { return block.Bytes }
	if len(data) == 0 || data[0] == 0x30 { return data }
	text := strings.Join(strings.Fields(string(data)), "")
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil { return decoded }
	return data
}

func parseInputs(files []cert.InputSource, text, password string) (*cert.ParsedInput, error) {
	sources := append([]cert.InputSource{}, files...); if strings.TrimSpace(text) != "" { sources = append(sources, cert.InputSource{Name: "붙여넣은 텍스트", Data: []byte(text)}) }
	parsed := cert.Parse(sources, password, ""); if len(parsed.Errors) > 0 { return nil, fmt.Errorf("%s", strings.Join(parsed.Errors, "\n")) }; return parsed, nil
}

func input(fields map[string]string, uploads map[string][]cert.InputSource, textKey, fileKey string) []byte {
	files := uploads[fileKey]; if len(files) > 0 { return files[0].Data }; if strings.TrimSpace(fields[textKey]) == "" { return nil }; return []byte(fields[textKey])
}

func keyMatches(key crypto.Signer, certificate *x509.Certificate) bool { return publicKeysEqual(key.Public(), certificate.PublicKey) }
func publicKeysEqual(a, b any) bool { aDER, errA := x509.MarshalPKIXPublicKey(a); bDER, errB := x509.MarshalPKIXPublicKey(b); return errA == nil && errB == nil && string(aDER) == string(bDER) }
func matchText(matches bool) string { if matches { return "일치" }; return "불일치" }
func compareValue(a, b string) string { if a == b { return "같음: " + a }; return "변경됨\n이전: " + a + "\n현재: " + b }
func ipStrings(addresses []net.IP) []string { out := make([]string, len(addresses)); for i, address := range addresses { out[i] = address.String() }; return out }

func inspectASN1(data []byte) (Result, error) {
	data = normalizeDER(data)
	var root asn1.RawValue; rest, err := asn1.Unmarshal(data, &root); if err != nil { return Result{}, err }; if len(rest) != 0 { return Result{}, fmt.Errorf("하나의 ASN.1 DER 구조를 입력하세요.") }
	count := 0; tree := asn1Tree("ASN.1", root, 0, &count)
	return Result{Tree: tree}, nil
}

func asn1Tree(name string, value asn1.RawValue, depth int, count *int) map[string]any {
	*count++; if *count > 500 { return map[string]any{"name": "…", "value": "노드 제한 도달"} }; if depth > 20 { return map[string]any{"name": name, "value": "깊이 제한 도달"} }
	children := []any{}
	if value.IsCompound { content := value.Bytes; index := 0; for len(content) > 0 { var child asn1.RawValue; rest, err := asn1.Unmarshal(content, &child); if err != nil || len(rest) == len(content) { break }; children = append(children, asn1Tree(fmt.Sprintf("%s[%d]", asn1Type(child), index), child, depth+1, count)); content = rest; index++; if *count >= 500 { break } } }
	display := fmt.Sprintf("%s (class=%d tag=%d, %d bytes)", asn1Type(value), value.Class, value.Tag, len(value.Bytes)); if len(value.Bytes) <= 64 && !value.IsCompound { display += ": " + fmt.Sprintf("%x", value.Bytes) }
	return map[string]any{"name": name, "value": display, "children": children}
}
func asn1Type(value asn1.RawValue) string { if value.Class == 0 { return map[int]string{1:"BOOLEAN",2:"INTEGER",3:"BIT STRING",4:"OCTET STRING",5:"NULL",6:"OBJECT IDENTIFIER",16:"SEQUENCE",17:"SET",23:"UTCTime",24:"GeneralizedTime"}[value.Tag] }; return "CONTEXT" }

var _ = sha256.Sum256
var _ = ed25519.PublicKeySize
