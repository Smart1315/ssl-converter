package cert

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testChain 은 테스트용 루트 → 중간 → 서버 인증서 체인.
type testChain struct {
	rootKey, intermediateKey, leafKey crypto.Signer
	root, intermediate, leaf          *x509.Certificate
}

func newTestChain(t *testing.T, ecLeaf bool, commonName string) *testChain {
	t.Helper()
	c := &testChain{rootKey: rsaKey(t), intermediateKey: rsaKey(t)}
	if ecLeaf {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c.leafKey = key
	} else {
		c.leafKey = rsaKey(t)
	}
	rootName := pkix.Name{CommonName: "Test Root CA", Organization: []string{"Test"}}
	intermediateName := pkix.Name{CommonName: "Test Intermediate CA", Organization: []string{"Test"}}
	c.root = issue(t, rootName, c.rootKey, rootName, c.rootKey, nil, true, "")
	c.intermediate = issue(t, intermediateName, c.intermediateKey, rootName, c.rootKey, c.root, true, "")
	c.leaf = issue(t, pkix.Name{CommonName: commonName}, c.leafKey, intermediateName, c.intermediateKey,
		c.intermediate, false, commonName)
	return c
}

func rsaKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func issue(t *testing.T, subject pkix.Name, key crypto.Signer, issuer pkix.Name, issuerKey crypto.Signer,
	parent *x509.Certificate, ca bool, dnsName string) *x509.Certificate {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		Issuer:                issuer,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{dnsName}
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func pemOf(t *testing.T, items ...any) string {
	t.Helper()
	var out bytes.Buffer
	for _, item := range items {
		switch v := item.(type) {
		case *x509.Certificate:
			pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: v.Raw})
		case crypto.Signer:
			der, err := x509.MarshalPKCS8PrivateKey(v)
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}
	}
	return out.String()
}

func text(name, content string) InputSource { return InputSource{Name: name, Data: []byte(content)} }

func options(password string, formats ...OutputFormat) ExportOptions {
	selected := map[string]bool{}
	for _, f := range formats {
		selected[f.ID] = true
	}
	return ExportOptions{Formats: selected, Password: password, IncludeRoot: true, KeyFormat: KeyPKCS8}
}

// convertBack 은 변환 결과를 다시 읽어 분석한다.
func convertBack(t *testing.T, file ExportedFile, password string) Analysis {
	t.Helper()
	analysis := Analyze([]InputSource{{Name: file.FileName, Data: file.Data}}, password, "")
	if len(analysis.Errors) > 0 {
		t.Fatalf("%s 다시 읽기 실패: %v", file.FileName, analysis.Errors)
	}
	return analysis
}

func TestJoinedPemBoundariesAndShuffledChainAreFixed(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	// END/BEGIN 이 한 줄에 붙고, 체인 순서가 뒤섞이고, CRLF 와 주변 텍스트가 있는 입력
	joined := strings.ReplaceAll(pemOf(t, c.root, c.leaf, c.intermediate), "-----\n-----BEGIN", "----------BEGIN")
	input := "Bag Attributes\r\n" + strings.ReplaceAll(joined, "\n", "\r\n") + pemOf(t, c.leafKey)

	analysis := Analyze([]InputSource{text("bundle.pem", input)}, "", "")
	if len(analysis.Errors) > 0 {
		t.Fatal(analysis.Errors)
	}
	view := analysis.Bundle
	if len(view.Certificates) != 3 || view.Certificates[0].Role != "서버 인증서" ||
		view.Certificates[1].Role != "중간 CA" || view.Certificates[2].Role != "루트 CA" {
		t.Fatalf("체인 정렬 실패: %+v", view.Certificates)
	}
	if view.PrivateKey == nil || view.PrivateKey.Description != "RSA 2048비트" {
		t.Fatalf("개인키 인식 실패: %+v", view.PrivateKey)
	}
	if !strings.Contains(strings.Join(analysis.Sources[0].Notes, " "), "END/BEGIN 경계") {
		t.Errorf("붙은 경계 안내가 없습니다: %v", analysis.Sources[0].Notes)
	}
	if *analysis.SuggestedBaseName != "example_com" || *analysis.SuggestedAlias != "example.com" {
		t.Errorf("추천 이름: %s / %s", *analysis.SuggestedBaseName, *analysis.SuggestedAlias)
	}
	if view.Certificates[0].Subject != "CN=example.com" || view.Certificates[0].Issuer != "O=Test,CN=Test Intermediate CA" {
		t.Errorf("이름 표시: %s / %s", view.Certificates[0].Subject, view.Certificates[0].Issuer)
	}
	statuses := map[string]Status{}
	for _, check := range analysis.Checks {
		statuses[check.ID] = check.Status
	}
	want := map[string]Status{"KEY_MATCH": StatusPass, "CHAIN": StatusPass, "VALIDITY": StatusPass, "SAN": StatusPass,
		"SERVER_AUTH": StatusPass, "KEY_STRENGTH": StatusPass, "SIGNATURE": StatusPass, "PUBLIC_TRUST": StatusWarn}
	if len(analysis.Checks) != len(want) {
		t.Errorf("점검 항목 %d개, 기대 %d개", len(analysis.Checks), len(want))
	}
	for id, status := range want {
		if statuses[id] != status {
			t.Errorf("%s 점검 = %v, 기대 %v", id, statuses[id], status)
		}
	}
}

func TestKeystoresRoundTrip(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	sources := []InputSource{text("cert.pem", pemOf(t, c.leaf, c.intermediate, c.root)), text("key.pem", pemOf(t, c.leafKey))}
	for _, tc := range []struct {
		name   string
		format OutputFormat
		legacy bool
	}{{"PFX", FormatPfx, false}, {"레거시 PFX", FormatPfx, true}, {"JKS", FormatJks, false}} {
		t.Run(tc.name, func(t *testing.T) {
			opts := options("changeit", tc.format)
			opts.Alias, opts.LegacyPfx = "my-server", tc.legacy
			file, err := Convert(sources, "", "", opts)
			if err != nil {
				t.Fatal(err)
			}
			analysis := convertBack(t, file, "changeit")
			if analysis.Bundle.PrivateKey == nil || len(analysis.Bundle.Certificates) != 3 {
				t.Fatalf("키스토어 내용이 다릅니다: %+v", analysis.Bundle)
			}
			if analysis.SelectedAlias == nil || *analysis.SelectedAlias != "my-server" {
				t.Errorf("별칭 = %v", analysis.SelectedAlias)
			}
			wrong := Analyze([]InputSource{{Name: file.FileName, Data: file.Data}}, "wrong", "")
			if len(wrong.Errors) != 1 || !strings.Contains(wrong.Errors[0], "비밀번호가 올바르지 않거나") {
				t.Errorf("잘못된 비밀번호 오류: %v", wrong.Errors)
			}
			none := Analyze([]InputSource{{Name: file.FileName, Data: file.Data}}, "", "")
			if len(none.Errors) != 1 || !strings.Contains(none.Errors[0], "비밀번호로 보호된 키스토어") {
				t.Errorf("비밀번호 없음 오류: %v", none.Errors)
			}
		})
	}
}

func TestCertificateOnlyKeystoresAndTruststore(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	sources := []InputSource{text("cert.pem", pemOf(t, c.leaf, c.intermediate, c.root))}
	for _, format := range []OutputFormat{FormatPfx, FormatJks, FormatTruststoreJks} {
		file, err := Convert(sources, "", "", options("changeit", format))
		if err != nil {
			t.Fatal(err)
		}
		analysis := convertBack(t, file, "changeit")
		if len(analysis.KeystoreEntries) == 0 || analysis.KeystoreEntries[0].Type != "trustedCertEntry" {
			t.Errorf("%s 항목: %+v", format.ID, analysis.KeystoreEntries)
		}
	}
}

func TestDerP7bAndHeaderlessInputsAreDetected(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	p7b, err := buildPkcs7([]*x509.Certificate{c.leaf, c.intermediate})
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]InputSource{
		"DER 인증서":     {Name: "cert.cer", Data: c.leaf.Raw},
		"PKCS#7(DER)": {Name: "chain.p7b", Data: p7b},
		"PEM":         text("chain.p7b.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7b}))),
	}
	for format, source := range inputs {
		analysis := Analyze([]InputSource{source}, "", "")
		if len(analysis.Errors) > 0 || !strings.Contains(analysis.Sources[0].Format, format) {
			t.Errorf("%s: %+v %v", format, analysis.Sources, analysis.Errors)
		}
	}
	headerless := base64.StdEncoding.EncodeToString(c.leaf.Raw)
	analysis := Analyze([]InputSource{text("cert.txt", headerless)}, "", "")
	if analysis.Bundle == nil || !strings.Contains(strings.Join(analysis.Sources[0].Notes, " "), "Base64") {
		t.Errorf("헤더 없는 Base64: %+v %v", analysis.Sources, analysis.Errors)
	}
	garbage := Analyze([]InputSource{text("readme.txt", "hello")}, "", "")
	if len(garbage.Errors) != 1 || !strings.Contains(garbage.Errors[0], "인증서/키 데이터를 찾을 수 없습니다") {
		t.Errorf("인증서가 아닌 입력: %v", garbage.Errors)
	}
}

func TestEncryptedAndTraditionalKeysRoundTrip(t *testing.T) {
	for _, ec := range []bool{false, true} {
		c := newTestChain(t, ec, "*.example.com")
		chainPem := pemOf(t, c.leaf, c.intermediate)
		for _, keyFormat := range []KeyFormat{KeyPKCS8, KeyTraditional, KeyPKCS8Encrypted} {
			opts := options("secret1", FormatKeyPem)
			opts.KeyFormat = keyFormat
			file, err := Convert([]InputSource{text("c.pem", chainPem), text("k.pem", pemOf(t, c.leafKey))}, "", "", opts)
			if err != nil {
				t.Fatal(err)
			}
			if file.FileName != "wildcard_example_com.key" {
				t.Errorf("파일명 = %s", file.FileName)
			}
			password := ""
			if keyFormat == KeyPKCS8Encrypted {
				password = "secret1"
			}
			analysis := Analyze([]InputSource{text("c.pem", chainPem), {Name: "k.key", Data: file.Data}}, password, "")
			if analysis.Bundle == nil || analysis.Bundle.PrivateKey == nil {
				t.Errorf("EC=%v %s 키 다시 읽기 실패: %v", ec, keyFormat, analysis.Errors)
			}
		}
	}
}

func TestLegacyEncryptedPemKey(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	//nolint:staticcheck // 구형 OpenSSL 암호화 키 입력을 흉내낸다
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(c.leafKey.(*rsa.PrivateKey)), []byte("pass"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	sources := []InputSource{text("c.pem", pemOf(t, c.leaf)), {Name: "k.key", Data: pem.EncodeToMemory(block)}}
	if analysis := Analyze(sources, "pass", ""); analysis.Bundle.PrivateKey == nil {
		t.Errorf("복호화 실패: %v", analysis.Errors)
	}
	if analysis := Analyze(sources, "nope", ""); len(analysis.Errors) == 0 ||
		!strings.Contains(analysis.Errors[0], "개인키 비밀번호가 올바르지 않습니다") {
		t.Errorf("잘못된 비밀번호: %v", analysis.Errors)
	}
}

func TestZipArchiveInput(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range map[string]string{
		"cert/example_com.crt": pemOf(t, c.leaf),
		"cert/chain.crt":       pemOf(t, c.intermediate, c.root),
		"cert/example.key":     pemOf(t, c.leafKey),
		"설치안내.txt":             "설치 방법 안내",
		"guide.pdf":            "%PDF",
		"__MACOSX/._x":         "x",
	} {
		entry, _ := writer.Create(name)
		entry.Write([]byte(content))
	}
	writer.Close()

	analysis := Analyze([]InputSource{{Name: "cert.zip", Data: buffer.Bytes()}}, "", "")
	if len(analysis.Errors) > 0 || analysis.Bundle == nil || analysis.Bundle.PrivateKey == nil ||
		len(analysis.Bundle.Certificates) != 3 {
		t.Fatalf("ZIP 입력: %v %+v", analysis.Errors, analysis.Sources)
	}
	notes := strings.Join(analysis.Sources[0].Notes, " ")
	if !strings.Contains(notes, "파일 5개 중 3개") || !strings.Contains(notes, "설치안내.txt") {
		t.Errorf("ZIP 안내: %s", notes)
	}
}

func TestMismatchedAndMissingKeys(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	other := rsaKey(t)
	analysis := Analyze([]InputSource{text("c.pem", pemOf(t, c.leaf, c.intermediate)), text("k.pem", pemOf(t, other))},
		"", "")
	if analysis.Checks[0].Status != StatusFail {
		t.Errorf("다른 키 점검 = %v", analysis.Checks[0].Status)
	}
	_, err := Convert([]InputSource{text("c.pem", pemOf(t, c.leaf, c.intermediate))}, "", "",
		options("", FormatKeyPem))
	if err == nil || !strings.Contains(err.Error(), "개인키가 없어") {
		t.Errorf("키 없는 KEY_PEM: %v", err)
	}
}

func TestKeystoreOutputRequiresPassword(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	sources := []InputSource{text("all.pem", pemOf(t, c.leaf, c.intermediate, c.leafKey))}
	for _, password := range []string{"", "   ", "\t"} {
		for _, format := range []OutputFormat{FormatPfx, FormatJks, FormatTruststoreJks} {
			_, err := Convert(sources, "", "", options(password, format))
			if err == nil || !strings.Contains(err.Error(), "출력 비밀번호") {
				t.Errorf("%s 비밀번호 %q: %v", format.ID, password, err)
			}
		}
		encryptedKey := options(password, FormatKeyPem)
		encryptedKey.KeyFormat = KeyPKCS8Encrypted
		if _, err := Convert(sources, "", "", encryptedKey); err == nil || !strings.Contains(err.Error(), "출력 비밀번호") {
			t.Errorf("암호화 키 비밀번호 %q: %v", password, err)
		}
	}
	// 앞뒤 공백이 있는 비밀번호는 그대로 사용한다
	file, err := Convert(sources, "", "", options(" change it ", FormatPfx))
	if err != nil {
		t.Fatal(err)
	}
	if analysis := Analyze([]InputSource{{Name: file.FileName, Data: file.Data}}, " change it ", ""); analysis.Bundle == nil ||
		analysis.Bundle.PrivateKey == nil {
		t.Errorf("앞뒤 공백 비밀번호로 열기 실패: %v", analysis.Errors)
	}
}

func TestMultipleFormatsAreZipped(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	file, err := Convert([]InputSource{text("all.pem", pemOf(t, c.leaf, c.intermediate, c.root, c.leafKey))}, "", "",
		options("changeit", FormatFullchainPem, FormatKeyPem, FormatPfx, FormatP7b, FormatDer))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(file.Data), int64(len(file.Data)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range reader.File {
		names = append(names, entry.Name)
	}
	want := "example_com_fullchain.pem example_com.key example_com.pfx example_com.p7b example_com.cer README.txt"
	if file.FileName != "example_com.zip" || strings.Join(names, " ") != want {
		t.Errorf("ZIP 내용 = %s %v", file.FileName, names)
	}
}

func TestBerIndefiniteLengthIsNormalized(t *testing.T) {
	// SEQUENCE(길이 미정) { INTEGER 1, OCTET STRING(조각 2개) }
	ber := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x24, 0x80, 0x04, 0x01, 'a', 0x04, 0x01, 'b', 0x00, 0x00, 0x00, 0x00}
	der, err := berToDer(ber)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 'a', 'b'}
	if !bytes.Equal(der, want) {
		t.Errorf("berToDer = % X", der)
	}
}

func TestSerialHexMatchesJava(t *testing.T) {
	for value, want := range map[int64]string{0: "00", 1: "01", 128: "0080", -1: "FF", -129: "FF7F"} {
		if got := serialHex(big.NewInt(value)); got != want {
			t.Errorf("serialHex(%d) = %s, 기대 %s", value, got, want)
		}
	}
}

func TestNonASCIIOutputPasswordIsRejected(t *testing.T) {
	c := newTestChain(t, false, "example.com")
	sources := []InputSource{text("all.pem", pemOf(t, c.leaf, c.intermediate, c.leafKey))}
	for _, password := range []string{"비밀번호123", "pässword", "pass\tword"} {
		for _, format := range []OutputFormat{FormatPfx, FormatJks, FormatTruststoreJks} {
			if _, err := Convert(sources, "", "", options(password, format)); err == nil || err.Error() != nonASCIIPassword {
				t.Errorf("%s 비밀번호 %q: %v", format.ID, password, err)
			}
		}
	}
	// 비밀번호가 필요 없는 형식에서는 검사하지 않는다
	if _, err := Convert(sources, "", "", options("비밀번호", FormatFullchainPem)); err != nil {
		t.Errorf("PEM 출력: %v", err)
	}
}

func TestKeyEncryptionIsSelectableForEachKeyFormat(t *testing.T) {
	for _, ec := range []bool{false, true} {
		c := newTestChain(t, ec, "example.com")
		for _, format := range []KeyFormat{KeyPKCS8, KeyTraditional} {
			for _, encrypt := range []bool{false, true} {
				opts := options("changeit", FormatKeyPem)
				opts.KeyFormat, opts.EncryptKey = format, encrypt
				file, err := Convert([]InputSource{text("c.pem", pemOf(t, c.leaf)), text("k.pem", pemOf(t, c.leafKey))}, "", "", opts)
				if err != nil {
					t.Fatal(err)
				}
				key := string(file.Data)
				label := fmt.Sprintf("EC=%v %s encrypt=%v", ec, format, encrypt)
				if strings.Contains(key, "ENCRYPTED") != encrypt {
					t.Errorf("%s: 암호화 여부가 다릅니다\n%s", label, key[:80])
				}
				pkcs8 := strings.HasPrefix(key, "-----BEGIN PRIVATE KEY-----") || strings.HasPrefix(key, "-----BEGIN ENCRYPTED PRIVATE KEY-----")
				if pkcs8 != (format == KeyPKCS8) {
					t.Errorf("%s: 형식이 다릅니다\n%s", label, key[:80])
				}
				reloaded := []InputSource{text("c.pem", pemOf(t, c.leaf)), {Name: "out.key", Data: file.Data}}
				password := ""
				if encrypt {
					password = "changeit"
					if a := Analyze(reloaded, "", ""); len(a.Errors) == 0 {
						t.Errorf("%s: 비밀번호 없이 열렸습니다", label)
					}
				}
				if a := Analyze(reloaded, password, ""); a.Bundle == nil || a.Bundle.PrivateKey == nil {
					t.Errorf("%s: 다시 읽기 실패 %v", label, a.Errors)
				}
			}
		}
	}
	// 이전 API 의 PKCS8_ENCRYPTED 는 PKCS8 + 암호화와 같다
	c := newTestChain(t, false, "example.com")
	opts := options("changeit", FormatKeyPem)
	opts.KeyFormat = KeyPKCS8Encrypted
	file, err := Convert([]InputSource{text("all.pem", pemOf(t, c.leaf, c.leafKey))}, "", "", opts)
	if err != nil || !strings.HasPrefix(string(file.Data), "-----BEGIN ENCRYPTED PRIVATE KEY-----") {
		t.Errorf("PKCS8_ENCRYPTED: %v", err)
	}
}
