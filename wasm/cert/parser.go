package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
)

// 어떤 형태로 들어오든 인증서와 개인키를 추출한다.
//   - PEM: 여러 블록 혼합, CRLF, BOM, 64자 줄바꿈 깨짐, "-----END ...----------BEGIN ...-----" 처럼 붙은 줄,
//     openssl 출력의 "Bag Attributes" 같은 주변 텍스트
//   - PEM 헤더 없는 Base64
//   - DER: X.509 인증서, PKCS#7(P7B), PKCS#8/PKCS#1/SEC1 개인키, 암호화된 PKCS#8
//   - 키스토어: PKCS#12(PFX/P12), JKS
//   - 위 파일들을 담은 ZIP 압축파일 (폴더, 중첩 ZIP 1단계 포함)

var (
	pemBegin       = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]+?)-----`)
	joinedBoundary = regexp.MustCompile(`-----END [A-Z0-9 ]+?-----[ \t]*-----BEGIN`)
	pemHeader      = regexp.MustCompile(`^(Proc-Type|DEK-Info):(.*)$`)
	base64Only     = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)
	nonBase64      = regexp.MustCompile(`[^A-Za-z0-9+/=]`)
	lineBreak      = regexp.MustCompile(`\r?\n|\r`)
)

const maxArchiveDepth = 2

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// Parse 는 모든 입력을 해석한다. password 는 키스토어/암호화 키 비밀번호, alias 는 키스토어에서 사용할 별칭 (없으면 "").
func Parse(sources []InputSource, password, alias string) *ParsedInput {
	result := newParsedInput()
	for _, source := range sources {
		parseInput(source, password, alias, result, 0)
	}
	return result
}

// parseInput 의 depth 가 0 이면 사용자가 직접 올린 파일, 1 이상이면 압축파일 안의 파일. 압축파일 안의 파일에서 난 문제는 오류가 아니라
// 경고로 남긴다 (CA 압축파일에는 비밀번호를 모르는 PFX 나 안내 문서 등이 함께 들어 있는 경우가 많기 때문).
func parseInput(source InputSource, password, alias string, result *ParsedInput, depth int) error {
	if len(source.Data) == 0 {
		return nil
	}
	if isZip(source.Data) {
		parseArchive(source, password, alias, result, depth)
		return nil
	}
	inArchive := depth > 0
	c := &collector{result: result}
	err := parseSource(source.Data, password, alias, source.Name, c)
	var conversion *ConversionError
	switch {
	case err == nil:
	case isUnrecognized(err):
		if inArchive {
			return err
		}
		result.Errors = append(result.Errors, source.Name+": "+err.Error())
	case errors.As(err, &conversion):
		result.report(inArchive, source.Name+": "+conversion.Message)
	default:
		result.report(inArchive, source.Name+": 처리 중 오류가 발생했습니다 - "+err.Error())
	}
	result.Sources = append(result.Sources, SourceSummary{Name: source.Name, Format: strings.Join(c.formats, ", "),
		Certificates: c.certificates, PrivateKeys: c.privateKeys, Notes: nonNil(c.notes)})
	return nil
}

func parseArchive(archive InputSource, password, alias string, result *ParsedInput, depth int) {
	index := len(result.Sources)
	result.Sources = append(result.Sources, SourceSummary{Name: archive.Name, Format: "ZIP 압축파일", Notes: []string{}})
	addNote := func(note string) { result.Sources[index].Notes = append(result.Sources[index].Notes, note) }
	if depth >= maxArchiveDepth {
		addNote("압축파일 안의 압축파일이 너무 깊어 건너뛰었습니다")
		return
	}
	entries, skipped, err := extractArchive(archive.Data)
	if err != nil {
		result.report(depth > 0, archive.Name+": "+err.Error())
		return
	}
	used := 0
	for _, entry := range entries {
		if err := parseInput(InputSource{archive.Name + "/" + entry.Name, entry.Data}, password, alias, result,
			depth+1); err != nil {
			skipped = append(skipped, entry.Name)
			continue
		}
		used++
	}
	addNote(fmt.Sprintf("파일 %d개 중 %d개에서 인증서/키를 찾았습니다", used+len(skipped), used))
	if len(skipped) > 0 {
		addNote("인증서가 아니어서 건너뛴 파일: " + strings.Join(skipped, ", "))
	}
	if used == 0 {
		result.report(depth > 0, archive.Name+": 압축파일 안에서 인증서/키 파일을 찾지 못했습니다")
	}
}

func parseSource(data []byte, password, alias, name string, c *collector) error {
	text, isText := decodeText(data)
	if isText && strings.Contains(text, "-----BEGIN ") {
		return parsePem(text, password, c)
	}
	if isText {
		compact := strings.TrimSpace(text)
		if len(compact) < 64 || !base64Only.MatchString(compact) {
			return &UnrecognizedError{"인증서/키 데이터를 찾을 수 없습니다 (PEM 헤더 없음, Base64 아님)"}
		}
		decoded, err := decodeBase64(compact)
		if err != nil {
			return &UnrecognizedError{"인증서/키 데이터를 찾을 수 없습니다 (Base64 디코딩 실패)"}
		}
		data = decoded
		c.note("PEM 헤더 없는 Base64 데이터를 디코딩했습니다")
	}
	return parseBinary(data, password, alias, name, c)
}

// ---------------------------------------------------------------- PEM

func parsePem(text, password string, c *collector) error {
	c.addFormat("PEM")
	if joinedBoundary.MatchString(text) {
		c.note("한 줄에 붙어 있던 END/BEGIN 경계를 자동으로 분리했습니다")
	}
	begins := pemBegin.FindAllStringSubmatchIndex(text, -1)
	blocks := 0
	position := 0
	for _, loc := range begins {
		if loc[0] < position {
			continue
		}
		pemType := text[loc[2]:loc[3]]
		end := "-----END " + pemType + "-----"
		length := strings.Index(text[loc[1]:], end)
		if length < 0 {
			continue
		}
		blocks++
		body := text[loc[1] : loc[1]+length]
		position = loc[1] + length + len(end)
		block, err := canonicalPem(strings.TrimSpace(pemType), body)
		if err != nil {
			return conversionError(err, "%d번째 PEM 블록(%s)을 해석할 수 없습니다: %v", blocks, pemType, err)
		}
		if err := acceptPem(block, blocks, password, c); err != nil {
			return err
		}
	}
	if blocks == 0 {
		return conversionError(nil, "BEGIN/END 짝이 맞는 PEM 블록이 없습니다")
	}
	if len(begins) > blocks {
		c.note(fmt.Sprintf("END 줄이 없는 PEM 블록 %d개는 무시했습니다", len(begins)-blocks))
	}
	return nil
}

// canonicalPem 은 블록 본문을 정리해 디코딩한다. 레거시 암호화 키의 Proc-Type/DEK-Info 헤더는 유지한다.
func canonicalPem(pemType, body string) (*pem.Block, error) {
	block := &pem.Block{Type: pemType, Headers: map[string]string{}}
	var base64Text strings.Builder
	for _, line := range lineBreak.Split(body, -1) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if m := pemHeader.FindStringSubmatch(trimmed); m != nil {
			block.Headers[m[1]] = strings.TrimSpace(m[2])
		} else {
			base64Text.WriteString(nonBase64.ReplaceAllString(trimmed, ""))
		}
	}
	decoded, err := decodeBase64(base64Text.String())
	if err != nil {
		return nil, err
	}
	block.Bytes = decoded
	return block, nil
}

func acceptPem(block *pem.Block, index int, password string, c *collector) error {
	cannotParse := func(err error) error {
		var conversion *ConversionError
		if errors.As(err, &conversion) {
			return err
		}
		return conversionError(err, "%d번째 PEM 블록(%s)을 해석할 수 없습니다: %v", index, block.Type, err)
	}
	switch block.Type {
	case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
		// TRUSTED CERTIFICATE 는 인증서 뒤에 OpenSSL 신뢰 설정이 붙어 있으므로 첫 번째 요소만 읽는다
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(block.Bytes, &raw); err != nil {
			return cannotParse(err)
		}
		certificate, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return cannotParse(err)
		}
		c.addCertificate(certificate)
	case "PKCS7", "CMS":
		certificates, err := parsePkcs7(block.Bytes)
		if err != nil {
			return cannotParse(err)
		}
		for _, certificate := range certificates {
			c.addCertificate(certificate)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return cannotParse(err)
		}
		return c.addPrivateKey(key)
	case "ENCRYPTED PRIVATE KEY":
		if err := acceptEncryptedPkcs8(block.Bytes, password, c); err != nil {
			return cannotParse(err)
		}
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY":
		if block.Type == "DSA PRIVATE KEY" {
			return conversionError(nil, "DSA 개인키는 지원하지 않습니다")
		}
		der := block.Bytes
		encrypted := strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
		if encrypted {
			if err := requirePassword(password); err != nil {
				return err
			}
			//nolint:staticcheck // 구형 OpenSSL 암호화 키(DEK-Info)를 읽기 위해 필요하다
			decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				return conversionError(err, "개인키 비밀번호가 올바르지 않습니다")
			}
			der = decrypted
		}
		var key any
		var err error
		if block.Type == "RSA PRIVATE KEY" {
			key, err = x509.ParsePKCS1PrivateKey(der)
		} else {
			key, err = x509.ParseECPrivateKey(der)
		}
		if err != nil {
			if encrypted {
				return conversionError(err, "개인키 비밀번호가 올바르지 않습니다")
			}
			return cannotParse(err)
		}
		if err := c.addPrivateKey(key); err != nil {
			return err
		}
		if encrypted {
			c.note("암호화된 개인키를 복호화했습니다")
		}
	case "EC PARAMETERS":
		// EC 개인키 앞에 붙어 오는 경우가 많으며 별도 처리 불필요
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		c.note("CSR(인증서 서명 요청)은 변환 대상이 아니므로 무시했습니다")
	case "PUBLIC KEY", "RSA PUBLIC KEY":
		c.note("공개키 블록은 무시했습니다")
	case "X509 CRL", "ATTRIBUTE CERTIFICATE":
		c.note("지원하지 않는 블록(" + block.Type + ")은 무시했습니다")
	default:
		return conversionError(nil, "%d번째 PEM 블록(%s)을 해석할 수 없습니다", index, block.Type)
	}
	return nil
}

func acceptEncryptedPkcs8(der []byte, password string, c *collector) error {
	if err := requirePassword(password); err != nil {
		return err
	}
	key, err := decryptPkcs8(der, password)
	if err != nil {
		return err
	}
	if err := c.addPrivateKey(key); err != nil {
		return err
	}
	c.note("암호화된 개인키를 복호화했습니다")
	return nil
}

func requirePassword(password string) error {
	if password == "" {
		return conversionError(nil, "암호화된 개인키입니다. '입력 비밀번호'를 입력하세요")
	}
	return nil
}

// ---------------------------------------------------------------- DER / keystore

func parseBinary(data []byte, password, alias, name string, c *collector) error {
	if bytes.HasPrefix(data, []byte{0xFE, 0xED, 0xFE, 0xED}) {
		return loadJks(data, password, alias, name, c)
	}
	if bytes.HasPrefix(data, []byte{0xCE, 0xCE, 0xCE, 0xCE}) {
		c.addFormat("JCEKS")
		return conversionError(nil, "JCEKS 키스토어는 지원하지 않습니다. keytool -importkeystore 로 PKCS12 로 바꾼 뒤 올리세요")
	}
	der := data
	seq, err := topLevelElements(der)
	if err != nil {
		// Windows 등에서 만든 BER(길이 미정) 인코딩은 DER 로 바꿔서 다시 읽는다
		if converted, berErr := berToDer(data); berErr == nil {
			der = converted
			seq, err = topLevelElements(der)
		}
	}
	if err != nil {
		return &UnrecognizedError{"인식할 수 없는 파일 형식입니다 (PEM/DER/PFX/JKS 아님)"}
	}
	if len(seq) < 2 {
		return &UnrecognizedError{"인식할 수 없는 DER 구조입니다"}
	}
	first, second := seq[0], seq[1]
	switch {
	case isInteger(first, 3) && isUniversal(second, asn1.TagSequence):
		return loadPkcs12(der, password, alias, name, c)
	case isUniversal(first, asn1.TagOID):
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(first.FullBytes, &oid); err != nil || !oid.Equal(oidSignedData) {
			return conversionError(nil, "지원하지 않는 PKCS#7 타입입니다: %v", oid)
		}
		c.addFormat("PKCS#7(DER)")
		certificates, err := parsePkcs7(der)
		if err != nil {
			return err
		}
		for _, certificate := range certificates {
			c.addCertificate(certificate)
		}
	case len(seq) == 3 && isUniversal(seq[2], asn1.TagBitString):
		c.addFormat("DER 인증서")
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		c.addCertificate(certificate)
	case isUniversal(first, asn1.TagInteger) && isUniversal(second, asn1.TagSequence) && len(seq) >= 3 &&
		isUniversal(seq[2], asn1.TagOctetString):
		c.addFormat("DER 개인키(PKCS#8)")
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		return c.addPrivateKey(key)
	case isUniversal(first, asn1.TagSequence) && isUniversal(second, asn1.TagOctetString) && len(seq) == 2:
		c.addFormat("DER 암호화 개인키(PKCS#8)")
		return acceptEncryptedPkcs8(der, password, c)
	case isUniversal(first, asn1.TagInteger) && len(seq) == 9:
		c.addFormat("DER RSA 개인키(PKCS#1)")
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return err
		}
		return c.addPrivateKey(key)
	case isInteger(first, 1) && isUniversal(second, asn1.TagOctetString):
		c.addFormat("DER EC 개인키(SEC1)")
		hasCurve := false
		for _, element := range seq[2:] {
			hasCurve = hasCurve || (element.Class == asn1.ClassContextSpecific && element.Tag == 0)
		}
		if !hasCurve {
			return conversionError(nil, "EC 개인키에 곡선(curve) 정보가 없습니다")
		}
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return err
		}
		return c.addPrivateKey(key)
	default:
		return &UnrecognizedError{"인식할 수 없는 DER 구조입니다"}
	}
	return nil
}

// topLevelElements 는 최상위 SEQUENCE 의 요소들을 돌려준다. 뒤에 다른 데이터가 붙어 있으면 오류.
func topLevelElements(der []byte) ([]asn1.RawValue, error) {
	var top asn1.RawValue
	rest, err := asn1.Unmarshal(der, &top)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data")
	}
	if top.Class != asn1.ClassUniversal || top.Tag != asn1.TagSequence {
		return nil, errors.New("not a sequence")
	}
	return sequenceElements(top.Bytes)
}

func sequenceElements(content []byte) ([]asn1.RawValue, error) {
	var elements []asn1.RawValue
	for len(content) > 0 {
		var element asn1.RawValue
		rest, err := asn1.Unmarshal(content, &element)
		if err != nil {
			return nil, err
		}
		elements = append(elements, element)
		content = rest
	}
	return elements, nil
}

func isUniversal(v asn1.RawValue, tag int) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag
}

func isInteger(v asn1.RawValue, value byte) bool {
	return isUniversal(v, asn1.TagInteger) && len(v.Bytes) == 1 && v.Bytes[0] == value
}

// ---------------------------------------------------------------- helpers

// decodeText 는 텍스트 파일이면 문자열과 true 를, 바이너리면 false 를 반환한다. UTF-8/UTF-16 BOM 을 처리한다.
func decodeText(data []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		return string(data[3:]), true
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		return decodeUtf16(data[2:], false), true
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		return decodeUtf16(data[2:], true), true
	}
	limit := min(len(data), 8192)
	for _, b := range data[:limit] {
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			return "", false
		}
	}
	return string(data), true
}

func decodeUtf16(data []byte, bigEndian bool) string {
	units := make([]uint16, len(data)/2)
	for i := range units {
		if bigEndian {
			units[i] = uint16(data[2*i])<<8 | uint16(data[2*i+1])
		} else {
			units[i] = uint16(data[2*i+1])<<8 | uint16(data[2*i])
		}
	}
	return string(utf16.Decode(units))
}

// decodeBase64 는 공백을 무시하고, 패딩(=)이 빠진 데이터도 읽는다.
func decodeBase64(text string) ([]byte, error) {
	compact := strings.Join(strings.Fields(text), "")
	if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(compact, "="))
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
