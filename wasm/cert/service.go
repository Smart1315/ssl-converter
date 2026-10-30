package cert

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
)

// 분석(입력 해석 + 체인 정리)과 변환(파일 생성)을 묶는다. 결과 형식은 Java 판 API 응답과 같다.

const noKeyWarning = "개인키가 입력되지 않았습니다. 서버에 설치할 .key/PFX/JKS 를 만들려면 개인키 파일을 추가하거나 " +
	"-----BEGIN PRIVATE KEY----- 블록을 함께 붙여넣으세요. (개인키 없이 만든 PFX/JKS 에는 인증서만 들어갑니다)"

// Analysis 는 분석 결과 (웹 화면 표시용).
type Analysis struct {
	Sources           []SourceSummary `json:"sources"`
	KeystoreEntries   []KeystoreEntry `json:"keystoreEntries"`
	SelectedAlias     *string         `json:"selectedAlias"`
	Bundle            *BundleView     `json:"bundle"`
	Checks            []CheckResult   `json:"checks"`
	Warnings          []string        `json:"warnings"`
	Notices           []string        `json:"notices"`
	Errors            []string        `json:"errors"`
	SuggestedBaseName *string         `json:"suggestedBaseName"`
	SuggestedAlias    *string         `json:"suggestedAlias"`
}

// BundleView 는 정렬된 체인 정보. Certificates 는 서버 인증서부터 루트 방향 순서.
type BundleView struct {
	Certificates []CertDetails `json:"certificates"`
	Unrelated    []CertDetails `json:"unrelated"`
	PrivateKey   *KeyView      `json:"privateKey"`
	RootIncluded bool          `json:"rootIncluded"`
}

// KeyView 는 개인키 정보.
type KeyView struct {
	Description        string `json:"description"`
	MatchesCertificate bool   `json:"matchesCertificate"`
}

// Analyze 는 입력을 해석하고 점검한다.
func Analyze(sources []InputSource, password, alias string) Analysis {
	input := Parse(sources, password, alias)
	bundle := Resolve(input)
	errorsList := append([]string{}, input.Errors...)
	if bundle == nil && len(errorsList) == 0 {
		if len(input.Sources) == 0 {
			errorsList = append(errorsList, "인증서 파일을 올리거나 PEM 텍스트를 붙여넣으세요.")
		} else {
			errorsList = append(errorsList, "입력에서 인증서를 찾지 못했습니다. 서버 인증서(.crt/.pem/.cer) 또는 PFX/JKS 를 함께 올리세요.")
		}
	}
	analysis := Analysis{Sources: input.Sources, KeystoreEntries: input.KeystoreEntries,
		SelectedAlias: input.SelectedAlias, Checks: []CheckResult{}, Warnings: append([]string{}, input.Warnings...),
		Notices: []string{}, Errors: errorsList}
	if bundle != nil {
		analysis.Warnings = append(analysis.Warnings, bundle.Warnings...)
		analysis.Notices = append(analysis.Notices, bundle.Notices...)
		if len(input.PrivateKeys()) == 0 {
			analysis.Warnings = append(analysis.Warnings, noKeyWarning)
		}
		view := toView(bundle)
		analysis.Bundle = &view
		analysis.Checks = RunChecks(bundle, len(input.PrivateKeys()) > 0)
		baseName, suggestedAliasValue := suggestedBaseName(bundle.Leaf), suggestedAlias(bundle.Leaf)
		analysis.SuggestedBaseName, analysis.SuggestedAlias = &baseName, &suggestedAliasValue
	}
	return analysis
}

// Convert 는 요청된 형식의 파일을 만든다. 파일이 여러 개면 README.txt 를 더한 ZIP 하나로 묶는다.
func Convert(sources []InputSource, password, alias string, options ExportOptions) (ExportedFile, error) {
	input := Parse(sources, password, alias)
	if len(input.Errors) > 0 {
		return ExportedFile{}, conversionError(nil, "%s", strings.Join(input.Errors, "\n"))
	}
	bundle := Resolve(input)
	if bundle == nil {
		return ExportedFile{}, conversionError(nil, "입력에서 인증서를 찾지 못했습니다.")
	}
	resolved, err := withDefaults(options, bundle)
	if err != nil {
		return ExportedFile{}, err
	}
	files, skipped, err := Export(bundle, resolved)
	if err != nil {
		return ExportedFile{}, err
	}
	if len(files) == 0 {
		if len(skipped) == 0 {
			return ExportedFile{}, conversionError(nil, "생성할 형식을 하나 이상 선택하세요.")
		}
		return ExportedFile{}, conversionError(nil, "%s", strings.Join(skipped, "\n"))
	}
	if len(files) == 1 && len(skipped) == 0 {
		return files[0], nil
	}
	archive, err := zipFiles(files, skipped, bundle, resolved)
	if err != nil {
		return ExportedFile{}, err
	}
	return ExportedFile{FileName: resolved.BaseName + ".zip", ContentType: "application/zip", Data: archive}, nil
}

func withDefaults(options ExportOptions, bundle *CertBundle) (ExportOptions, error) {
	if len(options.Formats) == 0 {
		return options, conversionError(nil, "생성할 형식을 하나 이상 선택하세요.")
	}
	if options.BaseName = sanitizeFileName(options.BaseName); options.BaseName == "" {
		options.BaseName = suggestedBaseName(bundle.Leaf)
	}
	if options.Alias = strings.TrimSpace(options.Alias); options.Alias == "" {
		options.Alias = suggestedAlias(bundle.Leaf)
	}
	if options.KeyFormat == "" {
		options.KeyFormat = KeyPKCS8
	}
	needsPassword := options.KeyFormat == KeyPKCS8Encrypted &&
		(options.Formats[FormatKeyPem.ID] || options.Formats[FormatCombinedPem.ID])
	for _, format := range OutputFormats {
		needsPassword = needsPassword || (options.Formats[format.ID] && format.RequiresPassword)
	}
	if needsPassword && options.Password == "" {
		return options, conversionError(nil, "PFX/JKS/암호화 키를 만들려면 '출력 비밀번호'를 입력하세요.")
	}
	return options, nil
}

func zipFiles(files []ExportedFile, skipped []string, bundle *CertBundle, options ExportOptions) ([]byte, error) {
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	add := func(name string, data []byte) error {
		entry, err := writer.Create(name)
		if err != nil {
			return err
		}
		_, err = entry.Write(data)
		return err
	}
	for _, file := range files {
		if err := add(file.FileName, file.Data); err != nil {
			return nil, conversionError(err, "ZIP 생성 실패: %v", err)
		}
	}
	if err := add("README.txt", []byte(summary(files, skipped, bundle, options))); err != nil {
		return nil, conversionError(err, "ZIP 생성 실패: %v", err)
	}
	if err := writer.Close(); err != nil {
		return nil, conversionError(err, "ZIP 생성 실패: %v", err)
	}
	return out.Bytes(), nil
}

func summary(files []ExportedFile, skipped []string, bundle *CertBundle, options ExportOptions) string {
	var text strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&text, format+"\r\n", args...) }
	yesNo := map[bool]string{true: "예", false: "아니오"}
	pfxMode := map[bool]string{true: "레거시(3DES/SHA1)", false: "기본(AES-256/SHA-256)"}
	line("SSL 인증서 변환 결과")
	line("====================")
	line("")
	line("별칭(alias): %s", options.Alias)
	line("루트 인증서 포함: %s", yesNo[options.IncludeRoot])
	line("PFX 암호화: %s", pfxMode[options.LegacyPfx])
	line("※ 비밀번호는 이 파일에 기록하지 않습니다.")
	if !bundle.HasPrivateKey() {
		line("※ 개인키 없음: PFX/JKS 에는 인증서만 들어 있어 서버 인증서로 사용할 수 없습니다.")
	}
	line("")
	line("[생성된 파일]")
	for _, file := range files {
		line(" - %s (%d bytes)", file.FileName, len(file.Data))
	}
	if len(skipped) > 0 {
		line("")
		line("[생성하지 않은 항목]")
		for _, s := range skipped {
			line(" - %s", s)
		}
	}
	line("")
	line("[인증서 체인]")
	for i, details := range toView(bundle).Certificates {
		line("")
		line("#%d %s", i+1, details.Role)
		line("  소유자    : %s", details.Subject)
		line("  발급자    : %s", details.Issuer)
		if len(details.SubjectAltNames) > 0 {
			line("  SAN       : %s", strings.Join(details.SubjectAltNames, ", "))
		}
		line("  유효기간  : %s ~ %s", details.NotBefore, details.NotAfter)
		line("  일련번호  : %s", details.SerialNumber)
		line("  공개키    : %s", details.PublicKey)
		line("  서명알고리즘: %s", details.SignatureAlgorithm)
		line("  SHA-256   : %s", details.SHA256)
	}
	line("")
	line("[확인 명령]")
	line(" keytool -list -v -keystore %s", FormatJks.FileName(options.BaseName))
	line(" keytool -list -v -storetype PKCS12 -keystore %s", FormatPfx.FileName(options.BaseName))
	line(" openssl x509 -in %s -noout -text", FormatCertPem.FileName(options.BaseName))
	return text.String()
}

func toView(bundle *CertBundle) BundleView {
	leafRole := "서버 인증서"
	if isSelfSigned(bundle.Leaf) {
		leafRole = "서버 인증서 (자체 서명)"
	}
	certificates := []CertDetails{describe(bundle.Leaf, leafRole)}
	for _, certificate := range bundle.Chain {
		role := "중간 CA"
		if isSelfSigned(certificate) {
			role = "루트 CA"
		}
		certificates = append(certificates, describe(certificate, role))
	}
	unrelated := []CertDetails{}
	for _, certificate := range bundle.Unrelated {
		unrelated = append(unrelated, describe(certificate, "체인 외 인증서"))
	}
	var key *KeyView
	if bundle.HasPrivateKey() {
		key = &KeyView{Description: describeKey(bundle.PrivateKey), MatchesCertificate: true}
	}
	return BundleView{Certificates: certificates, Unrelated: unrelated, PrivateKey: key,
		RootIncluded: bundle.RootIncluded()}
}

func suggestedBaseName(leaf *x509.Certificate) string {
	name := primaryName(leaf)
	wildcard := strings.HasPrefix(name, "*.")
	if wildcard {
		name = name[2:]
	}
	base := sanitizeFileName(strings.ReplaceAll(name, ".", "_"))
	if base == "" {
		base = "certificate"
	}
	if wildcard {
		return "wildcard_" + base
	}
	return base
}

func suggestedAlias(leaf *x509.Certificate) string {
	name := strings.TrimPrefix(primaryName(leaf), "*.")
	if strings.TrimSpace(name) == "" {
		return "certificate"
	}
	return name
}

func primaryName(leaf *x509.Certificate) string {
	if cn := commonName(leaf.RawSubject); cn != nil && strings.TrimSpace(*cn) != "" {
		return strings.TrimSpace(*cn)
	}
	if names := subjectAltNames(leaf); len(names) > 0 {
		return names[0]
	}
	return ""
}

var (
	unsafeFileChars = regexp.MustCompile(`[^\p{L}\p{N}._-]+`)
	leadingDots     = regexp.MustCompile(`^[._]+`)
)

func sanitizeFileName(name string) string {
	return leadingDots.ReplaceAllString(unsafeFileChars.ReplaceAllString(strings.TrimSpace(name), "_"), "")
}
