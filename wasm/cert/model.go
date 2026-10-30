package cert

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
)

// InputSource 는 업로드된 파일 또는 붙여넣은 텍스트 하나.
type InputSource struct {
	Name string
	Data []byte
}

// ConversionError 는 사용자에게 그대로 보여줄 수 있는 오류.
type ConversionError struct {
	Message string
	Err     error
}

func (e *ConversionError) Error() string { return e.Message }

func (e *ConversionError) Unwrap() error { return e.Err }

func conversionError(err error, format string, args ...any) *ConversionError {
	return &ConversionError{Message: fmt.Sprintf(format, args...), Err: err}
}

// UnrecognizedError 는 인증서/키 데이터가 아닌 입력. 압축파일 안에서는 오류 없이 건너뛴다.
type UnrecognizedError struct {
	Message string
}

func (e *UnrecognizedError) Error() string { return e.Message }

func isUnrecognized(err error) bool {
	var target *UnrecognizedError
	return errors.As(err, &target)
}

// Status 는 점검 결과. 값이 클수록 심각하다.
type Status int

const (
	StatusPass Status = iota
	StatusWarn
	StatusFail
	StatusSkipped
)

func (s Status) String() string {
	return [...]string{"PASS", "WARN", "FAIL", "SKIPPED"}[s]
}

func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func worst(a, b Status) Status {
	if a >= b {
		return a
	}
	return b
}

// CheckResult 는 점검 항목 하나의 결과.
type CheckResult struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Status  Status   `json:"status"`
	Summary string   `json:"summary"`
	Details []string `json:"details"`
}

func pass(id, title, summary string) CheckResult {
	return CheckResult{ID: id, Title: title, Status: StatusPass, Summary: summary, Details: []string{}}
}

// SourceSummary 는 입력 하나에서 무엇을 찾았는지에 대한 요약.
type SourceSummary struct {
	Name         string   `json:"name"`
	Format       string   `json:"format"`
	Certificates int      `json:"certificates"`
	PrivateKeys  int      `json:"privateKeys"`
	Notes        []string `json:"notes"`
}

// KeystoreEntry 는 키스토어(PFX/JKS) 안의 별칭 하나.
type KeystoreEntry struct {
	Source string `json:"source"`
	Alias  string `json:"alias"`
	Type   string `json:"type"`
}

// CertBundle 은 정리된 인증서 묶음. Chain 은 Leaf 의 발급자부터 상위로 정렬된 중간/루트 인증서.
type CertBundle struct {
	Leaf       *x509.Certificate
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
	Unrelated  []*x509.Certificate
	Warnings   []string
	Notices    []string
}

func (b *CertBundle) HasPrivateKey() bool { return b.PrivateKey != nil }

func (b *CertBundle) RootIncluded() bool {
	top := b.Leaf
	if len(b.Chain) > 0 {
		top = b.Chain[len(b.Chain)-1]
	}
	return isSelfSigned(top)
}

// ChainFor 는 출력용 체인. includeRoot 가 false 면 마지막의 자체 서명(루트) 인증서를 제외한다.
func (b *CertBundle) ChainFor(includeRoot bool) []*x509.Certificate {
	result := append([]*x509.Certificate{}, b.Chain...)
	if !includeRoot && len(result) > 0 && isSelfSigned(result[len(result)-1]) {
		result = result[:len(result)-1]
	}
	return result
}

// FullChain 은 Leaf + 출력용 체인.
func (b *CertBundle) FullChain(includeRoot bool) []*x509.Certificate {
	return append([]*x509.Certificate{b.Leaf}, b.ChainFor(includeRoot)...)
}

// KeyFormat 은 개인키 PEM 형식.
type KeyFormat string

const (
	KeyPKCS8          KeyFormat = "PKCS8"           // -----BEGIN PRIVATE KEY-----
	KeyTraditional    KeyFormat = "TRADITIONAL"     // -----BEGIN RSA PRIVATE KEY----- / EC PRIVATE KEY
	KeyPKCS8Encrypted KeyFormat = "PKCS8_ENCRYPTED" // -----BEGIN ENCRYPTED PRIVATE KEY----- (AES-256)
)

// ExportOptions 는 출력 옵션.
type ExportOptions struct {
	Formats     map[string]bool
	BaseName    string
	Alias       string
	Password    string
	IncludeRoot bool
	LegacyPfx   bool // PFX 를 3DES/SHA1 로 암호화 (Windows Server 2016 이하, 구형 Java 호환)
	KeyFormat   KeyFormat
}

// OutputFormat 은 생성 가능한 출력 형식. FilePattern 의 %s 는 기본 파일명으로 치환된다.
type OutputFormat struct {
	ID               string
	FilePattern      string
	ContentType      string
	RequiresKey      bool
	RequiresPassword bool
}

func (f OutputFormat) FileName(baseName string) string { return fmt.Sprintf(f.FilePattern, baseName) }

var (
	FormatFullchainPem  = OutputFormat{"FULLCHAIN_PEM", "%s_fullchain.pem", "application/x-pem-file", false, false}
	FormatCertPem       = OutputFormat{"CERT_PEM", "%s.crt", "application/x-pem-file", false, false}
	FormatChainPem      = OutputFormat{"CHAIN_PEM", "%s_chain.crt", "application/x-pem-file", false, false}
	FormatKeyPem        = OutputFormat{"KEY_PEM", "%s.key", "application/x-pem-file", true, false}
	FormatCombinedPem   = OutputFormat{"COMBINED_PEM", "%s_combined.pem", "application/x-pem-file", true, false}
	FormatPfx           = OutputFormat{"PFX", "%s.pfx", "application/x-pkcs12", false, true}
	FormatJks           = OutputFormat{"JKS", "%s.jks", "application/octet-stream", false, true}
	FormatTruststoreJks = OutputFormat{"TRUSTSTORE_JKS", "%s_truststore.jks", "application/octet-stream", false, true}
	FormatP7b           = OutputFormat{"P7B", "%s.p7b", "application/x-pkcs7-certificates", false, false}
	FormatDer           = OutputFormat{"DER", "%s.cer", "application/pkix-cert", false, false}

	// OutputFormats 는 생성 순서대로 나열한 전체 형식.
	OutputFormats = []OutputFormat{FormatFullchainPem, FormatCertPem, FormatChainPem, FormatKeyPem,
		FormatCombinedPem, FormatPfx, FormatJks, FormatTruststoreJks, FormatP7b, FormatDer}
)

// FormatByID 는 화면에서 보낸 형식 이름을 찾는다.
func FormatByID(id string) (OutputFormat, bool) {
	for _, f := range OutputFormats {
		if f.ID == id {
			return f, true
		}
	}
	return OutputFormat{}, false
}

// ExportedFile 은 생성된 파일 하나.
type ExportedFile struct {
	FileName    string
	ContentType string
	Data        []byte
}
