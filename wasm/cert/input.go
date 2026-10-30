package cert

import (
	"crypto"
	"crypto/x509"
)

// ParsedInput 은 모든 입력에서 추출한 인증서/개인키 모음. 같은 인증서나 키가 여러 파일에 있어도 한 번만 보관한다.
type ParsedInput struct {
	certificates    []*x509.Certificate
	certificateSeen map[string]bool
	privateKeys     []crypto.Signer
	privateKeySeen  map[string]bool
	Sources         []SourceSummary
	KeystoreEntries []KeystoreEntry
	Warnings        []string
	Errors          []string
	SelectedAlias   *string
}

func newParsedInput() *ParsedInput {
	return &ParsedInput{
		certificateSeen: map[string]bool{},
		privateKeySeen:  map[string]bool{},
		Sources:         []SourceSummary{},
		KeystoreEntries: []KeystoreEntry{},
		Warnings:        []string{},
		Errors:          []string{},
	}
}

func (p *ParsedInput) Certificates() []*x509.Certificate { return p.certificates }

func (p *ParsedInput) PrivateKeys() []crypto.Signer { return p.privateKeys }

func (p *ParsedInput) addCertificate(certificate *x509.Certificate) {
	key := string(certificate.Raw)
	if !p.certificateSeen[key] {
		p.certificateSeen[key] = true
		p.certificates = append(p.certificates, certificate)
	}
}

func (p *ParsedInput) addPrivateKey(key crypto.Signer) error {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return conversionError(err, "개인키 인코딩 실패: %v", err)
	}
	if !p.privateKeySeen[string(encoded)] {
		p.privateKeySeen[string(encoded)] = true
		p.privateKeys = append(p.privateKeys, key)
	}
	return nil
}

func (p *ParsedInput) report(warningOnly bool, message string) {
	if warningOnly {
		p.Warnings = append(p.Warnings, message)
	} else {
		p.Errors = append(p.Errors, message)
	}
}

// collector 는 입력 하나에 대해 찾은 항목을 집계하면서 전체 결과에 반영한다.
type collector struct {
	result       *ParsedInput
	formats      []string
	notes        []string
	certificates int
	privateKeys  int
}

func (c *collector) addFormat(format string) {
	for _, f := range c.formats {
		if f == format {
			return
		}
	}
	c.formats = append(c.formats, format)
}

func (c *collector) note(note string) { c.notes = append(c.notes, note) }

func (c *collector) addCertificate(certificate *x509.Certificate) {
	c.certificates++
	c.result.addCertificate(certificate)
}

func (c *collector) addPrivateKey(key any) error {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return conversionError(nil, "지원하지 않는 개인키 형식입니다 (%T)", key)
	}
	c.privateKeys++
	return c.result.addPrivateKey(signer)
}
