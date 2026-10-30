package cert

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// 인증서 상세 정보 (keytool -list -v 에 해당).

// CertDetails 는 인증서 한 장의 표시용 정보.
type CertDetails struct {
	Role               string   `json:"role"`
	CommonName         *string  `json:"commonName"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SubjectAltNames    []string `json:"subjectAltNames"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	DaysRemaining      int64    `json:"daysRemaining"`
	Status             string   `json:"status"`
	SerialNumber       string   `json:"serialNumber"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	PublicKey          string   `json:"publicKey"`
	SHA1               string   `json:"sha1"`
	SHA256             string   `json:"sha256"`
	CA                 bool     `json:"ca"`
	SelfSigned         bool     `json:"selfSigned"`
	CAIssuersURL       *string  `json:"caIssuersUrl"`
}

// now 는 테스트에서 시각을 고정할 수 있게 둔다.
var now = time.Now

func describe(certificate *x509.Certificate, role string) CertDetails {
	current := now()
	days := daysBetween(current, certificate.NotAfter)
	status := "VALID"
	switch {
	case certificate.NotAfter.Before(current):
		status = "EXPIRED"
	case certificate.NotBefore.After(current):
		status = "NOT_YET_VALID"
	case days < 30:
		status = "EXPIRING"
	}
	var caIssuers *string
	if len(certificate.IssuingCertificateURL) > 0 {
		caIssuers = &certificate.IssuingCertificateURL[0]
	}
	return CertDetails{
		Role:               role,
		CommonName:         commonName(certificate.RawSubject),
		Subject:            displayName(certificate.RawSubject),
		Issuer:             displayName(certificate.RawIssuer),
		SubjectAltNames:    subjectAltNames(certificate),
		NotBefore:          formatTime(certificate.NotBefore),
		NotAfter:           formatTime(certificate.NotAfter),
		DaysRemaining:      days,
		Status:             status,
		SerialNumber:       serialHex(certificate.SerialNumber),
		SignatureAlgorithm: signatureAlgorithmName(certificate),
		PublicKey:          describeKey(certificate.PublicKey),
		SHA1:               fingerprint(sha1Sum(certificate.Raw)),
		SHA256:             fingerprint(sha256Sum(certificate.Raw)),
		CA:                 isCA(certificate),
		SelfSigned:         isSelfSigned(certificate),
		CAIssuersURL:       caIssuers,
	}
}

// daysBetween 은 Java 의 Duration.toDays() 처럼 0 쪽으로 버린 일 수.
func daysBetween(from, to time.Time) int64 {
	return int64(to.Sub(from) / (24 * time.Hour))
}

func formatTime(t time.Time) string {
	return t.In(time.Local).Format("2006-01-02 15:04:05")
}

func isCA(certificate *x509.Certificate) bool {
	return certificate.BasicConstraintsValid && certificate.IsCA
}

// serialHex 는 Java BigInteger.toByteArray() 와 같이 부호 비트를 포함한 16진수.
func serialHex(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	var encoded []byte
	if serial.Sign() >= 0 {
		encoded = serial.Bytes()
		if len(encoded) == 0 || encoded[0]&0x80 != 0 {
			encoded = append([]byte{0}, encoded...)
		}
	} else {
		// 2의 보수
		length := (serial.BitLen() + 8) / 8
		modulus := new(big.Int).Lsh(big.NewInt(1), uint(length*8))
		encoded = new(big.Int).Add(modulus, serial).Bytes()
	}
	return strings.ToUpper(hex.EncodeToString(encoded))
}

func sha1Sum(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func fingerprint(digest []byte) string {
	var parts []string
	for _, b := range digest {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":")
}

// ---------------------------------------------------------------- 이름 (BouncyCastle X500Name.toString 형식)

var attributeNames = map[string]string{
	"2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "T", "2.5.4.3": "CN", "2.5.4.9": "STREET",
	"2.5.4.5": "SERIALNUMBER", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.4": "SURNAME", "2.5.4.42": "GIVENNAME",
	"2.5.4.43": "INITIALS", "2.5.4.44": "GENERATION", "2.5.4.45": "UniqueIdentifier", "2.5.4.46": "DN",
	"2.5.4.65": "Pseudonym", "2.5.4.15": "BusinessCategory", "2.5.4.17": "PostalCode", "2.5.4.97": "organizationIdentifier",
	"1.2.840.113549.1.9.1": "E", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
	"1.3.6.1.4.1.311.60.2.1.1": "JurisdictionL", "1.3.6.1.4.1.311.60.2.1.2": "JurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3": "JurisdictionC",
}

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

func parseName(raw []byte) pkix.RDNSequence {
	var sequence pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &sequence); err != nil {
		return nil
	}
	return sequence
}

// displayName 은 "C=KR,O=Example,CN=example.com" 처럼 인코딩된 순서대로 표시한다.
func displayName(raw []byte) string {
	var rdns []string
	for _, rdn := range parseName(raw) {
		var values []string
		for _, attribute := range rdn {
			name, ok := attributeNames[attribute.Type.String()]
			if !ok {
				name = attribute.Type.String()
			}
			values = append(values, name+"="+attributeValue(attribute.Value))
		}
		rdns = append(rdns, strings.Join(values, "+"))
	}
	return strings.Join(rdns, ",")
}

func commonName(raw []byte) *string {
	for _, rdn := range parseName(raw) {
		for _, attribute := range rdn {
			if attribute.Type.Equal(oidCommonName) {
				value := attributeValue(attribute.Value)
				return &value
			}
		}
	}
	return nil
}

func commonNameOrDn(raw []byte) string {
	if cn := commonName(raw); cn != nil {
		return *cn
	}
	return displayName(raw)
}

// attributeValue 는 IETFUtils.valueToString 처럼 특수문자를 이스케이프한다.
func attributeValue(value any) string {
	text, ok := value.(string)
	if !ok {
		encoded, err := asn1.Marshal(value)
		if err != nil {
			return fmt.Sprint(value)
		}
		return "#" + hex.EncodeToString(encoded)
	}
	var b strings.Builder
	for i, r := range text {
		if strings.ContainsRune(`,"\+=<>;`, r) || (i == 0 && r == '#') {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	escaped := b.String()
	if strings.HasPrefix(escaped, " ") {
		escaped = `\` + escaped
	}
	if strings.HasSuffix(escaped, " ") && len(escaped) > 1 {
		escaped = escaped[:len(escaped)-1] + `\ `
	}
	return escaped
}

// sameName 은 X500Principal.equals 처럼 대소문자/공백 차이를 무시하고 이름을 비교한다.
func sameName(a, b []byte) bool {
	if string(a) == string(b) {
		return true
	}
	return canonicalName(a) == canonicalName(b)
}

func canonicalName(raw []byte) string {
	var b strings.Builder
	for _, rdn := range parseName(raw) {
		for _, attribute := range rdn {
			b.WriteString(attribute.Type.String())
			b.WriteByte('=')
			b.WriteString(strings.ToLower(strings.Join(strings.Fields(fmt.Sprint(attribute.Value)), " ")))
			b.WriteByte('+')
		}
		b.WriteByte(',')
	}
	return b.String()
}

// ---------------------------------------------------------------- 확장

var (
	oidExtSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
)

func hasExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// subjectAltNames 는 DNS, IP, 이메일 이름을 인증서에 적힌 순서대로 돌려준다.
func subjectAltNames(certificate *x509.Certificate) []string {
	names := []string{}
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidExtSubjectAltName) {
			continue
		}
		input := cryptobyte.String(extension.Value)
		var sequence cryptobyte.String
		if !input.ReadASN1(&sequence, cbasn1.SEQUENCE) {
			return names
		}
		for !sequence.Empty() {
			var value cryptobyte.String
			var tag cbasn1.Tag
			if !sequence.ReadAnyASN1(&value, &tag) {
				return names
			}
			switch tag {
			case cbasn1.Tag(1).ContextSpecific(), cbasn1.Tag(2).ContextSpecific(): // rfc822Name, dNSName
				names = append(names, string(value))
			case cbasn1.Tag(7).ContextSpecific(): // iPAddress
				names = append(names, net.IP(value).String())
			}
		}
	}
	return names
}

var signatureAlgorithmNames = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA: "MD2withRSA", x509.MD5WithRSA: "MD5withRSA", x509.SHA1WithRSA: "SHA1withRSA",
	x509.SHA256WithRSA: "SHA256withRSA", x509.SHA384WithRSA: "SHA384withRSA", x509.SHA512WithRSA: "SHA512withRSA",
	x509.DSAWithSHA1: "SHA1withDSA", x509.DSAWithSHA256: "SHA256withDSA", x509.ECDSAWithSHA1: "SHA1withECDSA",
	x509.ECDSAWithSHA256: "SHA256withECDSA", x509.ECDSAWithSHA384: "SHA384withECDSA",
	x509.ECDSAWithSHA512: "SHA512withECDSA", x509.SHA256WithRSAPSS: "RSASSA-PSS", x509.SHA384WithRSAPSS: "RSASSA-PSS",
	x509.SHA512WithRSAPSS: "RSASSA-PSS", x509.PureEd25519: "Ed25519",
}

// signatureAlgorithmName 은 Java 의 X509Certificate.getSigAlgName() 과 같은 이름.
func signatureAlgorithmName(certificate *x509.Certificate) string {
	if name, ok := signatureAlgorithmNames[certificate.SignatureAlgorithm]; ok {
		return name
	}
	return "알 수 없음"
}
