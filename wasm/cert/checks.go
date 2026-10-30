package cert

import (
	"crypto/dsa" //nolint:staticcheck // 구형 DSA 키를 경고하기 위해 필요하다
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// 인증서 묶음에 대한 점검 항목을 실행한다. 결과는 화면의 점검표로 표시된다.

// RunChecks 는 점검 항목을 순서대로 실행한다.
// 폐기 여부(OCSP/CRL) 확인은 하지 않는다. 브라우저에서는 CA 서버가 CORS 를 허용하지 않아 대부분 접속할 수 없기 때문이다.
func RunChecks(bundle *CertBundle, privateKeyProvided bool) []CheckResult {
	return []CheckResult{
		checkKeyMatch(bundle, privateKeyProvided),
		checkChain(bundle),
		checkValidityPeriod(bundle),
		checkSubjectAltNames(bundle),
		checkServerAuthentication(bundle),
		checkKeyStrength(bundle),
		checkSignatureAlgorithm(bundle),
		checkPublicTrust(bundle),
	}
}

func checkKeyMatch(bundle *CertBundle, privateKeyProvided bool) CheckResult {
	const title = "개인키 일치"
	if bundle.HasPrivateKey() {
		return pass("KEY_MATCH", title, "개인키가 서버 인증서와 쌍이 맞습니다 ("+describeKey(bundle.PrivateKey)+")")
	}
	if privateKeyProvided {
		return CheckResult{"KEY_MATCH", title, StatusFail, "입력한 개인키가 서버 인증서와 맞지 않습니다", []string{}}
	}
	return CheckResult{"KEY_MATCH", title, StatusWarn, "개인키가 없습니다 (.key/PFX/JKS 를 만들려면 필요)", []string{}}
}

func checkChain(bundle *CertBundle) CheckResult {
	const title = "체인 구성"
	if isSelfSigned(bundle.Leaf) {
		return CheckResult{"CHAIN", title, StatusWarn, "자체 서명 인증서입니다 (브라우저에서 신뢰되지 않음)", []string{}}
	}
	if len(bundle.Chain) == 0 {
		return CheckResult{"CHAIN", title, StatusFail, "중간(체인) 인증서가 없습니다", []string{}}
	}
	var names []string
	for _, certificate := range bundle.Chain {
		names = append(names, commonNameOrDn(certificate.RawSubject))
	}
	summary := "서버 → " + strings.Join(names, " → ")
	if bundle.RootIncluded() {
		summary += " (루트 포함)"
	} else {
		summary += " (루트 미포함, 정상)"
	}
	return pass("CHAIN", title, summary)
}

func checkValidityPeriod(bundle *CertBundle) CheckResult {
	current := now()
	status := StatusPass
	details := []string{}
	for _, certificate := range bundle.FullChain(true) {
		name := commonNameOrDn(certificate.RawSubject)
		switch {
		case certificate.NotAfter.Before(current):
			status = StatusFail
			details = append(details, name+": 만료됨 ("+formatTime(certificate.NotAfter)+")")
		case certificate.NotBefore.After(current):
			status = StatusFail
			details = append(details, name+": 유효기간 시작 전 ("+formatTime(certificate.NotBefore)+")")
		case daysBetween(current, certificate.NotAfter) < expiryWarningDays:
			status = worst(status, StatusWarn)
			details = append(details, fmt.Sprintf("%s: %d일 후 만료", name, daysBetween(current, certificate.NotAfter)))
		}
	}
	summary := "만료되었거나 아직 유효하지 않은 인증서가 있습니다"
	switch status {
	case StatusPass:
		summary = fmt.Sprintf("모든 인증서가 유효합니다 (서버 인증서 %d일 남음)", daysBetween(current, bundle.Leaf.NotAfter))
	case StatusWarn:
		summary = "곧 만료되는 인증서가 있습니다"
	}
	return CheckResult{"VALIDITY", "유효기간", status, summary, details}
}

func checkSubjectAltNames(bundle *CertBundle) CheckResult {
	names := subjectAltNames(bundle.Leaf)
	if len(names) == 0 {
		return CheckResult{"SAN", "도메인(SAN)", StatusFail,
			"SAN(주체 대체 이름)이 없습니다. Chrome 등 최신 브라우저는 CN 만으로는 도메인을 인정하지 않습니다", []string{}}
	}
	return pass("SAN", "도메인(SAN)", strings.Join(names, ", "))
}

func checkServerAuthentication(bundle *CertBundle) CheckResult {
	leaf := bundle.Leaf
	status := StatusPass
	details := []string{}
	switch {
	case !hasExtension(leaf, oidExtExtKeyUsage):
		details = append(details, "확장 키 용도(EKU) 없음: 모든 용도 허용")
	case !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny):
		status = StatusFail
		details = append(details, "확장 키 용도에 TLS 서버 인증(serverAuth)이 없습니다. 클라이언트/코드서명용 인증서가 아닌지 확인하세요")
	default:
		details = append(details, "확장 키 용도: TLS 서버 인증 포함")
	}
	if hasExtension(leaf, oidExtKeyUsage) {
		digitalSignature := leaf.KeyUsage&x509.KeyUsageDigitalSignature != 0
		keyEncipherment := leaf.KeyUsage&x509.KeyUsageKeyEncipherment != 0
		keyAgreement := leaf.KeyUsage&x509.KeyUsageKeyAgreement != 0
		_, rsaKey := leaf.PublicKey.(*rsa.PublicKey)
		usable := digitalSignature || keyAgreement
		if rsaKey {
			usable = digitalSignature || keyEncipherment
		}
		if !usable {
			status = StatusFail
			details = append(details, "키 용도(KeyUsage)에 digitalSignature/keyEncipherment 가 없어 TLS 에 쓸 수 없습니다")
		}
	}
	if isCA(leaf) {
		status = worst(status, StatusWarn)
		details = append(details, "서버 인증서가 CA 인증서로 발급되었습니다")
	}
	summary := "TLS 서버 인증서로 사용할 수 있습니다"
	if status != StatusPass {
		summary = "TLS 서버 인증서로 쓰기에 문제가 있습니다"
	}
	return CheckResult{"SERVER_AUTH", "서버 인증 용도", status, summary, details}
}

func checkKeyStrength(bundle *CertBundle) CheckResult {
	status := StatusPass
	details := []string{}
	for _, certificate := range withoutRoot(bundle) {
		name := commonNameOrDn(certificate.RawSubject)
		description := describeKey(certificate.PublicKey)
		switch key := certificate.PublicKey.(type) {
		case *rsa.PublicKey:
			if key.N.BitLen() < 2048 {
				status = StatusFail
				details = append(details, name+": "+description+" — 2048비트 미만은 브라우저에서 거부됩니다")
				continue
			}
		case *ecdsa.PublicKey:
			if key.Curve.Params().BitSize < 256 {
				status = StatusFail
				details = append(details, name+": "+description+" — 256비트 미만 곡선은 안전하지 않습니다")
				continue
			}
		case *dsa.PublicKey:
			status = worst(status, StatusWarn)
			details = append(details, name+": DSA 키는 최신 TLS 에서 지원되지 않습니다")
			continue
		}
		details = append(details, name+": "+description)
	}
	summary := "충분한 키 길이입니다"
	if status != StatusPass {
		summary = "약한 키가 있습니다"
	}
	return CheckResult{"KEY_STRENGTH", "키 길이", status, summary, details}
}

func checkSignatureAlgorithm(bundle *CertBundle) CheckResult {
	status := StatusPass
	details := []string{}
	for _, certificate := range withoutRoot(bundle) {
		name := commonNameOrDn(certificate.RawSubject)
		algorithm := signatureAlgorithmName(certificate)
		upper := strings.ToUpper(algorithm)
		if strings.Contains(upper, "MD2") || strings.Contains(upper, "MD5") || strings.HasPrefix(upper, "SHA1") {
			status = StatusFail
			details = append(details, name+": "+algorithm+" — 취약한 서명으로 브라우저에서 거부됩니다")
		} else {
			details = append(details, name+": "+algorithm)
		}
	}
	summary := "안전한 서명 알고리즘입니다"
	if status != StatusPass {
		summary = "취약한 서명 알고리즘(SHA-1/MD5)이 있습니다 (루트 제외)"
	}
	return CheckResult{"SIGNATURE", "서명 알고리즘", status, summary, details}
}

// checkPublicTrust 는 브라우저처럼 경로를 찾는다. 서버가 보낸 체인 끝이 교차 서명 인증서여서 그 발급자(오래된 루트)가 신뢰 저장소에
// 없더라도, 다른 경로로 신뢰된 루트에 닿으면 신뢰된 것으로 본다.
func checkPublicTrust(bundle *CertBundle) CheckResult {
	const title = "공인 루트 신뢰"
	roots := trustStore()
	path := withoutRoot(bundle)
	intermediates := x509.NewCertPool()
	for _, certificate := range path[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := bundle.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err == nil && len(chains) > 0 {
		root := chains[0][len(chains[0])-1]
		return pass("PUBLIC_TRUST", title, "공인 루트 '"+commonNameOrDn(root.RawSubject)+"'까지 신뢰 체인이 확인되었습니다")
	}
	details := []string{"검증 실패 사유: " + verifyErrorMessage(err),
		"기준: Mozilla(NSS) 공인 루트 저장소. 사내/사설 CA 인증서라면 정상입니다"}
	summary := "공인 루트까지 연결되지 않습니다 (사설 CA 이거나 체인 오류)"
	if len(bundle.Chain) == 0 && !isSelfSigned(bundle.Leaf) {
		summary = "공인 루트까지 연결되지 않습니다 (중간 인증서 누락)"
	}
	return CheckResult{"PUBLIC_TRUST", title, StatusWarn, summary, details}
}

func verifyErrorMessage(err error) string {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var insecure x509.InsecureAlgorithmError
	switch {
	case err == nil:
		return "알 수 없음"
	case errors.As(err, &unknown):
		return "신뢰할 수 있는 루트 인증서를 찾을 수 없습니다 (" + err.Error() + ")"
	case errors.As(err, &insecure):
		return "취약한 서명 알고리즘이 경로에 있습니다 (" + err.Error() + ")"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "경로에 만료되었거나 아직 유효하지 않은 인증서가 있습니다 (" + err.Error() + ")"
	}
	return err.Error()
}

// withoutRoot 는 서버 인증서 + 중간 인증서. 루트(자체 서명)는 신뢰 기준이므로 강도/서명 점검과 경로 검증에서 제외한다.
func withoutRoot(bundle *CertBundle) []*x509.Certificate {
	result := []*x509.Certificate{bundle.Leaf}
	for _, certificate := range bundle.Chain {
		if !isSelfSigned(certificate) {
			result = append(result, certificate)
		}
	}
	return result
}
