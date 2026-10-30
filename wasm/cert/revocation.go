package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/crypto/ocsp"
)

// 인증서 폐기 여부를 CA 의 OCSP 응답기(우선) 또는 CRL 로 확인한다. 사용자가 요청한 경우에만 외부 네트워크에 접속한다.
//
// 브라우저(WebAssembly)에서는 fetch 로 접속하므로, CORS 헤더를 보내지 않는 응답기나 HTTPS 페이지에서의 http:// 주소는
// 브라우저가 막아 '확인 실패'로 표시된다.

// Fetcher 는 HTTP 요청을 보낸다. body 가 nil 이면 GET, 아니면 POST.
type Fetcher func(method, url, contentType string, body []byte) ([]byte, error)

// RevocationFetcher 는 폐기 여부 확인에 쓸 HTTP 클라이언트. 실행 환경(브라우저/서버)에서 설정한다.
var RevocationFetcher Fetcher

const ocspSigning = "1.3.6.1.5.5.7.3.9"

type revocationOutcome struct {
	status  Status
	message string
}

func checkRevocationStatus(bundle *CertBundle) CheckResult {
	const title = "폐기 여부"
	if RevocationFetcher == nil {
		return CheckResult{"REVOCATION", title, StatusSkipped, "이 실행 환경에서는 온라인 확인을 지원하지 않습니다", []string{}}
	}
	path := bundle.FullChain(true)
	status := StatusPass
	details := []string{}
	for i, certificate := range path {
		// 루트(자체 서명 또는 교차 서명된 신뢰 루트)는 폐기 확인 대상이 아니다
		if isSelfSigned(certificate) || (i > 0 && isTrustedRoot(certificate)) {
			break
		}
		name := commonNameOrDn(certificate.RawSubject)
		var issuer *x509.Certificate
		if i+1 < len(path) {
			issuer = path[i+1]
		} else {
			issuer = findTrustedIssuer(certificate)
		}
		if issuer == nil {
			status = worst(status, StatusWarn)
			details = append(details, name+": 발급자 인증서가 없어 확인할 수 없습니다")
			continue
		}
		outcome := checkOneRevocation(certificate, issuer)
		details = append(details, name+": "+outcome.message)
		status = worst(status, outcome.status)
	}
	summary := "일부 인증서의 폐기 여부를 확인하지 못했습니다"
	switch status {
	case StatusPass:
		summary = "폐기되지 않았습니다 (OCSP/CRL 확인)"
	case StatusFail:
		summary = "폐기된 인증서가 있습니다. CA 에서 재발급 받아야 합니다"
	}
	return CheckResult{"REVOCATION", title, status, summary, details}
}

func checkOneRevocation(certificate, issuer *x509.Certificate) revocationOutcome {
	var problems []string
	for _, address := range certificate.OCSPServer {
		outcome, err := checkOcsp(address, certificate, issuer)
		if err == nil {
			return outcome
		}
		problems = append(problems, fmt.Sprintf("OCSP %s 실패 (%v)", address, err))
	}
	for _, address := range certificate.CRLDistributionPoints {
		outcome, err := checkCrl(address, certificate, issuer)
		if err == nil {
			return outcome
		}
		problems = append(problems, fmt.Sprintf("CRL %s 실패 (%v)", address, err))
	}
	if len(problems) == 0 {
		return revocationOutcome{StatusWarn, "인증서에 OCSP/CRL 주소가 없어 확인할 수 없습니다"}
	}
	return revocationOutcome{StatusWarn, "확인 실패 - " + strings.Join(problems, "; ")}
}

func checkOcsp(address string, certificate, issuer *x509.Certificate) (revocationOutcome, error) {
	if err := checkAddress(address); err != nil {
		return revocationOutcome{}, err
	}
	request, err := ocsp.CreateRequest(certificate, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return revocationOutcome{}, err
	}
	body, err := RevocationFetcher("POST", address, "application/ocsp-request", request)
	if err != nil {
		return revocationOutcome{}, err
	}
	response, err := ocsp.ParseResponseForCert(body, certificate, issuer)
	if err != nil {
		var responseError ocsp.ResponseError
		if errors.As(err, &responseError) {
			return revocationOutcome{}, fmt.Errorf("응답 상태 %v", responseError.Status)
		}
		return revocationOutcome{}, fmt.Errorf("응답 서명을 검증할 수 없음: %v", err)
	}
	// 발급자가 위임한 OCSP 서명 전용 인증서로 서명한 경우 그 인증서의 용도를 확인한다
	if response.Certificate != nil && !hasOcspSigning(response.Certificate) {
		return revocationOutcome{}, errors.New("응답 서명 인증서에 OCSP 서명 용도가 없음")
	}
	switch response.Status {
	case ocsp.Good:
		return revocationOutcome{StatusPass, "정상 (OCSP)"}, nil
	case ocsp.Revoked:
		return revocationOutcome{StatusFail, "폐기됨 (" + formatTime(response.RevokedAt) + ", OCSP)"}, nil
	}
	return revocationOutcome{StatusWarn, "OCSP 응답기가 이 인증서를 알지 못합니다 (unknown)"}, nil
}

func hasOcspSigning(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	for _, oid := range certificate.UnknownExtKeyUsage {
		if oid.String() == ocspSigning {
			return true
		}
	}
	return false
}

var crlReasons = map[int]string{1: "KEY_COMPROMISE", 2: "CA_COMPROMISE", 3: "AFFILIATION_CHANGED", 4: "SUPERSEDED",
	5: "CESSATION_OF_OPERATION", 6: "CERTIFICATE_HOLD", 8: "REMOVE_FROM_CRL", 9: "PRIVILEGE_WITHDRAWN",
	10: "AA_COMPROMISE"}

func checkCrl(address string, certificate, issuer *x509.Certificate) (revocationOutcome, error) {
	if err := checkAddress(address); err != nil {
		return revocationOutcome{}, err
	}
	body, err := RevocationFetcher("GET", address, "", nil)
	if err != nil {
		return revocationOutcome{}, err
	}
	if block, _ := pem.Decode(body); block != nil {
		body = block.Bytes
	}
	list, err := x509.ParseRevocationList(body)
	if err != nil {
		return revocationOutcome{}, err
	}
	if !verifySignature(list.SignatureAlgorithm, list.RawTBSRevocationList, list.Signature, issuer.PublicKey) {
		return revocationOutcome{}, errors.New("CRL 서명을 검증할 수 없음")
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			reason := ""
			if name, ok := crlReasons[entry.ReasonCode]; ok {
				reason = ", " + name
			}
			return revocationOutcome{StatusFail, "폐기됨 (" + formatTime(entry.RevocationTime) + reason + ", CRL)"}, nil
		}
	}
	if !list.NextUpdate.IsZero() && list.NextUpdate.Before(now()) {
		return revocationOutcome{StatusWarn, "CRL 목록에는 없으나 CRL 이 오래되었습니다 (다음 갱신 " +
			formatTime(list.NextUpdate) + ")"}, nil
	}
	return revocationOutcome{StatusPass, "정상 (CRL)"}, nil
}

// checkAddress 는 http/https 만 허용한다. 인증서 안의 주소이므로 file: 등 다른 형식으로 접속하지 않는다.
// (서버에서 실행하는 경우 내부망 접속(SSRF) 차단은 Fetcher 쪽에서 해야 한다)
func checkAddress(address string) error {
	parsed, err := url.Parse(strings.TrimSpace(address))
	if err != nil {
		return err
	}
	if scheme := strings.ToLower(parsed.Scheme); scheme != "http" && scheme != "https" {
		return errors.New("지원하지 않는 주소 형식")
	}
	if parsed.Hostname() == "" {
		return errors.New("호스트 없음")
	}
	return nil
}
