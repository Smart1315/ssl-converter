package cert

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"slices"
)

// 입력 순서와 상관없이 서버 인증서를 찾고, 발급자 관계(DN + 서명 검증)를 따라 체인을 올바른 순서로 정렬한다.

const expiryWarningDays = 30

// Resolve 는 인증서 묶음을 정리한다. 인증서가 없으면 nil.
func Resolve(input *ParsedInput) *CertBundle {
	certificates := input.Certificates()
	if len(certificates) == 0 {
		return nil
	}
	warnings, notices := []string{}, []string{}

	var key crypto.Signer
	var leaf *x509.Certificate
	for _, candidate := range input.PrivateKeys() {
		for _, certificate := range certificates {
			if keyMatches(candidate, certificate.PublicKey) {
				key, leaf = candidate, certificate
				break
			}
		}
		if key != nil {
			break
		}
	}
	if len(input.PrivateKeys()) > 0 {
		if key == nil {
			warnings = append(warnings, "개인키와 일치하는 인증서가 없습니다. 키와 인증서가 같은 발급 건인지 확인하세요.")
		} else if len(input.PrivateKeys()) > 1 {
			warnings = append(warnings, fmt.Sprintf("개인키가 %d개 입력되어, 인증서와 일치하는 키 1개만 사용합니다.",
				len(input.PrivateKeys())))
		}
	}
	if leaf == nil {
		leaf = pickLeaf(certificates, &warnings)
	}

	chain := buildChain(leaf, certificates)
	unrelated := []*x509.Certificate{}
	for _, certificate := range certificates {
		if certificate != leaf && !slices.Contains(chain, certificate) {
			unrelated = append(unrelated, certificate)
		}
	}
	if len(unrelated) > 0 {
		notices = append(notices, fmt.Sprintf("체인에 속하지 않는 인증서 %d개는 출력에서 제외됩니다.", len(unrelated)))
	}

	top := leaf
	if len(chain) > 0 {
		top = chain[len(chain)-1]
	}
	if !isSelfSigned(top) {
		if len(chain) == 0 {
			message := "중간(체인) 인증서가 없습니다. 브라우저/클라이언트에서 신뢰 오류가 날 수 있으니 CA 에서 받은 체인 파일을 함께 올리세요."
			if len(leaf.IssuingCertificateURL) > 0 {
				message += " (발급자 인증서 다운로드 주소: " + leaf.IssuingCertificateURL[0] + ")"
			}
			warnings = append(warnings, message)
		} else {
			notices = append(notices, "체인의 마지막 발급자("+commonNameOrDn(top.RawIssuer)+
				") 인증서는 포함되어 있지 않습니다. 보통 루트 CA 이며 서버 설정에서는 생략해도 됩니다.")
		}
	}
	checkValidity(leaf, chain, &warnings)

	return &CertBundle{Leaf: leaf, Chain: chain, PrivateKey: key, Unrelated: unrelated, Warnings: warnings,
		Notices: notices}
}

func pickLeaf(certificates []*x509.Certificate, warnings *[]string) *x509.Certificate {
	var candidates []*x509.Certificate
	for _, certificate := range certificates {
		issuesOther := slices.ContainsFunc(certificates, func(other *x509.Certificate) bool {
			return other != certificate && issuedBy(other, certificate)
		})
		if !issuesOther {
			candidates = append(candidates, certificate)
		}
	}
	if len(candidates) == 0 {
		candidates = certificates
	}
	var endEntities []*x509.Certificate
	for _, certificate := range candidates {
		if !isCA(certificate) {
			endEntities = append(endEntities, certificate)
		}
	}
	if len(endEntities) > 0 {
		candidates = endEntities
	}
	leaf := candidates[0]
	if len(candidates) > 1 {
		*warnings = append(*warnings, fmt.Sprintf("서버 인증서로 보이는 인증서가 %d개입니다. '%s'를 사용합니다. "+
			"서로 다른 인증서를 함께 올리지 않았는지 확인하세요.", len(candidates), commonNameOrDn(leaf.RawSubject)))
	}
	return leaf
}

func buildChain(leaf *x509.Certificate, certificates []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{}
	visited := map[*x509.Certificate]bool{leaf: true}
	for current := leaf; !isSelfSigned(current); {
		issuer := findIssuer(current, certificates, visited)
		if issuer == nil {
			break
		}
		chain = append(chain, issuer)
		visited[issuer] = true
		current = issuer
	}
	return chain
}

// findIssuer 는 서명까지 맞는 발급자를 우선하고, 없으면 이름만 맞는 인증서를 돌려준다.
func findIssuer(certificate *x509.Certificate, candidates []*x509.Certificate,
	visited map[*x509.Certificate]bool) *x509.Certificate {
	var nameMatch *x509.Certificate
	for _, candidate := range candidates {
		if visited[candidate] || !sameName(certificate.RawIssuer, candidate.RawSubject) {
			continue
		}
		if verifies(certificate, candidate) {
			return candidate
		}
		if nameMatch == nil {
			nameMatch = candidate
		}
	}
	return nameMatch
}

func checkValidity(leaf *x509.Certificate, chain []*x509.Certificate, warnings *[]string) {
	current := now()
	switch {
	case leaf.NotAfter.Before(current):
		*warnings = append(*warnings, "서버 인증서가 만료되었습니다 ("+formatTime(leaf.NotAfter)+").")
	case leaf.NotBefore.After(current):
		*warnings = append(*warnings, "서버 인증서의 유효기간이 아직 시작되지 않았습니다 ("+formatTime(leaf.NotBefore)+").")
	case daysBetween(current, leaf.NotAfter) < expiryWarningDays:
		*warnings = append(*warnings, fmt.Sprintf("서버 인증서가 %d일 이내에 만료됩니다 (%s).", expiryWarningDays,
			formatTime(leaf.NotAfter)))
	}
	for _, certificate := range chain {
		if certificate.NotAfter.Before(current) {
			*warnings = append(*warnings, "체인 인증서 '"+commonNameOrDn(certificate.RawSubject)+
				"'가 만료되었습니다. 최신 체인 파일을 CA 에서 다시 받으세요.")
		}
	}
}
