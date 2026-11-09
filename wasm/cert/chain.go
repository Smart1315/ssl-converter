package cert

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"math"
	"slices"
)

// 입력 순서와 상관없이 서버 인증서를 찾고, 발급자 관계(DN + 서명 검증)를 따라 체인을 올바른 순서로 정렬한다.
// 교차 서명 인증서가 함께 들어 있으면 발급 경로가 여러 개가 된다. 이때는 브라우저처럼 신뢰된 루트에 가장 가까이 닿는 경로를 고르고,
// 고르지 않은 경로의 인증서는 체인과 상관없는 인증서와 구분해 대체 경로 인증서로 둔다.

const (
	expiryWarningDays = 30
	maxPaths          = 64
)

// Resolve 는 인증서 묶음을 정리한다. 인증서가 없으면 nil.
func Resolve(input *ParsedInput) *CertBundle { return ResolveWith(input, false) }

// ResolveWith 는 preferCrossSigned 가 true 면 교차 서명 인증서를 거쳐 옛 루트까지 가는 경로가 있을 때 그 경로를 고른다
// (새 루트를 모르는 구형 클라이언트 호환).
func ResolveWith(input *ParsedInput, preferCrossSigned bool) *CertBundle {
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

	paths := findPaths(leaf, certificates)
	crossSigned := crossSignedRoots(certificates)
	crossSignedPathAvailable := slices.ContainsFunc(paths, func(path issuerPath) bool {
		return path.passesAny(crossSigned)
	})
	preferred := map[*x509.Certificate]bool{}
	if preferCrossSigned {
		preferred = crossSigned
	}
	chosen := choosePath(paths, preferred)
	crossSignedPathChosen := chosen.passesAny(crossSigned)
	chain := chosen.chain
	onPaths := map[*x509.Certificate]bool{}
	for _, path := range paths {
		for _, certificate := range path.chain {
			onPaths[certificate] = true
		}
	}
	alternates, unrelated := []*x509.Certificate{}, []*x509.Certificate{}
	for _, certificate := range certificates {
		switch {
		case certificate == leaf || slices.Contains(chain, certificate):
		case onPaths[certificate] || isCrossSigned(certificate, chain):
			alternates = append(alternates, certificate)
		default:
			unrelated = append(unrelated, certificate)
		}
	}
	if len(alternates) > 0 {
		reason := "브라우저처럼 신뢰된 루트에 가장 가까운 경로를 체인으로 골랐습니다."
		if crossSignedPathChosen {
			reason = "구형 클라이언트 호환을 위해 교차 서명 인증서를 거치는 경로를 체인으로 골랐습니다."
		}
		notices = append(notices, fmt.Sprintf("다른 발급 경로(교차 서명 등)의 인증서 %d개는 출력에서 제외됩니다. %s",
			len(alternates), reason))
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

	return &CertBundle{Leaf: leaf, Chain: chain, PrivateKey: key, Alternates: alternates, Unrelated: unrelated,
		CrossSignedPathAvailable: crossSignedPathAvailable, Warnings: warnings, Notices: notices}
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

// issuerPath 는 서버 인증서의 발급자부터 상위 방향의 경로. nameOnlyLinks 는 서명은 맞지 않고 이름만 맞아 이어진 연결 수.
type issuerPath struct {
	chain         []*x509.Certificate
	nameOnlyLinks int
}

// findPaths 는 서버 인증서에서 루트 방향으로 갈 수 있는 경로를 모두 찾는다. 서명까지 맞는 발급자가 있으면 그것만 따라가고,
// 없으면 이름만 맞는 인증서를 따라간다.
func findPaths(leaf *x509.Certificate, certificates []*x509.Certificate) []issuerPath {
	var paths []issuerPath
	visited := map[*x509.Certificate]bool{leaf: true}
	var walk func(current *x509.Certificate, chain []*x509.Certificate, nameOnlyLinks int)
	walk = func(current *x509.Certificate, chain []*x509.Certificate, nameOnlyLinks int) {
		if len(paths) >= maxPaths {
			return
		}
		var verified, nameMatches []*x509.Certificate
		if !isSelfSigned(current) {
			for _, candidate := range certificates {
				if visited[candidate] || !sameName(current.RawIssuer, candidate.RawSubject) {
					continue
				}
				if verifies(current, candidate) {
					verified = append(verified, candidate)
				} else {
					nameMatches = append(nameMatches, candidate)
				}
			}
		}
		issuers, link := verified, 0
		if len(verified) == 0 {
			issuers, link = nameMatches, 1
		}
		if len(issuers) == 0 {
			paths = append(paths, issuerPath{chain: slices.Clone(chain), nameOnlyLinks: nameOnlyLinks})
			return
		}
		for _, issuer := range issuers {
			visited[issuer] = true
			walk(issuer, append(slices.Clip(chain), issuer), nameOnlyLinks+link)
			visited[issuer] = false
		}
	}
	walk(leaf, []*x509.Certificate{}, 0)
	return paths
}

// choosePath 는 브라우저가 고르는 경로에 가깝게, 신뢰된 루트에 더 일찍 닿는 경로 → 루트(자체 서명)로 끝나는 경로 →
// 서명이 확인된 경로 → 짧은 경로 순으로 고른다. 조건이 같으면 입력 순서상 먼저 찾은 경로.
func choosePath(paths []issuerPath, preferred map[*x509.Certificate]bool) issuerPath {
	best := paths[0]
	for _, path := range paths[1:] {
		if comparePaths(path, best, preferred) < 0 {
			best = path
		}
	}
	return best
}

func comparePaths(a, b issuerPath, preferred map[*x509.Certificate]bool) int {
	if a.passesAny(preferred) != b.passesAny(preferred) {
		if a.passesAny(preferred) {
			return -1
		}
		return 1
	}
	if a.trustedDepth() != b.trustedDepth() {
		if a.trustedDepth() < b.trustedDepth() {
			return -1
		}
		return 1
	}
	if a.complete() != b.complete() {
		if a.complete() {
			return -1
		}
		return 1
	}
	if c := a.nameOnlyLinks - b.nameOnlyLinks; c != 0 {
		return c
	}
	return len(a.chain) - len(b.chain)
}

// trustedDepth 는 신뢰된 루트에 닿는 위치. 체인 안에 신뢰된 루트(교차 서명본 포함)가 있으면 그 위치, 마지막 인증서의 발급자가
// 신뢰 저장소에 있으면 체인 길이, 닿지 않으면 가장 큰 값.
func (p issuerPath) trustedDepth() int {
	for i, certificate := range p.chain {
		if isTrustedRoot(certificate) {
			return i
		}
	}
	if len(p.chain) > 0 && !p.complete() && trustedIssuer(p.chain[len(p.chain)-1]) != nil {
		return len(p.chain)
	}
	return math.MaxInt
}

func (p issuerPath) passesAny(certificates map[*x509.Certificate]bool) bool {
	return slices.ContainsFunc(p.chain, func(certificate *x509.Certificate) bool { return certificates[certificate] })
}

func (p issuerPath) complete() bool {
	return len(p.chain) > 0 && isSelfSigned(p.chain[len(p.chain)-1])
}

// crossSignedRoots 는 같은 이름·공개키의 자체 서명 루트가 함께 들어 있는, 다른 CA 가 서명한 루트 인증서를 찾는다
// (예: AAA Certificate Services 가 서명한 USERTrust RSA CA).
func crossSignedRoots(certificates []*x509.Certificate) map[*x509.Certificate]bool {
	result := map[*x509.Certificate]bool{}
	for _, certificate := range certificates {
		if !isSelfSigned(certificate) && slices.ContainsFunc(certificates, func(root *x509.Certificate) bool {
			return isSelfSigned(root) && isCrossSigned(certificate, []*x509.Certificate{root})
		}) {
			result[certificate] = true
		}
	}
	return result
}

// isCrossSigned 는 체인의 인증서와 이름·공개키가 같은, 다른 CA 가 서명한 인증서인지 확인한다.
func isCrossSigned(certificate *x509.Certificate, chain []*x509.Certificate) bool {
	return slices.ContainsFunc(chain, func(member *x509.Certificate) bool {
		return member != certificate && sameName(member.RawSubject, certificate.RawSubject) &&
			bytes.Equal(member.RawSubjectPublicKeyInfo, certificate.RawSubjectPublicKeyInfo)
	})
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
