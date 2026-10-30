package cert

import (
	"crypto"
	"crypto/x509"
	"sync"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// Mozilla(NSS) 공인 루트 인증서. Java 판의 JDK cacerts 에 해당한다. 처음 사용할 때 한 번만 읽는다.
// 목록은 golang.org/x/crypto/x509roots/fallback 모듈을 올리고 다시 빌드하면 갱신된다.

var trustStore = sync.OnceValues(func() ([]*x509.Certificate, *x509.CertPool) {
	pool := x509.NewCertPool()
	var roots []*x509.Certificate
	for root := range bundle.Roots() {
		certificate, err := x509.ParseCertificate(root.Certificate)
		if err != nil {
			continue
		}
		roots = append(roots, certificate)
		if root.Constraint != nil {
			pool.AddCertWithConstraint(certificate, root.Constraint)
		} else {
			pool.AddCert(certificate)
		}
	}
	return roots, pool
})

// isTrustedRoot 는 같은 이름과 공개키의 루트가 신뢰 저장소에 있는지 확인한다. 교차 서명된 루트 인증서도 신뢰된 루트로 본다.
func isTrustedRoot(certificate *x509.Certificate) bool {
	roots, _ := trustStore()
	for _, root := range roots {
		if sameName(root.RawSubject, certificate.RawSubject) && keyEqual(root.PublicKey, certificate.PublicKey) {
			return true
		}
	}
	return false
}

// findTrustedIssuer 는 체인에 포함되지 않은 발급자를 신뢰 저장소에서 찾는다.
func findTrustedIssuer(certificate *x509.Certificate) *x509.Certificate {
	roots, _ := trustStore()
	for _, root := range roots {
		if issuedBy(certificate, root) {
			return root
		}
	}
	return nil
}

func keyEqual(a, b crypto.PublicKey) bool {
	key, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && key.Equal(b)
}
