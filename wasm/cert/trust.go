package cert

import (
	"bytes"
	"crypto/x509"
	"slices"
	"sync"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// Mozilla(NSS) 공인 루트 인증서. Java 판의 JDK cacerts 에 해당한다. 처음 사용할 때 한 번만 읽는다.
// 목록은 golang.org/x/crypto/x509roots/fallback 모듈을 올리고 다시 빌드하면 갱신된다.

type trustedRoots struct {
	pool         *x509.CertPool
	certificates []*x509.Certificate
}

var loadTrustStore = sync.OnceValue(func() trustedRoots {
	roots := trustedRoots{pool: x509.NewCertPool()}
	for root := range bundle.Roots() {
		certificate, err := x509.ParseCertificate(root.Certificate)
		if err != nil {
			continue
		}
		roots.certificates = append(roots.certificates, certificate)
		if root.Constraint != nil {
			roots.pool.AddCertWithConstraint(certificate, root.Constraint)
		} else {
			roots.pool.AddCert(certificate)
		}
	}
	return roots
})

func trustStore() *x509.CertPool { return loadTrustStore().pool }

// isTrustedRoot 는 같은 이름과 공개키의 루트가 신뢰 저장소에 있는지 확인한다. 교차 서명된 루트 인증서도 신뢰된 루트로 본다.
func isTrustedRoot(certificate *x509.Certificate) bool {
	return slices.ContainsFunc(loadTrustStore().certificates, func(root *x509.Certificate) bool {
		return sameName(root.RawSubject, certificate.RawSubject) &&
			bytes.Equal(root.RawSubjectPublicKeyInfo, certificate.RawSubjectPublicKeyInfo)
	})
}

// trustedIssuer 는 certificate 를 발급한 루트를 신뢰 저장소에서 찾는다.
func trustedIssuer(certificate *x509.Certificate) *x509.Certificate {
	for _, root := range loadTrustStore().certificates {
		if issuedBy(certificate, root) {
			return root
		}
	}
	return nil
}
