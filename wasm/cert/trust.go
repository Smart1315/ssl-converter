package cert

import (
	"crypto/x509"
	"sync"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// Mozilla(NSS) 공인 루트 인증서. Java 판의 JDK cacerts 에 해당한다. 처음 사용할 때 한 번만 읽는다.
// 목록은 golang.org/x/crypto/x509roots/fallback 모듈을 올리고 다시 빌드하면 갱신된다.

var trustStore = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	for root := range bundle.Roots() {
		certificate, err := x509.ParseCertificate(root.Certificate)
		if err != nil {
			continue
		}
		if root.Constraint != nil {
			pool.AddCertWithConstraint(certificate, root.Constraint)
		} else {
			pool.AddCert(certificate)
		}
	}
	return pool
})
