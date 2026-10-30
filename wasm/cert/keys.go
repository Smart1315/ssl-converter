package cert

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // 구형 DSA 인증서의 서명 확인용
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// 키 관련 공통 기능: 개인키-인증서 일치 확인, 키 설명 문자열, 서명 확인.

// keyMatches 는 개인키가 공개키와 짝인지 확인한다.
func keyMatches(privateKey crypto.Signer, publicKey crypto.PublicKey) bool {
	return keyEqual(privateKey.Public(), publicKey)
}

var curveNames = map[string]string{"P-224": "secp224r1", "P-256": "prime256v1", "P-384": "secp384r1",
	"P-521": "secp521r1"}

// describeKey 는 "RSA 2048비트", "EC secp384r1 (384비트)" 같은 설명을 만든다. 공개키/개인키 모두 받는다.
func describeKey(key any) string {
	if signer, ok := key.(crypto.Signer); ok {
		key = signer.Public()
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d비트", k.N.BitLen())
	case *ecdsa.PublicKey:
		params := k.Curve.Params()
		name := curveNames[params.Name]
		if name == "" {
			name = params.Name
		}
		return fmt.Sprintf("EC %s (%d비트)", name, params.BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	case *dsa.PublicKey:
		return "DSA"
	}
	return fmt.Sprintf("%T", key)
}

// issuedBy 는 issuer 가 certificate 를 발급했는지 (이름 + 서명) 확인한다.
func issuedBy(certificate, issuer *x509.Certificate) bool {
	return sameName(certificate.RawIssuer, issuer.RawSubject) && verifies(certificate, issuer)
}

func isSelfSigned(certificate *x509.Certificate) bool {
	return issuedBy(certificate, certificate)
}

// verifies 는 서명만 확인한다. x509.CheckSignatureFrom 은 SHA-1 서명과 CA 가 아닌 발급자를 거부하므로 직접 확인한다
// (SHA-1 로 서명된 오래된 루트도 루트로 인식해야 하고, 취약한 서명은 점검 항목에서 따로 알려준다).
func verifies(certificate, issuer *x509.Certificate) bool {
	return verifySignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature,
		issuer.PublicKey)
}

func verifySignature(algorithm x509.SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) bool {
	if algorithm == x509.PureEd25519 {
		key, ok := publicKey.(ed25519.PublicKey)
		return ok && ed25519.Verify(key, signed, signature)
	}
	var hashType crypto.Hash
	pss := false
	switch algorithm {
	case x509.MD5WithRSA:
		hashType = crypto.MD5
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.DSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	case x509.SHA256WithRSAPSS:
		hashType, pss = crypto.SHA256, true
	case x509.SHA384WithRSAPSS:
		hashType, pss = crypto.SHA384, true
	case x509.SHA512WithRSAPSS:
		hashType, pss = crypto.SHA512, true
	default:
		return false
	}
	digest := digest(hashType, signed)
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if pss {
			return rsa.VerifyPSS(key, hashType, digest, signature,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
		return rsa.VerifyPKCS1v15(key, hashType, digest, signature) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest, signature)
	case *dsa.PublicKey:
		var values struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signature, &values); err != nil {
			return false
		}
		size := (key.Q.BitLen() + 7) / 8
		if len(digest) > size {
			digest = digest[:size]
		}
		return dsa.Verify(key, digest, values.R, values.S)
	}
	return false
}

func digest(hashType crypto.Hash, data []byte) []byte {
	switch hashType {
	case crypto.MD5:
		sum := md5.Sum(data)
		return sum[:]
	case crypto.SHA1:
		sum := sha1.Sum(data)
		return sum[:]
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	default:
		sum := sha512.Sum512(data)
		return sum[:]
	}
}
