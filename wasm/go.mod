module sslconverter

go 1.26.0

// Java/BouncyCastle 처럼 음수 일련번호 인증서와 1024비트 미만 RSA 키도 읽어서 점검 결과로 보여준다
godebug (
	rsa1024min=0
	x509negativeserial=1
)

require (
	github.com/pavlo-v-chernykh/keystore-go/v4 v4.5.0
	golang.org/x/crypto v0.58.0
	golang.org/x/crypto/x509roots/fallback v0.0.0-20261029161132-16804593e8b0
	golang.org/x/text v0.43.0
	software.sslmate.com/src/go-pkcs12 v0.7.4
)
