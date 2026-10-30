package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// 정리된 인증서 묶음을 요청된 형식의 파일로 만든다. 모든 처리는 메모리에서만 이루어진다.

// pkcs8EncryptionIterations 는 암호화된 개인키 PEM 의 PBKDF2 반복 횟수.
const pkcs8EncryptionIterations = 100_000

// Export 는 선택된 형식의 파일과, 만들지 않은 항목과 그 이유를 돌려준다.
func Export(bundle *CertBundle, options ExportOptions) (files []ExportedFile, skipped []string, err error) {
	for _, format := range OutputFormats {
		if !options.Formats[format.ID] {
			continue
		}
		fileName := format.FileName(options.BaseName)
		switch {
		case format.RequiresKey && !bundle.HasPrivateKey():
			skipped = append(skipped, fileName+": 인증서와 일치하는 개인키가 없어 생성하지 않았습니다")
			continue
		case format == FormatChainPem && len(bundle.ChainFor(options.IncludeRoot)) == 0:
			skipped = append(skipped, fileName+": 체인(중간) 인증서가 없어 생성하지 않았습니다")
			continue
		case format == FormatTruststoreJks && len(bundle.Chain) == 0 && !bundle.RootIncluded():
			skipped = append(skipped, fileName+": 체인(CA) 인증서가 없어 생성하지 않았습니다")
			continue
		}
		data, err := create(format, bundle, options)
		if err != nil {
			return nil, nil, conversionError(err, "%s 생성 실패: %v", fileName, err)
		}
		files = append(files, ExportedFile{FileName: fileName, ContentType: format.ContentType, Data: data})
	}
	return files, skipped, nil
}

func create(format OutputFormat, bundle *CertBundle, options ExportOptions) ([]byte, error) {
	includeRoot := options.IncludeRoot
	switch format {
	case FormatFullchainPem:
		return certificatesPem(bundle.FullChain(includeRoot)), nil
	case FormatCertPem:
		return certificatesPem([]*x509.Certificate{bundle.Leaf}), nil
	case FormatChainPem:
		return certificatesPem(bundle.ChainFor(includeRoot)), nil
	case FormatKeyPem:
		return privateKeyPem(bundle, options)
	case FormatCombinedPem:
		key, err := privateKeyPem(bundle, options)
		if err != nil {
			return nil, err
		}
		return append(key, certificatesPem(bundle.FullChain(includeRoot))...), nil
	case FormatPfx:
		return encodePfx(bundle, options)
	case FormatJks:
		return encodeJks(bundle, options)
	case FormatTruststoreJks:
		return encodeTruststore(bundle, options)
	case FormatP7b:
		return buildPkcs7(bundle.FullChain(includeRoot))
	default:
		return bundle.Leaf.Raw, nil
	}
}

// certificatesPem 은 각 블록을 64자 줄바꿈과 독립된 BEGIN/END 줄로 기록한다 (END/BEGIN 이 한 줄에 붙는 문제 방지).
func certificatesPem(certificates []*x509.Certificate) []byte {
	var out bytes.Buffer
	for _, certificate := range certificates {
		pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	}
	return out.Bytes()
}

func privateKeyPem(bundle *CertBundle, options ExportOptions) ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(bundle.PrivateKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	switch options.KeyFormat {
	case KeyTraditional:
		// 전통(OpenSSL) 형식이 없는 키(Ed25519 등)는 PKCS#8 로 쓴다
		switch key := bundle.PrivateKey.(type) {
		case *rsa.PrivateKey:
			block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		case *ecdsa.PrivateKey:
			sec1, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, err
			}
			block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}
		}
	case KeyPKCS8Encrypted:
		encrypted, err := encryptPkcs8(pkcs8, options.Password, pbes2Encrypt, pkcs8EncryptionIterations)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encrypted}
	}
	return pem.EncodeToMemory(block), nil
}
