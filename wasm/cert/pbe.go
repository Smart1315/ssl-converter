package cert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// 비밀번호 기반 암호화 (PKCS#5 PBES1/PBES2, PKCS#12 PBE). 암호화된 PKCS#8 개인키와 PFX 에서 사용한다.

var (
	oidData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPBES2            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBEWithMD5AndDES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
	oidPBEWithSHA1DES   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
	oidPBEWithSHA3DES   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHA2DES   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	oidHmacWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHmacWithSHA224   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHmacWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHmacWithSHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHmacWithSHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC       = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

var errBadPassword = errors.New("bad password or corrupted data")

// decryptPkcs8 은 EncryptedPrivateKeyInfo 를 복호화해 개인키를 돌려준다.
func decryptPkcs8(der []byte, password string) (any, error) {
	input := cryptobyte.String(der)
	var info, algorithm cryptobyte.String
	var oid asn1.ObjectIdentifier
	var encrypted []byte
	if !input.ReadASN1(&info, cbasn1.SEQUENCE) || !info.ReadASN1(&algorithm, cbasn1.SEQUENCE) ||
		!algorithm.ReadASN1ObjectIdentifier(&oid) || !info.ReadASN1Bytes(&encrypted, cbasn1.OCTET_STRING) {
		return nil, errors.New("암호화된 개인키 구조가 올바르지 않습니다")
	}
	plain, err := pbeDecrypt(oid, algorithm, password, encrypted)
	if err != nil {
		if errors.Is(err, errBadPassword) {
			return nil, conversionError(err, "개인키 비밀번호가 올바르지 않습니다")
		}
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, conversionError(err, "개인키 비밀번호가 올바르지 않습니다")
	}
	return key, nil
}

// pbeEncrypter 는 암호화하고 AlgorithmIdentifier(DER) 와 암호문을 돌려준다.
type pbeEncrypter func(plain []byte, password string, iterations int) (algorithm, encrypted []byte, err error)

// encryptPkcs8 은 PKCS#8 개인키를 암호화한 EncryptedPrivateKeyInfo 를 만든다.
func encryptPkcs8(pkcs8 []byte, password string, encrypt pbeEncrypter, iterations int) ([]byte, error) {
	algorithm, encrypted, err := encrypt(pkcs8, password, iterations)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(algorithm)
		b.AddASN1OctetString(encrypted)
	})
	return b.Bytes()
}

func pbeDecrypt(oid asn1.ObjectIdentifier, params cryptobyte.String, password string, data []byte) ([]byte, error) {
	var block cipher.Block
	var iv []byte
	var err error
	switch {
	case oid.Equal(oidPBES2):
		block, iv, err = pbes2Cipher(params, password)
	case oid.Equal(oidPBEWithSHA3DES), oid.Equal(oidPBEWithSHA2DES):
		var salt []byte
		var iterations int
		if salt, iterations, err = pkcs12PbeParams(params); err == nil {
			block, iv, err = pkcs12TripleDes(salt, iterations, password, oid.Equal(oidPBEWithSHA2DES))
		}
	case oid.Equal(oidPBEWithMD5AndDES), oid.Equal(oidPBEWithSHA1DES):
		var salt []byte
		var iterations int
		if salt, iterations, err = pkcs12PbeParams(params); err == nil {
			newHash := md5.New
			if oid.Equal(oidPBEWithSHA1DES) {
				newHash = sha1.New
			}
			derived := pbkdf1(newHash, []byte(password), salt, iterations)
			iv = derived[8:16]
			block, err = des.NewCipher(derived[:8])
		}
	default:
		return nil, conversionError(nil, "지원하지 않는 개인키 암호화 방식입니다 (%v)", oid)
	}
	if err != nil {
		return nil, err
	}
	return cbcDecrypt(block, iv, data)
}

func pbes2Cipher(params cryptobyte.String, password string) (cipher.Block, []byte, error) {
	var sequence, kdf, kdfParams, scheme cryptobyte.String
	var kdfOid, schemeOid asn1.ObjectIdentifier
	if !params.ReadASN1(&sequence, cbasn1.SEQUENCE) || !sequence.ReadASN1(&kdf, cbasn1.SEQUENCE) ||
		!kdf.ReadASN1ObjectIdentifier(&kdfOid) || !sequence.ReadASN1(&scheme, cbasn1.SEQUENCE) ||
		!scheme.ReadASN1ObjectIdentifier(&schemeOid) {
		return nil, nil, errors.New("PBES2 파라미터가 올바르지 않습니다")
	}
	if !kdfOid.Equal(oidPBKDF2) {
		return nil, nil, conversionError(nil, "지원하지 않는 키 유도 방식입니다 (%v)", kdfOid)
	}
	var salt []byte
	var iterations int
	if !kdf.ReadASN1(&kdfParams, cbasn1.SEQUENCE) || !kdfParams.ReadASN1Bytes(&salt, cbasn1.OCTET_STRING) ||
		!kdfParams.ReadASN1Integer(&iterations) {
		return nil, nil, errors.New("PBKDF2 파라미터가 올바르지 않습니다")
	}
	var keyLength int
	if kdfParams.PeekASN1Tag(cbasn1.INTEGER) && !kdfParams.ReadASN1Integer(&keyLength) {
		return nil, nil, errors.New("PBKDF2 키 길이가 올바르지 않습니다")
	}
	newHash := sha1.New
	if kdfParams.PeekASN1Tag(cbasn1.SEQUENCE) {
		var prf cryptobyte.String
		var prfOid asn1.ObjectIdentifier
		if !kdfParams.ReadASN1(&prf, cbasn1.SEQUENCE) || !prf.ReadASN1ObjectIdentifier(&prfOid) {
			return nil, nil, errors.New("PBKDF2 PRF 가 올바르지 않습니다")
		}
		switch {
		case prfOid.Equal(oidHmacWithSHA1):
		case prfOid.Equal(oidHmacWithSHA224):
			newHash = sha256.New224
		case prfOid.Equal(oidHmacWithSHA256):
			newHash = sha256.New
		case prfOid.Equal(oidHmacWithSHA384):
			newHash = sha512.New384
		case prfOid.Equal(oidHmacWithSHA512):
			newHash = sha512.New
		default:
			return nil, nil, conversionError(nil, "지원하지 않는 PBKDF2 해시입니다 (%v)", prfOid)
		}
	}
	var iv []byte
	if !scheme.ReadASN1Bytes(&iv, cbasn1.OCTET_STRING) {
		return nil, nil, errors.New("암호화 IV 가 없습니다")
	}
	var size int
	var newCipher func([]byte) (cipher.Block, error)
	switch {
	case schemeOid.Equal(oidAES128CBC):
		size, newCipher = 16, aes.NewCipher
	case schemeOid.Equal(oidAES192CBC):
		size, newCipher = 24, aes.NewCipher
	case schemeOid.Equal(oidAES256CBC):
		size, newCipher = 32, aes.NewCipher
	case schemeOid.Equal(oidDESEDE3CBC):
		size, newCipher = 24, des.NewTripleDESCipher
	default:
		return nil, nil, conversionError(nil, "지원하지 않는 암호화 알고리즘입니다 (%v)", schemeOid)
	}
	if keyLength == 0 {
		keyLength = size
	}
	key, err := pbkdf2.Key(newHash, password, salt, iterations, keyLength)
	if err != nil {
		return nil, nil, err
	}
	block, err := newCipher(key)
	return block, iv, err
}

// pbes2Encrypt 는 PBKDF2-HMAC-SHA256 + AES-256-CBC 로 암호화하고 AlgorithmIdentifier(DER) 와 암호문을 돌려준다.
func pbes2Encrypt(plain []byte, password string, iterations int) (algorithm, encrypted []byte, err error) {
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidPBES2)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidPBKDF2)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(salt)
					b.AddASN1Int64(int64(iterations))
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidHmacWithSHA256)
						b.AddASN1NULL()
					})
				})
			})
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidAES256CBC)
				b.AddASN1OctetString(iv)
			})
		})
	})
	if algorithm, err = b.Bytes(); err != nil {
		return nil, nil, err
	}
	return algorithm, cbcEncrypt(block, iv, plain), nil
}

// pkcs12TripleDesEncrypt 는 PBE-SHA1-3DES (PKCS#12) 로 암호화하고 AlgorithmIdentifier(DER) 와 암호문을 돌려준다.
func pkcs12TripleDesEncrypt(plain []byte, password string, iterations int) (algorithm, encrypted []byte, err error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	block, iv, err := pkcs12TripleDes(salt, iterations, password, false)
	if err != nil {
		return nil, nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidPBEWithSHA3DES)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(salt)
			b.AddASN1Int64(int64(iterations))
		})
	})
	if algorithm, err = b.Bytes(); err != nil {
		return nil, nil, err
	}
	return algorithm, cbcEncrypt(block, iv, plain), nil
}

func pkcs12PbeParams(params cryptobyte.String) ([]byte, int, error) {
	var sequence cryptobyte.String
	var salt []byte
	var iterations int
	if !params.ReadASN1(&sequence, cbasn1.SEQUENCE) || !sequence.ReadASN1Bytes(&salt, cbasn1.OCTET_STRING) ||
		!sequence.ReadASN1Integer(&iterations) {
		return nil, 0, errors.New("PBE 파라미터가 올바르지 않습니다")
	}
	return salt, iterations, nil
}

func pkcs12TripleDes(salt []byte, iterations int, password string, twoKey bool) (cipher.Block, []byte, error) {
	encoded := bmpPassword(password)
	keyLength := 24
	if twoKey {
		keyLength = 16
	}
	key := pkcs12Kdf(sha1.New, salt, encoded, iterations, 1, keyLength)
	if twoKey {
		key = append(key, key[:8]...)
	}
	iv := pkcs12Kdf(sha1.New, salt, encoded, iterations, 2, 8)
	block, err := des.NewTripleDESCipher(key)
	return block, iv, err
}

// bmpPassword 는 PKCS#12 비밀번호 인코딩 (UTF-16BE + 0x0000).
func bmpPassword(password string) []byte {
	units := utf16.Encode([]rune(password))
	encoded := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		encoded = append(encoded, byte(u>>8), byte(u))
	}
	return append(encoded, 0, 0)
}

// pkcs12Kdf 는 RFC 7292 부록 B.2 의 키 유도 함수. id 1 = 암호화 키, 2 = IV, 3 = MAC 키.
func pkcs12Kdf(newHash func() hash.Hash, salt, password []byte, iterations int, id byte, size int) []byte {
	u := newHash().Size()
	v := newHash().BlockSize()
	fill := func(pattern []byte) []byte {
		if len(pattern) == 0 {
			return nil
		}
		out := make([]byte, v*((len(pattern)+v-1)/v))
		for i := range out {
			out[i] = pattern[i%len(pattern)]
		}
		return out
	}
	diversifier := bytes.Repeat([]byte{id}, v)
	input := append(fill(salt), fill(password)...)
	var result []byte
	for len(result) < size {
		h := newHash()
		h.Write(diversifier)
		h.Write(input)
		a := h.Sum(nil)
		for i := 1; i < iterations; i++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(nil)
		}
		result = append(result, a...)
		b := make([]byte, v)
		for i := range b {
			b[i] = a[i%u]
		}
		// 입력의 각 v 바이트 블록 Ij 를 (Ij + B + 1) mod 2^(8v) 로 바꾼다
		for j := 0; j < len(input); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(input[j+k]) + int(b[k]) + carry
				input[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return result[:size]
}

func pbkdf1(newHash func() hash.Hash, password, salt []byte, iterations int) []byte {
	h := newHash()
	h.Write(password)
	h.Write(salt)
	derived := h.Sum(nil)
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(derived)
		derived = h.Sum(nil)
	}
	return derived
}

func cbcEncrypt(block cipher.Block, iv, plain []byte) []byte {
	padding := block.BlockSize() - len(plain)%block.BlockSize()
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return padded
}

func cbcDecrypt(block cipher.Block, iv, data []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(data) == 0 || len(data)%size != 0 || len(iv) != size {
		return nil, errBadPassword
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > size || !bytes.Equal(plain[len(plain)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		return nil, errBadPassword
	}
	return plain[:len(plain)-padding], nil
}
