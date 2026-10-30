package cert

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ---------------------------------------------------------------- PKCS#7

// parsePkcs7 은 PKCS#7 SignedData(P7B) 안의 인증서를 꺼낸다.
func parsePkcs7(der []byte) ([]*x509.Certificate, error) {
	if converted, err := berToDer(der); err == nil {
		der = converted
	}
	input := cryptobyte.String(der)
	var contentInfo, signedData, certificates cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !input.ReadASN1(&contentInfo, cbasn1.SEQUENCE) || !contentInfo.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("PKCS#7 구조가 아닙니다")
	}
	if !oid.Equal(oidSignedData) {
		return nil, conversionError(nil, "지원하지 않는 PKCS#7 타입입니다: %v", oid)
	}
	var explicit cryptobyte.String
	if !contentInfo.ReadASN1(&explicit, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!explicit.ReadASN1(&signedData, cbasn1.SEQUENCE) {
		return nil, errors.New("PKCS#7 SignedData 가 비어 있습니다")
	}
	// version, digestAlgorithms, encapContentInfo 를 건너뛴다
	if !signedData.SkipASN1(cbasn1.INTEGER) || !signedData.SkipASN1(cbasn1.SET) ||
		!signedData.SkipASN1(cbasn1.SEQUENCE) {
		return nil, errors.New("PKCS#7 SignedData 구조가 올바르지 않습니다")
	}
	var present bool
	if !signedData.ReadOptionalASN1(&certificates, &present, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, errors.New("PKCS#7 인증서 목록을 읽을 수 없습니다")
	}
	var result []*x509.Certificate
	for !certificates.Empty() {
		var element cryptobyte.String
		var tag cbasn1.Tag
		if !certificates.ReadAnyASN1Element(&element, &tag) {
			return nil, errors.New("PKCS#7 인증서 목록이 손상되었습니다")
		}
		if tag != cbasn1.SEQUENCE {
			continue // 속성 인증서 등은 무시
		}
		certificate, err := x509.ParseCertificate(element)
		if err != nil {
			return nil, err
		}
		result = append(result, certificate)
	}
	return result, nil
}

// buildPkcs7 은 인증서만 담은 PKCS#7 SignedData (서명 없음) 를 만든다.
func buildPkcs7(certificates []*x509.Certificate) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidSignedData)
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1(cbasn1.SET, func(*cryptobyte.Builder) {})
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidData)
				})
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					for _, certificate := range certificates {
						b.AddBytes(certificate.Raw)
					}
				})
				b.AddASN1(cbasn1.SET, func(*cryptobyte.Builder) {})
			})
		})
	})
	return b.Bytes()
}

// ---------------------------------------------------------------- BER → DER

// berToDer 는 길이 미정(indefinite length) BER 인코딩을 확정 길이로 바꾸고, 조각난 OCTET STRING 을 합친다.
// encoding/asn1 이 DER 만 읽기 때문에 필요하다. 이미 DER 이면 같은 내용을 돌려준다.
func berToDer(data []byte) ([]byte, error) {
	out, rest, err := convertBer(data, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

const maxBerDepth = 64

func convertBer(data []byte, depth int) (out, rest []byte, err error) {
	if depth > maxBerDepth {
		return nil, nil, errors.New("too deep")
	}
	if len(data) < 2 {
		return nil, nil, errors.New("truncated")
	}
	tagEnd := 1
	if data[0]&0x1F == 0x1F {
		for tagEnd < len(data) && data[tagEnd]&0x80 != 0 {
			tagEnd++
		}
		tagEnd++
		if tagEnd >= len(data) {
			return nil, nil, errors.New("truncated tag")
		}
	}
	tag := data[:tagEnd]
	constructed := data[0]&0x20 != 0
	lengthByte := data[tagEnd]
	position := tagEnd + 1

	var content []byte
	if lengthByte == 0x80 {
		if !constructed {
			return nil, nil, errors.New("indefinite primitive")
		}
		var children []byte
		remaining := data[position:]
		for {
			if len(remaining) >= 2 && remaining[0] == 0 && remaining[1] == 0 {
				remaining = remaining[2:]
				break
			}
			child, next, err := convertBer(remaining, depth+1)
			if err != nil {
				return nil, nil, err
			}
			children = append(children, child...)
			remaining = next
		}
		content, rest = children, remaining
	} else {
		length := 0
		if lengthByte&0x80 == 0 {
			length = int(lengthByte)
		} else {
			count := int(lengthByte & 0x7F)
			if count > 4 || position+count > len(data) {
				return nil, nil, errors.New("bad length")
			}
			for _, b := range data[position : position+count] {
				length = length<<8 | int(b)
			}
			position += count
		}
		if length < 0 || position+length > len(data) {
			return nil, nil, errors.New("truncated content")
		}
		content, rest = data[position:position+length], data[position+length:]
		if constructed {
			var children []byte
			for remaining := content; len(remaining) > 0; {
				child, next, err := convertBer(remaining, depth+1)
				if err != nil {
					return nil, nil, err
				}
				children = append(children, child...)
				remaining = next
			}
			content = children
		}
	}

	// 조각난(constructed) OCTET STRING 은 하나의 primitive OCTET STRING 으로 합친다
	if len(tag) == 1 && tag[0] == 0x24 {
		merged, err := mergeOctetStrings(content)
		if err != nil {
			return nil, nil, err
		}
		tag, content = []byte{0x04}, merged
	}
	return append(append(append([]byte{}, tag...), encodeLength(len(content))...), content...), rest, nil
}

func mergeOctetStrings(content []byte) ([]byte, error) {
	var merged []byte
	input := cryptobyte.String(content)
	for !input.Empty() {
		var part cryptobyte.String
		if !input.ReadASN1(&part, cbasn1.OCTET_STRING) {
			return nil, errors.New("bad octet string fragment")
		}
		merged = append(merged, part...)
	}
	return merged, nil
}

func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var digits []byte
	for l := length; l > 0; l >>= 8 {
		digits = append([]byte{byte(l)}, digits...)
	}
	return append([]byte{0x80 | byte(len(digits))}, digits...)
}
