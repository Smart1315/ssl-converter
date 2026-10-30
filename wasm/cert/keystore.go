package cert

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ---------------------------------------------------------------- 읽기

func loadPkcs12(der []byte, password, alias, name string, c *collector) error {
	c.addFormat("PKCS#12(PFX/P12)")
	blocks, err := pkcs12.ToPEM(der, password)
	if isPfxPasswordError(err) {
		return keystorePasswordError(password, err)
	}
	if err != nil {
		// ToPEM 은 모르는 속성(Java 신뢰 표시 등)이나 Ed25519 키가 있으면 실패하므로 단순한 방식으로 다시 읽는다
		return loadPkcs12Simple(der, password, name, c)
	}

	type keyEntry struct {
		alias, localKeyID string
		key               any
	}
	var keys []keyEntry
	var certificates []*pemCertificate
	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			certificates = append(certificates, &pemCertificate{certificate, block.Headers["localKeyId"]})
		default:
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			var parsed any = key
			if err != nil {
				if parsed, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
					return err
				}
			}
			entryAlias := block.Headers["friendlyName"]
			if entryAlias == "" {
				entryAlias = strconv.Itoa(len(keys) + 1)
			}
			keys = append(keys, keyEntry{entryAlias, block.Headers["localKeyId"], parsed})
		}
	}

	var keyAliases []string
	for _, k := range keys {
		keyAliases = append(keyAliases, k.alias)
		c.result.KeystoreEntries = append(c.result.KeystoreEntries, KeystoreEntry{name, k.alias, "PrivateKeyEntry"})
	}
	selectedLocalKeyID := ""
	if len(keys) > 0 {
		selected := selectAlias(keyAliases, alias, name, c)
		index := slices.Index(keyAliases, selected)
		if err := c.addPrivateKey(keys[index].key); err != nil {
			return err
		}
		selectedLocalKeyID = keys[index].localKeyID
	}
	// 선택한 키의 인증서와 키에 묶이지 않은 (CA) 인증서만 사용한다
	for _, certificate := range certificates {
		if certificate.localKeyID == "" || certificate.localKeyID == selectedLocalKeyID {
			c.addCertificate(certificate.certificate)
		}
	}
	return nil
}

type pemCertificate struct {
	certificate *x509.Certificate
	localKeyID  string
}

func loadPkcs12Simple(der []byte, password, name string, c *collector) error {
	key, leaf, chain, err := pkcs12.DecodeChain(der, password)
	if err == nil {
		c.result.KeystoreEntries = append(c.result.KeystoreEntries, KeystoreEntry{name, "1", "PrivateKeyEntry"})
		selected := "1"
		c.result.SelectedAlias = &selected
		if err := c.addPrivateKey(key); err != nil {
			return err
		}
		for _, certificate := range append([]*x509.Certificate{leaf}, chain...) {
			c.addCertificate(certificate)
		}
		return nil
	}
	if isPfxPasswordError(err) {
		return keystorePasswordError(password, err)
	}
	certificates, trustErr := pkcs12.DecodeTrustStore(der, password)
	if trustErr != nil {
		if isPfxPasswordError(trustErr) {
			return keystorePasswordError(password, trustErr)
		}
		return conversionError(err, "PFX 파일을 읽을 수 없습니다: %v", err)
	}
	for i, certificate := range certificates {
		c.result.KeystoreEntries = append(c.result.KeystoreEntries,
			KeystoreEntry{name, strconv.Itoa(i + 1), "trustedCertEntry"})
		c.addCertificate(certificate)
	}
	return nil
}

func isPfxPasswordError(err error) bool {
	return errors.Is(err, pkcs12.ErrIncorrectPassword) || errors.Is(err, pkcs12.ErrDecryption)
}

func keystorePasswordError(password string, err error) error {
	if password == "" {
		return conversionError(err, "비밀번호로 보호된 키스토어입니다. '입력 비밀번호'를 입력하세요")
	}
	return conversionError(err, "키스토어 비밀번호가 올바르지 않거나 파일이 손상되었습니다")
}

func loadJks(data []byte, password, alias, name string, c *collector) error {
	c.addFormat("JKS")
	store := keystore.New(keystore.WithOrderedAliases())
	if err := store.Load(bytes.NewReader(data), []byte(password)); err != nil {
		return keystorePasswordError(password, err)
	}
	var keyAliases []string
	for _, entryAlias := range store.Aliases() {
		entryType := "trustedCertEntry"
		if store.IsPrivateKeyEntry(entryAlias) {
			entryType = "PrivateKeyEntry"
			keyAliases = append(keyAliases, entryAlias)
		}
		c.result.KeystoreEntries = append(c.result.KeystoreEntries, KeystoreEntry{name, entryAlias, entryType})
	}
	if len(keyAliases) > 0 {
		selected := selectAlias(keyAliases, alias, name, c)
		entry, err := store.GetPrivateKeyEntry(selected, []byte(password))
		if err != nil {
			return conversionError(err, "키 비밀번호가 키스토어 비밀번호와 다릅니다. 키 비밀번호를 입력해 보세요")
		}
		key, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
		if err != nil {
			return err
		}
		if err := c.addPrivateKey(key); err != nil {
			return err
		}
		for _, certificate := range entry.CertificateChain {
			addX509(certificate, c)
		}
	}
	for _, entryAlias := range store.Aliases() {
		if store.IsTrustedCertificateEntry(entryAlias) {
			entry, err := store.GetTrustedCertificateEntry(entryAlias)
			if err != nil {
				return err
			}
			addX509(entry.Certificate, c)
		}
	}
	return nil
}

func addX509(certificate keystore.Certificate, c *collector) {
	if certificate.Type != "" && certificate.Type != "X.509" && certificate.Type != "X509" {
		return
	}
	if parsed, err := x509.ParseCertificate(certificate.Content); err == nil {
		c.addCertificate(parsed)
	}
}

// selectAlias 는 사용자가 고른 별칭이 있으면 그것을, 없으면 첫 번째 개인키 항목을 고른다.
func selectAlias(keyAliases []string, alias, name string, c *collector) string {
	selected := keyAliases[0]
	if alias != "" && slices.Contains(keyAliases, alias) {
		selected = alias
	} else if len(keyAliases) > 1 {
		c.result.Warnings = append(c.result.Warnings, fmt.Sprintf(
			"%s: 개인키 항목이 여러 개입니다 [%s]. '%s' 항목을 사용합니다 (별칭 선택에서 변경 가능)", name,
			strings.Join(keyAliases, ", "), selected))
	}
	c.result.SelectedAlias = &selected
	c.note("별칭 '" + selected + "' 사용")
	return selected
}

// ---------------------------------------------------------------- 쓰기

var (
	oidEncryptedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidCertBag           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidShroudedKeyBag    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidX509Certificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidJavaTrustedUsage  = asn1.ObjectIdentifier{2, 16, 840, 1, 113894, 746875, 1, 1}
	oidAnyExtendedKeyUse = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidSHA1              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// pfxProfile 은 PFX 암호화 방식.
type pfxProfile struct {
	encrypt    pbeEncrypter
	iterations int
	macHash    func() hash.Hash
	macOid     asn1.ObjectIdentifier
}

var (
	// JDK 17 기본값과 같은 AES-256/PBKDF2-SHA256, MAC SHA-256
	modernPfx = pfxProfile{pbes2Encrypt, 10000, sha256.New, oidSHA256}
	// Windows Server 2016 이하 / 구형 Java 와 호환되는 PBE-SHA1-3DES, MAC SHA-1. OpenSSL 3 에서도 legacy 옵션 없이 읽힌다
	legacyPfx = pfxProfile{pkcs12TripleDesEncrypt, 2048, sha1.New, oidSHA1}
)

// trustedEntry 는 키스토어에 넣을 신뢰 인증서와 별칭.
type trustedEntry struct {
	alias       string
	certificate *x509.Certificate
}

var nonAliasChars = regexp.MustCompile(`[^a-z0-9.\-_]+`)

// trustedEntries 는 인증서마다 겹치지 않는 별칭을 붙인다. firstAlias 가 있으면 첫 인증서에 사용한다.
func trustedEntries(certificates []*x509.Certificate, firstAlias string) []trustedEntry {
	used := map[string]bool{}
	var entries []trustedEntry
	for _, certificate := range certificates {
		base := firstAlias
		if base == "" || len(used) > 0 {
			base = strings.Trim(nonAliasChars.ReplaceAllString(strings.ToLower(commonNameOrDn(certificate.RawSubject)), "-"), "-")
			if base == "" {
				base = "ca"
			}
		}
		entryAlias := base
		for i := 2; used[entryAlias]; i++ {
			entryAlias = fmt.Sprintf("%s-%d", base, i)
		}
		used[entryAlias] = true
		entries = append(entries, trustedEntry{entryAlias, certificate})
	}
	return entries
}

// encodePfx 는 PKCS#12 키스토어를 만든다. 개인키가 있으면 키 항목 하나(별칭 = alias), 없으면 신뢰 인증서 항목들로 저장한다.
func encodePfx(bundle *CertBundle, options ExportOptions) ([]byte, error) {
	profile := modernPfx
	if options.LegacyPfx {
		profile = legacyPfx
	}
	chain := bundle.FullChain(options.IncludeRoot)
	var certBags, keyBags cryptobyte.Builder
	if bundle.HasPrivateKey() {
		localKeyID := sha1.Sum(bundle.Leaf.Raw)
		attributes := func(b *cryptobyte.Builder) {
			addAttribute(b, oidFriendlyName, func(b *cryptobyte.Builder) { addBMPString(b, options.Alias) })
			addAttribute(b, oidLocalKeyID, func(b *cryptobyte.Builder) { b.AddASN1OctetString(localKeyID[:]) })
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(bundle.PrivateKey)
		if err != nil {
			return nil, err
		}
		shrouded, err := encryptPkcs8(pkcs8, options.Password, profile.encrypt, profile.iterations)
		if err != nil {
			return nil, err
		}
		addSafeBag(&keyBags, oidShroudedKeyBag, func(b *cryptobyte.Builder) { b.AddBytes(shrouded) }, attributes)
		for i, certificate := range chain {
			var certificateAttributes func(*cryptobyte.Builder)
			if i == 0 {
				certificateAttributes = attributes
			}
			addCertBag(&certBags, certificate, certificateAttributes)
		}
	} else {
		for _, entry := range trustedEntries(chain, options.Alias) {
			addCertBag(&certBags, entry.certificate, func(b *cryptobyte.Builder) {
				addAttribute(b, oidFriendlyName, func(b *cryptobyte.Builder) { addBMPString(b, entry.alias) })
				// Java 가 trustedCertEntry 로 인식하도록 신뢰 용도 속성을 붙인다
				addAttribute(b, oidJavaTrustedUsage, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidAnyExtendedKeyUse)
				})
			})
		}
	}

	certContents, err := safeContents(&certBags)
	if err != nil {
		return nil, err
	}
	algorithm, encryptedCerts, err := profile.encrypt(certContents, options.Password, profile.iterations)
	if err != nil {
		return nil, err
	}
	var keyContents []byte
	if bundle.HasPrivateKey() {
		if keyContents, err = safeContents(&keyBags); err != nil {
			return nil, err
		}
	}

	var authSafe cryptobyte.Builder
	authSafe.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if keyContents != nil {
			addDataContentInfo(b, keyContents)
		}
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEncryptedData)
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1Int64(0)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidData)
						b.AddBytes(algorithm)
						b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(encryptedCerts) })
					})
				})
			})
		})
	})
	authSafeBytes, err := authSafe.Bytes()
	if err != nil {
		return nil, err
	}

	macSalt := make([]byte, 16)
	if _, err := rand.Read(macSalt); err != nil {
		return nil, err
	}
	macKey := pkcs12Kdf(profile.macHash, macSalt, bmpPassword(options.Password), profile.iterations, 3,
		profile.macHash().Size())
	mac := hmac.New(profile.macHash, macKey)
	mac.Write(authSafeBytes)

	var pfx cryptobyte.Builder
	pfx.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3)
		addDataContentInfo(b, authSafeBytes)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(profile.macOid)
					b.AddASN1NULL()
				})
				b.AddASN1OctetString(mac.Sum(nil))
			})
			b.AddASN1OctetString(macSalt)
			b.AddASN1Int64(int64(profile.iterations))
		})
	})
	return pfx.Bytes()
}

func addSafeBag(b *cryptobyte.Builder, bagID asn1.ObjectIdentifier, value, attributes func(*cryptobyte.Builder)) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(bagID)
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), value)
		if attributes != nil {
			b.AddASN1(cbasn1.SET, attributes)
		}
	})
}

func addCertBag(b *cryptobyte.Builder, certificate *x509.Certificate, attributes func(*cryptobyte.Builder)) {
	addSafeBag(b, oidCertBag, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidX509Certificate)
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(certificate.Raw)
			})
		})
	}, attributes)
}

func addAttribute(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, value func(*cryptobyte.Builder)) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(cbasn1.SET, value)
	})
}

func addBMPString(b *cryptobyte.Builder, value string) {
	b.AddASN1(cbasn1.Tag(30), func(b *cryptobyte.Builder) {
		for _, u := range utf16.Encode([]rune(value)) {
			b.AddUint16(u)
		}
	})
}

func addDataContentInfo(b *cryptobyte.Builder, content []byte) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidData)
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(content)
		})
	})
}

func safeContents(bags *cryptobyte.Builder) ([]byte, error) {
	content, err := bags.Bytes()
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(content) })
	return b.Bytes()
}

// encodeJks 는 Java KeyStore 를 만든다. 개인키가 있으면 키 항목 하나, 없으면 신뢰 인증서 항목들로 저장한다.
func encodeJks(bundle *CertBundle, options ExportOptions) ([]byte, error) {
	chain := bundle.FullChain(options.IncludeRoot)
	if !bundle.HasPrivateKey() {
		return encodeTrustedJks(trustedEntries(chain, options.Alias), options.Password)
	}
	store := keystore.New()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(bundle.PrivateKey)
	if err != nil {
		return nil, err
	}
	entry := keystore.PrivateKeyEntry{CreationTime: time.Now(), PrivateKey: pkcs8}
	for _, certificate := range chain {
		entry.CertificateChain = append(entry.CertificateChain,
			keystore.Certificate{Type: "X.509", Content: certificate.Raw})
	}
	if err := store.SetPrivateKeyEntry(options.Alias, entry, []byte(options.Password)); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := store.Store(&out, []byte(options.Password)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// encodeTruststore 는 체인 인증서만 담은 트러스트스토어(JKS)를 만든다.
func encodeTruststore(bundle *CertBundle, options ExportOptions) ([]byte, error) {
	certificates := bundle.Chain
	if len(certificates) == 0 {
		certificates = []*x509.Certificate{bundle.Leaf}
	}
	return encodeTrustedJks(trustedEntries(certificates, ""), options.Password)
}

func encodeTrustedJks(entries []trustedEntry, password string) ([]byte, error) {
	store := keystore.New()
	for _, entry := range entries {
		if err := store.SetTrustedCertificateEntry(entry.alias, keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  keystore.Certificate{Type: "X.509", Content: entry.certificate.Raw},
		}); err != nil {
			return nil, err
		}
	}
	var out bytes.Buffer
	if err := store.Store(&out, []byte(password)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
