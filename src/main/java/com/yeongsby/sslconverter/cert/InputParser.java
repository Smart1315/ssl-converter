package com.yeongsby.sslconverter.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.X509TrustedCertificateBlock;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.stereotype.Component;

/**
 * 어떤 형태로 들어오든 인증서와 개인키를 추출한다.
 * <ul>
 * <li>PEM: 여러 블록 혼합, CRLF, BOM, 64자 줄바꿈 깨짐, {@code -----END ...----------BEGIN ...-----} 처럼 붙은 줄,
 * openssl 출력의 "Bag Attributes" 같은 주변 텍스트</li>
 * <li>PEM 헤더 없는 Base64</li>
 * <li>DER: X.509 인증서, PKCS#7(P7B), PKCS#8/PKCS#1/SEC1 개인키, 암호화된 PKCS#8</li>
 * <li>키스토어: PKCS#12(PFX/P12), JKS, JCEKS</li>
 * <li>위 파일들을 담은 ZIP 압축파일 (폴더, 중첩 ZIP 1단계 포함)</li>
 * </ul>
 */
@Component
public class InputParser {

	static {
		BouncyCastleSupport.register();
	}

	private static final Pattern PEM_BLOCK = Pattern
		.compile("-----BEGIN ([A-Z0-9 ]+?)-----(.*?)-----END \\1-----", Pattern.DOTALL);

	private static final Pattern PEM_BEGIN = Pattern.compile("-----BEGIN [A-Z0-9 ]+?-----");

	private static final Pattern JOINED_BOUNDARY = Pattern.compile("-----END [A-Z0-9 ]+?-----[ \\t]*-----BEGIN");

	private static final Pattern PEM_HEADER = Pattern.compile("^(Proc-Type|DEK-Info):.*$");

	private static final Pattern BASE64_ONLY = Pattern.compile("[A-Za-z0-9+/=\\s]+");

	private static final int MAX_ARCHIVE_DEPTH = 2;

	private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();

	private final JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();

	public ParsedInput parse(List<InputSource> sources, char[] password, String alias) {
		ParsedInput result = new ParsedInput();
		for (InputSource source : sources) {
			parseInput(source, password, alias, result, 0);
		}
		return result;
	}

	/**
	 * @param depth 0 이면 사용자가 직접 올린 파일, 1 이상이면 압축파일 안의 파일. 압축파일 안의 파일에서 난 문제는 오류가 아니라 경고로 남긴다
	 * (CA 압축파일에는 비밀번호를 모르는 PFX 나 안내 문서 등이 함께 들어 있는 경우가 많기 때문).
	 */
	private void parseInput(InputSource source, char[] password, String alias, ParsedInput result, int depth) {
		if (source.data() == null || source.data().length == 0) {
			return;
		}
		if (ArchiveExtractor.isZip(source.data())) {
			parseArchive(source, password, alias, result, depth);
			return;
		}
		boolean inArchive = depth > 0;
		Collector collector = new Collector(result);
		try {
			parseSource(source.data(), password, alias, source.name(), collector);
		}
		catch (UnrecognizedInputException ex) {
			if (inArchive) {
				throw ex;
			}
			result.addError(source.name() + ": " + ex.getMessage());
		}
		catch (ConversionException ex) {
			report(result, inArchive, source.name() + ": " + ex.getMessage());
		}
		catch (Exception ex) {
			report(result, inArchive, source.name() + ": 처리 중 오류가 발생했습니다 - " + ex.getMessage());
		}
		result.addSource(new ParsedInput.SourceSummary(source.name(), String.join(", ", collector.formats),
				collector.certificates, collector.privateKeys, collector.notes));
	}

	private void parseArchive(InputSource archive, char[] password, String alias, ParsedInput result, int depth) {
		List<String> notes = new ArrayList<>();
		result.addSource(new ParsedInput.SourceSummary(archive.name(), "ZIP 압축파일", 0, 0, notes));
		if (depth >= MAX_ARCHIVE_DEPTH) {
			notes.add("압축파일 안의 압축파일이 너무 깊어 건너뛰었습니다");
			return;
		}
		ArchiveExtractor.Extracted extracted;
		try {
			extracted = ArchiveExtractor.extract(archive.data());
		}
		catch (ConversionException ex) {
			report(result, depth > 0, archive.name() + ": " + ex.getMessage());
			return;
		}
		List<String> skipped = new ArrayList<>(extracted.skipped());
		int used = 0;
		for (InputSource entry : extracted.entries()) {
			try {
				parseInput(new InputSource(archive.name() + "/" + entry.name(), entry.data()), password, alias, result,
						depth + 1);
				used++;
			}
			catch (UnrecognizedInputException ex) {
				skipped.add(entry.name());
			}
		}
		notes.add("파일 " + (used + skipped.size()) + "개 중 " + used + "개에서 인증서/키를 찾았습니다");
		if (!skipped.isEmpty()) {
			notes.add("인증서가 아니어서 건너뛴 파일: " + String.join(", ", skipped));
		}
		if (used == 0) {
			report(result, depth > 0, archive.name() + ": 압축파일 안에서 인증서/키 파일을 찾지 못했습니다");
		}
	}

	private static void report(ParsedInput result, boolean warningOnly, String message) {
		if (warningOnly) {
			result.addWarning(message);
		}
		else {
			result.addError(message);
		}
	}

	private void parseSource(byte[] data, char[] password, String alias, String name, Collector collector)
			throws Exception {
		String text = decodeText(data);
		if (text != null && text.contains("-----BEGIN ")) {
			parsePem(text, password, collector);
			return;
		}
		if (text != null) {
			String compact = text.strip();
			if (compact.length() < 64 || !BASE64_ONLY.matcher(compact).matches()) {
				throw new UnrecognizedInputException("인증서/키 데이터를 찾을 수 없습니다 (PEM 헤더 없음, Base64 아님)");
			}
			data = Base64.getMimeDecoder().decode(compact);
			collector.notes.add("PEM 헤더 없는 Base64 데이터를 디코딩했습니다");
		}
		parseBinary(data, password, alias, name, collector);
	}

	// ---------------------------------------------------------------- PEM

	private void parsePem(String text, char[] password, Collector collector) throws Exception {
		collector.formats.add("PEM");
		if (JOINED_BOUNDARY.matcher(text).find()) {
			collector.notes.add("한 줄에 붙어 있던 END/BEGIN 경계를 자동으로 분리했습니다");
		}
		Matcher matcher = PEM_BLOCK.matcher(text);
		int blocks = 0;
		while (matcher.find()) {
			blocks++;
			String type = matcher.group(1).trim();
			String canonical = canonicalPem(type, matcher.group(2));
			Object object;
			try (PEMParser parser = new PEMParser(new StringReader(canonical))) {
				object = parser.readObject();
			}
			catch (IOException ex) {
				throw new ConversionException(blocks + "번째 PEM 블록(" + type + ")을 해석할 수 없습니다: " + ex.getMessage(), ex);
			}
			if (object == null) {
				throw new ConversionException(blocks + "번째 PEM 블록(" + type + ")을 해석할 수 없습니다");
			}
			accept(object, type, password, collector);
		}
		if (blocks == 0) {
			throw new ConversionException("BEGIN/END 짝이 맞는 PEM 블록이 없습니다");
		}
		long begins = PEM_BEGIN.matcher(text).results().count();
		if (begins > blocks) {
			collector.notes.add("END 줄이 없는 PEM 블록 " + (begins - blocks) + "개는 무시했습니다");
		}
	}

	/**
	 * 블록 본문을 정리해 표준 PEM(64자 줄바꿈, LF)으로 재구성한다. 레거시 암호화 키의 Proc-Type/DEK-Info 헤더는 유지한다.
	 */
	static String canonicalPem(String type, String body) {
		StringBuilder headers = new StringBuilder();
		StringBuilder base64 = new StringBuilder();
		for (String line : body.split("\\r?\\n|\\r")) {
			String trimmed = line.trim();
			if (trimmed.isEmpty()) {
				continue;
			}
			if (PEM_HEADER.matcher(trimmed).matches()) {
				headers.append(trimmed).append('\n');
			}
			else {
				base64.append(trimmed.replaceAll("[^A-Za-z0-9+/=]", ""));
			}
		}
		StringBuilder pem = new StringBuilder("-----BEGIN ").append(type).append("-----\n");
		if (!headers.isEmpty()) {
			pem.append(headers).append('\n');
		}
		for (int i = 0; i < base64.length(); i += 64) {
			pem.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
		}
		return pem.append("-----END ").append(type).append("-----\n").toString();
	}

	// ---------------------------------------------------------------- DER / keystore

	private void parseBinary(byte[] data, char[] password, String alias, String name, Collector collector)
			throws Exception {
		if (startsWith(data, 0xFE, 0xED, 0xFE, 0xED)) {
			loadKeyStore("JKS", data, password, alias, name, collector);
			return;
		}
		if (startsWith(data, 0xCE, 0xCE, 0xCE, 0xCE)) {
			loadKeyStore("JCEKS", data, password, alias, name, collector);
			return;
		}
		ASN1Primitive primitive;
		try {
			primitive = ASN1Primitive.fromByteArray(data);
		}
		catch (IOException | RuntimeException ex) {
			throw new UnrecognizedInputException("인식할 수 없는 파일 형식입니다 (PEM/DER/PFX/JKS 아님)");
		}
		if (!(primitive instanceof ASN1Sequence seq) || seq.size() < 2) {
			throw new UnrecognizedInputException("인식할 수 없는 DER 구조입니다");
		}
		Object first = seq.getObjectAt(0);
		Object second = seq.getObjectAt(1);

		if (first instanceof ASN1Integer version && version.hasValue(3) && second instanceof ASN1Sequence) {
			loadKeyStore("PKCS12", data, password, alias, name, collector);
		}
		else if (first instanceof ASN1ObjectIdentifier oid) {
			if (!PKCSObjectIdentifiers.signedData.equals(oid)) {
				throw new ConversionException("지원하지 않는 PKCS#7 타입입니다: " + oid);
			}
			collector.formats.add("PKCS#7(DER)");
			accept(ContentInfo.getInstance(seq), "PKCS7", password, collector);
		}
		else if (seq.size() == 3 && seq.getObjectAt(2) instanceof ASN1BitString) {
			collector.formats.add("DER 인증서");
			accept(new X509CertificateHolder(data), "CERTIFICATE", password, collector);
		}
		else if (first instanceof ASN1Integer && second instanceof ASN1Sequence && seq.size() >= 3
				&& seq.getObjectAt(2) instanceof ASN1OctetString) {
			collector.formats.add("DER 개인키(PKCS#8)");
			accept(PrivateKeyInfo.getInstance(seq), "PRIVATE KEY", password, collector);
		}
		else if (first instanceof ASN1Sequence && second instanceof ASN1OctetString && seq.size() == 2) {
			collector.formats.add("DER 암호화 개인키(PKCS#8)");
			accept(new PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.getInstance(seq)), "ENCRYPTED PRIVATE KEY",
					password, collector);
		}
		else if (first instanceof ASN1Integer && seq.size() == 9) {
			collector.formats.add("DER RSA 개인키(PKCS#1)");
			PrivateKeyInfo info = new PrivateKeyInfo(
					new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
					RSAPrivateKey.getInstance(seq));
			accept(info, "RSA PRIVATE KEY", password, collector);
		}
		else if (first instanceof ASN1Integer version && version.hasValue(1) && second instanceof ASN1OctetString) {
			collector.formats.add("DER EC 개인키(SEC1)");
			ECPrivateKey ecKey = ECPrivateKey.getInstance(seq);
			if (ecKey.getParametersObject() == null) {
				throw new ConversionException("EC 개인키에 곡선(curve) 정보가 없습니다");
			}
			PrivateKeyInfo info = new PrivateKeyInfo(
					new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecKey.getParametersObject()), ecKey);
			accept(info, "EC PRIVATE KEY", password, collector);
		}
		else {
			throw new UnrecognizedInputException("인식할 수 없는 DER 구조입니다");
		}
	}

	private void loadKeyStore(String type, byte[] data, char[] password, String alias, String name,
			Collector collector) throws GeneralSecurityException {
		collector.formats.add("PKCS12".equals(type) ? "PKCS#12(PFX/P12)" : type);
		char[] storePassword = (password != null) ? password : new char[0];
		KeyStore keyStore = KeyStore.getInstance(type);
		try {
			keyStore.load(new ByteArrayInputStream(data), storePassword);
		}
		catch (IOException ex) {
			if (storePassword.length == 0) {
				throw new ConversionException("비밀번호로 보호된 키스토어입니다. '입력 비밀번호'를 입력하세요");
			}
			throw new ConversionException("키스토어 비밀번호가 올바르지 않거나 파일이 손상되었습니다", ex);
		}

		List<String> aliases = Collections.list(keyStore.aliases());
		List<String> keyAliases = new ArrayList<>();
		for (String entryAlias : aliases) {
			boolean isKey = keyStore.isKeyEntry(entryAlias);
			if (isKey) {
				keyAliases.add(entryAlias);
			}
			collector.result.addKeystoreEntry(
					new ParsedInput.KeystoreEntry(name, entryAlias, isKey ? "PrivateKeyEntry" : "trustedCertEntry"));
		}

		String selected = null;
		if (!keyAliases.isEmpty()) {
			selected = (alias != null && keyAliases.contains(alias)) ? alias : keyAliases.get(0);
			if (keyAliases.size() > 1 && (alias == null || !keyAliases.contains(alias))) {
				collector.result.addWarning(name + ": 개인키 항목이 여러 개입니다 " + keyAliases + ". '" + selected
						+ "' 항목을 사용합니다 (별칭 선택에서 변경 가능)");
			}
			collector.result.setSelectedAlias(selected);
			collector.notes.add("별칭 '" + selected + "' 사용");
			Key key;
			try {
				key = keyStore.getKey(selected, storePassword);
			}
			catch (UnrecoverableKeyException ex) {
				throw new ConversionException("키 비밀번호가 키스토어 비밀번호와 다릅니다. 키 비밀번호를 입력해 보세요", ex);
			}
			if (key instanceof PrivateKey privateKey) {
				collector.addPrivateKey(privateKey);
			}
			Certificate[] chain = keyStore.getCertificateChain(selected);
			if (chain != null) {
				for (Certificate certificate : chain) {
					addIfX509(certificate, collector);
				}
			}
		}
		for (String entryAlias : aliases) {
			if (keyStore.isCertificateEntry(entryAlias)) {
				addIfX509(keyStore.getCertificate(entryAlias), collector);
			}
		}
	}

	private void addIfX509(Certificate certificate, Collector collector) {
		if (certificate instanceof X509Certificate x509) {
			collector.addCertificate(x509);
		}
	}

	// ---------------------------------------------------------------- object handling

	private void accept(Object object, String type, char[] password, Collector collector) throws Exception {
		if (object instanceof X509CertificateHolder holder) {
			collector.addCertificate(this.certificateConverter.getCertificate(holder));
		}
		else if (object instanceof X509TrustedCertificateBlock trusted) {
			collector.addCertificate(this.certificateConverter.getCertificate(trusted.getCertificateHolder()));
		}
		else if (object instanceof ContentInfo contentInfo) {
			CMSSignedData signedData = new CMSSignedData(contentInfo);
			for (X509CertificateHolder holder : signedData.getCertificates().getMatches(null)) {
				collector.addCertificate(this.certificateConverter.getCertificate(holder));
			}
		}
		else if (object instanceof PrivateKeyInfo info) {
			collector.addPrivateKey(this.keyConverter.getPrivateKey(info));
		}
		else if (object instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
			requirePassword(password);
			try {
				PrivateKeyInfo info = encrypted.decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder()
					.setProvider(BouncyCastleSupport.PROVIDER)
					.build(password));
				collector.addPrivateKey(this.keyConverter.getPrivateKey(info));
				collector.notes.add("암호화된 개인키를 복호화했습니다");
			}
			catch (PKCSException ex) {
				throw new ConversionException("개인키 비밀번호가 올바르지 않습니다", ex);
			}
		}
		else if (object instanceof PEMKeyPair keyPair) {
			collector.addPrivateKey(this.keyConverter.getPrivateKey(keyPair.getPrivateKeyInfo()));
		}
		else if (object instanceof PEMEncryptedKeyPair encrypted) {
			requirePassword(password);
			PEMKeyPair keyPair;
			try {
				keyPair = encrypted.decryptKeyPair(
						new JcePEMDecryptorProviderBuilder().setProvider(BouncyCastleSupport.PROVIDER).build(password));
			}
			catch (IOException ex) {
				throw new ConversionException("개인키 비밀번호가 올바르지 않습니다", ex);
			}
			collector.addPrivateKey(this.keyConverter.getPrivateKey(keyPair.getPrivateKeyInfo()));
			collector.notes.add("암호화된 개인키를 복호화했습니다");
		}
		else if (object instanceof ASN1ObjectIdentifier) {
			// EC PARAMETERS 블록: EC 개인키 앞에 붙어 오는 경우가 많으며 별도 처리 불필요
		}
		else if (object instanceof PKCS10CertificationRequest) {
			collector.notes.add("CSR(인증서 서명 요청)은 변환 대상이 아니므로 무시했습니다");
		}
		else if (object instanceof SubjectPublicKeyInfo) {
			collector.notes.add("공개키 블록은 무시했습니다");
		}
		else {
			collector.notes.add("지원하지 않는 블록(" + type + ")은 무시했습니다");
		}
	}

	private static void requirePassword(char[] password) {
		if (password == null || password.length == 0) {
			throw new ConversionException("암호화된 개인키입니다. '입력 비밀번호'를 입력하세요");
		}
	}

	// ---------------------------------------------------------------- helpers

	/**
	 * 텍스트 파일이면 문자열로, 바이너리면 null 을 반환한다. UTF-8/UTF-16 BOM 을 처리한다.
	 */
	static String decodeText(byte[] data) {
		if (startsWith(data, 0xEF, 0xBB, 0xBF)) {
			return new String(data, 3, data.length - 3, StandardCharsets.UTF_8);
		}
		if (startsWith(data, 0xFF, 0xFE)) {
			return new String(data, 2, data.length - 2, StandardCharsets.UTF_16LE);
		}
		if (startsWith(data, 0xFE, 0xFF)) {
			return new String(data, 2, data.length - 2, StandardCharsets.UTF_16BE);
		}
		int limit = Math.min(data.length, 8192);
		for (int i = 0; i < limit; i++) {
			int b = data[i] & 0xFF;
			if (b < 0x09 || (b > 0x0D && b < 0x20)) {
				return null;
			}
		}
		return new String(data, StandardCharsets.UTF_8);
	}

	private static boolean startsWith(byte[] data, int... prefix) {
		if (data.length < prefix.length) {
			return false;
		}
		for (int i = 0; i < prefix.length; i++) {
			if ((data[i] & 0xFF) != prefix[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 입력 하나에 대해 찾은 항목을 집계하면서 전체 결과에 반영한다.
	 */
	private static final class Collector {

		final ParsedInput result;

		final Set<String> formats = new LinkedHashSet<>();

		final List<String> notes = new ArrayList<>();

		int certificates;

		int privateKeys;

		Collector(ParsedInput result) {
			this.result = result;
		}

		void addCertificate(X509Certificate certificate) {
			this.certificates++;
			this.result.addCertificate(certificate);
		}

		void addPrivateKey(PrivateKey key) {
			this.privateKeys++;
			this.result.addPrivateKey(key);
		}

	}

}
