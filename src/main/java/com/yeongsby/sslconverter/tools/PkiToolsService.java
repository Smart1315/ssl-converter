package com.yeongsby.sslconverter.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.yeongsby.sslconverter.cert.ConversionException;
import com.yeongsby.sslconverter.cert.InputParser;
import com.yeongsby.sslconverter.cert.InputSource;
import com.yeongsby.sslconverter.cert.ParsedInput;
import com.yeongsby.sslconverter.tools.ToolResult.Artifact;
import com.yeongsby.sslconverter.tools.ToolResult.Row;
import com.yeongsby.sslconverter.tools.ToolResult.Section;
import com.yeongsby.sslconverter.tools.ToolResult.TreeNode;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

@Service
public class PkiToolsService {

	private final InputParser parser;
	private static final int ASN1_NODE_LIMIT = 500;

	public PkiToolsService(InputParser parser) { this.parser = parser; }

	public ToolResult execute(String tool, Map<String, String> fields, Map<String, List<InputSource>> uploads) {
		try {
			return switch (tool) {
				case "csr" -> csr(fields);
				case "self-signed" -> selfSigned(fields);
				case "csr-decode" -> decodeCsr(firstInput(fields, uploads, "text", "files"));
				case "issue" -> issue(fields, uploads);
				case "match" -> match(fields, uploads);
				case "crl" -> crl(firstInput(fields, uploads, "text", "files"), fields, uploads);
				case "ocsp" -> ocsp(firstInput(fields, uploads, "text", "files"), fields, uploads);
				case "asn1" -> asn1(firstInput(fields, uploads, "text", "files"));
				case "compare" -> compare(firstInput(fields, uploads, "text", "files"), firstInput(fields, uploads, "textB", "filesB"));
				case "cms" -> cms(firstInput(fields, uploads, "text", "files"), optionalInput(fields, uploads, "contentText", "contentFiles"));
				case "tls" -> tls(fields);
				default -> throw new ConversionException("알 수 없는 도구입니다: " + tool);
			};
		}
		catch (ConversionException ex) { throw ex; }
		catch (Exception ex) { throw new ConversionException("처리 중 오류가 발생했습니다: " + ex.getMessage(), ex); }
	}

	private ToolResult csr(Map<String, String> fields) throws Exception {
		String keyType = value(fields, "keyType", "RSA").toUpperCase();
		KeyPairGenerator generator;
		if (keyType.equals("EC") || keyType.equals("ECDSA")) {
			generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(256);
			keyType = "EC";
		}
		else {
			if (!keyType.equals("RSA")) throw new ConversionException("키 알고리즘은 RSA 또는 EC여야 합니다.");
			generator = KeyPairGenerator.getInstance("RSA");
			int bits = Integer.parseInt(value(fields, "keyBits", "2048"));
			if (bits < 2048 || bits > 4096 || bits % 256 != 0) throw new ConversionException("RSA 키 길이는 2048~4096비트 범위여야 합니다.");
			generator.initialize(bits);
		}
		KeyPair pair = generator.generateKeyPair();
		String subject = value(fields, "commonName", "").trim();
		if (subject.isEmpty()) throw new ConversionException("공통 이름(CN)을 입력하세요.");
		var name = new javax.security.auth.x500.X500Principal("CN=" + escapeDn(subject));
		JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(name, pair.getPublic());
		List<GeneralName> san = sanNames(fields.get("san"));
		if (!san.isEmpty()) {
			ExtensionsGenerator extensions = new ExtensionsGenerator();
			extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san.toArray(GeneralName[]::new)));
			builder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
		}
		PKCS10CertificationRequest request = builder.build(new JcaContentSignerBuilder(keyType.equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA").build(pair.getPrivate()));
		return new ToolResult(List.of("개인키는 암호화되지 않은 PKCS#8 PEM입니다. 안전한 위치에 저장하세요."),
			List.of(section("CSR", "생성", "키 알고리즘", keyType, "공개키", pair.getPublic().getAlgorithm())),
			List.of(new Artifact("request.csr", pem("CERTIFICATE REQUEST", request.getEncoded())),
				new Artifact("private-key.pem", pem("PRIVATE KEY", pair.getPrivate().getEncoded()))), null);
	}

	private ToolResult selfSigned(Map<String, String> fields) throws Exception {
		String keyType = value(fields, "keyType", "RSA").toUpperCase();
		KeyPairGenerator generator;
		if (keyType.equals("EC") || keyType.equals("ECDSA")) {
			generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(256);
			keyType = "EC";
		}
		else {
			if (!keyType.equals("RSA")) throw new ConversionException("키 알고리즘은 RSA 또는 EC여야 합니다.");
			generator = KeyPairGenerator.getInstance("RSA");
			int bits = Integer.parseInt(value(fields, "keyBits", "2048"));
			if (bits < 2048 || bits > 4096 || bits % 256 != 0) throw new ConversionException("RSA 키 길이는 2048~4096비트 범위여야 합니다.");
			generator.initialize(bits);
		}
		String commonName = value(fields, "commonName", "");
		if (commonName.isBlank()) throw new ConversionException("공통 이름(CN)을 입력하세요.");
		KeyPair pair = generator.generateKeyPair();
		var subject = new javax.security.auth.x500.X500Principal("CN=" + escapeDn(commonName));
		Instant now = Instant.now();
		BigInteger serial = new BigInteger(159, new SecureRandom()).add(BigInteger.ONE);
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial,
			Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(365))), subject, pair.getPublic());
		boolean isCa = "true".equalsIgnoreCase(fields.get("isCa"));
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
		int usage = isCa ? KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature : KeyUsage.digitalSignature;
		if (!isCa && keyType.equals("RSA")) usage |= KeyUsage.keyEncipherment;
		builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
		List<GeneralName> san = sanNames(fields.get("san"));
		if (!san.isEmpty()) builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san.toArray(GeneralName[]::new)));
		if (!isCa) builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(signer(pair.getPrivate())));
		certificate.verify(pair.getPublic());
		return new ToolResult(List.of("자체 서명 인증서입니다. 개인키는 암호화되지 않은 PKCS#8 PEM으로 제공됩니다."),
			List.of(section(isCa ? "사설 CA" : "자체 서명 인증서", "ok", "주체", certificate.getSubjectX500Principal().toString(), "키 알고리즘", keyType, "유효 기간", certificate.getNotAfter().toString())),
			List.of(new Artifact("certificate.pem", pem("CERTIFICATE", certificate.getEncoded())),
				new Artifact("private-key.pem", pem("PRIVATE KEY", pair.getPrivate().getEncoded()))), null);
	}

	private ToolResult decodeCsr(byte[] data) throws Exception {
		PKCS10CertificationRequest csr = parseCsr(data);
		if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo()))) {
			throw new ConversionException("CSR 서명을 확인할 수 없습니다.");
		}
		List<Row> rows = new ArrayList<>();
		rows.add(new Row("주체", csr.getSubject().toString()));
		rows.add(new Row("공개키 알고리즘", csr.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId()));
		var extensions = csr.getRequestedExtensions();
		if (extensions != null && extensions.getExtension(Extension.subjectAlternativeName) != null) {
			rows.add(new Row("SAN", extensions.getExtension(Extension.subjectAlternativeName).getParsedValue().toString()));
		}
		rows.add(new Row("서명", "유효"));
		return new ToolResult(List.of(), List.of(new Section("인증서 서명 요청", "info", rows)), List.of(), null);
	}

	private ToolResult issue(Map<String, String> fields, Map<String, List<InputSource>> uploads) throws Exception {
		PKCS10CertificationRequest csr = parseCsr(firstInput(fields, uploads, "text", "files"));
		if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo()))) throw new ConversionException("CSR 서명이 유효하지 않습니다.");
		ParsedInput ca = parseInputs(uploads.getOrDefault("caFiles", List.of()), fields.get("caText"), fields.get("caPassword"));
		if (ca.certificates().isEmpty() || ca.privateKeys().isEmpty()) throw new ConversionException("CA 인증서와 CA 개인키를 모두 입력하세요.");
		X509Certificate caCert = ca.certificates().get(0);
		PrivateKey caKey = ca.privateKeys().get(0);
		boolean[] caUsage = caCert.getKeyUsage();
		if (caCert.getBasicConstraints() < 0 || caUsage != null && (caUsage.length <= 5 || !caUsage[5])) {
			throw new ConversionException("인증서에 CA 및 keyCertSign 권한이 없습니다.");
		}
		if (!keyMatches(caKey, caCert)) throw new ConversionException("CA 인증서와 개인키가 서로 맞지 않습니다.");
		int days = Integer.parseInt(value(fields, "days", "365"));
		if (days < 1 || days > 825) throw new ConversionException("유효기간은 1~825일 범위여야 합니다.");
		Instant now = Instant.now();
		BigInteger serial = new BigInteger(159, new SecureRandom()).add(BigInteger.ONE);
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(caCert, serial,
			Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(days))), csr.getSubject(),
				new JcaPKCS10CertificationRequest(csr).getPublicKey());
		var requested = csr.getRequestedExtensions();
		if (requested != null && requested.getExtension(Extension.subjectAlternativeName) != null) {
			var san = requested.getExtension(Extension.subjectAlternativeName);
			builder.addExtension(Extension.subjectAlternativeName, san.isCritical(), san.getParsedValue());
		}
		builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		builder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | (csr.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption) ? KeyUsage.keyEncipherment : 0)));
		builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		X509Certificate issued = new JcaX509CertificateConverter().getCertificate(builder.build(signer(caKey)));
		issued.verify(caCert.getPublicKey());
		return new ToolResult(List.of("발급된 인증서는 입력한 CA 개인키로 서명했습니다."),
			List.of(section("발급 결과", "ok", "주체", issued.getSubjectX500Principal().toString(), "발급자", issued.getIssuerX500Principal().toString(), "만료", issued.getNotAfter().toString())),
			List.of(new Artifact("issued-certificate.pem", pem("CERTIFICATE", issued.getEncoded()))), null);
	}

	private ToolResult match(Map<String, String> fields, Map<String, List<InputSource>> uploads) throws Exception {
		ParsedInput parsed = parseInputs(uploads.getOrDefault("files", List.of()), fields.get("text"), fields.get("password"));
		List<Row> rows = new ArrayList<>();
		for (X509Certificate cert : parsed.certificates()) for (PrivateKey key : parsed.privateKeys()) {
			rows.add(new Row("인증서 ↔ 개인키", keyMatches(key, cert) ? "일치" : "불일치"));
		}
		String csrText = fields.get("csrText");
		if (csrText != null && !csrText.isBlank()) {
			PKCS10CertificationRequest csr = parseCsr(csrText.getBytes(StandardCharsets.UTF_8));
			for (X509Certificate cert : parsed.certificates()) rows.add(new Row("인증서 ↔ CSR", MessageDigest.isEqual(cert.getPublicKey().getEncoded(), new JcaPKCS10CertificationRequest(csr).getPublicKey().getEncoded()) ? "일치" : "불일치"));
		}
		if (rows.isEmpty()) throw new ConversionException("비교할 인증서와 개인키 또는 CSR을 입력하세요.");
		return new ToolResult(List.of(), List.of(new Section("짝 확인", "info", rows)), List.of(), null);
	}

	private ToolResult crl(byte[] data, Map<String, String> fields, Map<String, List<InputSource>> uploads) throws Exception {
		X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(normalizeDER(data)));
		List<Row> rows = new ArrayList<>(List.of(new Row("발급자", crl.getIssuerX500Principal().toString()), new Row("발급일", String.valueOf(crl.getThisUpdate())),
			new Row("다음 갱신", String.valueOf(crl.getNextUpdate())), new Row("폐기 인증서 수", Integer.toString(crl.getRevokedCertificates() == null ? 0 : crl.getRevokedCertificates().size()))));
		ParsedInput issuer = parseInputs(uploads.getOrDefault("issuerFiles", List.of()), fields.get("issuerText"), "");
		if (!issuer.certificates().isEmpty()) {
			crl.verify(issuer.certificates().get(0).getPublicKey());
			rows.add(new Row("서명 검증", "유효"));
		}
		if (crl.getRevokedCertificates() != null) {
			int shown = 0;
			for (var revoked : crl.getRevokedCertificates()) {
				if (shown++ >= 100) break;
				rows.add(new Row("폐기 일련번호", revoked.getSerialNumber() + " (" + revoked.getRevocationDate() + ")"));
			}
			if (crl.getRevokedCertificates().size() > 100) rows.add(new Row("목록", "처음 100개 항목만 표시했습니다."));
		}
		return new ToolResult(List.of(), List.of(new Section("인증서 폐기 목록", "info", rows)), List.of(), null);
	}

	private ToolResult ocsp(byte[] data, Map<String, String> fields, Map<String, List<InputSource>> uploads) throws Exception {
		OCSPResp response = new OCSPResp(normalizeDER(data));
		List<Row> rows = new ArrayList<>();
		rows.add(new Row("응답 상태", Integer.toString(response.getStatus())));
		if (response.getResponseObject() instanceof BasicOCSPResp basic) {
			rows.add(new Row("응답자", basic.getResponderId().toString()));
			ParsedInput issuer = parseInputs(uploads.getOrDefault("issuerFiles", List.of()), fields.get("issuerText"), "");
			X509CertificateHolder[] responseCerts = basic.getCerts();
			var signerCert = responseCerts.length > 0 ? responseCerts[0] : null;
			if (signerCert != null || !issuer.certificates().isEmpty()) {
				var verifier = signerCert != null ? signerCert.getSubjectPublicKeyInfo() :
					new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuer.certificates().get(0)).getSubjectPublicKeyInfo();
				rows.add(new Row("응답 서명", basic.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(verifier)) ? "유효" : "무효"));
			}
			else rows.add(new Row("응답 서명", "검증하지 않음 (발급자 인증서 미입력)"));
			for (var single : basic.getResponses()) rows.add(new Row("인증서 " + single.getCertID().getSerialNumber(), single.getCertStatus() == null ? "good" : single.getCertStatus().toString()));
		}
		return new ToolResult(List.of(), List.of(new Section("OCSP 응답", "info", rows)), List.of(), null);
	}

	private ToolResult asn1(byte[] data) throws Exception {
		try (ASN1InputStream input = new ASN1InputStream(normalizeDER(data))) {
			ASN1Primitive root = input.readObject();
			if (root == null || input.readObject() != null) throw new ConversionException("하나의 ASN.1 DER 구조를 입력하세요.");
			int[] count = {0};
			return new ToolResult(List.of(), List.of(), List.of(), tree("ASN.1", root, 0, count));
		}
	}

	private ToolResult compare(byte[] first, byte[] second) throws Exception {
		X509Certificate a = certificate(first), b = certificate(second);
		List<Row> rows = List.of(new Row("주체", comparison(a.getSubjectX500Principal().toString(), b.getSubjectX500Principal().toString())),
			new Row("발급자", comparison(a.getIssuerX500Principal().toString(), b.getIssuerX500Principal().toString())),
			new Row("유효 시작", comparison(a.getNotBefore().toString(), b.getNotBefore().toString())),
			new Row("유효 만료", comparison(a.getNotAfter().toString(), b.getNotAfter().toString())),
			new Row("공개키", comparison(a.getPublicKey().getAlgorithm() + " / " + fingerprint(a.getPublicKey().getEncoded()), b.getPublicKey().getAlgorithm() + " / " + fingerprint(b.getPublicKey().getEncoded()))),
			new Row("SAN", comparison(String.valueOf(a.getSubjectAlternativeNames()), String.valueOf(b.getSubjectAlternativeNames()))));
		return new ToolResult(List.of(), List.of(new Section("인증서 비교", "info", rows)), List.of(), null);
	}

	private ToolResult cms(byte[] signedData, byte[] detachedContent) throws Exception {
		signedData = normalizeDER(signedData);
		CMSSignedData cms = detachedContent.length == 0 ? new CMSSignedData(signedData) : new CMSSignedData(new CMSProcessableByteArray(detachedContent), signedData);
		Store<X509CertificateHolder> certificates = cms.getCertificates();
		List<Row> rows = new ArrayList<>();
		for (SignerInformation signer : cms.getSignerInfos().getSigners()) {
			var matches = certificates.getMatches(signer.getSID());
			boolean valid = false;
			for (Object match : matches) if (match instanceof X509CertificateHolder holder) {
				valid |= signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(holder));
			}
			rows.add(new Row("서명자 " + signer.getSID(), valid ? "유효" : "무효/인증서 없음"));
		}
		if (rows.isEmpty()) throw new ConversionException("CMS 서명자를 찾을 수 없습니다.");
		return new ToolResult(List.of("서명 값만 확인했습니다. 인증서 체인 신뢰성은 별도로 검증해야 합니다."), List.of(new Section("PKCS#7 / CMS", "info", rows)), List.of(), null);
	}

	private ToolResult tls(Map<String, String> fields) throws Exception {
		String host = value(fields, "host", "").trim();
		int port = Integer.parseInt(value(fields, "port", "443"));
		if (host.isEmpty() || host.length() > 253 || host.contains("/") || host.contains("@") || port < 1 || port > 65535) throw new ConversionException("호스트 이름과 1~65535 포트 범위를 확인하세요.");
		InetAddress[] addresses = InetAddress.getAllByName(host);
		if (addresses.length == 0 || Arrays.stream(addresses).anyMatch(a -> !isPublic(a))) throw new ConversionException("공인 IP 주소로 해석되는 호스트만 점검할 수 있습니다.");
		try (Socket raw = new Socket()) {
			raw.connect(new InetSocketAddress(addresses[0], port), 5000);
			raw.setSoTimeout(5000);
			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket ssl = (SSLSocket) factory.createSocket(raw, host, port, true);
			try (ssl) {
				SSLParameters parameters = ssl.getSSLParameters();
				parameters.setEndpointIdentificationAlgorithm("HTTPS");
				ssl.setSSLParameters(parameters);
				ssl.startHandshake();
				List<Row> rows = new ArrayList<>();
				rows.add(new Row("TLS 프로토콜", ssl.getSession().getProtocol()));
				rows.add(new Row("암호군", ssl.getSession().getCipherSuite()));
				for (var cert : ssl.getSession().getPeerCertificates()) if (cert instanceof X509Certificate x509) rows.add(new Row("인증서", x509.getSubjectX500Principal() + " (만료 " + x509.getNotAfter() + ")"));
				return new ToolResult(List.of("원격 서버 연결은 공인 주소로 제한됩니다."), List.of(new Section("TLS 점검", "info", rows)), List.of(), null);
			}
		}
	}

	private ParsedInput parseInputs(List<InputSource> files, String text, String password) {
		List<InputSource> sources = new ArrayList<>(files);
		if (text != null && !text.isBlank()) sources.add(new InputSource("붙여넣은 텍스트", text.getBytes(StandardCharsets.UTF_8)));
		ParsedInput parsed = parser.parse(sources, password == null ? null : password.toCharArray(), null);
		if (!parsed.errors().isEmpty()) throw new ConversionException(String.join("\n", parsed.errors()));
		return parsed;
	}

	private byte[] firstInput(Map<String, String> fields, Map<String, List<InputSource>> uploads, String textKey, String fileKey) {
		List<InputSource> files = uploads.getOrDefault(fileKey, List.of());
		if (!files.isEmpty()) return files.get(0).data();
		String text = fields.get(textKey);
		if (text == null || text.isBlank()) throw new ConversionException("입력 데이터를 제공하세요.");
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private byte[] optionalInput(Map<String, String> fields, Map<String, List<InputSource>> uploads, String textKey, String fileKey) {
		List<InputSource> files = uploads.getOrDefault(fileKey, List.of());
		if (!files.isEmpty()) return files.get(0).data();
		String text = fields.get(textKey);
		return text == null || text.isBlank() ? new byte[0] : text.getBytes(StandardCharsets.UTF_8);
	}

	private static PKCS10CertificationRequest parseCsr(byte[] input) throws Exception {
		input = normalizeDER(input);
		String text = new String(input, StandardCharsets.UTF_8);
		if (text.contains("-----BEGIN")) try (PEMParser parser = new PEMParser(new StringReader(text))) {
			Object object = parser.readObject();
			if (object instanceof PKCS10CertificationRequest csr) return csr;
		}
		return new PKCS10CertificationRequest(input);
	}

	private static X509Certificate certificate(byte[] data) throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(normalizeDER(data)));
	}

	private static byte[] normalizeDER(byte[] input) throws Exception {
		String text = new String(input, StandardCharsets.UTF_8).trim();
		if (text.startsWith("-----BEGIN")) {
			try (PemReader reader = new PemReader(new StringReader(text))) {
				var object = reader.readPemObject();
				if (object == null) throw new ConversionException("PEM 데이터를 읽을 수 없습니다.");
				return object.getContent();
			}
		}
		if (input.length == 0 || input[0] == 0x30) return input;
		try { return Base64.getMimeDecoder().decode(text); }
		catch (IllegalArgumentException ex) { return input; }
	}

	private static boolean keyMatches(PrivateKey key, X509Certificate certificate) throws Exception {
		Signature signature = Signature.getInstance(signatureAlgorithm(key));
		byte[] challenge = new byte[32]; new SecureRandom().nextBytes(challenge);
		signature.initSign(key); signature.update(challenge); byte[] signed = signature.sign();
		signature.initVerify(certificate.getPublicKey()); signature.update(challenge); return signature.verify(signed);
	}

	private static String signatureAlgorithm(PrivateKey key) {
		return switch (key.getAlgorithm().toUpperCase()) { case "RSA" -> "SHA256withRSA"; case "EC", "ECDSA" -> "SHA256withECDSA"; case "ED25519", "EDDSA" -> "Ed25519"; default -> throw new ConversionException("지원하지 않는 서명 키 알고리즘입니다."); };
	}

	private static ContentSigner signer(PrivateKey key) throws Exception { return new JcaContentSignerBuilder(signatureAlgorithm(key)).build(key); }

	private static String pem(String label, byte[] data) throws Exception {
		StringWriter writer = new StringWriter();
		try (JcaPEMWriter pem = new JcaPEMWriter(writer)) { pem.writeObject(new org.bouncycastle.util.io.pem.PemObject(label, data)); }
		return writer.toString();
	}

	private static List<GeneralName> sanNames(String raw) throws Exception {
		List<GeneralName> names = new ArrayList<>();
		if (raw == null || raw.isBlank()) return names;
		for (String entry : raw.split(",")) {
			String value = entry.trim(); if (value.isEmpty()) continue;
			if (value.matches("\\d{1,3}(\\.\\d{1,3}){3}") || value.contains(":")) names.add(new GeneralName(GeneralName.iPAddress, value));
			else names.add(new GeneralName(GeneralName.dNSName, value));
		}
		return names;
	}

	private static String escapeDn(String value) { return value.replace("\\", "\\\\").replace(",", "\\,").replace("+", "\\+"); }

	private static TreeNode tree(String name, ASN1Primitive value, int depth, int[] count) throws Exception {
		if (++count[0] > ASN1_NODE_LIMIT) return new TreeNode("…", "노드 제한 도달", List.of());
		if (depth > 20) return new TreeNode(name, "깊이 제한 도달", List.of());
		List<TreeNode> children = new ArrayList<>();
		if (value instanceof ASN1Sequence sequence) { for (int i = 0; i < sequence.size(); i++) children.add(tree("SEQUENCE[" + i + "]", sequence.getObjectAt(i).toASN1Primitive(), depth + 1, count)); }
		else if (value instanceof ASN1Set set) { for (int i = 0; i < set.size(); i++) children.add(tree("SET[" + i + "]", set.getObjectAt(i).toASN1Primitive(), depth + 1, count)); }
		else if (value instanceof ASN1TaggedObject tagged) children.add(tree("TAGGED", tagged.getBaseObject().toASN1Primitive(), depth + 1, count));
		String display = value.toString();
		if (display.length() > 240) display = display.substring(0, 240) + "…";
		return new TreeNode(value.getClass().getSimpleName(), display, children);
	}

	private static boolean isPublic(InetAddress address) {
		if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isMulticastAddress()) return false;
		byte[] bytes = address.getAddress();
		if (address instanceof Inet6Address && ((bytes[0] & 0xfe) == 0xfc || (bytes[0] == (byte) 0xfe && (bytes[1] & 0xc0) == 0x80))) return false;
		if (bytes.length == 4 && (bytes[0] == 100 && (bytes[1] & 0xc0) == 64 || bytes[0] == 0 || bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0)) return false;
		return true;
	}

	private static String fingerprint(byte[] encoded) throws Exception { return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(encoded)); }
	private static String comparison(String a, String b) { return a.equals(b) ? "같음: " + a : "변경됨\n이전: " + a + "\n현재: " + b; }
	private static String value(Map<String, String> fields, String name, String fallback) { String value = fields.get(name); return value == null || value.isBlank() ? fallback : value.trim(); }
	private static Section section(String title, String level, String... pairs) { List<Row> rows = new ArrayList<>(); for (int i = 0; i + 1 < pairs.length; i += 2) rows.add(new Row(pairs[i], pairs[i + 1])); return new Section(title, level, rows); }
}
