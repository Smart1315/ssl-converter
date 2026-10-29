package com.yeongsby.sslconverter.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.springframework.stereotype.Component;

/**
 * 정리된 인증서 묶음을 요청된 형식의 파일로 만든다. 모든 처리는 메모리에서만 이루어진다.
 */
@Component
public class Exporter {

	static {
		BouncyCastleSupport.register();
	}

	public ExportResult export(CertBundle bundle, ExportOptions options) {
		List<ExportedFile> files = new ArrayList<>();
		List<String> skipped = new ArrayList<>();
		for (OutputFormat format : OutputFormat.values()) {
			if (!options.formats().contains(format)) {
				continue;
			}
			if (format.requiresKey() && !bundle.hasPrivateKey()) {
				skipped.add(format.fileName(options.baseName()) + ": 인증서와 일치하는 개인키가 없어 생성하지 않았습니다");
				continue;
			}
			if (format == OutputFormat.CHAIN_PEM && bundle.chain(options.includeRoot()).isEmpty()) {
				skipped.add(format.fileName(options.baseName()) + ": 체인(중간) 인증서가 없어 생성하지 않았습니다");
				continue;
			}
			if (format == OutputFormat.TRUSTSTORE_JKS && bundle.chain().isEmpty() && !bundle.rootIncluded()) {
				skipped.add(format.fileName(options.baseName()) + ": 체인(CA) 인증서가 없어 생성하지 않았습니다");
				continue;
			}
			try {
				files.add(new ExportedFile(format.fileName(options.baseName()), format.contentType(),
						create(format, bundle, options)));
			}
			catch (GeneralSecurityException | IOException | OperatorCreationException | PKCSException ex) {
				throw new ConversionException(format.fileName(options.baseName()) + " 생성 실패: " + ex.getMessage(), ex);
			}
		}
		return new ExportResult(files, skipped);
	}

	private byte[] create(OutputFormat format, CertBundle bundle, ExportOptions options)
			throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException {
		boolean includeRoot = options.includeRoot();
		return switch (format) {
			case FULLCHAIN_PEM -> pem(bundle.fullChain(includeRoot));
			case CERT_PEM -> pem(List.of(bundle.leaf()));
			case CHAIN_PEM -> pem(bundle.chain(includeRoot));
			case KEY_PEM -> privateKeyPem(bundle, options);
			case COMBINED_PEM -> concat(privateKeyPem(bundle, options), pem(bundle.fullChain(includeRoot)));
			case PFX -> options.legacyPfx() ? legacyPkcs12(bundle, options) : keyStore("PKCS12", bundle, options);
			case JKS -> keyStore("JKS", bundle, options);
			case TRUSTSTORE_JKS -> trustStore(bundle, options);
			case P7B -> CertificateFactory.getInstance("X.509")
				.generateCertPath(bundle.fullChain(includeRoot))
				.getEncoded("PKCS7");
			case DER -> bundle.leaf().getEncoded();
		};
	}

	// ---------------------------------------------------------------- PEM

	/**
	 * 각 블록을 64자 줄바꿈과 독립된 BEGIN/END 줄로 기록한다 (END/BEGIN 이 한 줄에 붙는 문제 방지).
	 */
	static byte[] pem(List<?> objects) throws IOException {
		StringWriter writer = new StringWriter();
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
			for (Object object : objects) {
				if (object instanceof PemObjectGenerator generator) {
					pemWriter.writeObject(generator);
				}
				else {
					pemWriter.writeObject(object);
				}
			}
		}
		return writer.toString().replace("\r\n", "\n").getBytes(StandardCharsets.US_ASCII);
	}

	private byte[] privateKeyPem(CertBundle bundle, ExportOptions options)
			throws IOException, OperatorCreationException {
		return switch (options.keyFormat()) {
			case PKCS8 -> pem(List.of(new JcaPKCS8Generator(bundle.privateKey(), null)));
			case TRADITIONAL -> pem(List.of(traditional(bundle.privateKey())));
			case PKCS8_ENCRYPTED -> {
				OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
					.setProvider(BouncyCastleSupport.PROVIDER)
					.setPRF(PKCS8Generator.PRF_HMACSHA256)
					.setIterationCount(100_000)
					.setPassword(options.password())
					.build();
				yield pem(List.of(new JcaPKCS8Generator(bundle.privateKey(), encryptor)));
			}
		};
	}

	/**
	 * 전통(OpenSSL) 형식 키. EC 키는 JDK 의 PKCS#8 내부 구조에 곡선 정보가 없으므로 SEC1 구조에 곡선 OID 를 넣어 직접 만든다.
	 */
	private static Object traditional(PrivateKey key) throws IOException {
		if (!(key instanceof ECPrivateKey ecKey)) {
			return key;
		}
		PrivateKeyInfo info = PrivateKeyInfo.getInstance(key.getEncoded());
		org.bouncycastle.asn1.sec.ECPrivateKey inner = org.bouncycastle.asn1.sec.ECPrivateKey
			.getInstance(info.parsePrivateKey());
		ASN1BitString publicKey = inner.getPublicKey();
		org.bouncycastle.asn1.sec.ECPrivateKey sec1 = new org.bouncycastle.asn1.sec.ECPrivateKey(
				ecKey.getParams().getOrder().bitLength(), inner.getKey(),
				(publicKey != null) ? new DERBitString(publicKey.getBytes()) : null,
				info.getPrivateKeyAlgorithm().getParameters());
		return new PemObject("EC PRIVATE KEY", sec1.getEncoded(ASN1Encoding.DER));
	}

	// ---------------------------------------------------------------- keystores

	private byte[] keyStore(String type, CertBundle bundle, ExportOptions options)
			throws GeneralSecurityException, IOException {
		KeyStore keyStore = KeyStore.getInstance(type);
		keyStore.load(null, null);
		List<X509Certificate> chain = bundle.fullChain(options.includeRoot());
		if (bundle.hasPrivateKey()) {
			keyStore.setKeyEntry(options.alias(), bundle.privateKey(), options.password(),
					chain.toArray(new Certificate[0]));
		}
		else {
			addTrustedEntries(keyStore, chain, options.alias());
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		keyStore.store(out, options.password());
		return out.toByteArray();
	}

	private byte[] trustStore(CertBundle bundle, ExportOptions options) throws GeneralSecurityException, IOException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		List<X509Certificate> chain = bundle.chain().isEmpty() ? List.of(bundle.leaf()) : bundle.chain();
		addTrustedEntries(keyStore, chain, null);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		keyStore.store(out, options.password());
		return out.toByteArray();
	}

	private void addTrustedEntries(KeyStore keyStore, List<X509Certificate> certificates, String firstAlias)
			throws GeneralSecurityException {
		Set<String> used = new HashSet<>();
		for (X509Certificate certificate : certificates) {
			String base = (firstAlias != null && used.isEmpty()) ? firstAlias
					: aliasFor(CertInspector.commonNameOrDn(certificate.getSubjectX500Principal()));
			String alias = base;
			for (int i = 2; used.contains(alias); i++) {
				alias = base + "-" + i;
			}
			used.add(alias);
			keyStore.setCertificateEntry(alias, certificate);
		}
	}

	private static String aliasFor(String name) {
		String alias = name.toLowerCase().replaceAll("[^a-z0-9.\\-_]+", "-").replaceAll("^-+|-+$", "");
		return alias.isEmpty() ? "ca" : alias;
	}

	/**
	 * Windows Server 2016 이하 / 구형 Java 와 호환되는 PFX (키·인증서 모두 PBE-SHA1-3DES, MAC SHA-1). OpenSSL 3 에서도 legacy
	 * 옵션 없이 읽힌다.
	 */
	private byte[] legacyPkcs12(CertBundle bundle, ExportOptions options)
			throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException {
		char[] password = options.password();
		OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(
				PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
			.setProvider(BouncyCastleSupport.PROVIDER)
			.setIterationCount(2048)
			.build(password);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		SubjectKeyIdentifier localKeyId = extensionUtils.createSubjectKeyIdentifier(bundle.leaf().getPublicKey());
		DERBMPString friendlyName = new DERBMPString(options.alias());

		List<X509Certificate> chain = bundle.fullChain(options.includeRoot());
		PKCS12SafeBag[] certificateBags = new PKCS12SafeBag[chain.size()];
		for (int i = 0; i < chain.size(); i++) {
			PKCS12SafeBagBuilder builder = new JcaPKCS12SafeBagBuilder(chain.get(i));
			if (i == 0) {
				builder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, friendlyName);
				if (bundle.hasPrivateKey()) {
					builder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, localKeyId);
				}
			}
			certificateBags[i] = builder.build();
		}

		PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();
		pfxBuilder.addEncryptedData(encryptor, certificateBags);
		if (bundle.hasPrivateKey()) {
			PKCS12SafeBagBuilder keyBag = new JcaPKCS12SafeBagBuilder(bundle.privateKey(), encryptor);
			keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, friendlyName);
			keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, localKeyId);
			pfxBuilder.addData(keyBag.build());
		}
		return pfxBuilder.build(new BcPKCS12MacCalculatorBuilder().setIterationCount(2048), password)
			.getEncoded(ASN1Encoding.DER);
	}

	private static byte[] concat(byte[] first, byte[] second) {
		byte[] result = new byte[first.length + second.length];
		System.arraycopy(first, 0, result, 0, first.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	/**
	 * 생성된 파일 하나.
	 */
	public record ExportedFile(String fileName, String contentType, byte[] data) {
	}

	/**
	 * 생성 결과와 건너뛴 항목.
	 */
	public record ExportResult(List<ExportedFile> files, List<String> skipped) {
	}

}
