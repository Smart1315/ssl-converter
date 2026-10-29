package com.yeongsby.sslconverter.cert;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.yeongsby.sslconverter.cert.ConverterService.Analysis;
import com.yeongsby.sslconverter.cert.Exporter.ExportedFile;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConverterServiceTests {

	private static final char[] PASSWORD = "changeit".toCharArray();

	private static TestCertificates rsa;

	private final ConverterService service = new ConverterService(new InputParser(), new ChainResolver(),
			new Exporter());

	@BeforeAll
	static void createCertificates() throws Exception {
		rsa = TestCertificates.rsa();
	}

	@Test
	void joinedPemBoundariesAndShuffledChainAreFixed() throws Exception {
		// 가이드의 문제 상황: -----END CERTIFICATE----------BEGIN CERTIFICATE----- 가 한 줄, 순서도 뒤섞임, CRLF
		String joined = (TestCertificates.pem(rsa.root) + TestCertificates.pem(rsa.leaf)
				+ TestCertificates.pem(rsa.intermediate))
			.replace("-----END CERTIFICATE-----\r\n", "-----END CERTIFICATE-----")
			.replace("-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----")
			.replace("\n", "\r\n");
		assertThat(joined).contains("-----END CERTIFICATE----------BEGIN CERTIFICATE-----");

		Analysis analysis = this.service.analyze(
				List.of(source("all.pem", joined), source("ssl.key", TestCertificates.pem(rsa.leafKey.getPrivate()))),
				null, null);

		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.bundle().certificates()).extracting("commonName")
			.containsExactly("example.com", "Test Intermediate CA", "Test Root CA");
		assertThat(analysis.bundle().privateKey()).isNotNull();
		assertThat(analysis.bundle().rootIncluded()).isTrue();
		assertThat(analysis.suggestedBaseName()).isEqualTo("example_com");
		assertThat(analysis.suggestedAlias()).isEqualTo("example.com");
		assertThat(analysis.sources().get(0).notes()).anyMatch((note) -> note.contains("END/BEGIN"));
	}

	@Test
	void guideWorkflowProducesValidPfxAndJks() throws Exception {
		// ssl.crt + chain_ssl.crt + chain_all_ssl.crt + ssl.key → pfx → jks
		List<InputSource> sources = List.of(source("ssl.crt", TestCertificates.pem(rsa.leaf)),
				source("chain_ssl.crt", TestCertificates.pem(rsa.intermediate)),
				source("chain_all_ssl.crt", TestCertificates.pem(rsa.root)),
				source("ssl.key", TestCertificates.pem(rsa.leafKey.getPrivate())));

		for (boolean legacy : new boolean[] { false, true }) {
			byte[] pfx = convert(sources, options(EnumSet.of(OutputFormat.PFX), legacy)).data();
			assertKeyStore("PKCS12", pfx, "example.com", 3);
		}
		byte[] jks = convert(sources, options(EnumSet.of(OutputFormat.JKS), false)).data();
		assertKeyStore("JKS", jks, "example.com", 3);
	}

	@Test
	void keystoreCanBeConvertedBackToPem() throws Exception {
		byte[] pfx = convert(List.of(source("a.pem", TestCertificates.pem(rsa.leaf, rsa.intermediate)),
				source("a.key", TestCertificates.pem(rsa.leafKey.getPrivate()))),
				options(EnumSet.of(OutputFormat.PFX), false))
			.data();

		List<InputSource> fromPfx = List.of(new InputSource("in.pfx", pfx));
		ExportedFile zip = convert(fromPfx,
				options(EnumSet.of(OutputFormat.FULLCHAIN_PEM, OutputFormat.KEY_PEM, OutputFormat.P7B), false));
		assertThat(zip.fileName()).isEqualTo("example_com.zip");

		try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zip.data()))) {
			ZipEntry entry;
			while ((entry = in.getNextEntry()) != null) {
				byte[] data = in.readAllBytes();
				switch (entry.getName()) {
					case "example_com_fullchain.pem" -> {
						String pem = new String(data, StandardCharsets.US_ASCII);
						assertThat(pem).doesNotContain("----------").doesNotContain("\r");
						assertThat(CertificateFactory.getInstance("X.509")
							.generateCertificates(new ByteArrayInputStream(data))).hasSize(2);
					}
					case "example_com.key" -> assertThat(new String(data, StandardCharsets.US_ASCII))
						.startsWith("-----BEGIN PRIVATE KEY-----");
					case "example_com.p7b" -> assertThat(CertificateFactory.getInstance("X.509")
						.generateCertificates(new ByteArrayInputStream(data))).hasSize(2);
					case "README.txt" -> assertThat(new String(data, StandardCharsets.UTF_8)).contains("example.com");
					default -> throw new AssertionError("unexpected entry " + entry.getName());
				}
			}
		}
	}

	@Test
	void wrongKeystorePasswordIsReported() throws Exception {
		byte[] pfx = convert(List.of(source("a.pem", TestCertificates.pem(rsa.leaf, rsa.leafKey.getPrivate()))),
				options(EnumSet.of(OutputFormat.PFX), false))
			.data();
		Analysis analysis = this.service.analyze(List.of(new InputSource("in.pfx", pfx)), "wrong".toCharArray(), null);
		assertThat(analysis.errors()).singleElement().asString().contains("비밀번호");
		Analysis noPassword = this.service.analyze(List.of(new InputSource("in.pfx", pfx)), null, null);
		assertThat(noPassword.errors()).singleElement().asString().contains("입력 비밀번호");
	}

	@Test
	void derAndHeaderlessInputsAreDetected() throws Exception {
		PrivateKeyInfo info = PrivateKeyInfo.getInstance(rsa.leafKey.getPrivate().getEncoded());
		byte[] pkcs1 = info.parsePrivateKey().toASN1Primitive().getEncoded();
		String headerlessIntermediate = java.util.Base64.getMimeEncoder().encodeToString(rsa.intermediate.getEncoded());

		Analysis analysis = this.service.analyze(List.of(new InputSource("ssl.cer", rsa.leaf.getEncoded()),
				new InputSource("ssl.der.key", pkcs1), source("chain.txt", headerlessIntermediate)), null, null);

		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.bundle().certificates()).hasSize(2);
		assertThat(analysis.bundle().privateKey()).isNotNull();
		assertThat(analysis.bundle().rootIncluded()).isFalse();
		assertThat(analysis.warnings()).doesNotContain(ConverterService.NO_KEY_WARNING);
		assertThat(analysis.notices()).anyMatch((n) -> n.contains("Test Root CA"));
	}

	@Test
	void encryptedAndTraditionalKeysRoundTrip() throws Exception {
		List<InputSource> sources = List.of(source("ssl.crt", TestCertificates.pem(rsa.leaf)),
				source("ssl.key", TestCertificates.pem(rsa.leafKey.getPrivate())));
		ExportOptions encrypted = new ExportOptions(EnumSet.of(OutputFormat.KEY_PEM), null, null, PASSWORD, true,
				false, ExportOptions.KeyFormat.PKCS8_ENCRYPTED);
		String encryptedKey = new String(convert(sources, encrypted).data(), StandardCharsets.US_ASCII);
		assertThat(encryptedKey).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----");

		List<InputSource> reloaded = List.of(source("ssl.crt", TestCertificates.pem(rsa.leaf)),
				source("enc.key", encryptedKey));
		assertThat(this.service.analyze(reloaded, PASSWORD, null).bundle().privateKey()).isNotNull();
		assertThat(this.service.analyze(reloaded, "bad".toCharArray(), null).errors()).isNotEmpty();

		ExportOptions traditional = new ExportOptions(EnumSet.of(OutputFormat.KEY_PEM), null, null, null, true, false,
				ExportOptions.KeyFormat.TRADITIONAL);
		assertThat(new String(convert(sources, traditional).data(), StandardCharsets.US_ASCII))
			.startsWith("-----BEGIN RSA PRIVATE KEY-----");
	}

	@Test
	void ecKeyAndWildcardCertificate() throws Exception {
		TestCertificates ec = TestCertificates.ec();
		List<InputSource> sources = List.of(
				source("bundle.pem", TestCertificates.pem(new JcaPKCS8Generator(ec.leafKey.getPrivate(), null),
						ec.intermediate, ec.leaf)));
		Analysis analysis = this.service.analyze(sources, null, null);
		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.bundle().privateKey().description()).contains("EC").contains("256");
		assertThat(analysis.suggestedBaseName()).isEqualTo("wildcard_example_com");
		assertThat(analysis.suggestedAlias()).isEqualTo("example.com");

		byte[] pfx = convert(sources, options(EnumSet.of(OutputFormat.PFX), true)).data();
		assertKeyStore("PKCS12", pfx, "example.com", 2);

		// 전통 형식 EC 키는 곡선 정보를 포함해야 다시 읽을 수 있다
		ExportOptions traditional = new ExportOptions(EnumSet.of(OutputFormat.KEY_PEM), null, null, null, true, false,
				ExportOptions.KeyFormat.TRADITIONAL);
		String ecKey = new String(convert(sources, traditional).data(), StandardCharsets.US_ASCII);
		assertThat(ecKey).startsWith("-----BEGIN EC PRIVATE KEY-----");
		Analysis reloaded = this.service.analyze(List.of(source("ec.key", ecKey), source("ec.crt",
				TestCertificates.pem(ec.leaf))), null, null);
		assertThat(reloaded.errors()).isEmpty();
		assertThat(reloaded.bundle().privateKey()).isNotNull();
	}

	@Test
	void mismatchedKeyIsWarnedAndKeyOutputsAreSkipped() throws Exception {
		TestCertificates other = TestCertificates.rsa();
		List<InputSource> sources = List.of(source("ssl.crt", TestCertificates.pem(rsa.leaf, rsa.intermediate)),
				source("other.key", TestCertificates.pem(other.leafKey.getPrivate())));
		Analysis analysis = this.service.analyze(sources, null, null);
		assertThat(analysis.bundle().privateKey()).isNull();
		assertThat(analysis.warnings()).anyMatch((w) -> w.contains("일치하는 인증서가 없습니다"));
		assertThatThrownBy(() -> convert(sources, options(EnumSet.of(OutputFormat.KEY_PEM), false)))
			.isInstanceOf(ConversionException.class)
			.hasMessageContaining("개인키");
	}

	@Test
	void missingPrivateKeyIsWarned() throws Exception {
		Analysis analysis = this.service.analyze(
				List.of(source("paste", TestCertificates.pem(rsa.leaf, rsa.intermediate))), null, null);
		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.bundle().privateKey()).isNull();
		assertThat(analysis.warnings()).contains(ConverterService.NO_KEY_WARNING);
	}

	@Test
	void keystoreOutputRequiresPassword() {
		List<InputSource> sources = List.of(source("ssl.crt", "x"));
		ExportOptions noPassword = new ExportOptions(EnumSet.of(OutputFormat.JKS), null, null, null, true, false,
				ExportOptions.KeyFormat.PKCS8);
		assertThatThrownBy(() -> this.service.convert(sources, null, null, noPassword))
			.isInstanceOf(ConversionException.class);
	}

	private ExportedFile convert(List<InputSource> sources, ExportOptions options) {
		return this.service.convert(sources, PASSWORD, null, options).file();
	}

	private static ExportOptions options(Set<OutputFormat> formats, boolean legacyPfx) {
		return new ExportOptions(formats, null, null, PASSWORD, true, legacyPfx, ExportOptions.KeyFormat.PKCS8);
	}

	private static InputSource source(String name, String text) {
		return new InputSource(name, text.getBytes(StandardCharsets.UTF_8));
	}

	private static void assertKeyStore(String type, byte[] data, String alias, int chainLength) throws Exception {
		KeyStore keyStore = KeyStore.getInstance(type);
		keyStore.load(new ByteArrayInputStream(data), PASSWORD);
		assertThat(keyStore.isKeyEntry(alias)).isTrue();
		assertThat(keyStore.getKey(alias, PASSWORD)).isInstanceOf(PrivateKey.class);
		Certificate[] chain = keyStore.getCertificateChain(alias);
		assertThat(chain).hasSize(chainLength);
	}

}
