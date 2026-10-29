package com.yeongsby.sslconverter.cert;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.yeongsby.sslconverter.cert.ConverterService.Analysis;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ArchiveInputTests {

	private static TestCertificates certs;

	private final ConverterService service = new ConverterService(new InputParser(), new ChainResolver(),
			new Exporter(), new CertificateChecks(new RevocationChecker(false)));

	@BeforeAll
	static void createCertificates() throws Exception {
		certs = TestCertificates.rsa();
	}

	@Test
	void typicalCaArchiveIsRecognized() throws Exception {
		// CA 가 보내주는 형태: 서버별 폴더, 비밀번호를 모르는 PFX, 안내 문서, macOS 메타데이터
		Map<String, byte[]> files = new LinkedHashMap<>();
		files.put("example_com/Apache/example_com.crt", bytes(TestCertificates.pem(certs.leaf)));
		files.put("example_com/Apache/chain.crt", bytes(TestCertificates.pem(certs.intermediate)));
		files.put("example_com/Apache/root.crt", bytes(TestCertificates.pem(certs.root)));
		files.put("example_com/example_com.key", bytes(TestCertificates.pem(certs.leafKey.getPrivate())));
		files.put("example_com/IIS/example_com.pfx", pfx("pfx-password"));
		files.put("example_com/설치 안내.txt", bytes("PFX 비밀번호는 메일을 참고하세요."));
		files.put("example_com/manual.pdf", new byte[] { '%', 'P', 'D', 'F' });
		files.put("__MACOSX/example_com/._example_com.crt", new byte[] { 0, 5, 22, 7 });

		Analysis analysis = this.service.analyze(List.of(new InputSource("example_com.zip", zip(files,
				StandardCharsets.UTF_8))), null, null);

		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.bundle().certificates()).extracting("commonName")
			.containsExactly("example.com", "Test Intermediate CA", "Test Root CA");
		assertThat(analysis.bundle().privateKey()).isNotNull();
		assertThat(analysis.warnings()).anyMatch((w) -> w.contains("example_com.pfx") && w.contains("비밀번호"));
		assertThat(analysis.sources().get(0).notes()).anyMatch((n) -> n.contains("설치 안내.txt"))
			.anyMatch((n) -> n.contains("manual.pdf"))
			.noneMatch((n) -> n.contains("__MACOSX"));

		// 압축파일 안의 경고가 있어도 변환은 가능해야 한다
		byte[] converted = this.service
			.convert(List.of(new InputSource("example_com.zip", zip(files, StandardCharsets.UTF_8))), null, null,
					new ExportOptions(EnumSet.of(OutputFormat.JKS), null, null, "changeit".toCharArray(), true, false,
							ExportOptions.KeyFormat.PKCS8))
			.file()
			.data();
		assertThat(converted).isNotEmpty();
	}

	@Test
	void pfxInsideArchiveIsReadWithPassword() throws Exception {
		Analysis analysis = this.service.analyze(
				List.of(new InputSource("cert.zip", zip(Map.of("iis/site.pfx", pfx("pfx-password")),
						StandardCharsets.UTF_8))),
				"pfx-password".toCharArray(), null);
		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.warnings()).isEmpty();
		assertThat(analysis.bundle().certificates()).hasSize(3);
		assertThat(analysis.bundle().privateKey()).isNotNull();
	}

	@Test
	void koreanWindowsFileNamesAreDecoded() throws Exception {
		// 한국어 Windows 압축 프로그램은 파일명을 CP949 로 저장한다
		byte[] archive = zip(Map.of("인증서/서버인증서.crt", bytes(TestCertificates.pem(certs.leaf, certs.intermediate))),
				Charset.forName("MS949"));
		Analysis analysis = this.service.analyze(List.of(new InputSource("인증서.zip", archive)), null, null);
		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.sources()).extracting("name").contains("인증서.zip/인증서/서버인증서.crt");
	}

	@Test
	void nestedArchiveIsRecognized() throws Exception {
		byte[] inner = zip(Map.of("ssl.pem",
				bytes(TestCertificates.pem(new JcaPKCS8Generator(certs.leafKey.getPrivate(), null), certs.leaf))),
				StandardCharsets.UTF_8);
		byte[] outer = zip(Map.of("download/inner.zip", inner), StandardCharsets.UTF_8);
		Analysis analysis = this.service.analyze(List.of(new InputSource("outer.zip", outer)), null, null);
		assertThat(analysis.errors()).isEmpty();
		assertThat(analysis.bundle().privateKey()).isNotNull();
	}

	@Test
	void archiveWithoutCertificatesIsAnError() throws Exception {
		byte[] archive = zip(Map.of("readme.txt", bytes("hello")), StandardCharsets.UTF_8);
		Analysis analysis = this.service.analyze(List.of(new InputSource("empty.zip", archive)), null, null);
		assertThat(analysis.errors()).anyMatch((e) -> e.contains("찾지 못했습니다"));
		assertThat(analysis.bundle()).isNull();
	}

	private static byte[] pfx(String password) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);
		keyStore.setKeyEntry("site", certs.leafKey.getPrivate(), password.toCharArray(),
				new Certificate[] { certs.leaf, certs.intermediate, certs.root });
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		keyStore.store(out, password.toCharArray());
		return out.toByteArray();
	}

	private static byte[] zip(Map<String, byte[]> files, Charset charset) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(out, charset)) {
			for (Map.Entry<String, byte[]> file : files.entrySet()) {
				zip.putNextEntry(new ZipEntry(file.getKey()));
				zip.write(file.getValue());
				zip.closeEntry();
			}
		}
		return out.toByteArray();
	}

	private static byte[] bytes(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

}
