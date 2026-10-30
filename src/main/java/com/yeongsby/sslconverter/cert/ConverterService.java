package com.yeongsby.sslconverter.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.yeongsby.sslconverter.cert.CertInspector.CertDetails;
import com.yeongsby.sslconverter.cert.Exporter.ExportResult;
import com.yeongsby.sslconverter.cert.Exporter.ExportedFile;
import org.springframework.stereotype.Service;

/**
 * 분석(입력 해석 + 체인 정리)과 변환(파일 생성)을 묶는다. 서버에는 아무것도 저장하지 않는다.
 */
@Service
public class ConverterService {

	static final String NO_KEY_WARNING = "개인키가 입력되지 않았습니다. 서버에 설치할 .key/PFX/JKS 를 만들려면 개인키 파일을 추가하거나 "
			+ "-----BEGIN PRIVATE KEY----- 블록을 함께 붙여넣으세요. (개인키 없이 만든 PFX/JKS 에는 인증서만 들어갑니다)";

	static final String NON_ASCII_PASSWORD = "출력 비밀번호에는 영문, 숫자, 기호(ASCII)만 사용할 수 있습니다. "
			+ "한글 등이 들어간 비밀번호로 만든 PFX 는 Java(keytool, Tomcat 등)에서 열 수 없습니다.";

	private final InputParser parser;

	private final ChainResolver resolver;

	private final Exporter exporter;

	private final CertificateChecks checks;

	public ConverterService(InputParser parser, ChainResolver resolver, Exporter exporter, CertificateChecks checks) {
		this.parser = parser;
		this.resolver = resolver;
		this.exporter = exporter;
		this.checks = checks;
	}

	public Analysis analyze(List<InputSource> sources, char[] password, String alias) {
		return analyze(sources, password, alias, false);
	}

	/**
	 * @param checkRevocation true 면 CA 의 OCSP/CRL 서버에 접속해 폐기 여부를 확인한다
	 */
	public Analysis analyze(List<InputSource> sources, char[] password, String alias, boolean checkRevocation) {
		ParsedInput input = this.parser.parse(sources, password, alias);
		CertBundle bundle = this.resolver.resolve(input);
		List<String> errors = new ArrayList<>(input.errors());
		if (bundle == null && errors.isEmpty()) {
			errors.add(input.sources().isEmpty() ? "인증서 파일을 올리거나 PEM 텍스트를 붙여넣으세요."
					: "입력에서 인증서를 찾지 못했습니다. 서버 인증서(.crt/.pem/.cer) 또는 PFX/JKS 를 함께 올리세요.");
		}
		List<String> warnings = new ArrayList<>(input.warnings());
		List<String> notices = new ArrayList<>();
		BundleView view = null;
		List<CheckResult> checkResults = List.of();
		if (bundle != null) {
			warnings.addAll(bundle.warnings());
			notices.addAll(bundle.notices());
			if (input.privateKeys().isEmpty()) {
				warnings.add(NO_KEY_WARNING);
			}
			view = toView(bundle);
			checkResults = this.checks.run(bundle, !input.privateKeys().isEmpty(), checkRevocation);
		}
		return new Analysis(input.sources(), input.keystoreEntries(), input.selectedAlias(), view, checkResults,
				warnings, notices, errors, (bundle != null) ? suggestedBaseName(bundle.leaf()) : null,
				(bundle != null) ? suggestedAlias(bundle.leaf()) : null);
	}

	public ConvertedOutput convert(List<InputSource> sources, char[] password, String alias, ExportOptions options) {
		ParsedInput input = this.parser.parse(sources, password, alias);
		if (!input.errors().isEmpty()) {
			throw new ConversionException(String.join("\n", input.errors()));
		}
		CertBundle bundle = this.resolver.resolve(input);
		if (bundle == null) {
			throw new ConversionException("입력에서 인증서를 찾지 못했습니다.");
		}
		ExportOptions resolved = withDefaults(options, bundle);
		ExportResult result = this.exporter.export(bundle, resolved);
		if (result.files().isEmpty()) {
			throw new ConversionException(result.skipped().isEmpty() ? "생성할 형식을 하나 이상 선택하세요."
					: String.join("\n", result.skipped()));
		}
		if (result.files().size() == 1 && result.skipped().isEmpty()) {
			return new ConvertedOutput(result.files().get(0));
		}
		return new ConvertedOutput(new ExportedFile(resolved.baseName() + ".zip", "application/zip",
				zip(result, bundle, resolved)));
	}

	private ExportOptions withDefaults(ExportOptions options, CertBundle bundle) {
		if (options.formats() == null || options.formats().isEmpty()) {
			throw new ConversionException("생성할 형식을 하나 이상 선택하세요.");
		}
		String baseName = sanitizeFileName(options.baseName());
		if (baseName.isEmpty()) {
			baseName = suggestedBaseName(bundle.leaf());
		}
		String alias = (options.alias() == null || options.alias().isBlank()) ? suggestedAlias(bundle.leaf())
				: options.alias().trim();
		char[] password = (options.password() != null) ? options.password() : new char[0];
		// PKCS8_ENCRYPTED 는 이전 API 호환용: PKCS8 + 암호화로 바꾼다
		ExportOptions.KeyFormat keyFormat = (options.keyFormat() != null) ? options.keyFormat()
				: ExportOptions.KeyFormat.PKCS8;
		boolean encryptKey = options.encryptKey() || keyFormat == ExportOptions.KeyFormat.PKCS8_ENCRYPTED;
		if (keyFormat == ExportOptions.KeyFormat.PKCS8_ENCRYPTED) {
			keyFormat = ExportOptions.KeyFormat.PKCS8;
		}
		boolean needsPassword = options.formats().stream().anyMatch(OutputFormat::requiresPassword)
				|| (encryptKey && (options.formats().contains(OutputFormat.KEY_PEM)
						|| options.formats().contains(OutputFormat.COMBINED_PEM)));
		// 공백만 입력한 비밀번호는 화면에서 빈 칸처럼 보이므로 입력하지 않은 것으로 본다 (앞뒤 공백은 그대로 사용)
		if (needsPassword && new String(password).isBlank()) {
			throw new ConversionException("PFX/JKS/암호화 키를 만들려면 '출력 비밀번호'를 입력하세요.");
		}
		// JDK(keytool, Tomcat, Spring Boot)의 PKCS12 는 ASCII 가 아닌 비밀번호를 거부하므로, 열 수 없는 파일이 만들어지지 않게 막는다
		if (needsPassword && !isPrintableAscii(password)) {
			throw new ConversionException(NON_ASCII_PASSWORD);
		}
		return new ExportOptions(options.formats(), baseName, alias, password, options.includeRoot(),
				options.legacyPfx(), keyFormat, encryptKey);
	}

	private static boolean isPrintableAscii(char[] password) {
		for (char c : password) {
			if (c < 0x20 || c > 0x7E) {
				return false;
			}
		}
		return true;
	}

	private byte[] zip(ExportResult result, CertBundle bundle, ExportOptions options) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(out, StandardCharsets.UTF_8)) {
			for (ExportedFile file : result.files()) {
				zip.putNextEntry(new ZipEntry(file.fileName()));
				zip.write(file.data());
				zip.closeEntry();
			}
			zip.putNextEntry(new ZipEntry("README.txt"));
			zip.write(summary(result, bundle, options).getBytes(StandardCharsets.UTF_8));
			zip.closeEntry();
		}
		catch (IOException ex) {
			throw new ConversionException("ZIP 생성 실패: " + ex.getMessage(), ex);
		}
		return out.toByteArray();
	}

	private String summary(ExportResult result, CertBundle bundle, ExportOptions options) {
		StringBuilder text = new StringBuilder();
		text.append("SSL 인증서 변환 결과\r\n====================\r\n\r\n");
		text.append("별칭(alias): ").append(options.alias()).append("\r\n");
		text.append("루트 인증서 포함: ").append(options.includeRoot() ? "예" : "아니오").append("\r\n");
		text.append("PFX 암호화: ").append(options.legacyPfx() ? "레거시(3DES/SHA1)" : "기본(AES-256/SHA-256)").append("\r\n");
		text.append("개인키 파일 암호화: ").append(options.encryptKey() ? "예 (출력 비밀번호)" : "아니오").append("\r\n");
		text.append("※ 비밀번호는 이 파일에 기록하지 않습니다.\r\n");
		if (!bundle.hasPrivateKey()) {
			text.append("※ 개인키 없음: PFX/JKS 에는 인증서만 들어 있어 서버 인증서로 사용할 수 없습니다.\r\n");
		}
		text.append("\r\n");
		text.append("[생성된 파일]\r\n");
		for (ExportedFile file : result.files()) {
			text.append(" - ").append(file.fileName()).append(" (").append(file.data().length).append(" bytes)\r\n");
		}
		if (!result.skipped().isEmpty()) {
			text.append("\r\n[생성하지 않은 항목]\r\n");
			result.skipped().forEach((s) -> text.append(" - ").append(s).append("\r\n"));
		}
		text.append("\r\n[인증서 체인]\r\n");
		BundleView view = toView(bundle);
		int index = 1;
		for (CertDetails details : view.certificates()) {
			text.append("\r\n#").append(index++).append(" ").append(details.role()).append("\r\n");
			text.append("  소유자    : ").append(details.subject()).append("\r\n");
			text.append("  발급자    : ").append(details.issuer()).append("\r\n");
			if (!details.subjectAltNames().isEmpty()) {
				text.append("  SAN       : ").append(String.join(", ", details.subjectAltNames())).append("\r\n");
			}
			text.append("  유효기간  : ").append(details.notBefore()).append(" ~ ").append(details.notAfter()).append("\r\n");
			text.append("  일련번호  : ").append(details.serialNumber()).append("\r\n");
			text.append("  공개키    : ").append(details.publicKey()).append("\r\n");
			text.append("  서명알고리즘: ").append(details.signatureAlgorithm()).append("\r\n");
			text.append("  SHA-256   : ").append(details.sha256()).append("\r\n");
		}
		text.append("\r\n[확인 명령]\r\n");
		text.append(" keytool -list -v -keystore ").append(OutputFormat.JKS.fileName(options.baseName())).append("\r\n");
		text.append(" keytool -list -v -storetype PKCS12 -keystore ").append(OutputFormat.PFX.fileName(options.baseName()))
			.append("\r\n");
		text.append(" openssl x509 -in ").append(OutputFormat.CERT_PEM.fileName(options.baseName()))
			.append(" -noout -text\r\n");
		return text.toString();
	}

	private BundleView toView(CertBundle bundle) {
		List<CertDetails> certificates = new ArrayList<>();
		certificates.add(CertInspector.describe(bundle.leaf(),
				ChainResolver.isSelfSigned(bundle.leaf()) ? "서버 인증서 (자체 서명)" : "서버 인증서"));
		for (X509Certificate certificate : bundle.chain()) {
			certificates.add(CertInspector.describe(certificate,
					ChainResolver.isSelfSigned(certificate) ? "루트 CA" : "중간 CA"));
		}
		List<CertDetails> unrelated = bundle.unrelated()
			.stream()
			.map((certificate) -> CertInspector.describe(certificate, "체인 외 인증서"))
			.toList();
		KeyView key = bundle.hasPrivateKey() ? new KeyView(KeyUtils.describe(bundle.privateKey()), true) : null;
		return new BundleView(certificates, unrelated, key, bundle.rootIncluded());
	}

	static String suggestedBaseName(X509Certificate leaf) {
		String name = primaryName(leaf);
		boolean wildcard = name.startsWith("*.");
		String base = sanitizeFileName((wildcard ? name.substring(2) : name).replace('.', '_'));
		if (base.isEmpty()) {
			base = "certificate";
		}
		return wildcard ? "wildcard_" + base : base;
	}

	static String suggestedAlias(X509Certificate leaf) {
		String name = primaryName(leaf);
		name = name.startsWith("*.") ? name.substring(2) : name;
		return name.isBlank() ? "certificate" : name;
	}

	private static String primaryName(X509Certificate leaf) {
		String cn = CertInspector.commonName(leaf.getSubjectX500Principal());
		if (cn != null && !cn.isBlank()) {
			return cn.trim();
		}
		List<String> sans = CertInspector.subjectAltNames(leaf);
		return sans.isEmpty() ? "" : sans.get(0);
	}

	private static String sanitizeFileName(String name) {
		if (name == null) {
			return "";
		}
		return name.trim().replaceAll("[^\\p{L}\\p{N}._-]+", "_").replaceAll("^[._]+", "");
	}

	/**
	 * 분석 결과 (웹 화면 표시용).
	 */
	public record Analysis(List<ParsedInput.SourceSummary> sources, List<ParsedInput.KeystoreEntry> keystoreEntries,
			String selectedAlias, BundleView bundle, List<CheckResult> checks, List<String> warnings,
			List<String> notices, List<String> errors, String suggestedBaseName, String suggestedAlias) {
	}

	/**
	 * 정렬된 체인 정보. certificates 는 서버 인증서부터 루트 방향 순서.
	 */
	public record BundleView(List<CertDetails> certificates, List<CertDetails> unrelated, KeyView privateKey,
			boolean rootIncluded) {
	}

	/**
	 * 개인키 정보.
	 */
	public record KeyView(String description, boolean matchesCertificate) {
	}

	/**
	 * 다운로드할 결과 파일 (단일 파일 또는 ZIP).
	 */
	public record ConvertedOutput(ExportedFile file) {
	}

}
