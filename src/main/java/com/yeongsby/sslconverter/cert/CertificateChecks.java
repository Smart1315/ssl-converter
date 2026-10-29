package com.yeongsby.sslconverter.cert;

import java.security.PublicKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.yeongsby.sslconverter.cert.CheckResult.Status;
import org.springframework.stereotype.Component;

/**
 * 인증서 묶음에 대한 점검 항목을 실행한다. 결과는 화면의 점검표로 표시된다.
 */
@Component
public class CertificateChecks {

	private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

	private static final String ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

	private static final int EXPIRY_WARNING_DAYS = 30;

	private final RevocationChecker revocationChecker;

	public CertificateChecks(RevocationChecker revocationChecker) {
		this.revocationChecker = revocationChecker;
	}

	public List<CheckResult> run(CertBundle bundle, boolean privateKeyProvided, boolean checkRevocation) {
		List<CheckResult> results = new ArrayList<>();
		results.add(keyMatch(bundle, privateKeyProvided));
		results.add(chain(bundle));
		results.add(validity(bundle));
		results.add(subjectAltNames(bundle));
		results.add(serverAuthentication(bundle));
		results.add(keyStrength(bundle));
		results.add(signatureAlgorithm(bundle));
		results.add(publicTrust(bundle));
		results.add(checkRevocation ? this.revocationChecker.check(bundle)
				: new CheckResult("REVOCATION", "폐기 여부", Status.SKIPPED,
						"확인하지 않음 ('폐기 여부 온라인 확인'을 켜면 CA 의 OCSP/CRL 서버에 조회합니다)", List.of()));
		return results;
	}

	private CheckResult keyMatch(CertBundle bundle, boolean privateKeyProvided) {
		String title = "개인키 일치";
		if (bundle.hasPrivateKey()) {
			return pass("KEY_MATCH", title, "개인키가 서버 인증서와 쌍이 맞습니다 (" + KeyUtils.describe(bundle.privateKey()) + ")");
		}
		if (privateKeyProvided) {
			return new CheckResult("KEY_MATCH", title, Status.FAIL, "입력한 개인키가 서버 인증서와 맞지 않습니다", List.of());
		}
		return new CheckResult("KEY_MATCH", title, Status.WARN, "개인키가 없습니다 (.key/PFX/JKS 를 만들려면 필요)", List.of());
	}

	private CheckResult chain(CertBundle bundle) {
		String title = "체인 구성";
		if (ChainResolver.isSelfSigned(bundle.leaf())) {
			return new CheckResult("CHAIN", title, Status.WARN, "자체 서명 인증서입니다 (브라우저에서 신뢰되지 않음)", List.of());
		}
		if (bundle.chain().isEmpty()) {
			return new CheckResult("CHAIN", title, Status.FAIL, "중간(체인) 인증서가 없습니다", List.of());
		}
		List<String> details = bundle.chain()
			.stream()
			.map((c) -> CertInspector.commonNameOrDn(c.getSubjectX500Principal()))
			.toList();
		String summary = "서버 → " + String.join(" → ", details)
				+ (bundle.rootIncluded() ? " (루트 포함)" : " (루트 미포함, 정상)");
		return pass("CHAIN", title, summary);
	}

	private CheckResult validity(CertBundle bundle) {
		Instant now = Instant.now();
		Status status = Status.PASS;
		List<String> details = new ArrayList<>();
		for (X509Certificate certificate : bundle.fullChain(true)) {
			String name = CertInspector.commonNameOrDn(certificate.getSubjectX500Principal());
			Instant notAfter = certificate.getNotAfter().toInstant();
			if (notAfter.isBefore(now)) {
				status = Status.FAIL;
				details.add(name + ": 만료됨 (" + CertInspector.format(certificate.getNotAfter()) + ")");
			}
			else if (certificate.getNotBefore().toInstant().isAfter(now)) {
				status = Status.FAIL;
				details.add(name + ": 유효기간 시작 전 (" + CertInspector.format(certificate.getNotBefore()) + ")");
			}
			else if (Duration.between(now, notAfter).toDays() < EXPIRY_WARNING_DAYS) {
				status = worst(status, Status.WARN);
				details.add(name + ": " + Duration.between(now, notAfter).toDays() + "일 후 만료");
			}
		}
		long leafDays = Duration.between(now, bundle.leaf().getNotAfter().toInstant()).toDays();
		String summary = switch (status) {
			case PASS -> "모든 인증서가 유효합니다 (서버 인증서 " + leafDays + "일 남음)";
			case WARN -> "곧 만료되는 인증서가 있습니다";
			default -> "만료되었거나 아직 유효하지 않은 인증서가 있습니다";
		};
		return new CheckResult("VALIDITY", "유효기간", status, summary, details);
	}

	private CheckResult subjectAltNames(CertBundle bundle) {
		List<String> names = CertInspector.subjectAltNames(bundle.leaf());
		if (names.isEmpty()) {
			return new CheckResult("SAN", "도메인(SAN)", Status.FAIL,
					"SAN(주체 대체 이름)이 없습니다. Chrome 등 최신 브라우저는 CN 만으로는 도메인을 인정하지 않습니다", List.of());
		}
		return pass("SAN", "도메인(SAN)", String.join(", ", names));
	}

	private CheckResult serverAuthentication(CertBundle bundle) {
		X509Certificate leaf = bundle.leaf();
		String title = "서버 인증 용도";
		Status status = Status.PASS;
		List<String> details = new ArrayList<>();
		try {
			List<String> extendedKeyUsage = leaf.getExtendedKeyUsage();
			if (extendedKeyUsage == null) {
				details.add("확장 키 용도(EKU) 없음: 모든 용도 허용");
			}
			else if (!extendedKeyUsage.contains(SERVER_AUTH) && !extendedKeyUsage.contains(ANY_EXTENDED_KEY_USAGE)) {
				status = Status.FAIL;
				details.add("확장 키 용도에 TLS 서버 인증(serverAuth)이 없습니다. 클라이언트/코드서명용 인증서가 아닌지 확인하세요");
			}
			else {
				details.add("확장 키 용도: TLS 서버 인증 포함");
			}
		}
		catch (CertificateParsingException ex) {
			status = Status.WARN;
			details.add("확장 키 용도를 해석할 수 없습니다");
		}
		boolean[] keyUsage = leaf.getKeyUsage();
		if (keyUsage != null) {
			boolean digitalSignature = keyUsage.length > 0 && keyUsage[0];
			boolean keyEncipherment = keyUsage.length > 2 && keyUsage[2];
			boolean keyAgreement = keyUsage.length > 4 && keyUsage[4];
			boolean usable = (leaf.getPublicKey() instanceof RSAKey) ? (digitalSignature || keyEncipherment)
					: (digitalSignature || keyAgreement);
			if (!usable) {
				status = Status.FAIL;
				details.add("키 용도(KeyUsage)에 digitalSignature/keyEncipherment 가 없어 TLS 에 쓸 수 없습니다");
			}
		}
		if (leaf.getBasicConstraints() >= 0) {
			status = worst(status, Status.WARN);
			details.add("서버 인증서가 CA 인증서로 발급되었습니다");
		}
		String summary = (status == Status.PASS) ? "TLS 서버 인증서로 사용할 수 있습니다"
				: "TLS 서버 인증서로 쓰기에 문제가 있습니다";
		return new CheckResult("SERVER_AUTH", title, status, summary, details);
	}

	private CheckResult keyStrength(CertBundle bundle) {
		Status status = Status.PASS;
		List<String> details = new ArrayList<>();
		for (X509Certificate certificate : withoutRoot(bundle)) {
			String name = CertInspector.commonNameOrDn(certificate.getSubjectX500Principal());
			PublicKey key = certificate.getPublicKey();
			String description = KeyUtils.describe(key);
			if (key instanceof RSAKey rsa && rsa.getModulus().bitLength() < 2048) {
				status = Status.FAIL;
				details.add(name + ": " + description + " — 2048비트 미만은 브라우저에서 거부됩니다");
			}
			else if (key instanceof ECKey ec && ec.getParams().getCurve().getField().getFieldSize() < 256) {
				status = Status.FAIL;
				details.add(name + ": " + description + " — 256비트 미만 곡선은 안전하지 않습니다");
			}
			else if (key instanceof DSAKey) {
				status = worst(status, Status.WARN);
				details.add(name + ": DSA 키는 최신 TLS 에서 지원되지 않습니다");
			}
			else {
				details.add(name + ": " + description);
			}
		}
		return new CheckResult("KEY_STRENGTH", "키 길이", status,
				(status == Status.PASS) ? "충분한 키 길이입니다" : "약한 키가 있습니다", details);
	}

	private CheckResult signatureAlgorithm(CertBundle bundle) {
		Status status = Status.PASS;
		List<String> details = new ArrayList<>();
		for (X509Certificate certificate : withoutRoot(bundle)) {
			String name = CertInspector.commonNameOrDn(certificate.getSubjectX500Principal());
			String algorithm = certificate.getSigAlgName();
			String upper = algorithm.toUpperCase(Locale.ROOT);
			if (upper.contains("MD2") || upper.contains("MD5") || upper.startsWith("SHA1")) {
				status = Status.FAIL;
				details.add(name + ": " + algorithm + " — 취약한 서명으로 브라우저에서 거부됩니다");
			}
			else {
				details.add(name + ": " + algorithm);
			}
		}
		return new CheckResult("SIGNATURE", "서명 알고리즘", status,
				(status == Status.PASS) ? "안전한 서명 알고리즘입니다" : "취약한 서명 알고리즘(SHA-1/MD5)이 있습니다 (루트 제외)", details);
	}

	/**
	 * 브라우저처럼 경로를 찾는다. 서버가 보낸 체인 끝이 교차 서명 인증서여서 그 발급자(오래된 루트)가 신뢰 저장소에 없더라도, 체인을 줄였을 때 신뢰된
	 * 루트에 닿으면 신뢰된 것으로 본다.
	 */
	private CheckResult publicTrust(CertBundle bundle) {
		String title = "공인 루트 신뢰";
		List<X509Certificate> path = withoutRoot(bundle);
		CertPathValidatorException firstFailure = null;
		try {
			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			PKIXParameters parameters = new PKIXParameters(TrustStore.anchors());
			parameters.setRevocationEnabled(false);
			for (int length = path.size(); length >= 1; length--) {
				try {
					PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator
						.validate(factory.generateCertPath(path.subList(0, length)), parameters);
					X509Certificate root = result.getTrustAnchor().getTrustedCert();
					String rootName = (root != null) ? CertInspector.commonNameOrDn(root.getSubjectX500Principal())
							: result.getTrustAnchor().getCAName();
					return pass("PUBLIC_TRUST", title, "공인 루트 '" + rootName + "'까지 신뢰 체인이 확인되었습니다");
				}
				catch (CertPathValidatorException ex) {
					if (firstFailure == null) {
						firstFailure = ex;
					}
				}
			}
		}
		catch (Exception ex) {
			return new CheckResult("PUBLIC_TRUST", title, Status.WARN, "신뢰 체인을 검증할 수 없습니다: " + ex.getMessage(),
					List.of());
		}
		List<String> details = new ArrayList<>();
		details.add("검증 실패 사유: " + ((firstFailure != null) ? firstFailure.getMessage() : "알 수 없음"));
		details.add("기준: Java 기본 신뢰 저장소(cacerts). 사내/사설 CA 인증서라면 정상입니다");
		String summary = bundle.chain().isEmpty() && !ChainResolver.isSelfSigned(bundle.leaf())
				? "공인 루트까지 연결되지 않습니다 (중간 인증서 누락)"
				: "공인 루트까지 연결되지 않습니다 (사설 CA 이거나 체인 오류)";
		return new CheckResult("PUBLIC_TRUST", title, Status.WARN, summary, details);
	}

	/**
	 * 서버 인증서 + 중간 인증서. 루트(자체 서명)는 신뢰 기준이므로 강도/서명 점검과 경로 검증에서 제외한다.
	 */
	private static List<X509Certificate> withoutRoot(CertBundle bundle) {
		List<X509Certificate> result = new ArrayList<>();
		result.add(bundle.leaf());
		bundle.chain().stream().filter((c) -> !ChainResolver.isSelfSigned(c)).forEach(result::add);
		return result;
	}

	private static CheckResult pass(String id, String title, String summary) {
		return new CheckResult(id, title, Status.PASS, summary, List.of());
	}

	static Status worst(Status a, Status b) {
		return (a.ordinal() >= b.ordinal()) ? a : b;
	}

}
