package com.yeongsby.sslconverter.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CRLReason;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.yeongsby.sslconverter.cert.CheckResult.Status;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 인증서 폐기 여부를 CA 의 OCSP 응답기(우선) 또는 CRL 로 확인한다. 사용자가 요청한 경우에만 외부 네트워크에 접속한다.
 * <p>
 * 접속 주소는 업로드된 인증서 안에 들어 있으므로, 조작된 인증서로 내부망을 조회하는 것(SSRF)을 막기 위해 http/https 만 허용하고 기본적으로
 * 사설·루프백 주소에는 접속하지 않는다.
 */
@Component
public class RevocationChecker {

	private static final String TITLE = "폐기 여부";

	private static final int MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

	private static final String OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

	private final boolean allowPrivateAddresses;

	private final HttpClient httpClient = HttpClient.newBuilder()
		.connectTimeout(Duration.ofSeconds(5))
		.followRedirects(HttpClient.Redirect.NEVER)
		.build();

	public RevocationChecker(
			@Value("${ssl-converter.revocation.allow-private-addresses:false}") boolean allowPrivateAddresses) {
		this.allowPrivateAddresses = allowPrivateAddresses;
	}

	public CheckResult check(CertBundle bundle) {
		List<X509Certificate> path = bundle.fullChain(true);
		Status status = Status.PASS;
		List<String> details = new ArrayList<>();
		for (int i = 0; i < path.size(); i++) {
			X509Certificate certificate = path.get(i);
			// 루트(자체 서명 또는 교차 서명된 신뢰 루트)는 폐기 확인 대상이 아니다
			if (ChainResolver.isSelfSigned(certificate) || (i > 0 && TrustStore.isTrustedRoot(certificate))) {
				break;
			}
			String name = CertInspector.commonNameOrDn(certificate.getSubjectX500Principal());
			X509Certificate issuer = (i + 1 < path.size()) ? path.get(i + 1) : TrustStore.findIssuer(certificate);
			if (issuer == null) {
				status = CertificateChecks.worst(status, Status.WARN);
				details.add(name + ": 발급자 인증서가 없어 확인할 수 없습니다");
				continue;
			}
			Outcome outcome = checkOne(certificate, issuer);
			details.add(name + ": " + outcome.message());
			status = CertificateChecks.worst(status, outcome.status());
		}
		String summary = switch (status) {
			case PASS -> "폐기되지 않았습니다 (OCSP/CRL 확인)";
			case FAIL -> "폐기된 인증서가 있습니다. CA 에서 재발급 받아야 합니다";
			default -> "일부 인증서의 폐기 여부를 확인하지 못했습니다";
		};
		return new CheckResult("REVOCATION", TITLE, status, summary, details);
	}

	private Outcome checkOne(X509Certificate certificate, X509Certificate issuer) {
		List<String> problems = new ArrayList<>();
		for (String url : CertInspector.ocspUrls(certificate)) {
			try {
				return ocsp(url, certificate, issuer);
			}
			catch (Exception ex) {
				problems.add("OCSP " + url + " 실패 (" + ex.getMessage() + ")");
			}
		}
		for (String url : CertInspector.crlUrls(certificate)) {
			try {
				return crl(url, certificate, issuer);
			}
			catch (Exception ex) {
				problems.add("CRL " + url + " 실패 (" + ex.getMessage() + ")");
			}
		}
		if (problems.isEmpty()) {
			return new Outcome(Status.WARN, "인증서에 OCSP/CRL 주소가 없어 확인할 수 없습니다");
		}
		return new Outcome(Status.WARN, "확인 실패 - " + String.join("; ", problems));
	}

	private Outcome ocsp(String url, X509Certificate certificate, X509Certificate issuer) throws Exception {
		CertificateID id = new CertificateID(
				new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(issuer), certificate.getSerialNumber());
		OCSPReq request = new OCSPReqBuilder().addRequest(id).build();
		byte[] body = send(HttpRequest.newBuilder(safeUri(url))
			.timeout(Duration.ofSeconds(10))
			.header("Content-Type", "application/ocsp-request")
			.header("Accept", "application/ocsp-response")
			.POST(HttpRequest.BodyPublishers.ofByteArray(request.getEncoded()))
			.build());

		OCSPResp response = new OCSPResp(body);
		if (response.getStatus() != OCSPResp.SUCCESSFUL) {
			throw new IOException("응답 상태 " + response.getStatus());
		}
		BasicOCSPResp basic = (BasicOCSPResp) response.getResponseObject();
		if (!signedByIssuer(basic, issuer)) {
			throw new IOException("응답 서명을 검증할 수 없음");
		}
		for (SingleResp single : basic.getResponses()) {
			if (!single.getCertID().equals(id)) {
				continue;
			}
			Object status = single.getCertStatus();
			if (status == CertificateStatus.GOOD) {
				return new Outcome(Status.PASS, "정상 (OCSP)");
			}
			if (status instanceof RevokedStatus revoked) {
				return new Outcome(Status.FAIL, "폐기됨 (" + CertInspector.format(revoked.getRevocationTime()) + ", OCSP)");
			}
			return new Outcome(Status.WARN, "OCSP 응답기가 이 인증서를 알지 못합니다 (unknown)");
		}
		throw new IOException("응답에 이 인증서의 상태가 없음");
	}

	private boolean signedByIssuer(BasicOCSPResp basic, X509Certificate issuer) throws Exception {
		JcaContentVerifierProviderBuilder verifiers = new JcaContentVerifierProviderBuilder();
		if (basic.isSignatureValid(verifiers.build(issuer.getPublicKey()))) {
			return true;
		}
		// 발급자가 위임한 OCSP 서명 전용 인증서로 서명한 경우
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		for (X509CertificateHolder holder : basic.getCerts()) {
			X509Certificate responder = converter.getCertificate(holder);
			List<String> usage = responder.getExtendedKeyUsage();
			if (ChainResolver.issuedBy(responder, issuer) && usage != null && usage.contains(OCSP_SIGNING)
					&& basic.isSignatureValid(verifiers.build(responder.getPublicKey()))) {
				return true;
			}
		}
		return false;
	}

	private Outcome crl(String url, X509Certificate certificate, X509Certificate issuer) throws Exception {
		byte[] body = send(HttpRequest.newBuilder(safeUri(url)).timeout(Duration.ofSeconds(15)).GET().build());
		X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(body));
		crl.verify(issuer.getPublicKey());
		X509CRLEntry entry = crl.getRevokedCertificate(certificate);
		if (entry != null) {
			CRLReason reason = entry.getRevocationReason();
			return new Outcome(Status.FAIL, "폐기됨 (" + CertInspector.format(entry.getRevocationDate())
					+ ((reason != null) ? ", " + reason : "") + ", CRL)");
		}
		if (crl.getNextUpdate() != null && crl.getNextUpdate().toInstant().isBefore(Instant.now())) {
			return new Outcome(Status.WARN, "CRL 목록에는 없으나 CRL 이 오래되었습니다 (다음 갱신 "
					+ CertInspector.format(crl.getNextUpdate()) + ")");
		}
		return new Outcome(Status.PASS, "정상 (CRL)");
	}

	private byte[] send(HttpRequest request) throws IOException, InterruptedException {
		HttpResponse<InputStream> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
		try (InputStream in = response.body()) {
			if (response.statusCode() != 200) {
				throw new IOException("HTTP " + response.statusCode());
			}
			byte[] body = in.readNBytes(MAX_RESPONSE_BYTES + 1);
			if (body.length > MAX_RESPONSE_BYTES) {
				throw new IOException("응답이 너무 큼");
			}
			return body;
		}
	}

	/**
	 * http/https 만 허용하고, 허용 설정이 없으면 사설·루프백·링크로컬 주소로 접속하지 않는다.
	 */
	URI safeUri(String url) throws IOException {
		URI uri = URI.create(url.trim());
		String scheme = (uri.getScheme() != null) ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
		if (!scheme.equals("http") && !scheme.equals("https")) {
			throw new IOException("지원하지 않는 주소 형식");
		}
		if (uri.getHost() == null) {
			throw new IOException("호스트 없음");
		}
		if (!this.allowPrivateAddresses) {
			for (InetAddress address : InetAddress.getAllByName(uri.getHost())) {
				if (isInternal(address)) {
					throw new IOException("내부망 주소(" + address.getHostAddress() + ")라 접속하지 않음");
				}
			}
		}
		return uri;
	}

	private static boolean isInternal(InetAddress address) {
		if (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isLinkLocalAddress()
				|| address.isAnyLocalAddress() || address.isMulticastAddress()) {
			return true;
		}
		// IPv6 고유 로컬 주소 fc00::/7
		return address instanceof Inet6Address && (address.getAddress()[0] & 0xFE) == 0xFC;
	}

	private record Outcome(Status status, String message) {
	}

}
