package com.yeongsby.sslconverter.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.yeongsby.sslconverter.cert.CheckResult.Status;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 로컬 HTTP 서버로 CA 의 OCSP 응답기와 CRL 배포 지점을 흉내 내어 폐기 확인을 검증한다.
 */
class RevocationCheckerTests {

	private static final Set<BigInteger> revoked = ConcurrentHashMap.newKeySet();

	private static HttpServer server;

	private static TestCertificates ca;

	private static KeyPair intermediateKey;

	private static X509Certificate intermediate;

	private static KeyPair leafKey;

	private static X509Certificate leaf;

	@BeforeAll
	static void startCa() throws Exception {
		ca = TestCertificates.rsa();
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		String base = "http://127.0.0.1:" + server.getAddress().getPort();

		// 중간 인증서: 루트가 발행하는 CRL 로 확인
		intermediateKey = TestCertificates.rsaKey(2048);
		intermediate = TestCertificates.issue("CN=Revocation Test CA", intermediateKey.getPublic(), ca.root,
				ca.rootKey, "SHA256withRSA", (builder) -> {
					builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
					builder.addExtension(Extension.cRLDistributionPoints, false,
							new CRLDistPoint(new DistributionPoint[] { new DistributionPoint(
									new DistributionPointName(new GeneralNames(
											new GeneralName(GeneralName.uniformResourceIdentifier, base + "/root.crl"))),
									null, null) }));
				});
		// 서버 인증서: 중간 CA 의 OCSP 응답기로 확인
		leafKey = TestCertificates.rsaKey(2048);
		leaf = TestCertificates.issue("CN=revocation.example.com", leafKey.getPublic(), intermediate, intermediateKey,
				"SHA256withRSA", (builder) -> builder.addExtension(Extension.authorityInfoAccess, false,
						new AuthorityInformationAccess(AccessDescription.id_ad_ocsp,
								new GeneralName(GeneralName.uniformResourceIdentifier, base + "/ocsp"))));

		server.createContext("/ocsp", RevocationCheckerTests::ocsp);
		server.createContext("/root.crl", RevocationCheckerTests::crl);
		server.start();
	}

	@AfterAll
	static void stopCa() {
		server.stop(0);
	}

	@BeforeEach
	void reset() {
		revoked.clear();
	}

	@Test
	void goodCertificatesPass() {
		CheckResult result = new RevocationChecker(true).check(bundle());
		assertThat(result.status()).as(result.details().toString()).isEqualTo(Status.PASS);
		assertThat(result.details()).anyMatch((d) -> d.contains("OCSP")).anyMatch((d) -> d.contains("CRL"));
	}

	@Test
	void leafRevokedViaOcsp() {
		revoked.add(leaf.getSerialNumber());
		CheckResult result = new RevocationChecker(true).check(bundle());
		assertThat(result.status()).isEqualTo(Status.FAIL);
		assertThat(result.details()).anyMatch((d) -> d.startsWith("revocation.example.com: 폐기됨"));
	}

	@Test
	void intermediateRevokedViaCrl() {
		revoked.add(intermediate.getSerialNumber());
		CheckResult result = new RevocationChecker(true).check(bundle());
		assertThat(result.status()).isEqualTo(Status.FAIL);
		assertThat(result.details()).anyMatch((d) -> d.startsWith("Revocation Test CA: 폐기됨") && d.contains("CRL"));
	}

	@Test
	void internalAddressesAreNotContactedByDefault() {
		CheckResult result = new RevocationChecker(false).check(bundle());
		assertThat(result.status()).isEqualTo(Status.WARN);
		assertThat(result.details()).allMatch((d) -> d.contains("내부망 주소"));
	}

	@Test
	void unsupportedSchemesAreRejected() {
		RevocationChecker checker = new RevocationChecker(true);
		assertThatThrownBy(() -> checker.safeUri("file:///etc/passwd"))
			.isInstanceOf(IOException.class);
		assertThatThrownBy(() -> checker.safeUri("ldap://ca.example.com/crl"))
			.isInstanceOf(IOException.class);
	}

	private static CertBundle bundle() {
		return new CertBundle(leaf, List.of(intermediate, ca.root), leafKey.getPrivate(), List.of(), List.of(),
				List.of());
	}

	private static void ocsp(HttpExchange exchange) throws IOException {
		try {
			OCSPReq request = new OCSPReq(exchange.getRequestBody().readAllBytes());
			CertificateID id = request.getRequestList()[0].getCertID();
			CertificateStatus status = revoked.contains(id.getSerialNumber())
					? new RevokedStatus(new Date(), CRLReason.keyCompromise) : CertificateStatus.GOOD;
			JcaBasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(intermediate.getPublicKey(),
					new JcaDigestCalculatorProviderBuilder().build().get(RespID.HASH_SHA1));
			builder.addResponse(id, status);
			BasicOCSPResp basic = builder.build(
					new JcaContentSignerBuilder("SHA256withRSA").build(intermediateKey.getPrivate()),
					new X509CertificateHolder[0], new Date());
			respond(exchange, new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded());
		}
		catch (Exception ex) {
			exchange.sendResponseHeaders(500, -1);
			exchange.close();
		}
	}

	private static void crl(HttpExchange exchange) throws IOException {
		try {
			Instant now = Instant.now();
			JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(ca.root, Date.from(now));
			builder.setNextUpdate(Date.from(now.plus(Duration.ofDays(7))));
			for (BigInteger serial : revoked) {
				builder.addCRLEntry(serial, Date.from(now), CRLReason.cACompromise);
			}
			respond(exchange, builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(ca.rootKey.getPrivate()))
				.getEncoded());
		}
		catch (Exception ex) {
			exchange.sendResponseHeaders(500, -1);
			exchange.close();
		}
	}

	private static void respond(HttpExchange exchange, byte[] body) throws IOException {
		exchange.sendResponseHeaders(200, body.length);
		exchange.getResponseBody().write(body);
		exchange.close();
	}

}
