package com.yeongsby.sslconverter.cert;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.yeongsby.sslconverter.cert.CheckResult.Status;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateChecksTests {

	private static TestCertificates certs;

	private final CertificateChecks checks = new CertificateChecks(new RevocationChecker(false));

	@BeforeAll
	static void createCertificates() throws Exception {
		certs = TestCertificates.rsa();
	}

	@Test
	void healthyPrivateChain() {
		CertBundle bundle = bundle(certs.leaf, certs.leafKey);
		Map<String, CheckResult> results = byId(this.checks.run(bundle, true, false));

		assertThat(results.get("KEY_MATCH").status()).isEqualTo(Status.PASS);
		assertThat(results.get("CHAIN").status()).isEqualTo(Status.PASS);
		assertThat(results.get("VALIDITY").status()).isEqualTo(Status.PASS);
		assertThat(results.get("SAN").status()).isEqualTo(Status.PASS);
		assertThat(results.get("SERVER_AUTH").status()).isEqualTo(Status.PASS);
		assertThat(results.get("KEY_STRENGTH").status()).isEqualTo(Status.PASS);
		assertThat(results.get("SIGNATURE").status()).isEqualTo(Status.PASS);
		// 테스트 루트는 Java 기본 신뢰 저장소에 없다
		assertThat(results.get("PUBLIC_TRUST").status()).isEqualTo(Status.WARN);
		assertThat(results.get("REVOCATION").status()).isEqualTo(Status.SKIPPED);
	}

	@Test
	void weakAndMisissuedLeafFails() throws Exception {
		KeyPair weakKey = TestCertificates.rsaKey(1024);
		X509Certificate leaf = TestCertificates.issue("CN=weak.example.com", weakKey.getPublic(), certs.intermediate,
				certs.intermediateKey, "SHA1withRSA", (builder) -> {
					builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
					builder.addExtension(Extension.extendedKeyUsage, false,
							new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
				});
		Map<String, CheckResult> results = byId(this.checks.run(bundle(leaf, weakKey), true, false));

		assertThat(results.get("KEY_STRENGTH").status()).isEqualTo(Status.FAIL);
		assertThat(results.get("SIGNATURE").status()).isEqualTo(Status.FAIL);
		assertThat(results.get("SAN").status()).isEqualTo(Status.FAIL);
		assertThat(results.get("SERVER_AUTH").status()).isEqualTo(Status.FAIL);
	}

	@Test
	void missingAndMismatchedKeysAreReported() throws Exception {
		CertBundle noKey = new CertBundle(certs.leaf, List.of(certs.intermediate, certs.root), null, List.of(),
				List.of(), List.of());
		assertThat(byId(this.checks.run(noKey, false, false)).get("KEY_MATCH").status()).isEqualTo(Status.WARN);
		assertThat(byId(this.checks.run(noKey, true, false)).get("KEY_MATCH").status()).isEqualTo(Status.FAIL);
	}

	@Test
	void missingIntermediateFailsChainCheck() {
		CertBundle bundle = new CertBundle(certs.leaf, List.of(), certs.leafKey.getPrivate(), List.of(), List.of(),
				List.of());
		Map<String, CheckResult> results = byId(this.checks.run(bundle, true, false));
		assertThat(results.get("CHAIN").status()).isEqualTo(Status.FAIL);
		assertThat(results.get("PUBLIC_TRUST").summary()).contains("중간 인증서 누락");
	}

	private static CertBundle bundle(X509Certificate leaf, KeyPair key) {
		return new CertBundle(leaf, List.of(certs.intermediate, certs.root), key.getPrivate(), List.of(), List.of(),
				List.of());
	}

	private static Map<String, CheckResult> byId(List<CheckResult> results) {
		return results.stream().collect(Collectors.toMap(CheckResult::id, (r) -> r));
	}

}
