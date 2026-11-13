package com.yeongsby.sslconverter.tools;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.yeongsby.sslconverter.cert.ConversionException;
import com.yeongsby.sslconverter.cert.InputParser;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.Test;

class PkiToolsServiceTests {

	private final PkiToolsService service = new PkiToolsService(new InputParser());

	@Test
	void createsSelfSignedCa() throws Exception {
		ToolResult generated = service.execute("self-signed", Map.of("commonName", "local Test CA", "keyType", "EC", "isCa", "true"), Map.of());
		X509Certificate ca = parseCertificate(artifact(generated, "certificate.pem").content());
		assertThat(ca.getBasicConstraints()).isPositive();
		ca.verify(ca.getPublicKey());
	}

	@Test
	void generatesAndDecodesCsr() {
		ToolResult generated = service.execute("csr", Map.of("commonName", "example.test", "keyType", "EC", "san", "example.test"), Map.of());
		String csr = artifact(generated, "request.csr").content();
		ToolResult decoded = service.execute("csr-decode", Map.of("text", csr), Map.of());
		assertThat(decoded.sections()).anySatisfy(section -> assertThat(section.rows()).anySatisfy(row -> assertThat(row.value()).contains("example.test")));
	}

	@Test
	void issuesLeafAndMatchesItsKeyAndCsr() throws Exception {
		TestCa ca = testCa(true);
		ToolResult generated = service.execute("csr", Map.of("commonName", "service.example.test", "keyType", "RSA", "keyBits", "2048", "san", "service.example.test"), Map.of());
		String csr = artifact(generated, "request.csr").content();
		ToolResult issued = service.execute("issue", Map.of("text", csr, "caText", ca.pem()), Map.of());
		String issuedPem = artifact(issued, "issued-certificate.pem").content();
		X509Certificate leaf = parseCertificate(issuedPem);

		assertThat(leaf.getBasicConstraints()).isNegative();
		assertThat(leaf.getExtendedKeyUsage()).contains("1.3.6.1.5.5.7.3.1");
		leaf.verify(ca.certificate().getPublicKey());
		ToolResult matched = service.execute("match", Map.of("text", issuedPem + artifact(generated, "private-key.pem").content(), "csrText", csr), Map.of());
		assertThat(matched.sections().get(0).rows()).extracting(ToolResult.Row::value).allMatch(value -> value.contains("일치"));
	}

	@Test
	void refusesIssuanceFromNonCaCertificate() throws Exception {
		TestCa nonCa = testCa(false);
		ToolResult generated = service.execute("csr", Map.of("commonName", "service.example.test", "keyType", "EC"), Map.of());
		assertThatThrownBy(() -> service.execute("issue", Map.of("text", artifact(generated, "request.csr").content(), "caText", nonCa.pem()), Map.of()))
			.isInstanceOf(ConversionException.class).hasMessageContaining("CA");
	}

	@Test
	void inspectsCrlOcspAsn1AndComparesCertificates() throws Exception {
		TestCa ca = testCa(true);
		Date now = Date.from(Instant.now());
		X509CRLHolder crl = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now)
			.addCRLEntry(BigInteger.valueOf(77), now, org.bouncycastle.asn1.x509.CRLReason.keyCompromise)
			.setNextUpdate(new Date(now.getTime() + 3_600_000))
			.build(new JcaContentSignerBuilder("SHA256withRSA").build(ca.keyPair().getPrivate()));
		ToolResult crlResult = service.execute("crl", Map.of("text", pem("X509 CRL", crl.getEncoded()), "issuerText", ca.certificatePem()), Map.of());
		assertThat(crlResult.sections().get(0).rows()).anySatisfy(row -> { assertThat(row.label()).isEqualTo("폐기 일련번호"); assertThat(row.value()).contains("77"); });
		assertThat(crlResult.sections().get(0).rows()).anySatisfy(row -> assertThat(row.value()).isEqualTo("유효"));

		var digest = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
		var responseBuilder = new JcaBasicOCSPRespBuilder(ca.certificate().getPublicKey(), digest);
		responseBuilder.addResponse(new CertificateID(digest, new JcaX509CertificateHolder(ca.certificate()), BigInteger.valueOf(77)), CertificateStatus.GOOD,
			now, new Date(now.getTime() + 3_600_000), null);
		BasicOCSPResp basic = responseBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(ca.keyPair().getPrivate()),
			new org.bouncycastle.cert.X509CertificateHolder[]{new JcaX509CertificateHolder(ca.certificate())}, now);
		OCSPResp ocsp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic);
		ToolResult ocspResult = service.execute("ocsp", Map.of("text", Base64.getEncoder().encodeToString(ocsp.getEncoded()), "issuerText", ca.certificatePem()), Map.of());
		assertThat(ocspResult.sections().get(0).rows()).anySatisfy(row -> { assertThat(row.label()).isEqualTo("응답 서명"); assertThat(row.value()).isEqualTo("유효"); });

		byte[] integer = new ASN1Integer(123).getEncoded();
		ToolResult asn1 = service.execute("asn1", Map.of("text", Base64.getEncoder().encodeToString(integer)), Map.of());
		assertThat(asn1.tree()).isNotNull();
		assertThat(service.execute("asn1", Map.of("text", ca.certificatePem()), Map.of()).tree()).isNotNull();

		ToolResult generated = service.execute("csr", Map.of("commonName", "compare.example.test", "keyType", "EC"), Map.of());
		ToolResult issued = service.execute("issue", Map.of("text", artifact(generated, "request.csr").content(), "caText", ca.pem()), Map.of());
		ToolResult compared = service.execute("compare", Map.of("text", ca.certificatePem(), "textB", artifact(issued, "issued-certificate.pem").content()), Map.of());
		assertThat(compared.sections().get(0).rows()).hasSizeGreaterThan(3);
	}

	@Test
	void verifiesAttachedCmsSignature() throws Exception {
		TestCa ca = testCa(true);
		byte[] content = "signed content".getBytes(StandardCharsets.UTF_8);
		var digests = new JcaDigestCalculatorProviderBuilder().build();
		var signerInfo = new JcaSignerInfoGeneratorBuilder(digests).build(
			new JcaContentSignerBuilder("SHA256withRSA").build(ca.keyPair().getPrivate()), ca.certificate());
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addSignerInfoGenerator(signerInfo);
		generator.addCertificate(new JcaX509CertificateHolder(ca.certificate()));
		byte[] signed = generator.generate(new CMSProcessableByteArray(content), true).getEncoded();
		ToolResult result = service.execute("cms", Map.of("text", Base64.getEncoder().encodeToString(signed)), Map.of());
		assertThat(result.sections().get(0).rows()).anySatisfy(row -> assertThat(row.value()).isEqualTo("유효"));
		byte[] detached = generator.generate(new CMSProcessableByteArray(content), false).getEncoded();
		ToolResult detachedResult = service.execute("cms", Map.of("text", Base64.getEncoder().encodeToString(detached), "contentText", new String(content, StandardCharsets.UTF_8)), Map.of());
		assertThat(detachedResult.sections().get(0).rows()).anySatisfy(row -> assertThat(row.value()).isEqualTo("유효"));
	}

	private TestCa testCa(boolean isCa) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.generateKeyPair();
		X500Name name = new X500Name("CN=Test CA");
		Date now = new Date();
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(isCa ? 11 : 12),
			new Date(now.getTime() - 3_600_000), new Date(now.getTime() + 86_400_000), name, pair.getPublic());
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
		builder.addExtension(Extension.keyUsage, true, new KeyUsage(isCa ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
		X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
		return new TestCa(pair, certificate, pem(certificate) + pem(pair.getPrivate()), pem(certificate));
	}

	private static String pem(Object value) throws Exception {
		StringWriter writer = new StringWriter();
		try (JcaPEMWriter pem = new JcaPEMWriter(writer)) { pem.writeObject(value); }
		return writer.toString();
	}

	private static String pem(String label, byte[] bytes) throws Exception {
		StringWriter writer = new StringWriter();
		try (JcaPEMWriter pem = new JcaPEMWriter(writer)) { pem.writeObject(new PemObject(label, bytes)); }
		return writer.toString();
	}

	private static X509Certificate parseCertificate(String encoded) throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(encoded.getBytes(StandardCharsets.UTF_8)));
	}

	private static ToolResult.Artifact artifact(ToolResult result, String name) {
		return result.files().stream().filter(file -> file.name().equals(name)).findFirst().orElseThrow();
	}

	private record TestCa(KeyPair keyPair, X509Certificate certificate, String pem, String certificatePem) { }
}
