package com.yeongsby.sslconverter.cert;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

/**
 * 테스트용 루트 → 중간 → 서버 인증서 체인.
 */
final class TestCertificates {

	final KeyPair rootKey;

	final KeyPair intermediateKey;

	final KeyPair leafKey;

	final X509Certificate root;

	final X509Certificate intermediate;

	final X509Certificate leaf;

	private TestCertificates(String keyAlgorithm, String commonName) throws Exception {
		this.rootKey = generate("RSA");
		this.intermediateKey = generate("RSA");
		this.leafKey = generate(keyAlgorithm);
		this.root = issue("CN=Test Root CA,O=Test", this.rootKey, "CN=Test Root CA,O=Test", this.rootKey, true, null);
		this.intermediate = issue("CN=Test Intermediate CA,O=Test", this.intermediateKey, "CN=Test Root CA,O=Test",
				this.rootKey, true, null);
		this.leaf = issue("CN=" + commonName, this.leafKey, "CN=Test Intermediate CA,O=Test", this.intermediateKey,
				false, commonName);
	}

	static TestCertificates rsa() throws Exception {
		return new TestCertificates("RSA", "example.com");
	}

	static TestCertificates ec() throws Exception {
		return new TestCertificates("EC", "*.example.com");
	}

	static String pem(Object... objects) throws Exception {
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
		return writer.toString();
	}

	private static KeyPair generate(String algorithm) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		if ("EC".equals(algorithm)) {
			generator.initialize(new ECGenParameterSpec("secp256r1"));
		}
		else {
			generator.initialize(2048);
		}
		return generator.generateKeyPair();
	}

	private static X509Certificate issue(String subject, KeyPair subjectKey, String issuer, KeyPair issuerKey,
			boolean ca, String dnsName) throws Exception {
		Instant now = Instant.now();
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuer),
				BigInteger.valueOf(now.toEpochMilli()).add(BigInteger.valueOf(subject.hashCode() & 0xffff)),
				Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(365))),
				new X500Name(subject), subjectKey.getPublic());
		builder.addExtension(Extension.basicConstraints, true, ca ? new BasicConstraints(0) : new BasicConstraints(false));
		if (dnsName != null) {
			builder.addExtension(Extension.subjectAlternativeName, false,
					new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
		}
		String signature = "RSA".equals(issuerKey.getPrivate().getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
		return new JcaX509CertificateConverter()
			.getCertificate(builder.build(new JcaContentSignerBuilder(signature).build(issuerKey.getPrivate())));
	}

}
