package com.yeongsby.sslconverter.cert;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;

/**
 * 키 관련 공통 기능: 개인키-인증서 일치 확인, 키 설명 문자열.
 */
final class KeyUtils {

	private static final byte[] PROBE = "ssl-converter-key-match".getBytes(StandardCharsets.US_ASCII);

	private KeyUtils() {
	}

	/**
	 * 개인키가 공개키와 짝인지 확인한다. RSA 는 modulus 비교, 그 외는 서명/검증으로 확인한다.
	 */
	static boolean matches(PrivateKey privateKey, PublicKey publicKey) {
		if (privateKey instanceof RSAKey rsaPrivate && publicKey instanceof RSAKey rsaPublic) {
			return rsaPrivate.getModulus().equals(rsaPublic.getModulus());
		}
		String algorithm = switch (publicKey.getAlgorithm()) {
			case "EC" -> "SHA256withECDSA";
			case "DSA" -> "SHA256withDSA";
			case "EdDSA", "Ed25519", "Ed448" -> "EdDSA";
			default -> null;
		};
		if (algorithm == null) {
			return false;
		}
		try {
			Signature signer = Signature.getInstance(algorithm);
			signer.initSign(privateKey);
			signer.update(PROBE);
			byte[] signature = signer.sign();
			Signature verifier = Signature.getInstance(algorithm);
			verifier.initVerify(publicKey);
			verifier.update(PROBE);
			return verifier.verify(signature);
		}
		catch (GeneralSecurityException | RuntimeException ex) {
			return false;
		}
	}

	/**
	 * 예: "RSA 2048비트", "EC secp384r1 (384비트)".
	 */
	static String describe(Key key) {
		if (key instanceof RSAKey rsa) {
			return "RSA " + rsa.getModulus().bitLength() + "비트";
		}
		if (key instanceof ECKey ec) {
			String curve = curveName(key);
			int size = ec.getParams().getCurve().getField().getFieldSize();
			return "EC " + ((curve != null) ? curve + " " : "") + "(" + size + "비트)";
		}
		return key.getAlgorithm();
	}

	private static String curveName(Key key) {
		try {
			ASN1Encodable parameters = (key instanceof PublicKey)
					? SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm().getParameters()
					: PrivateKeyInfo.getInstance(key.getEncoded()).getPrivateKeyAlgorithm().getParameters();
			if (parameters instanceof ASN1ObjectIdentifier oid) {
				String name = ECNamedCurveTable.getName(oid);
				return (name != null) ? name : oid.getId();
			}
		}
		catch (RuntimeException ex) {
			// 곡선 이름은 표시용이므로 실패해도 무시
		}
		return null;
	}

}
