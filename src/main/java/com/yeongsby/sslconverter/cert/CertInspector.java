package com.yeongsby.sslconverter.cert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

/**
 * 인증서 상세 정보 (keytool -list -v 에 해당).
 */
public final class CertInspector {

	private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
		.withZone(ZoneId.systemDefault());

	private CertInspector() {
	}

	public static CertDetails describe(X509Certificate certificate, String role) {
		Instant now = Instant.now();
		Instant notAfter = certificate.getNotAfter().toInstant();
		long daysRemaining = Duration.between(now, notAfter).toDays();
		String status;
		if (notAfter.isBefore(now)) {
			status = "EXPIRED";
		}
		else if (certificate.getNotBefore().toInstant().isAfter(now)) {
			status = "NOT_YET_VALID";
		}
		else if (daysRemaining < 30) {
			status = "EXPIRING";
		}
		else {
			status = "VALID";
		}
		return new CertDetails(role, commonName(certificate.getSubjectX500Principal()),
				displayName(certificate.getSubjectX500Principal()), displayName(certificate.getIssuerX500Principal()),
				subjectAltNames(certificate), format(certificate.getNotBefore()), format(certificate.getNotAfter()),
				daysRemaining, status, HexFormat.of().withUpperCase().formatHex(certificate.getSerialNumber().toByteArray()),
				certificate.getSigAlgName(), KeyUtils.describe(certificate.getPublicKey()),
				fingerprint(certificate, "SHA-1"), fingerprint(certificate, "SHA-256"),
				certificate.getBasicConstraints() >= 0, ChainResolver.isSelfSigned(certificate),
				caIssuersUrl(certificate));
	}

	public static String commonName(X500Principal principal) {
		X500Name name = X500Name.getInstance(principal.getEncoded());
		RDN[] rdns = name.getRDNs(BCStyle.CN);
		if (rdns.length == 0) {
			return null;
		}
		return IETFUtils.valueToString(rdns[0].getFirst().getValue());
	}

	static String commonNameOrDn(X500Principal principal) {
		String cn = commonName(principal);
		return (cn != null) ? cn : displayName(principal);
	}

	static String displayName(X500Principal principal) {
		return X500Name.getInstance(principal.getEncoded()).toString();
	}

	public static List<String> subjectAltNames(X509Certificate certificate) {
		List<String> names = new ArrayList<>();
		try {
			Collection<List<?>> entries = certificate.getSubjectAlternativeNames();
			if (entries != null) {
				for (List<?> entry : entries) {
					int type = (Integer) entry.get(0);
					if (type == GeneralName.dNSName || type == GeneralName.iPAddress
							|| type == GeneralName.rfc822Name) {
						names.add(String.valueOf(entry.get(1)));
					}
				}
			}
		}
		catch (CertificateParsingException ex) {
			// SAN 은 표시용이므로 무시
		}
		return names;
	}

	static String caIssuersUrl(X509Certificate certificate) {
		List<String> urls = accessLocations(certificate, AccessDescription.id_ad_caIssuers);
		return urls.isEmpty() ? null : urls.get(0);
	}

	static List<String> ocspUrls(X509Certificate certificate) {
		return accessLocations(certificate, AccessDescription.id_ad_ocsp);
	}

	/**
	 * CRL 배포 지점(CDP)의 URI 목록.
	 */
	static List<String> crlUrls(X509Certificate certificate) {
		List<String> urls = new ArrayList<>();
		byte[] value = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
		if (value == null) {
			return urls;
		}
		try {
			CRLDistPoint points = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(value));
			for (DistributionPoint point : points.getDistributionPoints()) {
				DistributionPointName name = point.getDistributionPoint();
				if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
					for (GeneralName generalName : GeneralNames.getInstance(name.getName()).getNames()) {
						if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
							urls.add(generalName.getName().toString());
						}
					}
				}
			}
		}
		catch (IOException | RuntimeException ex) {
			// 잘못된 확장은 URL 없음으로 취급
		}
		return urls;
	}

	private static List<String> accessLocations(X509Certificate certificate, ASN1ObjectIdentifier method) {
		List<String> urls = new ArrayList<>();
		byte[] value = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
		if (value == null) {
			return urls;
		}
		try {
			ASN1Primitive parsed = JcaX509ExtensionUtils.parseExtensionValue(value);
			for (AccessDescription description : AuthorityInformationAccess.getInstance(parsed)
				.getAccessDescriptions()) {
				if (method.equals(description.getAccessMethod())
						&& description.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
					urls.add(description.getAccessLocation().getName().toString());
				}
			}
		}
		catch (IOException | RuntimeException ex) {
			// 잘못된 확장은 URL 없음으로 취급
		}
		return urls;
	}

	static String format(Date date) {
		return DATE_FORMAT.format(date.toInstant());
	}

	private static String fingerprint(X509Certificate certificate, String algorithm) {
		try {
			byte[] digest = MessageDigest.getInstance(algorithm).digest(certificate.getEncoded());
			return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
		}
		catch (GeneralSecurityException ex) {
			return "";
		}
	}

	/**
	 * 인증서 한 장의 표시용 정보.
	 */
	public record CertDetails(String role, String commonName, String subject, String issuer,
			List<String> subjectAltNames, String notBefore, String notAfter, long daysRemaining, String status,
			String serialNumber, String signatureAlgorithm, String publicKey, String sha1, String sha256, boolean ca,
			boolean selfSigned, String caIssuersUrl) {
	}

}
