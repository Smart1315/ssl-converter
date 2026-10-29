package com.yeongsby.sslconverter.cert;

import java.security.KeyStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * JDK 기본 신뢰 저장소(cacerts)의 루트 인증서. 처음 사용할 때 한 번만 읽는다.
 */
final class TrustStore {

	private static final List<X509Certificate> ROOTS = load();

	private static final Set<TrustAnchor> ANCHORS = toAnchors(ROOTS);

	private TrustStore() {
	}

	static Set<TrustAnchor> anchors() {
		return ANCHORS;
	}

	/**
	 * 같은 이름과 공개키의 루트가 신뢰 저장소에 있는지. 교차 서명된 루트 인증서도 신뢰된 루트로 본다.
	 */
	static boolean isTrustedRoot(X509Certificate certificate) {
		return ROOTS.stream()
			.anyMatch((root) -> root.getSubjectX500Principal().equals(certificate.getSubjectX500Principal())
					&& root.getPublicKey().equals(certificate.getPublicKey()));
	}

	/**
	 * 체인에 포함되지 않은 발급자를 신뢰 저장소에서 찾는다.
	 */
	static X509Certificate findIssuer(X509Certificate certificate) {
		return ROOTS.stream().filter((root) -> ChainResolver.issuedBy(certificate, root)).findFirst().orElse(null);
	}

	private static List<X509Certificate> load() {
		try {
			TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			factory.init((KeyStore) null);
			for (TrustManager manager : factory.getTrustManagers()) {
				if (manager instanceof X509TrustManager x509) {
					return List.of(x509.getAcceptedIssuers());
				}
			}
			return List.of();
		}
		catch (Exception ex) {
			throw new IllegalStateException("기본 신뢰 저장소를 읽을 수 없습니다", ex);
		}
	}

	private static Set<TrustAnchor> toAnchors(List<X509Certificate> roots) {
		Set<TrustAnchor> anchors = new HashSet<>();
		roots.forEach((root) -> anchors.add(new TrustAnchor(root, null)));
		return anchors;
	}

}
