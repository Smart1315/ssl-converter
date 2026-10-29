package com.yeongsby.sslconverter.cert;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Component;

/**
 * 입력 순서와 상관없이 서버 인증서를 찾고, 발급자 관계(DN + 서명 검증)를 따라 체인을 올바른 순서로 정렬한다.
 */
@Component
public class ChainResolver {

	private static final int EXPIRY_WARNING_DAYS = 30;

	public CertBundle resolve(ParsedInput input) {
		List<X509Certificate> certificates = input.certificates();
		if (certificates.isEmpty()) {
			return null;
		}
		List<String> warnings = new ArrayList<>();
		List<String> notices = new ArrayList<>();

		PrivateKey key = null;
		X509Certificate leaf = null;
		for (PrivateKey candidate : input.privateKeys()) {
			for (X509Certificate certificate : certificates) {
				if (KeyUtils.matches(candidate, certificate.getPublicKey())) {
					key = candidate;
					leaf = certificate;
					break;
				}
			}
			if (key != null) {
				break;
			}
		}
		if (!input.privateKeys().isEmpty()) {
			if (key == null) {
				warnings.add("개인키와 일치하는 인증서가 없습니다. 키와 인증서가 같은 발급 건인지 확인하세요.");
			}
			else if (input.privateKeys().size() > 1) {
				warnings.add("개인키가 " + input.privateKeys().size() + "개 입력되어, 인증서와 일치하는 키 1개만 사용합니다.");
			}
		}
		if (leaf == null) {
			leaf = pickLeaf(certificates, warnings);
		}

		List<X509Certificate> chain = buildChain(leaf, certificates);
		List<X509Certificate> unrelated = new ArrayList<>();
		for (X509Certificate certificate : certificates) {
			if (certificate != leaf && !chain.contains(certificate)) {
				unrelated.add(certificate);
			}
		}
		if (!unrelated.isEmpty()) {
			notices.add("체인에 속하지 않는 인증서 " + unrelated.size() + "개는 출력에서 제외됩니다.");
		}

		X509Certificate top = chain.isEmpty() ? leaf : chain.get(chain.size() - 1);
		if (!isSelfSigned(top)) {
			if (chain.isEmpty()) {
				String url = CertInspector.caIssuersUrl(leaf);
				warnings.add("중간(체인) 인증서가 없습니다. 브라우저/클라이언트에서 신뢰 오류가 날 수 있으니 CA 에서 받은 체인 파일을 함께 올리세요."
						+ ((url != null) ? " (발급자 인증서 다운로드 주소: " + url + ")" : ""));
			}
			else {
				notices.add("체인의 마지막 발급자(" + CertInspector.commonNameOrDn(top.getIssuerX500Principal())
						+ ") 인증서는 포함되어 있지 않습니다. 보통 루트 CA 이며 서버 설정에서는 생략해도 됩니다.");
			}
		}
		checkValidity(leaf, chain, warnings);

		return new CertBundle(leaf, chain, key, unrelated, warnings, notices);
	}

	private X509Certificate pickLeaf(List<X509Certificate> certificates, List<String> warnings) {
		List<X509Certificate> candidates = new ArrayList<>();
		for (X509Certificate certificate : certificates) {
			boolean issuesOther = certificates.stream()
				.anyMatch((other) -> other != certificate && issuedBy(other, certificate));
			if (!issuesOther) {
				candidates.add(certificate);
			}
		}
		if (candidates.isEmpty()) {
			candidates.addAll(certificates);
		}
		List<X509Certificate> endEntities = candidates.stream().filter((c) -> c.getBasicConstraints() < 0).toList();
		if (!endEntities.isEmpty()) {
			candidates = endEntities;
		}
		X509Certificate leaf = candidates.get(0);
		if (candidates.size() > 1) {
			warnings.add("서버 인증서로 보이는 인증서가 " + candidates.size() + "개입니다. '"
					+ CertInspector.commonNameOrDn(leaf.getSubjectX500Principal()) + "'를 사용합니다. 서로 다른 인증서를 함께 올리지 않았는지 확인하세요.");
		}
		return leaf;
	}

	private List<X509Certificate> buildChain(X509Certificate leaf, List<X509Certificate> certificates) {
		List<X509Certificate> chain = new ArrayList<>();
		Set<X509Certificate> visited = new HashSet<>();
		visited.add(leaf);
		X509Certificate current = leaf;
		while (!isSelfSigned(current)) {
			X509Certificate issuer = findIssuer(current, certificates, visited);
			if (issuer == null) {
				break;
			}
			chain.add(issuer);
			visited.add(issuer);
			current = issuer;
		}
		return chain;
	}

	private X509Certificate findIssuer(X509Certificate certificate, List<X509Certificate> candidates,
			Set<X509Certificate> visited) {
		X509Certificate nameMatch = null;
		for (X509Certificate candidate : candidates) {
			if (visited.contains(candidate)
					|| !certificate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
				continue;
			}
			if (verifies(certificate, candidate)) {
				return candidate;
			}
			if (nameMatch == null) {
				nameMatch = candidate;
			}
		}
		return nameMatch;
	}

	private void checkValidity(X509Certificate leaf, List<X509Certificate> chain, List<String> warnings) {
		Instant now = Instant.now();
		if (leaf.getNotAfter().toInstant().isBefore(now)) {
			warnings.add("서버 인증서가 만료되었습니다 (" + CertInspector.format(leaf.getNotAfter()) + ").");
		}
		else if (leaf.getNotBefore().toInstant().isAfter(now)) {
			warnings.add("서버 인증서의 유효기간이 아직 시작되지 않았습니다 (" + CertInspector.format(leaf.getNotBefore()) + ").");
		}
		else if (Duration.between(now, leaf.getNotAfter().toInstant()).toDays() < EXPIRY_WARNING_DAYS) {
			warnings.add("서버 인증서가 " + EXPIRY_WARNING_DAYS + "일 이내에 만료됩니다 (" + CertInspector.format(leaf.getNotAfter())
					+ ").");
		}
		for (X509Certificate certificate : chain) {
			if (certificate.getNotAfter().toInstant().isBefore(now)) {
				warnings.add("체인 인증서 '" + CertInspector.commonNameOrDn(certificate.getSubjectX500Principal())
						+ "'가 만료되었습니다. 최신 체인 파일을 CA 에서 다시 받으세요.");
			}
		}
	}

	static boolean issuedBy(X509Certificate certificate, X509Certificate issuer) {
		return certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
				&& verifies(certificate, issuer);
	}

	static boolean isSelfSigned(X509Certificate certificate) {
		return issuedBy(certificate, certificate);
	}

	private static boolean verifies(X509Certificate certificate, X509Certificate issuer) {
		try {
			certificate.verify(issuer.getPublicKey());
			return true;
		}
		catch (Exception ex) {
			return false;
		}
	}

}
