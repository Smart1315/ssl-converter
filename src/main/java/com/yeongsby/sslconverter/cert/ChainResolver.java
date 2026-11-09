package com.yeongsby.sslconverter.cert;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Component;

/**
 * 입력 순서와 상관없이 서버 인증서를 찾고, 발급자 관계(DN + 서명 검증)를 따라 체인을 올바른 순서로 정렬한다.
 * <p>
 * 교차 서명 인증서가 함께 들어 있으면 발급 경로가 여러 개가 된다. 이때는 브라우저처럼 신뢰된 루트에 가장 가까이 닿는 경로를 고르고,
 * 고르지 않은 경로의 인증서는 체인과 상관없는 인증서와 구분해 대체 경로 인증서로 둔다.
 */
@Component
public class ChainResolver {

	private static final int EXPIRY_WARNING_DAYS = 30;

	private static final int MAX_PATHS = 64;

	public CertBundle resolve(ParsedInput input) {
		return resolve(input, false);
	}

	/**
	 * @param preferCrossSigned true 면 교차 서명 인증서를 거쳐 옛 루트까지 가는 경로가 있을 때 그 경로를 고른다 (새 루트를 모르는
	 * 구형 클라이언트 호환)
	 */
	public CertBundle resolve(ParsedInput input, boolean preferCrossSigned) {
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

		List<IssuerPath> paths = findPaths(leaf, certificates);
		Set<X509Certificate> crossSignedRoots = crossSignedRoots(certificates);
		boolean crossSignedPathAvailable = paths.stream().anyMatch((path) -> path.passesAny(crossSignedRoots));
		IssuerPath chosen = choose(paths, preferCrossSigned ? crossSignedRoots : Set.of());
		boolean crossSignedPathChosen = chosen.passesAny(crossSignedRoots);
		List<X509Certificate> chain = chosen.chain();
		Set<X509Certificate> onPaths = new HashSet<>();
		paths.forEach((path) -> onPaths.addAll(path.chain()));
		List<X509Certificate> alternates = new ArrayList<>();
		List<X509Certificate> unrelated = new ArrayList<>();
		for (X509Certificate certificate : certificates) {
			if (certificate == leaf || chain.contains(certificate)) {
				continue;
			}
			if (onPaths.contains(certificate) || isCrossSigned(certificate, chain)) {
				alternates.add(certificate);
			}
			else {
				unrelated.add(certificate);
			}
		}
		if (!alternates.isEmpty()) {
			notices.add("다른 발급 경로(교차 서명 등)의 인증서 " + alternates.size() + "개는 출력에서 제외됩니다. "
					+ (crossSignedPathChosen ? "구형 클라이언트 호환을 위해 교차 서명 인증서를 거치는 경로를 체인으로 골랐습니다."
							: "브라우저처럼 신뢰된 루트에 가장 가까운 경로를 체인으로 골랐습니다."));
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

		return new CertBundle(leaf, chain, key, alternates, unrelated, crossSignedPathAvailable, warnings, notices);
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

	/**
	 * 서버 인증서에서 루트 방향으로 갈 수 있는 경로를 모두 찾는다. 서명까지 맞는 발급자가 있으면 그것만 따라가고, 없으면 이름만 맞는
	 * 인증서를 따라간다.
	 */
	private List<IssuerPath> findPaths(X509Certificate leaf, List<X509Certificate> certificates) {
		List<IssuerPath> paths = new ArrayList<>();
		Set<X509Certificate> visited = new HashSet<>();
		visited.add(leaf);
		walk(leaf, certificates, new ArrayList<>(), 0, visited, paths);
		return paths;
	}

	private void walk(X509Certificate current, List<X509Certificate> certificates, List<X509Certificate> chain,
			int nameOnlyLinks, Set<X509Certificate> visited, List<IssuerPath> paths) {
		if (paths.size() >= MAX_PATHS) {
			return;
		}
		List<X509Certificate> verified = new ArrayList<>();
		List<X509Certificate> nameMatches = new ArrayList<>();
		if (!isSelfSigned(current)) {
			for (X509Certificate candidate : certificates) {
				if (visited.contains(candidate)
						|| !current.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
					continue;
				}
				(verifies(current, candidate) ? verified : nameMatches).add(candidate);
			}
		}
		List<X509Certificate> issuers = verified.isEmpty() ? nameMatches : verified;
		if (issuers.isEmpty()) {
			paths.add(new IssuerPath(List.copyOf(chain), nameOnlyLinks));
			return;
		}
		for (X509Certificate issuer : issuers) {
			chain.add(issuer);
			visited.add(issuer);
			walk(issuer, certificates, chain, nameOnlyLinks + (verified.isEmpty() ? 1 : 0), visited, paths);
			visited.remove(issuer);
			chain.remove(chain.size() - 1);
		}
	}

	/**
	 * 브라우저가 고르는 경로에 가깝게, 신뢰된 루트에 더 일찍 닿는 경로 → 루트(자체 서명)로 끝나는 경로 → 서명이 확인된 경로 → 짧은 경로
	 * 순으로 고른다. 조건이 같으면 입력 순서상 먼저 찾은 경로.
	 */
	private IssuerPath choose(List<IssuerPath> paths, Set<X509Certificate> preferred) {
		return paths.stream()
			.min(Comparator.comparing((IssuerPath path) -> !path.passesAny(preferred))
				.thenComparingInt(IssuerPath::trustedDepth)
				.thenComparing(IssuerPath::complete, Comparator.reverseOrder())
				.thenComparingInt(IssuerPath::nameOnlyLinks)
				.thenComparingInt((path) -> path.chain().size()))
			.orElseThrow();
	}

	/**
	 * 같은 이름·공개키의 자체 서명 루트가 함께 들어 있는, 다른 CA 가 서명한 루트 인증서 (예: AAA Certificate Services 가 서명한
	 * USERTrust RSA CA).
	 */
	private static Set<X509Certificate> crossSignedRoots(List<X509Certificate> certificates) {
		Set<X509Certificate> result = new HashSet<>();
		for (X509Certificate certificate : certificates) {
			if (!isSelfSigned(certificate) && certificates.stream()
				.anyMatch((root) -> isSelfSigned(root) && isCrossSigned(certificate, List.of(root)))) {
				result.add(certificate);
			}
		}
		return result;
	}

	/**
	 * 체인의 인증서와 이름·공개키가 같은, 다른 CA 가 서명한 인증서인지.
	 */
	static boolean isCrossSigned(X509Certificate certificate, List<X509Certificate> chain) {
		return chain.stream()
			.anyMatch((member) -> member != certificate
					&& member.getSubjectX500Principal().equals(certificate.getSubjectX500Principal())
					&& member.getPublicKey().equals(certificate.getPublicKey()));
	}

	/**
	 * @param chain 서버 인증서의 발급자부터 상위 방향
	 * @param nameOnlyLinks 서명은 맞지 않고 이름만 맞아 이어진 연결 수
	 */
	private record IssuerPath(List<X509Certificate> chain, int nameOnlyLinks) {

		/**
		 * 신뢰된 루트에 닿는 위치. 체인 안에 신뢰된 루트(교차 서명본 포함)가 있으면 그 위치, 마지막 인증서의 발급자가 신뢰 저장소에
		 * 있으면 체인 길이, 닿지 않으면 가장 큰 값.
		 */
		int trustedDepth() {
			for (int i = 0; i < this.chain.size(); i++) {
				if (TrustStore.isTrustedRoot(this.chain.get(i))) {
					return i;
				}
			}
			if (!this.chain.isEmpty() && !complete() && TrustStore.findIssuer(top()) != null) {
				return this.chain.size();
			}
			return Integer.MAX_VALUE;
		}

		boolean passesAny(Set<X509Certificate> certificates) {
			return this.chain.stream().anyMatch(certificates::contains);
		}

		boolean complete() {
			return !this.chain.isEmpty() && isSelfSigned(top());
		}

		private X509Certificate top() {
			return this.chain.get(this.chain.size() - 1);
		}

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
