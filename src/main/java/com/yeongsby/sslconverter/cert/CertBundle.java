package com.yeongsby.sslconverter.cert;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * 정리된 인증서 묶음.
 *
 * @param leaf 서버(최종) 인증서
 * @param chain leaf 의 발급자부터 상위로 정렬된 중간/루트 인증서
 * @param privateKey leaf 와 일치하는 개인키 (없으면 null)
 * @param alternates 고르지 않은 다른 발급 경로(교차 서명 등)의 인증서. 출력에서 제외된다
 * @param unrelated 체인에 속하지 않아 제외된 인증서
 * @param crossSignedPathAvailable 교차 서명 인증서를 거쳐 옛 루트까지 가는 경로를 고를 수 있는지
 * @param warnings 주의가 필요한 사항
 * @param notices 참고 사항
 */
public record CertBundle(X509Certificate leaf, List<X509Certificate> chain, PrivateKey privateKey,
		List<X509Certificate> alternates, List<X509Certificate> unrelated, boolean crossSignedPathAvailable,
		List<String> warnings, List<String> notices) {

	public CertBundle(X509Certificate leaf, List<X509Certificate> chain, PrivateKey privateKey,
			List<X509Certificate> unrelated, List<String> warnings, List<String> notices) {
		this(leaf, chain, privateKey, List.of(), unrelated, false, warnings, notices);
	}

	public boolean hasPrivateKey() {
		return this.privateKey != null;
	}

	public boolean rootIncluded() {
		return ChainResolver.isSelfSigned(this.chain.isEmpty() ? this.leaf : this.chain.get(this.chain.size() - 1));
	}

	/**
	 * 출력용 체인. includeRoot 가 false 면 마지막의 자체 서명(루트) 인증서를 제외한다.
	 */
	public List<X509Certificate> chain(boolean includeRoot) {
		List<X509Certificate> result = new ArrayList<>(this.chain);
		if (!includeRoot && !result.isEmpty() && ChainResolver.isSelfSigned(result.get(result.size() - 1))) {
			result.remove(result.size() - 1);
		}
		return result;
	}

	/**
	 * leaf + 출력용 체인.
	 */
	public List<X509Certificate> fullChain(boolean includeRoot) {
		List<X509Certificate> result = new ArrayList<>();
		result.add(this.leaf);
		result.addAll(chain(includeRoot));
		return result;
	}

}
