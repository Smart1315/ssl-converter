package com.yeongsby.sslconverter.cert;

import java.util.Set;

/**
 * 출력 옵션.
 *
 * @param formats 생성할 형식
 * @param baseName 파일명 접두어 (예: example_com)
 * @param alias PFX/JKS 별칭 (예: example.com)
 * @param password PFX/JKS/암호화 키 비밀번호
 * @param includeRoot 루트 인증서 포함 여부
 * @param legacyPfx PFX 를 3DES/SHA1 로 암호화 (Windows Server 2016 이하, 구형 Java 호환)
 * @param keyFormat 개인키 PEM 형식
 * @param encryptKey 개인키 PEM(.key, 통합 PEM)을 출력 비밀번호로 암호화
 * @param noPassword 출력 비밀번호 없이 생성 (PFX 를 빈 비밀번호로 만든다. JKS 와 개인키 암호화에는 쓸 수 없다)
 * @param crossSignedPath 교차 서명 인증서를 거쳐 옛 루트까지 가는 경로를 체인으로 사용 (새 루트를 모르는 구형 클라이언트 호환)
 */
public record ExportOptions(Set<OutputFormat> formats, String baseName, String alias, char[] password,
		boolean includeRoot, boolean legacyPfx, KeyFormat keyFormat, boolean encryptKey, boolean noPassword,
		boolean crossSignedPath) {

	public ExportOptions(Set<OutputFormat> formats, String baseName, String alias, char[] password,
			boolean includeRoot, boolean legacyPfx, KeyFormat keyFormat, boolean encryptKey, boolean noPassword) {
		this(formats, baseName, alias, password, includeRoot, legacyPfx, keyFormat, encryptKey, noPassword, false);
	}

	public ExportOptions(Set<OutputFormat> formats, String baseName, String alias, char[] password,
			boolean includeRoot, boolean legacyPfx, KeyFormat keyFormat, boolean encryptKey) {
		this(formats, baseName, alias, password, includeRoot, legacyPfx, keyFormat, encryptKey, false);
	}

	/**
	 * 개인키를 암호화하지 않는 옵션. {@link KeyFormat#PKCS8_ENCRYPTED} 를 주면 암호화한다.
	 */
	public ExportOptions(Set<OutputFormat> formats, String baseName, String alias, char[] password,
			boolean includeRoot, boolean legacyPfx, KeyFormat keyFormat) {
		this(formats, baseName, alias, password, includeRoot, legacyPfx, keyFormat, false);
	}

	public enum KeyFormat {

		/** -----BEGIN PRIVATE KEY----- (암호화 시 ENCRYPTED PRIVATE KEY, AES-256) */
		PKCS8,

		/** -----BEGIN RSA PRIVATE KEY----- / EC PRIVATE KEY (구형 OpenSSL 형식, 암호화 시 DEK-Info AES-256-CBC) */
		TRADITIONAL,

		/** PKCS8 + 암호화. 이전 API 호환용이며 encryptKey=true 와 같다 */
		PKCS8_ENCRYPTED

	}

}
