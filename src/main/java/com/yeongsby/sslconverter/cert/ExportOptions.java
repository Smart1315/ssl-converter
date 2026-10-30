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
 */
public record ExportOptions(Set<OutputFormat> formats, String baseName, String alias, char[] password,
		boolean includeRoot, boolean legacyPfx, KeyFormat keyFormat, boolean encryptKey) {

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
