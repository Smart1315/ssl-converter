package com.example.sslconverter.cert;

/**
 * 생성 가능한 출력 형식. 파일명의 %s 는 기본 파일명으로 치환된다.
 */
public enum OutputFormat {

	/** 서버 인증서 + 중간(+루트). 기존 `cat ssl.crt chain.crt ... > x.pem` 결과물, Nginx ssl_certificate */
	FULLCHAIN_PEM("%s_fullchain.pem", "application/x-pem-file", false, false),

	/** 서버 인증서 단독 (Apache SSLCertificateFile) */
	CERT_PEM("%s.crt", "application/x-pem-file", false, false),

	/** 중간(+루트) 체인 / CA 번들 (Apache SSLCertificateChainFile) */
	CHAIN_PEM("%s_chain.crt", "application/x-pem-file", false, false),

	/** 개인키 PEM */
	KEY_PEM("%s.key", "application/x-pem-file", true, false),

	/** 개인키 + 풀체인 하나의 파일 (HAProxy 등) */
	COMBINED_PEM("%s_combined.pem", "application/x-pem-file", true, false),

	/** PKCS#12 키스토어 (IIS, Windows, Tomcat, Spring Boot) */
	PFX("%s.pfx", "application/x-pkcs12", false, true),

	/** Java KeyStore (Tomcat, WebLogic, JEUS 등) */
	JKS("%s.jks", "application/octet-stream", false, true),

	/** 체인 인증서만 담은 트러스트스토어 */
	TRUSTSTORE_JKS("%s_truststore.jks", "application/octet-stream", false, true),

	/** PKCS#7 인증서 체인 (키 미포함) */
	P7B("%s.p7b", "application/x-pkcs7-certificates", false, false),

	/** DER(바이너리) 서버 인증서 */
	DER("%s.cer", "application/pkix-cert", false, false);

	private final String filePattern;

	private final String contentType;

	private final boolean requiresKey;

	private final boolean requiresPassword;

	OutputFormat(String filePattern, String contentType, boolean requiresKey, boolean requiresPassword) {
		this.filePattern = filePattern;
		this.contentType = contentType;
		this.requiresKey = requiresKey;
		this.requiresPassword = requiresPassword;
	}

	public String fileName(String baseName) {
		return this.filePattern.formatted(baseName);
	}

	public String contentType() {
		return this.contentType;
	}

	public boolean requiresKey() {
		return this.requiresKey;
	}

	public boolean requiresPassword() {
		return this.requiresPassword;
	}

}
