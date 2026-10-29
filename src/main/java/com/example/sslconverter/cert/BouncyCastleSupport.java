package com.example.sslconverter.cert;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * BouncyCastle 프로바이더 등록. JDK 기본 프로바이더보다 뒤에 추가하므로
 * KeyStore/CertificateFactory 등은 계속 JDK 구현을 사용한다.
 */
final class BouncyCastleSupport {

	static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

	private BouncyCastleSupport() {
	}

	static synchronized void register() {
		if (Security.getProvider(PROVIDER) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

}
