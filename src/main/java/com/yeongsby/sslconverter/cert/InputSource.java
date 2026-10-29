package com.yeongsby.sslconverter.cert;

/**
 * 업로드된 파일 또는 붙여넣은 텍스트 하나.
 */
public record InputSource(String name, byte[] data) {
}
