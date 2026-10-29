package com.example.sslconverter.cert;

/**
 * 사용자에게 그대로 보여줄 수 있는 변환/해석 오류.
 */
public class ConversionException extends RuntimeException {

	public ConversionException(String message) {
		super(message);
	}

	public ConversionException(String message, Throwable cause) {
		super(message, cause);
	}

}
