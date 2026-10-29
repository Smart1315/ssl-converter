package com.yeongsby.sslconverter.cert;

/**
 * 인증서/키/키스토어 어느 것으로도 인식되지 않는 데이터. 압축파일 안에서는 오류가 아니라 건너뛴 파일로 처리한다.
 */
class UnrecognizedInputException extends ConversionException {

	UnrecognizedInputException(String message) {
		super(message);
	}

}
