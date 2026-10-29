package com.yeongsby.sslconverter.web;

import java.util.Map;

import com.yeongsby.sslconverter.cert.ConversionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@RestControllerAdvice
public class ApiExceptionHandler {

	private static final Logger logger = LoggerFactory.getLogger(ApiExceptionHandler.class);

	@ExceptionHandler(ConversionException.class)
	public ResponseEntity<Map<String, String>> conversion(ConversionException ex) {
		return ResponseEntity.badRequest().body(Map.of("message", ex.getMessage()));
	}

	@ExceptionHandler(MaxUploadSizeExceededException.class)
	public ResponseEntity<Map<String, String>> tooLarge(MaxUploadSizeExceededException ex) {
		return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
			.body(Map.of("message", "업로드 파일이 너무 큽니다 (파일당 최대 10MB)."));
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<Map<String, String>> unexpected(Exception ex) {
		logger.error("Unexpected error", ex);
		return ResponseEntity.internalServerError()
			.body(Map.of("message", "처리 중 오류가 발생했습니다: " + ex.getMessage()));
	}

}
