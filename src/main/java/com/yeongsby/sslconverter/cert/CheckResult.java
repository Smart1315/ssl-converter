package com.yeongsby.sslconverter.cert;

import java.util.List;

/**
 * 점검 항목 하나의 결과.
 *
 * @param id 항목 식별자 (예: KEY_STRENGTH)
 * @param title 화면 표시 이름
 * @param status 결과
 * @param summary 한 줄 요약
 * @param details 인증서별 상세 내용
 */
public record CheckResult(String id, String title, Status status, String summary, List<String> details) {

	public enum Status {

		/** 문제 없음 */
		PASS,

		/** 확인 필요 (사용은 가능할 수 있음) */
		WARN,

		/** 실제 서비스에서 오류가 날 가능성이 높음 */
		FAIL,

		/** 점검하지 않음 */
		SKIPPED

	}

}
