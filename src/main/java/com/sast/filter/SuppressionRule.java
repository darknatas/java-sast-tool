package com.sast.filter;

/**
 * sast-suppressions.json 억제 규칙 항목 (IV-6.2 오탐 관리)
 *
 * 모든 필드는 null 허용 — null인 필드는 "모든 값과 매칭"을 의미함.
 *   file   null → 모든 파일
 *   ruleId null → 모든 규칙
 *   line   null → 모든 라인
 */
public record SuppressionRule(
        String  file,    // 파일 경로 일부 (예: "SomeClass.java", "com/example/")
        String  ruleId,  // 규칙 ID (예: "IV-1.1")
        Integer line,    // 정확한 라인 번호
        String  reason   // 억제 이유 (문서 목적)
) {}
