package com.sast.filter;

import com.sast.model.Finding;

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
) {
    /**
     * file, ruleId, line이 모두 null인 빈 규칙은 전체 억제 방지를 위해 false 반환.
     * 그 외에는 각 필드를 Finding과 대조하여 매칭 여부를 반환한다.
     */
    public boolean matches(Finding f) {
        if (file == null && ruleId == null && line == null) return false;
        if (file   != null && !f.getFilePath().contains(file))     return false;
        if (ruleId != null && !ruleId.equals(f.getRuleId()))       return false;
        if (line   != null && !line.equals(f.getLineNumber()))     return false;
        return true;
    }
}
