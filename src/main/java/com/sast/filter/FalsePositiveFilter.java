package com.sast.filter;

import com.sast.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 오탐(False Positive) 필터링 시스템
 *
 * 지원 필터:
 *   1. 테스트 경로 자동 감지: src/test/ 하위 파일 → 위험도 LOW로 하향
 *   2. sast-suppressions.json 사용자 정의 억제: 파일/규칙/라인 기반 제외
 *   (3. @SuppressWarnings("sast-ignore") 어노테이션 지원은 SASTEngine에서 처리)
 */
public class FalsePositiveFilter {

    private static final Logger log = LoggerFactory.getLogger(FalsePositiveFilter.class);

    /**
     * src/test/ 하위 파일인지 판별
     */
    public static boolean isTestPath(String filePath) {
        if (filePath == null) return false;
        return filePath.contains("/src/test/")
                || filePath.contains("\\src\\test\\")
                || filePath.contains("/test/resources/");
    }

    /**
     * 테스트 경로 파일의 탐지 결과를 LOW로 하향 (제거하지 않고 표시)
     * 테스트 코드는 의도적으로 취약 패턴을 포함하는 경우가 많으므로 참고 수준으로 낮춤
     */
    public static List<Finding> lowerTestPathSeverity(List<Finding> findings) {
        return findings.stream()
                .map(f -> {
                    if (isTestPath(f.getFilePath()) && f.getSeverity() != Finding.Severity.LOW) {
                        log.debug("[FP-Filter] 테스트 경로 위험도 하향: {} L{}", f.getFilePath(), f.getLineNumber());
                        return Finding.builder()
                                .ruleId(f.getRuleId())
                                .ruleName(f.getRuleName())
                                .severity(Finding.Severity.LOW)
                                .filePath(f.getFilePath())
                                .lineNumber(f.getLineNumber())
                                .vulnerableCode(f.getVulnerableCode())
                                .description("[테스트 코드] " + f.getDescription())
                                .taintFlows(f.getTaintFlows())
                                .remediatedCode(f.getRemediatedCode())
                                .guideRef(f.getGuideRef())
                                .cweIds(f.getCweIds())
                                .build();
                    }
                    return f;
                })
                .collect(Collectors.toList());
    }

    /**
     * src/test/resources/samples 경로 여부 판별 — 검증용 샘플은 필터링 제외
     */
    private static boolean isSamplePath(String filePath) {
        if (filePath == null) return false;
        return filePath.contains("src/test/resources/samples")
                || filePath.contains("src\\test\\resources\\samples");
    }

    /**
     * sast-suppressions.json 기반 억제 적용
     * 억제 조건이 모두 일치하는 Finding은 결과에서 제외.
     * 단, src/test/resources/samples 경로의 파일은 억제를 건너뛴다(Bypass).
     */
    public static List<Finding> apply(List<Finding> findings, List<SuppressionRule> suppressions) {
        if (suppressions == null || suppressions.isEmpty()) return findings;

        List<Finding> filtered = findings.stream()
                .filter(f -> isSamplePath(f.getFilePath()) || !isSuppressed(f, suppressions))
                .collect(Collectors.toList());

        int suppressed = findings.size() - filtered.size();
        if (suppressed > 0) {
            log.info("[FP-Filter] suppressions.json 기준 {}건 억제됨", suppressed);
        }
        return filtered;
    }

    private static boolean isSuppressed(Finding f, List<SuppressionRule> rules) {
        for (SuppressionRule r : rules) {
            if (!r.matches(f)) continue;
            log.debug("[FP-Filter] 억제 적용: {} L{} ({}) — 이유: {}",
                    f.getFilePath(), f.getLineNumber(), f.getRuleId(), r.reason());
            return true;
        }
        return false;
    }
}
