package com.sast.engine.pattern;

import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 정규식 기반 정적 분석 엔진 — dangerousPatterns 라인별 스캔
 *
 * 대상: taintAnalysis: false 규칙 (PART3 설계단계 + PART4 패턴 규칙)
 * 알고리즘: 소스파일을 라인 단위로 읽어 각 규칙의 dangerousPatterns 정규식과 매칭
 * 중복 방지: 동일 규칙+라인 조합은 한 건만 리포트
 */
public class PatternAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(PatternAnalyzer.class);

    /**
     * @param filePath 분석할 Java 소스 파일 절대 경로
     * @param rules    dangerousPatterns가 있는 규칙 목록 (없는 규칙은 내부에서 건너뜀)
     * @return 탐지된 Finding 목록
     */
    public List<Finding> analyze(String filePath, List<SecurityRule> rules) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(filePath));
        List<Finding> findings = new ArrayList<>();
        // (ruleId, lineNumber) 중복 방지 — 같은 규칙이 한 라인에서 여러 패턴에 매칭될 때
        Set<String> reported = new HashSet<>();

        for (SecurityRule rule : rules) {
            if (rule.getDangerousPatterns().isEmpty()) continue;

            List<Pattern> compiled = compilePatterns(rule);
            if (compiled.isEmpty()) continue;

            for (int i = 0; i < lines.size(); i++) {
                String lineText = lines.get(i);
                String dedupKey = rule.getRuleId() + ":" + (i + 1);

                // 주석 라인 건너뜀: 주석 처리된 코드에서 패턴 매칭 방지 (오탐 감소)
                // 대상: // 라인 주석, /* 블록 시작, * 블록 내부 라인
                if (isCommentLine(lineText)) {
                    log.debug("[PatternAnalyzer] 주석 라인 건너뜀: L{} {}", i + 1, lineText.trim());
                    continue;
                }

                for (Pattern pattern : compiled) {
                    Matcher m = pattern.matcher(lineText);
                    if (m.find() && reported.add(dedupKey)) {
                        int lineNo = i + 1;
                        findings.add(Finding.builder()
                                .ruleId(rule.getRuleId())
                                .ruleName(rule.getName())
                                .severity(Finding.Severity.valueOf(rule.getSeverity()))
                                .filePath(filePath)
                                .lineNumber(lineNo)
                                .vulnerableCode(lineText.trim())
                                .description(buildDescription(rule, pattern.pattern(), lineNo))
                                .taintFlows(Collections.emptyList())
                                .guideRef(rule.getGuideRef())
                                .cweIds(rule.getCwe())
                                .build());
                        log.debug("[PatternAnalyzer] {} L{} — {} ({})",
                                rule.getRuleId(), lineNo, lineText.trim(), pattern.pattern());
                        break; // 이 라인은 이미 보고됨 — 다음 라인으로
                    }
                }
            }
        }

        log.debug("[PatternAnalyzer] {} — {}건 탐지", filePath, findings.size());
        return findings;
    }

    /**
     * 라인이 순수 주석인지 판별 (블록 주석 내부·시작 / 라인 주석)
     * 인라인 주석(코드 뒤 //)은 완전 제외하지 않아 과도한 오탐 억제 방지
     */
    private boolean isCommentLine(String line) {
        String t = line.stripLeading();
        return t.startsWith("//")
                || t.startsWith("/*")
                || t.startsWith("* ")
                || t.equals("*/")
                || t.startsWith("**/");
    }

    private List<Pattern> compilePatterns(SecurityRule rule) {
        List<Pattern> compiled = new ArrayList<>();
        for (String patternStr : rule.getDangerousPatterns()) {
            try {
                compiled.add(Pattern.compile(patternStr));
            } catch (PatternSyntaxException e) {
                log.warn("[PatternAnalyzer] 잘못된 정규식 무시 (ruleId={}, pattern={}): {}",
                        rule.getRuleId(), patternStr, e.getMessage());
            }
        }
        return compiled;
    }

    private String buildDescription(SecurityRule rule, String matchedPattern, int lineNo) {
        String remediationHint = (rule.getRemediation() != null)
                ? rule.getRemediation().getDescription() : "";
        return String.format("[%s] L%d에서 위험 패턴이 탐지되었습니다. %s",
                rule.getRuleId(), lineNo, remediationHint.isEmpty() ? "" : "조치: " + remediationHint);
    }
}
