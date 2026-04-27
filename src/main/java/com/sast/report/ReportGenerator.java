package com.sast.report;

import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ReportGenerator — 탐지 결과를 Markdown / JSON / Console 형식으로 출력
 */
public class ReportGenerator {

    private static final Logger log = LoggerFactory.getLogger(ReportGenerator.class);

    private final RemediationService remediationService;

    public ReportGenerator(RemediationService remediationService) {
        this.remediationService = remediationService;
    }

    // ── Markdown 리포트 ───────────────────────────────────────────────────

    public String generateMarkdown(List<Finding> findings, String targetProject) {
        StringBuilder sb = new StringBuilder();

        sb.append("# Java 소스코드 보안약점 진단 리포트\n\n");
        sb.append("> 기준: 소프트웨어 보안약점 진단가이드 (2021), 행정안전부\n\n");
        sb.append("| 항목 | 내용 |\n");
        sb.append("|------|------|\n");
        sb.append("| **진단 대상** | ").append(targetProject).append(" |\n");
        sb.append("| **진단 일시** | ").append(
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")))
                .append(" |\n");
        sb.append("| **총 발견 건수** | ").append(findings.size()).append("건 |\n");

        Map<Finding.Severity, Long> severityCount = findings.stream()
                .collect(Collectors.groupingBy(Finding::getSeverity, Collectors.counting()));
        sb.append("| **위험도별** | ");
        for (Finding.Severity s : Finding.Severity.values()) {
            sb.append(s.toKorean()).append(": ")
              .append(severityCount.getOrDefault(s, 0L)).append("건  ");
        }
        sb.append("|\n\n");

        // 요약 테이블
        sb.append("---\n\n## 발견 요약\n\n");
        sb.append("| No | 진단항목 번호 | 약점명 | 위험도 | 파일 | 라인 |\n");
        sb.append("|----|-------------|--------|--------|------|------|\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append(String.format("| %d | `%s` | %s | %s | `%s` | %d |\n",
                    i + 1, f.getRuleId(), f.getRuleName(),
                    severityBadge(f.getSeverity()), shortPath(f.getFilePath()), f.getLineNumber()));
        }

        // 상세 리포트
        sb.append("\n---\n\n## 상세 진단 결과\n\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            RemediationService.RemediationResult remedy = remediationService.suggest(f);

            sb.append(String.format("### [%d] %s — %s\n\n", i + 1, f.getRuleId(), f.getRuleName()));

            sb.append("| 항목 | 내용 |\n|------|------|\n");
            sb.append("| **진단항목 번호** | `").append(f.getRuleId()).append("` |\n");
            sb.append("| **약점명** | ").append(f.getRuleName()).append(" |\n");
            sb.append("| **위험도** | ").append(severityBadge(f.getSeverity())).append(" |\n");
            sb.append("| **파일** | `").append(f.getFilePath()).append("` |\n");
            sb.append("| **라인** | ").append(f.getLineNumber()).append(" |\n");
            sb.append("| **CWE** | ").append(String.join(", ", f.getCweIds())).append(" |\n");
            sb.append("| **가이드 참조** | ").append(f.getGuideRef()).append(" |\n\n");

            sb.append("#### 탐지 근거\n\n");
            sb.append("> ").append(f.getDescription()).append("\n\n");

            if (f.getTaintFlows() != null && !f.getTaintFlows().isEmpty()) {
                sb.append("#### 오염 흐름 (Source → Propagator → Sink)\n\n");
                sb.append("```\n");
                f.getTaintFlows().forEach(flow -> sb.append(flow.toString()).append("\n"));
                sb.append("```\n\n");
            }

            sb.append("#### ❌ 취약한 코드\n\n");
            sb.append("```java\n// Line ").append(f.getLineNumber()).append("\n");
            sb.append(f.getVulnerableCode()).append("\n```\n\n");

            if (remedy.getSecurityPrinciple() != null && !remedy.getSecurityPrinciple().isBlank()) {
                sb.append("#### 보안 원칙\n\n");
                sb.append("> **").append(remedy.getSecurityPrinciple()).append("**\n\n");
            }

            sb.append("#### ✅ 권고 수정 코드\n\n");
            sb.append("```java\n").append(remedy.getRemediatedCode()).append("\n```\n\n");

            sb.append("#### 조치 설명\n\n");
            sb.append("> ").append(remedy.getExplanation()).append("\n\n");

            sb.append("#### 참고자료\n\n");
            remedy.getReferences().forEach(ref -> sb.append("- ").append(ref).append("\n"));
            sb.append("\n---\n\n");
        }

        log.info("[ReportGenerator] Markdown 리포트 생성 완료 ({}건)", findings.size());
        return sb.toString();
    }

    // ── JSON 리포트 ───────────────────────────────────────────────────────

    public String generateJson(List<Finding> findings, String targetProject) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"reportTitle\": \"Java 소스코드 보안약점 진단 리포트\",\n");
        sb.append("  \"standard\": \"소프트웨어 보안약점 진단가이드 (2021)\",\n");
        sb.append("  \"targetProject\": \"").append(targetProject).append("\",\n");
        sb.append("  \"generatedAt\": \"").append(LocalDateTime.now()).append("\",\n");
        sb.append("  \"totalFindings\": ").append(findings.size()).append(",\n");
        sb.append("  \"findings\": [\n");

        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            RemediationService.RemediationResult remedy = remediationService.suggest(f);

            sb.append("    {\n");
            sb.append("      \"no\": ").append(i + 1).append(",\n");
            sb.append("      \"ruleId\": \"").append(f.getRuleId()).append("\",\n");
            sb.append("      \"ruleName\": \"").append(f.getRuleName()).append("\",\n");
            sb.append("      \"severity\": \"").append(f.getSeverity()).append("\",\n");
            sb.append("      \"severityKorean\": \"").append(f.getSeverity().toKorean()).append("\",\n");
            sb.append("      \"filePath\": \"").append(escape(f.getFilePath())).append("\",\n");
            sb.append("      \"lineNumber\": ").append(f.getLineNumber()).append(",\n");
            sb.append("      \"cweIds\": [")
              .append(f.getCweIds().stream().map(c -> "\"" + c + "\"").collect(Collectors.joining(", ")))
              .append("],\n");
            sb.append("      \"description\": \"").append(escape(f.getDescription())).append("\",\n");
            sb.append("      \"vulnerableCode\": \"").append(escape(f.getVulnerableCode())).append("\",\n");

            if (f.getTaintFlows() != null && !f.getTaintFlows().isEmpty()) {
                sb.append("      \"taintFlows\": [\n");
                for (Finding.TaintFlow flow : f.getTaintFlows()) {
                    sb.append("        {\n");
                    sb.append("          \"source\": \"").append(escape(flow.getSourceExpression())).append("\",\n");
                    sb.append("          \"sourceLine\": ").append(flow.getSourceLine()).append(",\n");
                    sb.append("          \"propagators\": [")
                      .append(flow.getPropagators().stream()
                              .map(p -> "\"" + p + "\"").collect(Collectors.joining(", ")))
                      .append("],\n");
                    sb.append("          \"sink\": \"").append(escape(flow.getSinkExpression())).append("\",\n");
                    sb.append("          \"sinkLine\": ").append(flow.getSinkLine()).append("\n");
                    sb.append("        }\n");
                }
                sb.append("      ],\n");
            }

            sb.append("      \"remediatedCode\": \"").append(escape(remedy.getRemediatedCode())).append("\",\n");
            sb.append("      \"remediationExplanation\": \"").append(escape(remedy.getExplanation())).append("\",\n");
            sb.append("      \"guideRef\": \"").append(f.getGuideRef()).append("\"\n");
            sb.append("    }");
            if (i < findings.size() - 1) sb.append(",");
            sb.append("\n");
        }

        sb.append("  ]\n}");
        return sb.toString();
    }

    // ── Console Summary ───────────────────────────────────────────────────

    public void printConsoleSummary(List<Finding> findings) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("  Java SAST 보안약점 진단 결과");
        System.out.println("  기준: 소프트웨어 보안약점 진단가이드 (2021)");
        System.out.println("=".repeat(80));
        System.out.printf("  총 발견 건수: %d건%n%n", findings.size());
        System.out.printf("  %-10s %-30s %-10s %-30s %s%n",
                "Rule ID", "약점명", "위험도", "파일", "라인");
        System.out.println("  " + "-".repeat(90));
        findings.forEach(f -> System.out.printf("  %-10s %-30s %-10s %-30s %d%n",
                f.getRuleId(), f.getRuleName(),
                f.getSeverity().toKorean() + "(" + f.getSeverity() + ")",
                shortPath(f.getFilePath()), f.getLineNumber()));
        System.out.println("=".repeat(80) + "\n");
    }

    // ── Utility ───────────────────────────────────────────────────────────

    private String severityBadge(Finding.Severity s) {
        if (s == Finding.Severity.CRITICAL) return "🔴 치명(CRITICAL)";
        if (s == Finding.Severity.HIGH)     return "🟠 높음(HIGH)";
        if (s == Finding.Severity.MEDIUM)   return "🟡 중간(MEDIUM)";
        return "🟢 낮음(LOW)";
    }

    private String shortPath(String path) {
        if (path == null) return "";
        int idx = path.lastIndexOf('/');
        return idx >= 0 ? ".../" + path.substring(idx + 1) : path;
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
