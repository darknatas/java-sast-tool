package com.sast.validator;

import com.sast.SASTEngine;
import com.sast.engine.rules.RuleLoader;
import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * 내부 검증 에이전트 — SAST 엔진의 Rule Coverage 측정 (IV-3.1, CWE-367 등 전 규칙)
 *
 * 동작:
 *   1. security-rules.json에서 전체 규칙 로드
 *   2. 각 규칙에 해당하는 샘플 Java 파일 없으면 자동 생성 (src/test/resources/samples/)
 *   3. SASTEngine으로 각 샘플을 개별 분석
 *   4. 탐지 ruleId와 규칙 정의를 대조하여 결과 집계
 *   5. [Rule Coverage Report] 표 출력
 */
public class SastValidator {

    /** 샘플 파일 저장 디렉터리 (Maven 빌드 시 working-dir = 프로젝트 루트) */
    private static final Path SAMPLES_DIR =
            Paths.get("src/test/resources/samples");

    // ── 분석 방식 분류 ──────────────────────────────────────────────────────

    enum AnalysisType {
        TAINT("Taint"),
        SEQUENCE("Sequence"),
        PATTERN("Pattern"),
        NOT_SUPPORTED("미지원");

        final String label;
        AnalysisType(String label) { this.label = label; }
    }

    // ── 커버리지 결과 ────────────────────────────────────────────────────────

    private static class CoverageResult {
        final SecurityRule rule;
        final AnalysisType type;
        boolean sampleExists;
        boolean generated;
        Boolean detected;     // null = 미지원
        int     findingCount;
        String  errorMsg;

        CoverageResult(SecurityRule rule, AnalysisType type) {
            this.rule = rule;
            this.type = type;
        }
    }

    // ── Test Entry Point ────────────────────────────────────────────────────

    @Test
    void runCoverageReport() throws Exception {
        List<SecurityRule> rules = RuleLoader.loadFromClasspath("security-rules.json");
        Files.createDirectories(SAMPLES_DIR);

        SASTEngine engine = new SASTEngine();
        Map<String, CoverageResult> resultMap = new LinkedHashMap<>();

        for (SecurityRule rule : rules) {
            AnalysisType type = classifyRule(rule);
            CoverageResult cr  = new CoverageResult(rule, type);
            resultMap.put(rule.getRuleId(), cr);

            Path sampleFile = SAMPLES_DIR.resolve(sampleFileName(rule.getRuleId()));

            // 샘플 파일 없으면 자동 생성
            if (!Files.exists(sampleFile)) {
                String code = generateSample(rule);
                Files.writeString(sampleFile, code, StandardCharsets.UTF_8);
                cr.generated = true;
            }
            cr.sampleExists = Files.exists(sampleFile);

            // 탐지 가능한 분류만 엔진 실행
            if (type != AnalysisType.NOT_SUPPORTED && cr.sampleExists) {
                try {
                    List<Finding> findings = engine.analyzeFile(sampleFile.toFile());
                    String ruleId = rule.getRuleId();
                    cr.findingCount = (int) findings.stream()
                            .filter(f -> ruleId.equals(f.getRuleId()))
                            .count();
                    cr.detected = cr.findingCount > 0;
                } catch (Exception ex) {
                    cr.errorMsg = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                }
            }
        }

        printReport(resultMap);
    }

    // ── 규칙 분류 ───────────────────────────────────────────────────────────

    private AnalysisType classifyRule(SecurityRule rule) {
        if (rule.isTaintAnalysis())          return AnalysisType.TAINT;
        if (rule.isSequenceAnalysis())       return AnalysisType.SEQUENCE;
        if (!rule.getDangerousPatterns().isEmpty()) return AnalysisType.PATTERN;
        return AnalysisType.NOT_SUPPORTED;
    }

    // ── 샘플 파일명 ─────────────────────────────────────────────────────────

    private String sampleFileName(String ruleId) {
        // IV-1.1 → Sample_IV_1_1.java
        return "Sample_" + ruleId.replace("-", "_").replace(".", "_") + ".java";
    }

    // ── 샘플 코드 생성 ──────────────────────────────────────────────────────

    private String generateSample(SecurityRule rule) {
        String id        = rule.getRuleId();
        String className = sampleFileName(id).replace(".java", "");
        String specific  = specificTemplate(id, className);
        return specific != null ? specific : placeholderTemplate(className, rule);
    }

    /**
     * 엔진이 탐지할 수 있는 규칙별 최소 취약 코드 템플릿.
     * 탐지 근거: TaintAnalysisEngine.RULE_SINKS / SequenceAnalyzer CHECK_METHODS / PatternAnalyzer.
     */
    private String specificTemplate(String ruleId, String className) {
        return switch (ruleId) {

            // ── IV-1.1 SQL 삽입 (taint: getParameter → executeQuery) ─────────
            case "IV-1.1" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import java.sql.*;
                    public class %s {
                        void vuln(HttpServletRequest req, Statement stmt) throws Exception {
                            String id  = req.getParameter("id");
                            String sql = "SELECT * FROM users WHERE id='" + id + "'";
                            stmt.executeQuery(sql);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.2 코드삽입 (taint: getParameter → eval) ────────────────
            case "IV-1.2" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import javax.script.*;
                    public class %s {
                        void vuln(HttpServletRequest req, ScriptEngine engine) throws Exception {
                            String code = req.getParameter("code");
                            engine.eval(code);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.3 경로 조작 (taint: getParameter → openConnection) ──────
            case "IV-1.3" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import java.net.*;
                    public class %s {
                        void vuln(HttpServletRequest req) throws Exception {
                            String target = req.getParameter("url");
                            URL    url    = new URL(target);
                            url.openConnection();
                        }
                    }
                    """.formatted(className);

            // ── IV-1.4 XSS (taint: getParameter → println) ──────────────────
            case "IV-1.4" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import java.io.PrintWriter;
                    public class %s {
                        void vuln(HttpServletRequest req, PrintWriter out) {
                            String name = req.getParameter("name");
                            out.println(name);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.5 OS 명령어 삽입 (taint: getParameter → exec) ──────────
            case "IV-1.5" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    public class %s {
                        void vuln(HttpServletRequest req) throws Exception {
                            String cmd = req.getParameter("cmd");
                            Runtime.getRuntime().exec(cmd);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.7 URL 자동접속 연결 (taint: getParameter → sendRedirect) ─
            case "IV-1.7" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import javax.servlet.http.HttpServletResponse;
                    public class %s {
                        void vuln(HttpServletRequest req, HttpServletResponse resp) throws Exception {
                            String url = req.getParameter("redirect");
                            resp.sendRedirect(url);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.9 XML 삽입 (taint: getParameter → evaluate) ────────────
            case "IV-1.9" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import javax.xml.xpath.*;
                    public class %s {
                        void vuln(HttpServletRequest req, XPath xpath) throws Exception {
                            String user = req.getParameter("user");
                            xpath.evaluate("/users[@name='" + user + "']", (Object) null);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.10 LDAP 삽입 (taint: getParameter → search) ───────────
            case "IV-1.10" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import javax.naming.*;
                    import javax.naming.directory.*;
                    public class %s {
                        void vuln(HttpServletRequest req, DirContext ctx) throws Exception {
                            String user = req.getParameter("user");
                            ctx.search("dc=example,dc=com", "(uid=" + user + ")", new SearchControls());
                        }
                    }
                    """.formatted(className);

            // ── IV-1.12 SSRF (taint: getParameter → openConnection) ─────────
            case "IV-1.12" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import java.net.*;
                    public class %s {
                        void vuln(HttpServletRequest req) throws Exception {
                            String target = req.getParameter("url");
                            URL    url    = new URL(target);
                            url.openConnection();
                        }
                    }
                    """.formatted(className);

            // ── IV-1.13 HTTP 응답분할 (taint: getParameter → setHeader) ─────
            case "IV-1.13" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    import javax.servlet.http.HttpServletResponse;
                    public class %s {
                        void vuln(HttpServletRequest req, HttpServletResponse resp) {
                            String lang = req.getParameter("lang");
                            resp.setHeader("Content-Language", lang);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.15 보안기능 부적절 입력 (taint: getParameter → if-admin)
            case "IV-1.15" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    public class %s {
                        void vuln(HttpServletRequest req) {
                            String role = req.getParameter("role");
                            if ("admin".equals(role)) {
                                deleteAllRecords();
                            }
                        }
                        private void deleteAllRecords() {}
                    }
                    """.formatted(className);

            // ── IV-1.17 포맷 스트링 삽입 (taint: getParameter → format) ─────
            case "IV-1.17" -> """
                    package com.example.sample;
                    import javax.servlet.http.HttpServletRequest;
                    public class %s {
                        void vuln(HttpServletRequest req) {
                            String fmt    = req.getParameter("format");
                            String result = String.format(fmt, "arg");
                            System.out.println(result);
                        }
                    }
                    """.formatted(className);

            // ── IV-2.6 하드코드된 중요정보 (pattern: password = "...") ───────
            case "IV-2.6" -> """
                    package com.example.sample;
                    public class %s {
                        private static final String password = "hardcoded_secret_123";
                        private static final String apiKey   = "sk-prod-0987654321abcdef";
                    }
                    """.formatted(className);

            // ── IV-2.13 주석 중요정보 (pattern: //.*password) ───────────────
            case "IV-2.13" -> """
                    package com.example.sample;
                    public class %s {
                        // password = admin123
                        void connect() {
                            String host = "db.internal";
                        }
                    }
                    """.formatted(className);

            // ── IV-3.1 TOCTOU (sequence: exists → FileInputStream) ───────────
            case "IV-3.1" -> """
                    package com.example.sample;
                    import java.io.*;
                    public class %s {
                        void vuln(File f) throws IOException {
                            if (f.exists()) {
                                FileInputStream fis = new FileInputStream(f);
                                fis.close();
                            }
                        }
                    }
                    """.formatted(className);

            // ── IV-4.2 오류상황 대응 부재 (pattern: catch(...){}) ───────────
            case "IV-4.2" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln() {
                            try {
                                int x = 1 / 0;
                            } catch (Exception e) {}
                        }
                    }
                    """.formatted(className);

            // ── IV-5.5 역직렬화 (taint: getInputStream → readObject) ─────────
            case "IV-5.5" -> """
                    package com.example.sample;
                    import java.io.*;
                    import javax.servlet.http.HttpServletRequest;
                    public class %s {
                        void vuln(HttpServletRequest req) throws Exception {
                            InputStream raw = req.getInputStream();
                            ObjectInputStream ois = new ObjectInputStream(raw);
                            Object obj = ois.readObject();
                        }
                    }
                    """.formatted(className);

            // ── IV-6.2 디버그 코드 (pattern: System.out.print) ──────────────
            case "IV-6.2" -> """
                    package com.example.sample;
                    public class %s {
                        void debug(String msg) {
                            System.out.println("DEBUG: " + msg);
                        }
                    }
                    """.formatted(className);

            default -> null;
        };
    }

    /** 탐지 미지원 또는 탐지 불가 규칙용 플레이스홀더 */
    private String placeholderTemplate(String className, SecurityRule rule) {
        return """
                package com.example.sample;
                /**
                 * [자동 생성 샘플] %s — %s
                 * 구분: %s / %s
                 * 현재 엔진에서 자동 탐지가 구현되지 않은 규칙입니다.
                 */
                public class %s {
                    void placeholder() { }
                }
                """.formatted(
                rule.getRuleId(), rule.getName(),
                rule.getPart(), rule.getSection(),
                className);
    }

    // ── 리포트 출력 ─────────────────────────────────────────────────────────

    private void printReport(Map<String, CoverageResult> results) {
        String border  = "═".repeat(100);
        String divider = "─".repeat(100);

        System.out.println();
        System.out.println("╔" + border + "╗");
        System.out.println("║" + center("[Rule Coverage Report] — Java SAST Engine", 100) + "║");
        System.out.println("╠" + border + "╣");
        System.out.printf("║ %-10s ║ %-38s ║ %-9s ║ %-8s ║ %-22s ║%n",
                "Rule ID", "진단명", "분석방식", "샘플", "탐지결과");
        System.out.println("╠" + border + "╣");

        int totalDetectable = 0, totalDetected = 0, totalRules = results.size();
        String lastPart = "";

        for (CoverageResult cr : results.values()) {
            String part = cr.rule.getPart();
            if (!part.equals(lastPart)) {
                if (!lastPart.isEmpty()) System.out.println("║ " + divider + " ║");
                System.out.printf("║  %-97s ║%n",
                        "▶ " + part + " — " + cr.rule.getSection());
                lastPart = part;
            }

            String sampleStatus;
            if (!cr.sampleExists) {
                sampleStatus = "없음";
            } else if (cr.generated) {
                sampleStatus = "생성됨";
            } else {
                sampleStatus = "존재함";
            }

            String detectionStatus;
            if (cr.type == AnalysisType.NOT_SUPPORTED) {
                detectionStatus = "미지원";
            } else if (cr.errorMsg != null) {
                detectionStatus = "오류";
            } else if (Boolean.TRUE.equals(cr.detected)) {
                detectionStatus = "✓ 탐지 (" + cr.findingCount + "건)";
                totalDetected++;
                totalDetectable++;
            } else if (Boolean.FALSE.equals(cr.detected)) {
                detectionStatus = "✗ 미탐지";
                totalDetectable++;
            } else {
                detectionStatus = "—";
            }

            System.out.printf("║ %-10s ║ %-38s ║ %-9s ║ %-8s ║ %-22s ║%n",
                    cr.rule.getRuleId(),
                    truncate(cr.rule.getName(), 38),
                    cr.type.label,
                    sampleStatus,
                    detectionStatus);
        }

        System.out.println("╚" + border + "╝");
        System.out.println();

        double coverage = totalDetectable > 0 ? (double) totalDetected / totalDetectable * 100 : 0;
        System.out.printf(
                "  전체 규칙 수    : %d개%n" +
                "  탐지 구현 규칙  : %d개  (Taint / Sequence / Pattern)%n" +
                "  탐지 성공       : %d건%n" +
                "  탐지 실패       : %d건%n" +
                "  Rule 커버리지   : %.1f%%%n",
                totalRules, totalDetectable,
                totalDetected,
                totalDetectable - totalDetected,
                coverage);
        System.out.println();
        System.out.println("  ※ '미지원' 규칙은 현재 엔진에 탐지 로직이 구현되지 않은 설계단계(DS-*) 또는 ");
        System.out.println("     추가 분석기가 필요한 PART4 항목입니다.");
        System.out.println();
    }

    // ── 출력 유틸리티 ───────────────────────────────────────────────────────

    private String center(String s, int width) {
        int padding = (width - s.length()) / 2;
        return " ".repeat(Math.max(0, padding)) + s +
               " ".repeat(Math.max(0, width - s.length() - padding));
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }
}
