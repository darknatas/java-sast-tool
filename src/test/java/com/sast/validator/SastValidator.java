package com.sast.validator;

import com.sast.SASTEngine;
import com.sast.engine.rules.RuleLoader;
import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;
import com.sast.remediation.RemediationService;
import com.sast.report.PdfReportGenerator;
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
        List<Finding> allFindings = new ArrayList<>();

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
                    allFindings.addAll(findings);
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
        generatePdfReport(allFindings);
    }

    private void generatePdfReport(List<Finding> findings) {
        Path pdfPath = Paths.get("target/sast-report.pdf");
        try {
            Files.createDirectories(pdfPath.getParent());
            RemediationService remService = new RemediationService();
            PdfReportGenerator pdfGen    = new PdfReportGenerator();
            byte[] pdfBytes = pdfGen.generateFromFindings(
                    findings, remService, "SastValidator Coverage Run");
            Files.write(pdfPath, pdfBytes);
            System.out.println("[PDF] PDF 리포트 생성 완료: " + pdfPath.toAbsolutePath());
        } catch (Exception e) {
            System.err.println("[PDF] PDF 생성 실패: " + e.getMessage());
            e.printStackTrace();
        }
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

            // ── DS-1.1 DBMS 조회 (pattern: executeQuery) ─────────────────────
            case "DS-1.1" -> """
                    package com.example.sample;
                    import java.sql.*;
                    public class %s {
                        void vuln(Statement stmt, String id) throws Exception {
                            String sql = "SELECT * FROM users WHERE id='" + id + "'";
                            stmt.executeQuery(sql);  // DS-1.1: SQL 바인딩 미적용
                        }
                    }
                    """.formatted(className);

            // ── DS-1.2 XML 조회 (pattern: xpath.evaluate) ─────────────────────
            case "DS-1.2" -> """
                    package com.example.sample;
                    import javax.xml.xpath.*;
                    public class %s {
                        void vuln(XPath xpath, String user) throws Exception {
                            xpath.evaluate("/users[@name='" + user + "']", (Object) null);
                        }
                    }
                    """.formatted(className);

            // ── DS-1.3 LDAP 조회 (pattern: DirContext) ────────────────────────
            case "DS-1.3" -> """
                    package com.example.sample;
                    import javax.naming.directory.*;
                    public class %s {
                        void vuln(DirContext ctx, String user) throws Exception {
                            ctx.search("dc=example,dc=com", "(uid=" + user + ")", new SearchControls());
                        }
                    }
                    """.formatted(className);

            // ── DS-1.4 OS 명령어 (pattern: Runtime.getRuntime().exec) ──────────
            case "DS-1.4" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln(String cmd) throws Exception {
                            Runtime.getRuntime().exec(cmd);  // DS-1.4: OS 명령어 직접 실행
                        }
                    }
                    """.formatted(className);

            // ── DS-1.5 웹 서비스 (pattern: out.print) ────────────────────────
            case "DS-1.5" -> """
                    package com.example.sample;
                    import java.io.PrintWriter;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req, HttpServletResponse response) throws Exception {
                            String name = req.getParameter("name");
                            PrintWriter out = response.getWriter();
                            out.print(name);  // DS-1.5: XSS 인코딩 미적용
                        }
                    }
                    """.formatted(className);

            // ── DS-1.6 CSRF (pattern: void doPost) ────────────────────────────
            case "DS-1.6" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s extends HttpServlet {
                        @Override
                        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
                            String amount = req.getParameter("amount");
                            processTransfer(amount);  // DS-1.6: CSRF 토큰 검증 없음
                        }
                        private void processTransfer(String amount) {}
                    }
                    """.formatted(className);

            // ── DS-1.7 HTTP 응답분할 (pattern: setHeader) ────────────────────
            case "DS-1.7" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req, HttpServletResponse resp) {
                            String lang = req.getParameter("lang");
                            resp.setHeader("Content-Language", lang);  // DS-1.7: CRLF 필터 없음
                        }
                    }
                    """.formatted(className);

            // ── DS-1.8 메모리 접근 (pattern: byte[], System.arraycopy) ─────────
            case "DS-1.8" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln(byte[] src, int offset, int length) {
                            byte[] dst = new byte[length];
                            System.arraycopy(src, offset, dst, 0, length);  // DS-1.8: 경계 검사 없음
                        }
                    }
                    """.formatted(className);

            // ── DS-1.9 보안기능 입력값 (pattern: getParameter.*role) ───────────
            case "DS-1.9" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req, HttpSession session) {
                            String role = req.getParameter("role");  // DS-1.9: 외부 입력으로 보안결정
                            session.setAttribute("userRole", role);
                        }
                    }
                    """.formatted(className);

            // ── DS-1.10 파일 업로드 (pattern: getPart) ─────────────────────────
            case "DS-1.10" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req) throws Exception {
                            Part part = req.getPart("file");  // DS-1.10: 파일 검증 미설계
                            part.write("/upload/" + part.getSubmittedFileName());
                        }
                    }
                    """.formatted(className);

            // ── DS-2.1 인증 (pattern: HttpSession) ─────────────────────────────
            case "DS-2.1" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void processRequest(HttpServletRequest req) {
                            HttpSession session = req.getSession(false);
                            performSensitiveAction();  // DS-2.1: 인증 상태 확인 없이 실행
                        }
                        private void performSensitiveAction() {}
                    }
                    """.formatted(className);

            // ── DS-2.2 인증 횟수 제한 (pattern: loginAttempt) ──────────────────
            case "DS-2.2" -> """
                    package com.example.sample;
                    public class %s {
                        private int loginAttempt = 0;  // DS-2.2: 횟수 제한 미설계
                        boolean authenticate(String user, String pass) {
                            loginAttempt++;
                            return checkCredentials(user, pass);
                        }
                        private boolean checkCredentials(String u, String p) { return true; }
                    }
                    """.formatted(className);

            // ── DS-2.3 비밀번호 관리 (pattern: password = ") ──────────────────
            case "DS-2.3" -> """
                    package com.example.sample;
                    public class %s {
                        private static final String password = "admin123";  // DS-2.3: 하드코드 비밀번호
                        void connect() {
                            String user = "admin";
                        }
                    }
                    """.formatted(className);

            // ── DS-2.4 접근통제 (pattern: setReadable, setWritable) ────────────
            case "DS-2.4" -> """
                    package com.example.sample;
                    import java.io.*;
                    public class %s {
                        void vuln(File sensitiveFile) {
                            sensitiveFile.setReadable(true, false);  // DS-2.4: 전체 읽기 허용
                            sensitiveFile.setWritable(true, false);  // DS-2.4: 전체 쓰기 허용
                        }
                    }
                    """.formatted(className);

            // ── DS-2.5 암호키 관리 (pattern: KeyGenerator.getInstance) ─────────
            case "DS-2.5" -> """
                    package com.example.sample;
                    import javax.crypto.*;
                    import javax.crypto.spec.*;
                    public class %s {
                        void vuln() throws Exception {
                            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                            SecretKey key = keyGen.generateKey();
                            SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), "AES");
                        }
                    }
                    """.formatted(className);

            // ── DS-2.6 암호연산 (pattern: Cipher.getInstance) ──────────────────
            case "DS-2.6" -> """
                    package com.example.sample;
                    import javax.crypto.*;
                    import java.security.*;
                    public class %s {
                        void vuln(byte[] data) throws Exception {
                            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                            MessageDigest md = MessageDigest.getInstance("MD5");  // DS-2.6: 취약 알고리즘
                        }
                    }
                    """.formatted(className);

            // ── DS-2.7 중요정보 저장 (pattern: new Cookie) ─────────────────────
            case "DS-2.7" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletResponse resp, String userId) {
                            Cookie cookie = new Cookie("userId", userId);  // DS-2.7: 보안속성 미설정
                            resp.addCookie(cookie);
                        }
                    }
                    """.formatted(className);

            // ── DS-2.8 중요정보 전송 (pattern: HttpURLConnection) ──────────────
            case "DS-2.8" -> """
                    package com.example.sample;
                    import java.net.*;
                    public class %s {
                        void vuln() throws Exception {
                            HttpURLConnection conn = (HttpURLConnection)
                                new URL("http://api.example.com/data").openConnection();
                            conn.setRequestMethod("POST");  // DS-2.8: 평문 전송
                        }
                    }
                    """.formatted(className);

            // ── DS-3.1 예외처리 (pattern: e.printStackTrace) ───────────────────
            case "DS-3.1" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln() {
                            try {
                                int x = Integer.parseInt("abc");
                            } catch (NumberFormatException e) {  // DS-3.1: 예외 정보 노출
                                e.printStackTrace();
                            }
                        }
                    }
                    """.formatted(className);

            // ── DS-4.1 세션통제 (pattern: setMaxInactiveInterval) ──────────────
            case "DS-4.1" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req) {
                            HttpSession session = req.getSession(true);
                            session.setMaxInactiveInterval(86400);  // DS-4.1: 세션 만료 미설계
                        }
                    }
                    """.formatted(className);

            // ── IV-1.6 파일 업로드 (pattern: getPart) ──────────────────────────
            case "IV-1.6" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req) throws Exception {
                            Part filePart = req.getPart("file");  // IV-1.6: 파일 확장자 검증 없음
                            String filename = filePart.getSubmittedFileName();
                            filePart.write("/upload/" + filename);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.8 XXE (pattern: DocumentBuilderFactory) ───────────────────
            case "IV-1.8" -> """
                    package com.example.sample;
                    import javax.xml.parsers.*;
                    import java.io.*;
                    public class %s {
                        void vuln(InputStream input) throws Exception {
                            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                            // IV-1.8: 외부 엔티티 비활성화 없음
                            factory.newDocumentBuilder().parse(input);
                        }
                    }
                    """.formatted(className);

            // ── IV-1.11 CSRF (pattern: void doPost(HttpServletRequest) ──────────
            case "IV-1.11" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s extends HttpServlet {
                        @Override
                        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
                            // IV-1.11: CSRF 토큰 검증 없이 중요기능 처리
                            String action = req.getParameter("action");
                            executeAction(action);
                        }
                        private void executeAction(String a) {}
                    }
                    """.formatted(className);

            // ── IV-1.14 정수형 오버플로우 (pattern: Integer.parseInt) ───────────
            case "IV-1.14" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req) {
                            int size = Integer.parseInt(req.getParameter("size"));
                            byte[] buffer = new byte[size * 2];  // IV-1.14: 오버플로우 검사 없음
                        }
                    }
                    """.formatted(className);

            // ── IV-1.16 메모리 버퍼 (pattern: System.arraycopy) ─────────────────
            case "IV-1.16" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln(byte[] src, int userOffset, int userLength) {
                            byte[] dst = new byte[1024];
                            System.arraycopy(src, userOffset, dst, 0, userLength);
                        }
                    }
                    """.formatted(className);

            // ── IV-2.1 인증 부재 (pattern: void doGet(HttpServletRequest) ───────
            case "IV-2.1" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s extends HttpServlet {
                        @Override
                        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
                            // IV-2.1: 인증 확인 없이 관리자 기능 실행
                            executeAdminAction(req.getParameter("action"));
                        }
                        private void executeAdminAction(String a) {}
                    }
                    """.formatted(className);

            // ── IV-2.2 부적절한 인가 (pattern: isAdmin()) ───────────────────────
            case "IV-2.2" -> """
                    package com.example.sample;
                    public class %s {
                        private String userRole = "user";
                        boolean isAdmin() { return "admin".equals(userRole); }
                        void sensitiveAction() {
                            if (isAdmin()) {  // IV-2.2: 서버 권한 검증 미흡
                                deleteAllData();
                            }
                        }
                        private void deleteAllData() {}
                    }
                    """.formatted(className);

            // ── IV-2.3 잘못된 권한 설정 (pattern: setReadable(true) ──────────────
            case "IV-2.3" -> """
                    package com.example.sample;
                    import java.io.*;
                    public class %s {
                        void vuln(File sensitiveFile) {
                            sensitiveFile.setReadable(true, false);  // IV-2.3: 전체 읽기 권한 부여
                            sensitiveFile.setWritable(true, false);  // IV-2.3: 전체 쓰기 권한 부여
                        }
                    }
                    """.formatted(className);

            // ── IV-2.4 취약한 암호화 (pattern: getInstance.*DES) ────────────────
            case "IV-2.4" -> """
                    package com.example.sample;
                    import javax.crypto.*;
                    public class %s {
                        void vuln(byte[] data, javax.crypto.spec.SecretKeySpec key) throws Exception {
                            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                            cipher.init(Cipher.ENCRYPT_MODE, key);  // IV-2.4: 취약한 DES 알고리즘
                            cipher.doFinal(data);
                        }
                    }
                    """.formatted(className);

            // ── IV-2.5 암호화되지 않은 중요정보 (pattern: password.*getParameter) ─
            case "IV-2.5" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletRequest req) {
                            String password = req.getParameter("password");  // IV-2.5: 평문 비밀번호 처리
                            storeUser("admin", password);
                        }
                        private void storeUser(String u, String p) {}
                    }
                    """.formatted(className);

            // ── IV-2.7 키 길이 부족 (pattern: .initialize(512)) ─────────────────
            case "IV-2.7" -> """
                    package com.example.sample;
                    import java.security.*;
                    public class %s {
                        void vuln() throws Exception {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                            kpg.initialize(512);  // IV-2.7: RSA 512비트는 취약한 키 길이
                            KeyPair keyPair = kpg.generateKeyPair();
                        }
                    }
                    """.formatted(className);

            // ── IV-2.8 부적절한 난수 (pattern: new Random()) ────────────────────
            case "IV-2.8" -> """
                    package com.example.sample;
                    import java.util.Random;
                    public class %s {
                        String generateToken() {
                            Random rng = new Random();  // IV-2.8: 예측 가능한 난수
                            return Integer.toHexString(rng.nextInt());
                        }
                    }
                    """.formatted(className);

            // ── IV-2.9 취약한 비밀번호 (pattern: password.length() <) ─────────────
            case "IV-2.9" -> """
                    package com.example.sample;
                    public class %s {
                        boolean isValidPassword(String password) {
                            if (password.length() < 4) {  // IV-2.9: 최소 길이 너무 짧음
                                return false;
                            }
                            return true;
                        }
                    }
                    """.formatted(className);

            // ── IV-2.10 전자서명 (pattern: Signature.getInstance) ───────────────
            case "IV-2.10" -> """
                    package com.example.sample;
                    import java.security.*;
                    public class %s {
                        void vuln(byte[] data, PrivateKey key) throws Exception {
                            Signature sig = Signature.getInstance("SHA1withRSA");
                            sig.initSign(key);
                            sig.update(data);
                            byte[] signature = sig.sign();  // IV-2.10: 서명 검증 없이 사용
                        }
                    }
                    """.formatted(className);

            // ── IV-2.11 인증서 유효성 (pattern: X509TrustManager) ───────────────
            case "IV-2.11" -> """
                    package com.example.sample;
                    import javax.net.ssl.*;
                    import java.security.cert.*;
                    public class %s {
                        void vuln() throws Exception {
                            TrustManager[] trustAll = new TrustManager[] {
                                new X509TrustManager() {  // IV-2.11: 모든 인증서 신뢰
                                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                                    public X509Certificate[] getAcceptedIssuers() { return null; }
                                }
                            };
                        }
                    }
                    """.formatted(className);

            // ── IV-2.12 쿠키 정보 노출 (pattern: new Cookie) ────────────────────
            case "IV-2.12" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        void vuln(HttpServletResponse resp, String sessionId) {
                            Cookie cookie = new Cookie("JSESSIONID", sessionId);
                            // IV-2.12: HttpOnly/Secure 속성 미설정
                            resp.addCookie(cookie);
                        }
                    }
                    """.formatted(className);

            // ── IV-2.14 솔트 없는 해시 (pattern: MessageDigest.getInstance.*MD5) ─
            case "IV-2.14" -> """
                    package com.example.sample;
                    import java.security.*;
                    public class %s {
                        byte[] vuln(String password) throws Exception {
                            MessageDigest md = MessageDigest.getInstance("MD5");
                            return md.digest(password.getBytes());  // IV-2.14: 솔트 없는 MD5 해시
                        }
                    }
                    """.formatted(className);

            // ── IV-2.15 무결성 검사 없는 다운로드 (pattern: openStream) ───────────
            case "IV-2.15" -> """
                    package com.example.sample;
                    import java.net.*;
                    import java.io.*;
                    public class %s {
                        void vuln(String url) throws Exception {
                            InputStream in = new URL(url).openStream();  // IV-2.15: 체크섬 검증 없음
                            byte[] data = in.readAllBytes();
                        }
                    }
                    """.formatted(className);

            // ── IV-2.16 반복 인증시도 제한 부재 (pattern: authenticate) ──────────
            case "IV-2.16" -> """
                    package com.example.sample;
                    public class %s {
                        boolean authenticate(String user, String pass) {
                            return checkDB(user, pass);  // IV-2.16: 로그인 시도 횟수 제한 없음
                        }
                        private boolean checkDB(String u, String p) { return false; }
                    }
                    """.formatted(className);

            // ── IV-3.2 무한루프 (pattern: while(true)) ──────────────────────────
            case "IV-3.2" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln() {
                            while (true) {  // IV-3.2: 종료 조건 없는 무한루프
                                processNext();
                            }
                        }
                        private void processNext() {}
                    }
                    """.formatted(className);

            // ── IV-4.1 오류 메시지 정보노출 (pattern: e.printStackTrace) ──────────
            case "IV-4.1" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln() {
                            try {
                                riskyOperation();
                            } catch (Exception e) {
                                e.printStackTrace();  // IV-4.1: 시스템 정보 노출
                            }
                        }
                        private void riskyOperation() throws Exception {}
                    }
                    """.formatted(className);

            // ── IV-4.3 부적절한 예외처리 (pattern: catch(Exception) ──────────────
            case "IV-4.3" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln() {
                            try {
                                riskyOperation();
                            } catch (Exception e) {  // IV-4.3: 너무 넓은 예외 타입 사용
                                handleError(e);
                            }
                        }
                        private void riskyOperation() throws Exception {}
                        private void handleError(Exception e) {}
                    }
                    """.formatted(className);

            // ── IV-5.1 Null Pointer 역참조 (pattern: .get().word) ────────────────
            case "IV-5.1" -> """
                    package com.example.sample;
                    import java.util.Optional;
                    public class %s {
                        void vuln(Optional<String> optional) {
                            String value = optional.get().trim();  // IV-5.1: null 체크 없이 get() 사용
                            System.out.println(value);
                        }
                    }
                    """.formatted(className);

            // ── IV-5.2 자원 해제 부재 (pattern: new FileInputStream) ────────────
            case "IV-5.2" -> """
                    package com.example.sample;
                    import java.io.*;
                    public class %s {
                        void vuln(File file) throws Exception {
                            FileInputStream fis = new FileInputStream(file);
                            int data = fis.read();  // IV-5.2: try-with-resources 미사용
                        }
                    }
                    """.formatted(className);

            // ── IV-5.3 해제된 자원 사용 (pattern: .close();) ────────────────────
            case "IV-5.3" -> """
                    package com.example.sample;
                    import java.io.*;
                    public class %s {
                        void vuln(File file) throws Exception {
                            FileInputStream fis = new FileInputStream(file);
                            int first = fis.read();
                            fis.close();   // IV-5.3: 자원 해제 후 재사용 위험
                            int second = fis.read();
                        }
                    }
                    """.formatted(className);

            // ── IV-5.4 미초기화 변수 (pattern: private int var;) ─────────────────
            case "IV-5.4" -> """
                    package com.example.sample;
                    public class %s {
                        private int counter;      // IV-5.4: 명시적 초기화 없음
                        private String state;     // IV-5.4: 명시적 초기화 없음
                        private Object context;   // IV-5.4: 명시적 초기화 없음
                        void process() {
                            counter++;
                        }
                    }
                    """.formatted(className);

            // ── IV-6.1 세션 데이터 노출 (pattern: static.*HttpSession) ──────────
            case "IV-6.1" -> """
                    package com.example.sample;
                    import javax.servlet.http.*;
                    public class %s {
                        private static HttpSession sharedSession;  // IV-6.1: 스레드 간 세션 공유
                        void setSession(HttpSession session) {
                            sharedSession = session;
                        }
                    }
                    """.formatted(className);

            // ── IV-6.3 Private 배열 반환 (pattern: public int[] getX()) ──────────
            case "IV-6.3" -> """
                    package com.example.sample;
                    public class %s {
                        private int[] sensitiveData = {1, 2, 3};
                        public int[] getSensitiveData() {  // IV-6.3: private 배열 직접 반환
                            return sensitiveData;
                        }
                    }
                    """.formatted(className);

            // ── IV-6.4 Private 배열에 Public 데이터 (pattern: this.x = y;) ───────
            case "IV-6.4" -> """
                    package com.example.sample;
                    public class %s {
                        private int[] data;
                        public void setData(int[] input) {
                            this.data = input;  // IV-6.4: 방어적 복사 없이 직접 할당
                        }
                    }
                    """.formatted(className);

            // ── IV-7.1 DNS lookup 보안결정 (pattern: InetAddress.getByName) ──────
            case "IV-7.1" -> """
                    package com.example.sample;
                    import java.net.*;
                    public class %s {
                        boolean isTrustedHost(String host) throws Exception {
                            String resolved = InetAddress.getByName(host).getHostName();
                            return resolved.endsWith(".trusted.com");  // IV-7.1: DNS 역조회 의존
                        }
                    }
                    """.formatted(className);

            // ── IV-7.2 취약한 API (pattern: Runtime.exec) ───────────────────────
            case "IV-7.2" -> """
                    package com.example.sample;
                    public class %s {
                        void vuln(String cmd) throws Exception {
                            Runtime.exec(cmd);  // IV-7.2: 취약한 API 직접 사용
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
