package com.sast.remediation;

import com.sast.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RemediationService — 탐지된 보안약점에 대한 수정 코드 자동 생성
 * 규칙별 Contextual Suggestion: 실제 변수명을 수정 템플릿에 삽입
 */
public class RemediationService {

    private static final Logger log = LoggerFactory.getLogger(RemediationService.class);

    public RemediationResult suggest(Finding finding) {
        String strategy = resolveStrategy(finding.getRuleId());
        log.debug("[Remediation] {} → 전략: {}", finding.getRuleId(), strategy);

        if ("USE_PREPARED_STATEMENT".equals(strategy))   return remediateSqlInjection(finding);
        if ("PATH_CANONICALIZATION".equals(strategy))    return remediatePathTraversal(finding);
        if ("OUTPUT_ENCODING".equals(strategy))          return remediateXss(finding);
        if ("AVOID_OS_COMMAND".equals(strategy))         return remediateOsCommand(finding);
        if ("FILE_EXTENSION_WHITELIST".equals(strategy)) return remediateFileUpload(finding);
        if ("GENERIC_ERROR_MESSAGE".equals(strategy))    return remediateErrorExposure(finding);
        if ("SECURE_RANDOM".equals(strategy))            return remediateWeakRandom(finding);
        if ("DISABLE_XML_ENTITY".equals(strategy))       return remediateXxe(finding);
        if ("CRLF_REMOVAL".equals(strategy))             return remediateCrLf(finding);
        if ("SAFE_DESERIALIZATION".equals(strategy))     return remediateDeserialization(finding);
        if ("ATOMIC_FILE_OPERATION".equals(strategy))   return remediateToctou(finding);
        return remediateGeneric(finding);
    }

    // ── [IV-1.1] SQL 삽입 ────────────────────────────────────────────────

    private RemediationResult remediateSqlInjection(Finding finding) {
        String var = extractTaintedVariable(finding);
        SqlQueryContext ctx = parseSqlContext(finding.getVulnerableCode());

        String code =
            "// [수정] IV-1.1 SQL 삽입 방지: PreparedStatement 사용\n" +
            "//\n" +
            "// ▶ 취약 원인: 외부 입력값을 SQL 문자열 연결(+)로 직접 포함\n" +
            "// ▶ 보안 원칙: SQL 구조(쿼리 템플릿)와 데이터(파라미터)를 완전히 분리\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import java.sql.Connection;\n" +
            "//   import java.sql.PreparedStatement;\n" +
            "//   import java.sql.ResultSet;\n" +
            "//   import java.sql.SQLException;\n" +
            "\n" +
            "// ── Step 1. SQL 템플릿 — 입력값 위치를 '?'로 고정 ──────────────────\n" +
            "// ❌ 취약: \"" + finding.getVulnerableCode().replace("\"", "\\\"") + "\"\n" +
            "// ✅ 안전: 쿼리 구조가 파싱 시점에 확정되어 SQL 구조 변경 불가\n" +
            "String sql = \"" + ctx.safeSqlTemplate + "\";\n" +
            "\n" +
            "// ── Step 2. PreparedStatement 생성 (try-with-resources) ──────────\n" +
            "try (Connection con = dataSource.getConnection();\n" +
            "     PreparedStatement pstmt = con.prepareStatement(sql)) {\n" +
            "\n" +
            "    // ── Step 3. 파라미터 바인딩 — 입력값을 '순수 데이터'로만 처리 ──\n" +
            "    // setString()이 특수문자(', \", --, ;, /*)를 자동 이스케이프함\n" +
            "    pstmt.setString(1, " + var + ");   // 첫 번째 '?' 위치에 바인딩\n" +
            "    // 파라미터가 여러 개라면 순서대로 추가:\n" +
            "    // pstmt.setInt(2, pageSize);\n" +
            "    // pstmt.setString(3, orderBy);\n" +
            "\n" +
            "    // ── Step 4. 쿼리 실행 ───────────────────────────────────────\n" +
            "    try (ResultSet rs = pstmt.executeQuery()) {\n" +
            "        while (rs.next()) {\n" +
            "            // ... 결과 처리 로직\n" +
            "        }\n" +
            "    }\n" +
            "\n" +
            "// ── Step 5. 오류 처리 — 상세 정보는 로그에만 기록 (IV-4.1) ────\n" +
            "} catch (SQLException e) {\n" +
            "    log.error(\"[DB] 쿼리 실행 오류: {}\", e.getMessage(), e);\n" +
            "    throw new RuntimeException(\"데이터 조회 중 오류가 발생했습니다.\", e);\n" +
            "}\n" +
            "\n" +
            "// ── [대안] MyBatis 사용 환경: ${ } 대신 #{ } 사용 ──────────────\n" +
            "// ❌ 취약 (Mapper XML): WHERE b_gubun = '${" + var + "}'\n" +
            "// ✅ 안전 (Mapper XML): WHERE b_gubun = #{" + var + "}";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("USE_PREPARED_STATEMENT")
                .securityPrinciple("SQL 구조(쿼리 템플릿)와 데이터(파라미터)를 분리하면 " +
                    "외부 입력값이 SQL 문법으로 해석되지 않습니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "PreparedStatement를 사용하면 SQL 쿼리 구조가 컴파일 시점에 고정됩니다. " +
                    "외부 입력값 '" + var + "'는 데이터로만 처리되어 SQL 구조를 변경할 수 없습니다. " +
                    "MyBatis 환경에서는 '${}'를 '#{}' 바인딩 파라미터로 교체하세요. " +
                    "가이드 참조: PART4 제1절 1항 SQL 삽입 (p.180-193)")
                .references(Arrays.asList(
                    "PART4 제1절 1항 (p.180-193)",
                    "CWE-89: SQL Injection",
                    "OWASP SQL Injection Prevention Cheat Sheet",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"))
                .build();
    }

    // ── [IV-1.3] 경로 조작 ───────────────────────────────────────────────

    private RemediationResult remediatePathTraversal(Finding finding) {
        String var     = extractTaintedVariable(finding);
        String baseDir = extractBaseDirectory(finding.getVulnerableCode());

        String code =
            "// [수정] IV-1.3 경로 조작 및 자원 삽입 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: 외부 입력 파일명에 '../', '..\\'가 포함되면 허용 디렉터리 탈출 가능\n" +
            "// ▶ 보안 원칙: getCanonicalPath()로 경로 정규화 후 허용 범위를 검증\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import java.io.File;\n" +
            "//   import java.io.FileInputStream;\n" +
            "//   import java.io.IOException;\n" +
            "//   import java.util.Set;\n" +
            "\n" +
            "// ── Step 1. 입력값 null / 빈 값 검증 ──────────────────────────────\n" +
            "String " + var + " = request.getParameter(\"" + var + "\");\n" +
            "if (" + var + " == null || " + var + ".isBlank()) {\n" +
            "    throw new IllegalArgumentException(\"파일명이 제공되지 않았습니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 2. 화이트리스트 문자 검증 (영문·숫자·하이픈·점만 허용) ──\n" +
            "// 경로 구분자 및 특수문자를 사전에 차단\n" +
            "if (!" + var + ".matches(\"^[a-zA-Z0-9._-]{1,255}$\")) {\n" +
            "    log.warn(\"[SECURITY] 비정상 파일명 입력 감지: {}\", " + var + ");\n" +
            "    throw new SecurityException(\"허용되지 않는 파일명 형식입니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 3. 허용 확장자(화이트리스트) 검증 ─────────────────────\n" +
            "int dotIdx = " + var + ".lastIndexOf('.');\n" +
            "if (dotIdx < 0) throw new SecurityException(\"확장자가 없는 파일은 허용되지 않습니다.\");\n" +
            "String ext = " + var + ".substring(dotIdx + 1).toLowerCase();\n" +
            "Set<String> allowedExt = Set.of(\"pdf\", \"jpg\", \"png\", \"docx\");\n" +
            "if (!allowedExt.contains(ext)) {\n" +
            "    throw new SecurityException(\"허용되지 않는 파일 형식: \" + ext);\n" +
            "}\n" +
            "\n" +
            "// ── Step 4. 정규화 경로 검증 — 허용 디렉터리 범위 내 확인 ───────\n" +
            "// getCanonicalFile()이 '../', './', 심볼릭 링크를 모두 해소\n" +
            "File baseDir = new File(\"" + baseDir + "\").getCanonicalFile();\n" +
            "File target  = new File(baseDir, " + var + ").getCanonicalFile();\n" +
            "\n" +
            "// toPath().startsWith()가 부분 디렉터리명 혼동을 방지 (예: /data vs /data2)\n" +
            "if (!target.toPath().startsWith(baseDir.toPath())) {\n" +
            "    log.warn(\"[SECURITY] 경로 순회 시도 감지 — 입력: {}, 정규화: {}\",\n" +
            "             " + var + ", target.getPath());\n" +
            "    throw new SecurityException(\"허용되지 않은 경로 접근입니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 5. 검증된 경로로 파일 접근 ──────────────────────────────\n" +
            "try (FileInputStream fis = new FileInputStream(target)) {\n" +
            "    // ... 파일 처리 로직\n" +
            "} catch (IOException e) {\n" +
            "    log.error(\"[FileAccess] 파일 읽기 오류: {}\", target.getPath(), e);\n" +
            "    throw new RuntimeException(\"파일을 읽을 수 없습니다.\", e);\n" +
            "}";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("PATH_CANONICALIZATION")
                .securityPrinciple("경로 정규화(canonicalize) 후 결과 경로가 허용된 기본 디렉터리 내부에 있는지 검증합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "외부 입력값 '" + var + "'에서 화이트리스트 문자 검증 → 확장자 검증 → getCanonicalPath() 정규화 → " +
                    "허용 디렉터리 경계 검증의 4단계 방어를 적용합니다. " +
                    "String.startsWith() 대신 Path.startsWith()를 사용해 '/data2'가 '/data'로 오인되는 문제를 방지합니다. " +
                    "가이드 참조: PART4 제1절 3항 경로 조작 및 자원 삽입 (p.201-210)")
                .references(Arrays.asList(
                    "PART4 제1절 3항 (p.201-210)",
                    "CWE-22: Path Traversal",
                    "CWE-99: Resource Injection",
                    "OWASP Path Traversal Prevention Cheat Sheet"))
                .build();
    }

    // ── [IV-1.4] XSS ─────────────────────────────────────────────────────

    private RemediationResult remediateXss(Finding finding) {
        String var = extractTaintedVariable(finding);

        String code =
            "// [수정] IV-1.4 크로스사이트 스크립트(XSS) 방지: 컨텍스트별 출력 인코딩\n" +
            "//\n" +
            "// ▶ 취약 원인: 사용자 입력값을 HTML에 그대로 출력 — <script> 등 실행 가능\n" +
            "// ▶ 보안 원칙: 출력 컨텍스트(HTML body / 속성 / JS / URL)에 맞는 인코딩 적용\n" +
            "//\n" +
            "// 필요 dependency (pom.xml):\n" +
            "//   <!-- OWASP Java Encoder -->\n" +
            "//   <dependency>\n" +
            "//     <groupId>org.owasp.encoder</groupId>\n" +
            "//     <artifactId>encoder</artifactId>\n" +
            "//     <version>1.2.3</version>\n" +
            "//   </dependency>\n" +
            "\n" +
            "// ── Step 1. 입력값 수신 ───────────────────────────────────────────\n" +
            "String " + var + " = request.getParameter(\"" + var + "\");\n" +
            "if (" + var + " == null) " + var + " = \"\";\n" +
            "\n" +
            "// ── Step 2. 컨텍스트별 출력 인코딩 선택 ────────────────────────\n" +
            "\n" +
            "// [방법 A] HTML Body 컨텍스트 — 가장 일반적\n" +
            "// OWASP Java Encoder (권장): <, >, &, \", ' 등 5개 특수문자 인코딩\n" +
            "String safeHtml_" + var + " = org.owasp.encoder.Encode.forHtml(" + var + ");\n" +
            "out.println(safeHtml_" + var + ");\n" +
            "\n" +
            "// [방법 B] HTML 속성 컨텍스트 (value=\"...\" 등)\n" +
            "String safeAttr_" + var + " = org.owasp.encoder.Encode.forHtmlAttribute(" + var + ");\n" +
            "// <input value=\"" + "\" + safeAttr_" + var + " + \"\">\n" +
            "\n" +
            "// [방법 C] JavaScript 컨텍스트\n" +
            "String safeJs_" + var + " = org.owasp.encoder.Encode.forJavaScript(" + var + ");\n" +
            "// var x = '" + "' + safeJs_" + var + " + ''\n" +
            "\n" +
            "// [방법 D] URL 파라미터 컨텍스트\n" +
            "String safeUrl_" + var + " = java.net.URLEncoder.encode(" + var + ", java.nio.charset.StandardCharsets.UTF_8);\n" +
            "\n" +
            "// [방법 E] Spring MVC 환경 — Spring의 HtmlUtils 활용\n" +
            "// String safeHtml_" + var + " = org.springframework.web.util.HtmlUtils.htmlEscape(" + var + ");\n" +
            "\n" +
            "// ── Step 3. CSP(Content Security Policy) 헤더 추가 (심층 방어) ─\n" +
            "// 인코딩만으로는 부족한 경우 브라우저 수준에서도 스크립트 실행 제한\n" +
            "response.setHeader(\"Content-Security-Policy\",\n" +
            "    \"default-src 'self'; script-src 'self'; object-src 'none';\");";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("OUTPUT_ENCODING")
                .securityPrinciple("출력 컨텍스트(HTML/속성/JS/URL)에 맞는 인코딩을 적용해 " +
                    "사용자 입력이 코드로 해석되지 않도록 합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "사용자 입력값 '" + var + "'을 HTML 출력 전 컨텍스트에 맞는 인코딩으로 처리합니다. " +
                    "HTML Body는 Encode.forHtml(), 속성은 Encode.forHtmlAttribute(), JS는 Encode.forJavaScript()를 사용하세요. " +
                    "CSP 헤더를 추가하면 인코딩 누락 시 브라우저 수준에서도 실행을 차단합니다. " +
                    "가이드 참조: PART4 제1절 4항 크로스사이트 스크립트 (p.211-222)")
                .references(Arrays.asList(
                    "PART4 제1절 4항 (p.211-222)",
                    "CWE-79: Cross-site Scripting",
                    "OWASP XSS Prevention Cheat Sheet",
                    "OWASP Java Encoder Project: https://owasp.org/www-project-java-encoder/"))
                .build();
    }

    // ── [IV-1.5] OS 명령어 삽입 ──────────────────────────────────────────

    private RemediationResult remediateOsCommand(Finding finding) {
        String var = extractTaintedVariable(finding);

        String code =
            "// [수정] IV-1.5 운영체제 명령어 삽입 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: Runtime.exec(\"cmd \" + userInput) — Shell 메타문자(; | & ` $) 실행 가능\n" +
            "// ▶ 보안 원칙: 외부 입력을 셸 명령 문자열에 포함 금지. 불가피하면 화이트리스트 검증 후 배열 전달\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import java.util.Arrays;\n" +
            "//   import java.util.Set;\n" +
            "//   import java.util.HashSet;\n" +
            "\n" +
            "// ── Step 1. 입력값 null 검증 ────────────────────────────────────\n" +
            "String " + var + " = request.getParameter(\"" + var + "\");\n" +
            "if (" + var + " == null || " + var + ".isBlank()) {\n" +
            "    throw new IllegalArgumentException(\"명령어 파라미터가 없습니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 2. 화이트리스트 기반 허용 값 검증 (가장 강력한 방어) ───\n" +
            "// 허용 가능한 고정값 목록만 사전 정의\n" +
            "Set<String> ALLOWED_VALUES = new HashSet<>(Arrays.asList(\n" +
            "    \"report\", \"summary\", \"status\"  // ← 실제 허용 값으로 교체\n" +
            "));\n" +
            "if (!ALLOWED_VALUES.contains(" + var + ")) {\n" +
            "    log.warn(\"[SECURITY] 허용되지 않은 명령어 파라미터 요청: {}\", " + var + ");\n" +
            "    throw new SecurityException(\"허용되지 않은 파라미터: \" + " + var + ");\n" +
            "}\n" +
            "\n" +
            "// ── Step 3. 배열 형태로 인자 분리 — 셸 해석 없이 직접 실행 ─────\n" +
            "// ❌ 취약: Runtime.getRuntime().exec(\"/usr/bin/tool \" + " + var + ")\n" +
            "// ✅ 안전: 배열 전달 시 셸이 개입하지 않으므로 메타문자 삽입 무력화\n" +
            "ProcessBuilder pb = new ProcessBuilder(\n" +
            "    \"/usr/bin/tool\",   // 절대경로 사용 (PATH 환경변수 조작 방지)\n" +
            "    " + var + "          // 화이트리스트 통과한 값만 전달\n" +
            ");\n" +
            "pb.redirectErrorStream(true);\n" +
            "\n" +
            "// ── Step 4. 환경변수 격리 및 작업 디렉터리 고정 ───────────────\n" +
            "pb.environment().clear();   // 불필요한 환경변수 제거\n" +
            "pb.directory(new java.io.File(\"/tmp/sandbox\"));  // 작업 디렉터리 제한\n" +
            "\n" +
            "// ── Step 5. 실행 및 타임아웃 처리 ───────────────────────────────\n" +
            "Process process = pb.start();\n" +
            "boolean finished = process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);\n" +
            "if (!finished) {\n" +
            "    process.destroyForcibly();\n" +
            "    throw new RuntimeException(\"명령어 실행 타임아웃 (10초 초과)\");\n" +
            "}\n" +
            "int exitCode = process.exitValue();\n" +
            "if (exitCode != 0) {\n" +
            "    log.warn(\"[Exec] 명령어 비정상 종료: exitCode={}\", exitCode);\n" +
            "}\n" +
            "\n" +
            "// ── [권고] OS 명령어 실행 자체를 Java API로 대체하는 것이 최선 ─\n" +
            "// 예: 파일 목록 → java.nio.file.Files.list()\n" +
            "//     파일 삭제 → java.nio.file.Files.delete()\n" +
            "//     압축     → java.util.zip.ZipOutputStream";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("AVOID_OS_COMMAND")
                .securityPrinciple("외부 입력을 OS 명령어에 포함하지 않습니다. " +
                    "불가피한 경우 화이트리스트 검증 후 배열 형태로 인자를 분리해 셸 해석을 차단합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "화이트리스트로 허용 값을 제한하고, ProcessBuilder 배열 형태로 인자를 전달해 " +
                    "셸 메타문자(; | & ` $)가 해석되지 않도록 합니다. " +
                    "가능하면 OS 명령어 대신 동일 기능의 Java API(java.nio.file.Files 등)로 교체하는 것이 최선입니다. " +
                    "가이드 참조: PART4 제1절 5항 운영체제 명령어 삽입 (p.223-231)")
                .references(Arrays.asList(
                    "PART4 제1절 5항 (p.223-231)",
                    "CWE-78: OS Command Injection",
                    "OWASP OS Command Injection Prevention Cheat Sheet"))
                .build();
    }

    // ── [IV-1.6] 위험 파일 업로드 ────────────────────────────────────────

    private RemediationResult remediateFileUpload(Finding finding) {
        String code =
            "// [수정] IV-1.6 위험한 형식 파일 업로드 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: 업로드 파일의 확장자/MIME 미검증 → 웹셸(JSP, PHP) 업로드 후 실행 가능\n" +
            "// ▶ 보안 원칙: 확장자 화이트리스트 + MIME 검증 + 파일명 랜덤화 + 웹 루트 외부 저장\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import java.nio.file.*;\n" +
            "//   import java.util.*;\n" +
            "//   import org.apache.commons.io.FilenameUtils;\n" +
            "\n" +
            "// ── Step 1. 파일명 null / 빈 값 검증 ──────────────────────────\n" +
            "String originalFilename = multipartFile.getOriginalFilename();\n" +
            "if (originalFilename == null || originalFilename.isBlank()) {\n" +
            "    throw new IllegalArgumentException(\"업로드 파일명이 없습니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 2. 확장자 화이트리스트 검증 ──────────────────────────\n" +
            "// 블랙리스트 방식은 우회 가능 (.jsp, .Jsp, .jsp%00 등)\n" +
            "// 화이트리스트만 허용\n" +
            "String ext = FilenameUtils.getExtension(originalFilename).toLowerCase();\n" +
            "Set<String> allowedExt = Set.of(\"jpg\", \"jpeg\", \"png\", \"gif\", \"pdf\", \"docx\", \"xlsx\");\n" +
            "if (!allowedExt.contains(ext)) {\n" +
            "    log.warn(\"[SECURITY] 허용되지 않은 업로드 파일 형식: {}\", ext);\n" +
            "    throw new SecurityException(\"허용되지 않는 파일 형식: \" + ext);\n" +
            "}\n" +
            "\n" +
            "// ── Step 3. MIME 타입 검증 (확장자 위변조 방어) ───────────────\n" +
            "// 파일 매직 바이트(헤더)를 읽어 실제 파일 형식 확인\n" +
            "String detectedMime = Files.probeContentType(multipartFile.getInputStream());\n" +
            "// 또는 Apache Tika 사용: new Tika().detect(multipartFile.getInputStream())\n" +
            "Set<String> allowedMime = Set.of(\n" +
            "    \"image/jpeg\", \"image/png\", \"image/gif\",\n" +
            "    \"application/pdf\",\n" +
            "    \"application/vnd.openxmlformats-officedocument.wordprocessingml.document\",\n" +
            "    \"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\"\n" +
            ");\n" +
            "if (detectedMime == null || !allowedMime.contains(detectedMime)) {\n" +
            "    throw new SecurityException(\"파일 내용과 형식이 불일치하거나 허용되지 않습니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 4. 파일 크기 검증 ─────────────────────────────────────\n" +
            "long MAX_SIZE = 10 * 1024 * 1024L;  // 10 MB\n" +
            "if (multipartFile.getSize() > MAX_SIZE) {\n" +
            "    throw new IllegalArgumentException(\"파일 크기가 허용 한도(10MB)를 초과합니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 5. 파일명 랜덤화 — 원본 파일명 제거 ──────────────────\n" +
            "// 원본 파일명은 DB에만 보관; 디스크에는 예측 불가한 UUID 사용\n" +
            "String safeFilename = UUID.randomUUID().toString() + \".\" + ext;\n" +
            "\n" +
            "// ── Step 6. 웹 루트 외부 디렉터리에 저장 ─────────────────────\n" +
            "// 웹 루트 내 저장 시 브라우저에서 직접 실행 가능\n" +
            "Path uploadDir = Paths.get(\"/var/app/uploads\");  // 웹 루트 외부\n" +
            "if (!Files.exists(uploadDir)) Files.createDirectories(uploadDir);\n" +
            "Path savePath = uploadDir.resolve(safeFilename);\n" +
            "Files.write(savePath, multipartFile.getBytes());\n" +
            "\n" +
            "log.info(\"[Upload] 파일 저장 완료: {} → {}\", originalFilename, safeFilename);";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("FILE_EXTENSION_WHITELIST")
                .securityPrinciple("확장자 화이트리스트 + MIME 검증 + 파일명 랜덤화 + 웹 루트 외부 저장의 4중 방어를 적용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "확장자 화이트리스트로 실행 가능 파일(.jsp, .php 등)을 차단하고, " +
                    "MIME 타입 검증으로 확장자 위변조를 방어합니다. " +
                    "UUID 파일명으로 경로 예측을 방지하고, 웹 루트 외부에 저장해 직접 실행을 차단합니다. " +
                    "가이드 참조: PART4 제1절 6항 위험한 형식 파일 업로드 (p.232-238)")
                .references(Arrays.asList(
                    "PART4 제1절 6항 (p.232-238)",
                    "CWE-434: Unrestricted Upload of File with Dangerous Type",
                    "OWASP File Upload Cheat Sheet"))
                .build();
    }

    // ── [IV-4.1] 오류 메시지 정보노출 ───────────────────────────────────

    private RemediationResult remediateErrorExposure(Finding finding) {
        String code =
            "// [수정] IV-4.1 오류 메시지를 통한 정보 노출 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: 스택트레이스, DB 오류, 경로 정보를 그대로 응답에 포함\n" +
            "// ▶ 보안 원칙: 상세 오류는 서버 로그에만 기록, 사용자에게는 일반 메시지 반환\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import javax.servlet.http.HttpServletResponse;\n" +
            "\n" +
            "// ── Step 1. 비즈니스 로직 실행 + 계층별 예외 처리 ───────────────\n" +
            "try {\n" +
            "    // ... 비즈니스 로직\n" +
            "\n" +
            "} catch (java.sql.SQLException e) {\n" +
            "    // DB 오류: 테이블명, 컬럼명, 쿼리 등 민감 정보가 getMessage()에 포함될 수 있음\n" +
            "    log.error(\"[DB] 데이터베이스 오류 발생 (errorCode={}): {}\",\n" +
            "              e.getErrorCode(), e.getMessage(), e);\n" +
            "    sendGenericError(response, \"데이터 처리 중 오류가 발생했습니다.\");\n" +
            "\n" +
            "} catch (java.io.IOException e) {\n" +
            "    // 파일/네트워크 오류: 내부 경로 노출 방지\n" +
            "    log.error(\"[IO] 입출력 오류: {}\", e.getMessage(), e);\n" +
            "    sendGenericError(response, \"요청을 처리할 수 없습니다.\");\n" +
            "\n" +
            "} catch (SecurityException e) {\n" +
            "    // 접근 제어 위반: 403 응답, 공격 시도 로그\n" +
            "    log.warn(\"[SECURITY] 접근 거부: {}\", e.getMessage());\n" +
            "    response.sendError(HttpServletResponse.SC_FORBIDDEN, \"접근이 거부되었습니다.\");\n" +
            "\n" +
            "} catch (Exception e) {\n" +
            "    // 예상치 못한 오류: 최상위에서 잡아 상세 내용 차단\n" +
            "    log.error(\"[Unhandled] 예상치 못한 오류: {}\", e.getMessage(), e);\n" +
            "    sendGenericError(response, \"요청을 처리할 수 없습니다. 관리자에게 문의하세요.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 2. 일반 오류 응답 헬퍼 — 스택트레이스 미포함 ───────────\n" +
            "private void sendGenericError(HttpServletResponse response, String message)\n" +
            "        throws IOException {\n" +
            "    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);\n" +
            "    response.setContentType(\"application/json;charset=UTF-8\");\n" +
            "    // JSON으로 일반 메시지만 반환 — 스택트레이스·경로·버전 미포함\n" +
            "    response.getWriter().write(\n" +
            "        \"{\\\"error\\\": \\\"\" + message + \"\\\"}\"  );\n" +
            "}\n" +
            "\n" +
            "// ── Step 3. 전역 예외 핸들러 설정 (Spring MVC 환경) ─────────────\n" +
            "// @ControllerAdvice + @ExceptionHandler로 중앙 집중 처리 권장\n" +
            "// @ExceptionHandler(Exception.class)\n" +
            "// public ResponseEntity<ErrorResponse> handleAll(Exception e) {\n" +
            "//     log.error(\"[GlobalHandler] {}\", e.getMessage(), e);\n" +
            "//     return ResponseEntity.status(500)\n" +
            "//             .body(new ErrorResponse(\"처리 중 오류가 발생했습니다.\"));\n" +
            "// }";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("GENERIC_ERROR_MESSAGE")
                .securityPrinciple("예외 상세 정보는 서버 로그에만 기록하고 사용자에게는 일반적인 메시지만 반환합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "예외 종류별(SQL/IO/Security/일반)로 분리 처리하여 각각 적절한 로그를 남기고 " +
                    "사용자에게는 오류 유형을 알 수 없는 일반 메시지를 반환합니다. " +
                    "Spring MVC 환경에서는 @ControllerAdvice로 중앙 집중 처리를 권장합니다. " +
                    "가이드 참조: PART4 제4절 1항 오류 메시지를 통한 정보 노출 (p.419-424)")
                .references(Arrays.asList(
                    "PART4 제4절 1항 (p.419-424)",
                    "CWE-209: Information Exposure Through Error Messages",
                    "OWASP Error Handling Cheat Sheet"))
                .build();
    }

    // ── [IV-2.8] 취약한 난수 ─────────────────────────────────────────────

    private RemediationResult remediateWeakRandom(Finding finding) {
        String code =
            "// [수정] IV-2.8 적절하지 않은 난수 값 사용 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: java.util.Random은 선형합동 알고리즘(LCG) 기반 — 시드 예측 후 값 추측 가능\n" +
            "// ▶ 보안 원칙: 보안 목적 난수는 반드시 java.security.SecureRandom 사용\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import java.security.SecureRandom;\n" +
            "//   import java.util.Base64;\n" +
            "\n" +
            "// ── Step 1. SecureRandom 인스턴스 생성 ─────────────────────────\n" +
            "// SecureRandom은 OS 엔트로피 소스(/dev/urandom 등)를 사용\n" +
            "// 클래스 레벨 필드로 선언해 재사용 (인스턴스 생성 비용이 높음)\n" +
            "private static final SecureRandom SECURE_RANDOM = new SecureRandom();\n" +
            "\n" +
            "// ── Step 2. 정수 범위 난수 생성 ─────────────────────────────────\n" +
            "// ❌ 취약: new Random().nextInt(bound)  — 예측 가능\n" +
            "// ✅ 안전:\n" +
            "int randomInt = SECURE_RANDOM.nextInt(bound);   // [0, bound) 범위\n" +
            "\n" +
            "// ── Step 3. 세션 토큰 / 인증 코드 생성 (바이트 배열 방식) ───────\n" +
            "// 256비트(32바이트) = 충분한 엔트로피\n" +
            "byte[] tokenBytes = new byte[32];\n" +
            "SECURE_RANDOM.nextBytes(tokenBytes);\n" +
            "\n" +
            "// URL-safe Base64 인코딩 (패딩 제거)\n" +
            "String sessionToken = Base64.getUrlEncoder().withoutPadding()\n" +
            "                           .encodeToString(tokenBytes);\n" +
            "// 예: \"dGhpcyBpcyBhIHRlc3Q\" (43자, URL-safe)\n" +
            "\n" +
            "// ── Step 4. 인증 코드(숫자 6자리) 생성 예시 ──────────────────────\n" +
            "int authCode = 100000 + SECURE_RANDOM.nextInt(900000);  // [100000, 999999]\n" +
            "String authCodeStr = String.valueOf(authCode);\n" +
            "\n" +
            "// ── Step 5. UUID 기반 식별자 생성 (간편 대안) ──────────────────\n" +
            "// UUID.randomUUID()는 내부적으로 SecureRandom을 사용 (Java 표준)\n" +
            "String uniqueId = java.util.UUID.randomUUID().toString();\n" +
            "\n" +
            "// ── [주의] 보안 목적이 아닌 경우 ──────────────────────────────\n" +
            "// 성능이 중요하고 보안이 불필요한 경우(게임 아이템 드랍률 등)에만\n" +
            "// java.util.Random 또는 ThreadLocalRandom 사용 가능\n" +
            "// int nonSecureRandom = ThreadLocalRandom.current().nextInt(100);";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SECURE_RANDOM")
                .securityPrinciple("보안 목적 난수는 OS 엔트로피 소스를 사용하는 java.security.SecureRandom을 사용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "java.util.Random은 시드를 알면 이후 모든 값 예측이 가능합니다. " +
                    "세션 토큰, 인증 코드, 암호화 키 등 보안 목적에는 반드시 SecureRandom을 사용하세요. " +
                    "인스턴스는 재사용 가능하므로 클래스 레벨 static 필드로 선언하는 것이 효율적입니다. " +
                    "가이드 참조: PART4 제2절 8항 적절하지 않은 난수 값 사용 (p.364-369)")
                .references(Arrays.asList(
                    "PART4 제2절 8항 (p.364-369)",
                    "CWE-330: Use of Insufficiently Random Values",
                    "CWE-338: Use of Cryptographically Weak PRNG"))
                .build();
    }

    // ── [IV-1.8] XXE ─────────────────────────────────────────────────────

    private RemediationResult remediateXxe(Finding finding) {
        String code =
            "// [수정] IV-1.8 XML 외부개체(XXE) 참조 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: XML 파서의 외부 엔티티 처리가 활성화 → 내부 파일 읽기 / SSRF 가능\n" +
            "//   예: <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n" +
            "// ▶ 보안 원칙: 외부 엔티티 참조 및 DOCTYPE 선언을 파서 수준에서 완전히 비활성화\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import javax.xml.parsers.DocumentBuilderFactory;\n" +
            "//   import javax.xml.parsers.DocumentBuilder;\n" +
            "//   import org.w3c.dom.Document;\n" +
            "\n" +
            "// ── [방법 A] DocumentBuilderFactory 사용 환경 ──────────────────\n" +
            "\n" +
            "// ── Step 1. Factory 생성 ─────────────────────────────────────────\n" +
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
            "\n" +
            "// ── Step 2. DOCTYPE 및 외부 엔티티 참조 전면 비활성화 ───────────\n" +
            "// DOCTYPE 선언 자체를 금지 (가장 강력)\n" +
            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
            "// 일반 외부 엔티티 참조 비활성화\n" +
            "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
            "// 파라미터 외부 엔티티 참조 비활성화\n" +
            "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
            "// 외부 DTD 로드 비활성화\n" +
            "dbf.setFeature(\"http://apache.org/xml/features/nonvalidating/load-external-dtd\", false);\n" +
            "// XInclude 및 엔티티 확장 비활성화\n" +
            "dbf.setXIncludeAware(false);\n" +
            "dbf.setExpandEntityReferences(false);\n" +
            "\n" +
            "// ── Step 3. 안전한 파서로 XML 파싱 ─────────────────────────────\n" +
            "DocumentBuilder db = dbf.newDocumentBuilder();\n" +
            "Document doc = db.parse(inputStream);\n" +
            "\n" +
            "// ── [방법 B] StAX(Streaming API) 사용 환경 ──────────────────────\n" +
            "// javax.xml.stream.XMLInputFactory factory = XMLInputFactory.newInstance();\n" +
            "// factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);\n" +
            "// factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n" +
            "// XMLStreamReader reader = factory.createXMLStreamReader(inputStream);\n" +
            "\n" +
            "// ── [방법 C] Jackson XML / JAXB 환경 ────────────────────────────\n" +
            "// XmlMapper mapper = new XmlMapper();\n" +
            "// mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);\n" +
            "// // Jackson은 기본적으로 XXE 안전하나 XMLInputFactory 주입 시 확인 필요\n" +
            "\n" +
            "// ── [권고] XML 대신 JSON 사용 ───────────────────────────────────\n" +
            "// 외부 입력 처리에는 XXE 위험이 없는 JSON 형식 사용을 권장\n" +
            "// ObjectMapper mapper = new ObjectMapper();\n" +
            "// MyDto dto = mapper.readValue(jsonString, MyDto.class);";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("DISABLE_XML_ENTITY")
                .securityPrinciple("XML 파서에서 DOCTYPE 및 외부 엔티티 참조를 완전히 비활성화합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "setFeature()로 DOCTYPE 선언과 모든 외부 엔티티 참조를 파서 수준에서 차단합니다. " +
                    "DocumentBuilderFactory, StAX, Jackson 각 환경별 설정 방법을 제공하며, " +
                    "가능하면 외부 입력은 JSON 형식으로 처리하는 것이 근본적인 해결책입니다. " +
                    "가이드 참조: PART4 제1절 8항 XML 외부개체 참조 (p.244-250)")
                .references(Arrays.asList(
                    "PART4 제1절 8항 (p.244-250)",
                    "CWE-611: Improper Restriction of XML External Entity Reference",
                    "OWASP XXE Prevention Cheat Sheet"))
                .build();
    }

    // ── [IV-1.13] HTTP 응답분할 ──────────────────────────────────────────

    private RemediationResult remediateCrLf(Finding finding) {
        String var = extractTaintedVariable(finding);

        String code =
            "// [수정] IV-1.13 HTTP 응답분할(CRLF Injection) 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: HTTP 헤더 값에 CR(\\r, %0d) / LF(\\n, %0a)가 포함되면\n" +
            "//   응답을 분할해 가짜 헤더·Set-Cookie를 삽입하거나 XSS를 유발할 수 있음\n" +
            "// ▶ 보안 원칙: 헤더에 사용할 외부 입력에서 CR/LF 문자를 완전히 제거\n" +
            "//\n" +
            "// ── Step 1. 입력값 수신 ───────────────────────────────────────────\n" +
            "String " + var + " = request.getParameter(\"" + var + "\");\n" +
            "if (" + var + " == null) {\n" +
            "    throw new IllegalArgumentException(\"리다이렉트 URL이 없습니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 2. CR/LF 및 URL 인코딩 변형 모두 제거 ─────────────────\n" +
            "// \\r(CR), \\n(LF) 직접 문자 + URL 인코딩(%0d, %0a) + 중간 인코딩(%250d 등)\n" +
            "String safe_" + var + " = " + var + "\n" +
            "    .replaceAll(\"[\\\\r\\\\n]\", \"\")          // 직접 CR/LF 문자\n" +
            "    .replaceAll(\"%0[dDaA]\", \"\")             // %0d, %0a (단순 URL 인코딩)\n" +
            "    .replaceAll(\"%25%?0[dDaA]\", \"\");        // %250d, %250a (이중 인코딩)\n" +
            "\n" +
            "// ── Step 3. 리다이렉트 허용 도메인 화이트리스트 검증 (SSRF 방어) ─\n" +
            "// CR/LF 제거만으로는 오픈 리다이렉트(CWE-601)를 방지하지 못함\n" +
            "try {\n" +
            "    java.net.URI uri = new java.net.URI(safe_" + var + ");\n" +
            "    String host = uri.getHost();\n" +
            "    Set<String> allowedHosts = Set.of(\"example.com\", \"www.example.com\");\n" +
            "    if (host != null && !allowedHosts.contains(host.toLowerCase())) {\n" +
            "        log.warn(\"[SECURITY] 허용되지 않은 리다이렉트 시도: {}\", safe_" + var + ");\n" +
            "        throw new SecurityException(\"허용되지 않는 리다이렉트 주소입니다.\");\n" +
            "    }\n" +
            "} catch (java.net.URISyntaxException e) {\n" +
            "    throw new IllegalArgumentException(\"유효하지 않은 URL 형식입니다.\");\n" +
            "}\n" +
            "\n" +
            "// ── Step 4. 검증된 값으로 헤더 설정 ────────────────────────────\n" +
            "response.setHeader(\"Location\", safe_" + var + ");\n" +
            "\n" +
            "// ── [참고] Spring MVC 환경에서는 RedirectAttributes 사용 권장 ──\n" +
            "// return \"redirect:\" + safe_" + var + ";";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("CRLF_REMOVAL")
                .securityPrinciple("HTTP 헤더 값에서 CR/LF 문자(직접·URL 인코딩 변형 포함)를 제거하고 허용 도메인을 검증합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "CR/LF 직접 문자뿐 아니라 URL 인코딩(%0d/%0a)과 이중 인코딩(%250d/%250a) 변형도 제거합니다. " +
                    "리다이렉트 URL이라면 허용 도메인 화이트리스트로 오픈 리다이렉트(CWE-601)도 함께 방어하세요. " +
                    "가이드 참조: PART4 제1절 13항 HTTP 응답분할 (p.284-289)")
                .references(Arrays.asList(
                    "PART4 제1절 13항 (p.284-289)",
                    "CWE-113: HTTP Response Splitting",
                    "CWE-601: URL Redirection to Untrusted Site"))
                .build();
    }

    // ── [IV-5.5] 역직렬화 ───────────────────────────────────────────────

    private RemediationResult remediateDeserialization(Finding finding) {
        String code =
            "// [수정] IV-5.5 신뢰할 수 없는 데이터의 역직렬화 방지\n" +
            "//\n" +
            "// ▶ 취약 원인: ObjectInputStream.readObject()는 바이트스트림에 담긴 임의 클래스를\n" +
            "//   모두 인스턴스화 → Gadget Chain 이용 원격 코드 실행(RCE) 가능\n" +
            "// ▶ 보안 원칙: 1) 안전한 직렬화 형식(JSON)으로 교체 또는\n" +
            "//             2) ObjectInputFilter로 허용 클래스를 엄격히 제한\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import java.io.ObjectInputStream;\n" +
            "//   import java.io.ObjectInputFilter;\n" +
            "//   import com.fasterxml.jackson.databind.ObjectMapper;\n" +
            "\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// [방법 A] JSON으로 교체 — 가장 권장하는 근본적 해결책\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "\n" +
            "// ── Step 1. Jackson ObjectMapper로 역직렬화 ─────────────────────\n" +
            "ObjectMapper mapper = new ObjectMapper();\n" +
            "// DEFAULT_TYPING 비활성화 확인 (활성화 시 다형성 역직렬화 위험)\n" +
            "mapper.deactivateDefaultTyping();\n" +
            "// enableDefaultTyping() 절대 호출 금지!\n" +
            "\n" +
            "// 명시적 타입으로만 역직렬화 (임의 클래스 인스턴스화 불가)\n" +
            "SafeDataClass data = mapper.readValue(jsonBytes, SafeDataClass.class);\n" +
            "\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// [방법 B] Java 직렬화 유지 시 — ObjectInputFilter 적용 (Java 9+)\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "\n" +
            "// ── Step 2. 허용 클래스 목록 정의 ───────────────────────────────\n" +
            "// 최소 권한 원칙: 실제로 필요한 클래스만 명시\n" +
            "ObjectInputFilter allowlistFilter = ObjectInputFilter.Config.createFilter(\n" +
            "    \"com.example.SafeDataClass;\"   // 허용 클래스 패키지\n" +
            "    + \"java.util.ArrayList;\"       // 허용 JDK 클래스\n" +
            "    + \"!*\"                          // 나머지 모두 거부\n" +
            ");\n" +
            "\n" +
            "// ── Step 3. ObjectInputStream에 필터 적용 ────────────────────────\n" +
            "try (ObjectInputStream ois = new ObjectInputStream(inputStream)) {\n" +
            "    ois.setObjectInputFilter(allowlistFilter);\n" +
            "\n" +
            "    // ── Step 4. 크기 제한 — 역직렬화 DoS 방지 ──────────────────\n" +
            "    // 필터 내 maxarray, maxbytes 등도 설정 권장\n" +
            "    // \"maxbytes=100000;maxarray=1000;maxdepth=5;!*\"\n" +
            "\n" +
            "    Object obj = ois.readObject();\n" +
            "    if (!(obj instanceof SafeDataClass)) {\n" +
            "        throw new SecurityException(\"예상치 못한 역직렬화 타입: \" + obj.getClass());\n" +
            "    }\n" +
            "    SafeDataClass data = (SafeDataClass) obj;\n" +
            "    // ... 처리\n" +
            "} catch (ClassNotFoundException e) {\n" +
            "    log.error(\"[Deser] 알 수 없는 클래스 역직렬화 시도: {}\", e.getMessage(), e);\n" +
            "    throw new SecurityException(\"역직렬화 실패: 허용되지 않은 클래스\", e);\n" +
            "}\n" +
            "\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// [방법 C] 전역 필터 설정 (JVM 전체 적용, Java 9+)\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// JVM 옵션: -Djdk.serialFilter=com.example.**;!*\n" +
            "// 또는 코드로:\n" +
            "// ObjectInputFilter.Config.setSerialFilter(allowlistFilter);";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SAFE_DESERIALIZATION")
                .securityPrinciple("Java 직렬화 대신 JSON 형식을 사용하거나, ObjectInputFilter로 허용 클래스를 엄격히 제한합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "가장 권장하는 방법은 Java 직렬화를 JSON(Jackson)으로 교체하는 것입니다. " +
                    "직렬화 유지가 필요한 경우 ObjectInputFilter 허용리스트로 인스턴스화 가능한 클래스를 최소화하고, " +
                    "maxbytes/maxdepth 등으로 역직렬화 DoS도 함께 방어하세요. " +
                    "가이드 참조: PART4 제5절 5항 신뢰할 수 없는 데이터의 역직렬화 (p.462-468)")
                .references(Arrays.asList(
                    "PART4 제5절 5항 (p.462-468)",
                    "CWE-502: Deserialization of Untrusted Data",
                    "OWASP Deserialization Cheat Sheet"))
                .build();
    }

    // ── [IV-3.1] 경쟁조건: 검사 시점과 사용 시점(TOCTOU) ────────────────────

    private RemediationResult remediateToctou(Finding finding) {
        String code =
            "// [수정] IV-3.1 경쟁조건(TOCTOU) 방지: 원자적 파일 연산 사용\n" +
            "//\n" +
            "// ▶ 취약 원인: f.exists() 후 f.delete()/FileInputStream(f) 사이 간격에\n" +
            "//   다른 스레드/프로세스가 파일을 생성·삭제·교체할 수 있음 (심볼릭 링크 공격 포함)\n" +
            "// ▶ 보안 원칙: 상태 검사 없이 직접 연산을 시도하고 예외로 실패를 처리\n" +
            "//   또는 java.nio.file 원자적 API 사용\n" +
            "//\n" +
            "// 필요 import:\n" +
            "//   import java.nio.file.*;\n" +
            "//   import java.nio.file.attribute.BasicFileAttributes;\n" +
            "\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// [방법 A] 파일 읽기 — exists() 없이 직접 열기 (권장)\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "\n" +
            "// ❌ 취약: exists() 검사 후 open — 사이 간격에 파일 교체 가능\n" +
            "// if (f.exists()) {\n" +
            "//     new FileInputStream(f);  // TOCTOU!\n" +
            "// }\n" +
            "\n" +
            "// ✅ 안전: 직접 열기 시도 — NoSuchFileException으로 '없음' 처리\n" +
            "Path filePath = Path.of(\"/app/data/target.txt\");\n" +
            "try (var reader = Files.newBufferedReader(filePath)) {\n" +
            "    // 파일이 존재하고 읽기 가능한 경우의 처리\n" +
            "    String line;\n" +
            "    while ((line = reader.readLine()) != null) {\n" +
            "        // ... 처리\n" +
            "    }\n" +
            "} catch (NoSuchFileException e) {\n" +
            "    log.warn(\"[FileOp] 파일 없음: {}\", filePath);\n" +
            "} catch (AccessDeniedException e) {\n" +
            "    log.warn(\"[FileOp] 읽기 권한 없음: {}\", filePath);\n" +
            "} catch (IOException e) {\n" +
            "    log.error(\"[FileOp] 파일 읽기 오류: {}\", filePath, e);\n" +
            "}\n" +
            "\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// [방법 B] 파일 삭제 — exists() 없이 직접 삭제\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "\n" +
            "// ❌ 취약:\n" +
            "// if (f.exists()) { f.delete(); }  // TOCTOU!\n" +
            "\n" +
            "// ✅ 안전 (파일 없으면 예외 발생):\n" +
            "try {\n" +
            "    Files.delete(filePath);\n" +
            "} catch (NoSuchFileException e) {\n" +
            "    // 이미 삭제됨 — 무시하거나 로그\n" +
            "    log.debug(\"[FileOp] 이미 삭제된 파일: {}\", filePath);\n" +
            "} catch (IOException e) {\n" +
            "    log.error(\"[FileOp] 파일 삭제 오류: {}\", filePath, e);\n" +
            "}\n" +
            "\n" +
            "// ✅ 안전 (파일 없어도 조용히 처리):\n" +
            "Files.deleteIfExists(filePath);\n" +
            "\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// [방법 C] 파일 생성 — 원자적 OpenOption 사용\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "\n" +
            "// ❌ 취약:\n" +
            "// if (!f.exists()) { f.createNewFile(); }  // TOCTOU!\n" +
            "\n" +
            "// ✅ 안전: CREATE_NEW는 파일이 이미 존재하면 FileAlreadyExistsException 발생\n" +
            "try {\n" +
            "    Files.newOutputStream(filePath, StandardOpenOption.CREATE_NEW,\n" +
            "                                    StandardOpenOption.WRITE);\n" +
            "} catch (FileAlreadyExistsException e) {\n" +
            "    log.warn(\"[FileOp] 파일 이미 존재: {}\", filePath);\n" +
            "} catch (IOException e) {\n" +
            "    log.error(\"[FileOp] 파일 생성 오류: {}\", filePath, e);\n" +
            "}\n" +
            "\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// [보충] 심볼릭 링크 공격 방어 — NOFOLLOW_LINKS 옵션\n" +
            "// ════════════════════════════════════════════════════════════\n" +
            "// Files.readAttributes(filePath, BasicFileAttributes.class,\n" +
            "//         LinkOption.NOFOLLOW_LINKS);  // 심볼릭 링크를 따르지 않음";

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("ATOMIC_FILE_OPERATION")
                .securityPrinciple("파일 상태 검사(exists 등)와 실제 사용 사이의 간격을 없애기 위해 " +
                    "예외 처리 기반의 원자적 파일 연산(java.nio.file.Files)을 사용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(code)
                .explanation(
                    "exists()/canRead() 후 open/delete 사이에 다른 프로세스가 파일을 교체·삭제할 수 있습니다. " +
                    "Files.delete(), Files.newBufferedReader() 등 java.nio.file API는 검사와 사용을 단일 시스템 콜로 처리하므로 " +
                    "경쟁 조건 윈도우가 발생하지 않습니다. 심볼릭 링크 공격 방어에는 NOFOLLOW_LINKS 옵션을 추가하세요. " +
                    "가이드 참조: PART4 제3절 1항 경쟁조건 검사 시점과 사용 시점 (p.406-414)")
                .references(Arrays.asList(
                    "PART4 제3절 1항 (p.406-414)",
                    "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition",
                    "CWE-362: Race Condition Enabling Link Following"))
                .build();
    }

    // ── 기본 수정 제안 ────────────────────────────────────────────────────

    private RemediationResult remediateGeneric(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("GENERIC")
                .securityPrinciple("가이드에서 해당 약점의 조치 방안을 확인하세요.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode("// 해당 약점의 수정 방법을 가이드에서 확인하세요: " + finding.getGuideRef())
                .explanation("보안약점 '" + finding.getRuleName() + "'의 조치방안을 가이드에서 확인하세요.")
                .references(Collections.singletonList(finding.getGuideRef()))
                .build();
    }

    // ── Context Extraction ────────────────────────────────────────────────

    private String extractTaintedVariable(Finding finding) {
        if (finding.getTaintFlows() == null || finding.getTaintFlows().isEmpty()) {
            return "userInput";
        }
        Finding.TaintFlow flow = finding.getTaintFlows().get(0);
        List<String> propagators = flow.getPropagators();
        if (propagators != null && !propagators.isEmpty()) {
            return propagators.get(propagators.size() - 1);
        }
        String source = flow.getSourceExpression();
        Matcher m = Pattern.compile("getParameter\\(\"(\\w+)\"\\)").matcher(source);
        if (m.find()) return m.group(1);
        return "userInput";
    }

    private SqlQueryContext parseSqlContext(String vulnerableCode) {
        SqlQueryContext ctx = new SqlQueryContext();
        Pattern sqlPattern = Pattern.compile(
            "\"(SELECT[^\"]*|INSERT[^\"]*|UPDATE[^\"]*|DELETE[^\"]*|FROM[^\"]*WHERE[^\"]*)'\"",
            Pattern.CASE_INSENSITIVE);
        Matcher m = sqlPattern.matcher(vulnerableCode);
        if (m.find()) {
            ctx.safeSqlTemplate = m.group(1).trim() + " ?";
        } else {
            Pattern fallback = Pattern.compile(
                "\"([^\"]*SELECT[^\"]*|[^\"]*FROM[^\"]*WHERE[^\"]*)\"");
            Matcher fm = fallback.matcher(vulnerableCode);
            ctx.safeSqlTemplate = fm.find()
                    ? fm.group(1).replaceAll("'[^']*'", "?")
                    : "SELECT * FROM table WHERE column = ?";
        }
        return ctx;
    }

    private String extractBaseDirectory(String vulnerableCode) {
        Pattern p = Pattern.compile("\"([A-Za-z]:[/\\\\][^\"]+|/[^\"]+/)\"");
        Matcher m = p.matcher(vulnerableCode);
        return m.find() ? m.group(1) : "/app/data/";
    }

    private String resolveStrategy(String ruleId) {
        if ("IV-1.1".equals(ruleId))  return "USE_PREPARED_STATEMENT";
        if ("IV-1.3".equals(ruleId))  return "PATH_CANONICALIZATION";
        if ("IV-1.4".equals(ruleId))  return "OUTPUT_ENCODING";
        if ("IV-1.5".equals(ruleId))  return "AVOID_OS_COMMAND";
        if ("IV-1.6".equals(ruleId))  return "FILE_EXTENSION_WHITELIST";
        if ("IV-1.13".equals(ruleId)) return "CRLF_REMOVAL";
        if ("IV-2.8".equals(ruleId))  return "SECURE_RANDOM";
        if ("IV-1.8".equals(ruleId))  return "DISABLE_XML_ENTITY";
        if ("IV-4.1".equals(ruleId))  return "GENERIC_ERROR_MESSAGE";
        if ("IV-5.5".equals(ruleId))  return "SAFE_DESERIALIZATION";
        if ("IV-3.1".equals(ruleId))  return "ATOMIC_FILE_OPERATION";
        return "GENERIC";
    }

    // ── Inner Classes ─────────────────────────────────────────────────────

    private static class SqlQueryContext {
        String safeSqlTemplate = "SELECT * FROM table WHERE column = ?";
    }

    // ── RemediationResult DTO ─────────────────────────────────────────────

    public static class RemediationResult {
        private String       ruleId;
        private String       strategy;
        private String       securityPrinciple;
        private String       vulnerableCode;
        private String       remediatedCode;
        private String       explanation;
        private List<String> references;

        public static Builder builder() { return new Builder(); }

        public static class Builder {
            private final RemediationResult r = new RemediationResult();
            public Builder ruleId(String v)             { r.ruleId = v;             return this; }
            public Builder strategy(String v)            { r.strategy = v;           return this; }
            public Builder securityPrinciple(String v)   { r.securityPrinciple = v;  return this; }
            public Builder vulnerableCode(String v)      { r.vulnerableCode = v;     return this; }
            public Builder remediatedCode(String v)      { r.remediatedCode = v;     return this; }
            public Builder explanation(String v)         { r.explanation = v;        return this; }
            public Builder references(List<String> v)    { r.references = v;         return this; }
            public RemediationResult build()             { return r; }
        }

        public String getRuleId()             { return ruleId; }
        public String getStrategy()           { return strategy; }
        public String getSecurityPrinciple()  { return securityPrinciple; }
        public String getVulnerableCode()     { return vulnerableCode; }
        public String getRemediatedCode()     { return remediatedCode; }
        public String getExplanation()        { return explanation; }
        public List<String> getReferences()   { return references; }
    }
}
