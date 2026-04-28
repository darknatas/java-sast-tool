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

        return switch (strategy) {
            case "USE_PREPARED_STATEMENT"  -> remediateSqlInjection(finding);
            case "WHITELIST_VALIDATION"    -> remediateCodeInjection(finding);
            case "PATH_CANONICALIZATION"   -> remediatePathTraversal(finding);
            case "OUTPUT_ENCODING"         -> remediateXss(finding);
            case "AVOID_OS_COMMAND"        -> remediateOsCommand(finding);
            case "FILE_EXTENSION_WHITELIST"-> remediateFileUpload(finding);
            case "REDIRECT_WHITELIST"      -> remediateOpenRedirect(finding);
            case "DISABLE_XML_ENTITY"      -> remediateXxe(finding);
            case "PARAMETERIZED_XPATH"     -> remediateXmlInjection(finding);
            case "LDAP_ENCODING"           -> remediateLdapInjection(finding);
            case "CSRF_TOKEN"              -> remediateCsrf(finding);
            case "SSRF_ALLOWLIST"          -> remediateSsrf(finding);
            case "CRLF_REMOVAL"            -> remediateCrLf(finding);
            case "BOUNDS_CHECK"            -> remediateIntegerOverflow(finding);
            case "SERVER_SIDE_AUTH_CHECK"  -> remediateSecurityInput(finding);
            case "SAFE_ARRAY_ACCESS"       -> remediateBufferOverflow(finding);
            case "LITERAL_FORMAT_STRING"   -> remediateFormatString(finding);
            case "AUTH_GATE_FILTER"        -> remediateAuthMissing(finding);
            case "RBAC_CHECK"              -> remediateImproperAuthz(finding);
            case "LEAST_PRIVILEGE"         -> remediateWrongPermission(finding);
            case "STRONG_CRYPTO"           -> remediateWeakCrypto(finding);
            case "ENCRYPT_SENSITIVE_DATA"  -> remediateUnencryptedData(finding);
            case "EXTERNALIZE_SECRETS"     -> remediateHardcodedSecret(finding);
            case "MIN_KEY_SIZE"            -> remediateShortKey(finding);
            case "SECURE_RANDOM"           -> remediateWeakRandom(finding);
            case "PASSWORD_POLICY"         -> remediateWeakPassword(finding);
            case "VERIFY_SIGNATURE"        -> remediateSignatureVerify(finding);
            case "PROPER_CERT_VALIDATION"  -> remediateCertValidation(finding);
            case "SECURE_COOKIE_ATTRIBUTES"-> remediateInsecureCookie(finding);
            case "REMOVE_SENSITIVE_COMMENTS"->remediateSensitiveComment(finding);
            case "SALTED_HASH"             -> remediateSaltedHash(finding);
            case "CHECKSUM_VERIFY"         -> remediateCodeDownload(finding);
            case "ACCOUNT_LOCKOUT"         -> remediateNoLockout(finding);
            case "ATOMIC_FILE_OPERATION"   -> remediateToctou(finding);
            case "TERMINATION_CONDITION"   -> remediateInfiniteLoop(finding);
            case "GENERIC_ERROR_MESSAGE"   -> remediateErrorExposure(finding);
            case "HANDLE_ALL_EXCEPTIONS"   -> remediateEmptyCatch(finding);
            case "SPECIFIC_EXCEPTION_HANDLING" -> remediateOverbroadCatch(finding);
            case "NULL_CHECK"              -> remediateNullPointer(finding);
            case "TRY_WITH_RESOURCES"      -> remediateResourceLeak(finding);
            case "NULL_AFTER_CLOSE"        -> remediateUseAfterClose(finding);
            case "INITIALIZE_VARIABLES"    -> remediateUninitVar(finding);
            case "SAFE_DESERIALIZATION"    -> remediateDeserialization(finding);
            case "SESSION_ISOLATION"       -> remediateSessionIsolation(finding);
            case "SESSION_DESIGN"          -> remediateSessionDesign(finding);
            case "REMOVE_DEBUG_CODE"       -> remediateDebugCode(finding);
            case "DEFENSIVE_COPY"          -> remediatePrivateArrayReturn(finding);
            case "DEFENSIVE_COPY_INPUT"    -> remediatePrivateArrayAssign(finding);
            case "IP_BASED_CHECK"          -> remediateDnsLookup(finding);
            case "SAFE_API_REPLACEMENT"    -> remediateVulnerableApi(finding);
            default                        -> remediateGeneric(finding);
        };
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

    // ── [IV-1.2] 코드 삽입 ──────────────────────────────────────────────────

    private RemediationResult remediateCodeInjection(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("WHITELIST_VALIDATION")
                .securityPrinciple("외부 입력을 코드로 직접 실행하지 않습니다. 허용 가능한 값 목록(화이트리스트)으로 제한합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.2 코드 삽입 방지: 화이트리스트 검증\n" +
                    "Set<String> ALLOWED = Set.of(\"report\", \"summary\", \"status\");\n" +
                    "String input = request.getParameter(\"action\");\n" +
                    "if (!ALLOWED.contains(input)) throw new SecurityException(\"허용되지 않는 값: \" + input);\n" +
                    "// 동적 코드 실행(eval, exec, Class.forName 등) 절대 금지")
                .explanation("외부 입력값을 ScriptEngine.eval(), Runtime.exec() 등에 직접 사용하면 임의 코드 실행이 가능합니다. " +
                    "화이트리스트로 허용 값을 제한하고 동적 코드 실행 자체를 제거하세요. " +
                    "가이드 참조: PART4 제1절 2항 코드 삽입 (p.194-200)")
                .references(Arrays.asList("PART4 제1절 2항 (p.194-200)", "CWE-94: Code Injection", "CWE-95: Eval Injection"))
                .build();
    }

    // ── [IV-1.7] 오픈 리다이렉트 ────────────────────────────────────────────

    private RemediationResult remediateOpenRedirect(Finding finding) {
        String var = extractTaintedVariable(finding);
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("REDIRECT_WHITELIST")
                .securityPrinciple("리다이렉트 URL을 서버 측 허용 목록과 비교 검증합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.7 오픈 리다이렉트 방지: 허용 도메인 화이트리스트 검증\n" +
                    "String " + var + " = request.getParameter(\"redirect\");\n" +
                    "Set<String> allowedHosts = Set.of(\"example.com\", \"www.example.com\");\n" +
                    "try {\n" +
                    "    URI uri = new URI(" + var + ");\n" +
                    "    if (uri.getHost() != null && !allowedHosts.contains(uri.getHost()))\n" +
                    "        throw new SecurityException(\"허용되지 않는 리다이렉트 주소\");\n" +
                    "} catch (URISyntaxException e) { throw new IllegalArgumentException(\"유효하지 않은 URL\"); }\n" +
                    "response.sendRedirect(" + var + ");")
                .explanation("외부 입력 URL로 리다이렉트하면 피싱 공격에 악용될 수 있습니다. " +
                    "허용 도메인 화이트리스트로 검증하거나 상대 경로만 허용하세요. " +
                    "가이드 참조: PART4 제1절 7항 신뢰되지 않는 URL 자동접속 (p.239-243)")
                .references(Arrays.asList("PART4 제1절 7항 (p.239-243)", "CWE-601: Open Redirect"))
                .build();
    }

    // ── [IV-1.9] XPath/XML 삽입 ─────────────────────────────────────────────

    private RemediationResult remediateXmlInjection(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("PARAMETERIZED_XPATH")
                .securityPrinciple("XPath 변수 바인딩을 사용하여 입력값을 데이터로만 처리합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.9 XPath 삽입 방지: 변수 바인딩 사용\n" +
                    "// ❌ 취약: xpath.evaluate(\"/users/user[@name='\" + name + \"']\", doc, ...)\n" +
                    "// ✅ 안전:\n" +
                    "XPath xpath = XPathFactory.newInstance().newXPath();\n" +
                    "XPathVariableResolver resolver = qName -> \n" +
                    "    \"name\".equals(qName.getLocalPart()) ? name : null;\n" +
                    "xpath.setXPathVariableResolver(resolver);\n" +
                    "String result = (String) xpath.evaluate(\"/users/user[@name=$name]\", doc, XPathConstants.STRING);\n" +
                    "// 또는: 입력값에서 XPath 특수문자(' \" [ ] * / @ = 등) 제거")
                .explanation("XPath 표현식에 외부 입력을 직접 포함하면 쿼리 구조 변경으로 인증 우회가 가능합니다. " +
                    "XPath 변수 바인딩을 사용하거나 ESAPI.encoder().encodeForXPath()로 인코딩하세요. " +
                    "가이드 참조: PART4 제1절 9항 XML 삽입 (p.251-263)")
                .references(Arrays.asList("PART4 제1절 9항 (p.251-263)", "CWE-652: XPath Injection", "CWE-643: XPath Injection"))
                .build();
    }

    // ── [IV-1.10] LDAP 삽입 ─────────────────────────────────────────────────

    private RemediationResult remediateLdapInjection(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("LDAP_ENCODING")
                .securityPrinciple("LDAP 필터에 사용되는 입력값에 LDAP 특수문자를 인코딩합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.10 LDAP 삽입 방지: 특수문자 인코딩\n" +
                    "// ❌ 취약: \"(&(uid=\" + userId + \")(password=\" + password + \"))\"\n" +
                    "// ✅ 안전:\n" +
                    "// OWASP ESAPI 사용:\n" +
                    "String safeUserId = ESAPI.encoder().encodeForLDAP(userId);\n" +
                    "String filter = \"(&(uid=\" + safeUserId + \")(objectClass=person))\";\n" +
                    "// 또는 LDAP 특수문자(* ( ) \\ \\0) 수동 이스케이프:\n" +
                    "String escapedId = userId.replaceAll(\"[\\\\*\\\\(\\\\)\\\\\\\\\\\\0]\", \"\");")
                .explanation("LDAP 필터에 외부 입력을 직접 포함하면 필터 구조 변경으로 인증 우회가 가능합니다. " +
                    "ESAPI.encoder().encodeForLDAP()로 특수문자(*, (, ), \\, NUL)를 이스케이프하세요. " +
                    "가이드 참조: PART4 제1절 10항 LDAP 삽입 (p.264-271)")
                .references(Arrays.asList("PART4 제1절 10항 (p.264-271)", "CWE-90: LDAP Injection"))
                .build();
    }

    // ── [IV-1.11] CSRF ──────────────────────────────────────────────────────

    private RemediationResult remediateCsrf(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("CSRF_TOKEN")
                .securityPrinciple("중요 기능 요청에 예측 불가한 CSRF 토큰을 생성·검증합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.11 CSRF 방지: 동기화 토큰 패턴\n" +
                    "// 토큰 생성 (로그인 시 또는 폼 렌더링 시)\n" +
                    "byte[] tokenBytes = new byte[32];\n" +
                    "new java.security.SecureRandom().nextBytes(tokenBytes);\n" +
                    "String csrfToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);\n" +
                    "session.setAttribute(\"csrfToken\", csrfToken);\n" +
                    "// HTML 폼: <input type=\"hidden\" name=\"_csrf\" value=\"${csrfToken}\">\n\n" +
                    "// 요청 수신 시 검증\n" +
                    "String submitted = request.getParameter(\"_csrf\");\n" +
                    "String expected  = (String) session.getAttribute(\"csrfToken\");\n" +
                    "if (!MessageDigest.isEqual(submitted.getBytes(), expected.getBytes()))\n" +
                    "    throw new SecurityException(\"CSRF 토큰 불일치\");\n" +
                    "// Spring Security: @EnableWebSecurity + CsrfConfigurer 사용 권장")
                .explanation("CSRF 공격은 인증된 사용자를 대신해 의도하지 않은 요청을 보내게 합니다. " +
                    "서버 측에서 생성한 토큰을 폼과 세션에 저장하고 요청마다 비교 검증하세요. " +
                    "Spring Security를 사용하면 자동으로 CSRF 방어가 적용됩니다. " +
                    "가이드 참조: PART4 제1절 11항 CSRF (p.272-275)")
                .references(Arrays.asList("PART4 제1절 11항 (p.272-275)", "CWE-352: CSRF", "OWASP CSRF Prevention Cheat Sheet"))
                .build();
    }

    // ── [IV-1.12] SSRF ──────────────────────────────────────────────────────

    private RemediationResult remediateSsrf(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SSRF_ALLOWLIST")
                .securityPrinciple("외부 요청 대상 URL을 서버 측 허용 목록으로 엄격히 제한합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.12 SSRF 방지: 허용 호스트 화이트리스트 검증\n" +
                    "String targetUrl = request.getParameter(\"url\");\n" +
                    "Set<String> allowedHosts = Set.of(\"api.example.com\", \"cdn.example.com\");\n" +
                    "URI uri = new URI(targetUrl);\n" +
                    "String host = uri.getHost();\n" +
                    "if (host == null || !allowedHosts.contains(host.toLowerCase()))\n" +
                    "    throw new SecurityException(\"허용되지 않는 외부 요청 대상: \" + host);\n" +
                    "// URL 스킴 검증 (http/https만 허용)\n" +
                    "if (!uri.getScheme().matches(\"https?\"))\n" +
                    "    throw new SecurityException(\"허용되지 않는 프로토콜\");")
                .explanation("외부 입력 URL로 서버가 내부 네트워크에 요청을 보내면 내부 서비스가 노출될 수 있습니다. " +
                    "허용 호스트 화이트리스트로 제한하고 DNS 리바인딩 공격에 주의하세요. " +
                    "가이드 참조: PART4 제1절 12항 SSRF (p.276-283)")
                .references(Arrays.asList("PART4 제1절 12항 (p.276-283)", "CWE-918: SSRF", "OWASP SSRF Prevention Cheat Sheet"))
                .build();
    }

    // ── [IV-1.14] 정수형 오버플로우 ─────────────────────────────────────────

    private RemediationResult remediateIntegerOverflow(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("BOUNDS_CHECK")
                .securityPrinciple("정수 연산 전 범위 검사를 수행하거나 BigInteger/Math.addExact를 사용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.14 정수형 오버플로우 방지\n" +
                    "// ❌ 취약: int result = Integer.parseInt(request.getParameter(\"count\")) * multiplier;\n" +
                    "// ✅ 안전:\n" +
                    "String countStr = request.getParameter(\"count\");\n" +
                    "long count;\n" +
                    "try {\n" +
                    "    count = Long.parseLong(countStr);\n" +
                    "} catch (NumberFormatException e) {\n" +
                    "    throw new IllegalArgumentException(\"유효하지 않은 숫자: \" + countStr);\n" +
                    "}\n" +
                    "if (count < 0 || count > Integer.MAX_VALUE)\n" +
                    "    throw new IllegalArgumentException(\"허용 범위 초과: \" + count);\n" +
                    "// 또는: Math.addExact(a, b) — 오버플로우 시 ArithmeticException 발생")
                .explanation("외부 입력 정수를 검증 없이 연산에 사용하면 오버플로우로 예상치 못한 결과가 발생합니다. " +
                    "Long으로 파싱 후 Integer 범위 검증, 또는 Math.addExact()로 오버플로우를 예외로 처리하세요. " +
                    "가이드 참조: PART4 제1절 14항 정수형 오버플로우 (p.290-296)")
                .references(Arrays.asList("PART4 제1절 14항 (p.290-296)", "CWE-190: Integer Overflow"))
                .build();
    }

    // ── [IV-1.15] 보안기능 결정 부적절 입력 ──────────────────────────────────

    private RemediationResult remediateSecurityInput(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SERVER_SIDE_AUTH_CHECK")
                .securityPrinciple("보안 결정은 서버 측 세션·SecurityContext에서만 수행하고 클라이언트 입력을 사용하지 않습니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.15 보안기능 결정 입력값 방지\n" +
                    "// ❌ 취약: String role = request.getParameter(\"role\"); if (\"admin\".equals(role)) { ... }\n" +
                    "// ✅ 안전: 서버 측 세션에서 권한 확인\n" +
                    "MemberVO member = (MemberVO) session.getAttribute(\"admin\");\n" +
                    "if (member == null) throw new UnauthorizedException(\"로그인 필요\");\n" +
                    "// DB 또는 Security Context에서 실시간 권한 확인\n" +
                    "boolean hasAdminRole = memberService.selectMemberDetailInfo(member).isAdmin();\n" +
                    "if (!hasAdminRole) throw new ForbiddenException(\"관리자 권한 필요\");")
                .explanation("클라이언트에서 전달된 권한 정보(role, admin 파라미터 등)를 신뢰해서는 안 됩니다. " +
                    "권한 확인은 반드시 서버 측 세션이나 SecurityContext에서 수행하세요. " +
                    "가이드 참조: PART4 제1절 15항 보안기능 결정 부적절 입력값 (p.297-302)")
                .references(Arrays.asList("PART4 제1절 15항 (p.297-302)", "CWE-807: Reliance on Untrusted Inputs"))
                .build();
    }

    // ── [IV-1.16] 버퍼 오버플로우 ──────────────────────────────────────────

    private RemediationResult remediateBufferOverflow(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SAFE_ARRAY_ACCESS")
                .securityPrinciple("배열·버퍼 접근 전 경계값을 검증하여 오버플로우를 방지합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.16 버퍼 오버플로우 방지\n" +
                    "// ❌ 취약: System.arraycopy(src, 0, dest, 0, src.length); // dest 크기 미검증\n" +
                    "// ✅ 안전:\n" +
                    "int copyLength = Math.min(src.length, dest.length);\n" +
                    "System.arraycopy(src, 0, dest, 0, copyLength);\n" +
                    "// NIO Buffer 사용 시:\n" +
                    "ByteBuffer buffer = ByteBuffer.allocate(maxSize);\n" +
                    "buffer.limit(Math.min(data.length, maxSize));\n" +
                    "buffer.put(data, 0, buffer.limit());")
                .explanation("배열 복사·버퍼 쓰기 시 대상 버퍼의 크기를 초과하면 메모리 손상이 발생합니다. " +
                    "항상 min(src.length, dest.length)로 복사 길이를 제한하거나 NIO Buffer의 limit()을 설정하세요. " +
                    "가이드 참조: PART4 제1절 16항 메모리 버퍼 오버플로우 (p.303-308)")
                .references(Arrays.asList("PART4 제1절 16항 (p.303-308)", "CWE-119: Buffer Overflow"))
                .build();
    }

    // ── [IV-1.17] 포맷 스트링 ────────────────────────────────────────────────

    private RemediationResult remediateFormatString(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("LITERAL_FORMAT_STRING")
                .securityPrinciple("String.format 첫 인자는 리터럴로 고정하고 외부 입력값을 포맷 문자열로 사용하지 않습니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-1.17 포맷 스트링 삽입 방지\n" +
                    "// ❌ 취약: String.format(userInput, arg1, arg2);\n" +
                    "// ✅ 안전: 포맷 문자열은 항상 리터럴\n" +
                    "String userInput = request.getParameter(\"name\");\n" +
                    "String result = String.format(\"사용자: %s\", userInput);  // 포맷은 리터럴\n" +
                    "// 로깅 시:\n" +
                    "log.info(\"입력값: {}\", userInput);  // SLF4J placeholder 사용 (% 해석 없음)")
                .explanation("외부 입력을 포맷 문자열 첫 인자로 사용하면 %n, %s, %x 등으로 스택 정보 유출이 가능합니다. " +
                    "포맷 문자열은 항상 코드 내 리터럴로 고정하고 사용자 데이터는 인수(arguments)로만 전달하세요. " +
                    "가이드 참조: PART4 제1절 17항 포맷 스트링 삽입 (p.309-313)")
                .references(Arrays.asList("PART4 제1절 17항 (p.309-313)", "CWE-134: Format String Vulnerability"))
                .build();
    }

    // ── [IV-2.1] 인증 없는 중요기능 ──────────────────────────────────────────

    private RemediationResult remediateAuthMissing(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("AUTH_GATE_FILTER")
                .securityPrinciple("모든 중요 기능 진입 전 인증 상태를 확인하는 필터/인터셉터를 적용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.1 인증 누락 방지: 인증 필터 적용\n" +
                    "// Spring Security 설정:\n" +
                    "// http.authorizeRequests()\n" +
                    "//     .antMatchers(\"/admin/**\").hasRole(\"ADMIN\")\n" +
                    "//     .anyRequest().authenticated();\n\n" +
                    "// 또는 직접 확인:\n" +
                    "MemberVO loginUser = (MemberVO) session.getAttribute(\"admin\");\n" +
                    "if (loginUser == null) {\n" +
                    "    response.sendRedirect(\"/login.do\");\n" +
                    "    return;\n" +
                    "}\n" +
                    "// 권한 확인\n" +
                    "if (!loginUser.hasRole(\"ADMIN\")) response.sendError(403, \"권한 없음\");")
                .explanation("인증 없이 중요 기능에 접근 가능하면 권한 없는 사용자가 데이터를 탈취·변조할 수 있습니다. " +
                    "서블릿 필터 또는 Spring Security 인터셉터로 모든 요청에 인증을 강제하세요. " +
                    "가이드 참조: PART4 제2절 1항 적절한 인증 없는 중요기능 (p.314-318)")
                .references(Arrays.asList("PART4 제2절 1항 (p.314-318)", "CWE-306: Missing Authentication"))
                .build();
    }

    // ── [IV-2.2] 부적절한 인가 ──────────────────────────────────────────────

    private RemediationResult remediateImproperAuthz(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("RBAC_CHECK")
                .securityPrinciple("기능별 접근 권한을 서버에서 명시적으로 검증합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.2 부적절한 인가 방지: 명시적 권한 검증\n" +
                    "MemberVO member = (MemberVO) session.getAttribute(\"admin\");\n" +
                    "// 리소스 소유자 확인 (자신의 데이터만 접근 가능)\n" +
                    "String resourceOwnerId = boardService.selectBoardDetail(boardVo).getRegId();\n" +
                    "if (!member.getId().equals(resourceOwnerId) && !member.isAdmin())\n" +
                    "    throw new SecurityException(\"접근 권한이 없습니다.\");\n" +
                    "// 또는 Spring Security @PreAuthorize:\n" +
                    "// @PreAuthorize(\"#boardVo.regId == authentication.name or hasRole('ADMIN')\")")
                .explanation("인증은 되었으나 권한 검증이 없으면 다른 사용자의 데이터에 접근 가능합니다. " +
                    "RBAC(역할 기반) 또는 ABAC(속성 기반) 접근 제어를 적용하여 리소스 단위로 권한을 검증하세요. " +
                    "가이드 참조: PART4 제2절 2항 부적절한 인가 (p.319-324)")
                .references(Arrays.asList("PART4 제2절 2항 (p.319-324)", "CWE-285: Improper Authorization"))
                .build();
    }

    // ── [IV-2.3] 잘못된 권한 설정 ──────────────────────────────────────────

    private RemediationResult remediateWrongPermission(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("LEAST_PRIVILEGE")
                .securityPrinciple("파일·디렉터리 권한을 최소 권한 원칙으로 설정합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.3 잘못된 권한 설정 방지: 최소 권한\n" +
                    "// ❌ 취약: file.setReadable(true, false);  // 모든 사용자에게 읽기 허용\n" +
                    "// ✅ 안전:\n" +
                    "Set<PosixFilePermission> perms = PosixFilePermissions.fromString(\"rw-------\"); // 소유자만\n" +
                    "Files.setPosixFilePermissions(uploadedFile.toPath(), perms);\n" +
                    "// 또는 Java 레거시:\n" +
                    "file.setReadable(true, true);   // 소유자만 읽기\n" +
                    "file.setWritable(true, true);   // 소유자만 쓰기\n" +
                    "file.setExecutable(false, false); // 실행 불가")
                .explanation("파일·디렉터리를 과도하게 허용된 권한으로 생성하면 다른 사용자나 악성 프로세스가 접근할 수 있습니다. " +
                    "최소 필요 권한(소유자 읽기/쓰기 = 600)으로 설정하고 실행 권한을 부여하지 마세요. " +
                    "가이드 참조: PART4 제2절 3항 중요 자원 잘못된 권한 설정 (p.325-329)")
                .references(Arrays.asList("PART4 제2절 3항 (p.325-329)", "CWE-732: Incorrect Permission Assignment"))
                .build();
    }

    // ── [IV-2.4] 취약한 암호화 알고리즘 ────────────────────────────────────

    private RemediationResult remediateWeakCrypto(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("STRONG_CRYPTO")
                .securityPrinciple("DES/RC4/MD5/SHA-1 등 취약한 알고리즘을 AES-256/SHA-256 이상으로 교체합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.4 취약한 암호화 알고리즘 교체\n" +
                    "// ❌ 취약: Cipher.getInstance(\"DES\") / MessageDigest.getInstance(\"MD5\")\n" +
                    "// ✅ 대칭키 암호화:\n" +
                    "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n" +
                    "// ✅ 해시 (단방향):\n" +
                    "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n" +
                    "// ✅ 비밀번호 해시 (단방향, Salt 포함):\n" +
                    "// BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);\n" +
                    "// String hash = encoder.encode(rawPassword);\n" +
                    "// ✅ 비대칭키:\n" +
                    "KeyPairGenerator keyGen = KeyPairGenerator.getInstance(\"RSA\");\n" +
                    "keyGen.initialize(2048);")
                .explanation("DES(56비트), RC4, MD5, SHA-1은 이미 취약점이 알려진 알고리즘입니다. " +
                    "AES-256-GCM, SHA-256/SHA-3, RSA-2048 이상으로 교체하세요. 비밀번호는 BCrypt/Argon2/PBKDF2를 사용하세요. " +
                    "가이드 참조: PART4 제2절 4항 취약한 암호화 알고리즘 (p.330-336)")
                .references(Arrays.asList("PART4 제2절 4항 (p.330-336)", "CWE-327: Weak Cryptographic Algorithm"))
                .build();
    }

    // ── [IV-2.5] 암호화되지 않은 중요정보 ─────────────────────────────────

    private RemediationResult remediateUnencryptedData(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("ENCRYPT_SENSITIVE_DATA")
                .securityPrinciple("중요정보(비밀번호, 개인정보 등)는 반드시 암호화하여 저장합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.5 중요정보 암호화 저장\n" +
                    "// ❌ 취약: String password = request.getParameter(\"password\"); db.save(password);\n" +
                    "// ✅ 안전: BCrypt 해시 저장 (복호화 불필요한 경우)\n" +
                    "BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);\n" +
                    "String hashedPassword = encoder.encode(rawPassword);\n" +
                    "// 복호화가 필요한 정보 (개인정보 등): AES-256-GCM 사용\n" +
                    "// 암호화 키는 환경변수 또는 HSM/KMS에서 로드\n" +
                    "String encryptedData = AesGcmUtil.encrypt(sensitiveData, encryptionKey);\n" +
                    "db.save(encryptedData);\n" +
                    "// 쿠키: 민감정보 포함 금지, 필요시 암호화 + Secure + HttpOnly 속성")
                .explanation("중요정보를 평문으로 저장하면 DB 탈취 시 즉시 유출됩니다. " +
                    "비밀번호는 BCrypt/Argon2로 해시하고, 복호화 필요 정보는 AES-256-GCM으로 암호화하세요. " +
                    "가이드 참조: PART4 제2절 5항 암호화되지 않은 중요정보 (p.337-349)")
                .references(Arrays.asList("PART4 제2절 5항 (p.337-349)", "CWE-312: Cleartext Storage"))
                .build();
    }

    // ── [IV-2.6] 하드코드된 중요정보 ──────────────────────────────────────

    private RemediationResult remediateHardcodedSecret(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("EXTERNALIZE_SECRETS")
                .securityPrinciple("소스코드에서 비밀정보를 제거하고 환경변수·외부 설정 파일·Vault를 사용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.6 하드코드된 비밀정보 제거\n" +
                    "// ❌ 취약: String password = \"P@ssw0rd123\";\n" +
                    "// ✅ 안전 1: 환경변수\n" +
                    "String password = System.getenv(\"DB_PASSWORD\");\n" +
                    "if (password == null) throw new IllegalStateException(\"DB_PASSWORD 환경변수 미설정\");\n" +
                    "// ✅ 안전 2: Spring 외부 설정 (application.properties → Vault/KMS)\n" +
                    "// @Value(\"${db.password}\")\n" +
                    "// private String dbPassword;\n" +
                    "// ✅ 안전 3: AWS Secrets Manager / HashiCorp Vault API로 실시간 로드")
                .explanation("소스코드에 하드코드된 비밀정보는 버전관리 시스템에 노출되면 영구적으로 유출됩니다. " +
                    "환경변수, Spring Cloud Config, AWS Secrets Manager, HashiCorp Vault 등을 사용하고 .gitignore를 설정하세요. " +
                    "가이드 참조: PART4 제2절 6항 하드코드된 중요정보 (p.350-359)")
                .references(Arrays.asList("PART4 제2절 6항 (p.350-359)", "CWE-321: Hard-coded Cryptographic Key"))
                .build();
    }

    // ── [IV-2.7] 충분하지 않은 키 길이 ────────────────────────────────────

    private RemediationResult remediateShortKey(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("MIN_KEY_SIZE")
                .securityPrinciple("RSA 2048비트 이상, AES 128비트 이상, ECC 224비트 이상의 키 길이를 사용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.7 충분한 키 길이 사용\n" +
                    "// ❌ 취약: kpg.initialize(512); / kpg.initialize(1024);\n" +
                    "// ✅ RSA (비대칭키):\n" +
                    "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\n" +
                    "kpg.initialize(2048);  // 최소 2048비트 (권장 3072비트 이상)\n" +
                    "// ✅ AES (대칭키):\n" +
                    "KeyGenerator kg = KeyGenerator.getInstance(\"AES\");\n" +
                    "kg.init(256);  // 128비트 최소, 256비트 권장\n" +
                    "// ✅ ECC:\n" +
                    "KeyPairGenerator ecKpg = KeyPairGenerator.getInstance(\"EC\");\n" +
                    "ecKpg.initialize(new ECGenParameterSpec(\"secp256r1\"));  // 최소 224비트")
                .explanation("짧은 암호화 키는 브루트포스 공격으로 해독될 수 있습니다. " +
                    "국가정보원 및 NIST 권고에 따라 RSA 2048비트 이상, AES 128비트 이상을 사용하세요. " +
                    "가이드 참조: PART4 제2절 7항 충분하지 않은 키 길이 (p.360-363)")
                .references(Arrays.asList("PART4 제2절 7항 (p.360-363)", "CWE-326: Inadequate Encryption Strength"))
                .build();
    }

    // ── [IV-2.9] 취약한 비밀번호 정책 ─────────────────────────────────────

    private RemediationResult remediateWeakPassword(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("PASSWORD_POLICY")
                .securityPrinciple("비밀번호 복잡성·길이 정책을 강제하고 안전한 해시로 저장합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.9 비밀번호 정책 강화\n" +
                    "String password = request.getParameter(\"password\");\n" +
                    "// 복잡성 검증: 8자 이상, 대소문자·숫자·특수문자 포함\n" +
                    "if (!password.matches(\"^(?=.*[A-Z])(?=.*[a-z])(?=.*\\\\d)(?=.*[!@#$%^&*]).{8,}$\"))\n" +
                    "    throw new IllegalArgumentException(\"비밀번호는 8자 이상, 대소문자·숫자·특수문자를 포함해야 합니다.\");\n" +
                    "// 안전한 해시 저장\n" +
                    "BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);\n" +
                    "String hashedPw = encoder.encode(password);\n" +
                    "// 검증 시: encoder.matches(rawPw, hashedPw)")
                .explanation("취약한 비밀번호는 브루트포스·사전 공격에 취약합니다. " +
                    "복잡성 정책(8자 이상, 대소문자·숫자·특수문자)을 강제하고 BCrypt(cost=12) 이상으로 안전하게 저장하세요. " +
                    "가이드 참조: PART4 제2절 9항 취약한 비밀번호 정책 (p.370-376)")
                .references(Arrays.asList("PART4 제2절 9항 (p.370-376)", "CWE-521: Weak Password Requirements"))
                .build();
    }

    // ── [IV-2.10] 서명 검증 없는 코드 다운로드 ──────────────────────────────

    private RemediationResult remediateSignatureVerify(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("VERIFY_SIGNATURE")
                .securityPrinciple("외부에서 다운로드한 코드·데이터의 서명 또는 체크섬을 반드시 검증합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.10 코드 서명 검증\n" +
                    "// 체크섬(SHA-256) 검증:\n" +
                    "byte[] downloadedBytes = Files.readAllBytes(downloadedFile.toPath());\n" +
                    "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n" +
                    "String actualHash = HexFormat.of().formatHex(digest.digest(downloadedBytes));\n" +
                    "if (!expectedHash.equals(actualHash))\n" +
                    "    throw new SecurityException(\"무결성 검증 실패: 파일이 변조되었습니다.\");\n" +
                    "// 코드 서명(JAR): jarsigner -verify myapp.jar")
                .explanation("서명 없이 다운로드한 코드를 실행하면 공급망 공격(Supply Chain Attack)에 노출됩니다. " +
                    "SHA-256 체크섬 또는 코드 서명(JAR Signing, GPG)으로 무결성을 검증하세요. " +
                    "가이드 참조: PART4 제2절 10항 (p.377-382)")
                .references(Arrays.asList("PART4 제2절 10항 (p.377-382)", "CWE-494: Download without Integrity Check"))
                .build();
    }

    // ── [IV-2.11] 인증서 검증 누락 ─────────────────────────────────────────

    private RemediationResult remediateCertValidation(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("PROPER_CERT_VALIDATION")
                .securityPrinciple("TLS/SSL 인증서 검증을 비활성화하지 않습니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.11 인증서 검증 누락 방지\n" +
                    "// ❌ 취약: 인증서 검증 무력화 금지\n" +
                    "// TrustManager가 모든 인증서를 허용하거나 HostnameVerifier.verify()가 항상 true 반환 금지\n\n" +
                    "// ✅ 안전: 기본 SSLContext (시스템 CA 신뢰)\n" +
                    "HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();\n" +
                    "// 기본 설정만 사용 — SSLSocketFactory를 덮어쓰지 않음\n\n" +
                    "// 자체 서명 인증서 사용 시: 해당 CA를 신뢰 저장소(TrustStore)에 등록\n" +
                    "// keytool -import -alias myCa -keystore truststore.jks -file ca.crt\n" +
                    "// SSLContext ctx = SSLContext.getInstance(\"TLS\");\n" +
                    "// ctx.init(null, trustManagerFromTrustStore, null);")
                .explanation("인증서 검증을 비활성화하면 중간자 공격(MITM)으로 통신 내용이 탈취될 수 있습니다. " +
                    "프로덕션 환경에서는 절대로 TrustManager나 HostnameVerifier를 무력화하지 마세요. " +
                    "가이드 참조: PART4 제2절 11항 인증서 유효성 검증 (p.383-387)")
                .references(Arrays.asList("PART4 제2절 11항 (p.383-387)", "CWE-295: Improper Certificate Validation"))
                .build();
    }

    // ── [IV-2.12] 쿠키 보안속성 ────────────────────────────────────────────

    private RemediationResult remediateInsecureCookie(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SECURE_COOKIE_ATTRIBUTES")
                .securityPrinciple("모든 세션 쿠키에 Secure, HttpOnly, SameSite 속성을 설정합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.12 쿠키 보안 속성 설정\n" +
                    "Cookie sessionCookie = new Cookie(\"JSESSIONID\", sessionId);\n" +
                    "sessionCookie.setHttpOnly(true);    // JavaScript에서 쿠키 접근 금지 (XSS 방어)\n" +
                    "sessionCookie.setSecure(true);      // HTTPS 전송만 허용\n" +
                    "sessionCookie.setPath(\"/\");\n" +
                    "sessionCookie.setMaxAge(1200);      // 20분 (세션 만료와 일치)\n" +
                    "// SameSite 속성 (서블릿 API 직접 지원 없음, 헤더로 설정):\n" +
                    "response.setHeader(\"Set-Cookie\",\n" +
                    "    \"JSESSIONID=\" + sessionId + \"; Path=/; HttpOnly; Secure; SameSite=Strict\");\n" +
                    "response.addCookie(sessionCookie);\n" +
                    "// Spring Boot: server.servlet.session.cookie.http-only=true 설정")
                .explanation("HttpOnly 없으면 XSS로 세션 토큰 탈취, Secure 없으면 HTTP에서 쿠키 노출, " +
                    "SameSite 없으면 CSRF 공격에 취약합니다. 세션 쿠키에 3가지 속성을 반드시 설정하세요. " +
                    "가이드 참조: PART4 제2절 12항 쿠키 보안 속성 미설정 (p.388-393)")
                .references(Arrays.asList("PART4 제2절 12항 (p.388-393)", "CWE-614: Sensitive Cookie without Secure Attribute"))
                .build();
    }

    // ── [IV-2.13] 주석 내 민감정보 ─────────────────────────────────────────

    private RemediationResult remediateSensitiveComment(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("REMOVE_SENSITIVE_COMMENTS")
                .securityPrinciple("소스코드 주석에서 계정정보·내부 구조·취약점 관련 정보를 제거합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.13 주석 내 민감정보 제거\n" +
                    "// ❌ 제거 대상 주석:\n" +
                    "// // admin: admin / password: P@ssw0rd\n" +
                    "// // TODO: 이 쿼리는 SQL 인젝션에 취약함 — 나중에 수정\n" +
                    "// // DB: 192.168.1.100:3306 / testdb\n\n" +
                    "// ✅ 허용되는 주석:\n" +
                    "// IV-2.13: 민감정보 주석 제거 완료\n" +
                    "// 인증 로직은 AuthService.authenticate() 참고\n\n" +
                    "// 배포 전 검사: grep -rn 'password\\|secret\\|TODO.*취약\\|DB.*IP' src/")
                .explanation("소스코드 주석의 계정 정보, 내부 IP, 취약점 설명은 소스코드 유출 시 공격자에게 직접 노출됩니다. " +
                    "배포 전 민감 키워드(password, secret, TODO:취약 등)를 grep으로 검색하여 제거하세요. " +
                    "가이드 참조: PART4 제2절 13항 주석 내 민감정보 포함 (p.394-397)")
                .references(Arrays.asList("PART4 제2절 13항 (p.394-397)", "CWE-615: Sensitive Data in Comments"))
                .build();
    }

    // ── [IV-2.14] 솔트 없는 단방향 해시 ────────────────────────────────────

    private RemediationResult remediateSaltedHash(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SALTED_HASH")
                .securityPrinciple("비밀번호 해시 시 솔트를 추가하거나 BCrypt/Argon2를 사용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.14 솔트 없는 해시 방지: BCrypt 사용 (내부적으로 솔트 자동 포함)\n" +
                    "// ❌ 취약: MessageDigest.getInstance(\"SHA-256\").digest(password.getBytes())\n" +
                    "// ✅ 안전 1: BCrypt (Spring Security)\n" +
                    "BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);  // cost=12\n" +
                    "String hash = encoder.encode(rawPassword);\n" +
                    "boolean matches = encoder.matches(rawPassword, hash);\n\n" +
                    "// ✅ 안전 2: PBKDF2 (직접 구현 필요 시)\n" +
                    "PBEKeySpec spec = new PBEKeySpec(rawPassword.toCharArray(), salt, 310000, 256);\n" +
                    "SecretKeyFactory skf = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");\n" +
                    "byte[] hash2 = skf.generateSecret(spec).getEncoded();")
                .explanation("솔트 없는 해시는 레인보우 테이블 공격으로 역추적됩니다. " +
                    "BCrypt(cost≥12), Argon2, PBKDF2(310000회 이상 반복)를 사용하면 솔트가 자동 포함됩니다. " +
                    "가이드 참조: PART4 제2절 14항 적절하지 않은 단방향 함수 (p.398-401)")
                .references(Arrays.asList("PART4 제2절 14항 (p.398-401)", "CWE-759: Use of a One-Way Hash without Salt"))
                .build();
    }

    // ── [IV-2.15] 코드 다운로드 체크섬 ────────────────────────────────────

    private RemediationResult remediateCodeDownload(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("CHECKSUM_VERIFY")
                .securityPrinciple("외부에서 다운로드한 파일의 체크섬을 검증하여 무결성을 확인합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.15 체크섬 미검증 방지\n" +
                    "URL url = new URL(downloadUrl);\n" +
                    "Path tempFile = Files.createTempFile(\"download\", \".tmp\");\n" +
                    "try (InputStream is = url.openStream()) {\n" +
                    "    Files.copy(is, tempFile, StandardCopyOption.REPLACE_EXISTING);\n" +
                    "}\n" +
                    "// SHA-256 체크섬 검증\n" +
                    "String actualSha256 = computeSha256(tempFile);\n" +
                    "if (!expectedSha256.equalsIgnoreCase(actualSha256))\n" +
                    "    throw new SecurityException(\"파일 무결성 검증 실패 — 변조 의심\");\n" +
                    "// 공개키 서명 검증 (더 강력):\n" +
                    "// Signature sig = Signature.getInstance(\"SHA256withRSA\");\n" +
                    "// sig.initVerify(publicKey);\n" +
                    "// sig.update(Files.readAllBytes(tempFile));\n" +
                    "// if (!sig.verify(signature)) throw new SecurityException(\"서명 불일치\");")
                .explanation("서명 없이 다운로드한 라이브러리·코드를 사용하면 공급망 공격에 노출됩니다. " +
                    "SHA-256 체크섬 또는 공개키 서명으로 무결성을 검증하고 TLS HTTPS를 통해서만 다운로드하세요. " +
                    "가이드 참조: PART4 제2절 15항 (p.402-405)")
                .references(Arrays.asList("PART4 제2절 15항 (p.402-405)", "CWE-494: Download without Integrity Check"))
                .build();
    }

    // ── [IV-2.16] 계정 잠금 미구현 ─────────────────────────────────────────

    private RemediationResult remediateNoLockout(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("ACCOUNT_LOCKOUT")
                .securityPrinciple("반복 인증 실패 시 계정 잠금 또는 지연 메커니즘을 적용합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-2.16 계정 잠금 구현\n" +
                    "int failCount = memberService.getLoginFailCount(userId);\n" +
                    "if (failCount >= 5) {\n" +
                    "    long lockoutEnd = memberService.getLockoutEndTime(userId);\n" +
                    "    if (System.currentTimeMillis() < lockoutEnd) {\n" +
                    "        long remaining = (lockoutEnd - System.currentTimeMillis()) / 1000;\n" +
                    "        throw new LockedException(remaining + \"초 후에 다시 시도하세요.\");\n" +
                    "    }\n" +
                    "}\n" +
                    "boolean success = authenticate(userId, password);\n" +
                    "if (success) {\n" +
                    "    memberService.resetFailCount(userId);\n" +
                    "} else {\n" +
                    "    memberService.incrementFailCount(userId);\n" +
                    "    if (failCount + 1 >= 5) memberService.setLockout(userId, 30);  // 30분\n" +
                    "    throw new BadCredentialsException(\"인증 실패\");\n" +
                    "}\n" +
                    "// Spring Security: UserDetailsService + AbstractUserDetailsAuthenticationProvider")
                .explanation("계정 잠금 미구현 시 브루트포스·스터핑 공격으로 계정이 탈취될 수 있습니다. " +
                    "5회 실패 후 30분 잠금 또는 지수 백오프(exponential backoff)를 적용하고 " +
                    "CAPTCHA를 추가하는 것을 권장합니다. " +
                    "가이드 참조: PART4 제2절 16항 인증 수행 횟수 제한 (p.406-408)")
                .references(Arrays.asList("PART4 제2절 16항 (p.406-408)", "CWE-307: Brute Force"))
                .build();
    }

    // ── [IV-3.2] 무한 반복문 ────────────────────────────────────────────────

    private RemediationResult remediateInfiniteLoop(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("TERMINATION_CONDITION")
                .securityPrinciple("반복문·재귀 함수에 명확한 종료 조건과 최대 반복 횟수를 제한합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-3.2 무한 반복문 방지: 명확한 종료 조건 추가\n" +
                    "// ❌ 취약: while(true) { ... } / for(;;) { ... }\n" +
                    "// ✅ 안전:\n" +
                    "int maxRetries = 3;\n" +
                    "int attempt = 0;\n" +
                    "while (attempt < maxRetries && !isComplete()) {\n" +
                    "    process();\n" +
                    "    attempt++;\n" +
                    "}\n" +
                    "if (attempt >= maxRetries) log.warn(\"최대 재시도 횟수 초과\");\n\n" +
                    "// 재귀 함수: 최대 깊이 제한\n" +
                    "private void recurse(int depth) {\n" +
                    "    if (depth > 100) throw new RuntimeException(\"최대 재귀 깊이 초과\");\n" +
                    "    // ...\n" +
                    "    recurse(depth + 1);\n" +
                    "}")
                .explanation("종료 조건 없는 반복문은 서비스 거부(DoS) 공격에 악용되거나 CPU를 고갈시킬 수 있습니다. " +
                    "외부 입력에 의존하는 반복에는 반드시 최대 반복 횟수나 타임아웃을 설정하세요. " +
                    "가이드 참조: PART4 제3절 2항 종료되지 않는 반복문 (p.415-418)")
                .references(Arrays.asList("PART4 제3절 2항 (p.415-418)", "CWE-835: Loop with Unreachable Exit Condition"))
                .build();
    }

    // ── [IV-4.2] 빈 catch 블록 ──────────────────────────────────────────────

    private RemediationResult remediateEmptyCatch(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("HANDLE_ALL_EXCEPTIONS")
                .securityPrinciple("모든 catch 블록에서 예외를 적절히 처리하고 로그를 기록합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-4.2 빈 catch 블록 금지\n" +
                    "// ❌ 취약: try { ... } catch (Exception e) { }\n" +
                    "// ✅ 안전:\n" +
                    "try {\n" +
                    "    businessLogic();\n" +
                    "} catch (SQLException e) {\n" +
                    "    log.error(\"[DB] 데이터베이스 오류: {}\", e.getMessage(), e);\n" +
                    "    throw new ServiceException(\"데이터 처리 중 오류 발생\", e);\n" +
                    "} catch (IOException e) {\n" +
                    "    log.error(\"[IO] 입출력 오류: {}\", e.getMessage(), e);\n" +
                    "    throw new ServiceException(\"파일 처리 중 오류 발생\", e);\n" +
                    "} catch (Exception e) {\n" +
                    "    log.error(\"[Unhandled] 예상치 못한 오류: {}\", e.getMessage(), e);\n" +
                    "    throw new ServiceException(\"처리 중 오류가 발생했습니다.\", e);\n" +
                    "}")
                .explanation("빈 catch 블록은 예외를 무시하여 잘못된 상태로 실행이 계속되거나 보안 이벤트를 놓칠 수 있습니다. " +
                    "모든 예외를 로그에 기록하고 필요시 상위로 전파하거나 사용자에게 일반 오류 메시지를 반환하세요. " +
                    "가이드 참조: PART4 제4절 2항 부적절한 예외 처리 (p.425-428)")
                .references(Arrays.asList("PART4 제4절 2항 (p.425-428)", "CWE-390: Detection of Error Condition Without Action"))
                .build();
    }

    // ── [IV-4.3] 과도한 예외 처리 ───────────────────────────────────────────

    private RemediationResult remediateOverbroadCatch(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SPECIFIC_EXCEPTION_HANDLING")
                .securityPrinciple("Exception과 같이 과도하게 넓은 예외 대신 구체적인 예외 타입을 처리합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-4.3 과도한 예외 처리 개선\n" +
                    "// ❌ 취약: catch (Exception e) { /* 모든 예외를 하나로 */ }\n" +
                    "// ✅ 안전: 예외 종류별 분리 처리\n" +
                    "try {\n" +
                    "    // 구체적인 예외 먼저 처리\n" +
                    "} catch (java.sql.SQLException e) {\n" +
                    "    // DB 관련 처리\n" +
                    "    log.error(\"[DB] SQL 오류: errorCode={}\", e.getErrorCode(), e);\n" +
                    "} catch (java.io.IOException e) {\n" +
                    "    // 파일/네트워크 처리\n" +
                    "    log.error(\"[IO] 입출력 오류\", e);\n" +
                    "} catch (RuntimeException e) {\n" +
                    "    log.error(\"[Runtime] 런타임 오류\", e);\n" +
                    "    throw e;  // 재발생\n" +
                    "}")
                .explanation("catch(Exception e)는 복구 불가능한 오류(OutOfMemoryError 제외)를 포함하여 의도치 않은 처리가 됩니다. " +
                    "구체적인 예외 타입별로 분리하여 오류 원인을 명확히 파악하고 적절한 복구 로직을 적용하세요. " +
                    "가이드 참조: PART4 제4절 3항 과도하게 광범위한 예외 처리 (p.429-432)")
                .references(Arrays.asList("PART4 제4절 3항 (p.429-432)", "CWE-396: Overly Broad Catch"))
                .build();
    }

    // ── [IV-5.1] Null 포인터 역참조 ────────────────────────────────────────

    private RemediationResult remediateNullPointer(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("NULL_CHECK")
                .securityPrinciple("외부 입력과 메서드 반환값에 대해 null 검사를 수행합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-5.1 Null 포인터 역참조 방지\n" +
                    "// ❌ 취약: String value = request.getParameter(\"key\"); value.trim();\n" +
                    "// ✅ 안전 1: null 체크\n" +
                    "String value = request.getParameter(\"key\");\n" +
                    "if (value == null || value.isBlank()) {\n" +
                    "    throw new IllegalArgumentException(\"필수 파라미터 누락: key\");\n" +
                    "}\n" +
                    "// ✅ 안전 2: Optional 활용\n" +
                    "Optional.ofNullable(request.getParameter(\"key\"))\n" +
                    "    .filter(v -> !v.isBlank())\n" +
                    "    .orElseThrow(() -> new IllegalArgumentException(\"필수 파라미터 누락\"));\n" +
                    "// ✅ 안전 3: @NotNull 검증 (Bean Validation)\n" +
                    "// @RequestParam(required = true) String key")
                .explanation("null 역참조는 서비스를 중단시키고 오류 메시지를 통해 내부 정보를 노출할 수 있습니다. " +
                    "외부 입력, DB 조회 결과, Optional 등에 대해 항상 null 검사를 수행하세요. " +
                    "가이드 참조: PART4 제5절 1항 Null 포인터 역참조 (p.433-437)")
                .references(Arrays.asList("PART4 제5절 1항 (p.433-437)", "CWE-476: NULL Pointer Dereference"))
                .build();
    }

    // ── [IV-5.2] 자원 반환 누락 ─────────────────────────────────────────────

    private RemediationResult remediateResourceLeak(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("TRY_WITH_RESOURCES")
                .securityPrinciple("AutoCloseable 자원은 try-with-resources로 자동 반환을 보장합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-5.2 자원 반환 누락 방지: try-with-resources 사용\n" +
                    "// ❌ 취약:\n" +
                    "// InputStream in = new FileInputStream(file);\n" +
                    "// // 예외 발생 시 in.close() 호출 안 됨\n\n" +
                    "// ✅ 안전:\n" +
                    "try (InputStream in = new FileInputStream(file);\n" +
                    "     BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {\n" +
                    "    String line;\n" +
                    "    while ((line = reader.readLine()) != null) {\n" +
                    "        // 처리\n" +
                    "    }\n" +
                    "} catch (IOException e) {\n" +
                    "    log.error(\"파일 읽기 오류: {}\", e.getMessage(), e);\n" +
                    "}\n" +
                    "// DB 연결:\n" +
                    "try (Connection con = dataSource.getConnection();\n" +
                    "     PreparedStatement pstmt = con.prepareStatement(sql)) { ... }")
                .explanation("파일·DB 연결 등의 자원을 finally 블록 없이 사용하면 예외 발생 시 자원이 누수됩니다. " +
                    "Java 7+ try-with-resources를 사용하면 예외 발생 여부와 관계없이 자원이 자동으로 닫힙니다. " +
                    "가이드 참조: PART4 제5절 2항 자원 반환 누락 (p.438-442)")
                .references(Arrays.asList("PART4 제5절 2항 (p.438-442)", "CWE-772: Resource Leak"))
                .build();
    }

    // ── [IV-5.3] 해제된 자원 사용 ───────────────────────────────────────────

    private RemediationResult remediateUseAfterClose(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("NULL_AFTER_CLOSE")
                .securityPrinciple("자원 반환 후 참조 변수를 null로 설정하여 재사용을 방지합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-5.3 해제된 자원 재사용 방지\n" +
                    "// ❌ 취약:\n" +
                    "// connection.close();\n" +
                    "// connection.createStatement();  // 이미 닫힌 연결 사용\n\n" +
                    "// ✅ 안전 1: try-with-resources (범위 밖에서 사용 불가)\n" +
                    "try (Connection con = dataSource.getConnection()) {\n" +
                    "    // con은 이 블록 안에서만 유효\n" +
                    "}\n" +
                    "// con은 여기서 더 이상 참조할 수 없음\n\n" +
                    "// ✅ 안전 2: 수동 닫기 시 null 할당\n" +
                    "InputStream in = null;\n" +
                    "try {\n" +
                    "    in = new FileInputStream(file);\n" +
                    "    // 사용\n" +
                    "} finally {\n" +
                    "    if (in != null) { in.close(); in = null; }\n" +
                    "}")
                .explanation("이미 닫힌 스트림·연결을 재사용하면 예외가 발생하고 오류 처리 과정에서 내부 정보가 노출될 수 있습니다. " +
                    "try-with-resources를 사용하거나 close() 후 변수를 null로 설정하세요. " +
                    "가이드 참조: PART4 제5절 3항 해제된 자원 사용 (p.443-446)")
                .references(Arrays.asList("PART4 제5절 3항 (p.443-446)", "CWE-416: Use After Free"))
                .build();
    }

    // ── [IV-5.4] 초기화되지 않은 변수 사용 ────────────────────────────────

    private RemediationResult remediateUninitVar(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("INITIALIZE_VARIABLES")
                .securityPrinciple("변수를 선언과 동시에 안전한 기본값으로 초기화합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-5.4 초기화되지 않은 변수 사용 방지\n" +
                    "// ❌ 취약:\n" +
                    "// int count;\n" +
                    "// if (condition) count = 5;\n" +
                    "// process(count);  // count가 초기화되지 않을 수 있음\n\n" +
                    "// ✅ 안전: 선언 시 기본값 설정\n" +
                    "int count = 0;  // 안전한 기본값\n" +
                    "String message = \"\";  // null 대신 빈 문자열\n" +
                    "List<String> items = new ArrayList<>();  // null 대신 빈 컬렉션\n\n" +
                    "if (condition) count = fetchCount();\n" +
                    "process(count);\n\n" +
                    "// 객체형: Optional 활용\n" +
                    "Optional<User> user = Optional.empty();\n" +
                    "if (authenticated) user = Optional.of(loadUser());\n" +
                    "user.ifPresent(u -> process(u));")
                .explanation("초기화되지 않은 변수를 사용하면 예측 불가한 값으로 처리되어 보안 검사가 우회될 수 있습니다. " +
                    "항상 선언과 동시에 안전한 기본값(0, \"\", false, null 검사 후 Optional)을 할당하세요. " +
                    "가이드 참조: PART4 제5절 4항 초기화되지 않은 변수 사용 (p.447-450)")
                .references(Arrays.asList("PART4 제5절 4항 (p.447-450)", "CWE-457: Use of Uninitialized Variable"))
                .build();
    }

    // ── [IV-6.1] 세션 격리 ──────────────────────────────────────────────────

    private RemediationResult remediateSessionIsolation(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SESSION_ISOLATION")
                .securityPrinciple("사용자별 세션을 완전히 격리하고 세션 공유를 방지합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-6.1 세션 격리\n" +
                    "// 로그인 성공 시 Session Fixation 방지:\n" +
                    "HttpSession oldSession = request.getSession(false);\n" +
                    "if (oldSession != null) {\n" +
                    "    oldSession.invalidate();  // 기존 세션 파기\n" +
                    "}\n" +
                    "HttpSession newSession = request.getSession(true);  // 새 세션 ID 발급\n" +
                    "newSession.setAttribute(\"admin\", authenticatedMember);\n" +
                    "newSession.setMaxInactiveInterval(1200);  // 20분 타임아웃\n\n" +
                    "// 로그아웃 시 세션 완전 무효화:\n" +
                    "HttpSession session = request.getSession(false);\n" +
                    "if (session != null) {\n" +
                    "    session.invalidate();\n" +
                    "}\n" +
                    "// JSESSIONID 쿠키 삭제:\n" +
                    "Cookie cookie = new Cookie(\"JSESSIONID\", \"\");\n" +
                    "cookie.setMaxAge(0);\n" +
                    "cookie.setPath(\"/\");\n" +
                    "response.addCookie(cookie);")
                .explanation("세션 고정(Session Fixation) 공격은 공격자가 미리 알고 있는 세션 ID로 피해자를 인증시킵니다. " +
                    "로그인 성공 후 반드시 새 세션을 생성하고 20분 타임아웃을 설정하세요. " +
                    "가이드 참조: PART4 제6절 1항 세션 관리 (p.451-457)")
                .references(Arrays.asList("PART4 제6절 1항 (p.451-457)", "CWE-384: Session Fixation"))
                .build();
    }

    // ── [DS-4.1] 세션 설계 ──────────────────────────────────────────────────

    private RemediationResult remediateSessionDesign(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SESSION_DESIGN")
                .securityPrinciple("서비스 레이어 메서드에 HttpSession 객체를 직접 전달하지 않고 필요한 속성값만 추출하여 전달합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] DS-4.1 세션 통제 설계\n" +
                    "// ❌ 취약: boardService.setMemberInfo(vo, request.getSession());\n" +
                    "// ✅ 안전: 필요한 속성값만 추출하여 전달\n\n" +
                    "// [Controller]\n" +
                    "MemberVO loginMember = (MemberVO) session.getAttribute(\"admin\");\n" +
                    "if (loginMember == null) throw new UnauthorizedException(\"로그인 필요\");\n" +
                    "vo = boardService.setMemberInfo(vo, loginMember.getId(), loginMember.getName());\n\n" +
                    "// [Service] - HttpSession 파라미터 제거\n" +
                    "public BoardVO setMemberInfo(BoardVO vo, String userId, String userName) {\n" +
                    "    if (userId != null) {\n" +
                    "        vo.setRegId(userId);\n" +
                    "        vo.setRegName(userName);\n" +
                    "        vo.setUpdId(userId);\n" +
                    "        vo.setUpdName(userName);\n" +
                    "    }\n" +
                    "    return vo;\n" +
                    "}\n" +
                    "// 세션 만료: web.xml <session-timeout>20</session-timeout>\n" +
                    "// Session Fixation: 로그인 후 session.invalidate() + 새 세션 발급")
                .explanation("서비스 레이어가 HttpSession 전체를 받으면 불필요한 데이터 접근·변조 위험이 있습니다. " +
                    "컨트롤러에서 session.getAttribute()로 필요한 값만 추출 후 서비스에 전달하세요. " +
                    "가이드 참조: PART3 제4절 1항 세션 통제 (p.165-170)")
                .references(Arrays.asList("PART3 제4절 1항 (p.165-170)", "CWE-488: Exposure of Data Element to Wrong Session"))
                .build();
    }

    // ── [IV-6.2] 디버그 코드 ────────────────────────────────────────────────

    private RemediationResult remediateDebugCode(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("REMOVE_DEBUG_CODE")
                .securityPrinciple("배포 버전에서 디버그 코드, 백도어, 테스트 계정을 제거합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-6.2 디버그 코드 제거\n" +
                    "// ❌ 제거 대상:\n" +
                    "// System.out.println(\"DEBUG: password=\" + password);\n" +
                    "// e.printStackTrace();\n" +
                    "// if (userId.equals(\"testadmin\")) { return true; }  // 테스트 우회\n\n" +
                    "// ✅ 안전: SLF4J Logger + 조건부 디버그 로그\n" +
                    "private static final Logger log = LoggerFactory.getLogger(MyClass.class);\n\n" +
                    "log.debug(\"처리 시작 (민감정보 미포함)\");  // 프로덕션에서 DEBUG 레벨 비활성화\n" +
                    "// logback.xml: <root level=\"INFO\"> (프로덕션)\n\n" +
                    "// 배포 전 검사:\n" +
                    "// grep -rn 'System.out\\|e.printStackTrace\\|TODO.*debug\\|hardcode' src/")
                .explanation("디버그 코드나 테스트 우회 코드가 배포되면 공격자에게 시스템 내부 정보가 노출됩니다. " +
                    "배포 전 반드시 System.out.println, printStackTrace, 하드코드된 테스트 계정을 제거하고 " +
                    "프로덕션 로그 레벨을 INFO 이상으로 설정하세요. " +
                    "가이드 참조: PART4 제6절 2항 디버그 코드 (p.458-461)")
                .references(Arrays.asList("PART4 제6절 2항 (p.458-461)", "CWE-489: Active Debug Code"))
                .build();
    }

    // ── [IV-6.3] 공개 메서드 배열 반환 ─────────────────────────────────────

    private RemediationResult remediatePrivateArrayReturn(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("DEFENSIVE_COPY")
                .securityPrinciple("내부 배열·컬렉션을 반환할 때 방어적 복사본을 제공합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-6.3 공개 메서드에서 배열 직접 반환 방지\n" +
                    "// ❌ 취약: public String[] getValues() { return internalArray; }  // 내부 배열 직접 노출\n\n" +
                    "// ✅ 안전 1: 배열 복사 반환\n" +
                    "public String[] getValues() {\n" +
                    "    return Arrays.copyOf(internalArray, internalArray.length);\n" +
                    "}\n\n" +
                    "// ✅ 안전 2: 불변 리스트 반환 (권장)\n" +
                    "private final List<String> internalList;\n" +
                    "public List<String> getValues() {\n" +
                    "    return Collections.unmodifiableList(internalList);\n" +
                    "    // 또는: return List.copyOf(internalList);  // Java 10+\n" +
                    "}")
                .explanation("내부 배열을 직접 반환하면 호출자가 배열을 변조하여 클래스의 불변성이 깨집니다. " +
                    "방어적 복사(Arrays.copyOf) 또는 불변 뷰(Collections.unmodifiableList)를 반환하세요. " +
                    "가이드 참조: PART4 제6절 3항 Public 메서드로부터 반환된 Private 배열 (p.462-464)")
                .references(Arrays.asList("PART4 제6절 3항 (p.462-464)", "CWE-375: Returning a Mutable Object Installed in a Field"))
                .build();
    }

    // ── [IV-6.4] private 배열 입력값 할당 ───────────────────────────────────

    private RemediationResult remediatePrivateArrayAssign(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("DEFENSIVE_COPY_INPUT")
                .securityPrinciple("외부에서 전달받은 배열·컬렉션은 방어적 복사 후 내부 필드에 저장합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-6.4 Private 배열에 외부 입력 직접 할당 방지\n" +
                    "// ❌ 취약: this.internalArray = inputArray;  // 외부 참조 그대로 저장\n\n" +
                    "// ✅ 안전: 방어적 복사 후 저장\n" +
                    "public void setValues(String[] inputArray) {\n" +
                    "    if (inputArray == null) {\n" +
                    "        this.internalArray = new String[0];\n" +
                    "    } else {\n" +
                    "        this.internalArray = Arrays.copyOf(inputArray, inputArray.length);\n" +
                    "    }\n" +
                    "}\n\n" +
                    "// 컬렉션:\n" +
                    "public void setItems(List<String> items) {\n" +
                    "    this.items = items != null ? new ArrayList<>(items) : new ArrayList<>();\n" +
                    "}")
                .explanation("외부 배열을 방어적 복사 없이 내부 필드에 저장하면 호출자가 내부 상태를 변조할 수 있습니다. " +
                    "생성자와 setter에서 Arrays.copyOf() 또는 new ArrayList<>()로 복사본을 저장하세요. " +
                    "가이드 참조: PART4 제6절 4항 Private 배열에 Public 데이터 할당 (p.465-467)")
                .references(Arrays.asList("PART4 제6절 4항 (p.465-467)", "CWE-374: Passing Mutable Objects to an Untrusted Method"))
                .build();
    }

    // ── [IV-7.1] IP 주소 기반 인증 ─────────────────────────────────────────

    private RemediationResult remediateDnsLookup(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("IP_BASED_CHECK")
                .securityPrinciple("DNS 조회 결과나 클라이언트 IP를 보안 결정에 사용하지 않습니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-7.1 DNS 조회 기반 인증 제거\n" +
                    "// ❌ 취약:\n" +
                    "// String hostname = InetAddress.getByName(ip).getHostName();\n" +
                    "// if (hostname.endsWith(\".trusted.com\")) { allow(); }  // DNS 스푸핑 가능\n\n" +
                    "// ❌ 취약:\n" +
                    "// if (request.getHeader(\"X-Forwarded-For\").startsWith(\"192.168\")) { allow(); }\n\n" +
                    "// ✅ 안전: 강력한 인증 수단 사용 (IP 기반 보조 수단으로만)\n" +
                    "// 1) API Key + 인증서 기반 mTLS 인증\n" +
                    "// 2) OAuth 2.0 / JWT 토큰 검증\n" +
                    "// 3) Spring Security 기반 인증\n\n" +
                    "// IP를 보조 수단으로 사용 시 (로컬 네트워크 확인만):\n" +
                    "String remoteAddr = request.getRemoteAddr();  // X-Forwarded-For 미신뢰\n" +
                    "InetAddress addr = InetAddress.getByName(remoteAddr);\n" +
                    "if (!addr.isSiteLocalAddress()) throw new SecurityException(\"내부 네트워크만 허용\");")
                .explanation("DNS 역방향 조회는 DNS 스푸핑으로 위조될 수 있습니다. X-Forwarded-For 헤더는 공격자가 조작할 수 있습니다. " +
                    "IP는 보조 수단에만 사용하고 인증서·토큰 기반 강력한 인증을 주 수단으로 사용하세요. " +
                    "가이드 참조: PART4 제7절 1항 DNS 조회를 통한 보안 결정 (p.468-471)")
                .references(Arrays.asList("PART4 제7절 1항 (p.468-471)", "CWE-350: Reliance on Reverse DNS Resolution"))
                .build();
    }

    // ── [IV-7.2] 취약한 API 사용 ────────────────────────────────────────────

    private RemediationResult remediateVulnerableApi(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SAFE_API_REPLACEMENT")
                .securityPrinciple("알려진 취약한 API를 안전한 대안으로 교체합니다.")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(
                    "// [수정] IV-7.2 취약한 API 교체\n" +
                    "// ❌ 취약 API → ✅ 안전 대안:\n\n" +
                    "// 문자열 비교 (타이밍 공격 방어):\n" +
                    "// ❌: token.equals(expected)\n" +
                    "// ✅: MessageDigest.isEqual(token.getBytes(), expected.getBytes())\n\n" +
                    "// 난수 생성:\n" +
                    "// ❌: new Random().nextInt()\n" +
                    "// ✅: new SecureRandom().nextInt()\n\n" +
                    "// XML 파싱:\n" +
                    "// ❌: DocumentBuilderFactory.newInstance() (기본 설정 — XXE 취약)\n" +
                    "// ✅: dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n\n" +
                    "// 스레드 정지:\n" +
                    "// ❌: thread.stop() / thread.suspend()\n" +
                    "// ✅: interrupt 신호 + volatile boolean running 플래그")
                .explanation("취약한 API는 보안 취약점으로 직결됩니다. 최신 Java 보안 API로 교체하고 " +
                    "deprecated된 API(Thread.stop, System.getenv 등)의 사용 여부를 정기적으로 검토하세요. " +
                    "가이드 참조: PART4 제7절 2항 취약한 API 사용 (p.472-476)")
                .references(Arrays.asList("PART4 제7절 2항 (p.472-476)", "CWE-477: Use of Obsolete Function"))
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
        return switch (ruleId) {
            // ── PART4 제1절 ──
            case "IV-1.1"  -> "USE_PREPARED_STATEMENT";
            case "IV-1.2"  -> "WHITELIST_VALIDATION";
            case "IV-1.3"  -> "PATH_CANONICALIZATION";
            case "IV-1.4"  -> "OUTPUT_ENCODING";
            case "IV-1.5"  -> "AVOID_OS_COMMAND";
            case "IV-1.6"  -> "FILE_EXTENSION_WHITELIST";
            case "IV-1.7"  -> "REDIRECT_WHITELIST";
            case "IV-1.8"  -> "DISABLE_XML_ENTITY";
            case "IV-1.9"  -> "PARAMETERIZED_XPATH";
            case "IV-1.10" -> "LDAP_ENCODING";
            case "IV-1.11" -> "CSRF_TOKEN";
            case "IV-1.12" -> "SSRF_ALLOWLIST";
            case "IV-1.13" -> "CRLF_REMOVAL";
            case "IV-1.14" -> "BOUNDS_CHECK";
            case "IV-1.15" -> "SERVER_SIDE_AUTH_CHECK";
            case "IV-1.16" -> "SAFE_ARRAY_ACCESS";
            case "IV-1.17" -> "LITERAL_FORMAT_STRING";
            // ── PART4 제2절 ──
            case "IV-2.1"  -> "AUTH_GATE_FILTER";
            case "IV-2.2"  -> "RBAC_CHECK";
            case "IV-2.3"  -> "LEAST_PRIVILEGE";
            case "IV-2.4"  -> "STRONG_CRYPTO";
            case "IV-2.5"  -> "ENCRYPT_SENSITIVE_DATA";
            case "IV-2.6"  -> "EXTERNALIZE_SECRETS";
            case "IV-2.7"  -> "MIN_KEY_SIZE";
            case "IV-2.8"  -> "SECURE_RANDOM";
            case "IV-2.9"  -> "PASSWORD_POLICY";
            case "IV-2.10" -> "VERIFY_SIGNATURE";
            case "IV-2.11" -> "PROPER_CERT_VALIDATION";
            case "IV-2.12" -> "SECURE_COOKIE_ATTRIBUTES";
            case "IV-2.13" -> "REMOVE_SENSITIVE_COMMENTS";
            case "IV-2.14" -> "SALTED_HASH";
            case "IV-2.15" -> "CHECKSUM_VERIFY";
            case "IV-2.16" -> "ACCOUNT_LOCKOUT";
            // ── PART4 제3절 ──
            case "IV-3.1"  -> "ATOMIC_FILE_OPERATION";
            case "IV-3.2"  -> "TERMINATION_CONDITION";
            // ── PART4 제4절 ──
            case "IV-4.1"  -> "GENERIC_ERROR_MESSAGE";
            case "IV-4.2"  -> "HANDLE_ALL_EXCEPTIONS";
            case "IV-4.3"  -> "SPECIFIC_EXCEPTION_HANDLING";
            // ── PART4 제5절 ──
            case "IV-5.1"  -> "NULL_CHECK";
            case "IV-5.2"  -> "TRY_WITH_RESOURCES";
            case "IV-5.3"  -> "NULL_AFTER_CLOSE";
            case "IV-5.4"  -> "INITIALIZE_VARIABLES";
            case "IV-5.5"  -> "SAFE_DESERIALIZATION";
            // ── PART4 제6절 ──
            case "IV-6.1"  -> "SESSION_ISOLATION";
            case "IV-6.2"  -> "REMOVE_DEBUG_CODE";
            case "IV-6.3"  -> "DEFENSIVE_COPY";
            case "IV-6.4"  -> "DEFENSIVE_COPY_INPUT";
            // ── PART4 제7절 ──
            case "IV-7.1"  -> "IP_BASED_CHECK";
            case "IV-7.2"  -> "SAFE_API_REPLACEMENT";
            // ── PART3 설계단계 ──
            case "DS-4.1"  -> "SESSION_DESIGN";
            default        -> "GENERIC";
        };
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
