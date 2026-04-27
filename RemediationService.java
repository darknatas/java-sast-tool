package com.sast.remediation;

import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.sast.model.Finding;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RemediationService
 *
 * 탐지된 보안약점에 대해 수정 코드를 자동 생성하는 서비스입니다.
 *
 * 핵심 기능:
 *  1. 규칙별 수정 전략(Strategy) 선택
 *  2. AST 노드에서 추출된 변수명을 수정 템플릿에 자동 삽입 (Contextual Suggestion)
 *  3. 전·후 코드 비교 제공
 *
 * 지원 전략 (가이드 PART4 기반):
 *  - USE_PREPARED_STATEMENT  : SQL 삽입 → PreparedStatement 변환
 *  - PATH_CANONICALIZATION   : 경로 조작 → 경로 정규화 및 필터링
 *  - OUTPUT_ENCODING         : XSS → HTML 인코딩 적용
 *  - AVOID_OS_COMMAND        : OS 명령어 삽입 → 직접 실행 제거
 *  - FILE_EXTENSION_WHITELIST: 위험 파일 업로드 → 확장자 검증
 *  - GENERIC_ERROR_MESSAGE   : 오류 정보노출 → 일반 메시지 출력
 *  - SECURE_RANDOM           : 취약한 난수 → SecureRandom 교체
 *  - DISABLE_XML_ENTITY      : XXE → 외부 엔티티 비활성화
 */
public class RemediationService {

    // ────────────────────────────────────────────────────────────────────
    //  공개 인터페이스
    // ────────────────────────────────────────────────────────────────────

    /**
     * 탐지된 Finding에 대해 수정 제안을 생성하고 반환합니다.
     *
     * @param finding 분석 엔진이 탐지한 보안약점 정보
     * @return 수정 제안 (수정 전 코드, 수정 후 코드, 설명 포함)
     */
    public RemediationResult suggest(Finding finding) {
        String strategy = resolveStrategy(finding.getRuleId());

        return switch (strategy) {
            case "USE_PREPARED_STATEMENT"   -> remediateSqlInjection(finding);
            case "PATH_CANONICALIZATION"    -> remediatePathTraversal(finding);
            case "OUTPUT_ENCODING"          -> remediateXss(finding);
            case "AVOID_OS_COMMAND"         -> remediateOsCommand(finding);
            case "FILE_EXTENSION_WHITELIST" -> remediateFileUpload(finding);
            case "GENERIC_ERROR_MESSAGE"    -> remediateErrorExposure(finding);
            case "SECURE_RANDOM"            -> remediateWeakRandom(finding);
            case "DISABLE_XML_ENTITY"       -> remediateXxe(finding);
            case "CRLF_REMOVAL"             -> remediateCrLf(finding);
            case "SAFE_DESERIALIZATION"     -> remediateDeserialization(finding);
            default                         -> remediateGeneric(finding);
        };
    }

    // ────────────────────────────────────────────────────────────────────
    //  전략별 수정 로직
    // ────────────────────────────────────────────────────────────────────

    /**
     * [IV-1.1] SQL 삽입 수정 전략: USE_PREPARED_STATEMENT
     *
     * 탐지 예시:
     *   String sql = "SELECT * FROM board WHERE id = '" + userId + "'";
     *   ResultSet rs = stmt.executeQuery(sql);
     *
     * 수정 결과: AST에서 추출된 변수명(userId)을 템플릿에 자동 삽입
     */
    private RemediationResult remediateSqlInjection(Finding finding) {
        // AST에서 오염 변수명 추출 (Taint 흐름의 마지막 propagator)
        String taintedVar = extractTaintedVariable(finding);

        // 취약 코드에서 테이블명과 컬럼명 패턴 추출
        SqlQueryContext ctx = parseSqlContext(finding.getVulnerableCode());

        String vulnerableCode = finding.getVulnerableCode();

        String remediatedCode = String.format(
            """
            // [수정] IV-1.1 SQL 삽입 방지: PreparedStatement 사용
            // 원래 취약 코드: %s
            
            // 1. 상수 스트링으로 쿼리를 정의하고, 외부 입력값 위치에 '?' 바인딩 변수 사용
            String sql = "%s";
            
            // 2. PreparedStatement 객체 생성
            PreparedStatement pstmt = con.prepareStatement(sql);
            
            // 3. 외부 입력값 '%s'를 파라미터로 바인딩 (구조 변경 불가)
            pstmt.setString(1, %s);
            
            // 4. 쿼리 실행
            ResultSet rs = pstmt.executeQuery();
            """,
            vulnerableCode,
            ctx.safeSqlTemplate,
            taintedVar,
            taintedVar
        );

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("USE_PREPARED_STATEMENT")
                .vulnerableCode(vulnerableCode)
                .remediatedCode(remediatedCode)
                .explanation(
                    "PreparedStatement를 사용하면 SQL 쿼리 구조가 컴파일 시점에 고정됩니다. " +
                    "외부 입력값 '" + taintedVar + "'는 데이터로만 처리되어 SQL 구조를 변경할 수 없습니다. " +
                    "가이드 참조: PART4 제1절 1항 SQL 삽입 (p.180-193)"
                )
                .references(List.of(
                    "PART4 제1절 1항 (p.180-193)",
                    "CWE-89: SQL Injection",
                    "OWASP SQL Injection Prevention Cheat Sheet"
                ))
                .build();
    }

    /**
     * [IV-1.3] 경로 조작 및 자원 삽입 수정 전략: PATH_CANONICALIZATION
     *
     * 탐지 예시:
     *   String fileName = request.getParameter("P");
     *   fis = new FileInputStream("C:/datas/" + fileName);
     *
     * 수정 결과: 경로순회 문자 제거 → 정규화 경로 → 허용 디렉터리 검증
     */
    private RemediationResult remediatePathTraversal(Finding finding) {
        String taintedVar = extractTaintedVariable(finding);
        String baseDir    = extractBaseDirectory(finding.getVulnerableCode());

        String remediatedCode = String.format(
            """
            // [수정] IV-1.3 경로 조작 및 자원 삽입 방지
            // 원래 취약 코드: %s
            
            String %s = request.getParameter("%s");
            
            // 1. null 체크
            if (%s == null || %s.isEmpty()) {
                throw new IllegalArgumentException("파일명이 제공되지 않았습니다.");
            }
            
            // 2. 경로 순회 문자열 제거: ../ ..\\ / \\ 등 (가이드 p.202 안전한 코드 참조)
            String safe_%s = %s.replaceAll("\\\\.{2,}[/\\\\\\\\]", "")
                                .replaceAll("[/\\\\\\\\]", "");
            
            // 3. 정규화된 절대 경로 생성 및 허용 디렉터리 검증
            File baseDir = new File("%s").getCanonicalFile();
            File target  = new File(baseDir, safe_%s).getCanonicalFile();
            
            if (!target.getPath().startsWith(baseDir.getPath() + File.separator)) {
                throw new SecurityException("허용되지 않은 경로 접근이 감지되었습니다: " + safe_%s);
            }
            
            // 4. 검증된 경로로 파일 접근
            try (FileInputStream fis = new FileInputStream(target)) {
                // ... 파일 처리 로직
            }
            """,
            finding.getVulnerableCode(),
            taintedVar, taintedVar,
            taintedVar, taintedVar,
            taintedVar, taintedVar,
            baseDir,
            taintedVar,
            taintedVar
        );

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("PATH_CANONICALIZATION")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation(
                    "외부 입력값 '" + taintedVar + "'에서 경로 순회 문자(../, ..\\)를 제거하고, " +
                    "정규화된 절대 경로가 허용된 기본 디렉터리 내에 있는지 검증합니다. " +
                    "가이드 참조: PART4 제1절 3항 경로 조작 및 자원 삽입 (p.201-210)"
                )
                .references(List.of(
                    "PART4 제1절 3항 (p.201-210)",
                    "CWE-22: Path Traversal",
                    "CWE-99: Resource Injection"
                ))
                .build();
    }

    /**
     * [IV-1.4] XSS 수정 전략: OUTPUT_ENCODING
     */
    private RemediationResult remediateXss(Finding finding) {
        String taintedVar = extractTaintedVariable(finding);

        String remediatedCode = String.format(
            """
            // [수정] IV-1.4 크로스사이트 스크립트(XSS) 방지: 출력 시 HTML 인코딩
            // 원래 취약 코드: %s
            
            // Spring 사용 시: HtmlUtils.htmlEscape() 적용
            String safe_%s = org.springframework.web.util.HtmlUtils.htmlEscape(%s);
            
            // 또는 OWASP ESAPI 사용 시:
            // String safe_%s = ESAPI.encoder().encodeForHTML(%s);
            
            // 인코딩된 값을 출력 (HTML 태그 삽입 불가)
            out.println(safe_%s);
            """,
            finding.getVulnerableCode(),
            taintedVar, taintedVar,
            taintedVar, taintedVar,
            taintedVar
        );

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("OUTPUT_ENCODING")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation(
                    "사용자 입력값 '" + taintedVar + "'을 HTML 출력 전 인코딩하여 " +
                    "<script> 등의 악성 태그가 브라우저에서 실행되지 않도록 방지합니다."
                )
                .references(List.of(
                    "PART4 제1절 4항 (p.211-222)",
                    "CWE-79: Cross-site Scripting"
                ))
                .build();
    }

    /**
     * [IV-1.5] OS 명령어 삽입 수정 전략: AVOID_OS_COMMAND
     */
    private RemediationResult remediateOsCommand(Finding finding) {
        String taintedVar = extractTaintedVariable(finding);

        String remediatedCode = String.format(
            """
            // [수정] IV-1.5 운영체제 명령어 삽입 방지
            // 원래 취약 코드: %s
            // 권고: OS 명령어 직접 실행을 피하고 Java API로 대체
            
            // 방법 1: 화이트리스트 기반 허용 명령어 검증
            Set<String> allowedCommands = Set.of("ls", "pwd", "date");
            if (!allowedCommands.contains(%s)) {
                throw new SecurityException("허용되지 않은 명령어: " + %s);
            }
            
            // 방법 2: 불가피하게 exec 사용 시, 문자열 연결 대신 배열 형태로 인자 분리
            // (Shell 메타문자 영향 방지)
            ProcessBuilder pb = new ProcessBuilder(List.of("/usr/bin/ls", safe_%s));
            pb.redirectErrorStream(true);
            Process process = pb.start();
            """,
            finding.getVulnerableCode(),
            taintedVar, taintedVar,
            taintedVar
        );

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("AVOID_OS_COMMAND")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation("OS 명령어 직접 실행 금지. 불가피한 경우 화이트리스트 검증 후 배열 형태로 인자를 분리합니다.")
                .references(List.of("PART4 제1절 5항 (p.223-231)", "CWE-78: OS Command Injection"))
                .build();
    }

    /**
     * [IV-1.6] 위험 파일 업로드 수정 전략: FILE_EXTENSION_WHITELIST
     */
    private RemediationResult remediateFileUpload(Finding finding) {
        String taintedVar = extractTaintedVariable(finding);

        String remediatedCode = String.format(
            """
            // [수정] IV-1.6 위험한 형식 파일 업로드 방지
            // 원래 취약 코드: %s
            
            // 1. 허용 확장자 화이트리스트 정의
            Set<String> allowedExtensions = Set.of("jpg", "jpeg", "png", "gif", "pdf", "docx");
            
            // 2. 원본 파일명에서 확장자 추출 및 검증
            String originalFilename = multipartFile.getOriginalFilename();
            if (originalFilename == null || originalFilename.isEmpty()) {
                throw new IllegalArgumentException("파일명이 없습니다.");
            }
            String ext = FilenameUtils.getExtension(originalFilename).toLowerCase();
            if (!allowedExtensions.contains(ext)) {
                throw new SecurityException("허용되지 않은 파일 형식: " + ext);
            }
            
            // 3. 저장 파일명 랜덤화 (디렉터리 탐색 방지)
            String safeFilename = UUID.randomUUID().toString() + "." + ext;
            
            // 4. 웹 루트 외부의 안전한 경로에 저장
            Path savePath = Paths.get("/var/app/uploads", safeFilename);
            Files.write(savePath, multipartFile.getBytes());
            """,
            finding.getVulnerableCode()
        );

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("FILE_EXTENSION_WHITELIST")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation("파일 확장자 화이트리스트 검증, 파일명 랜덤화, 웹 루트 외부 저장소 사용으로 위험 파일 업로드를 방지합니다.")
                .references(List.of("PART4 제1절 6항 (p.232-238)", "CWE-434: Unrestricted Upload"))
                .build();
    }

    /**
     * [IV-4.1] 오류 메시지 정보노출 수정 전략: GENERIC_ERROR_MESSAGE
     */
    private RemediationResult remediateErrorExposure(Finding finding) {
        String remediatedCode =
            """
            // [수정] IV-4.1 오류 메시지 정보노출 방지
            // 원래 취약 코드: e.printStackTrace() 또는 e.getMessage()를 응답에 출력
            
            try {
                // ... 비즈니스 로직
            } catch (Exception e) {
                // 1. 상세 오류는 서버 로그에만 기록 (운영자만 확인 가능)
                logger.error("처리 중 오류 발생: {}", e.getMessage(), e);
                
                // 2. 사용자에게는 일반적인 메시지만 반환 (스택트레이스, 경로, DB 정보 노출 금지)
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                   "요청을 처리할 수 없습니다. 관리자에게 문의하세요.");
            }
            """;

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("GENERIC_ERROR_MESSAGE")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation("예외 상세 정보는 서버 로그에만 기록하고, 사용자에게는 일반적인 메시지만 반환합니다.")
                .references(List.of("PART4 제4절 1항 (p.419-424)", "CWE-209: Information Exposure Through Error Messages"))
                .build();
    }

    /**
     * [IV-2.8] 취약한 난수 수정 전략: SECURE_RANDOM
     */
    private RemediationResult remediateWeakRandom(Finding finding) {
        String remediatedCode =
            """
            // [수정] IV-2.8 적절하지 않은 난수 값 사용 방지
            // 원래 취약 코드: new Random() 또는 Math.random() 사용
            
            // java.security.SecureRandom으로 교체 (암호학적으로 안전한 난수 생성)
            import java.security.SecureRandom;
            
            SecureRandom secureRandom = new SecureRandom();
            
            // 정수 난수 생성 예시
            int randomInt = secureRandom.nextInt(bound);
            
            // 바이트 배열 난수 생성 (토큰, 세션키 등)
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            """;

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SECURE_RANDOM")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation("java.util.Random은 예측 가능한 난수를 생성합니다. 보안 목적에는 반드시 java.security.SecureRandom을 사용하세요.")
                .references(List.of("PART4 제2절 8항 (p.364-369)", "CWE-330: Use of Insufficiently Random Values"))
                .build();
    }

    /**
     * [IV-1.8] XXE 수정 전략: DISABLE_XML_ENTITY
     */
    private RemediationResult remediateXxe(Finding finding) {
        String remediatedCode =
            """
            // [수정] IV-1.8 부적절한 XML 외부개체 참조(XXE) 방지
            // XML 파서에서 외부 엔티티 참조 및 DOCTYPE 선언 비활성화
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            
            // 외부 엔티티 및 DOCTYPE 비활성화 (OWASP 권장)
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(inputStream);
            """;

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("DISABLE_XML_ENTITY")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation("XML 파서에서 외부 엔티티 참조를 비활성화하여 XXE(XML External Entity) 공격을 방지합니다.")
                .references(List.of("PART4 제1절 8항 (p.244-250)", "CWE-611: XXE"))
                .build();
    }

    /**
     * [IV-1.13] HTTP 응답분할 수정 전략: CRLF_REMOVAL
     */
    private RemediationResult remediateCrLf(Finding finding) {
        String taintedVar = extractTaintedVariable(finding);

        String remediatedCode = String.format(
            """
            // [수정] IV-1.13 HTTP 응답분할 방지: CR/LF 문자 제거
            // 원래 취약 코드: %s
            
            // HTTP 헤더에 삽입되는 값에서 CR(\\r), LF(\\n) 문자 제거
            String safe_%s = %s
                .replaceAll("\\\\r", "")
                .replaceAll("\\\\n", "")
                .replaceAll("%%0d", "")  // URL 인코딩 형태 제거
                .replaceAll("%%0a", "");
            
            response.setHeader("Location", safe_%s);
            """,
            finding.getVulnerableCode(),
            taintedVar, taintedVar,
            taintedVar
        );

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("CRLF_REMOVAL")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation("HTTP 헤더 값에서 CR/LF 문자를 제거하여 응답분할 공격을 방지합니다.")
                .references(List.of("PART4 제1절 13항 (p.284-289)", "CWE-113: HTTP Response Splitting"))
                .build();
    }

    /**
     * [IV-5.5] 역직렬화 수정 전략: SAFE_DESERIALIZATION
     */
    private RemediationResult remediateDeserialization(Finding finding) {
        String remediatedCode =
            """
            // [수정] IV-5.5 신뢰할 수 없는 데이터의 역직렬화 방지
            // 원래 취약 코드: ObjectInputStream.readObject() 무조건 사용
            
            // 방법 1: ObjectInputFilter로 허용 클래스만 역직렬화 (Java 9+)
            ObjectInputStream ois = new ObjectInputStream(inputStream);
            ois.setObjectInputFilter(filterInfo -> {
                Class<?> clazz = filterInfo.serialClass();
                if (clazz == null) return ObjectInputFilter.Status.UNDECIDED;
                // 허용 클래스 목록
                if (clazz == SafeDataClass.class || clazz == AnotherSafeClass.class) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
                return ObjectInputFilter.Status.REJECTED;
            });
            Object obj = ois.readObject();
            
            // 방법 2: 직렬화 대신 JSON/XML 사용 (권장)
            // ObjectMapper mapper = new ObjectMapper();
            // SafeDataClass data = mapper.readValue(jsonString, SafeDataClass.class);
            """;

        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("SAFE_DESERIALIZATION")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode(remediatedCode)
                .explanation("ObjectInputFilter로 허용 클래스를 제한하거나 JSON 등 안전한 직렬화 형식으로 교체합니다.")
                .references(List.of("PART4 제5절 5항 (p.462-468)", "CWE-502: Deserialization of Untrusted Data"))
                .build();
    }

    /** 기타 규칙에 대한 기본 수정 제안 */
    private RemediationResult remediateGeneric(Finding finding) {
        return RemediationResult.builder()
                .ruleId(finding.getRuleId())
                .strategy("GENERIC")
                .vulnerableCode(finding.getVulnerableCode())
                .remediatedCode("// 해당 약점의 수정 템플릿을 참조하세요: " + finding.getGuideRef())
                .explanation("보안약점 '" + finding.getRuleName() + "' 의 조치방안을 가이드에서 확인하세요.")
                .references(List.of(finding.getGuideRef()))
                .build();
    }

    // ────────────────────────────────────────────────────────────────────
    //  Context Extraction (AST 기반 변수명/SQL 추출)
    // ────────────────────────────────────────────────────────────────────

    /**
     * Finding의 Taint 흐름에서 오염 변수명을 추출합니다.
     * AST에서 직접 변수 이름을 가져오므로 템플릿에 정확한 변수명이 삽입됩니다.
     *
     * 예: TaintFlow [Source L3: request.getParameter("userId")] → propagators: [userId]
     *     → "userId" 반환
     */
    private String extractTaintedVariable(Finding finding) {
        if (finding.getTaintFlows() == null || finding.getTaintFlows().isEmpty()) {
            return "userInput"; // fallback
        }
        Finding.TaintFlow flow = finding.getTaintFlows().get(0);
        List<String> propagators = flow.getPropagators();
        if (propagators != null && !propagators.isEmpty()) {
            return propagators.get(propagators.size() - 1); // 마지막 전파 변수
        }
        // Source 표현식에서 변수명 추출 시도 (e.g., request.getParameter("userId"))
        String source = flow.getSourceExpression();
        Matcher m = Pattern.compile("getParameter\\(\"(\\w+)\"\\)").matcher(source);
        if (m.find()) return m.group(1);
        return "userInput";
    }

    /**
     * SQL 쿼리 코드에서 컨텍스트 파싱 (테이블·컬럼 추출, 안전한 템플릿 생성)
     *
     * 예:
     *   "SELECT * FROM board WHERE id = '" + userId + "'"
     *   → SafeSqlTemplate: "SELECT * FROM board WHERE id = ?"
     */
    private SqlQueryContext parseSqlContext(String vulnerableCode) {
        SqlQueryContext ctx = new SqlQueryContext();

        // 패턴: "SELECT ... " + var + "..."  또는 " + var
        Pattern sqlPattern = Pattern.compile(
            "\"(SELECT[^\"]*|INSERT[^\"]*|UPDATE[^\"]*|DELETE[^\"]*|FROM[^\"]*WHERE[^\"]*)'\"",
            Pattern.CASE_INSENSITIVE
        );
        Matcher m = sqlPattern.matcher(vulnerableCode);
        if (m.find()) {
            String sqlFragment = m.group(1);
            // 문자열 연결 부분을 ? 플레이스홀더로 교체
            ctx.safeSqlTemplate = sqlFragment.trim() + " ?";
        } else {
            // 일반 fallback
            Pattern fallback = Pattern.compile("\"([^\"]*SELECT[^\"]*|[^\"]*FROM[^\"]*WHERE[^\"]*)\"");
            Matcher fm = fallback.matcher(vulnerableCode);
            ctx.safeSqlTemplate = fm.find()
                    ? fm.group(1).replaceAll("'[^']*'", "?")
                    : "SELECT * FROM table WHERE column = ?";
        }

        return ctx;
    }

    /** 파일 경로 코드에서 기본 디렉터리 추출 */
    private String extractBaseDirectory(String vulnerableCode) {
        Pattern p = Pattern.compile("\"([A-Za-z]:[/\\\\][^\"]+|/[^\"]+/)\"");
        Matcher m = p.matcher(vulnerableCode);
        return m.find() ? m.group(1) : "/app/data/";
    }

    /** ruleId → 수정 전략 문자열 매핑 */
    private String resolveStrategy(String ruleId) {
        return switch (ruleId) {
            case "IV-1.1"  -> "USE_PREPARED_STATEMENT";
            case "IV-1.3"  -> "PATH_CANONICALIZATION";
            case "IV-1.4"  -> "OUTPUT_ENCODING";
            case "IV-1.5"  -> "AVOID_OS_COMMAND";
            case "IV-1.6"  -> "FILE_EXTENSION_WHITELIST";
            case "IV-1.13" -> "CRLF_REMOVAL";
            case "IV-2.8"  -> "SECURE_RANDOM";
            case "IV-1.8"  -> "DISABLE_XML_ENTITY";
            case "IV-4.1"  -> "GENERIC_ERROR_MESSAGE";
            case "IV-5.5"  -> "SAFE_DESERIALIZATION";
            default        -> "GENERIC";
        };
    }

    // ────────────────────────────────────────────────────────────────────
    //  Inner Classes
    // ────────────────────────────────────────────────────────────────────

    private static class SqlQueryContext {
        String safeSqlTemplate = "SELECT * FROM table WHERE column = ?";
    }

    // ── Result DTO ───────────────────────────────────────────────────────

    public static class RemediationResult {
        private String       ruleId;
        private String       strategy;
        private String       vulnerableCode;
        private String       remediatedCode;
        private String       explanation;
        private List<String> references;

        public static Builder builder() { return new Builder(); }

        public static class Builder {
            private final RemediationResult r = new RemediationResult();
            public Builder ruleId(String v)          { r.ruleId = v;          return this; }
            public Builder strategy(String v)         { r.strategy = v;        return this; }
            public Builder vulnerableCode(String v)   { r.vulnerableCode = v;  return this; }
            public Builder remediatedCode(String v)   { r.remediatedCode = v;  return this; }
            public Builder explanation(String v)      { r.explanation = v;     return this; }
            public Builder references(List<String> v) { r.references = v;      return this; }
            public RemediationResult build()          { return r; }
        }

        public String getRuleId()          { return ruleId; }
        public String getStrategy()        { return strategy; }
        public String getVulnerableCode()  { return vulnerableCode; }
        public String getRemediatedCode()  { return remediatedCode; }
        public String getExplanation()     { return explanation; }
        public List<String> getReferences(){ return references; }
    }
}
