# CLAUDE.md — Java SAST Engine

> **Claude Code가 이 파일을 읽고 프로젝트 전체를 이해한 뒤 작업을 시작합니다.**
> 새로운 기능을 추가하거나 버그를 수정하기 전에 이 파일을 반드시 숙지하세요.

---

## 1. 프로젝트 개요

### 1.1 목적

이 프로젝트는 **Java 소스코드를 정적 분석(SAST)** 하여 보안약점을 자동으로 탐지·보고하는 도구입니다.

**준수 기준:** 행정안전부 *소프트웨어 보안약점 진단가이드 (2021)*
- **PART3** — 분석·설계단계 보안설계 기준 (20개 항목, Rule ID: `DS-x.x`)
- **PART4** — 구현단계 보안약점 제거 기준 (49개 항목, Rule ID: `IV-x.x`)

이 가이드는 `src/main/resources/security-rules.json`에 Rule 형태로 완전히 추상화되어 있습니다.
새 기능을 작성할 때 **가이드 항목 번호와 CWE 번호를 항상 주석에 명시**하세요.

### 1.2 기술 스택

| 항목 | 선택 | 비고 |
|---|---|---|
| 언어 | Java 21 | Record, Pattern Matching, Text Block 사용 가능 |
| 빌드 | Maven 3.x | `pom.xml` 참조 |
| AST 파서 | **JavaParser 3.25.x** | Spoon 사용 금지 — 아래 이유 참조 |
| Symbol Solver | JavaParser SymbolSolver | 타입 해석 필수 활성화 |
| JSON | Jackson 2.17.x | 규칙 로드·리포트 출력 |
| 로깅 | SLF4J + Logback | `System.out.print` 코드 작성 금지 |
| 테스트 | JUnit 5 + AssertJ | |

> **왜 JavaParser인가?** Spoon은 코드 변환(rewriting) 목적에 최적화되어 있고 Eclipse JDT 의존으로 무겁습니다. 이 프로젝트는 탐지(분석) 목적이므로 경량이고 API가 직관적인 JavaParser를 사용합니다. Spoon으로의 전환은 별도 아키텍처 결정 없이 금지합니다.

---

## 2. 디렉터리 구조

```
java-sast/
├── CLAUDE.md                          ← 이 파일
├── pom.xml
└── src/
    ├── main/
    │   ├── java/com/sast/
    │   │   ├── SASTEngine.java         ← 진입점, 파이프라인 조율
    │   │   ├── model/
    │   │   │   └── Finding.java        ← 탐지 결과 모델 (Builder 패턴)
    │   │   ├── engine/
    │   │   │   ├── ast/
    │   │   │   │   └── AstParser.java  ← JavaParser 설정 및 파싱 캡슐화
    │   │   │   ├── taint/
    │   │   │   │   ├── TaintAnalysisEngine.java  ← Taint 분석 핵심
    │   │   │   │   ├── TaintSet.java             ← 오염 변수 상태 관리
    │   │   │   │   └── TaintFlow.java            ← 오염 흐름 경로 모델
    │   │   │   ├── pattern/
    │   │   │   │   └── PatternAnalyzer.java      ← 정규식 기반 탐지
    │   │   │   └── rules/
    │   │   │       ├── SecurityRule.java          ← Rule DTO
    │   │   │       └── RuleLoader.java            ← JSON → SecurityRule 로드
    │   │   ├── analyzer/
    │   │   │   └── FileAnalyzer.java   ← 파일 단위 분석 오케스트레이터
    │   │   ├── remediation/
    │   │   │   └── RemediationService.java  ← 수정 코드 자동 생성
    │   │   └── report/
    │   │       ├── ReportGenerator.java     ← MD / JSON / Console 출력
    │   │       └── ReportFormat.java        ← 출력 포맷 열거형
    │   └── resources/
    │       ├── security-rules.json    ← 핵심 규칙 DB (수정 시 주의)
    │       └── logback.xml
    └── test/
        └── java/com/sast/
            ├── engine/taint/
            │   └── TaintAnalysisEngineTest.java
            ├── remediation/
            │   └── RemediationServiceTest.java
            └── fixtures/                  ← 테스트용 취약/안전 Java 파일
                ├── vulnerable/
                └── safe/
```

---

## 3. 빌드 및 실행 명령어

### 3.1 기본 빌드

```bash
# 전체 빌드 (테스트 포함)
mvn clean package

# 테스트 건너뛰고 빠르게 빌드
mvn clean package -DskipTests

# Fat JAR 위치
target/sast.jar
```

### 3.2 실행

```bash
# 기본 실행: <소스 디렉터리> <리포트 출력 경로>
java -jar target/sast.jar ./src/main/java ./report.md

# JSON 리포트 동시 생성 (report.md → report.json 자동 생성)
java -jar target/sast.jar /path/to/project/src ./output/report.md

# 특정 규칙만 실행 (Rule ID 필터)
java -jar target/sast.jar ./src ./report.md --rules IV-1.1,IV-1.3

# 위험도 필터 (HIGH 이상만)
java -jar target/sast.jar ./src ./report.md --severity HIGH
```

### 3.3 개발 중 단위 테스트

```bash
# 전체 테스트
mvn test

# 특정 클래스만
mvn test -Dtest=TaintAnalysisEngineTest

# 특정 메서드만
mvn test -Dtest=TaintAnalysisEngineTest#detectSqlInjection_whenStringConcatenation_shouldFindVulnerability
```

### 3.4 코드 커버리지

```bash
mvn test jacoco:report
open target/site/jacoco/index.html
```

---

## 4. 아키텍처 & 데이터 흐름

### 4.1 분석 파이프라인 (7단계)

```
[Java 소스 파일]
       │
       ▼
 ① AstParser                  JavaParser + SymbolSolver → CompilationUnit
       │
       ▼
 ② RuleLoader                 security-rules.json → List<SecurityRule>
       │
       ├──────────────────────────────────────────────────┐
       ▼                                                  ▼
 ③ TaintAnalysisEngine                          ④ PatternAnalyzer
    (taintAnalysis: true 규칙)                  (dangerousPatterns 규칙)
    Source → Propagation → Sink                 정규식 기반 탐지
       │                                                  │
       └──────────────────────┬───────────────────────────┘
                              ▼
                    ⑤ List<Finding>               탐지 결과 집합
                              │
                              ▼
                    ⑥ RemediationService          수정 코드 자동 생성
                              │
                              ▼
                    ⑦ ReportGenerator             MD / JSON / Console
```

### 4.2 Taint Analysis 핵심 원리

**3단계 흐름:**

```
Source (외부 입력)  →  Propagation (변수 전파)  →  Sink (위험 API)
```

| 단계 | 역할 | 예시 |
|---|---|---|
| **Source** | 신뢰할 수 없는 외부 데이터 진입 | `request.getParameter()`, `getenv()`, `args[]` |
| **Propagator** | 오염값이 이동하는 변수/연산 | `String sql = "SELECT..." + userId` |
| **Sanitizer** | 오염을 무력화하는 처리 | `prepareStatement()`, `escapeHtml()`, `getCanonicalPath()` |
| **Sink** | 오염값이 도달하면 취약점 | `executeQuery()`, `new File()`, `exec()` |

**알고리즘:** 인트라-프로시저럴(메서드 단위) Dataflow
- `TaintSet`: `Map<String varName, TaintInfo>` — 메서드 진입 시 초기화
- AST Visitor 방문 순서: `VariableDeclarator` → `AssignExpr` → `MethodCallExpr`
- Binary `+` 연산에 오염 변수가 포함되면 결과 변수도 오염됨
- Sanitizer 호출 시 해당 변수를 `TaintSet`에서 제거

---

## 5. 핵심 클래스 계약

### 5.1 `Finding` (탐지 결과 모델)

`Finding`은 불변(immutable) 객체입니다. **Builder 패턴으로만 생성**하세요.

```java
Finding finding = Finding.builder()
    .ruleId("IV-1.1")          // 필수: 규칙 ID
    .ruleName("SQL 삽입")       // 필수: 가이드 항목명
    .severity(Severity.HIGH)    // 필수: 위험도
    .filePath(filePath)         // 필수: 절대 경로
    .lineNumber(lineNo)         // 필수: 1-based 라인 번호
    .vulnerableCode(snippet)    // 필수: 취약 코드 스니펫 (1~3줄 이내)
    .description(description)   // 필수: 탐지 근거 (한국어 문장)
    .taintFlows(flows)          // Taint 분석 결과가 있으면 필수
    .guideRef("PART4 제1절 1항 (p.180-193)") // 필수: 가이드 페이지
    .cweIds(List.of("CWE-89")) // 필수: CWE 번호
    .build();
```

**절대 금지:**
- `Finding` 객체를 직접 `new`로 생성하지 마세요.
- `Finding`의 필드를 setter로 수정하지 마세요 (setter 없음).
- `null`을 `guideRef`나 `cweIds`에 넣지 마세요.

### 5.2 `SecurityRule` (규칙 모델)

`security-rules.json`에서 역직렬화됩니다. 코드에서 직접 `new SecurityRule()`하지 마세요.

```java
// 올바른 사용
List<SecurityRule> rules = RuleLoader.loadFromClasspath("security-rules.json");
List<SecurityRule> taintRules = rules.stream()
    .filter(SecurityRule::isTaintAnalysis)
    .toList();
```

### 5.3 `TaintAnalysisEngine`

```java
// 반드시 CompilationUnit과 filePath를 함께 전달
List<Finding> findings = taintEngine.analyze(cu, filePath, taintRules);

// ❌ 금지: 엔진 인스턴스를 스레드 간 공유하지 마세요 (TaintSet이 상태를 가짐)
// ✅ 허용: 파일마다 새 분석 컨텍스트로 초기화됨 (analyze() 호출 시 taintSet.clear())
```

### 5.4 `RemediationService`

```java
RemediationResult result = remediationService.suggest(finding);

// result.getRemediatedCode()  — 수정 코드 (변수명 자동 삽입됨)
// result.getExplanation()     — 한국어 설명
// result.getReferences()      — 가이드 참조 목록
```

---

## 6. `security-rules.json` 수정 규칙

> **이 파일은 프로젝트의 핵심 규칙 DB입니다. 수정 시 아래 규칙을 반드시 준수하세요.**

### 6.1 Rule ID 체계

```
DS-{절}.{항}   → PART3 설계단계 (예: DS-1.1, DS-2.3)
IV-{절}.{항}   → PART4 구현단계 (예: IV-1.1, IV-4.1)
```

### 6.2 필수 필드 (모든 규칙에 존재해야 함)

```jsonc
{
  "ruleId":      "IV-1.1",           // 위 체계 준수
  "part":        "PART4",            // "PART3" 또는 "PART4"
  "section":     "입력데이터 검증 및 표현",
  "name":        "SQL 삽입",          // 가이드 공식 명칭 그대로
  "cwe":         ["CWE-89"],         // 반드시 배열, 공식 CWE 번호
  "severity":    "HIGH",             // "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"
  "phase":       "IMPLEMENTATION",   // "DESIGN"|"IMPLEMENTATION"
  "taintAnalysis": true,             // Taint 분석 여부
  "remediation": {
    "strategy":  "USE_PREPARED_STATEMENT",
    "description": "...",
    "guideRef":  "PART4 제1절 1항 (p.180-193)"  // 페이지 번호 필수
  }
}
```

### 6.3 Taint 규칙에 필요한 추가 필드

```jsonc
{
  "sources":          ["getParameter", "getenv"],   // Source API 이름
  "sinks":            ["executeQuery", "execute"],  // Sink API 이름
  "sanitizers":       ["prepareStatement"],         // Sanitizer API 이름
  "dangerousPatterns": ["String sql = .* \\+ .*"]  // 위험 패턴 정규식 (Java regex)
}
```

### 6.4 새 규칙 추가 절차

1. `security-rules.json`에 규칙 추가 (위 필드 완전히 채울 것)
2. `TaintAnalysisEngine.RULE_SINKS`에 `ruleId → Sink 메서드 집합` 추가
3. `RemediationService`에 수정 전략 메서드 추가
4. `test/fixtures/vulnerable/`에 취약 예시 Java 파일 추가
5. `test/fixtures/safe/`에 안전 예시 Java 파일 추가
6. 단위 테스트 작성 후 `mvn test` 통과 확인

---

## 7. 코드 스타일 가이드

### 7.1 일반 원칙

```java
// ✅ Java 21 기능 적극 활용
List<Finding> taintRules = rules.stream()
    .filter(SecurityRule::isTaintAnalysis)
    .toList();                          // .collect(Collectors.toList()) 대신

// ✅ 패턴 매칭
if (expr instanceof NameExpr ne) {      // instanceof + 변수 선언 한 줄
    return taintSet.containsKey(ne.getNameAsString());
}

// ✅ Switch 표현식
String strategy = switch (ruleId) {
    case "IV-1.1" -> "USE_PREPARED_STATEMENT";
    case "IV-1.3" -> "PATH_CANONICALIZATION";
    default       -> "GENERIC";
};

// ✅ Text Block (수정 코드 템플릿)
String template = """
        // [수정] %s
        PreparedStatement pstmt = con.prepareStatement(sql);
        pstmt.setString(1, %s);
        """.formatted(description, varName);
```

### 7.2 JavaParser 사용 원칙

```java
// ✅ SymbolSolver 반드시 활성화 (타입 해석 없으면 오탐 증가)
CombinedTypeSolver typeSolver = new CombinedTypeSolver();
typeSolver.add(new ReflectionTypeSolver());
ParserConfiguration config = new ParserConfiguration()
    .setSymbolResolver(new JavaSymbolSolver(typeSolver));
JavaParser parser = new JavaParser(config);

// ✅ 파싱 결과 항상 검증
ParseResult<CompilationUnit> result = parser.parse(file);
if (!result.isSuccessful() || result.getResult().isEmpty()) {
    log.warn("파싱 실패: {} — {}", file, result.getProblems());
    return List.of();
}

// ✅ Visitor는 VoidVisitorAdapter 상속
class TaintVisitor extends VoidVisitorAdapter<Void> {
    @Override
    public void visit(MethodCallExpr n, Void arg) {
        super.visit(n, arg);  // 반드시 super 먼저 호출 (자식 노드 방문)
        // ... 분석 로직
    }
}

// ❌ 금지: getResult().get() 직접 호출 (검증 없이)
CompilationUnit cu = result.getResult().get(); // NullPointerException 위험

// ❌ 금지: AST 노드를 직접 수정 (분석 도구는 읽기 전용)
n.setNameAsString("newName"); // 금지
```

### 7.3 Taint Analysis 로직 원칙

```java
// ✅ 원칙 1: Source 탐지는 메서드 이름으로만 (수신 객체 타입 무관)
// getParameter가 어느 클래스에서 호출되든 Source로 간주
private boolean isSourceCall(Expression expr) {
    if (expr instanceof MethodCallExpr call) {
        return SOURCE_METHODS.contains(call.getNameAsString());
    }
    return false;
}

// ✅ 원칙 2: 이진 연산(+)에서 오염 전파는 양방향 확인
private boolean isTainted(Expression expr) {
    if (expr instanceof BinaryExpr be) {
        return isTainted(be.getLeft()) || isTainted(be.getRight());
    }
    // ...
}

// ✅ 원칙 3: Sanitizer는 변수를 TaintSet에서 제거 (not add)
if (SANITIZER_METHODS.contains(methodName)) {
    n.getArguments().forEach(arg -> {
        if (arg instanceof NameExpr ne) taintSet.remove(ne.getNameAsString());
    });
}

// ✅ 원칙 4: Sink 탐지 시 즉시 Finding 생성 (지연 없음)
if (sinks.contains(methodName)) {
    n.getArguments().stream()
        .filter(this::isTainted)
        .forEach(arg -> reportFinding(...));
}

// ✅ 원칙 5: TaintSet은 메서드 단위로 초기화 (메서드 간 상태 공유 금지)
cu.findAll(MethodDeclaration.class).forEach(method -> {
    taintSet.clear();          // 반드시 초기화
    method.accept(visitor, null);
});
```

### 7.4 로깅 규칙

```java
// ✅ SLF4J Logger 사용 (클래스마다 선언)
private static final Logger log = LoggerFactory.getLogger(TaintAnalysisEngine.class);

// ✅ 수준별 사용 기준
log.debug("TaintSet 상태: {}", taintSet.keySet());        // 개발 디버깅
log.info("[SAST] 파일 분석 완료: {} ({}건)", path, count); // 진행 상황
log.warn("[SAST] 파싱 실패: {}", file);                   // 복구 가능한 문제
log.error("[SAST] 규칙 로드 실패: {}", e.getMessage(), e); // 치명적 오류

// ❌ 금지
System.out.println("분석 중...");   // System.out 사용 금지
e.printStackTrace();                // 스택트레이스 직접 출력 금지
```

### 7.5 예외 처리 규칙

```java
// ✅ 파일 분석 오류는 삼켜서 다음 파일 계속 처리
try {
    List<Finding> findings = analyzeFile(file);
    allFindings.addAll(findings);
} catch (IOException e) {
    log.warn("[SAST] 파일 분석 건너뜀: {} — {}", file, e.getMessage());
    // 계속 진행
}

// ✅ 규칙 로드 실패는 즉시 중단 (분석 불가)
List<SecurityRule> rules = RuleLoader.loadFromClasspath("security-rules.json");
// RuleLoader 내부에서 IOException 발생 시 RuntimeException으로 래핑

// ❌ 금지: 빈 catch 블록 (IV-4.2 오류상황 대응 부재 위반)
try { ... } catch (Exception e) { }  // 절대 금지
```

### 7.6 네이밍 컨벤션

| 대상 | 규칙 | 예시 |
|---|---|---|
| 클래스 | PascalCase | `TaintAnalysisEngine` |
| 메서드 | camelCase, 동사 시작 | `detectSqlInjection()`, `isTainted()` |
| 상수 | UPPER_SNAKE_CASE | `SOURCE_METHODS`, `RULE_SINKS` |
| 테스트 메서드 | `메서드명_조건_기대결과` | `detectSqlInjection_whenStringConcat_shouldFindVulnerability` |
| Rule ID 상수 | `RULE_` 접두사 | `RULE_SQL_INJECTION = "IV-1.1"` |

---

## 8. 보안약점 탐지 시 리포트 작성 규칙

### 8.1 Finding.description 작성 원칙

탐지 근거 설명은 **한국어로 작성**하며 다음 템플릿을 따릅니다.

```
외부 입력값 '{변수명}'({소스 표현식}, L{소스 라인})이
검증 없이 {싱크 표현식}(L{싱크 라인})에 사용됩니다.
```

**예시:**
```
외부 입력값 'gubun'(request.getParameter("gubun"), L3)이
검증 없이 stmt.executeQuery(sql)(L8)에 사용됩니다.
```

### 8.2 Taint Flow 기록 규칙

`TaintFlow` 객체는 탐지된 경로를 **완전하게** 기록해야 합니다.

```java
new Finding.TaintFlow(
    "request.getParameter(\"gubun\")",   // sourceExpression: 원본 Source 호출 표현식
    3,                                    // sourceLine: 1-based 라인 번호
    List.of("gubun", "sql"),             // propagators: Source → Sink 사이 변수 이름 목록
    "stmt.executeQuery(sql)",            // sinkExpression: Sink 호출 표현식
    8                                    // sinkLine: 1-based 라인 번호
)
```

**규칙:**
- `sourceExpression`: 반드시 실제 코드 표현식 ("`<unknown>`" 사용 최소화)
- `propagators`: Source 변수부터 Sink 직전 변수까지 순서대로 (빈 리스트 허용)
- `sinkExpression`: Sink API 호출 전체 표현식 (잘라내지 말 것)

### 8.3 취약 코드 스니펫 추출 규칙

`vulnerableCode`는 Sink API 호출 라인을 기준으로 **1~3줄 이내**로 추출합니다.

```java
// ✅ 좋음: Sink 라인만 (단순한 경우)
"stmt.executeQuery(sql)"

// ✅ 좋음: 컨텍스트가 필요한 경우 최대 3줄
"String sql = \"SELECT * FROM board WHERE id='\" + userId + \"'\";\n" +
"ResultSet rs = stmt.executeQuery(sql);"

// ❌ 나쁨: 메서드 전체를 넣지 마세요
```

### 8.4 수정 코드 작성 원칙 (RemediationService)

**Contextual Suggestion:** 단순 보일러플레이트가 아니라 실제 변수명이 삽입된 코드를 생성합니다.

```java
// ✅ 올바른 수정 코드 생성 — 실제 변수명 사용
String remediatedCode = """
        // [수정] IV-1.1 SQL 삽입 방지: PreparedStatement 사용
        String sql = "SELECT * FROM board WHERE b_gubun = ?";
        PreparedStatement pstmt = con.prepareStatement(sql);
        pstmt.setString(1, %s);   // ← 탐지된 변수명 자동 삽입
        ResultSet rs = pstmt.executeQuery();
        """.formatted(taintedVar);  // taintedVar = "gubun" (AST에서 추출)

// ❌ 잘못된 수정 코드 — 플레이스홀더 사용
"pstmt.setString(1, <YOUR_VAR_HERE>);"  // 금지
```

**수정 코드 주석 형식:**
```java
// [수정] {Rule ID} {약점명}: {핵심 조치 한 줄 요약}
// 예: // [수정] IV-1.1 SQL 삽입: PreparedStatement 사용
```

### 8.5 위험도(Severity) 판정 기준

가이드에 명시된 위험도를 따르되, 다음 기준으로 보완합니다.

| 위험도 | 판정 기준 | 해당 Rule 예시 |
|---|---|---|
| **CRITICAL** | 원격 코드 실행, 시스템 완전 장악 가능 | IV-1.5 OS 명령어 삽입, IV-5.5 역직렬화 |
| **HIGH** | 인증 우회, 데이터 탈취, 경로 탈출 가능 | IV-1.1 SQL 삽입, IV-1.3 경로 조작 |
| **MEDIUM** | 제한적 정보 노출, 서비스 장애 가능 | IV-1.13 HTTP 응답분할, IV-4.1 오류 노출 |
| **LOW** | 잠재적 위험, 직접 악용 어려움 | IV-6.2 디버그 코드, IV-2.13 주석 정보 |

### 8.6 리포트 출력 형식 (ReportGenerator)

Markdown 리포트의 각 Finding 섹션은 **정확히 이 구조**를 따릅니다.

```markdown
### [{순번}] {Rule ID} — {약점명}

| 항목 | 내용 |
|------|------|
| **진단항목 번호** | `IV-1.1` |
| **약점명** | SQL 삽입 |
| **위험도** | 🟠 높음(HIGH) |
| **파일** | `com/example/BoardController.java` |
| **라인** | 42 |
| **CWE** | CWE-89 |
| **가이드 참조** | PART4 제1절 1항 (p.180-193) |

#### 탐지 근거

> 외부 입력값 'gubun'(request.getParameter("gubun"), L3)이 검증 없이 stmt.executeQuery(sql)(L8)에 사용됩니다.

#### 오염 흐름 (Source → Propagator → Sink)

```
[Source L3: request.getParameter("gubun")] → [Propagators: [gubun, sql]] → [Sink L8: stmt.executeQuery(sql)]
```

#### ❌ 취약한 코드

```java
// Line 42
String sql = "SELECT * FROM board WHERE b_gubun = '" + gubun + "'";
ResultSet rs = stmt.executeQuery(sql);
```

#### ✅ 권고 수정 코드

```java
// [수정] IV-1.1 SQL 삽입: PreparedStatement 사용
String sql = "SELECT * FROM board WHERE b_gubun = ?";
PreparedStatement pstmt = con.prepareStatement(sql);
pstmt.setString(1, gubun);
ResultSet rs = pstmt.executeQuery();
```

#### 조치 설명

> PreparedStatement를 사용하면 SQL 쿼리 구조가 컴파일 시점에 고정됩니다...

#### 참고자료

- PART4 제1절 1항 (p.180-193)
- CWE-89: SQL Injection
- OWASP SQL Injection Prevention Cheat Sheet

---
```

---

## 9. 테스트 작성 규칙

### 9.1 테스트 파일 구조

```java
class TaintAnalysisEngineTest {

    // ✅ 각 Rule ID마다 취약/안전 케이스를 쌍으로 작성
    @Test
    void detectSqlInjection_whenStringConcatenation_shouldFindVulnerability() {
        // given: 취약한 코드 파싱
        CompilationUnit cu = parseFixture("vulnerable/SqlInjection_JDBC.java");

        // when: 분석 실행
        List<Finding> findings = engine.analyze(cu, "test.java", sqlRules);

        // then: 정확히 1건, 올바른 Rule ID, 올바른 라인
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).getRuleId()).isEqualTo("IV-1.1");
        assertThat(findings.get(0).getLineNumber()).isEqualTo(8);
        assertThat(findings.get(0).getTaintFlows()).isNotEmpty();
    }

    @Test
    void detectSqlInjection_whenPreparedStatement_shouldNotFindVulnerability() {
        // given: 안전한 코드
        CompilationUnit cu = parseFixture("safe/SqlSafe_PreparedStatement.java");

        // when
        List<Finding> findings = engine.analyze(cu, "test.java", sqlRules);

        // then: 취약점 없음 (False Positive 방지)
        assertThat(findings).isEmpty();
    }
}
```

### 9.2 테스트 픽스처 파일 명명 규칙

```
test/fixtures/
├── vulnerable/
│   ├── SqlInjection_JDBC.java          # IV-1.1: JDBC 취약 패턴
│   ├── SqlInjection_MyBatis.java       # IV-1.1: MyBatis ${ } 취약 패턴
│   ├── PathTraversal_FileInputStream.java  # IV-1.3: 경로 조작
│   └── XSS_PrintWriter.java            # IV-1.4: XSS
└── safe/
    ├── SqlSafe_PreparedStatement.java  # IV-1.1: PreparedStatement 사용
    ├── SqlSafe_MyBatis.java            # IV-1.1: MyBatis #{ } 사용
    ├── PathSafe_CanonicalPath.java     # IV-1.3: 경로 정규화
    └── XSSSafe_HtmlEscape.java        # IV-1.4: HTML 인코딩
```

---

## 10. 자주 하는 실수 & 주의사항

### 🚫 절대 금지 사항

1. **`System.out.print` 사용** → `log.info()` 사용
2. **빈 catch 블록** → IV-4.2 위반, 반드시 로그 또는 throw
3. **`new SecurityRule()` 직접 생성** → `RuleLoader`로만 로드
4. **`Finding` setter 사용** → Builder 패턴으로만 생성
5. **AST 노드 수정** → 분석 도구는 읽기 전용
6. **`super.visit()` 생략** → 자식 노드 방문 누락으로 탐지 실패
7. **TaintSet 공유** → 메서드 분석마다 반드시 `taintSet.clear()`
8. **가이드 참조 페이지 생략** → `guideRef` 필드는 항상 채울 것

### ⚠️ 주의 사항

1. **오탐(False Positive) 최소화**: Sanitizer 목록을 꼼꼼히 유지하세요. 특히 `replaceAll` 단독 호출은 완전한 sanitizer로 간주하지 마세요.
2. **MyBatis `${}`와 `#{}`**: `${}` 는 Sink, `#{}` 는 Sanitizer입니다.
3. **메서드 체이닝**: `request.getParameter("id").trim()` 에서 `trim()` 결과도 오염된 것으로 추적해야 합니다.
4. **라인 번호**: JavaParser는 1-based입니다. `n.getBegin().map(p -> p.line).orElse(-1)` 패턴 사용.

---

## 11. 의존성 추가 시 규칙

`pom.xml`에 새 의존성을 추가하기 전에:

1. **기존 의존성으로 해결 가능한지 먼저 확인** (JavaParser, Jackson, Commons IO)
2. **라이선스 확인** (Apache 2.0, MIT 허용 / GPL 금지)
3. **security-rules.json에 해당 라이브러리 취약점 패턴이 있는지 검토**
4. `pom.xml` 상단 `<properties>` 섹션에 버전 변수 추가 후 참조

```xml
<!-- ✅ 올바른 패턴 -->
<properties>
    <new-lib.version>1.2.3</new-lib.version>
</properties>
<dependency>
    <groupId>com.example</groupId>
    <artifactId>new-lib</artifactId>
    <version>${new-lib.version}</version>
</dependency>
```

---

## 12. Claude Code에게 — 작업 시작 전 체크리스트

새 작업을 시작할 때 이 체크리스트를 확인하세요.

- [ ] 작업과 관련된 `security-rules.json` 항목을 먼저 읽었는가?
- [ ] 가이드 Rule ID(`IV-x.x`, `DS-x.x`)를 주석에 명시했는가?
- [ ] `Finding`을 Builder 패턴으로 생성했는가?
- [ ] `guideRef`와 `cweIds` 필드를 채웠는가?
- [ ] Visitor에서 `super.visit()`를 먼저 호출했는가?
- [ ] 빈 catch 블록이 없는가?
- [ ] `System.out.print` 대신 `log.*`를 사용했는가?
- [ ] 취약/안전 테스트 픽스처를 쌍으로 작성했는가?
- [ ] `mvn test`가 통과하는가?
