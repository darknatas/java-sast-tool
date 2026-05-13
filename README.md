# Java SAST Engine

행정안전부 **소프트웨어 보안약점 진단가이드 (2021)** 의 **69개 전 항목**을 준수하는 Java 소스코드 정적 분석 플랫폼입니다.

> PART3 설계단계 20개 (DS-x.x) + PART4 구현단계 49개 (IV-x.x)

---

## 주요 특징

### 지능형 Taint Analysis (Sanitizer 인식)

Source → Propagator → Sink 3단계 오염 흐름을 인트라-프로시저럴 Dataflow로 추적합니다.

- **Source** 12종: `getParameter`, `getHeader`, `getInputStream`, `readLine`, `getenv` 등 외부 입력 진입점
- **Sanitizer** 30종 자동 인식: `prepareStatement`, `escapeHtml`, `getCanonicalPath`, `encodeForHTML`, `validate` 등 — Sanitizer를 거친 변수는 오염 상태에서 자동 제거되어 오탐이 억제됩니다
- **Sink**: 규칙별로 독립적으로 정의 (`executeQuery`, `exec`, `new File`, `sendRedirect` 등 14개 규칙 매핑)

### 69개 규칙 전 항목 Bad / Good Code 가이드

`security-rules.json` 내 모든 규칙에 `bad_code` / `good_code` 예시와 수정 전략이 내장되어 있습니다. 탐지 결과에서 상세 보기 클릭 시 취약 코드와 권고 코드를 나란히 비교할 수 있습니다.

### 3-Track 분석 엔진

| 분석 트랙 | 대상 규칙 | 동작 방식 |
|---|---|---|
| **Taint Analysis** | taintAnalysis: true 규칙 (14개) | JavaParser AST + 오염 전파 추적 |
| **Sequence Analysis** | IV-3.1 (TOCTOU) | exists() 체크와 사용 사이의 경쟁 조건 탐지 |
| **Pattern Analysis** | dangerousPatterns 규칙 (57개) | 정규식 기반 AST 매칭 |

### 3-Layer 오탐(False Positive) 필터

1. `@SuppressWarnings("sast-ignore")` 어노테이션으로 특정 라인 억제
2. `src/test/` 경로 탐지 결과 자동 위험도 **LOW** 하향
3. `sast-suppressions.json` 사용자 정의 억제 규칙 (파일·규칙·라인 단위)

### 전문 PDF 보안 진단서

OpenPDF 라이브러리로 분석 즉시 PDF를 생성합니다. NotoSansCJKkr 폰트 적용으로 한국어 조치 가이드와 권고 코드를 완벽하게 렌더링합니다.

---

## 기술 스택

| 항목 | 선택 |
|---|---|
| Language | Java 17 |
| Build | Maven 3.8+ |
| AST Parser | JavaParser 3.25.x + SymbolSolver |
| Web | Spring Boot 3.3 + Thymeleaf |
| JSON | Jackson 2.17.x |
| PDF | OpenPDF 2.0.x |
| Logging | SLF4J + Logback |
| Test | JUnit 5 + AssertJ |

---

## 빠른 시작

### 빌드

```bash
# 전체 빌드 (테스트 포함)
mvn clean package

# 빠른 빌드 (테스트 생략)
mvn clean package -DskipTests
```

### 웹 서버 실행 (권장)

```bash
# 백그라운드 실행 (포트 5000)
nohup java -jar target/sast.jar > sast.log 2>&1 &
echo $! > sast.pid

# 브라우저에서 접속
# http://<서버IP>:5000

# 서비스 종료
kill $(cat sast.pid) && rm sast.pid
```

### CLI 실행 (자동화 / CI-CD)

```bash
# <소스 디렉터리> <리포트 출력 경로>
java -cp target/sast.jar com.sast.SASTEngine ./src/main/java ./report.md

# report.md / report.json / report.pdf 자동 생성
```

### 단위 테스트 (69개 규칙 검증)

```bash
mvn test -Dtest=SastValidator
```

---

## 웹 대시보드 사용 흐름

```
브라우저 접속 → ZIP / 7z 업로드 → 분석 시작 →
결과 대시보드 (위험도별 필터) → 상세 보기 (Bad/Good 코드 비교) → PDF 다운로드
```

- 업로드 최대 크기: **100MB** (`.zip`, `.7z` 지원)
- 결과 화면: CRITICAL / HIGH / MEDIUM / LOW 카운트 + 파일·라인 정보 + 오염 흐름(Taint Flow)
- 상세 모달: 탐지 근거 + 취약 코드 + 권고 수정 코드 + CWE 참조

---

## 위험도 분포 (현재 규칙 기준)

| 위험도 | 규칙 수 | 대표 항목 |
|---|---|---|
| CRITICAL | 2 | OS 명령어 삽입 (IV-1.5), 역직렬화 (IV-5.5) |
| HIGH | 42 | SQL 삽입 (IV-1.1), 경로 조작 (IV-1.3), XSS (IV-1.4) |
| MEDIUM | 20 | HTTP 응답분할 (IV-1.13), 오류 정보 노출 (IV-4.1) |
| LOW | 5 | 디버그 코드 (IV-6.2), 주석 내 정보 (IV-2.13) |

---

## 디렉터리 구조

```
src/main/java/com/sast/
├── SASTEngine.java                        # 진입점 (CLI), 9단계 파이프라인 조율
├── engine/
│   ├── taint/TaintAnalysisEngine.java     # Taint 분석 코어 (Source/Sanitizer/Sink)
│   ├── sequence/SequenceAnalyzer.java     # TOCTOU 시퀀스 분석
│   └── pattern/PatternAnalyzer.java       # 정규식 기반 패턴 탐지
├── model/Finding.java                     # 탐지 결과 모델 (Builder 패턴, 불변)
├── filter/FalsePositiveFilter.java        # 3-Layer 오탐 필터
├── remediation/RemediationService.java    # 수정 코드 자동 생성
├── report/
│   ├── ReportGenerator.java               # Markdown / JSON 출력
│   └── PdfReportGenerator.java            # PDF 진단서 생성
└── web/
    ├── SastApplication.java               # Spring Boot 진입점 (포트 5000)
    ├── SastWebController.java             # 업로드 / 결과 / PDF 다운로드 엔드포인트
    └── SastAnalysisService.java           # 웹 분석 서비스 레이어

src/main/resources/
├── security-rules.json                    # 69개 규칙 DB (bad_code / good_code 포함)
├── sast-suppressions.json                 # 사용자 정의 오탐 억제 규칙
└── templates/
    ├── index.html                         # 업로드 UI
    └── results.html                       # 분석 결과 대시보드
```

---

## 오탐 억제 방법

**1. 어노테이션 (라인 단위)**
```java
@SuppressWarnings("sast-ignore")
String sql = "SELECT * FROM legacy_table WHERE id=" + id; // 레거시 읽기전용 쿼리
```

**2. sast-suppressions.json (파일·규칙 단위)**
```json
[
  {
    "file": "LegacyBoardController.java",
    "ruleId": "IV-1.1",
    "line": null,
    "reason": "레거시 읽기전용 — 외부 노출 없음"
  }
]
```

---

## CI/CD 연동 예시

```bash
java -cp target/sast.jar com.sast.SASTEngine ./src ./report.md

CRITICAL=$(jq '[.findings[] | select(.severity=="CRITICAL")] | length' report.json)
if [ "$CRITICAL" -gt 0 ]; then
  echo "CRITICAL 취약점 ${CRITICAL}건 탐지 — 빌드 실패"
  exit 1
fi
```

---

*Java SAST Engine v1.0.0 — 행정안전부 소프트웨어 보안약점 진단가이드 2021 기반*
