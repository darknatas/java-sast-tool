# Java SAST 도구 — 보안약점 점검 항목 및 탐지·수정 방식 요약

본 도구는 행정안전부 **「소프트웨어 보안약점 진단가이드(2021)」** 를 기준으로 Java 소스코드를 정적 분석(SAST)하여 총 **69개 보안약점**을 자동 탐지하고, 항목별 수정 방향을 제시합니다.

- **PART3 (DS-x.x)** — 분석·설계단계 보안설계 기준: **20개 항목**
- **PART4 (IV-x.x)** — 구현단계 보안약점 제거 기준: **49개 항목**

---

## 1. 탐지 방식

모든 규칙은 `security-rules.json`에 정의되어 있으며, 규칙 성격에 따라 아래 엔진이 분석을 수행합니다.

| 탐지 방식 | 엔진 | 적용 규칙 수 | 동작 원리 |
|---|---|---|---|
| **오염 추적 (Taint Analysis)** | `TaintAnalysisEngine` | 14개 | 외부 입력(Source: `getParameter()`, `getenv()` 등) → 변수 전파(Propagation: 문자열 연결·대입) → 위험 API(Sink: `executeQuery()`, `exec()` 등) 도달 여부를 AST 기반 데이터플로우로 추적. 중간에 Sanitizer(`prepareStatement()`, `escapeHtml()` 등)를 거치면 오염 해제로 판단하여 오탐 방지 |
| **위험 패턴 매칭 (Pattern Analysis)** | `PatternAnalyzer` | 55개 | 규칙별 `dangerousPatterns` 정규식으로 취약한 API 호출·코딩 패턴(취약 암호 알고리즘, 하드코딩된 비밀번호, 빈 catch 블록 등)을 탐지 |
| **시퀀스 분석** | `SequenceAnalyzer` | IV-3.1 | 파일 검사 시점과 사용 시점 사이의 호출 순서를 분석하여 TOCTOU 경쟁조건 탐지 |
| **오탐 필터** | `FalsePositiveFilter` | 전체 | 테스트 경로 제외, Sanitizer 인식, 사용자 정의 억제 규칙(`sast-suppressions.json`)의 3-Layer 필터로 오탐 최소화 |

> AST 파싱은 JavaParser + SymbolSolver(타입 해석)를 사용하며, 메서드 단위 인트라-프로시저럴 데이터플로우로 분석합니다.

---

## 2. 점검 항목 목록 (69개)

### PART3 — 설계단계 (DS, 20개)

#### 입력데이터 검증 및 표현 (10개)

| Rule ID | 약점명 | CWE | 위험도 | 수정 방향 |
|---|---|---|---|---|
| DS-1.1 | DBMS 조회 및 결과 검증 | CWE-89 | HIGH | PreparedStatement 파라미터 바인딩 설계 |
| DS-1.2 | XML 조회 및 결과 검증 | CWE-652, 643 | HIGH | XPath 변수 바인딩·특수문자 검증 |
| DS-1.3 | 디렉토리 서비스 조회 및 결과 검증 | CWE-90 | HIGH | LDAP 입력값 인코딩 |
| DS-1.4 | 시스템 자원 접근 및 명령어 수행 입력값 검증 | CWE-78, 22, 99 | HIGH | OS 명령 호출 회피·입력값 검증 |
| DS-1.5 | 웹 서비스 요청 및 결과 검증 | CWE-79 | HIGH | 출력값 HTML 인코딩 |
| DS-1.6 | 웹 기반 중요 기능 수행 요청 유효성 검증 | CWE-352 | HIGH | CSRF 토큰 적용 |
| DS-1.7 | HTTP 프로토콜 유효성 검증 | CWE-113 | MEDIUM | CRLF 문자 제거 |
| DS-1.8 | 허용된 범위내 메모리 접근 | CWE-119, 190 | HIGH | 배열·정수 경계값 검사 |
| DS-1.9 | 보안기능 입력값 검증 | CWE-807, 476 | HIGH | 서버 측 권한 검증 |
| DS-1.10 | 업로드·다운로드 파일 검증 | CWE-434, 494 | HIGH | 파일 확장자 화이트리스트 |

#### 보안기능 (8개)

| Rule ID | 약점명 | CWE | 위험도 | 수정 방향 |
|---|---|---|---|---|
| DS-2.1 | 인증 대상 및 방식 | CWE-306 | HIGH | 인증 필터(게이트) 설계 |
| DS-2.2 | 인증 수행 제한 | CWE-307 | MEDIUM | 계정 잠금 정책 |
| DS-2.3 | 비밀번호 관리 | CWE-521 | HIGH | 비밀번호 복잡도 정책 |
| DS-2.4 | 중요자원 접근통제 | CWE-285, 732 | HIGH | 최소 권한 원칙 |
| DS-2.5 | 암호키 관리 | CWE-321 | HIGH | 키·비밀정보 외부화 |
| DS-2.6 | 암호연산 | CWE-327, 326 | HIGH | 검증된 강력한 암호 알고리즘 |
| DS-2.7 | 중요정보 저장 | CWE-312, 539 | HIGH | 중요정보 암호화 저장 |
| DS-2.8 | 중요정보 전송 | CWE-319 | HIGH | TLS 등 암호화 전송 |

#### 에러처리·세션통제 (2개)

| Rule ID | 약점명 | CWE | 위험도 | 수정 방향 |
|---|---|---|---|---|
| DS-3.1 | 예외처리 | CWE-209, 390 | MEDIUM | 일반화된 오류 메시지 설계 |
| DS-4.1 | 세션 통제 | CWE-488 | HIGH | 세션 격리·안전한 세션 설계 |

### PART4 — 구현단계 (IV, 49개)

#### 입력데이터 검증 및 표현 (17개)

| Rule ID | 약점명 | CWE | 위험도 | 탐지 | 수정 방향 |
|---|---|---|---|---|---|
| IV-1.1 | SQL 삽입 | CWE-89 | HIGH | Taint | PreparedStatement / MyBatis `#{}` 사용 |
| IV-1.2 | 코드삽입 | CWE-94, 95 | HIGH | Taint | 입력값 화이트리스트 검증 |
| IV-1.3 | 경로 조작 및 자원 삽입 | CWE-22, 99, 78 | HIGH | Taint | `getCanonicalPath()` 경로 정규화·기준 디렉터리 검증 |
| IV-1.4 | 크로스사이트 스크립트(XSS) | CWE-79 | HIGH | Taint | 출력 시 HTML 인코딩(`escapeHtml` 등) |
| IV-1.5 | 운영체제 명령어 삽입 | CWE-78 | **CRITICAL** | Taint | OS 명령 직접 호출 회피·인자 분리 |
| IV-1.6 | 위험한 형식 파일 업로드 | CWE-434 | HIGH | Pattern | 확장자 화이트리스트·저장 경로 분리 |
| IV-1.7 | 신뢰되지 않는 URL 주소로 자동접속 연결 | CWE-601 | MEDIUM | Taint | 리다이렉트 URL 화이트리스트 |
| IV-1.8 | 부적절한 XML 외부개체 참조(XXE) | CWE-611 | HIGH | Pattern | 외부 엔티티(DTD) 기능 비활성화 |
| IV-1.9 | XML 삽입 | CWE-652, 643 | HIGH | Taint | XPath 변수 바인딩 |
| IV-1.10 | LDAP 삽입 | CWE-90 | HIGH | Taint | LDAP 특수문자 인코딩 |
| IV-1.11 | 크로스사이트 요청 위조(CSRF) | CWE-352 | HIGH | Pattern | CSRF 토큰 검증 |
| IV-1.12 | 서버사이드 요청 위조(SSRF) | CWE-918 | HIGH | Taint | 요청 대상 호스트 허용목록 |
| IV-1.13 | HTTP 응답분할 | CWE-113 | MEDIUM | Taint | 헤더 값 CRLF 제거 |
| IV-1.14 | 정수형 오버플로우 | CWE-190 | MEDIUM | Pattern | 연산 전 범위 검사 |
| IV-1.15 | 보안기능 결정에 사용되는 부적절한 입력값 | CWE-807 | HIGH | Taint | 서버 세션 기반 권한 판단 |
| IV-1.16 | 메모리 버퍼 오버플로우 | CWE-119 | HIGH | Pattern | 안전한 배열 접근·경계 검사 |
| IV-1.17 | 포맷 스트링 삽입 | CWE-134 | HIGH | Taint | 포맷 문자열 리터럴 고정 |

#### 보안기능 (16개)

| Rule ID | 약점명 | CWE | 위험도 | 수정 방향 |
|---|---|---|---|---|
| IV-2.1 | 적절한 인증 없는 중요기능 허용 | CWE-306 | HIGH | 인증 필터 적용 |
| IV-2.2 | 부적절한 인가 | CWE-285 | HIGH | 역할 기반 접근통제(RBAC) 검사 |
| IV-2.3 | 중요한 자원에 대한 잘못된 권한 설정 | CWE-732 | HIGH | 최소 권한 부여 |
| IV-2.4 | 취약한 암호화 알고리즘 사용 | CWE-327 | HIGH | DES·MD5 등 제거, AES-256/SHA-256 이상 사용 |
| IV-2.5 | 암호화되지 않은 중요정보 | CWE-312 | HIGH | 중요정보 암호화 저장·전송 |
| IV-2.6 | 하드코드된 중요정보 | CWE-321 | HIGH | 비밀번호·키를 외부 설정/보안 저장소로 분리 |
| IV-2.7 | 충분하지 않은 키 길이 사용 | CWE-326 | MEDIUM | RSA 2048bit·AES 128bit 이상 키 길이 |
| IV-2.8 | 적절하지 않은 난수 값 사용 | CWE-330 | MEDIUM | `Random` 대신 `SecureRandom` 사용 |
| IV-2.9 | 취약한 비밀번호 허용 | CWE-521 | MEDIUM | 비밀번호 복잡도 검증 |
| IV-2.10 | 부적절한 전자서명 확인 | CWE-347 | HIGH | 서명 검증 수행 |
| IV-2.11 | 부적절한 인증서 유효성 검증 | CWE-295 | HIGH | 인증서 검증 우회 코드 제거 |
| IV-2.12 | 쿠키를 통한 정보 노출 | CWE-539 | MEDIUM | `Secure`·`HttpOnly` 속성, 영속 쿠키에 중요정보 금지 |
| IV-2.13 | 주석문 안에 포함된 시스템 주요정보 | CWE-615 | LOW | 주석 내 계정·키 정보 제거 |
| IV-2.14 | 솔트 없이 일방향 해쉬 함수 사용 | CWE-759 | MEDIUM | 솔트 적용 해시(bcrypt 등) |
| IV-2.15 | 무결성 검사 없는 코드 다운로드 | CWE-494 | HIGH | 체크섬·서명 검증 후 실행 |
| IV-2.16 | 반복된 인증시도 제한 기능 부재 | CWE-307 | MEDIUM | 인증 실패 횟수 제한·계정 잠금 |

#### 시간 및 상태 (2개)

| Rule ID | 약점명 | CWE | 위험도 | 탐지 | 수정 방향 |
|---|---|---|---|---|---|
| IV-3.1 | 경쟁조건: 검사 시점과 사용 시점(TOCTOU) | CWE-367, 362 | MEDIUM | Sequence | 원자적 파일 연산·동기화 |
| IV-3.2 | 종료되지 않는 반복문 또는 재귀 함수 | CWE-835 | MEDIUM | Pattern | 명확한 종료 조건 추가 |

#### 에러처리 (3개)

| Rule ID | 약점명 | CWE | 위험도 | 수정 방향 |
|---|---|---|---|---|
| IV-4.1 | 오류 메시지 정보노출 | CWE-209 | MEDIUM | 스택트레이스 노출 금지, 일반화된 메시지 |
| IV-4.2 | 오류상황 대응 부재 | CWE-390 | MEDIUM | 빈 catch 블록 금지, 로깅·복구 처리 |
| IV-4.3 | 부적절한 예외 처리 | CWE-754 | LOW | 광범위한 `Exception` 대신 구체적 예외 처리 |

#### 코드오류 (5개)

| Rule ID | 약점명 | CWE | 위험도 | 탐지 | 수정 방향 |
|---|---|---|---|---|---|
| IV-5.1 | Null Pointer 역참조 | CWE-476 | HIGH | Pattern | null 검사 후 사용 |
| IV-5.2 | 부적절한 자원 해제 | CWE-772 | MEDIUM | Pattern | try-with-resources 사용 |
| IV-5.3 | 해제된 자원 사용 | CWE-416 | HIGH | Pattern | 해제 후 참조 제거(null 할당) |
| IV-5.4 | 초기화되지 않은 변수 사용 | CWE-457 | MEDIUM | Pattern | 선언 시 초기화 |
| IV-5.5 | 신뢰할 수 없는 데이터의 역직렬화 | CWE-502 | **CRITICAL** | Taint | 역직렬화 클래스 허용목록·안전한 포맷 사용 |

#### 캡슐화 (4개)

| Rule ID | 약점명 | CWE | 위험도 | 수정 방향 |
|---|---|---|---|---|
| IV-6.1 | 잘못된 세션에 의한 데이터 정보 노출 | CWE-488 | HIGH | 세션 간 데이터 격리(멤버 변수 공유 금지) |
| IV-6.2 | 제거되지 않고 남은 디버그 코드 | CWE-489 | LOW | 배포 전 디버그 코드 제거 |
| IV-6.3 | Public 메소드부터 반환된 Private 배열 | CWE-495 | LOW | 방어적 복사 후 반환 |
| IV-6.4 | Private 배열에 Public 데이터 할당 | CWE-496 | LOW | 입력 배열 방어적 복사 |

#### API 오용 (2개)

| Rule ID | 약점명 | CWE | 위험도 | 수정 방향 |
|---|---|---|---|---|
| IV-7.1 | DNS lookup에 의존한 보안결정 | CWE-350 | MEDIUM | 호스트명 대신 IP 기반 검증 |
| IV-7.2 | 취약한 API 사용 | CWE-676 | MEDIUM | 안전한 대체 API 사용 |

---

## 3. 수정 방향 제시 방식

탐지된 각 취약점에 대해 `RemediationService`가 **실제 코드 맥락이 반영된 수정안**을 자동 생성합니다.

1. **맞춤형 수정 코드** — 플레이스홀더가 아닌, AST에서 추출한 **실제 변수명이 삽입된** 수정 코드를 제시합니다.
   ```java
   // [수정] IV-1.1 SQL 삽입: PreparedStatement 사용
   String sql = "SELECT * FROM board WHERE b_gubun = ?";
   PreparedStatement pstmt = con.prepareStatement(sql);
   pstmt.setString(1, gubun);   // ← 탐지된 변수명 자동 삽입
   ```
2. **탐지 근거 설명** — 오염 흐름(Source 라인 → 전파 변수 → Sink 라인)을 한국어 문장으로 설명합니다.
3. **참고자료 연결** — 진단가이드 페이지(예: `PART4 제1절 1항 (p.180-193)`), CWE 번호, OWASP 참고 URL을 함께 제공합니다.

## 4. 리포트 출력

분석 완료 시 다음 형식으로 결과가 생성됩니다.

- **Markdown / JSON 리포트** (`ReportGenerator`) — 항목별 진단번호·위험도·취약 코드·권고 수정 코드·오염 흐름 포함
- **PDF 진단서** (`PdfReportGenerator`) — 웹 UI(`http://<서버IP>:5000`)에서 다운로드 가능

> 상세 사용 방법은 `user_manual.md`(또는 PDF/DOCX) 문서를 참고하세요.
