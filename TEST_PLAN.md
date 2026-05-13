# TEST_PLAN.md — Java SAST Engine 기능 검증 체크리스트

> 한 번에 하나씩 순서대로 수행한다. 각 항목은 이전 항목이 통과된 상태를 전제로 한다.

---

## 체크리스트

| # | 항목 | 검증 방법 | 기대 결과 | 상태 |
|---|------|-----------|-----------|------|
| 1 | **빌드** | `mvn package -DskipTests` 실행 후 JAR 존재 확인 | BUILD SUCCESS, `target/sast.jar` 생성 | ✅ |
| 2 | **서버 기동** | JAR 실행 후 `GET /` 응답 확인 | HTTP 200, 페이지 내 "Java SAST Engine" 포함 | ⬜ |
| 3 | **규칙 로드** | 서버 기동 로그에서 규칙 수 확인 | "보안 규칙 69개 로드 완료" 로그 출력 | ⬜ |
| 4 | **ZIP 업로드 및 분석** | 취약한 Java 파일이 담긴 ZIP을 `POST /analyze`로 전송 | HTTP 200, findings 1건 이상 반환 | ⬜ |
| 5 | **7z 업로드 및 분석** | 동일 파일을 7z로 압축하여 `POST /analyze`로 전송 | ZIP과 동일한 탐지 결과 반환 | ⬜ |
| 6 | **잘못된 확장자 거부** | `.txt` 파일을 `POST /analyze`로 전송 | 리다이렉트 후 에러 메시지 표시 | ⬜ |
| 7 | **빈 파일 거부** | 크기 0인 ZIP을 `POST /analyze`로 전송 | 리다이렉트 후 에러 메시지 표시 | ⬜ |
| 8 | **Zip Slip 방어** | `../../../etc/passwd` 경로를 포함한 ZIP 전송 | SecurityException 발생, 에러 메시지 반환 | ⬜ |
| 9 | **결과 화면 구성** | 분석 결과 페이지에서 UI 요소 확인 | 심각도 카드 4개, 아코디언 항목, 취약/수정 코드 탭 정상 렌더링 | ⬜ |
| 10 | **파일 크기 제한 설정** | `application.properties` 값 확인 | `max-file-size=100MB`, `max-request-size=100MB` | ⬜ |

---

## 테스트 환경

- **서버 주소**: `http://localhost:5000` (외부: `http://teskim-vibecoding.ddns.net:5000`)
- **테스트 픽스처**: `src/test/java/com/sast/fixtures/vulnerable/` 내 Java 파일 사용
- **상태 기호**: ⬜ 미수행 · ✅ 통과 · ❌ 실패

---

## 진행 로그

<!-- 각 항목 수행 후 결과를 아래에 기록 -->

| # | 수행일 | 결과 | 비고 |
|---|--------|------|------|
| 1 | 2026-04-27 | ✅ 통과 | BUILD SUCCESS, 30MB JAR 생성, `security-rules.json` / `SASTEngine.class` / `SastApplication.class` JAR 내 포함 확인 |
| - | 2026-04-27 | ✅ 엔진 최적화 | Dual-Track 분석 적용: Taint(13개 규칙) + Pattern(56개 규칙). 샘플 파일 스캔 결과: IV-1.1(Taint) 1건, IV-2.6(Pattern) 2건, IV-4.2(Pattern) 1건, IV-6.2(Pattern) 1건 정상 탐지 확인 |
