# 🛡️ Java SAST Engine Platform

행정안전부 **'소프트웨어 보안약점 진단가이드(2021)'**를 준수하는 Java 소스코드 정적 분석(SAST) 플랫폼입니다.

## 🚀 핵심 기능
- **Dual-Track 분석 엔진**: Taint Analysis(오염 흐름 추적)와 Pattern Matching(정규식 분석)을 결합한 정밀 진단
- **Sequence Analysis**: TOCTOU(경쟁 조건)와 같은 함수 호출 순서 기반 취약점 탐지
- **Web Dashboard**: ZIP 파일 업로드 방식의 직관적인 분석 결과 시각화 및 조치 방안 제안
- **Validation Agent**: 69개 보안 규칙에 대한 자동화된 커버리지 테스트 및 리포팅 (`SastValidator`)
- **Security First**: Zip Slip, ZIP Bomb 방어 로직 및 임시 파일 자동 삭제 메커니즘 적용

## 🛠 Tech Stack
- **Language**: Java 17
- **Framework**: Spring Boot 3.3.0, Thymeleaf
- **Library**: JavaParser (AST Analysis), Jackson, Bootstrap 5
- **Build Tool**: Maven

## 📊 Project Status (Rule Coverage)
현재 행정안전부 가이드의 총 69개 규칙 중 핵심 항목들에 대한 구현이 완료되었습니다.
- **Total Rules**: 69
- **Implemented**: 18 (Taint: 11, Sequence: 1, Pattern: 6)
- **Success Rate**: 100% (Implemented 기준)

## 🏃 Quick Start
### Prerequisites
- JDK 17 이상
- Maven 3.x 이상

### Build & Run
```bash
# 빌드
mvn clean package -DskipTests

# 실행
java -jar target/java-sast-engine-1.0.0.jar
```
이후 브라우저에서 `http://localhost:8080` 접속

### Run Validation Agent
```bash
# 보안 규칙 탐지 성능 전수 검사
mvn test -Dtest=SastValidator
```

## 📂 Project Structure
- `src/main/java/com/sast/engine`: 분석 핵심 엔진 및 로직
- `src/main/java/com/sast/web`: 웹 UI 및 API 컨트롤러
- `src/main/resources`: 보안 규칙(json) 및 웹 템플릿
- `src/test/resources/samples`: 규칙 검증용 취약점 코드 샘플 (69종)

