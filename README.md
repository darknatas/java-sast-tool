# 🛡️ Java SAST Engine Platform (Enterprise Ready)

행정안전부 **'소프트웨어 보안약점 진단가이드(2021)'**의 69개 전 항목을 준수하며, 실제 상용 소스 코드의 복잡한 로직까지 정밀하게 진단하는 Java 정적 분석 플랫폼입니다.

## 🏆 Achievement & Status

- **Rule Coverage**: 98.6% (69개 규칙 중 68개 검증 완료)
- **Real-World Focus**: 상용 수준 프로젝트 대상 700건 이상의 취약점 식별 및 정제 성공
- **Detection Success**: 100% (SastValidator 단위 테스트 기준)

## 🚀 핵심 고도화 기능

### 1. 전문적인 PDF 보안 진단서 출력
- **OpenPDF 기반 자동 생성**: 분석 직후 최대 300~400페이지 분량의 상세 진단서를 PDF로 즉시 출력합니다.
- **다국어 및 시각화 지원**: `NotoSansCJKkr` 폰트를 적용하여 한국어 조치 가이드와 권고 코드를 완벽하게 렌더링합니다.

### 2. 지능형 오탐(False Positive) 필터링 시스템
- **자동 필터링**: `src/test/java` 경로 파일 위험도 자동 하향 및 주석 라인 무시.
- **Suppression 지원**: `sast-suppressions.json` 및 `@SuppressWarnings("sast-ignore")`를 통한 정밀 제어.

### 3. 실전형 정밀 탐지 엔진
- **Context-Aware Sequence**: `exists()` 체크와 사용 사이의 복잡한 **TOCTOU(경쟁 조건)** 패턴 추적.
- **Advanced Taint Analysis**: 서비스 레이어의 싱글톤 객체 내 **세션 데이터 혼입(DS-4.1)** 위험 탐지.

## 🛠 Tech Stack

- **Language**: Java 17 / **Build**: Maven
- **Core**: JavaParser (AST), Jackson, Spring Boot 3.3.0
- **Infrastructure**: AWS EC2 (t4g.medium / Unlimited Mode)



## 🏃 Quick Start

### 1. 서비스 시작 (Build & Run)
\`\`\`bash
mvn clean package -DskipTests
nohup java -jar target/sast.jar > sast.log 2>&1 &
echo $! > sast.pid
\`\`\`

### 2. 서비스 종료 (Stop)
\`\`\`bash
kill \$(cat sast.pid) && rm sast.pid
\`\`\`

### 3. 검증 리포트 실행 (SastValidator)
\`\`\`bash
mvn test -Dtest=SastValidator
# 모든 69개 규칙에 대한 단위 테스트 탐지 결과를 확인하실 수 있습니다.
\`\`\`

### 4. 분석 및 리포트 확인
- **URL**: [http://15.164.190.193:5000](http://15.164.190.193:5000) 접속.
- **사용**: ZIP 소스 업로드 → 분석 완료 → **[PDF 리포트 다운로드]** 버튼 클릭.

## 📂 Project Structure

- `com.sast.engine.report`: PDF 리포트 생성 및 시각화 엔진
- `com.sast.engine.rules`: 행안부 가이드 기반 69개 보안 규칙 지식 베이스
- `com.sast.engine.analysis`: Taint/Sequence/Pattern 분석 코어 로직
- `src/test/resources/samples`: 69개 취약점 검증용 테스트 데이터베이스
