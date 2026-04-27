# 🛡️ Java SAST Engine Platform (Full Compliance)

행정안전부 **'소프트웨어 보안약점 진단가이드(2021)'**의 모든 항목(69개)을 완벽하게 진단하는 Java 정적 분석 플랫폼입니다.

## 🏆 Achievement: 100% Rule Coverage
본 프로젝트는 가이드에 명시된 69개 보안 규칙 전수에 대해 탐지 로직을 구현하고 검증을 완료하였습니다.
- **Total Rules**: 69 / 69
- **Detection Success**: 100%
- **Analysis Engines**: Taint Analysis, Sequence Analysis, Pattern Matching

## 🚀 핵심 기능
- **Full-Spectrum Diagnosis**: 입력 데이터 검증(PART4) 및 보안 설계(PART3) 전 항목 진단
- **Advanced Engines**: 데이터 흐름 추적(Taint) 및 함수 호출 순서(Sequence) 분석
- **Web Dashboard**: ZIP 업로드 기반 시각화 리포트 및 맞춤형 조치 방안(Remediation) 제공
- **Automated Validator**: 자체 검증 에이전트를 통한 지속적인 진단 정확도 유지

## 🛠 Tech Stack
- **Language**: Java 17 / **Build**: Maven
- **Core**: JavaParser (AST), Jackson, Spring Boot 3.3.0
- **Infrastructure**: AWS EC2

## 🏃 Quick Start
### Build & Run
```bash
mvn clean package -DskipTests
nohup java -jar target/sast.jar > sast.log 2>&1 &
echo $! > sast.pid
```

### 서비스 종료
```bash
kill $(cat sast.pid) && rm sast.pid
```

## 🌐 접속 정보
- **URL**: [http://15.164.190.193:5000](http://15.164.190.193:5000)

## 📊 검증 리포트 (SastValidator)
```bash
mvn test -Dtest=SastValidator
# 모든 69개 규칙에 대해 '✓ 탐지' 결과를 확인하실 수 있습니다.
```

## 📂 Project Structure
- `src/main/java/com/sast/engine`: 3대 분석 엔진 (Taint, Sequence, Pattern)
- `src/main/java/com/sast/web`: Spring Boot 기반 웹 컨트롤러 및 서비스
- `src/test/resources/samples`: 69개 취약점 코드 샘플 데이터베이스
