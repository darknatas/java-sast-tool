# 🛡️ Java SAST Engine Platform

행정안전부 **'소프트웨어 보안약점 진단가이드(2021)'**를 준수하는 Java 소스코드 정적 분석(SAST) 플랫폼입니다.

## 🚀 핵심 기능
- **Dual-Track 분석 엔진**: Taint Analysis와 Pattern Matching을 결합한 정밀 진단
- **Sequence Analysis**: TOCTOU(경쟁 조건)와 같은 함수 호출 순서 기반 취약점 탐지
- **Web Dashboard**: ZIP 파일 업로드 방식의 분석 결과 시각화 및 조치 방안 제안
- **Validation Agent**: 69개 보안 규칙에 대한 자동화된 커버리지 테스트 (`SastValidator`)
- **Safety Mechanism**: Zip Slip 방어, ZIP Bomb 방지 및 임시 파일 자동 삭제

## 🛠 Tech Stack
- **Language**: Java 17
- **Framework**: Spring Boot 3.3.0, Thymeleaf
- **Infrastructure**: AWS EC2 (Amazon Linux)

## 🏃 Quick Start (Deployment)

### 빌드
```bash
mvn clean package -DskipTests
```

### 서비스 실행 (백그라운드)
```bash
# 기존 서버 종료 (5000번 포트)
kill $(lsof -ti:5000) 2>/dev/null || true

# nohup으로 재시작
nohup java -jar target/sast.jar > sast.log 2>&1 &
echo $! > sast.pid
```

### 서비스 종료
```bash
kill $(cat sast.pid)
rm sast.pid
```

## 🌐 접속 정보
- **URL**: [http://15.164.190.193:5000](http://15.164.190.193:5000)

## 📊 검증 에이전트 실행
```bash
# 전수 검사 리포트 출력
mvn test -Dtest=SastValidator
```

## 📂 Project Structure
- `src/main/java/com/sast/engine`: 분석 핵심 엔진 및 로직
- `src/main/java/com/sast/web`: 웹 UI 및 API 컨트롤러
- `src/test/resources/samples`: 규칙 검증용 취약점 코드 샘플 (69종)

