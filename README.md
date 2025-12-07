# ISO Platform 백엔드

인증, 인증서 관리, 규정 준수 추적 기능을 제공하는 ISO Platform의 Spring Boot 백엔드 애플리케이션입니다.

## 목차

- [주요 기능](#주요-기능)
- [인증](#인증)
- [기술 스택](#기술-스택)
- [사전 요구사항](#사전-요구사항)
- [시작하기](#시작하기)
- [설정](#설정)
- [API 문서](#api-문서)
- [테스트](#테스트)
- [배포](#배포)
- [프로젝트 구조](#프로젝트-구조)

---

## 주요 기능

- **이중 인증 시스템:**
  - 이메일/비밀번호를 통한 로컬 인증
  - Google OAuth2 소셜 로그인
  - 모바일 딥링크 지원

- **보안 토큰 관리:**
  - JWT 액세스 토큰 (1시간 만료)
  - 자동 로테이션이 적용된 리프레시 토큰 (7일 만료)
  - 일회용 리프레시 토큰으로 보안 강화

- **인증서 관리:**
  - ISO 인증서 추적 및 관리
  - 규정 준수 상태 모니터링

- **RESTful API:**
  - 문서화된 REST 엔드포인트
  - 일관된 에러 핸들링
  - 요청 유효성 검사

---

## 인증

ISO Platform은 두 가지 인증 방식을 지원합니다.

### 1. 로컬 인증 (이메일/비밀번호)

JWT 토큰을 사용하는 전통적인 이메일/비밀번호 인증입니다.

**엔드포인트:**
- `POST /api/auth/signup` - 신규 사용자 등록
- `POST /api/auth/login` - 로그인
- `POST /api/auth/refresh` - 액세스 토큰 갱신
- `POST /api/auth/logout` - 로그아웃 및 리프레시 토큰 폐기

**사용 예시:**
```bash
# 회원가입
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "name": "홍길동",
    "company": "딥테크"
  }'

# 응답 예시:
# {
#   "accessToken": "eyJhbGc...",
#   "refreshToken": "a1b2c3d4...",
#   "tokenType": "Bearer",
#   "expiresIn": 3600000,
#   "userId": 1,
#   "email": "user@example.com",
#   "name": "홍길동",
#   "role": "USER"
# }

# API 요청 시 액세스 토큰 사용
curl -X GET http://localhost:8080/api/certificates \
  -H "Authorization: Bearer eyJhbGc..."
```

### 2. OAuth2 인증 (Google)

웹 및 모바일 애플리케이션을 위한 Google 소셜 로그인입니다.

**인증 흐름:**
1. 사용자를 다음 URL로 리다이렉트: `GET /api/auth/oauth2/authorization/google`
2. 사용자가 Google에서 인증
3. 토큰과 함께 앱으로 리다이렉트

**웹 리다이렉트:**
```
http://localhost:3000#access_token=eyJhbGc...&refresh_token=a1b2c3d4...&token_type=Bearer
```

**모바일 딥링크:**
```
totaload://oauth2/callback#access_token=eyJhbGc...&refresh_token=a1b2c3d4...&token_type=Bearer
```

### 토큰 수명

- **액세스 토큰:** 1시간 (3600초)
- **리프레시 토큰:** 7일 (604800초)

**토큰 갱신:**
```bash
# 액세스 토큰 만료 시 (401 응답) 갱신
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "a1b2c3d4..."}'

# 새 토큰이 발급되며, 기존 리프레시 토큰은 폐기됩니다
```

자세한 내용은 **[docs/API_AUTHENTICATION.md](docs/API_AUTHENTICATION.md)** 참고

---

## 기술 스택

- **프레임워크:** Spring Boot 3.5.4
- **언어:** Java 21
- **보안:** Spring Security 6.x + OAuth2
- **데이터베이스:** PostgreSQL + JPA/Hibernate
- **인증:** JWT (HS512) + OAuth2
- **빌드 도구:** Gradle 8.x
- **테스트:** JUnit 5, MockMvc, Testcontainers
- **문서화:** SpringDoc OpenAPI (Swagger)

---

## 사전 요구사항

- Java 21 이상
- PostgreSQL 14 이상
- Gradle 8.x (또는 포함된 wrapper 사용)
- Docker (선택사항)

---

## 시작하기

### 1. 저장소 클론

```bash
git clone https://github.com/your-org/iso-platform.git
cd iso-platform
```

### 2. 데이터베이스 설정

**방법 A: 로컬 PostgreSQL**
```bash
# 데이터베이스 생성
createdb isoplatform

# application-local.yml에서 연결 정보 수정
```

**방법 B: Docker PostgreSQL**
```bash
docker run -d \
  --name iso-postgres \
  -e POSTGRES_DB=isoplatform \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:14
```

### 3. 환경 변수 설정

프로젝트 루트에 `.env` 파일 생성:

```bash
# JWT 설정
JWT_SECRET=your-secret-key-minimum-256-bits-for-hs512-algorithm-required
JWT_EXPIRATION_TIME=3600000
JWT_REFRESH_EXPIRATION_TIME=604800000

# 데이터베이스
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/isoplatform
SPRING_DATASOURCE_USERNAME=postgres
SPRING_DATASOURCE_PASSWORD=postgres

# OAuth2 (Google 로그인 사용 시)
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

# 프론트엔드
FRONTEND_URL=http://localhost:3000
```

### 4. 빌드 및 실행

```bash
# 빌드
./gradlew build

# 실행
./gradlew bootRun

# 특정 프로파일로 실행
./gradlew bootRun --args='--spring.profiles.active=local'
```

애플리케이션이 `http://localhost:8080`에서 시작됩니다.

### 5. 설치 확인

```bash
# 헬스체크
curl http://localhost:8080/actuator/health
# 예상 응답: {"status":"UP"}

# 회원가입 테스트
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "name": "테스트"
  }'
```

---

## 설정

### 애플리케이션 프로파일

- **`local`** - 로컬 개발 환경 (기본값)
- **`test`** - 테스트 환경 (H2 인메모리 데이터베이스)
- **`prod`** - 운영 환경

**프로파일 활성화:**
```bash
# 커맨드라인
./gradlew bootRun --args='--spring.profiles.active=prod'

# 환경변수
export SPRING_PROFILES_ACTIVE=prod
./gradlew bootRun
```

### 주요 설정 파일

- `application.yml` - 기본 설정
- `application-local.yml` - 로컬 개발 설정
- `application-test.yml` - 테스트 환경 설정
- `application-prod.yml` - 운영 환경 설정

### Google OAuth2 설정

Google 로그인을 활성화하려면:

1. **Google Cloud 프로젝트 생성:**
   - [Google Cloud Console](https://console.cloud.google.com) 접속
   - 새 프로젝트 생성

2. **OAuth2 자격 증명 생성:**
   - "APIs & Services" > "Credentials" 이동
   - "Create Credentials" > "OAuth client ID" 클릭
   - 애플리케이션 유형: "Web application"
   - 승인된 리다이렉트 URI:
     - `http://localhost:8080/login/oauth2/code/google` (개발)
     - `https://api.yourdomain.com/login/oauth2/code/google` (운영)

3. **애플리케이션 설정:**
   - Client ID와 Client Secret 복사
   - `GOOGLE_CLIENT_ID`와 `GOOGLE_CLIENT_SECRET` 환경 변수 설정

---

## API 문서

### Swagger UI (대화형 API 문서)

로컬 실행 시:
- **Swagger UI:** http://localhost:8080/swagger-ui.html
- **OpenAPI JSON:** http://localhost:8080/v3/api-docs

### API 레퍼런스

| 엔드포인트 | 메서드 | 설명 | 인증 필요 |
|------------|--------|------|-----------|
| `/api/auth/signup` | POST | 신규 사용자 등록 | 아니오 |
| `/api/auth/login` | POST | 이메일/비밀번호 로그인 | 아니오 |
| `/api/auth/refresh` | POST | 액세스 토큰 갱신 | 아니오 |
| `/api/auth/logout` | POST | 로그아웃 및 토큰 폐기 | 아니오 |
| `/api/auth/oauth2/authorization/google` | GET | Google 로그인 시작 | 아니오 |
| `/api/certificates` | GET | 인증서 목록 조회 | 예 |
| `/api/certificates/{id}` | GET | 인증서 상세 조회 | 예 |
| `/actuator/health` | GET | 헬스체크 | 아니오 |

---

## 테스트

### 전체 테스트 실행

```bash
./gradlew test
```

### 특정 테스트 클래스 실행

```bash
./gradlew test --tests LocalAuthServiceTest
```

### 커버리지 리포트

```bash
./gradlew test jacocoTestReport
```

리포트 위치: `build/reports/jacoco/test/html/index.html`

### 테스트 현황

- 유닛 테스트: 45개
- 통합 테스트: 33개
- 총 78개 테스트, 100% 통과

---

## 배포

### 운영 배포 체크리스트

- [ ] `JWT_SECRET`을 보안 랜덤 값으로 변경 (최소 256비트)
- [ ] 운영 데이터베이스 설정 (연결 풀링 적용)
- [ ] HTTPS/SSL 인증서 설정
- [ ] `FRONTEND_URL`을 운영 프론트엔드 URL로 설정
- [ ] Google OAuth2 운영 리다이렉트 URI 설정
- [ ] 모니터링 및 로깅 설정
- [ ] 운영 도메인에 대한 CORS 설정
- [ ] 인증 엔드포인트 Rate Limiting 설정
- [ ] 데이터베이스 백업 설정

### Docker 배포

**Docker 이미지 빌드:**
```bash
./gradlew bootBuildImage --imageName=iso-platform-backend:latest
```

**Docker Compose 실행:**
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: isoplatform
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data

  backend:
    image: iso-platform-backend:latest
    ports:
      - "8080:8080"
    environment:
      SPRING_PROFILES_ACTIVE: prod
      SPRING_DATASOURCE_URL: jdbc:postgresql://postgres:5432/isoplatform
      SPRING_DATASOURCE_USERNAME: postgres
      SPRING_DATASOURCE_PASSWORD: ${DB_PASSWORD}
      JWT_SECRET: ${JWT_SECRET}
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
      GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET}
      FRONTEND_URL: ${FRONTEND_URL}
    depends_on:
      - postgres

volumes:
  postgres-data:
```

```bash
docker-compose up -d
```

---

## 프로젝트 구조

```
iso-platform/
├── src/
│   ├── main/
│   │   ├── java/com/isoplatform/api/
│   │   │   ├── auth/
│   │   │   │   ├── controller/      # REST 컨트롤러
│   │   │   │   ├── dto/             # 요청/응답 DTO
│   │   │   │   ├── service/         # 비즈니스 로직
│   │   │   │   ├── repository/      # 데이터 접근
│   │   │   │   ├── handler/         # OAuth2 핸들러
│   │   │   │   ├── security/        # 보안 필터
│   │   │   │   └── exception/       # 커스텀 예외
│   │   │   ├── certification/       # 인증서 모듈
│   │   │   └── config/              # 설정
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-local.yml
│   │       ├── application-test.yml
│   │       └── db/migration/        # Flyway 마이그레이션
│   └── test/                        # 테스트 파일
├── docs/
│   ├── API_AUTHENTICATION.md        # 인증 API 문서
│   └── plans/                       # 구현 계획서
├── build.gradle                     # Gradle 빌드 설정
└── README.md                        # 이 파일
```

---

## 문제 해결

### 자주 발생하는 문제

**1. 데이터베이스 연결 오류**
```
Error: Could not open JPA EntityManager for transaction
```
**해결:** PostgreSQL 실행 여부 확인, `application-local.yml` 연결 정보 확인

**2. JWT Secret 오류**
```
Error: The specified key byte array is 128 bits which is not secure enough
```
**해결:** JWT_SECRET을 더 긴 값으로 설정 (최소 256비트 / 32자)

**3. OAuth2 리다이렉트 오류**
```
Error: redirect_uri_mismatch
```
**해결:** Google Cloud Console에서 정확한 리다이렉트 URI 추가

**4. 테스트 실패**
```
Error: Port 8080 already in use
```
**해결:** 테스트 실행 전 애플리케이션 중지

**5. Gradle 빌드 오류**
```
Error: Could not find or load main class
```
**해결:** `./gradlew clean build`로 클린 빌드 수행

---

## 보안

### 보안 기능

- BCrypt 비밀번호 해싱 (strength 10)
- HS512 알고리즘의 JWT 토큰 서명
- 리프레시 토큰 로테이션 (일회용 토큰)
- SQL 인젝션 방지 (JPA 파라미터화된 쿼리)
- XSS 방지 (Spring Security 기본 설정)
- OAuth2 플로우 CSRF 방지
- 보안 헤더 설정 (Spring Security)

### 보안 취약점 신고

보안 취약점은 security@isoplatform.com 으로 신고해 주세요.
공개 GitHub 이슈로 보안 취약점을 신고하지 마세요.

---

**최종 업데이트:** 2025-12-07
**버전:** 1.0.0
