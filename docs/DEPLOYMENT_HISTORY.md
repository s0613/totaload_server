# Deployment History

> iso-platform 백엔드 배포 이력 관리

## 배포 정보

| 항목 | 값 |
|------|---|
| 프로젝트 | iso-platform |
| 기술 스택 | Spring Boot 3.5.4, Java 21 |
| 배포 환경 | AWS EC2 + Docker |
| 배포 방식 | 단일 스크립트 (deploy.sh) |
| 도메인 | api.totaloadcert.com |

---

## 배포 이력

### v1.0.2 - 2025-11-27

**배포 유형:** 정기 배포

**변경 사항:**
- 최신 코드 배포 (deploy.sh 스크립트 사용)

**검증:**
- Health Check: https://api.totaloadcert.com/actuator/health → `{"status":"UP"}`

**상태:** 🟢 성공

---

### Infrastructure Setup - 2025-11-27

**배포 유형:** AWS 인프라 구축

**변경 사항:**
- VPC 생성 (vpc-0dc0703020d146418, 10.0.0.0/16)
- Public Subnets 생성 (10.0.1.0/24, 10.0.2.0/24)
- Internet Gateway 생성 (igw-0273e8519bbf27e83)
- Security Groups 생성 (ALB-SG, App-SG, DB-SG)
- App EC2 생성 (i-0e1175beb258ca3fb, t3.small)
- DB EC2 생성 (i-0b621ab49dfd56866, t3.small)
- Elastic IP 할당 (13.124.207.109)
- ALB 생성 (totaload-alb)
- ACM 인증서 발급 (api.totaloadcert.com, *.totaloadcert.com)
- Route 53 레코드 추가 (api.totaloadcert.com → ALB)

**상태:** 🟢 완료

---

### v1.0.1 - 2025-11-27

**배포 유형:** 배포 전략 변경 및 DNS 설정

**변경 사항:**
- CI/CD (CodePipeline) → 단일 스크립트 (deploy.sh) 전환
- deploy.sh 스크립트 생성 및 테스트
- www.totaloadcert.com DNS 레코드 추가 (Vercel용)

**DNS 설정:**
| 도메인 | 타입 | 값 |
|--------|------|-----|
| api.totaloadcert.com | A (Alias) | totaload-alb-*.elb.amazonaws.com |
| www.totaloadcert.com | CNAME | cname.vercel-dns.com |

**상태:** 🟢 성공

---

### v1.0.0 - 2025-11-27

**배포 유형:** 초기 애플리케이션 배포

**변경 사항:**
- App EC2에 Docker 설치
- DB EC2에 MariaDB 10.5 설치
- totaload 데이터베이스 및 사용자 생성
- application-prod.yml 프로필 추가
- spring-boot-starter-actuator 의존성 추가
- Docker 이미지 빌드 (AMD64) 및 배포
- HTTPS 엔드포인트 검증 완료

**검증:**
- Health Check: https://api.totaloadcert.com/actuator/health → `{"status":"UP"}`
- Database: MariaDB 10.5.29 연결 성공

**상태:** 🟢 성공

---

## 배포 상태 범례

| 상태 | 설명 |
|------|------|
| 🟢 성공 | 배포 완료 및 정상 동작 |
| 🔴 실패 | 배포 실패 또는 롤백 |
| 🟡 대기중 | 배포 예정 |
| 🔵 진행중 | 배포 진행 중 |

---

## 배포 절차

### 배포 실행

```bash
# 프로젝트 루트에서 실행
./deploy.sh
```

스크립트가 자동으로 수행하는 작업:
1. Gradle 빌드
2. Docker 이미지 빌드 (linux/amd64)
3. 이미지 압축 및 EC2 전송
4. EC2에서 컨테이너 재시작
5. Health check 검증

### 롤백

```bash
# EC2 접속 후 실행
ssh -i ~/.ssh/totaload-key.pem ec2-user@13.124.207.109
./scripts/rollback.sh
```

---

## 환경 변수 체크리스트

배포 전 EC2의 `/home/ec2-user/.env` 파일에 다음 변수가 설정되어 있는지 확인:

- [ ] `SPRING_DATASOURCE_URL`
- [ ] `SPRING_DATASOURCE_USERNAME`
- [ ] `SPRING_DATASOURCE_PASSWORD`
- [ ] `JWT_SECRET`
- [ ] `GOOGLE_CLIENT_ID`
- [ ] `GOOGLE_CLIENT_SECRET`
- [ ] `AWS_ACCESS_KEY_ID`
- [ ] `AWS_SECRET_ACCESS_KEY`
- [ ] `AWS_S3_BUCKET`

---

## 인프라 정보

| 리소스 | ID/값 |
|--------|------|
| VPC | vpc-0dc0703020d146418 (10.0.0.0/16) |
| Public Subnet 1 | subnet-00f73baedefe9722d (10.0.1.0/24, ap-northeast-2a) |
| Public Subnet 2 | subnet-0de8609798c5dd410 (10.0.2.0/24, ap-northeast-2c) |
| Internet Gateway | igw-0273e8519bbf27e83 |
| ALB-SG | sg-0f7edf43ae8001adb |
| App-SG | sg-06459a9e862afb992 |
| DB-SG | sg-0da377181f08e7fbe |
| App EC2 | i-0e1175beb258ca3fb (t3.small, 10.0.1.115) |
| DB EC2 | i-0b621ab49dfd56866 (t3.small, 10.0.1.89) |
| App Elastic IP | 13.124.207.109 |
| ALB | totaload-alb-1455478047.ap-northeast-2.elb.amazonaws.com |
| ACM | arn:aws:acm:ap-northeast-2:132205776095:certificate/f551a273-603e-467a-afd9-aa9b001fc4c1 |
| API Domain | api.totaloadcert.com |
| Key Pair | totaload-key (~/.ssh/totaload-key.pem)

---

## 연락처

문제 발생 시 연락:
- 개발팀: -
- 인프라: -
