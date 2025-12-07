#!/bin/bash
set -e

# ===========================================
# Totaload Backend 배포 스크립트
# 사용법: ./deploy.sh
# ===========================================

# 설정
EC2_HOST="13.124.207.109"
EC2_USER="ec2-user"
SSH_KEY="$HOME/.ssh/totaload-key.pem"
APP_NAME="iso-platform"
REMOTE_DIR="/home/ec2-user/app"

echo "=========================================="
echo "  Totaload Backend 배포 시작"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="

# 1. 프로젝트 빌드
echo ""
echo "[1/5] Gradle 빌드 중..."
./gradlew clean build -x test --quiet

# 2. Docker 이미지 빌드 (AMD64)
echo ""
echo "[2/5] Docker 이미지 빌드 중 (linux/amd64)..."
docker buildx build --platform linux/amd64 -t ${APP_NAME}:latest --load .

# 3. Docker 이미지 저장
echo ""
echo "[3/5] Docker 이미지 저장 중..."
docker save ${APP_NAME}:latest | gzip > ${APP_NAME}.tar.gz
echo "이미지 크기: $(du -h ${APP_NAME}.tar.gz | cut -f1)"

# 4. EC2로 전송
echo ""
echo "[4/5] EC2로 이미지 전송 중..."
scp -i ${SSH_KEY} -o StrictHostKeyChecking=no ${APP_NAME}.tar.gz ${EC2_USER}@${EC2_HOST}:${REMOTE_DIR}/

# 5. EC2에서 배포 실행
echo ""
echo "[5/5] EC2에서 배포 실행 중..."
ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_HOST} << 'DEPLOY_SCRIPT'
set -e
cd /home/ec2-user/app

echo "이전 이미지 백업..."
docker tag iso-platform:latest iso-platform:previous 2>/dev/null || true

echo "새 이미지 로드..."
gunzip -c iso-platform.tar.gz | docker load

echo "컨테이너 재시작..."
docker stop iso-platform 2>/dev/null || true
docker rm iso-platform 2>/dev/null || true

docker run -d \
  --name iso-platform \
  --restart unless-stopped \
  -p 8080:8080 \
  --env-file /home/ec2-user/.env \
  -v /home/ec2-user/app/logs:/app/logs \
  iso-platform:latest

echo "Health check 대기 (30초)..."
sleep 30

if curl -sf http://localhost:8080/actuator/health > /dev/null 2>&1; then
    echo "✅ 배포 성공!"
    rm -f iso-platform.tar.gz
else
    echo "❌ Health check 실패 - 롤백 시도..."
    docker stop iso-platform 2>/dev/null || true
    docker rm iso-platform 2>/dev/null || true
    docker run -d \
      --name iso-platform \
      --restart unless-stopped \
      -p 8080:8080 \
      --env-file /home/ec2-user/.env \
      -v /home/ec2-user/app/logs:/app/logs \
      iso-platform:previous
    exit 1
fi
DEPLOY_SCRIPT

# 로컬 정리
rm -f ${APP_NAME}.tar.gz

echo ""
echo "=========================================="
echo "  배포 완료!"
echo "  URL: https://api.totaloadcert.com"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
