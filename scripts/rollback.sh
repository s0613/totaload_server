#!/bin/bash
set -e

echo "=== Rollback Phase ==="
echo "Timestamp: $(date)"

# Check if previous image exists
if ! docker images iso-platform:previous -q | grep -q .; then
    echo "ERROR: No previous image found for rollback"
    exit 1
fi

# Stop current container
echo "Stopping current container..."
docker stop iso-platform 2>/dev/null || true
docker rm iso-platform 2>/dev/null || true

# Run previous version
echo "Starting previous version..."
docker run -d \
  --name iso-platform \
  --restart unless-stopped \
  -p 8080:8080 \
  --env-file /home/ec2-user/.env \
  -v /home/ec2-user/app/logs:/app/logs \
  iso-platform:previous

# Wait and validate
sleep 10

if curl -sf http://localhost:8080/actuator/health > /dev/null 2>&1; then
    echo "Rollback successful!"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Rollback successful" >> /home/ec2-user/app/deployment.log
    exit 0
else
    echo "Rollback failed - health check not passing"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Rollback failed" >> /home/ec2-user/app/deployment.log
    exit 1
fi
