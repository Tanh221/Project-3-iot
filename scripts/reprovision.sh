#!/usr/bin/env bash
set -euo pipefail
cd ~/project3
: > .env
for d in a b; do
  tok=$(docker compose exec -T ca python provision.py "device-$d" | awk '/^token/{print $3}')
  echo "DEVICE_${d^^}_TOKEN=$tok" >> .env
done
# Xóa cert cũ của thiết bị để chúng enroll lại từ đầu
docker compose rm -sf device-a device-b
docker volume rm -f project3_device-a-data project3_device-b-data
docker compose up -d --build device-a device-b
echo "Done: .env updated, devices re-enrolled"