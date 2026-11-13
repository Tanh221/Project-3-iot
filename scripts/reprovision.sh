#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: > .env
for d in a b; do
  tok=$(docker compose exec -T ca python provision.py "device-$d" | awk '/^token/{print $3}')
  echo "DEVICE_${d^^}_TOKEN=$tok" >> .env
done
docker compose up -d --force-recreate device-a device-b
echo "Done: .env updated, devices recreated"