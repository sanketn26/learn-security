#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/labs"
docker compose down
echo "Lab containers stopped. Volumes retained. Use lab-reset.sh to wipe state."
