#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/labs"
echo "Stopping lab and deleting volumes (logs, sqlite, cases)..."
docker compose down -v
rm -rf data logs cases
echo "Lab state wiped."
