#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$ROOT/labs/cases/evidence-$STAMP"
mkdir -p "$DEST"
docker exec lab-notes-api sh -c 'cat /logs/notes-api.jsonl' > "$DEST/notes-api.jsonl" || true
curl -s http://127.0.0.1:8090/alerts > "$DEST/alerts.json" || true
curl -s http://127.0.0.1:8090/cases > "$DEST/cases.json" || true
echo "Preserved evidence under $DEST"
echo "Do not modify these files. Copy, don't edit, if you continue investigating."
