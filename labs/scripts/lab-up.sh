#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/labs"
echo "Starting isolated lab (loopback binds only)..."
docker compose up -d --build
echo
echo "notes-api:    http://127.0.0.1:8080/health"
echo "soc-lite:     http://127.0.0.1:8090/health"
echo "agentic-soc:  http://127.0.0.1:8091/health"
echo
echo "Lab users: alice / alice-lab-password, bob / bob-lab-password, admin / admin-lab-password"
echo "AUTHORIZED LAB USE ONLY. See docs/ethics.md."
