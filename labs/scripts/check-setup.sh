#!/usr/bin/env bash
# Check required/optional host dependencies, then bring the lab up and
# verify its safety banner. Combines the manual steps in docs/setup.md
# into one command. Safe to re-run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

missing_required=0
info()  { printf '%s\n' "$1"; }
ok()    { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '  %s⚠%s %s\n' "$YELLOW" "$RESET" "$1"; }
fail()  { printf '  %s✗%s %s\n' "$RED" "$RESET" "$1"; }

check_required() {
  local name="$1" cmd="$2" hint="$3"
  if command -v "$cmd" >/dev/null 2>&1; then
    ok "$name found ($(command -v "$cmd"))"
  else
    fail "$name not found. $hint"
    missing_required=1
  fi
}

check_optional() {
  local name="$1" cmd="$2" hint="$3"
  if command -v "$cmd" >/dev/null 2>&1; then
    ok "$name found ($(command -v "$cmd"))"
  else
    warn "$name not found (optional). $hint"
  fi
}

info "${BOLD}1. Checking required dependencies${RESET}"
check_required "Docker" "docker" \
  "Install Docker Desktop or Docker Engine: https://docs.docker.com/get-docker/"
check_required "Python 3" "python3" \
  "Install Python 3.12+: https://www.python.org/downloads/"
check_required "curl" "curl" \
  "Install curl via your OS package manager."

if command -v docker >/dev/null 2>&1; then
  if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose (v2 plugin) not found. Update Docker Desktop, or install the compose plugin: https://docs.docker.com/compose/install/"
    missing_required=1
  else
    ok "docker compose plugin found"
  fi
  if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon is not running. Start Docker Desktop (or the docker service) and re-run this script."
    missing_required=1
  else
    ok "Docker daemon is running"
  fi
fi

info ""
info "${BOLD}2. Checking optional dependencies${RESET}"
check_optional "jq" "jq" \
  "Nice-to-have for reading JSON responses; scripts fall back to python3 -m json.tool."
check_optional "git" "git" \
  "Only needed if you cloned without git or want to contribute changes."

if [ "$missing_required" -ne 0 ]; then
  info ""
  fail "Missing required dependencies above. Install them, then re-run: ./labs/scripts/check-setup.sh"
  info ""
  info "Cannot run containers at all? See the read-only preview and lightweight"
  info "host path in docs/setup.md."
  exit 1
fi

info ""
info "${BOLD}3. Starting the lab (loopback binds only)${RESET}"
chmod +x "$ROOT/labs/scripts"/*.sh
( cd "$ROOT/labs" && docker compose up -d --build )

info ""
info "${BOLD}4. Waiting for notes-api to become healthy${RESET}"
attempts=0
max_attempts=30
until curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge "$max_attempts" ]; then
    fail "notes-api did not become healthy after ${max_attempts} attempts."
    info "Check logs: docker compose -f labs/compose.yaml logs notes-api"
    exit 1
  fi
  sleep 2
done
ok "notes-api is responding"

info ""
info "${BOLD}5. Verifying the safety boundary${RESET}"
safety_json="$(curl -fsS http://127.0.0.1:8080/.well-known/lab)"
health_json="$(curl -fsS http://127.0.0.1:8080/health)"

case "$safety_json" in
  *AUTHORIZED*) ok "Safety banner present: $safety_json" ;;
  *) fail "Safety banner missing or unexpected: $safety_json"; exit 1 ;;
esac

case "$health_json" in
  *'"lab_mode":true'*|*'"lab_mode": true'*) ok "lab_mode is true (teaching mode)" ;;
  *) warn "lab_mode is not true — health response was: $health_json" ;;
esac

info ""
info "${BOLD}Done.${RESET} notes-api: http://127.0.0.1:8080  soc-lite: http://127.0.0.1:8090  agentic-soc: http://127.0.0.1:8091"
info "Lab users: alice / alice-lab-password, bob / bob-lab-password, admin / admin-lab-password"
info "Next: read docs/ethics.md, then start Module 1."
info ""
info "Optional CLI toolbox (trivy, tshark, kubectl, jq, sqlite3), no local"
info "install needed: docker compose -f labs/compose.yaml --profile toolbox run --rm toolbox"
