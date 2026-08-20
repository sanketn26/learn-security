# Hands-on lab environment

Isolated Docker Compose lab for this course. All published ports bind to
`127.0.0.1`. The application network `labnet` is `internal: true` (no internet
egress). Simulated attacks must target loopback; `attack-sim/simulate.py`
exits if they do not.

**AUTHORIZED LAB USE ONLY.** Read [ethics.md](ethics.md).

## Architecture

```
 learner workstation
        |
        |  127.0.0.1:8080 / 8090 / 8091
        v
 +------+------------------+
 |      edgenet            |
 |                         |
 |  notes-api  soc-lite  agentic-soc
 |      |          |          |
 +------+----------+----------+
        |          |          |
        v          v          v
 +----------------------------------+
 | labnet (internal, 172.30.0.0/24) |
 |   mock-imds (synthetic metadata) |
 +----------------------------------+
        |
   volumes: logs, sqlite, cases
```

## Resource requirements

| Profile | RAM | Disk | Required |
| --- | --- | --- | --- |
| Default compose stack | ~1.0–1.5 GiB | ~2 GiB images | Yes for most labs |
| Host-only (no Docker), Python venv | ~300 MiB | ~200 MiB | Alternative |
| Optional Grafana/Loki (not in default compose) | +512 MiB | +1 GiB | No |
| Optional kind/k3d (module 5) | +2 GiB | +2 GiB | No |
| Optional local LLM (Ollama) | +4 GiB | model size | No |

## Quick start

```bash
chmod +x labs/scripts/*.sh
./labs/scripts/lab-up.sh
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/.well-known/lab
```

Lab users (dummy passwords, local only):

| User | Password | Role |
| --- | --- | --- |
| alice | alice-lab-password | user |
| bob | bob-lab-password | user |
| admin | admin-lab-password | admin |

```bash
# Simulated activity (local only)
python3 labs/attack-sim/simulate.py --scenario all

# Build alerts
curl -s -X POST http://127.0.0.1:8090/ingest
curl -s http://127.0.0.1:8090/alerts | python3 -m json.tool

# Agentic assistant (no response action without APPROVE)
ALERT_ID=$(curl -s http://127.0.0.1:8090/alerts | python3 -c "import sys,json; print(json.load(sys.stdin)['alerts'][0]['id'])")
curl -s http://127.0.0.1:8091/investigate -H 'Content-Type: application/json' \
  -d "{\"alert_id\":\"$ALERT_ID\"}" | python3 -m json.tool
```

## Tooling map

| Tool | Role | Lightweight alternative | Required |
| --- | --- | --- | --- |
| Docker / Compose | Isolation and reproducible services | Podman Compose, or run Python apps in venvs | Required (or venv alternative) |
| notes-api | Intentionally dual-mode web API | — | Required |
| mock-imds | Synthetic cloud metadata | Static JSON file | Required for SSRF lab |
| soc-lite | Log ingest, detections, cases | `jq` + files | Required from module 7 |
| agentic-soc | Policy-bound assistant | Manual playbook reading | Required from module 12 |
| attack-sim | Authorized local traffic generator | curl | Required from module 9 |
| curl, jq, python3 | Investigation | — | Required |
| tcpdump / tshark | Packet capture on docker bridge | Compose logs only | Optional |
| Trivy / Grype | Image and FS scanning | `pip-audit` | Optional |
| kind or k3d | Local Kubernetes | Skip module 5 k8s lab | Optional |
| Ollama or hosted LLM | Natural-language summaries | Deterministic planner (default) | Optional |

## Modes

- `LAB_MODE=true` (default): application-level vulnerabilities enabled for teaching.
- `LAB_MODE=false`: owner checks, parameterized search, metadata fetch blocked, bcrypt passwords, JWT expiry.

The **lab safety rail** remains on in both modes: `/fetch` cannot target hosts
outside the compose allowlist (`mock-imds`, `metadata.internal`, and other
compose service names). The notes-api container is also attached to `edgenet`
so it can publish loopback ports; do not treat Docker attachment as egress
proof. The allowlist is the application rail.

**No-Docker / venv alternative:** run `mock-imds` on `PORT=18080`, set
`LAB_FETCH_EXTRA_HOSTS=127.0.0.1` only on your workstation, and still bind
APIs to `127.0.0.1`. Never point `LAB_FETCH_EXTRA_HOSTS` at a non-lab host.

## Cleanup

```bash
./labs/scripts/lab-down.sh     # stop
./labs/scripts/lab-reset.sh    # stop and wipe volumes
```
