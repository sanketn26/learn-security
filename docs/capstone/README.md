# Capstone — Build and operate a small defensive security platform

You will take the course lab from “compose up” to an operated mini-platform:
modeled, attacked only in-lab, detected, investigated, purple-validated, and
assisted by a policy-bound agent.

**AUTHORIZED LAB USE ONLY.** Scope is this repository’s compose stack and
loopback ports. No real cloud accounts, no employer systems, no malware.

## What you must include

1. Containerized web API with authentication and an intentional vulnerability
   (provided `notes-api` with `LAB_MODE=true`, or your port).
2. Threat model and trust-boundary diagram.
3. Secure logging and audit events (JSONL + soc-lite).
4. Simulated attack **only** in the isolated lab (`attack-sim`).
5. ATT&CK mapping of simulated behavior.
6. At least five detections (`labs/detections/rules.yaml`).
7. Alert-triage and case-management workflow (soc-lite cases).
8. Incident timeline.
9. Containment and recovery steps (simulated + `LAB_MODE=false` redeploy).
10. Purple-team validation report.
11. Agentic SOC assistant: summarize, retrieve context, propose ATT&CK,
    recommend next steps, **explicit human approval** for simulated actions.
12. Final architecture document and security review.

## Milestones

| Milestone | When | Done when |
| --- | --- | --- |
| M0 Environment | Day 1 | `make lab-up`; health endpoints 200; ethics read |
| M1 Model | Day 1–2 | Threat model + diagram in `docs/capstone/artifacts/` |
| M2 Telemetry | Day 2 | JSON events for login, AuthZ, fetch, search |
| M3 Emulate | Day 3 | `simulate.py --scenario all` against loopback only |
| M4 Detect | Day 3–4 | Five alerts with technique tags |
| M5 Investigate | Day 4–5 | Case + timeline + evidence dir from `preserve-logs.sh` |
| M6 Respond | Day 5 | Simulated actions with APPROVE; recover with LAB_MODE=false |
| M7 Purple | Day 6 | Re-test; report TP/FN; one improved rule or control |
| M8 Agent | Day 6 | `/investigate` + denied then approved action |
| M9 Review | Day 7 | Architecture doc + residual risk |

12-week cohort: use week 12. Intensive: last 3 days.

## Acceptance criteria

- [ ] Lab binds only to 127.0.0.1; `simulate.py` still refuses non-local.
- [ ] Threat model names assets, boundaries, residual risk.
- [ ] Five detections fire on the provided sim (or documented FN with a fix).
- [ ] Mappings include tactic, technique id, confidence, limitation.
- [ ] Case exists with timeline entries.
- [ ] Evidence snapshot is unmodified after preservation.
- [ ] At least one control change (`LAB_MODE=false` or a code patch) is
      re-tested.
- [ ] Agent cannot simulate an action without `approval=APPROVE`.
- [ ] Architecture review lists at least five findings.
- [ ] No real secrets, no extra-scope testing.

## Rubric (100 points)

| Criterion | Points |  Full marks |
| --- | --- | --- |
| Threat model clarity | 10 | Assets, STRIDE-or-equivalent, residual risk |
| Telemetry quality | 10 | UTC, event names, actor, object, trace_id |
| Detection quality | 15 | Five rules, not all IOC-only, documented FPs |
| ATT&CK discipline | 10 | Confidence and “why wrong”; no matrix theatre |
| Investigation | 15 | Timeline, hypotheses, impact, RCA |
| Response & recovery | 10 | Approval gate; actual harden; retest |
| Purple validation | 10 | Hypothesis, evidence, delta |
| Agent safety | 10 | Policy, untrusted evidence, no unbounded tools |
| Architecture writing | 10 | Trade-offs, what not to automate |

Score ≥ 80 and all acceptance checkboxes to pass.

## Expected artifacts

Create `docs/capstone/artifacts/` (gitignore it if it contains logs; keep
shareable Markdown):

- `threat-model.md` — diagram + table
- `attack-coverage.md` — five-plus-gap matrix
- `incident-report.md` — timeline, RCA, comms (lab)
- `purple-report.md`
- `architecture-review.md`
- `agent-run.json` — saved `/investigate` output (redact if you used a hosted LLM)
- Optional: evidence tarball **not committed** if it contains dummy secrets

Templates live beside this README.

## Stretch goals

- Replay tests: store JSONL fixture, assert rule IDs in CI.
- Add DET-006 for `ssrf_blocked` attempts.
- Non-root USER in notes-api Dockerfile.
- Rate-limit `/login`.
- Optional kind deploy with a NetworkPolicy denying metadata.
- Groundedness checks: fail `/investigate` if mapping not in catalog.
- OpenTelemetry traces exported to a file (not a full vendor APM).

## Failure scenarios to test

| Scenario | Expect |
| --- | --- |
| Alice reads `/notes/2` in LAB_MODE | DET-002; data in body |
| Same after LAB_MODE=false | 404; no DET-002 success event |
| Six bad passwords | DET-001 |
| Fetch mock-imds in LAB_MODE | dummy JSON; DET-003 |
| Fetch `http://example.com` | safety rail 400 |
| `simulate.py --base http://8.8.8.8` | script exits |
| Agent action `approval=nope` | 403 |
| Agent action not in allowlist | 403 |
| Instruction-like text in evidence | stripped or ignored |
| One required field absent from an event | rejected/quarantined or explicitly marked partial; no silent match |
| Malformed JSON log line | pipeline continues; parse error becomes observable |
| Producer clock skew of five minutes | timeline flags skew; ordering does not silently claim certainty |
| Duplicate event delivery | idempotent ingest or documented duplicate suppression |
| Collector unavailable, then restored | buffered/lost interval measured; recovery documented |
| Stolen dummy session token replay | actor appears valid; behavior/object context drives detection |
| Suspicious but legitimate bulk API use | false positive recorded and rule tuned without hiding true abuse |
| Synthetic dependency alert | owner and reachability are enriched before severity decision |
| Container starts as root or privileged | posture check fails; workload does not pass production review |
| Threat-intel/enrichment source unavailable | investigation continues with lower confidence; no invented result |
| Misleading synthetic evidence contradicts primary log | conflict is surfaced; evidence trust is stated |
| Agent recommends an unsafe action | policy denies it even if a human types ambiguous approval |
| Allowed agent tool returns an error | action is not reported successful; tool error is audited |
| Action verification fails | workflow stops and proposes/executes the documented simulated rollback |
| Partial telemetry from one source only | scope and confidence remain explicitly limited |

## Security and ethical constraints

- Scope: local lab only.
- Dummy credentials never used against a real IdP or cloud.
- No persistence, no ransomware simulation, no data destruction labs.
- Hosted LLMs: lab data only; assume provider logging.
- Publish reports without raw dummy secrets if the repo is public.
- Cleanup: `make lab-reset` at the end.
