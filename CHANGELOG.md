# Changelog

Notable changes to the course content and labs. Newest first.

## Unreleased

- Added [Module 12b, the agent security workshop](docs/modules/12b-agent-security-workshop.md) (optional): a deliberately gullible scripted planner, a tool gateway with `unsafe` and `hardened` modes, a mock MCP registry, persistent memory with provenance, `POST /agent/run`, traces, replay, and a kill switch.
- Added signed, single-use, argument-bound approvals (`approval.mode: bound`), per-run scoped identity, argument validation, protected actors, and a cap on approval requests.
- Added the agent eval harness (`labs/agentic-soc/evals/run_evals.py`): 12 labeled alerts and 29 injection payloads scored across four defense layers, enforced in CI.
- Added `replay.py` and `export_agent_run.py`, an [agent threat model](docs/agent-threat-model.md), and [Securing your coding agent](docs/appendix-coding-agent-security.md).
- Fixed an unencoded query parameter in the agent's `search_logs` backend.
- Review fixes: approved action arguments (for example `target_actor`) now reach soc-lite and its audit row; the entire persisted trace (arguments and memory context, not only results) is redacted; replay reuses the recorded text filter, compares arguments, outcome and side effects, and reports configuration differences separately from behavior differences; actions and approvals must name an existing alert.

- Module 4b is classified as optional and outside the 100-hour budget; the home page, learning paths, and the page itself say so.
- Semgrep is pinned in `requirements-workshop.txt`; CI and the docs use it.
- Fixed in review: NUL byte crash in `/files`, canary overwritten across restarts, secure-mode export revealing which note ids exist, logged file names unbounded.

- Added [Module 4b, the secure coding workshop](docs/modules/04b-secure-coding-workshop.md): five vulnerable routes (UNION SQLi, stored XSS, path traversal, mass assignment, fail-open authorization with verbose errors), exercise tests that fail until the code is fixed, a Semgrep triage exercise, and a pull-request review drill.
- Added notes-api routes `/notes/{id}/page`, `/files`, `PATCH /users/me`, `/notes/{id}/export`, each vulnerable only under `LAB_MODE`.
- Added detections DET-006–DET-009 and four playbooks; tagged every detection with OWASP IDs.
- Added attack-sim scenarios `injection_union`, `xss`, `traversal`, `mass_assign`, `fail_open`, `error_leak`.

- Added the [OWASP coverage matrix](docs/owasp-coverage.md) and verified the cited OWASP IDs against their sources.
- Added `last_reviewed` to module pages, enforced by tests.
- Added tests that check internal doc links and that documented make targets, repo paths, and attack-sim scenarios exist.
- Pinned lab base images by digest; added Dependabot and CodeQL.
- Added [ROADMAP.md](ROADMAP.md).
