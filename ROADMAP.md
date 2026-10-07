# Roadmap: gap analysis and closure plan

Captured from a repo review on 2026-10-07. The gaps were derived from the
repo structure, module outlines, labs, tests and keyword coverage, not from a
full read of every module. Task 0.1 confirms each gap before later phases act
on it.

Sizing: S ≈ 1 day, M ≈ 2–4 days, L ≈ 1–2 weeks.

---

## Part A: Gaps identified

### A1. Lab depth is thinner than the curriculum
- notes-api has 10 endpoints, so the lab can't exercise most of Module 4's
  OWASP list.
- Only 5 detections exist (DET-001–005). `labs/soc-lite/rules.yaml` has no
  `id: DET` entries. Modules 5, 6, 16 and 17 have no telemetry of their own.
- Kubernetes is optional and manual: no manifests, NetworkPolicy, RBAC or Pod
  Security examples in `labs/`.
- Supply-chain topics (SBOM, SLSA, signing) are mentioned with no lab.
- Module 2 relies on tshark/tcpdump but ships no sample pcaps or fixtures.

### A2. Topics touched only lightly
- Secrets management and scanning (zero mentions of secret scanning).
- Dependency/SCA, SAST and IaC scanning in CI: mentioned, not practiced.
- Runtime/endpoint detection (Falco, eBPF, auditd, Sysmon).
- Threat intelligence and hunting (3 mentions each, no workflow).
- Digital forensics beyond log preservation.
- Vulnerability-management lifecycle (CVSS, EPSS, KEV, SLAs, patching).
- Federation and modern identity (OAuth/OIDC, passkeys, WebAuthn, SCIM).
- Data security and privacy (classification, encryption at rest, GDPR).
- Backup, recovery and ransomware resilience: mentioned, no exercise.
- Disclosure and bug-bounty process.
- Security culture and GRC (risk registers, metrics, communicating risk).
- Mobile, desktop and browser security: out of scope but not stated as such.

### A3. App-sec gaps
- Only one injection variant (string-concatenated `LIKE` in sqlite). Missing:
  UNION/boolean/time-based blind SQLi, second-order injection, ORM misuse,
  NoSQL injection, OS command injection, template injection, header/log
  (CRLF) injection, and failed defenses (blocklist/escaping bypasses).
- No XSS, CSRF, deserialization, file upload or path-traversal code. Module 4
  says these are "still in your mental model".
- No mass-assignment or excessive-data-exposure route.
- No business-logic flaws (race conditions, workflow bypass, replay).
- Little on app-layer authentication attacks (password reset, JWT pitfalls,
  session fixation).
- No GraphQL, WebSocket or SSO flows.
- Secure mode is a toggle: learners observe the fix but never write it.
- No security regression tests (for example, "this payload must be literal").
- No SAST/DAST practice (Semgrep, CodeQL, ZAP, Burp).
- No code-level "review this PR for security" drill.
- Detection coverage is narrow: no WAF/RASP comparison.

### A4. OWASP gaps
OWASP is used as vocabulary, not as a working framework.
- Top 10:2025 items with no lab or only a mention: A02 (headers exercise
  only), A03, A06, A07 (brute force only), A08, A10 (new in 2025, no coverage).
- No course-to-OWASP coverage matrix. Detections and playbooks carry ATT&CK
  IDs but no A0x / API0x tags.
- ASVS is only linked (3 files), never used as a rubric.
- Cheat Sheet Series linked but not taught.
- Missing entirely: Proactive Controls, WSTG, SAMM/BSIMM, ZAP,
  Dependency-Check, CycloneDX, Threat Dragon, Juice Shop/WebGoat pointers,
  Kubernetes/Docker/CI-CD Top 10s, Non-Human Identities Top 10.
- API3, API4, API9 and API10 are barely covered.
- Cited versions and IDs (2025 / 2023 / 2026) have not been verified and will
  drift. No review process.

### A5. Agentic gaps
- Default planner is deterministic, so learners never see a model choose
  tools. Goal hijack (ASI01), tool misuse (ASI02) and excessive agency can't
  be demonstrated.
- Injection defense is a regex. No exercise bypasses it.
- Approval is a string (`approval=APPROVE`): no approver authentication, no
  binding to action and arguments, no expiry or replay protection.
- No tool-argument validation (for example, `block_actor` on the admin).
- Named but not exercised: memory poisoning (ASI06), inter-agent comms
  (ASI07), cascading failures (ASI08), rogue agents (ASI10), agent supply
  chain/MCP (ASI04), code execution/sandboxing (ASI05), identity and
  privilege abuse (ASI03), RAG poisoning, improper output handling, system
  prompt leakage.
- No evaluation harness or adversarial corpus (only 1 injection test).
- No tracing, token/cost accounting or run replay. The `agent-run` and
  `replay-fixture` templates have no tool that produces them.
- No guardrails comparison (filters vs structured output vs dual-LLM).
- No cost/abuse controls (budgets, timeouts, denial-of-wallet).
- No exercise on approval fatigue.
- Agent security is split across Modules 12, 14, 15 with no single threat
  model page.
- Coding-agent security (repo/issue injection, MCP trust, secrets in
  context, permission modes, sandboxing) is not covered.
- No starter code for "build a safe agent" (follow-up #8).

### A6. Pedagogy and assessment
- No answer key or model solutions.
- No automated lab verification (`make verify-module N`).
- About 35 tests, all on lab apps. Nothing checks doc commands, lab steps or
  links.
- No capstone auto-grader.
- `exercises.md` is 88 lines, 10 follow-up ideas have no starter code,
  `capstone/work/` holds only a README.
- No difficulty tracks or placement self-assessment.

### A7. Project hygiene
- `site/` build output is in the working tree (check it is gitignored).
- No CONTRIBUTING.md, issue templates or CHANGELOG.
- No Dependabot, CodeQL or pinned image digests.
- No per-module "last reviewed" tracking.
- English only; mermaid diagrams lack alt text.

---

## Part B: Plan

### Phase 0: Foundations (do first)

| # | Task | Size | Closes |
|---|---|---|---|
| 0.1 | OWASP coverage matrix page: Top 10:2025, API Top 10, LLM and Agentic 2026, ASVS chapters × module/lab. Mark every uncovered row. | S | A4, planning baseline |
| 0.2 | Verify every cited ID and version (Top 10:2025, API 2023, LLM01/03, ASI01–10, ATT&CK) against sources. Fix errors. | S | A4 currency |
| 0.3 | Repo hygiene: confirm `site/` ignored; add CONTRIBUTING, issue/PR templates, CHANGELOG, Dependabot, CodeQL, pinned image digests. | S | A7 |
| 0.4 | "Last reviewed" front-matter field per module, enforced by `test_docs_front_matter.py`. | S | A4, A7 |
| 0.5 | Test scaffolding: markdown link checker and doc-command smoke test (fenced `bash` blocks tagged `smoke`) in CI. | M | A6 |

Exit: matrix published, IDs verified, CI has the new checks.

**Status: done 2026-10-07.** Matrix at `docs/owasp-coverage.md`; IDs verified (all matched; A10:2025 and API9:2023 confirmed uncovered); `last_reviewed` seeded from each module's last commit date (not a content re-read); link and doc-command checks in `tests/test_docs_links.py`. Digest pins are unbuilt (no Docker daemon available when pinned).

### Phase 1: App-sec workshop (highest value)

New Module 4b "Secure coding workshop", with lab changes behind `LAB_MODE`.
Keep `assert_local`, loopback-only binding and benign payloads.

| # | Task | Size |
|---|---|---|
| 1.1 | Vulnerable routes with secure-mode fixes: UNION/blind SQLi (extends `/search`), stored XSS comment field, file upload with path traversal, mass-assignable `PATCH /users/me`, verbose-error/fail-open route (A10), weak-secret JWT variant. | L |
| 1.2 | Paired failing pytest per route. Learner patches until it passes. Reference fix is the secure-mode branch. | M |
| 1.3 | Semgrep (or CodeQL) rules plus triage exercise on the f-string SQLi, including one false positive and one false negative. | M |
| 1.4 | `attack-sim` scenarios per new route, plus 4 detections and playbooks tagged with ATT&CK and OWASP IDs. | M |
| 1.5 | Business-logic/race exercise, CORS/misconfiguration (A02), session/reset flow (A07). | M |
| 1.6 | "Review this PR" security-design drill (A06). | S |
| 1.7 | OWASP toolbox section: ZAP, Cheat Sheet mapping table, Proactive Controls, WSTG as Module 9 test-case source, Juice Shop/WebGoat next steps. | S |

Exit: every Top 10:2025 row has a lab or an explicit out-of-scope note, and
`make test` fails on a regressed fix.

**Status: done 2026-10-07, except 1.5 and the JWT variant of 1.1.**
- 1.1: UNION SQLi (existing `/search`), stored XSS (`/notes/{id}/page`), path traversal (`/files`), mass assignment (`PATCH /users/me`), fail-open and verbose errors (`/notes/{id}/export`). **Not done:** the weak-secret JWT variant.
- 1.2: `labs/workshop/test_fixes.py`; `tests/test_workshop.py` proves exploit tests fail on the vulnerable app and everything passes on the reference fix.
- 1.3: Semgrep rules and triage sample in `labs/workshop/semgrep/`; CI job `workshop-semgrep`.
- 1.4: DET-006–009, four playbooks, six attack-sim scenarios, OWASP tags on all detections.
- 1.5: **Not done** (race conditions, CORS misconfiguration, password-reset flaw).
- 1.6, 1.7: in Module 4b (`docs/modules/04b-secure-coding-workshop.md`).
- Verified on the real compose stack (Colima, digest-pinned base images, 2026-10-07): all four images build; `simulate.py --scenario all` in `LAB_MODE=true` raises DET-001–009 and the agent maps the new rules; the safety rail blocks `/etc/passwd` and an escape write inside the container. In `LAB_MODE=false` on a fresh volume every scenario is blocked, and the attempts still raise DET-001/005/006/007/008 (not DET-009, since nothing failed open).
- Not verified: the new CI jobs (CodeQL, `workshop-semgrep`) on GitHub; learner timing for Module 4b.

### Phase 2: Agentic depth

| # | Task | Size |
|---|---|---|
| 2.1 | Eval and adversarial harness: labeled alert set, scoring script (precision/recall, groundedness, action correctness), injection corpus (direct, indirect, encoded, multi-field, tool-result) with a CI gate. Delivers follow-up #10. | M |
| 2.2 | Harden approval: bind to action and arguments, expiry, replay protection, authenticated approver, argument validation. | M |
| 2.3 | LLM-driven "unsafe mode" in agentic-soc (stub or local Ollama) with weaker defenses, then a hardened mode. | L |
| 2.4 | Tracing and replay: record prompt, tool call and result per run, with token/cost counters. Generate `agent-run` and `replay-fixture` artifacts from real runs. | M |
| 2.5 | Small labs: memory poisoning, tool-description poisoning (mock MCP server), per-run scoped identity/confused deputy, budget and kill switch (ASI08/10). | L |
| 2.6 | Agent threat model page: ASI01–10 × control × exercising lab. | S |
| 2.7 | Appendix or module "Securing your coding agent". | M |
| 2.8 | Guardrails comparison: prompt filters vs structured output vs dual-LLM. | S |

Exit: every ASI item maps to a runnable lab or a stated non-goal, and the
injection corpus gates CI.

**Status: done 2026-10-07**, with these deviations from the plan:
- 2.3: the "unsafe mode" is a deterministic scripted planner (`planner.py`), not a local model. No real-LLM planner was built; the docs say so. Nothing here measures a real model's rate of being fooled.
- 2.1: the corpus has 29 payloads (26 attacks, 3 controls) and 12 labeled alerts. CI gates on the hardened gateway letting nothing through and on the corpus still hijacking the unsafe layer.
- 2.5: memory poisoning, tool-description poisoning (mock MCP, hash pinning), scoped identity / confused deputy, and budget + kill switch are built. Not built: inter-agent communication (ASI07), a code-execution tool (ASI05, a stated non-goal).
- 2.2: soc-lite still trusts the agent; it does not verify approval tokens itself.
- Verified natively over real HTTP (pinned deps, Python 3.11): a payload sent as a login *username* reaches a real soc-lite alert and the agent; unsafe blocks `admin` as `agent-service`, hardened does not. Then verified on the real compose stack (Colima, 2026-10-07): the agentic-soc image builds with every new file; `AGENT_MODE` / `AGENT_APPROVAL_MODE` / `MCP_REGISTRY_PATH` reach the container; Module 12b exercises 1, 2, 5, 6 and the kill switch and `export_agent_run.py` all behave as documented. Not exercised live: exercise 7's playbook-loop edit and the replay CLI against a container trace.

### Phase 3: Supply chain, platform and detection breadth

| # | Task | Size |
|---|---|---|
| 3.1 | CI/supply-chain lab: secret scanning, SCA, SBOM (CycloneDX), image scan, cosign signing. Covers A03/A08, Docker and CI/CD Top 10s, follow-up #5. | L |
| 3.2 | Kubernetes manifests in `labs/` (Deployment, NetworkPolicy, RBAC, Pod Security), kind script, make target. | M |
| 3.3 | Runtime telemetry exercise (auditd/Falco in toolbox, or documented stand-in). | M |
| 3.4 | Expand detections from 5 to about 12 covering Modules 5, 6, 16, 17. Resolve the empty `soc-lite/rules.yaml` IDs. | M |
| 3.5 | Sample pcap and fixtures for Module 2. | S |
| 3.6 | Threat-hunting and vulnerability-management sections (fold into Modules 7 and 11). | M |
| 3.7 | Federation/OIDC/passkey sidebar in Module 3; NHI note for agent and service identity. | S |
| 3.8 | Short sections: backup/ransomware recovery, data classification and privacy, disclosure and bug bounty. | M |
| 3.9 | Explicit out-of-scope entry for mobile, desktop and browser security. | S |

Exit: no module lab relies only on DET-001/003, and the K8s and supply-chain
labs run from `make`.

### Phase 4: Assessment, pedagogy and verification

| # | Task | Size |
|---|---|---|
| 4.1 | Answer keys (model solutions) in a separate folder. | L |
| 4.2 | `make verify-module N` to check expected observations. | M |
| 4.3 | Scanner-capstone auto-grader, output as ASVS L1 IDs. | M |
| 4.4 | ASVS L1 as the rubric for the Module 13 review and scanner capstone. | S |
| 4.5 | Expand `exercises.md` (time-boxed, tiered). Starter code for follow-ups #1, #2, #6, #8. Populate `capstone/work/`. | M |
| 4.6 | Placement self-assessment and difficulty tracks in `learning-paths.md`. | S |
| 4.7 | Diagram alt text and accessibility pass. | S |

### Phase 5: Maintenance loop
- Quarterly scheduled workflow that opens an issue listing modules past their
  "last reviewed" date and OWASP/ATT&CK versions with new releases.
- Update the coverage matrix whenever a module or lab changes (PR checklist).

---

## Dependencies and ordering
- 0.1 and 0.2 come before everything else; they define "covered".
- 1.1 → 1.2 → 1.4: routes, then tests, then detections and attack-sim.
- 2.2 → 2.3: harden approval before building the unsafe mode.
- 2.1 and 2.4 are independent of 2.3 and can run parallel to Phase 1.
- 3.1 and 3.2 are independent and can go to a separate contributor.
- 4.1 and 4.2 trail the lab changes.

## Risks
- Scope creep: about 45 tasks on a course that is already about 100 hours.
  First candidates to demote to further reading: 3.8, 3.3, 2.8.
- Safety: more vulnerable routes widen the lab's attack surface. Keep them
  loopback-only and `LAB_MODE`-gated, and test that secure mode blocks each.
- Maintenance burden of 4.1 and 4.2 unless they are CI-tested.
- Gaps are unverified against full module text (see Task 0.1).

## Minimum cut (about 4–5 weeks)
0.1, 0.2, 1.1–1.4, 2.1, 2.2, 3.1: app-sec depth, OWASP mapping, agent evals
and approval, supply chain.
