---
description: "Which OWASP Top 10:2025, API Top 10:2023, LLM Top 10 2026, and Agentic Top 10 2026 items each module and lab exercises, with the gaps marked."
last_reviewed: 2026-10-07
---

# OWASP coverage matrix

OWASP lists are used here as a **shared vocabulary**. This page shows where
each item is actually exercised in a lab and where it is only named, so
learners and maintainers can see the holes.

IDs and names below were checked against the OWASP sources on 2026-10-07
(see [Verification](#verification)).

**Legend**

| Mark | Meaning |
| --- | --- |
| **Lab** | A runnable lab step in this repo exercises it. |
| **Concept** | Explained in a module, with no runnable step. |
| **Mention** | Named in passing. |
| **Gap** | Not covered. Planned in [ROADMAP.md](https://github.com/sanketn26/learn-security/blob/main/ROADMAP.md). |

## OWASP Top 10:2025

| ID | Name | Coverage | Where |
| --- | --- | --- | --- |
| A01:2025 | Broken Access Control | **Lab** | [Module 3](modules/03-identity-and-access.md) admin route; [Module 4](modules/04-application-and-api.md) BOLA and SSRF (SSRF was folded into A01 in 2025); [Module 4b](modules/04b-secure-coding-workshop.md) path traversal |
| A02:2025 | Security Misconfiguration | **Lab** (partial) | Module 4 response-headers exercise; [Module 5](modules/05-cloud-containers-k8s.md) container-posture lab. No debug-endpoint, CORS, or verbose-error exercise. |
| A03:2025 | Software Supply Chain Failures | **Concept** | Module 4 dependency paragraph; [Module 15](modules/15-ml-ai-security.md) ML-pipeline analogy; mentioned in Modules 5 and [14](modules/14-future.md). No lab. |
| A04:2025 | Cryptographic Failures | **Lab** | [Module 6](modules/06-cryptography.md) passwords and signatures |
| A05:2025 | Injection | **Lab** (partial) | Module 4 `/search` concatenated SQL; [Module 4b](modules/04b-secure-coding-workshop.md) UNION-based SQLi and stored XSS; prompt injection in [Module 12](modules/12-agentic-soc.md). No command, NoSQL, or template injection. |
| A06:2025 | Insecure Design | **Concept** | Module 4 table; the Module 4b pull-request review drill. The [Module 13](modules/13-security-architecture.md) review is a design exercise but does not name or teach A06. |
| A07:2025 | Authentication Failures | **Lab** (partial) | Module 3 login/JWT review; brute-force scenario. Sessions and MFA are concepts in Module 3 but have no exercise; no reset-flow coverage. |
| A08:2025 | Software or Data Integrity Failures | **Concept** | Module 4 deserialization paragraph. No lab; CI/CD integrity untouched. |
| A09:2025 | Security Logging and Alerting Failures | **Lab** | [Module 7](modules/07-monitoring-and-logs.md), plus every detection lab |
| A10:2025 | Mishandling of Exceptional Conditions | **Lab** | Module 4b exercise 5: an authorization check that fails open, and stack traces returned to the client |

## OWASP API Security Top 10:2023

| ID | Name | Coverage | Where |
| --- | --- | --- | --- |
| API1:2023 | Broken Object Level Authorization | **Lab** | Module 4 IDOR scenario |
| API2:2023 | Broken Authentication | **Lab** (partial) | Module 3; brute-force scenario |
| API3:2023 | Broken Object Property Level Authorization | **Lab** | Module 4b exercise 4: mass assignment on `PATCH /users/me` |
| API4:2023 | Unrestricted Resource Consumption | **Lab** | [Module 16](modules/16-availability-and-dos.md) unthrottled login |
| API5:2023 | Broken Function Level Authorization | **Lab** | `/admin/users` in Modules 3 and 4 |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | **Concept** | Module 4 paragraph; Module 16. No lab. |
| API7:2023 | Server Side Request Forgery | **Lab** | Module 4 and [Module 5](modules/05-cloud-containers-k8s.md) `/fetch` to mock-imds |
| API8:2023 | Security Misconfiguration | **Lab** (partial) | See A02 |
| API9:2023 | Improper Inventory Management | **Gap** | Not covered. |
| API10:2023 | Unsafe Consumption of APIs | **Concept** | Module 4 table only. |

## OWASP Top 10 for LLM Applications 2026

| ID | Name | Coverage | Where |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | **Lab** | Module 12 injection test; [Module 12b](modules/12b-agent-security-workshop.md) hijack and eval corpus (29 payloads); [Module 15](modules/15-ml-ai-security.md) |
| LLM02 | Sensitive Information Disclosure | **Concept** | Module 15 |
| LLM03 | Excessive Agency | **Lab** | Module 12 policy and approval gate; Module 12b gateway, scopes, bound approvals |
| LLM04 | Supply Chain | **Lab** (partial) | Module 12b pinned tool descriptions (rug-pull exercise); Modules 14 and 15 |
| LLM05 | Data and Model Poisoning | **Concept** | Module 15 |
| LLM06 | Unbounded Consumption | **Lab** | Module 12b step, call, and request budgets, cost accounting, kill switch |
| LLM07 | Misinformation | **Mention** | Module 14 |
| LLM08 | Hidden Context Exposure | **Gap** | No system-prompt leakage coverage. |
| LLM09 | Vector and Embedding Weaknesses | **Mention** | Modules 14 and 15. The lab has no RAG pipeline. |
| LLM10 | Improper Output Handling | **Mention** | Module 14 |

## OWASP Top 10 for Agentic Applications 2026

| ID | Name | Coverage | Where |
| --- | --- | --- | --- |
| ASI01 | Agent Goal Hijack | **Lab** | [Module 12b](modules/12b-agent-security-workshop.md): a scripted planner is hijacked through alert evidence, a playbook, memory, and a tool description. Not measured against a real model. |
| ASI02 | Tool Misuse and Exploitation | **Lab** | Module 12 allowlist; Module 12b argument schemas, protected actors, bound approvals |
| ASI03 | Identity and Privilege Abuse | **Lab** (partial) | Module 12b per-run scoped identity vs an ambient one. soc-lite does not authenticate the agent. |
| ASI04 | Agentic Supply Chain Vulnerabilities | **Lab** (partial) | Module 12b mock MCP registry, descriptor pinning, rug-pull. No signature or dependency checks. |
| ASI05 | Unexpected Code Execution (RCE) | **Concept** | The lab agent has no code-running tool, by design. Guidance in [Securing your coding agent](appendix-coding-agent-security.md). |
| ASI06 | Memory and Context Poisoning | **Lab** | Module 12b persistent memory with provenance |
| ASI07 | Insecure Inter-Agent Communication | **Gap** | Single agent. The [agent threat model](agent-threat-model.md) says what a second agent would need. |
| ASI08 | Cascading Failures | **Lab** (partial) | Module 12b runaway loop, budgets, circuit breaker, kill switch. Single agent only. |
| ASI09 | Human-Agent Trust Exploitation | **Lab** (partial) | Module 12b approval-queue flood cap and argument-bound tokens. Whether a person reads before approving is not measured. |
| ASI10 | Rogue Agents | **Lab** (partial) | Module 12b traces, audit, replay, kill switch, repeated-denial abort. No drift or baseline detection. |

## Biggest gaps

1. **API9:2023** and **LLM08** have no coverage.
2. **A03/A08** (supply chain and integrity) are named but never practiced.
3. **A02 and A07** are covered by one narrow exercise each, and **A05** by SQL and XSS only.
4. **ASI07** (inter-agent communication) has no coverage, and **ASI05** is a deliberate non-goal. The agent coverage is against a scripted planner, so it shows the gateway holds, not how often a real model is fooled. See the [agent threat model](agent-threat-model.md).

## Verification

Checked on 2026-10-07 against:

- [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction): all ten IDs and names match Module 4. SSRF is folded into A01.
- [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10): all ten match.
- [OWASP LLM Top 10 2026](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final): the ten names match Module 14. Excessive Agency is LLM03, as Module 12 says.
- [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/): ASI01–ASI10 names match secondary sources listing the published document. The official page only links a PDF, so re-check against it when updating.
- ATT&CK technique names used in the course (T1190, T1213, T1110.001/.003, T1552.005, T1087, T1069, T1059, T1005) match their official titles. The course does not pin an ATT&CK version.

`owasp.org/Top10/2025/` and `owasp.org/API-Security/` now redirect to
`top10.owasp.org` and `api-security.owasp.org`. Existing links still work.

## Keeping this page current

Update this page in the same PR as any module or lab change, and bump
`last_reviewed` in its front matter.
