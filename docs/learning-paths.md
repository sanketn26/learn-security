---
description: Choose a guided beginner, standard engineer, architecture-focus, or SOC-focus path through the course modules and labs.
---

# Learning paths

The complete course is progressive, but not every learner needs every optional
tool. Choose a path. **Keep the relative order of the modules you do** (do not
reorder); skipped modules are deferred, not deleted. Do not skip safety or
the foundation concepts. [How defenders think](how-defenders-think.md) is
short and belongs on every path.

Hours for each path are only in the [time table](index.md#time) on the home page. This page says what each path includes.

| Path | Complete | Skip or defer |
| --- | --- | --- |
| Guided beginner | onboarding, modules 1–17, one capstone | optional kind, packet capture, scanners, LLM |
| Standard engineer | modules 1–17 and one capstone | only hardware-heavy options |
| Architecture focus | 1, 3–7, 8–9, 11–13; threat model + review. Skim [how defenders think](how-defenders-think.md). Defer 14–17. | deep SOC queues |
| Detection/SOC focus | 1–4, 7–12, plus 16 before 17; incident capstone artifacts. Read [how defenders think](how-defenders-think.md) before module 7. Module 5 is the metadata hole and does not name DET-003. Module 10 triages `DET-003:alice`. Module 11 is where you author more rules (the worked example is DET-001). Defer 14–15. | optional Kubernetes |
| Preview | onboarding, each module's Visual overview, module summaries, knowledge checks | runnable labs and capstone |

## Capstone choice

Choose the [defensive platform](capstone/README.md) for SOC operations, or
the [Python vulnerability scanner](capstone/vulnerability-scanner.md) for
application security automation: inventory, focused validation, connected
paths, and repair verification. The scanner assumes proficient Python and
uses no LLM. Scanner hours are 25–35. Platform hours are 12–20 if you kept the module work, or 25–30 from a cold start. Both figures are in the [time table](index.md#time). Doing both capstones adds the scanner’s 25–35 hours.
Its [course-knowledge map](capstone/vulnerability-scanner.md#course-knowledge-you-will-use)
lists the modules it needs and which are optional. The platform capstone
has the same map in [How to work through](capstone/howto.md#course-knowledge-you-will-use).

## Recommended beginner rhythm

For each module, budget:

- 20 minutes for the visual mental model;
- 45–75 minutes for key concepts;
- 60–120 minutes for the lab;
- 20 minutes for the knowledge check and engineering decision;
- a break before introducing the next layer.

Pause after Modules 3, 6, and 11 for a synthesis exercise. Explain the whole
Acme Notes request path without notes and add the new identities, controls,
and evidence sources you have learned.

## Required versus optional

Core labs use the Compose stack, Python, and curl. Anything labeled optional
is an enrichment, not a hidden prerequisite. In particular:

- the [Module 4b secure coding workshop](modules/04b-secure-coding-workshop.md) is optional and outside every path's hours; take it if you ship application code or want an AppSec focus;
- the [Module 12b agent security workshop](modules/12b-agent-security-workshop.md) is optional and outside every path's hours; take it if you build or run AI agents or coding agents (see also [securing your coding agent](appendix-coding-agent-security.md));
- packet capture is optional; application and container logs are sufficient;
- kind/k3d and Kubernetes tools are optional;
- Trivy/Grype are optional;
- hosted or local LLM use is optional—the agent has a deterministic mode;
- a commercial SIEM, EDR, NDR, or SOAR is never required.
