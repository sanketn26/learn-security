# Learning paths

The complete course is progressive, but not every learner needs every optional
tool. Choose a path, keep the module order, and do not skip safety or the
foundation concepts.

| Path | Time | Complete | Skip or defer |
| --- | ---: | --- | --- |
| Guided beginner | 100–120 h | onboarding, all core readings/labs, capstone | optional kind, packet capture, scanners, LLM |
| Standard engineer | 80–100 h | all modules and capstone | only hardware-heavy options |
| Architecture focus | 35–45 h | 1, 3–7, 9, 11–13; threat model + review | deep SOC operations; return later |
| Detection/SOC focus | 40–50 h | 1–4, 7–12; incident capstone artifacts | optional Kubernetes |
| Preview | 8–12 h | onboarding, each module's Visual overview, module summaries, knowledge checks | runnable labs and capstone |

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

- packet capture is optional; application and container logs are sufficient;
- kind/k3d and Kubernetes tools are optional;
- Trivy/Grype are optional;
- hosted or local LLM use is optional—the agent has a deterministic mode;
- a commercial SIEM, EDR, NDR, or SOAR is never required.
