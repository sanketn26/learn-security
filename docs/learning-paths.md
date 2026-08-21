# Learning paths

The complete course is progressive, but not every learner needs every optional
tool. Choose a path. **Keep the relative order of the modules you do** (do not
reorder); skipped modules are deferred, not deleted. Do not skip safety or
the foundation concepts. [How defenders think](how-defenders-think.md) is
short and belongs on every path.

| Path | Time | Complete | Skip or defer |
| --- | ---: | --- | --- |
| Guided beginner | 100–120 h | onboarding, all core readings/labs, capstone | optional kind, packet capture, scanners, LLM |
| Standard engineer | 80–100 h | all modules and capstone | only hardware-heavy options |
| Architecture focus | 35–45 h | 1, 3–7, 8–9, 11–13; threat model + review. Skim [how defenders think](how-defenders-think.md). Defer 14–17. | deep SOC queues |
| Detection/SOC focus | 40–50 h | 1–4, 7–12, plus 16 before 17; incident capstone artifacts. Read [how defenders think](how-defenders-think.md) before module 7. Skim Module 5’s IMDS section before DET-003. Defer 14–15. | optional Kubernetes |
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
