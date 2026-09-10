---
description: How this course grades you: the Explain, Predict, Diagnose, Design, Defend rubric, formative labs, and the 100-point capstone pass bar.
---

# Assessment plan

## Formative (each module)

- Short knowledge check (self-graded; answers in the module).
- Short engineering assignment (one page or a small patch).
- Lab completion: expected observations present.

A transcript without reasoning does not pass. You pass a module when you
can do all of the following for its material, in this order:

| Move | You can |
| --- | --- |
| **Explain** | State the security invariant. Identify the trust boundary. |
| **Predict** | Predict expected evidence: what appears, what does not, and why. |
| **Diagnose** | Diagnose a failure from telemetry. |
| **Design** | Propose prevention **and** detection. |
| **Defend** | Explain containment. Explain residual risk. |

That is Explain → Predict → Diagnose → Design → Defend. Module exit
checklists instantiate this bar; they do not replace it. Lab output
(screenshots or command transcripts of **local** services) is necessary
evidence, not a substitute for the explanations.

Runtime labs use the predict → run → compare loop in
[How defenders think](how-defenders-think.md). Design and writing labs
use the same cycle on findings, not telemetry. Do not invent extra labs.

## Summative

Choose the [platform capstone](capstone/README.md) or the
[Python vulnerability scanner](capstone/vulnerability-scanner.md). Each has
its own 100-point rubric; pass at 80+ with all of that project’s acceptance
checkboxes. The scanner assumes Python proficiency and has no LLM component.

## Integrity

- Do not submit production logs or real credentials.
- Do not “pass” by disabling `assert_local` in `simulate.py`.
- Using an LLM to **edit prose** is fine; using it to skip labs is not.
  If an agent writes your incident report, you must still be able to defend
  the timeline live.

## Optional oral

Fifteen minutes: explain DET-003 mapping, why approval is in the API, and
one residual risk after `LAB_MODE=false`.
