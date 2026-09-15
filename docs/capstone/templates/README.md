---
description: "Blank templates for the platform capstone: copy each one into your local work folder, fill in the copy, and never edit the template itself."
---

# Capstone templates

These are blank forms. **Copy, don’t edit.** Put the copy in your
[work folder](../work/README.md), which git ignores, and fill that in. The
templates stay blank so the next `git pull` never overwrites your work.

```bash
cp docs/capstone/templates/threat-model.md docs/capstone/work/threat-model.md
```

Every template uses the same headings as its
[Helix Tickets example](../reference/README.md). Helix is the wrong product
with the right shape. Copy its structure, never its names.

| Template | Save as | Milestone | Start in | Helix example |
| --- | --- | --- | --- | --- |
| [Threat model](threat-model.md) | `work/threat-model.md` | M1 | Module 1 | [example](../reference/threat-model-example.md) |
| [ATT&CK coverage](attack-coverage.md) | `work/attack-coverage.md` | M4 | Module 8 | [example](../reference/attack-coverage-example.md) |
| [Replay fixtures](replay-fixture.md) | `work/fixtures/<rule>.fire.jsonl` + `.quiet.jsonl` | M4 | Module 11 | [example](../reference/attack-coverage-example.md#replay-fixture) |
| [Incident report](incident-report.md) | `work/incident-report.md` | M5 | Modules 10–11 | [example](../reference/incident-report-example.md) |
| [Containment runbook](containment-runbook.md) | `work/containment-runbook.md` | M6 | Module 11 | [example](../reference/containment-runbook-example.md) |
| [Purple-team report](purple-report.md) | `work/purple-report.md` | M7 | Module 9 | [example](../reference/purple-report-example.md) |
| [Agent run](agent-run.md) | `work/agent-run.json` | M8 | Module 12 | — |
| [Architecture review](architecture-review.md) | `work/architecture-review.md` | M9 | Module 13 | [example](../reference/architecture-review-example.md) |
| [Security decision record](security-decision-record.md) | `work/security-decision-record.md` | M9 | Module 13 | [example](../reference/security-decision-record-example.md) |
