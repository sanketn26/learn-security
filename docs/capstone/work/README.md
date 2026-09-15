---
description: "Where your platform capstone files live: a local, gitignored folder you fill from the templates as you work through the modules."
---

# Your capstone work folder

Everything you hand in for the [platform capstone](../README.md) goes in
this folder: `docs/capstone/work/`. Git ignores everything here except this
README, so your drafts survive a `git pull` and your dummy secrets don't end
up in a commit. The site build skips the folder too.

To start a file, copy its template here. Never edit the template in place.

```bash
cp docs/capstone/attack-coverage.md docs/capstone/work/attack-coverage.md
```

## What ends up here

| File | Milestone | Start from | Started in |
| --- | --- | --- | --- |
| `threat-model.md` | M1 Model | [template](../threat-model.md) | Module 1 lab |
| `attack-coverage.md` | M4 Detect | [template](../attack-coverage.md) | Module 8 lab |
| `fixtures/` | M4 Detect | one abnormal + one normal JSONL per rule | Module 11 assignment |
| `incident-report.md` | M5 Investigate | [template](../incident-report.md) | Modules 10–11 labs |
| `containment-runbook.md` | M6 Contain | [template](../containment-runbook.md) | Module 11 lab |
| `purple-report.md` | M7 Purple | [template](../purple-report.md) | Module 9 lab |
| `agent-run.json` | M8 Agent | saved `/investigate` response | Module 12 lab |
| `architecture-review.md` | M9 Review | [template](../architecture-review.md) | Module 13 lab |
| `security-decision-record.md` | M9 Review | [template](../security-decision-record.md) | Module 13 assignment |

The three detections you write go in `labs/detections/rules.yaml` next to
DET-001–005, not in this folder.

If you want your work under version control, keep it in a private repository
or on a branch you never push. Before you share anything, remove raw dummy
secrets such as IMDS keys and JWT secrets.
