---
description: "How to work through the platform capstone: which module already produced each milestone, what to promote rather than redo, the only new engineering, and a time budget."
---

# How to work through the platform capstone

You’ve already done most of this. Modules 1–13 had you draw the trust
boundaries, map the alerts, run the purple loop, open a case, write the
timeline, run the agent, and review the architecture. The capstone asks you
to **promote** that work: finish it, make it consistent, and prove it with
evidence. Only redo a piece if you didn’t keep it.

The only new engineering is **three rules you write yourself and eight
replay fixture pairs**. Everything else is operating the lab and writing
up what you saw.

## Step 0 — see what you already have

```bash
ls docs/capstone/work/ docs/capstone/work/fixtures/ 2>/dev/null
```

Compare the listing with the table below. Each row says what to do if the
file is there, and where to go back to if it isn’t.

## Milestone by milestone

| Milestone | If you kept it… | If you didn’t… | Hours (kept / cold) |
| --- | --- | --- | --- |
| **Setup** | `make lab-up`; check loopback binds and that `simulate.py --base http://8.8.8.8` exits | Same | 0.5 / 1 |
| **Artifact A — Model** | Extend your Module 1 `threat-model.md` from `notes-api` to the whole stack: soc-lite, the agent, the log volume. Add five named threats and a residual-risk paragraph | Module 1 lab, steps 1–7, then do the above | 1 / 2 |
| **Artifact B — Telemetry** | Pick one event per rule and check it has UTC `ts`, `event`, actor, object, `trace_id`. Record gaps in `attack-coverage.md` | Module 7 lab: `POST /ingest`, `GET /events` | 1 / 2 |
| **Artifact C — Emulate** | `lab-reset`, then `simulate.py --scenario all` against loopback | Same | 0.5 / 1 |
| **Artifact D — Detect** | Your Module 8 matrix has five rows. **New work:** write three rules in `labs/detections/rules.yaml` against events no rule covers, then create a fire/quiet fixture pair for all eight and replay them | Module 8 lab for the matrix; Module 11 DET-001 walkthrough for rules and fixtures | 6 / 8 |
| **Artifact E — Investigate** | Your Module 10 case plus Module 11 timeline: add competing hypotheses and an RCA that names a control defect | Module 10 lab (case), Module 11 lab (timeline, RCA) | 2 / 4 |
| **Artifact F — Contain** | Rewrite your Module 11 notes as the sequence you actually ran: preserve first, then `LAB_MODE=false`, then retest | Module 11 lab, from “preserve” to “retest” | 1.5 / 2 |
| **Artifact G — Purple** | Expand the Module 9 ten-line report into a TP/FN/TN table with at least one benign run, plus the rule or control you changed | Module 9 lab | 1.5 / 2.5 |
| **Artifact H — Agent** | Re-run the three action attempts and save them with the `/investigate` response ([template](templates/agent-run.md)) | Module 12 lab | 1 / 1.5 |
| **Artifact I — Review** | Turn the Module 13 findings into five, each with evidence and a “not this”. Move the Module 13 ADR into the decision-record template | Module 13 lab and assignment | 2 / 3 |
| | | **Total** | **17 / 27** |

The row sums are **17 / 27**. Plan on **12–20 hours** if you kept your module work, and **25–30 hours** if you’re starting cold — the same platform cell as the [time table](../index.md#time). The scanner’s only range is 25–35 hours. Most of the extra time goes on Artifact D: writing rules you haven’t tested before takes longer than anyone expects.

## Order that saves time

1. Setup → Artifact C in one sitting. That gives you a clean, fully populated log.
2. **Artifact D before anything else.** Artifact E cites alert IDs, and Artifact G needs a rule to
   change.
3. Artifact E → Artifact F back to back, while the evidence snapshot is fresh.
4. Artifact G once `LAB_MODE=false` is in place, so you test the fix, not the bug.
5. Artifact H, then Artifact I last, because the review should cite everything above.

## Course knowledge you will use

| Module | What the capstone uses it for |
| --- | --- |
| 1: foundations | Artifact A: assets, trust boundaries, residual risk |
| 2: network and OS | Setup/Artifact A: which process binds which port; where logs live |
| 3: identity and access | Artifact A/Artifact E: a valid token isn’t authorization; reading actor vs object |
| 4: application and API | Artifact C/Artifact F: IDOR, injection, and the `LAB_MODE=false` fix you retest |
| 5: cloud, containers, Kubernetes | Artifact A/Artifact C: SSRF to mock IMDS; the metadata boundary |
| 6: cryptography | Artifact I: password hashing and JWT findings |
| 7: monitoring and logs | Artifact B: the fields every detection depends on |
| 8: MITRE ATT&CK | Artifact D: the coverage matrix, with confidence and limitations |
| 9: red, blue, purple | Artifact G: hypothesis → emulate → TP/FN/TN → delta |
| 10: SOC | Artifact E: triage, cases, the approval gate on response actions |
| 11: detection and IR | Artifact D/Artifact E/Artifact F: rule authoring, fixtures, timeline, containment |
| 12: agentic SOC | Artifact H: policy outside the model, untrusted evidence, APPROVE |
| 13: security architecture | Artifact I: findings, what not to automate, decision record |
| 14: future directions | Optional. Its judgment memo can seed “What we will not automate” in Artifact I |
| 15: ML/AI security | Optional. Stretch: the prompt-injection and unsafe-agent-action scenarios |
| 16: availability and DoS | Optional. Stretch: `/login` rate limiting and the bulk-use false positive |
| 17: human factor | Optional. Stretch: the stolen-session-token replay scenario |

Modules 1–13 are required. Modules 14–17 aren’t scored, but each one feeds
a [stretch scenario](README.md#stretch-scenarios-and-goals).

## Before you hand in

Open the [brief](README.md) and read the “Done when” column one row at a
time. For each row, point at the file in `work/` that proves it. If you
can’t find the file within a few seconds, a reviewer won’t find it either.
