---
description: Index of required hands-on exercises across all modules, from threat modeling and ATT&CK mapping to incident response and purple-team validation.
---

# Exercise index

Every exercise is a controlled engineering experiment. Record a hypothesis,
normal result, safe abnormal result, evidence, control, replay result, and
cleanup. Use the [experiment record worksheet](#experiment-record-worksheet)
below.

| Module | Required exercise | Starting level | Main output |
| --- | --- | --- | --- |
| 1 | Threat-model the Notes API | Read-only possible | Boundary diagram + residual risk |
| 2 | Inspect local network/host visibility | Introductory | Observation comparison |
| 3 | Review authentication and authorization | Introductory | Identity/decision trace |
| 4 | Replay four safe API failures, then repair | Intermediate | Before/after evidence |
| 5 | Trace metadata and container posture | Intermediate | Workload hardening findings |
| 6 | Compare password storage and signatures | Introductory | Crypto decision note |
| 7 | Ingest, normalize, and search events | Intermediate | Searchable evidence |
| 8 | Map five detections to ATT&CK | Intermediate | Coverage matrix with caveats |
| 9 | Run one purple-team loop | Intermediate | Validation report |
| 10 | Triage and open a case | Intermediate | Case record |
| 11 | Investigate simulated exposure; walk DET-001 then author more rules | Advanced | Timeline, RCA, incident report |
| 12 | Test a bounded SOC assistant | Advanced | Audited recommendation/approval run |
| 13 | Review the platform architecture | Advanced | Findings + architecture decision |
| 14 | Write a future-facing judgment memo | Reflective | Established/emerging risk memo |
| 15 | Threat-model an added ML feature; audit an agent's tools | Advanced | Trust-boundary diagram + audit note |
| 16 | Time the login endpoint under load | Intermediate | Cost-asymmetry measurement |
| 17 | Write competing narratives for two alerts | Advanced | Phishing vs. insider writeup |

## Exercise safety gate

Before any step labeled **AUTHORIZED LAB USE ONLY**, confirm all three:

- target hostname is `127.0.0.1` or `localhost`;
- data and credentials are synthetic;
- the command is one supplied by this course for the named scenario.

If any check fails, stop. Reading source, diagrams, logs, and synthetic
fixtures remains a safe alternative.

Runtime exercises use the predict → run → compare loop in
[How defenders think](how-defenders-think.md). Design and writing
exercises predict findings, then compare. Do not invent extra labs.

## Experiment record worksheet

Copy this for every module:

| Field | Your record |
| --- | --- |
| Question | |
| Hypothesis | |
| Scope and safety boundary | local compose + loopback only |
| Starting state | LAB_MODE, running services, clean/dirty logs |
| Normal observation | response + relevant telemetry |
| Safe abnormal stimulus | provided simulator/scenario only |
| Expected evidence/detection | event fields + rule id; also what should *not* appear |
| Actual result | |
| Prediction vs result | match, or which assumption was wrong |
| Control applied | |
| Replay comparison | |
| Failure mode tested | missing/malformed/delayed/duplicate/unsafe recommendation/etc. |
| Cleanup / rollback | command and resulting state |
| Engineering decision | production change + residual risk |
| Surface you could delete | route/tool/identity that need not exist |
| Bulkhead that would have limited this | identity / network / store / approval |
| Detection claim (one sentence) | event, field, window clock, grouping key |
| Quarantine switch | what you would isolate without destroying evidence |

The last four rows are the [thinking guide](how-defenders-think.md) in
worksheet form. Fill them even when the module does not ask.

## Shipped detection rules (DET-001–005)

The lab ships five rules in `labs/detections/rules.yaml`. This index is where each one is taught. Later modules may cite a rule without re-teaching it.

| Rule | What it matches | Where you learn it |
| --- | --- | --- |
| DET-001 | `login_failure` burst from one `src_ip` (password guessing) | Module 7 reads the alert. [Module 11](modules/11-detection-and-ir.md#worked-walkthrough-authoring-det-001) walks authoring it, then you write more rules. |
| DET-002 | `cross_user_note_access` (IDOR) | Module 8 maps it from evidence. |
| DET-003 | `ssrf_metadata_access` (SSRF to mock IMDS) | Module 5 is the hole and does not name the rule. Module 8 names the rule and the event it watches. Module 9 fires it, then shows the miss after the fix. Module 10 triages `DET-003:alice`. |
| DET-004 | `broken_function_authz` (non-admin calls an admin route) | Module 17 reads two stories from the same alert. |
| DET-005 | `search` query with SQL metacharacters | Module 4 is the injection hole and does not name the rule. Module 8 maps it in the five-row pack. Module 10 only warns against paging on every DET-005 regex hit. |

Module 11’s DET-001 walkthrough is the sequence to copy when you add rules. The capstone still requires three rules you author yourself; this course does not publish those solutions. Save each rule’s fire and quiet files as described in the [replay-fixture template](capstone/templates/replay-fixture.md).

