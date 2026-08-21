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
| 11 | Investigate simulated exposure | Advanced | Timeline, RCA, incident report |
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
| Expected evidence/detection | event fields + rule id |
| Actual result | |
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

