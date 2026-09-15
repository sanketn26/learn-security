---
description: "Blank incident report template for the capstone: UTC timeline, competing hypotheses, ATT&CK mappings, root cause, containment, and residual risk."
---

# Incident report — notes-api (fill in)

!!! info "Before you fill this in"
    **Start in:** Module 10 (case), finish in Module 11 (timeline, RCA). **Save as:** `docs/capstone/work/incident-report.md`. Edit the copy, never this template.
    **Example:** [Helix incident report](../reference/incident-report-example.md). If your copy mentions Dana, `cross_user_ticket_read`, or ticket 42, you’ve written up the wrong incident.

| Field | Value |
| --- | --- |
| Case ID | (soc-lite case) |
| Severity | |
| Status | |
| Detected (UTC) | |
| Contained (UTC) | |
| Recovered (UTC) | |
| Author | |

## Summary

Three to five sentences: what happened, what fired, what didn’t, and what
you changed.

## UTC timeline

Every row cites a source. If two sources disagree on time, say so; don’t
pick one silently.

| Time (UTC) | Event | Actor | Object | Source |
| --- | --- | --- | --- | --- |
| | | | | |

## Competing hypotheses

Include the boring one. Mark each hypothesis supported or rejected, and say
which evidence did it.

| H | Claim | Status — evidence |
| --- | --- | --- |
| H1 | | |
| H2 | | |

## Impact

What data, for whom, and whether it left the boundary. Dummy data is still
described as if it were real.

## ATT&CK mappings

Technique, confidence, and why the mapping might be wrong. Link to your
`attack-coverage.md` rows rather than re-arguing them.

## Root cause

Name the control defect (for example “object authorization is optional”),
not the attacker.

## Containment, eradication, recovery

One paragraph, plus a link to `containment-runbook.md` for the steps you
actually ran.

## Detection gaps and follow-ups

What was visible in the logs but had no rule, and what you did about it.

## Communications

Who you would tell, and what you would say. Lab: internal only.

## Residual risk

What is still true after recovery.
