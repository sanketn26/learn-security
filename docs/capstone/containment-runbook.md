---
description: Template for the capstone containment runbook: the specific incident containment steps you actually executed, not a generic playbook.
---

# Containment runbook (lab)

The record of containment **actually executed** for one incident — not the
generic technique playbook (see `labs/soc-lite/playbooks/`), which lists
options. This is the specific sequence you ran, in order, with evidence of
each step.

**Warning:** AUTHORIZED LAB USE ONLY. Dummy data. Simulated actions only.

| Field | Value |
| --- | --- |
| Incident id | (matches `incident-report.md`) |
| Executed by | |
| Started (UTC) | |
| Completed (UTC) | |

## Pre-containment check

- [ ] Evidence preserved (`preserve-logs.sh` run, evidence dir hashed)
      **before** any containment action below.
- [ ] Playbook consulted: `labs/soc-lite/playbooks/______.md`

Containing before preserving destroys the evidence you'd need to prove the
containment worked or was even necessary — see Module 11's "quarantine vs
eradicate" distinction.

## Actions taken, in order

| Step | Action | Target | Reversible? | Verified by | Result |
| --- | --- | --- | --- | --- | --- |
| 1 | | | yes/no | | |
| 2 | | | yes/no | | |

Example row: `1 | disable_lab_mode via compose recreate | notes-api | yes (re-enable LAB_MODE=true) | re-ran idor scenario, got 404 | contained`

## What was NOT done and why

Actions considered and deliberately skipped (e.g. "did not revoke all
sessions — blast radius was one account, full revocation would have logged
out legitimate users for no added containment value").

## Verification

How you confirmed containment actually worked, not just that the command
exited 0 — the specific replayed request/scenario and its result.

## Rollback plan

If a containment action turns out to be wrong (e.g. blocks legitimate
traffic), the exact steps to reverse it, and what evidence you'd lose or
keep by reversing.

## Handoff to eradication and recovery

Link to the permanent fix tracked in `incident-report.md`'s root-cause
analysis. Containment buys time; it is not the fix.
