---
description: "Template for the capstone containment runbook: the specific incident containment steps you actually executed, not a generic playbook."
---

# Containment runbook — notes-api (fill in)

!!! info "Before you fill this in"
    **Start in:** Module 11 lab. **Save as:** `docs/capstone/work/containment-runbook.md`. Edit the copy, never this template.
    **Example:** [Helix containment runbook](../reference/containment-runbook-example.md). If your copy says `HELIX_DEBUG`, you’ve contained the wrong system.

This is the record of the containment you **actually carried out** for one
incident. It isn’t the generic playbook in `labs/soc-lite/playbooks/`,
which lists options. Write down the sequence you ran, in order, with the
evidence for each step. Simulated actions only.

| Field | Value |
| --- | --- |
| Incident ID | (matches `incident-report.md`) |
| Executed by | |
| Started (UTC) | |
| Completed (UTC) | |

## Preconditions

- [ ] Evidence preserved (`preserve-logs.sh` run, evidence dir hashed)
      **before** any containment action below.
- [ ] Playbook consulted: `labs/soc-lite/playbooks/______.md`
- [ ] Scope is loopback lab only.

If you contain before you preserve, you destroy the evidence that would
show whether containment worked, or was needed at all. See Module 11 on
quarantine versus eradication.

## Sequence executed

| Step | Action | Why this order | Reversible? | Evidence |
| --- | --- | --- | --- | --- |
| 1 | | | yes / no | |
| 2 | | | yes / no | |

## What was not done, and why

Actions you considered and chose to skip. For example: “did not revoke all
sessions. Only one account was affected, so full revocation would have
logged out legitimate users without containing anything more.”

## Verification

How you confirmed containment actually worked, beyond the command exiting
0. Give the exact request or scenario you replayed and its result.

## Rollback

If a containment step turns out to be wrong (for example, it blocks
legitimate traffic): the exact steps to reverse it, and which evidence
reversing it would lose or keep.

## Handoff to eradication and recovery

Link to the permanent fix in `incident-report.md` under Root cause.
Containment buys time; it isn’t the fix.
