---
description: "Index to the Helix Tickets worked example: a parallel miniature incident showing finished threat model, coverage, incident, containment, purple, review, and decision artifacts."
---

# Worked example — Helix Tickets

**Wrong product, right shape.** Helix Tickets is a different, imaginary
service with its own incident. None of these pages is an answer for Acme
Notes. They show what a finished artifact looks like, and every one uses the
same headings as its [template](../templates/README.md), so you can copy the
structure directly.

!!! warning "The most common way to fail the capstone with these pages"
    Copying names across. Dana, Eli, ticket 42, `HELIX_DEBUG`,
    `cross_user_ticket_read`, and HELIX-001–003 belong here. `LAB_MODE`,
    Alice, Bob, and DET-001–005 belong to notes-api. If a submission mixes
    them, whoever wrote it modelled the wrong system.

**The incident in one paragraph.** Someone guesses at Dana’s password and
fails. They log in with the lab password anyway, read Eli’s ticket 42
because debug mode turned off the owner check, and make the API fetch mock
instance metadata. Two rules fire and the third behaviour goes unseen. The
analyst preserves evidence, turns debug off, proves the fix with a replay,
and turns the missed detection into a new rule.

| Artifact | Example | Template |
| --- | --- | --- |
| Threat model | [example](threat-model-example.md) | [template](../templates/threat-model.md) |
| ATT&CK coverage + replay fixture | [example](attack-coverage-example.md) | [template](../templates/attack-coverage.md) |
| Incident report | [example](incident-report-example.md) | [template](../templates/incident-report.md) |
| Containment runbook | [example](containment-runbook-example.md) | [template](../templates/containment-runbook.md) |
| Purple-team report | [example](purple-report-example.md) | [template](../templates/purple-report.md) |
| Architecture review | [example](architecture-review-example.md) | [template](../templates/architecture-review.md) |
| Security decision record | [example](security-decision-record-example.md) | [template](../templates/security-decision-record.md) |

Each example ends with the same three callouts. Use them to judge your own
work:

- **Why this is strong:** what earns full marks.
- **Evidence:** what a reviewer would ask to see.
- **What would make it weak:** the usual ways it goes wrong.

Synthetic evidence only. Nothing here is a procedure to run outside the
lab.
