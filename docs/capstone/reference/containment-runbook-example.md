---
description: "Worked example containment runbook for the Helix Tickets incident: the numbered sequence of actions actually executed, with evidence."
---

# Example — containment runbook (Helix Tickets)

*Parallel miniature. Not the notes-api capstone.*

This is the **sequence that was executed**, not a menu of options.

| Field | Value |
| --- | --- |
| Incident ID | HELIX-IR-2026-08-31 |
| Executed by | lab analyst (example) |
| Started (UTC) | 14:18:00 |
| Completed (UTC) | 14:33:00 |

## Preconditions

- Scope is loopback Helix lab only.
- Analyst has write access to the compose project.
- SOC analog is up.

## Sequence executed

| Step | Action | Why this order | Reversible? | Evidence |
| --- | --- | --- | --- | --- |
| 1 | Snapshot JSONL + sqlite + alert export | Evidence before mutation | n/a | `evidence/helix-2026-08-31T14-18Z/` checksums |
| 2 | Record HELIX-001 / HELIX-002 IDs in the case | Containment must cite alerts | yes | case timeline entry |
| 3 | Set `HELIX_DEBUG=false` and recreate the API container | Stops IDOR and debug SSRF | yes | compose env, `/health` now `debug=false` |
| 4 | Rotate JWT secret in the lab | Debug tokens had no `exp` | no (old tokens stay dead) | new secret in env; old tokens 401 |
| 5 | Treat ticket-42 VPN placeholder as burned (lab narrative) | Data left the object boundary | no | ticket comment |
| 6 | Verify: Dana `GET /tickets/42` → 404; fetch metadata → 400 | Containment without verification is a hope | n/a | HTTP transcripts |
| 7 | Re-ingest logs; confirm no new HELIX-002 from the verify traffic | Detection stays honest | n/a | alert list |

## What was not done, and why

- Did not `rm` the JSONL to "clean the incident." It is the evidence.
- Did not disable HELIX-001 because it was noisy during replay; that
  would hide the next real attempt.
- Did not test any host other than 127.0.0.1. Out of scope.

## Verification

Steps 6 and 7. Dana's request for ticket 42 returns 404, the metadata
fetch returns 400, and re-ingesting the verification traffic produces no
new HELIX-002 alert.

## Rollback

Re-enable debug only in a fresh compose project for teaching, never on
the evidence snapshot.

## Handoff to eradication and recovery

The permanent fix is the flag split in the
[decision record](security-decision-record-example.md), tracked from the
[incident report](incident-report-example.md) root cause.

!!! success "Why this is strong"

    Evidence is step 1. Verification is a numbered step. "What we did
    not do" prevents destructive improvisation.

!!! note "Evidence"

    Directory listing of the snapshot, health JSON, HTTP 404/400
    transcripts, case timeline.

!!! warning "What would make it weak"

    "Disable the user" as the only step. Containment before snapshot.
    A generic NIST loop with no Helix commands. Using `LAB_MODE` — that
    flag belongs to notes-api, not Helix.
