---
description: Worked example purple-team report for Helix Tickets, showing emulation results, an SSRF detection gap, and the resulting rule change.
---

# Example — purple-team report (Helix Tickets)

*Parallel miniature. Not the notes-api capstone.*

**Hypothesis.** If an authenticated non-owner requests `/tickets/{id}`
while debug is on, we will see `cross_user_ticket_read` and HELIX-002
will fire. If debug is off, the same request returns 404 and no new
HELIX-002 evidence is appended.

## Emulation (lab)

Authorized loopback only. Sequence: six failed logins, valid Dana login,
`GET /tickets/42`, metadata fetch URL.

## Results

| Step | Expected | Observed | Verdict |
| --- | --- | --- | --- |
| Password spray | HELIX-001 | Fired on `src_ip` after 5 failures in 120s | TP |
| Ticket 42 as Dana, debug on | HELIX-002 | Fired | TP |
| Metadata fetch, debug on | Detection | JSONL `ssrf_metadata_access`; **no rule** | **FN** (coverage gap) |
| Ticket 42 as Dana, debug off | 404, no new HELIX-002 | 404 | TP for control; detection correctly quiet |
| Benign Dana reads Dana's ticket | no HELIX-002 | quiet | TN |

## Detection delta

v1 missed metadata fetch. v2 adds HELIX-003:

- event: `ssrf_metadata_access`
- group_by: `actor`
- threshold: 1
- ATT&CK: T1552.005 (high confidence for *observed fetch*; T1190 as
  extra, medium, because the path is the application)

Replay fixture: one metadata-access line fires HELIX-003; a `fetch_ok`
to an allowlisted status page does not.

## Control delta

`HELIX_DEBUG=false` turns owner checks on. Purple replay confirms Dana
cannot read ticket 42. Residual: never-expiring debug JWTs still need
rotation (see decision record).

!!! success "Why this is strong"

    A table of TP/FN/TN. The FN is admitted and turned into a rule.
    Benign traffic is tested, not only the attack.

!!! note "Evidence"

    Alert IDs, fixture JSONL, before/after HTTP codes.

!!! warning "What would make it weak"

    "We ran the attack and saw alerts" with no TN. Claiming 100% ATT&CK
    coverage. Copying DET-001–005 IDs from notes-api.
