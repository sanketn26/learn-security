---
description: Worked example security decision record for Helix Tickets, explaining why debug mode must never be allowed to disable authorization.
---

# Example — security decision record (Helix Tickets)

*Parallel miniature. Not the notes-api capstone.*

| Field | Value |
| --- | --- |
| Decision ID | ADR-HELIX-1: Debug mode must not disable authorization |
| Date | 2026-08-31 |
| Author | lab analyst (example) |
| Status | Accepted (lab teaching fork: a separate *fault-injection* flag may still exist) |

## Threat

An operator (or a default compose file) leaves `HELIX_DEBUG=true`.
Object authorization, token expiry, and outbound-fetch policy all
collapse together. The incident above is that collapse.

## Chosen control

Split flags:

- `HELIX_DEBUG` — verbose logs, OpenAPI UI, synthetic seed.
- Authorization, `exp` on JWT, and IMDS-shaped fetch blocks are **always
  on**.

A teaching overlay `HELIX_INJECT_IDOR=true` may exist on a named lab
profile so the course can still demonstrate the failure, but it is not
the same bit as "debug."

## Why this control

Debug is the setting most likely to be left on by accident, so it is the
worst place to hide a security bypass. Splitting the flags keeps the
teaching failure available without making "verbose logs" and "no authz"
the same switch.

## Alternative considered

Keep a single `HELIX_DEBUG` that weakens authz, because "it's only a
lab."

Rejected: the lab exists to train the muscle that **debug is not a
security boundary**. A single flag trains the opposite muscle.

## Residual risk

Instructors can still turn `HELIX_INJECT_IDOR=true`. Detection HELIX-002
must remain on whenever that overlay is used. Production (if this code
were ever copied) must not ship the overlay.

## Detection coverage

HELIX-002 is the compensating control for the teaching overlay.
HELIX-003 covers metadata fetch.

## Operational cost

Two flags instead of one. Compose files get a comment. Cheaper than an
incident report that says "debug was on."

!!! success "Why this is strong"

    Names the threat, the choice, the rejected alternative, residual
    risk, detection, and cost. A reader could implement it.

!!! note "Evidence"

    This ADR plus the purple table showing IDOR only when the inject
    flag (or old debug flag) is on.

!!! warning "What would make it weak"

    "We will add MFA later." No alternative. No residual. Copying the
    notes-api `LAB_MODE` decision word-for-word — that is a different
    flag on a different service.
