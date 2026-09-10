---
description: "Blank template for a capstone security decision record: the threat addressed, chosen control, alternative considered, and residual risk."
---

# Security decision record (lab)

One record per significant security decision — a control you chose, a
threshold you set, an architecture tradeoff you made. Copy this template
per decision; do not try to make one record cover the whole capstone.

**Warning:** AUTHORIZED LAB USE ONLY. Dummy data.

| Field | Value |
| --- | --- |
| Decision id | |
| Date | |
| Author | |
| Status | proposed / accepted / superseded |

## Threat

What specific attack or failure this decision responds to. Name the
invariant it protects, not just the vulnerability class.

## Chosen control

## Why this control

The reasoning, not just the choice — what made this the right tradeoff
given the constraints you actually had (cost, latency, existing
architecture, team size).

## Alternative considered

At least one option you did not pick, and the specific reason it lost —
"more work" is not a reason; "adds a round trip to every request for a
threat we rate low-likelihood" is.

## Residual risk

What this control does **not** cover. If you cannot name one, you have
not looked hard enough.

## Detection coverage

If this control fails or is bypassed, what would notice — a rule id, or
"none yet" stated plainly.

## Operational cost

Who maintains this, what breaks if it's misconfigured, and what it costs
at the resource/latency/on-call level.
