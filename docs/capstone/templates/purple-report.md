---
description: "Fill-in template for a purple-team validation report: hypothesis, emulation, TP/FN/TN results table, detection delta, control delta, and residual gap."
---

# Purple-team report — notes-api (fill in)

!!! info "Before you fill this in"
    **Start in:** Module 9 lab (the 10-line report). **Save as:** `docs/capstone/work/purple-report.md`. Edit the copy, never this template.
    **Example:** [Helix purple report](../reference/purple-report-example.md). If your copy mentions HELIX-003 or `HELIX_DEBUG`, you’ve tested the wrong system.

## Hypothesis

“If _actor_ does _procedure_ while _condition_, we will see _event_ and
_rule_ will fire. If _control_ is on, the request gets _result_ and no new
evidence appears.”

## Emulation

The authorized local sequence you ran: commands, `LAB_MODE` state, start time
(UTC).

## Results

Include at least one benign run. A report with no TN has only half-tested
the rule.

| Step | Expected | Observed | Verdict (TP / FN / FP / TN) |
| --- | --- | --- | --- |
| | | | |

## Detection delta

What you changed in `rules.yaml` because of a FN or FP: rule ID, event,
`group_by`, threshold, ATT&CK mapping, and the replay fixture that proves
it.

## Control delta

What you changed in the system (`LAB_MODE=false`, a code patch), and the
replay that proves it held.

## Residual gap

What this round didn’t test or didn’t fix.
