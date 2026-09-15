---
description: "Template for the capstone's architecture and security review: five falsifiable findings with owner and evidence, what you will not automate, and a production-shaped variant."
---

# Architecture review — notes-api platform (fill in)

!!! info "Before you fill this in"
    **Start in:** Module 13 lab. **Save as:** `docs/capstone/work/architecture-review.md`. Edit the copy, never this template.
    **Example:** [Helix architecture review](../reference/architecture-review-example.md). If your copy mentions `HELIX_DEBUG` or `/webhooks/fetch`, you’ve reviewed the wrong system.

## Scope

Which reviewer are you, and what is the system about to face? For example:
“a staff engineer reading this before it is exposed to a partner network.”

## Diagram

Link your `threat-model.md` diagram, or redraw it with the fixes in place.

## Findings

At least five. Each one must be falsifiable: someone could show it is
wrong with a request, a config line, or a log line.

### F1 — (one-line claim)

**Observation.** What you saw, and where.

**Why it matters.** The consequence on this system, not the vulnerability
class.

**Recommendation.** The specific change.

**Owner.** Team or component.

**Evidence.** The request, file, or log line that proves the observation.

**Not this.** The tempting fix that wouldn’t work (for example “add a WAF”).

*(Repeat for F2–F5.)*

## What we will not automate

Actions that stay behind a human, and why.

## Production-shaped variant (not implemented)

What the same platform looks like with the findings fixed: identity,
AuthZ, egress, secrets, detection in CI.

## What this review is not

Name what you didn’t cover, so nobody reads it as a clean bill of health.
