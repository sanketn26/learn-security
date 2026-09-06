---
description: "Worked example threat model for the Helix Tickets lab: assets, trust boundaries, and top threats including password spray and SSRF."
---

# Example — threat model (Helix Tickets)

*Parallel miniature. Not the notes-api capstone.*

## Diagram

```
[agent browser] --> 127.0.0.1:8180 helix-tickets --> sqlite tickets.db
                                              |
                                              +--> mock-imds (should never)
                                              +--> JSONL --> soc analog
```

## Assets

| Asset | Sensitivity | Why it matters here |
| --- | --- | --- |
| Ticket bodies | High in a real IT org; dummy in this lab | Ticket 42 contains a VPN shared-secret *placeholder* |
| Password verifiers | High | Spray against `dana` is the opening move |
| JWT signing secret | High | Stolen token = Dana's session |
| Mock IMDS keys | Treat as high | Teaching stand-in for cloud credentials |

## Trust boundaries

| From | To | Control in the incident | Residual |
| --- | --- | --- | --- |
| Agent | API | JWT, no MFA | Stolen or guessed password |
| API | ticket row | Owner check **off** while `HELIX_DEBUG=true` | IDOR (ticket 42) |
| API | outbound fetch | Allowlist only in the write-up's V2 | Debug SSRF to mock-imds |
| Host | log volume | Directory perms | Anyone with the volume can rewrite history |

## Top threats (Helix, not a generic STRIDE dump)

1. Password spray produces a session for an agent.
2. Authenticated agent reads another agent's ticket (broken object authz).
3. Server-side fetch reaches instance metadata.
4. JWT secret is a default string in debug.
5. Logs are truncated or rotated before preservation.

## Residual risk statement

After `HELIX_DEBUG=false`, object checks and the application-level
metadata block are on. Residual: a valid Dana session still reads Dana's
tickets; a stolen JWT that was issued in debug has no `exp`. Tokens
issued before the change must be treated as burned. The lab safety rail
is **not** claimed as a production control.

!!! success "Why this is strong"

    Assets are named with *this* product's data (ticket 42, VPN
    placeholder). Each boundary has a control *and* a residual. The
    residual-risk paragraph says what the fix does **not** do.

!!! note "Evidence that would support this model"

    - `GET /health` shows debug flag.
    - Seed data listing ticket 42 owner `eli`.
    - Log lines `login_failure`, `cross_user_ticket_read`,
      `ssrf_metadata_access`.

!!! warning "What would make it weak"

    - A STRIDE table with no Helix-specific rows.
    - "OWASP compliant" as residual risk.
    - Claiming the loopback bind *is* authorization.
    - Copying notes-api asset names (`note 2`, `LAB_MODE`) into this file
      — that would mean the author modeled the wrong system.
