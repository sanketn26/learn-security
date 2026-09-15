---
description: Worked example incident report for the Helix Tickets lab, with a UTC timeline, competing hypotheses, and password-spray and IDOR findings.
---

# Example — incident report (Helix Tickets)

*Parallel miniature. Not the notes-api capstone. Lab-only; dummy secrets.*

| Field | Value |
| --- | --- |
| Case ID | HELIX-IR-2026-08-31 |
| Severity | High (lab) |
| Status | Contained in lab; recovered with debug off |
| Detected (UTC) | 14:12:00 |
| Contained (UTC) | 14:25:00 |
| Recovered (UTC) | 14:31:00 |
| Author | lab analyst (example) |

## Summary

A simulated adversary password-sprayed Dana, then used Dana's legitimate
session to read Eli's ticket 42 (VPN placeholder) and to trigger a
server-side fetch of mock instance metadata. Two detections fired
(HELIX-001, HELIX-002). Metadata fetch was visible in JSONL but had no
rule in v1. Debug mode was disabled after evidence preservation.

## UTC timeline

| Time (UTC) | Event | Actor | Object | Source |
| --- | --- | --- | --- | --- |
| 14:01:02 | six `login_failure`, `src_ip=127.0.0.1` | — | `dana` account | helix JSONL |
| 14:01:18 | `login_success` (spray did not succeed; this login used the lab password) | dana | session | helix JSONL |
| 14:01:22 | `cross_user_ticket_read`, owner=eli | dana | ticket 42 | helix JSONL |
| 14:01:40 | `ssrf_metadata_access` url=http://mock-imds/... | dana | mock-imds | helix JSONL |
| 14:12:00 | HELIX-001, HELIX-002 alerts; case opened | analyst | case | SOC analog |
| 14:18:00 | evidence snapshot (`preserve-logs` analog) | analyst | evidence dir | evidence dir |
| 14:25:00 | `HELIX_DEBUG=false` redeploy | analyst | helix-tickets | runbook |
| 14:31:00 | replay: ticket 42 → 404 for dana; metadata fetch blocked | analyst | ticket 42, fetch | purple |

The spray **failed**. The IDOR used a valid password. Do not write "they
brute-forced Dana and then read Eli" as one causal chain if the logs
show a successful login with the known lab password after failed guesses.

## Competing hypotheses

| H | Claim | Status — evidence |
| --- | --- | --- |
| H1 | Spray produced the Dana session | **Rejected** — `login_success` uses the seed password, not a guessed one |
| H2 | Broken object authz in debug is the ticket-42 leak | **Supported** — same actor, owner mismatch, debug on |
| H3 | Fetch of mock-imds is SSRF using API identity | **Supported** — `ssrf_metadata_access` |
| H4 | Logs were planted | **Rejected** — hashes match pre-containment snapshot |

## Impact

Eli's dummy VPN placeholder in ticket 42 was readable by Dana.
Mock IMDS credentials (explicitly fake) were returned to the API
process. No extra-scope systems were contacted.

## ATT&CK mappings

See the [coverage matrix](attack-coverage-example.md). HELIX-001 →
T1110.001 (high, but the attempt failed; the narrative says "spray", yet
six guesses at one account is guessing, not T1110.003). HELIX-002 → T1213
(medium; the flaw is BOLA, T1190 also plausible). Metadata fetch →
T1552.005 (high for the observed fetch), with no rule in v1.

## Root cause

Object and function authorization, token expiry, and outbound-fetch
policy were behind a debug flag. The flag was on because the lab needed
to demonstrate the failures. The engineering defect is "authz is
optional," not "an attacker is clever."

## Containment, eradication, recovery

Evidence snapshot first, then `HELIX_DEBUG=false` and a JWT secret
rotation, then a verification replay. Full sequence in the
[containment runbook](containment-runbook-example.md). Eradication is the
flag split in the [decision record](security-decision-record-example.md).

## Detection gaps and follow-ups

`ssrf_metadata_access` was in the logs with no rule. The
[purple report](purple-report-example.md) turns that FN into HELIX-003 with
a replay fixture.

## Communications

Internal only. No customer notice. Dummy secret in ticket 42 treated as
burned *in the lab narrative*.

## Residual risk

A teaching overlay can still re-enable the IDOR, and HELIX-002 is the only
thing that would notice. Any other internal SSRF target has no attempt
detection yet.

!!! success "Why this is strong"

    Timeline is UTC and sourced. Hypotheses include the boring one (H1
    failed spray). RCA names a control defect, not a movie plot.

!!! note "Evidence"

    JSONL lines, alert IDs, snapshot checksum, before/after request for
    ticket 42.

!!! warning "What would make it weak"

    A story that ignores timestamps. "Nation-state." RCA = "human error."
    Using notes-api event names (`cross_user_note_access`) — that is the
    other incident.
