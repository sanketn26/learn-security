---
description: "Worked example ATT&CK coverage matrix for Helix Tickets: three detections mapped from observed alerts, a gap row, and one replay fixture pair."
---

# Example — ATT&CK coverage matrix (Helix Tickets)

*Parallel miniature. Not the notes-api capstone. Helix rules and event
names don't exist in this repository.*

## Matrix

| Detection | Data source | Tactic | Technique ID | Technique | Confidence | Limitation / gap |
| --- | --- | --- | --- | --- | --- | --- |
| HELIX-001 | helix JSONL `login_failure` | Credential Access | T1110.001 | Password Guessing | high | Groups by `src_ip`; one NAT egress looks like one attacker. Called a "spray" in the narrative, but six guesses at one account isn't T1110.003 |
| HELIX-002 | `cross_user_ticket_read` | Collection | T1213 | Data from Information Repositories | medium | The flaw is BOLA; T1190 also plausible. Only fires while debug disables the owner check |
| HELIX-003 (v2) | `ssrf_metadata_access` | Credential Access | T1552.005 | Cloud Instance Metadata API | high for the observed fetch | Added after the purple FN. Misses SSRF to any other internal target |
| (gap) | none | Persistence | — | — | n/a | Not emulated. "No data source," not a coloured cell |

## Procedure notes

- T1110.001: six `POST /login` for `dana` with wrong passwords from 127.0.0.1.
- T1213: `GET /tickets/42` as dana; the owner is eli.
- T1552.005: `POST /webhooks/fetch` with a mock-imds URL.

## Replay fixtures

| Rule | Fire file → alert | Quiet file → nothing |
| --- | --- | --- |
| HELIX-003 | one `ssrf_metadata_access` → `HELIX-003:dana` | one `fetch_ok` to an allowlisted status page → nothing |

### Replay fixture

`HELIX-003.fire.jsonl`:

```json
{"ts":"2026-08-31T14:01:40.000000Z","event":"ssrf_metadata_access","service":"helix-tickets","trace_id":"fx-h3","actor":"dana","url":"http://mock-imds/latest/meta-data/"}
```

`HELIX-003.quiet.jsonl`: the nearest legitimate case, a fetch that
the allowlist permits.

```json
{"ts":"2026-08-31T14:02:10.000000Z","event":"fetch_ok","service":"helix-tickets","trace_id":"fx-h3q","actor":"dana","url":"https://status.helix.example/health"}
```

!!! success "Why this is strong"

    Every row came from an observed alert. The v1 miss is visible as a v2
    row, not hidden. The quiet fixture is the case an analyst would
    actually confuse with the attack.

!!! note "Evidence"

    Alert IDs from the SOC analog, the rule file, and both fixture files
    replayed through the evaluator.

!!! warning "What would make it weak"

    A matrix painted green from rule names. Mapping every web bug to
    T1190 only. Copying DET-001–005 — those are notes-api rules.
