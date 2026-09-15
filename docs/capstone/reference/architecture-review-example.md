---
description: Worked example architecture review for the Helix Tickets lab, with findings on broken object authorization, SSRF, and weak password hashing.
---

# Example — architecture review (Helix Tickets)

*Parallel miniature. Not the notes-api capstone.*

## Scope

Reviewer hat: a staff engineer reading Helix as if it were about to be
exposed to a contractor VPN. Five findings, each with owner, evidence,
and a "not this" so the review cannot be satisfied by renaming a ticket.

## Diagram

See the [threat model](threat-model-example.md). The findings below refer
to its boundaries.

## Findings

### F1 — Object authorization is a flag, not a default

**Observation.** `GET /tickets/{id}` returns Eli's body to Dana when
`HELIX_DEBUG=true`.

**Why it matters.** Debug mode is the production posture of every "we'll
turn it off later" service.

**Recommendation.** Owner check always on; debug mode may only inject
faults that are *not* authz bypasses.

**Owner.** API.

**Evidence.** Request/response pair for ticket 42 as Dana, debug on and off.

**Not this.** "Turn debug off in production" alone; the next debug flag reintroduces the bypass.

### F2 — Outbound fetch shares the API's identity

**Observation.** `/webhooks/fetch` uses the API process to retrieve
attacker-supplied URLs.

**Why it matters.** SSRF is not "the server requested a page." It is
"the server's trust was borrowed."

**Recommendation.** Allowlist hosts; never follow IMDS-shaped paths;
give the fetcher its own egress policy.

**Owner.** API + platform.

**Evidence.** The fetch code path, and `ssrf_metadata_access` in JSONL.

**Not this.** A deny-list of `169.254.169.254`; redirects and DNS tricks walk around it.

### F3 — Password verifiers in debug are unsalted SHA-256

**Observation.** Debug hasher is SHA-256 hex.

**Why it matters.** A dumped sqlite file becomes an offline guessing
oracle.

**Recommendation.** bcrypt (or the platform default) in every mode;
debug should not weaken verifiers.

**Owner.** API.

**Evidence.** A verifier from the sqlite file that is 64 hex characters, no salt.

**Not this.** "Add a pepper" while keeping a fast hash.

### F4 — JWT has no expiry in debug

**Observation.** Debug tokens omit `exp`.

**Why it matters.** Containment that "rotates users" does not contain
a stolen never-expiring token.

**Recommendation.** Hard `exp` in all modes; rotate signing secret on
debug→secure transition.

**Owner.** API.

**Evidence.** A debug JWT decoded without `exp`.

**Not this.** Shorter sessions in the UI; the token itself still never expires.

### F5 — Detection coverage stops at the two noisy events

**Observation.** The miniature SOC has HELIX-001 (spray) and HELIX-002
(cross-user read). No rule on `ssrf_metadata_access` in v1 of this
write-up.

**Why it matters.** Purple testing later shows a true-positive gap.
That gap is a finding, not a surprise.

**Recommendation.** Author a metadata-fetch rule with a replay fixture
before claiming "we detect the path."

**Owner.** Detection engineering.

**Evidence.** The rule file listing only HELIX-001/002, and the purple FN.

**Not this.** Marking T1552.005 "covered" because the event is logged.

## What we will not automate

- Disabling an agent account on HELIX-001 alone. The spray failed; an
  automatic lockout would have punished Dana for an attacker's guesses.
- Rotating the JWT secret without a human. It logs everyone out.

## Production-shaped variant (not implemented)

Owner checks always on; a separate fetcher with its own egress allowlist
and no route to metadata; bcrypt everywhere; `exp` on every token; HELIX-001
to -003 replayed in CI against fixtures.

## What this review is not

It is not a scanner PDF. It is not "add WAF." It does not claim Helix
is ready for the internet.

!!! success "Why this is strong"

    Five findings, each falsifiable, each with an owner. F5 admits a
    detection hole instead of inventing coverage.

!!! note "Evidence"

    Request/response for ticket 42; code path for fetch; a JWT decoded
    without `exp`; rule file listing only HELIX-001/002.

!!! warning "What would make it weak"

    Ten generic OWASP headings. Findings without evidence. "The WAF
    will catch it." Copying notes-api `LAB_MODE` language.
