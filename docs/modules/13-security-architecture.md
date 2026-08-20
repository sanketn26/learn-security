# Module 13 — Security architecture for software engineers

## Why it matters to a software engineer

Architecture is the set of defaults that remain when you are not looking:
how services authenticate, where secrets live, what CI will sign, what the
SOC can see. Tools do not substitute for this. Compliance does not either.

## Visual overview

```text
INSECURE
Internet -> API (shared secret, broad DB, broad egress) -> shared database
              +---------------------------------------> metadata
CI (long-lived prod key) -> mutable image tag -> cluster-admin deployment

IMPROVED
Internet -> gateway -> API (audience identity, object policy) -> scoped data
                       +--deny--> metadata
                       +-------> protected audit pipeline
CI OIDC -> signed immutable artifact -> admission -> non-root workload
```

!!! note "Intuition"
    Notice every line in `IMPROVED` is narrower than its counterpart in
    `INSECURE` — broad database access becomes scoped data, a long-lived key
    becomes short-lived OIDC, a mutable tag becomes a signed immutable
    artifact. "More secure" in this course almost always means "the same
    capability, with a tighter, more specific, more revocable boundary
    around it" — not an extra product bolted on top.

Annotate every production diagram with trust boundaries, identity paths,
data classification, allowed network paths, enforcement points, telemetry,
and owners. State trade-offs: aggressive blocking vs availability;
centralized authorization vs failure domain; logging vs privacy/cost;
encryption vs inspection; isolation vs operability; least privilege vs
delivery speed. The output is a decision with residual risk, not "add WAF."

!!! tip "Hint"
    If a design review's conclusion is a product name instead of a sentence
    about residual risk, the review didn't finish. "Add a WAF" doesn't say
    what risk remains after adding it, for whom, or under what failure mode —
    "add a WAF, which reduces but doesn't eliminate injection risk, and does
    nothing for BOLA" does.

## Learning objectives

- Design a service with explicit identity, secrets, segmentation, and
  observability.
- Place threat modeling in design reviews and tests in CI.
- State distributed-systems security trade-offs (consistency, blast radius,
  replay, poison-pill messages).

## Key concepts

**Secure service design.** Every service: authenticated callers, authorized
objects, least-privilege outbound, structured audit events, fail closed,
timeouts, bounded retries (so you do not amplify incidents).

**Secrets management.** Generate, distribute, rotate, revoke. Runtime
injection beats images. Separate prod from lab. JWT_SECRET in compose is
acceptable only as a lab smell you would ticket.

**Identity-aware service communication.** mTLS or JWT/OIDC between services
with `aud` per callee. No “VPC = trusted.”

**Network segmentation.** Still useful to reduce SSRF and ransomware blast
radius. Not a replacement for AuthZ.

**Supply-chain security.** Pin, verify, provenance (SLSA as a *framework
of levels*, not a certificate), signed images, review GitHub Actions
permissions, do not `latest`.

**Secure SDLC.** Threat model on design; code review including AuthZ;
dependency scan; SAST as a *helper*; DAST/API tests for IDOR; deploy gates;
production security observability. None of these is complete.

**Distributed-systems trade-offs.**

| Decision | Security implication |
| --- | --- |
| Shared database vs per-service DB | Shared DB makes object AuthZ and blast radius worse |
| Sync vs async | Poisoned messages persist; consumers need AuthN of producers |
| Caches | Stale AuthZ; cache poisoning |
| Retries | Credential stuffing looks like your own retry storm |
| Multi-tenant isolation | One missing `tenant_id` predicate is a breach class |
| Feature flags | Flags that skip AuthZ in “emergency” become the incident |

## Architecture connection

Capstone platform:

```
users --> notes-api --audit--> soc-lite <--analyst
                |                 ^
                +--X--> mock-imds | detections as code
                                  v
                             agent (approve)
```

Your design review should say which arrows are allowed.

## Hands-on lab — security review of the platform

### Prerequisites

You have run modules 4–12 once.

### Steps

1. Read `labs/compose.yaml` and list trust boundaries.
2. File five findings in a table: severity, location, rec, residual risk.
   Suggested: default LAB_MODE true; JWT in env; container user possibly
   root; no rate limit; agent LLM optional data path.
3. Propose a production-shaped variant: LAB_MODE off, OIDC login, parameterized
   SQL, IMDS blocked at three layers (app, network, hop limit), signed
   images, detections in CI replay.
4. Write “what we will not automate”: e.g. disabling user accounts without
   human approval.

### Expected observations

A findings list that a staff engineer could action. Not a vendor pitch.

### Security lessons

Defense in depth is independent mechanisms. Observability is part of the
architecture diagram, not an add-on slide.

### Common mistakes

- “We’ll put it on the service mesh” as the entire AuthZ story.
- Secrets in IaC state with no rotation.
- CI with write to prod.

### Cleanup

None.

## Knowledge check

1. Why is VPC-only exposure not object AuthZ?
2. Name two independent controls against SSRF-to-IMDS.
3. What does pinning a digest not protect against?
4. Why are retries a security concern?
5. Where should threat modeling sit in an SDLC?

**Answers:** (1) Any workload in the VPC can call you. (2) App allowlist +
no network route / IMDSv2 + least-privilege role. (3) Compromised signer or
malicious but pinned content. (4) Amplification and confusion with attacks.
(5) Design review, before code freeze, updated when threats change.

## Engineering assignment

One-page architecture decision record: “How notes-api will authenticate
service callers in production.” Options, choice, residual risk.

## Further reading

- [CISA Secure by Design](https://www.cisa.gov/securebydesign)
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- [SLSA](https://slsa.dev/)
- [CNCF software supply chain](https://github.com/cncf/tag-security)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
