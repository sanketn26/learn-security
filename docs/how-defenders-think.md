# How defenders think

The rest of this course teaches vocabulary, controls, and lab procedures.
This page is the missing layer: **how to invent a next move** when the
checklist does not already contain the answer. Use it as a companion from
Module 1 through the capstone. Re-read it after Modules 4, 7, 11, and 13.

Ingenuity in security is not clever exploits. It is asking a better question
about a system you did not design, then proving or disproving the answer
with evidence.

## Five moves that generate ideas

These are habits, not a framework. Steal them into design reviews.

**1. Invert the happy path.**
Take any arrow on a diagram and ask what happens if it is forged, delayed,
duplicated, or omitted. The interesting bug is usually not “the request
succeeds.” It is “the request succeeds *for the wrong reason*.” Alice’s
valid token on Bob’s note is this move.

**2. Follow the blast radius, not the bug.**
A missing owner check is a one-line defect. The security question is *what
else that identity can reach once it is inside*: other notes, `/admin`,
`/fetch`, the metadata service, the JWT secret, the log volume. Draw the
radius before you argue about severity.

**3. Name the cheapest path to the asset.**
Attackers optimize for cost. If Bob’s payroll note is the asset, guessing
Alice’s password, stealing her session, and calling `/notes/2` are three
different costs. Design and detection should worry about the cheap paths
first. Exotic kernel exploits are rarely the cheapest path to a JSON API.

**4. Ask what must be true for you to notice.**
A detection is a claim: “if this happens, this field will exist, in this
window, grouped by this key.” Write the claim down, then attack the claim
— delayed ingest, missing `actor`, shared NAT `src_ip`, clocks skewed,
the attacker switching identities. The holes in the claim are the real
detection work.

**5. Prefer a smaller system to a smarter control.**
The best finding in a design review is often “delete the route.” `/fetch`
that can reach metadata, `/docs` left on in production, a debug port bound
to `0.0.0.0` — these are attack surface. A WAF in front of a route you do
not need is theatre. Shrinking the system is a control.

## Attack surface is a budget

Attack surface is every reachable way to interact: HTTP routes, identity
issuers, CI jobs, admin tools, metadata services, uploaded files, LLM
tool APIs. Treat it like a budget you spend deliberately.

- **Inventory before you harden.** You cannot reduce what you have not
  listed. The lab API’s surface includes `/login`, `/notes`, `/notes/{id}`,
  `/search`, `/admin/users`, `/fetch`, `/whoami`, `/health`,
  `/.well-known/lab`, and — in `LAB_MODE` — `/docs` and `/openapi.json`.
- **Default deny the exotic.** Server-side fetch, admin dumps, OpenAPI UI,
  and debug endpoints should have to justify their existence, not their
  absence.
- **Every new integration is a new surface.** A hosted embedding API, a
  webhook, a model tool — each is a trust boundary you just drew, whether
  or not it appears on the architecture slide.

Reducing surface is usually cheaper than detecting abuse of a surface you
did not need. Detection is what you buy for the surface that has to stay.

## Bulkheads: limit how far a failure travels

A bulkhead is a partition that keeps one flooded compartment from sinking
the ship. In software it is a **failure domain**: a place where a
compromise, a bug, or a runaway process is *allowed* to hurt, and a place
it is not.

```text
without bulkheads:  stolen Alice token --> every note, admin list, IMDS keys, SOC actions
with bulkheads:     stolen Alice token --> Alice's notes only
                    IMDS unreachable from the app network
                    agent cannot act without a human
                    logs live off the app host
```

Engineering bulkheads you already know under other names:

| Bulkhead | What it contains | Lab / production example |
| --- | --- | --- |
| Object authorization | One identity’s blast radius | Owner check on `GET /notes/{id}` |
| Network partition | What a workload can *call* | No route from app to IMDS; `labnet` vs public egress |
| Separate credentials | How far a stolen secret goes | Per-service cloud role, not one key for the cluster |
| Separate data stores | How far a query or injection goes | Per-tenant DB or `tenant_id` on every predicate |
| Process / container isolation | How far a RCE goes | Non-root, no host mounts, dropped capabilities |
| Rate limit / timeout | How far a cheap request goes | Cap `/login` *before* bcrypt |
| Human approval | How far an agent or SOAR playbook goes | `approval=APPROVE` on respond tools |
| Evidence off-box | How far an attacker who lands on the app can rewrite history | Ship logs out; `preserve-logs.sh` copies off the volume |

Defense in depth is **independent** bulkheads, not five copies of the same
wall. If the app allowlist, the network policy, and the IMDS hop limit all
fail the same way (they all trust “this hostname looks safe”), they are
one control wearing three hats.

Design question for every new box: *if this box is wrong or compromised,
what is the largest thing it still cannot do?* If the answer is “nothing —
it can do everything,” you do not have a bulkhead. You have a single
point of failure with extra YAML.

## Detection is a hypothesis, not a regex

A useful detection starts as a sentence a skeptic could test:

> If an authenticated user reads another user’s note, we will see event
> `cross_user_note_access` with `actor ≠ owner` within one minute, grouped
> by actor, and DET-002 will fire.

That sentence names **telemetry**, **logic**, **window**, **grouping**, and
**output**. If any of those is untrue, you do not have coverage. You have
a hope.

### Event time versus processing time

A window of “5 failures in 120 seconds” is meaningless until you say
**120 seconds of what**. Wall-clock at ingest time punishes you for
reading the docs before you POST `/ingest`. Event time — “120 seconds
between the first and last event in the bucket” — matches the adversary’s
behavior. soc-lite evaluates DET-001 on **event time** for that reason.
In production, delayed pipelines, clock skew, and “the collector was
down” are the same bug class: your window is measuring the wrong clock.

### Grouping keys lie

DET-001 groups by `src_ip`. Behind NAT or Docker’s gateway, every student
on the lab looks like one IP — or every attacker on a corporate proxy
does. DET-002 groups by `actor`. An attacker who rotates accounts will
not meet a per-actor threshold. When a detection is quiet, ask whether
the grouping key is what the adversary actually shares.

### Detect attempts, not only wins

`LAB_MODE=false` turns `ssrf_metadata_access` into `ssrf_blocked`. The
control worked; the old alert goes silent. That is a **detection gap for
the attempt**. Purple-team the blocked path. A bulkhead nobody can see
working will be removed in the next “cleanup” PR.

### Quarantine is containment that preserves the system

People jump from “alert” to “delete the user / kill the pod / wipe the
disk.” That is eradication-shaped action taken too early, and it often
destroys the evidence you needed.

**Quarantine** means: isolate the suspected thing so it cannot cause
further harm, while you still have it to inspect.

| Isolate this | Quarantine move | Not this |
| --- | --- | --- |
| A session / token | Revoke or block that credential; leave the user row | Delete the employee’s account before you know it was phishing vs insider |
| A workload | Network-policy it off IMDS and off data stores; snapshot the disk | `docker compose down -v` mid-incident |
| An identity | Disable the key / freeze the role; keep audit | Rotate every secret in the company as step 1 |
| A tenant | Fail closed for that tenant; others keep serving | Global maintenance page |
| An agent tool | Deny respond-class tools; keep read tools | Unplug the model so you also lose the timeline summary |

Good systems are **quarantine-ready**: you can disable one identity, one
tenant, one egress path, or one agent tool without collapsing the product.
If the only switch you have is “turn the API off,” you designed a single
compartment.

Containment (quarantine) happens while investigation is still open.
Eradication (fix the owner check, rotate the role) happens when you know
what was actually wrong. Recovery is proving the cheap path is gone —
replay the same request.

## Design for the failure you will have

Assume breach is not pessimism. It is a design constraint: a token will
leak, a dependency will be hostile, an analyst will click APPROVE on a
fluent wrong summary. Then ask:

- Can that failure be **partitioned** (bulkhead)?
- Can it be **noticed** (telemetry + a testable detection claim)?
- Can it be **isolated without destroying evidence** (quarantine)?
- Can the remaining surface still do the job (least privilege, not least
  function)?

If you cannot answer those four, you do not yet have a safety property.
You have a list of controls.

## A 10-minute drill for any system

Use this on notes-api, on a PR, or on a service you own. No tools required.

1. Circle the asset (the thing whose disclosure, change, or absence hurts).
2. List three reachable surfaces. Delete one on paper. What breaks?
3. Pick one identity. Write the blast radius if it is stolen.
4. Draw one bulkhead that would shrink that radius without new product
   features (owner check, egress deny, shorter token, separate role).
5. Write one detection claim in a single sentence, including the field and
   the window clock you are using.
6. Write one quarantine switch you wish existed (block this actor, this
   tenant, this egress, this tool) and whether the system can do it today.
7. State residual risk in one line: what still works for the attacker after
   4–6.

The drill is the whole course in miniature. Modules teach you the names
of the parts. This page is how you keep inventing the next part yourself.
