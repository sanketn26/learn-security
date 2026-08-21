# Onboarding — security from an engineer's point of view

You already know more of the foundation than the course previously made
visible. A request crosses a network, reaches a process, carries an identity,
reads data, and emits logs. Security asks whether each transition is allowed,
whether an assumption can be abused, and whether you could prove what happened.

## The only prerequisites for the first module

You should be able to:

- recognize an HTTP request and response;
- use a terminal to change directories and run a command;
- read a small Python function, even if you do not write Python daily;
- understand that a container packages a process and its dependencies.

You do **not** need to know ATT&CK, SIEM, EDR, OAuth, Kubernetes RBAC,
cryptographic algorithms, incident response, or offensive-security tools.
Those are taught when they become useful.

If Docker, Python, or networking is unfamiliar, use the previews below and
take the standard path slowly. Optional Kubernetes, packet capture, image
scanning, and LLM exercises can all be skipped.

## Ten translations from engineering to security

| Familiar engineering idea | Security lens |
| --- | --- |
| A database row or service | Asset: something worth protecting |
| Public method or API route | Attack surface: a reachable way to interact |
| API/service boundary | Trust boundary: input crosses into different trust |
| Bug or unsafe design assumption | Vulnerability |
| Failure scenario with an actor and impact | Threat scenario |
| Likelihood and consequence in context | Risk |
| Guard clause, policy, isolation, backup | Security control |
| Request identity | Authentication: who/what is calling? |
| Business rule on the requested object | Authorization: may it do this? |
| Logs, metrics, traces | Telemetry; it becomes evidence when relevant and preserved |

## The five questions to ask on every page

```text
1. What is normal?
2. Which trust assumption can fail?
3. What can an attacker gain conceptually?
4. Which evidence is produced?
5. Which design change prevents, limits, or reveals it?
```

Do not memorize acronyms on first contact. Use the [glossary](glossary.md),
then return to the concrete request or system diagram.

A second, overlapping checklist lives in
[How defenders think](how-defenders-think.md) — invert the path, follow blast
radius, name the cheapest path to the asset, attack your own detection
claim, and prefer a smaller system to a smarter control. Use both. The five
questions above orient you on a page; the thinking guide is how you invent
a control, a detection, or a quarantine switch that the page does not
already name.

## A gentle preview without Docker

Imagine Alice sends `GET /notes/2` with a valid login token. Note 2 belongs
to Bob.

```text
Alice --valid identity--> API --missing owner check--> Bob's note
```

- Authentication succeeds: the API knows this is Alice.
- Authorization should fail: Alice does not own Bob's note.
- The vulnerability is the missing owner check.
- A useful audit event records actor `alice`, object `note:2`, owner `bob`,
  action `read`, and decision `denied`—without recording the note body/token.
- The best fix is the owner check. An alert is useful but does not undo theft.

That single example carries through foundations, identity, APIs, logging,
detection, incident response, and architecture. The lab simply lets you see
the cause and effect yourself.

## How to study a module

1. Read the module's "Why it matters" and its **Visual overview** section
   (diagrams, intuition, hints) first.
2. Read the learning objectives.
3. Skim unfamiliar key concepts; use the glossary instead of stopping to
   memorize them.
4. Predict normal and abnormal outcomes before running commands.
5. Complete the required lab steps and record evidence.
6. Explain “what just happened” in your own words.
7. Answer the knowledge check without notes, then correct your model.

Move on when you can explain the request, boundary, failure, evidence, and
fix. You do not need perfect recall of every framework name.

