# Module 17 — Phishing, social engineering, and insider risk

## Why it matters to a software engineer

Every technical control in this course — MFA, object authorization, egress
allowlists, detection rules — assumes an attacker starts from *outside* with
*no* valid credential. In most real breaches that assumption is false on
day one: the attacker starts with Alice's password because Alice typed it
into a fake page, or the "attacker" is a legitimately authenticated employee
misusing access they were actually granted. This module is deliberately
**not** hands-on the way Modules 1–13 are — there is no safe, local way to
simulate email-based social engineering the way `simulate.py` simulates
SSRF — but it changes how you read every detection in this course, so it
belongs here rather than being skipped.

## Learning objectives

- Distinguish phishing (credential/access theft via deception) from insider
  risk (misuse of access someone was legitimately granted).
- Explain why technical controls change *where* the attack starts, not
  *whether* the human/organizational layer can be attacked.
- Read DET-001 and DET-004 as evidence of two different human-factor
  scenarios, not just two different technique IDs.
- Name the controls that work when the attacker already holds a valid
  credential.

## Key concepts

**Phishing changes the starting point, not the rest of the kill chain.**
Once Alice's password is phished, everything downstream — login, token
issuance, object access — proceeds exactly as it would for Alice herself.
This is why Module 3's authentication/authorization split matters so much:
authentication having succeeded (a real password, a real MFA prompt
approved under pressure) tells you nothing about whether the *request* that
follows is one Alice intended.

**Insider risk is not a technical vulnerability.** DET-004 (broken
function-level authorization: a non-admin calling an admin endpoint) is a
missing-control story. A *true* insider incident looks different: a
legitimately admin-privileged account doing something within its technical
permissions but outside its business justification — reading every
customer's notes with no ticket, no case, no reason. No authorization check
catches that, because the access was authorized. Only audit review, least
privilege, and anomaly detection on legitimate access patterns catch it.

**Both leave a similar-looking evidence trail with a different response.**
An unusual burst of note reads by one actor could be an automated scraper
using a stolen token (phishing case: rotate the credential, review scope of
compromise) or an employee doing something they are not supposed to
(insider case: HR/legal process, not a token rotation). The SOC (Module 10)
has to hold both hypotheses open until evidence — not the alert alone —
distinguishes them.

**MFA and phishing-resistance are not the same property.** Any MFA raises
the cost of a phished password alone. *Phishing-resistant* MFA (passkeys,
hardware security keys using WebAuthn) specifically defeats real-time
credential-relay phishing, where the attacker proxies the login in real
time including the MFA prompt. A one-time code can still be relayed; a
hardware-bound key cannot.

**Least privilege is the only control that limits insider blast radius.**
You cannot detect your way out of a legitimately authorized action. The
only thing that bounds the damage of a trusted actor going wrong is how
much that actor was trusted with in the first place — which is Module 1's
"residual risk" idea applied to your own team, not just to attackers.

## Architecture connection

Add "the human holding a valid credential" as an explicit actor in your
Module 1 trust-boundary diagram, distinct from "the untrusted internet."
Every box that trusts a token implicitly trusts whoever is currently
holding it. Design reviews that only ask "is this endpoint authenticated"
and never ask "what if the authenticated caller's intent is wrong" are
missing this actor entirely.

## Hands-on lab — read two identical-looking alerts, two different ways

No new containers; this reuses alerts you can already generate.

### Prerequisites

`make lab-up`; alerts exist from Module 9/11 (`simulate` + `ingest`, or
`python3 labs/attack-sim/simulate.py --scenario all`).

### Steps

1. Pull DET-001 (password guessing) and DET-004 (broken function-level
   authorization) alerts from soc-lite.
2. For DET-001, write two competing incident narratives from the same
   evidence: (a) an external attacker guessing Alice's password, (b) Alice
   herself, having forgotten her password, retrying it — and note what
   *additional* evidence (source IP reputation, geographic distance between
   attempts, time-of-day pattern) would let you tell them apart.
3. For DET-004, write two competing narratives: (a) a bug lets a non-admin
   token reach an admin route, (b) an admin account was phished and the
   attacker is now probing available endpoints. Note that the *technical*
   fix (authorization check) is identical either way, but the *incident*
   response is not — (b) requires credential rotation and scope review,
   (a) does not.
4. State, for each narrative, one control that would have prevented it
   regardless of which story is true (hint: rate limiting from Module 16
   helps DET-001 either way; least privilege helps DET-004's insider
   variant even when the authorization bug is also fixed).

### Expected observations

Two short written narratives per alert, each naming the specific additional
evidence that would resolve the ambiguity, and one "works regardless of
which story is true" control per alert.

### Security lessons

An alert is evidence, not a verdict. The same event stream is compatible
with an external attacker, a confused legitimate user, and a misbehaving
insider; good incident response keeps competing hypotheses open (Module 11)
specifically because the human-factor layer cannot be ruled out by log
data alone.

### Common mistakes

- Assuming every alert implies an external attacker, which biases the
  response toward "block an IP" and away from "review who actually holds
  this credential right now."
- Treating "insider threat" as a monitoring product to buy instead of a
  least-privilege and process question.
- Recommending security-awareness training as if it were a complete
  control. It reduces phishing susceptibility; it does not replace
  phishing-resistant MFA or least privilege, the same way "code review"
  does not replace parameterized queries.

### Cleanup

`make lab-down`.

## Knowledge check

1. Why does successful authentication tell you nothing about whether a
   request reflects the account holder's intent?
2. Why is a one-time code weaker than a hardware key against phishing,
   even though both are "MFA"?
3. What distinguishes a phishing incident from an insider incident when the
   technical evidence looks the same?
4. What is the only control that bounds the damage of a legitimately
   authorized actor?
5. Why should an alert like DET-004 keep two competing narratives open
   during triage?

**Answers:** (1) Authentication proves identity, not intent — the same
"valid token is not proof of permission" idea from Module 3, applied to the
human holding the token. (2) A one-time code can be relayed in real time by
a proxying attacker; a hardware key's response is bound to the origin and
cannot be relayed. (3) Whether the access was ever authorized in the first
place — phishing steals unauthorized access, insider misuse abuses
authorized access. (4) Least privilege — how much authority that actor
holds if they go wrong. (5) Because the response differs (credential
rotation and scope review vs. an authorization bug fix), and picking the
wrong one wastes the response window without addressing the real cause.

## Engineering assignment

Write a one-page policy answering: which of your team's accounts or
service identities would cause the most damage if phished, and which would
cause the most damage if legitimately misused by their holder? They are not
always the same account. Name one control for each.

## Further reading

- [CISA Phishing-Resistant MFA](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf)
- [Verizon Data Breach Investigations Report](https://www.verizon.com/business/resources/reports/dbir/)
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [CISA Insider Threat Mitigation](https://www.cisa.gov/topics/physical-security/insider-threat-mitigation)
