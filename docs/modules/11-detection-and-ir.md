---
description: Treat detections as tested code and run incident response through NIST SP 800-61 containment, eradication, and recovery.
---

# Module 11 — Detection engineering and incident response

## Why it matters to a software engineer

Detections are code. They have false positives, owners, tests, and decay.
Incident response is a project under time pressure: preserve evidence,
decide severity, contain, eradicate, recover, communicate. NIST now frames
IR inside CSF 2.0 ([SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)).
Many SOCs still teach the Rev. 2 loop (prepare → detect/analyze →
contain/eradicate/recover → post-incident). Use both: the loop for muscle
memory, CSF for “IR is not only the IR team.”

## Visual overview

```mermaid
flowchart LR
  H[Threat hypothesis] --> T[Required telemetry]
  T --> L[Detection logic]
  L --> TEST[Test fixtures / replay]
  TEST --> A[Alert]
  A --> F[Analyst feedback]
  F --> L
```

!!! note "Intuition"
    A detection rule is code, and code without tests degrades silently. The
    `TEST` node is not optional polish — it's the difference between "I wrote
    a rule that I believe detects SSRF" and "I have a fixture that proves
    this rule fires on SSRF and stays quiet on normal traffic."

```text
Detection -> validate -> scope -> contain -> eradicate -> recover -> learn
```

| Signature/IOC | Anomaly | Behavior |
| --- | --- | --- |
| Known value/pattern | Deviation from baseline | Meaningful sequence/action |
| Precise but brittle | Finds novelty but can be noisy | More resilient, needs context |

Preserve originals, inventory evidence, state competing hypotheses, build a
UTC timeline, separate root cause from contributing controls, and verify
recovery by replay. Sigma expresses log-query ideas portably; YARA describes
content patterns. Neither is a complete investigation.

!!! tip "Hint"
    "State competing hypotheses" is the step most people skip under time
    pressure, and it's the one most likely to save you from an embarrassing
    correction later. Write down the boring explanation ("scheduled job,"
    "known test traffic") alongside the alarming one before you start
    digging — it costs one sentence and it is often the answer.

## Learning objectives

- Write detection logic as rules with thresholds and stated assumptions.
- Explain Sigma-like portability and YARA at a conceptual level.
- Investigate a simulated account-compromise / data-exposure case.
- Produce a timeline, incident report, RCA, and remediation plan.

## Key concepts

**Detection logic.** Boolean or statistical conditions on telemetry.
**Thresholds.** 5 failures / 120s — arbitrary until purple-tested.
**Baselines.** “Unusual” needs a usual. Hard in tiny labs; crucial in prod.
**Behavioral analytics.** Sequences and outliers, not a single IOC.
**Detection-as-code.** Rules in git (`labs/detections/rules.yaml`), reviewed,
tested with replayed JSONL, versioned with ATT&CK tags.

**Sigma.** An open generic signature format for logs, convertible to SIEM
queries. Our YAML is *Sigma-like* (event, fields, threshold), not a full
Sigma backend.

**YARA.** Pattern language for files/memory (malware hunting). You do not
need YARA for JSON API logs. Do not download malware to “try YARA.”

**Queries.** `/events?q=` is a toy. Production: constrain time, index, cost.

**Correlation.** Joining multiple *individually weak* events — across
sources, across time, sharing an actor or asset — into one higher-
confidence story, instead of paging an analyst once per event. This is a
different idea from Module 7's correlation ID (which threads *one
request* through *one system*): correlation here threads *one actor or
asset* through *many independent events*, possibly minutes or hours apart,
possibly from rules that don't know about each other. Concretely in this
lab: DET-001 (password-guessing burst) and DET-002 (cross-user note
access) are independent rules, each firing its own alert. A real SIEM's
correlation layer would ask "did the same `actor`/`src_ip` trigger both,
within one window?" and — if so — raise one case with higher severity
("credential guessing immediately followed by data access") instead of
two disconnected low-context alerts an analyst has to notice are related
by hand. Correlation is what turns a pile of alerts into an incident
narrative before a human even opens the case.

**Threat intelligence.** External data about what's known-bad, consumed
as an *enrichment* input to correlation and triage, never as ground truth
on its own. Concretely: a feed is typically a list of indicators (IPs,
domains, hashes, or higher-level "this actor's known TTPs") with a
confidence score and an age. Two things make intel different from your
own telemetry:

- **It answers a question your own data structurally cannot.** Your logs
  can show `src_ip=203.0.113.4` connected; only external data can tell you
  that IP is a known Tor exit node or was flagging phishing infrastructure
  last week.
- **It decays, and it can be wrong.** An IP flagged bad six months ago may
  be reassigned to an innocent host today; a feed vendor's false positive
  becomes *your* false positive if you treat a match as fact. Use intel to
  raise or lower a detection's *confidence* and *priority* — "this alert
  also matched a known-bad indicator, escalate it" — not to auto-decide
  guilt. That is the entire content of "without treating intel as gospel"
  above.

The lab has no intel feed to query — practice the judgment on paper: if
DET-001's `src_ip` (the password-guessing burst) matched a public feed's
"known scanner" indicator, how would that change your triage of the
*same* evidence you already have — and what would NOT change (the
underlying missing-rate-limit root cause still needs fixing either way)?

**Worked example: one alert through the full pipe.** Trace a single
password-guessing attempt from raw event to a correlated, prioritized
case:

1. **Collection.** notes-api emits a raw JSON line for one failed login:
   `{"ts":"2026-08-24T10:02:11Z","event":"login_failure","username":"alice","src_ip":"203.0.113.4"}`.
   If this had come from a legacy edge firewall instead of notes-api, it
   might have arrived as
   `CEF:0|VendorX|EdgeFW|1.0|4001|Auth failure|3|src=203.0.113.4 suser=alice`
   — same fact, different shape.
2. **Normalization.** Both forms get mapped to the same schema field names
   (`actor`, `src_ip`, `event`) so a rule written once can match either
   source. This is the step that makes step 1's two formats interchangeable.
3. **Enrichment.** The normalized event is joined with: internal context
   (alice's account is a regular user, not an admin) and external context
   (a threat-intel lookup on `203.0.113.4` — say it matches a "known
   credential-stuffing infrastructure" indicator, confidence medium, seen
   14 days ago).
4. **Correlation.** Five more `login_failure` events from the same
   `src_ip` land in the next 90 seconds (DET-001's actual threshold in
   this lab: 5 in 120s), then — 40 seconds after the fifth failure — a
   `cross_user_note_access` event fires for `actor=alice`. Correlated by
   shared actor within one short window, these become **one case**:
   "credential-guessing burst immediately followed by cross-user data
   access from the same identity," not two disconnected low-context
   alerts.
5. **Detection / prioritization.** DET-001 alone, with no intel match and
   no follow-on access, might be routine noise a real SOC auto-tunes down
   (scanners guess passwords constantly). The same DET-001 correlated with
   DET-002 *and* an intel match on the source is a different-severity
   incident entirely — same underlying facts, but the pipe's later stages
   are what turned "one low-value alert" into "escalate now."

Notice what did **not** change anywhere in that pipe: the actual fix is
still the missing rate limit (Module 16) and the missing per-object
authorization check (Module 4). Intel and correlation change how fast you
notice and how you prioritize — never what the permanent repair is.

**The Diamond Model.** A structuring tool for one intrusion event, not a
replacement for the timeline: every event has an **adversary** using a
**capability** over some **infrastructure** against a **victim**.

```text
        Adversary
        /        \
Capability ---- Infrastructure
        \        /
         Victim
```

Fill in what you actually know and mark the rest unknown — for DET-002 in
this lab: adversary = "Alice's session, attribution unknown"; capability =
"a valid token plus another user's object id, no exploit tooling";
infrastructure = "the notes-api itself, no external C2"; victim = "Bob's
note." An empty adversary corner is normal and honest; guessing to fill it
is not. Pivoting along one edge (same infrastructure, different victim;
same capability, different adversary) is how you find related activity you
were not already looking for.

**Incident severity.** Combine impact (data class, blast radius) and
urgency (active vs historical). Dummy payroll note → practice as high.

**Evidence preservation and chain of custody.** Copy, hash, write who/when,
do not edit originals. Lab: `preserve-logs.sh` writes
`labs/evidence/evidence-*` (survives `lab-reset`). The script copies; **you**
hash (`shasum labs/evidence/evidence-*/**`). This is not courtroom-grade
forensics; it teaches the habit.

**Quarantine vs eradicate.** Isolate the suspected identity or egress path
*while you still have the evidence* — disable `LAB_MODE` or block `/fetch`
to metadata without `down -v`. Eradicate after you know the cause (owner
check, rotate JWT). See [How defenders think](../how-defenders-think.md).

**Containment / eradication / recovery.**
Contain: stop the bleeding (disable LAB_MODE, rotate JWT secret).
Eradicate: remove the weakness and any persistence (none in lab).
Recover: restore service, watch for recurrence.
Communicate: who needs to know (in the lab: your report readers).

**Classic IR loop (still useful operationally).**
Prepare; detect & analyze; contain, eradicate, recover; post-incident.
Rev. 3 asks you to also **govern and identify** continuously so IR is not
a surprise.

## Architecture connection

```
rule in git --> deploy to soc-lite --> fire on JSONL
incident --> preserve --> timeline --> RCA --> new rule or patch --> retest
```

## Worked walkthrough — authoring DET-001

Open `labs/detections/rules.yaml` and find **DET-001**. Do not skip to a
fixture. A detection is a **claim** a skeptic can test
([How defenders think](../how-defenders-think.md)): telemetry, fields,
grouping key, window clock, threshold, and what must stay quiet. Walk the
existing password-guessing rule in that order. Then write additional rules
yourself — this page will not publish them.

**AUTHORIZED LAB USE ONLY.** Replay only against synthetic JSONL for this
lab.

### Threat hypothesis

Someone will try many passwords against Acme Notes `/login` from one source
in a short span, hoping a dummy account yields a session. That is
credential access, not yet object theft. The claim is: *if that burst
happens, we will see it in application logs and raise one alert, even if
no password is correct.*

Prevention (rate limit, lockout, MFA) is a different control. DET-001 does
not stop guessing; it notices a pattern the login handler already emits.

### Expected telemetry

`POST /login` with a wrong password must emit `login_failure` *before* the
401 body. `labs/notes-api/app.py` does that: it audits, then raises 401.
A success is `login_success` — a different event. DET-001 must not treat
successes as guesses.

If the app logged only `"login failed"` with no source and no timestamp,
the hypothesis would be untestable. Telemetry is a product feature for this
rule.

### Fields

The evaluator matches `event == login_failure`. Useful fields on that line:

| Field | Why DET-001 needs it |
| --- | --- |
| `ts` | Event-time window (not “when we ingested”) |
| `event` | Selection |
| `username` | Who was targeted (evidence, not the grouping key) |
| `src_ip` | Grouping key |
| `trace_id` | Dedup / join with other lines from the same request |

`actor` is often empty on failures: there is no authenticated subject yet.
soc-lite’s group-key helper falls back to `username` when a listed field is
missing — which is why grouping **must** be `src_ip` here, not `actor`.

### Grouping key

`group_by: [src_ip]`. One alert id looks like `DET-001:172.30.0.1` (or
whatever source the container saw). Behind Docker’s gateway or NAT, many
guessers can collapse to one IP — noisy — or one guesser on many IPs can
split buckets and stay under the threshold — a miss. When the rule is
quiet, ask whether the adversary shared the key you grouped on.

### Window

`window_seconds: 120`. soc-lite measures **event time**: 120 seconds between
the newest `login_failure` in the bucket and the earlier ones, not wall
clock at `POST /ingest`. Delayed ingest still fires. A collector outage
still means you cannot see failures that were never written.

### Threshold

`threshold: 5`. Five matching events in that window from one `src_ip`.
`simulate.py --scenario brute_force` sends **six** wrong passwords so the
rule has margin. Four failures in two minutes is intentional quiet.

Five-in-120s is arbitrary until you purple-test it. It is not a property of
password guessing; it is a tradeoff you own.

### False positives

Legitimate bursts: shared NAT or a lab full of students; a password-manager
retry loop; an integration test that hammers `/login`; an operator who
typed the staging password four times and then the right one.

Write those in the rule’s operational notes (Sigma-style `falsepositives`)
so the next tuner does not “fix” them by disabling the rule. A detection
with no recorded FPs has usually never been run against real traffic.

### ATT&CK mapping

| Field | DET-001 |
| --- | --- |
| Tactic | Credential Access |
| Technique | T1110.001 Password Guessing |
| Playbook | `brute-force.md` |
| Confidence | High for *this procedure* (HTTP login failures from one IP) |
| Limitation | Not credential stuffing from many IPs; not a successful guess by itself; not availability/DoS (same telemetry, different response — Module 16) |

ATT&CK is the language for the behavior, not proof that an APT was in your
compose stack. Do not paint Persistence or C2 cells from this rule.

### Replay fixture

Write the claim *before* you look at events: five-plus `login_failure`
lines from one `src_ip` inside 120 seconds of **event** time must fire
`DET-001`; one or two failures, or a `login_success`, must stay quiet.

??? question "Expand after you write the claim — DET-001 JSONL example only"
    Abnormal (must fire). Six failures, same `src_ip`, ~90 seconds of event
    time — the same shape as `simulate.py` brute_force. TEST-NET `203.0.113.50`
    is documentation; the lab often sees the Docker gateway instead.

    ```json
    {"ts":"2026-08-24T10:00:00.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-abn-1","username":"alice","src_ip":"203.0.113.50"}
    {"ts":"2026-08-24T10:00:12.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-abn-2","username":"alice","src_ip":"203.0.113.50"}
    {"ts":"2026-08-24T10:00:24.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-abn-3","username":"alice","src_ip":"203.0.113.50"}
    {"ts":"2026-08-24T10:00:36.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-abn-4","username":"alice","src_ip":"203.0.113.50"}
    {"ts":"2026-08-24T10:00:48.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-abn-5","username":"alice","src_ip":"203.0.113.50"}
    {"ts":"2026-08-24T10:01:00.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-abn-6","username":"alice","src_ip":"203.0.113.50"}
    ```

    Normal (must stay quiet). Two failures and a success from the same IP
    are not a guessing burst under this threshold.

    ```json
    {"ts":"2026-08-24T11:00:00.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-ok-1","username":"alice","src_ip":"203.0.113.50"}
    {"ts":"2026-08-24T11:00:08.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"det001-ok-2","username":"alice","src_ip":"203.0.113.50"}
    {"ts":"2026-08-24T11:00:20.000000Z","event":"login_success","service":"notes-api","lab_mode":true,"trace_id":"det001-ok-3","username":"alice","role":"user","src_ip":"203.0.113.50"}
    ```

    Store both sides as JSONL and assert `DET-001` on the abnormal file and
    no `DET-001` on the normal file. This page does **not** include replay
    fixtures for DET-002–005. Author those tests yourself if you need them.

??? question "Finished DET-001 fields (confirm against rules.yaml)"
    `event: login_failure`, `group_by: [src_ip]`, `threshold: 5`,
    `window_seconds: 120`, `severity: medium`, ATT&CK T1110.001, playbook
    `brute-force.md`. If your copy differs, the file on disk wins.

### Tuning decision

Keep 5/120s for the lab: `simulate.py` is supposed to be loud, and the
playbook tells L1 not to lock real accounts. Document the FPs (shared
`src_ip`, retries) instead of raising the threshold until the sim no
longer fires. A slow guesser (one failure every minute) is an accepted
false negative until you add a longer-window rule or a control that does
not depend on burstiness (rate limit, MFA). Changing only the number
slides FPs into FNs; a better grouping key or an attempt-vs-success
correlation is the actual upgrade.

### Your turn — additional rules

DET-001–005 are the starting pack. The [capstone](../capstone/README.md)
requires **at least three more rules you author**, against event types those
five do not already cover, each with a replay fixture that fires on the
abnormal case and stays quiet on normal traffic. Repeat this walkthrough
for every rule you add. This module will not publish those rules, their
fields, or their fixtures.

## Hands-on lab — investigate simulated exposure

**AUTHORIZED LAB USE ONLY.** Use the lab sim as the “attacker.”

### Prerequisites

Prefer a fresh story:

```bash
./labs/scripts/lab-reset.sh
./labs/scripts/lab-up.sh
python3 labs/attack-sim/simulate.py --scenario all
curl -s -X POST http://127.0.0.1:8090/ingest
./labs/scripts/preserve-logs.sh   # writes labs/evidence/, survives lab-reset
```

### Before you run this

Predict: (1) which evidence appears (2) which does not (3) why.

Then run the steps. Compare with the prediction. If the result differs,
which assumption was wrong?

### Steps

1. List alerts; open one case for “possible account misuse / data exposure.”
2. Build a **timeline** (table: time, event, actor, object, source). Default
   `GET /events` is **newest-first** (`order=desc`). For a chronology:

   ```bash
   curl -s 'http://127.0.0.1:8090/events?order=asc&limit=500'
   ```

   Or query one event type at a time (`?event=cross_user_note_access&order=asc`)
   and sort `ts` yourself. Default limit is 100. Include login_success,
   cross_user_note_access, ssrf_metadata_access, login_failure bursts.

   The sim concatenates six failures **and then** real logins for other
   scenarios. H2 (“password guessed then success”) will *look* supported.
   The true lab story is H3 (you ran `simulate.py`). In production you would
   need MFA/device evidence you do not have here.
3. Hypotheses:
   - H1: Alice is malicious insider
   - H2: Alice’s dummy password was guessed (DET-001 then success?)
   - H3: Lab operator ran simulate.py (true in this course)
   Record what evidence would distinguish H1/H2 in production (MFA, device
   posture, mail) that you **do not have** here. Sketch each hypothesis as a
   Diamond Model quad — H1 and H2 share victim and infrastructure but differ
   in adversary and capability, which is exactly why the telemetry alone
   cannot resolve them.
4. Impact: which notes, dummy IMDS keys treated as burned.
5. Containment (simulated): snapshot_logs, revoke_token_notice,
   disable_lab_mode via compose recreate with `LAB_MODE=false` **after**
   evidence copy.
6. Write `incidents/lab-incident.md` (you create) with:
   summary, severity, timeline, ATT&CK, RCA (root = missing object AuthZ
   and an application that would fetch metadata; the **lab safety rail**
   allowlist is always on — do not call that the missing control), fix,
   residual risk, detection gaps.
7. Purple: reset, bring the API up with `LAB_MODE=false` so hashes match,
   re-run idor; confirm **404** (not 403 — existence hiding). Blocked IDOR
   logs `authz_failure` / `idor_blocked`, not `cross_user_note_access`. Note
   whether an **attempt** detection exists (it does not, unless you add one).

### Expected observations

Ordered JSON events. Preserve dir untouched. After disable, IDOR fails.
Report distinguishes sim operator vs real Alice.

### Extra: tuning a threshold rule (false positives and false negatives)

Take a rule shaped like DET-001 but written more aggressively: *alert if a
user accesses more than 100 records in five minutes.* Work through it on
paper, then check your answers against the reasoning below.

1. What legitimate workflow would trigger this? (A bulk export feature, an
   admin running a data-quality report, a paginated "load all" UI action —
   any of these produce a burst of reads with no bad intent.)
2. How would an attacker avoid the threshold? (Stay under 100 in five
   minutes — 90 records every five minutes forever is invisible to this
   rule and just as damaging over a day.)
3. What additional signal would improve precision without just raising the
   number? (Object diversity — 100 reads of *your own* notes is normal;
   100 reads spanning 80 different owners is not. Group by
   `(actor, owner)` pairs, not just `actor`.)
4. What happens if you raise the threshold to 500 to kill the false
   positives from step 1? A new false negative appears: an attacker who
   paces themselves at 400 records per five-minute window now clears
   every 100-owner span undetected, and you have made the *real* attack
   slower to catch in exchange for fewer paged analysts.

The general lesson: a threshold alone trades false positives for false
negatives along one dial. The fix is usually a better *grouping key* or
added *context* (object diversity, actor's normal baseline, whether the
actor is delegated to the objects touched) — not a bigger or smaller
number on the same dial. This is also why the capstone rubric asks for
"documented FPs," not zero FPs: a detection with no recorded false
positives has usually never been run against real traffic.

### Extra: investigating with incomplete evidence

Real investigations rarely hand you a complete, well-formed timeline.
Before your next investigation (this lab's or a real one), assume at least
one of these is true, and decide how it changes your confidence:

- **A field is missing.** The `owner` field is absent from some
  `note_read` events (an older app version, a partial rollout). Can you
  still tell BOLA from a normal read? (No — without `owner`, a `note_read`
  event alone cannot prove or disprove cross-user access. State that gap
  explicitly rather than assuming innocence.)
- **Timestamps disagree.** The collector's ingest time and the event's
  own `ts` differ by minutes. Which do you trust for ordering the
  timeline, and what do you write in the report when they conflict?
- **One log source is down for part of the window.** `login_failure`
  events exist for the first half of the incident, then stop. Do you
  conclude the attacker stopped, or that the collector did?
- **Legitimate admin activity is mixed in.** An admin ran a bulk export
  during the same window as the suspicious reads. Which events are
  attributable to which actor, and where does your evidence actually
  distinguish them (hint: `actor`, not just timing)?

In every case, the correct move is the same: state what you know, state
what you cannot know from the available evidence, and do not fill the gap
with the more dramatic explanation by default. A root-cause analysis that
silently assumes complete evidence is a common, avoidable way investigations
go wrong under time pressure.

### Security lessons

Timeline before containment when possible. RCA names a systemic cause
(AuthZ missing) not “Alice was naughty.” Recovery includes tests.

### Common mistakes

- Skipping preservation.
- Declaring root cause “the attacker.”
- Publishing dummy IMDS keys into a public gist.

### Cleanup

`lab-reset` after you export the report.

## Knowledge check

1. What is detection-as-code’s main benefit?
2. Sigma vs YARA?
3. Why might threshold 5/120s miss a slow guesser?
4. Contain vs eradicate for SSRF-to-IMDS in cloud (conceptual)?
5. What does chain of custody protect against?

**Answers:** (1) Review, test, history. (2) Sigma ~ log rules; YARA ~ file
patterns. (3) Spread-out attempts stay under threshold. (4) Contain: block
IMDS/path, rotate role creds; eradicate: fix SSRF, reduce role. (5) Silent
alteration or disputed origin of evidence.

## Exit criteria

You pass this module when you can meet the course
[pass bar](../assessment.md) (Explain → Predict → Diagnose → Design →
Defend) on this material:

- ✓ Turn a threat hypothesis into a detection rule backed by a fixture that
  proves it fires on the abnormal case and stays quiet on the normal one.
- ✓ State a detection threshold's tradeoff: what legitimate behavior it
  might catch, and what slow/spread-out attack it might miss.
- ✓ Build a UTC timeline from ordered evidence and state at least two
  competing hypotheses before picking one.
- ✓ Distinguish quarantine (reversible, evidence-preserving) from eradicate
  (removes the weakness) for a given incident.
- ✓ Write a root-cause statement that names a systemic cause, not "the
  attacker."
- ✓ Preserve evidence before containment, and explain what containing first
  would have destroyed.
- ✓ Investigate an incident with incomplete telemetry and say what evidence
  would resolve it that you don't currently have.
- ✓ Explain how correlation differs from a per-request correlation ID, and
  combine two independently-firing rules into one prioritized case by a
  shared actor and time window.
- ✓ Use a threat-intel match to change an alert's priority without treating
  it as proof, and say what a false intel match would cost you.
- ✓ Defend one tradeoff: why a Sigma-style `falsepositives` field is part of
  the rule, not an afterthought.

## Engineering assignment

Convert DET-002 into a one-page Sigma-inspired rule (title, logsource,
detection, falsepositives, level, tags). You do not need a Sigma compiler.
Separately, author the additional capstone rules yourself using the
DET-001 walkthrough — do not wait for a published solution.

## Self-check

Answer before expanding. These are the [assessment](../assessment.md) moves
on this module's Acme Notes lab, not trivia.

??? question "Explain: What claim does DET-001 actually make?"
    If five or more `login_failure` events from one `src_ip` occur within
    120 seconds of *event* time, soc-lite will raise `DET-001`. It does not
    claim the password was guessed, that Alice is malicious, or that the
    source is a unique human.

??? question "Predict: What stays quiet if an operator POSTs /ingest an hour after six failures?"
    DET-001 still fires: the window is event time in the bucket, not wall
    clock at ingest. What does *not* appear is a second alert id for the
    same `src_ip` on a later ingest — the id is `DET-001:<key>` and is
    updated, not duplicated.

??? question "Diagnose: The timeline shows six failures, then real logins for other scenarios. Why is H2 (password guessed) not proven?"
    The sim concatenates brute_force *and then* legitimate logins for IDOR
    and the rest. Adjacent `login_success` is the operator continuing the
    script (H3), not evidence the sixth guess worked. Distinguishing H1/H2
    in production would need MFA, device, or mail evidence this lab does
    not have.

??? question "Design: Why is raising DET-001's threshold a weak response to shared-NAT false positives?"
    You trade those FPs for false negatives on slower guessing. A better
    grouping key, correlation with `login_success` / later data-access, or
    a prevention control (rate limit) changes the claim. Document the FP
    instead of silent-disabling the rule.

??? question "Defend: For SSRF-to-IMDS, what is quarantine versus eradicate in this lab?"
    Quarantine: copy evidence, then disable `LAB_MODE` or block `/fetch` to
    metadata without `down -v` so logs survive. Eradicate: fix the fetch
    (allowlist already is a rail — the missing control is "app should not
    fetch metadata" plus rotate dummy creds). Residual risk: other internal
    SSRF targets and no attempt-detection until you add one.

## Before you leave

- **Predict** — write expected evidence (what appears, what does not, and why) before the next observation.
- **Diagnose** — name the failed invariant from the UTC timeline, not from the sim's scenario name.
- **Build** — investigate the simulated exposure (timeline, competing hypotheses, RCA, preserve-before-contain).
- **Defend** — state containment and residual risk in one sentence each.
- **Exit criteria** — meet [this module's list](#exit-criteria) and the course [pass bar](../assessment.md).

## Further reading

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST CSF 2.0](https://www.nist.gov/cyberframework)
- [Sigma](https://github.com/SigmaHQ/sigma)
- [YARA](https://yara.readthedocs.io/) (conceptual; no malware lab)
- [FIRST TLP](https://www.first.org/tlp/)
- [The Diamond Model of Intrusion Analysis (Caltagirone, Pendergast, Betz)](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
