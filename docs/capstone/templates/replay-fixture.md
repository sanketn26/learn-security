---
description: "Replay fixture template for capstone detections: one JSONL file that must fire a rule and one that must stay quiet, plus the command that proves both."
---

# Replay fixtures (fill in)

!!! info "Before you fill this in"
    **Start in:** Module 11 (DET-001 walkthrough and assignment). **Save as:** `docs/capstone/work/fixtures/<rule-id>.fire.jsonl` and `<rule-id>.quiet.jsonl`, one pair per rule, eight pairs in total.
    **Example:** [Helix HELIX-003 fixture](../reference/attack-coverage-example.md#replay-fixture). Helix event names don’t exist in notes-api.

A rule you’ve never replayed is a belief. A fixture turns it into a claim
someone else can test: *this* input fires the rule, and *that* input, which
looks almost the same, does not.

## The two files

| File | Contains | Must produce |
| --- | --- | --- |
| `<rule-id>.fire.jsonl` | The smallest set of events that should trip the rule | Exactly the alert ID `<rule-id>:<group key>` |
| `<rule-id>.quiet.jsonl` | The nearest *legitimate* case: below threshold, outside the window, a different group key, or a benign value | No alert |

An empty quiet file proves nothing. Make it the case a tired analyst would
confuse with the attack.

Each line is one notes-api event, in the same shape the API writes:

```json
{"ts":"2026-09-15T10:00:01.000000Z","event":"<event name>","service":"notes-api","lab_mode":true,"trace_id":"fx-1","actor":"alice"}
```

- `ts` is UTC with microseconds. Windows are measured in event time, not ingest time.
- Include every field your rule’s `group_by` and `match_field` read. A
  missing field groups under `username`, or under an empty key.
- Use dummy values only. Never paste a real token or a real IMDS key.

### Shape example — DET-001 (provided rule)

`DET-001.fire.jsonl`: six `login_failure` events from one `src_ip` within
120 seconds.

```json
{"ts":"2026-09-15T10:00:01.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"fx-1","src_ip":"127.0.0.1","username":"alice"}
{"ts":"2026-09-15T10:00:02.000000Z","event":"login_failure","service":"notes-api","lab_mode":true,"trace_id":"fx-2","src_ip":"127.0.0.1","username":"alice"}
```
*(…four more, up to `10:00:06`.)*

`DET-001.quiet.jsonl`: three failures from the same `src_ip`, which is below
the threshold of five. A user who mistypes a password three times isn’t an
attack.

## Replay command

This runs soc-lite’s own `ingest` and `evaluate` against one file with a
throwaway database, so it never touches your live cases.

=== "Docker (lab running)"

    ```bash
    F=docs/capstone/work/fixtures/DET-001.fire.jsonl
    docker cp "$F" lab-soc-lite:/tmp/fixture.jsonl
    docker exec -e LOG_PATH=/tmp/fixture.jsonl -e DB_PATH=/tmp/replay.db lab-soc-lite \
      sh -c 'rm -f /tmp/replay.db && python -c "import app; app.init(); app.ingest(); print(app.evaluate())"'
    ```

=== "Host Python"

    Needs `requirements-labs.txt` installed.

    ```bash
    F=$PWD/docs/capstone/work/fixtures/DET-001.fire.jsonl
    (cd labs/soc-lite && LOG_PATH="$F" DB_PATH="$(mktemp -d)/soc.db" \
      RULES_PATH=../detections/rules.yaml \
      python3 -c 'import app; app.init(); app.ingest(); print(app.evaluate())')
    ```

The fire file should print `['DET-001:127.0.0.1']` and the quiet file `[]`.
The Docker path reads the rules mounted from `labs/detections/rules.yaml`,
so your authored rules are included.

## Record

Copy this table into `work/attack-coverage.md` under **Replay fixtures**.

| Rule | Fire file → alert | Quiet file → nothing | What the quiet case represents |
| --- | --- | --- | --- |
| DET-001 | | | |
| DET-002 | | | |
| DET-003 | | | |
| DET-004 | | | |
| DET-005 | | | |
| (yours) | | | |
| (yours) | | | |
| (yours) | | | |
