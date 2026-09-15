---
description: "Agent run template for the capstone: the saved /investigate response plus the denied and approved action attempts that prove the approval gate."
---

# Agent run (fill in)

!!! info "Before you fill this in"
    **Start in:** Module 12 lab. **Save as:** `docs/capstone/work/agent-run.json`.
    There is no Helix example. The agent only exists in this repository’s lab.

M8 asks you to prove three things with evidence you saved, not describe
them:

1. The agent investigated a real alert and got its mapping from the catalog.
2. It refused an action without `approval=APPROVE`.
3. It refused an action outside the allowlist, and ran an approved one.

## Capture it

```bash
A='DET-003:alice'   # an alert id from GET http://127.0.0.1:8090/alerts

curl -s -X POST http://127.0.0.1:8091/investigate \
  -H 'Content-Type: application/json' -d "{\"alert_id\":\"$A\"}" > /tmp/investigate.json

for body in \
  "{\"alert_id\":\"$A\",\"action\":\"disable_lab_mode\",\"approval\":\"nope\"}" \
  "{\"alert_id\":\"$A\",\"action\":\"delete_everything\",\"approval\":\"APPROVE\"}" \
  "{\"alert_id\":\"$A\",\"action\":\"disable_lab_mode\",\"approval\":\"APPROVE\"}"
do
  curl -s -o /dev/null -w "%{http_code} $body\n" -X POST http://127.0.0.1:8091/actions \
    -H 'Content-Type: application/json' -d "$body"
done
```

Expect `403`, `403`, then `200`. Then copy the matching lines from the
audit log inside the agent’s volume:

```bash
docker exec lab-agentic-soc cat /cases/agent-audit.jsonl
```

## Save it in this shape

```json
{
  "captured_at": "<UTC time>",
  "llm": "none | local | hosted (redacted)",
  "investigate": {
    "request": {"alert_id": "<alert id>"},
    "response": "<paste the whole /investigate response object>"
  },
  "actions": [
    {"request": {"action": "disable_lab_mode", "approval": "nope"}, "status": 403, "why": "no human approval"},
    {"request": {"action": "delete_everything", "approval": "APPROVE"}, "status": 403, "why": "not in policy allowlist"},
    {"request": {"action": "disable_lab_mode", "approval": "APPROVE"}, "status": 200, "why": "allowlisted and approved"}
  ],
  "audit_lines": ["<the matching lines from agent-audit.jsonl>"],
  "analyst_notes": "<one or two sentences: was the mapping right, and would you have taken the action?>"
}
```

## Redaction

- **Hosted LLM:** assume the provider logged the prompt. Replace any
  evidence text you wouldn’t publish with `"<redacted>"`, and set `llm` to
  `hosted (redacted)`.
- **Always:** remove dummy IMDS keys and JWTs from the evidence arrays
  before you share this file anywhere.
