#!/usr/bin/env python3
"""Capture Artifact H (agent-run.json) from a RUNNING lab: no copy-paste.

Investigates one alert, tries the three action attempts that prove the
approval gate, reads the matching audit lines, and optionally attaches a full
model-driven run trace. Loopback only.

    python3 labs/agentic-soc/tools/export_agent_run.py --alert DET-003:alice \\
        --out docs/capstone/work/agent-run.json [--with-trace]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

APPROVER_HEADERS = {"X-Approver": "analyst-resp", "X-Approver-Key": "lab-approver-key-resp"}


def call(base: str, method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode() or "{}")
        except json.JSONDecodeError:
            return exc.code, {}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="http://127.0.0.1:8091")
    parser.add_argument("--alert", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--with-trace", action="store_true", help="also run /agent/run and attach its trace")
    args = parser.parse_args()
    if urllib.parse.urlparse(args.base).hostname not in {"127.0.0.1", "localhost", "::1"}:
        sys.exit("Refusing non-local target. AUTHORIZED LAB USE ONLY.")

    code, investigate = call(args.base, "POST", "/investigate", {"alert_id": args.alert})
    if code != 200:
        sys.exit(f"/investigate failed: {code} {investigate}")
    _, health = call(args.base, "GET", "/health")
    bound = health.get("approval_mode") == "bound"
    attempts = [
        ({"action": "disable_lab_mode", "approval": "nope"}, "no human approval"),
        ({"action": "delete_everything", "approval": "APPROVE"}, "not in policy allowlist"),
    ]
    actions = []
    for body, why in attempts:
        status, _ = call(args.base, "POST", "/actions", {"alert_id": args.alert, **body})
        actions.append({"request": body, "status": status, "why": why})
    final = {"action": "disable_lab_mode", "approval": "APPROVE"}
    if bound:
        _, minted = call(args.base, "POST", "/approvals", {"alert_id": args.alert, "action": "disable_lab_mode"}, APPROVER_HEADERS)
        final = {"action": "disable_lab_mode", "approval_token": minted.get("token", "")}
    status, _ = call(args.base, "POST", "/actions", {"alert_id": args.alert, **final})
    shown = {k: ("<token>" if k == "approval_token" else v) for k, v in final.items()}
    actions.append({"request": shown, "status": status, "why": "allowlisted and approved"})

    _, audit = call(args.base, "GET", "/audit?limit=60")
    record = {
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "llm": "none",
        "approval_mode": health.get("approval_mode"),
        "investigate": {"request": {"alert_id": args.alert}, "response": investigate},
        "actions": actions,
        "audit_lines": [json.dumps(line) for line in audit.get("lines", []) if line.get("event", "").startswith(("action_", "investigate", "approval_", "prompt_"))],
        "analyst_notes": "<one or two sentences: was the mapping right, and would you have taken the action?>",
    }
    if args.with_trace:
        code, trace = call(args.base, "POST", "/agent/run", {"alert_id": args.alert})
        record["trace"] = trace if code == 200 else {"error": code}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)
    print(f"wrote {args.out}: statuses {[a['status'] for a in actions]} (expect 403, 403, 200)")


if __name__ == "__main__":
    main()
