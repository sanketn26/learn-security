"""A deliberately gullible planner, so agent failures are safe and repeatable.

This is NOT a language model. It is a small script that models one real
failure mode: text it reads as data (an alert field, a playbook, a memory note,
a tool description) can be taken for instructions. It plans a normal
investigation, but anything that LOOKS like a tool call in what it reads is
queued ahead of the plan, exactly as a hijacked model would.

Its recognition is broader than agent.py's phrase filter on purpose: models
follow paraphrases, other languages, obfuscated text and encoded blocks that a
regex list does not. The planner never decides what is ALLOWED. The gateway
does, and the point of Module 12b is that it must not matter how gullible this
planner is.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# "call simulate_action(a=b, c=d)" and a few translations of "call".
DIRECTIVE_RE = re.compile(
    r"\b(?:call|use|run|appelle|appelez|llama|rufe)\s+(?:the\s+)?(?:tool\s+|l'outil\s+)?([a-z_]+)\s*\(([^)]*)\)",
    re.IGNORECASE,
)
B64_RE = re.compile(r"b64:([A-Za-z0-9+/=]{12,})")
# Stop at a quote or newline: a reader takes the sentence, not the JSON around it.
REMEMBER_RE = re.compile(r"remember(?:\s+that)?\s*:\s*([^\"\n]+)", re.IGNORECASE)
LOOP_RE = re.compile(r"re-?investigate (?:the )?alert", re.IGNORECASE)
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    note: str = "plan"  # stub-only: why the planner made this call


def normalize(text: str) -> str:
    """What a reader perceives: fullwidth letters folded, zero-width marks gone."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


def parse_args(raw: str) -> dict[str, Any]:
    args: dict[str, Any] = {}
    for part in raw.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        value = value.strip().strip("'\"")
        args[key.strip()] = int(value) if value.isdigit() else value
    return args


def extract_directives(text: str, alert_id: str, source: str) -> list[ToolCall]:
    seen = normalize(text).replace("{alert_id}", alert_id)
    layers = [seen]
    for match in B64_RE.finditer(seen):
        try:
            layers.append(base64.b64decode(match.group(1)).decode("utf-8", "ignore"))
        except ValueError:
            continue
    calls: list[ToolCall] = []
    for layer in layers:
        for name, raw in DIRECTIVE_RE.findall(layer):
            calls.append(ToolCall(name.lower(), parse_args(raw), f"obeyed text in {source}"))
        for fact in REMEMBER_RE.findall(layer):
            calls.append(ToolCall("remember", {"text": fact.strip()[:300]}, f"obeyed text in {source}"))
    return calls


class GulliblePlanner:
    """Plans: get_alert, search_logs, get_playbook, enrich_ip, propose_actions."""

    def __init__(self, alert_id: str, playbook_for_rule: dict[str, str], can_enrich: bool) -> None:
        self.alert_id = alert_id
        self.playbook_for_rule = playbook_for_rule
        self.can_enrich = can_enrich
        self.queue: deque[ToolCall] = deque([ToolCall("get_alert", {"alert_id": alert_id})])
        self.alert: dict[str, Any] = {}
        self._obeyed: set[str] = set()  # a model would not issue the exact same injected call again and again

    def see(self, text: str, source: str) -> None:
        """Read some text. Anything that looks like an instruction jumps the queue."""
        fresh = []
        for call in extract_directives(text, self.alert_id, source):
            key = f"{call.tool}:{sorted(call.args.items())}"
            if key not in self._obeyed:
                self._obeyed.add(key)
                fresh.append(call)
        for call in reversed(fresh):
            self.queue.appendleft(call)
        if LOOP_RE.search(normalize(text)):
            self._restart(f"obeyed text in {source}")

    def _restart(self, note: str) -> None:
        self.queue.appendleft(ToolCall("get_alert", {"alert_id": self.alert_id}, note))

    def observe(self, call: ToolCall, result_text: str, result: Any) -> None:
        if call.tool == "get_alert" and isinstance(result, dict) and result.get("id"):
            self.alert = result
            actor = result.get("actor") or ""
            self.queue.append(ToolCall("search_logs", {"q": actor, "limit": 10}))
            name = self.playbook_for_rule.get(result.get("rule_id", ""))
            if name:
                self.queue.append(ToolCall("get_playbook", {"name": name}))
            ip = next((e["src_ip"] for e in result.get("evidence") or [] if e.get("src_ip")), None)
            if ip and self.can_enrich:
                self.queue.append(ToolCall("enrich_ip", {"ip": ip}))
            self.queue.append(ToolCall("propose_actions", {"alert_id": self.alert_id}))
        self.see(result_text, f"result of {call.tool}")

    def next_call(self) -> ToolCall | None:
        return self.queue.popleft() if self.queue else None
