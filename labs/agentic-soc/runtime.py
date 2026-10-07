"""The agent run loop: plan, pass every call through the gateway, trace it all."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from typing import Any, Protocol

from gateway import Gateway, make_identity
from planner import GulliblePlanner, ToolCall

UNSAFE_STEP_CAP = 60  # only so the lab does not hang; the unsafe mode has no real limit
SECRET_RE = re.compile(r"(lab-secret-[\w-]+|lab-jwt-[\w-]+|LABFAKE[\w-]*|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]+)")
PROMPT_TOKEN_COST = 1
COMPLETION_TOKEN_COST = 3


class Backend(Protocol):
    async def get_alert(self, alert_id: str) -> dict[str, Any]: ...
    async def search_logs(self, q: str, limit: int) -> Any: ...
    async def get_playbook(self, name: str) -> dict[str, Any]: ...
    async def map_attack(self, rule_id: str) -> dict[str, Any]: ...
    async def propose_actions(self, alert_id: str) -> Any: ...
    async def enrich_ip(self, ip: str) -> dict[str, Any]: ...
    async def remember(self, text: str, author: str) -> dict[str, Any]: ...
    async def simulate_action(self, action: str, alert_id: str, actor: str, args: dict[str, Any]) -> dict[str, Any]: ...
    async def request_action(self, action: str, alert_id: str, requested_by: str, args: dict[str, Any]) -> dict[str, Any]: ...


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:12]


def redact(text: str) -> str:
    return SECRET_RE.sub("<redacted>", text)


def sanitize(value: Any) -> Any:
    """Redact secret-looking values everywhere in a structure, keeping its shape."""
    return json.loads(redact(json.dumps(value, default=str, ensure_ascii=False)))


def words(value: Any) -> int:
    return len(json.dumps(value, default=str, ensure_ascii=False).split())


async def _execute(backend: Backend, gateway: Gateway, call: ToolCall) -> Any:
    a = call.args
    who = gateway.identity.on_behalf_of or gateway.identity.sub
    if call.tool == "get_alert":
        return await backend.get_alert(a["alert_id"])
    if call.tool == "search_logs":
        return await backend.search_logs(a["q"], a.get("limit", 10))
    if call.tool == "get_playbook":
        return await backend.get_playbook(a["name"])
    if call.tool == "map_attack":
        return await backend.map_attack(a["rule_id"])
    if call.tool == "propose_actions":
        return await backend.propose_actions(a["alert_id"])
    if call.tool == "enrich_ip":
        return await backend.enrich_ip(a["ip"])
    if call.tool == "remember":
        return await backend.remember(a["text"], "agent")
    if call.tool == "request_action":
        extra = {k: v for k, v in a.items() if k == "target_actor"}
        return await backend.request_action(a["action"], a["alert_id"], who, extra)
    if call.tool == "simulate_action":
        extra = {k: v for k, v in a.items() if k == "target_actor"}
        # The ambient identity acts, whoever asked.
        return await backend.simulate_action(a["action"], a["alert_id"], gateway.identity.sub, extra)
    raise KeyError(call.tool)


async def run_agent(
    *,
    mode: str,
    policy: dict[str, Any],
    backend: Backend,
    registry: dict[str, dict[str, Any]],
    memory_entries: list[dict[str, Any]],
    playbook_for_rule: dict[str, str],
    alert_id: str,
    requested_by: str | None,
    killed: Any = lambda: False,
    run_id: str | None = None,
    text_filter: re.Pattern[str] | None = None,
) -> dict[str, Any]:
    """text_filter models a prompt-level defense: text that matches is replaced
    with a warning BEFORE the planner reads it. It is one layer, not the gate."""
    run_id = run_id or uuid.uuid4().hex[:8]
    identity = make_identity(mode, policy, run_id, requested_by)
    trace: dict[str, Any] = {
        "run_id": run_id,
        "mode": mode,
        "task": "investigate",
        "alert_id": alert_id,
        "requested_by": requested_by,
        "identity": None,
        "steps": [],
        "side_effects": [],
        "pending_requests": [],
        "totals": {},
        "outcome": "completed",
    }
    if identity is None:
        trace["outcome"] = "refused_unknown_requester"
        return trace
    trace["identity"] = {"sub": identity.sub, "on_behalf_of": identity.on_behalf_of, "scopes": sorted(identity.scopes)}
    gateway = Gateway(mode, policy, identity, registry)
    trace["config"] = {
        # What shaped this run besides the planner, so replay can tell a changed
        # configuration from a changed behavior.
        "text_filter": text_filter.pattern if text_filter is not None else None,
        "text_filter_flags": int(text_filter.flags) if text_filter is not None else 0,
        "budgets": dict(policy["budgets"]) if mode == "hardened" else {"unsafe_step_cap": UNSAFE_STEP_CAP},
        "protected_actors": list(policy["approval"]["protected_actors"]),
    }
    trace["context"] = {
        "memory": [{"text": e["text"], "source": e["source"]} for e in memory_entries],
        "registry": {name: d["sha256"] for name, d in registry.items()},
    }
    trace["tools_visible"] = gateway.visible_tools()
    trace["tools_disabled"] = dict(gateway.disabled_tools)

    def screened(text: str) -> tuple[str, bool]:
        if text_filter is not None and text_filter.search(text):
            return '{"warning": "instruction-like content stripped"}', True
        return text, False

    planner = GulliblePlanner(alert_id, playbook_for_rule, can_enrich="enrich_ip" in gateway.visible_tools())
    # What the model is shown before it starts: trusted-or-not memory, and tool text.
    for entry in memory_entries:
        shown, _ = screened(entry["text"])
        planner.see(shown, f"memory ({entry['source']})")
    if mode == "unsafe":
        for descriptor in registry.values():
            shown, _ = screened(descriptor["description"])
            planner.see(shown, f"description of {descriptor['name']}")

    budgets = policy["budgets"]
    max_steps = budgets["max_steps"] if mode == "hardened" else UNSAFE_STEP_CAP
    max_calls = budgets["max_tool_calls"] if mode == "hardened" else UNSAFE_STEP_CAP
    max_blocked = budgets.get("max_blocked", 3)
    started = time.monotonic()
    context_words = 0
    calls_executed = 0
    totals = {"prompt_tokens": 0, "completion_tokens": 0, "blocked": 0}

    while True:
        if killed():
            trace["outcome"] = "killed"
            break
        if mode == "hardened" and time.monotonic() - started > budgets["deadline_seconds"]:
            trace["outcome"] = "deadline_exceeded"
            break
        call = planner.next_call()
        if call is None:
            break
        if mode == "hardened" and totals["blocked"] >= max_blocked:
            # Repeated denials mean the planner is being steered. Stop and say so,
            # rather than quietly spending the step budget on attacker-chosen calls.
            trace["outcome"] = "aborted_policy_violations"
            break
        if len(trace["steps"]) >= max_steps or calls_executed >= max_calls:
            trace["outcome"] = "budget_exceeded" if mode == "hardened" else "runaway_capped"
            break
        completion = words({"tool": call.tool, "args": call.args})
        totals["prompt_tokens"] += context_words
        totals["completion_tokens"] += completion
        decision = gateway.check(call.tool, call.args)
        step: dict[str, Any] = {
            "i": len(trace["steps"]),
            "tool": call.tool,
            "args": call.args,
            "planner_note": call.note,
            "decision": "allowed" if decision.allowed else "blocked",
            "reason": decision.reason,
            "prompt_tokens": context_words,
            "completion_tokens": completion,
        }
        if decision.allowed:
            calls_executed += 1
            try:
                result = await _execute(backend, gateway, call)
                step["result"] = result
                if call.tool == "simulate_action":
                    trace["side_effects"].append({"action": call.args.get("action"), "alert_id": call.args.get("alert_id"), "args": call.args, "by": identity.sub})
                if call.tool == "request_action":
                    trace["pending_requests"].append(result)
            except Exception as exc:  # noqa: BLE001
                result = {"error": type(exc).__name__}
                step["decision"], step["reason"], step["result"] = "error", type(exc).__name__, result
            # Keep structure for replay but never persist secret-looking values.
            step["result"] = json.loads(redact(json.dumps(result, default=str, ensure_ascii=False)))
            text, was_filtered = screened(json.dumps(result, default=str, ensure_ascii=False))
            step["filtered"] = was_filtered
            context_words += words(result)
            planner.observe(call, text, result)
        else:
            totals["blocked"] += 1
            step["result"] = None
        step["result_digest"] = digest(step.get("result"))
        step["result_preview"] = redact(json.dumps(step.get("result"), default=str, ensure_ascii=False))[:160]
        trace["steps"].append(step)

    trace["totals"] = {
        "steps": len(trace["steps"]),
        "tool_calls": calls_executed,
        **totals,
        "cost_units": totals["prompt_tokens"] * PROMPT_TOKEN_COST + totals["completion_tokens"] * COMPLETION_TOKEN_COST,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    # Arguments, memory context, and results can all carry secret-looking text.
    return sanitize(trace)
