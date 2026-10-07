#!/usr/bin/env python3
"""Replay a recorded agent run.

  rejudge  Ask "what would a DIFFERENT gateway have done with these same calls?"
           Takes a trace (for example an unsafe run) and re-decides every call
           under another mode. It does not run the planner or touch any backend.

  rerun    Run the whole thing again from the trace (same alert, memory, tool
           registry, recorded tool results) and check the run comes out the
           same. This is a regression check: change the gateway, replay your
           saved traces, read the diff.

    python3 labs/agentic-soc/tools/replay.py TRACE.json --rejudge hardened
    python3 labs/agentic-soc/tools/replay.py TRACE.json --rerun
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from gateway import Gateway, make_identity  # noqa: E402
from planner import ToolCall  # noqa: E402
from runtime import run_agent  # noqa: E402
from tool_registry import load_registry  # noqa: E402

HERE = Path(__file__).resolve().parent.parent
PLAYBOOK_FOR_RULE_FALLBACK: dict[str, str] = {}


def load_policy(path: Path = HERE / "policy.yaml") -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def rejudge(trace: dict[str, Any], mode: str, policy: dict[str, Any], registry_path: Path = HERE / "mcp_registry.json") -> list[dict[str, Any]]:
    """Per-step comparison of the recorded decision with the one `mode` would make."""
    identity = make_identity(mode, policy, trace["run_id"], trace.get("requested_by"))
    if identity is None:
        return [{"i": -1, "tool": "(run)", "recorded": trace["outcome"], "replayed": "refused_unknown_requester"}]
    gateway = Gateway(mode, policy, identity, load_registry(str(registry_path)))
    diffs = []
    for step in trace["steps"]:
        replayed = gateway.check(step["tool"], step["args"])
        recorded = "allowed" if step["decision"] == "allowed" else f"blocked:{step['reason']}"
        now = "allowed" if replayed.allowed else f"blocked:{replayed.reason}"
        if recorded != now:
            diffs.append({"i": step["i"], "tool": step["tool"], "args": step["args"], "recorded": recorded, "replayed": now})
    return diffs


class _ReplayBackend:
    """Answers each tool from the results recorded in the trace, in order."""

    def __init__(self, trace: dict[str, Any]) -> None:
        self.by_tool: dict[str, list[Any]] = {}
        for step in trace["steps"]:
            if step["decision"] == "allowed":
                self.by_tool.setdefault(step["tool"], []).append(step.get("result"))
        self.executed: list[dict[str, Any]] = []

    def _next(self, tool: str) -> Any:
        queue = self.by_tool.get(tool, [])
        return queue.pop(0) if queue else {}

    async def get_alert(self, alert_id): return self._next("get_alert")
    async def search_logs(self, q, limit): return self._next("search_logs")
    async def get_playbook(self, name): return self._next("get_playbook")
    async def map_attack(self, rule_id): return self._next("map_attack")
    async def propose_actions(self, alert_id): return self._next("propose_actions")
    async def enrich_ip(self, ip): return self._next("enrich_ip")
    async def remember(self, text, author): return self._next("remember")
    async def request_action(self, action, alert_id, requested_by, args): return self._next("request_action")

    async def simulate_action(self, action, alert_id, actor, args):
        self.executed.append({"action": action, "alert_id": alert_id})
        return self._next("simulate_action")


RECORDED = object()  # "use the filter the original run used"


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _step_key(step: dict[str, Any] | None) -> dict[str, Any] | None:
    if step is None:
        return None
    return {"tool": step["tool"], "args": step["args"], "decision": step["decision"], "reason": step["reason"]}


def rerun(
    trace: dict[str, Any],
    policy: dict[str, Any],
    registry_path: Path,
    playbook_for_rule: dict[str, str],
    text_filter: Any = RECORDED,
) -> dict[str, Any]:
    """Run again from the trace and report how it differs.

    The text filter defaults to the one the original run used (recorded in the
    trace), because a run is only reproducible under the same configuration.
    The result separates:

      config_differences  something about the setup changed (filter, budgets,
                          protected actors, tool descriptors). Expected if you
                          changed it on purpose.
      step_differences    the sequence of (tool, arguments, decision, reason)
                          differs.
      outcome / side_effects_differ  the run ended differently, or acted
                          differently.

    identical is true only when none of those differ.
    """
    recorded = trace.get("config", {})
    if text_filter is RECORDED:
        pattern = recorded.get("text_filter")
        text_filter = re.compile(pattern, recorded.get("text_filter_flags", 0)) if pattern else None
    new = asyncio.run(
        run_agent(
            mode=trace["mode"],
            policy=policy,
            backend=_ReplayBackend(trace),
            registry=load_registry(str(registry_path)),
            memory_entries=trace.get("context", {}).get("memory", []),
            playbook_for_rule=playbook_for_rule,
            alert_id=trace["alert_id"],
            requested_by=trace.get("requested_by"),
            run_id=trace["run_id"],
            text_filter=text_filter,
        )
    )
    now = new.get("config", {})
    config_differences: dict[str, Any] = {}
    for key in ("text_filter", "budgets", "protected_actors"):
        if recorded.get(key) != now.get(key):
            config_differences[key] = {"recorded": recorded.get(key), "replayed": now.get(key)}
    if trace.get("context", {}).get("registry") != new.get("context", {}).get("registry"):
        config_differences["registry"] = {
            "recorded": trace.get("context", {}).get("registry"),
            "replayed": new.get("context", {}).get("registry"),
        }

    step_differences: list[dict[str, Any]] = []
    old_steps, new_steps = trace["steps"], new["steps"]
    for i in range(max(len(old_steps), len(new_steps))):
        a = _step_key(old_steps[i]) if i < len(old_steps) else None
        b = _step_key(new_steps[i]) if i < len(new_steps) else None
        if _canon(a) != _canon(b):
            step_differences.append({"i": i, "recorded": a, "replayed": b})

    def effects(t: dict[str, Any]) -> list[str]:
        return sorted(_canon({k: e.get(k) for k in ("action", "alert_id", "args")}) for e in t.get("side_effects", []))

    outcome = None if trace["outcome"] == new["outcome"] else {"recorded": trace["outcome"], "replayed": new["outcome"]}
    side_effects_differ = effects(trace) != effects(new)
    behavior_identical = not step_differences and outcome is None and not side_effects_differ
    return {
        "identical": behavior_identical and not config_differences,
        "behavior_identical": behavior_identical,
        "config_differences": config_differences,
        "step_differences": step_differences,
        "outcome": outcome,
        "side_effects_differ": side_effects_differ,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("trace")
    parser.add_argument("--rejudge", choices=["unsafe", "hardened"])
    parser.add_argument("--rerun", action="store_true")
    parser.add_argument("--no-filter", action="store_true", help="with --rerun: drop the recorded text filter")
    parser.add_argument("--registry", default=str(HERE / "mcp_registry.json"))
    args = parser.parse_args()
    trace = json.loads(Path(args.trace).read_text(encoding="utf-8"))
    policy = load_policy()
    if args.rejudge:
        diffs = rejudge(trace, args.rejudge, policy, Path(args.registry))
        print(f"{len(diffs)} call(s) would be decided differently under {args.rejudge}:")
        for diff in diffs:
            print("  ", json.dumps(diff, default=str))
        return
    sys.path.insert(0, str(HERE))
    from agent import PLAYBOOK_BY_RULE  # noqa: PLC0415

    result = rerun(
        trace,
        policy,
        Path(args.registry),
        PLAYBOOK_BY_RULE,
        text_filter=None if args.no_filter else RECORDED,
    )
    if result["identical"]:
        print("identical: same steps, arguments, outcome, and side effects under the same configuration")
        return
    if result["config_differences"]:
        print("CONFIGURATION differs (expected if you changed it on purpose):")
        for key, diff in result["config_differences"].items():
            print(f"   {key}: {json.dumps(diff, default=str)}")
    if result["outcome"]:
        print(f"OUTCOME differs: {json.dumps(result['outcome'])}")
    if result["side_effects_differ"]:
        print("SIDE EFFECTS differ")
    for diff in result["step_differences"]:
        print("   step", json.dumps(diff, default=str))
    # Exit nonzero only for behavior changes, so a deliberate config change is not a CI failure by itself.
    sys.exit(0 if result["behavior_identical"] else 1)


if __name__ == "__main__":
    main()
