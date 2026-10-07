"""The tool gateway: the one place that decides what an agent may do.

Two modes, to show the difference:

  unsafe    What many agents ship with. The model sees every tool, tool
            arguments are not checked, the agent runs with one powerful
            identity, the model supplies its own "approval", memory and tool
            descriptions are trusted, and nothing limits a runaway.

  hardened  The model is assumed compromised. The gateway enforces, outside
            the model: which tools exist, a per-run identity with scopes
            (the requesting person's role intersected with the agent's),
            strict argument schemas, a request-not-execute path for response
            actions, pinned third-party tool descriptions, analyst-only
            memory, and step / call / time budgets with a kill switch.

Nothing here depends on the planner behaving.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

ALERT_ID_RE = re.compile(r"^DET-\d{3}:[A-Za-z0-9._:-]{1,64}$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# tool -> (scope it needs, {param: (type, regex-or-None, required)})
TOOLS: dict[str, tuple[str, dict[str, tuple[type, re.Pattern[str] | None, bool]]]] = {
    "get_alert": ("read:alerts", {"alert_id": (str, ALERT_ID_RE, True)}),
    "search_logs": ("read:logs", {"q": (str, re.compile(r"^.{0,100}$"), True), "limit": (int, None, False)}),
    "get_playbook": ("read:playbooks", {"name": (str, re.compile(r"^[a-z0-9-]+\.md$"), True)}),
    "map_attack": ("read:alerts", {"rule_id": (str, re.compile(r"^DET-\d{3}$"), True)}),
    "propose_actions": ("read:alerts", {"alert_id": (str, ALERT_ID_RE, True)}),
    "enrich_ip": ("read:enrichment", {"ip": (str, IPV4_RE, True)}),
    "request_action": (
        "request:action",
        {
            "action": (str, re.compile(r"^[a-z_]{1,40}$"), True),
            "alert_id": (str, ALERT_ID_RE, True),
            "target_actor": (str, re.compile(r"^[A-Za-z0-9._-]{1,64}$"), False),
        },
    ),
    # Present only in the unsafe mode:
    "remember": ("write:memory", {"text": (str, re.compile(r"^.{1,300}$", re.DOTALL), True)}),
    "simulate_action": (
        "act:respond",
        {
            "action": (str, None, True),
            "alert_id": (str, None, True),
            "target_actor": (str, None, False),
            "approval": (str, None, False),
        },
    ),
}
UNSAFE_ONLY = {"remember", "simulate_action"}
ALL_SCOPES = {scope for scope, _ in TOOLS.values()}


@dataclass
class Identity:
    sub: str
    on_behalf_of: str | None
    scopes: set[str] = field(default_factory=set)


@dataclass
class Decision:
    allowed: bool
    reason: str = "ok"


def make_identity(mode: str, policy: dict[str, Any], run_id: str, requested_by: str | None) -> Identity | None:
    """None means the requester is unknown and the run must not start."""
    if mode == "unsafe":
        # One ambient, all-powerful service identity. Who asked does not matter.
        return Identity("agent-service", requested_by, set(ALL_SCOPES))
    roles = policy["identity"]["roles"]
    if requested_by not in roles:
        return None
    scopes = set(policy["identity"]["agent_scopes"]) & set(roles[requested_by])
    return Identity(f"agent-run:{run_id}", requested_by, scopes)


class Gateway:
    def __init__(self, mode: str, policy: dict[str, Any], identity: Identity, registry: dict[str, dict[str, Any]]) -> None:
        if mode not in {"unsafe", "hardened"}:
            raise ValueError(f"unknown mode {mode!r}")
        self.mode = mode
        self.policy = policy
        self.identity = identity
        self.registry = registry
        self.allowed_actions = set(policy["tools"]["simulate_action"]["allowed_actions"])
        self.pinned = {
            tool: digest
            for server in policy.get("tool_servers", {}).values()
            for tool, digest in server.items()
        }
        self.disabled_tools: dict[str, str] = {}
        self.requests_made = 0
        if mode == "hardened":
            for name, descriptor in registry.items():
                if self.pinned.get(name) != descriptor["sha256"]:
                    self.disabled_tools[name] = "descriptor_changed" if name in self.pinned else "unpinned_tool"

    def visible_tools(self) -> list[str]:
        names = [n for n in TOOLS if n != "enrich_ip"]
        names += [n for n in self.registry if n not in self.disabled_tools]
        if self.mode == "hardened":
            names = [n for n in names if n not in UNSAFE_ONLY]
        return names

    def check(self, tool: str, args: dict[str, Any]) -> Decision:
        if tool not in TOOLS or (tool == "enrich_ip" and tool not in self.registry):
            return Decision(False, "unknown_tool")
        if self.mode == "unsafe":
            return self._check_unsafe(tool, args)
        if tool in self.disabled_tools:
            return Decision(False, f"tool_disabled:{self.disabled_tools[tool]}")
        if tool in UNSAFE_ONLY:
            return Decision(False, "tool_not_available")
        scope = TOOLS[tool][0]
        if scope not in self.identity.scopes:
            return Decision(False, f"missing_scope:{scope}")
        problem = self._schema_problem(tool, args)
        if problem:
            return Decision(False, f"invalid_args:{problem}")
        if tool == "request_action":
            if args["action"] not in self.allowed_actions:
                return Decision(False, "action_not_allowlisted")
            if args["action"] == "block_actor" and args.get("target_actor") in self.policy["approval"]["protected_actors"]:
                return Decision(False, "protected_actor")
            if self.requests_made >= self.policy["budgets"].get("max_requests_per_run", 2):
                return Decision(False, "request_budget")
            self.requests_made += 1
        return Decision(True)

    def _check_unsafe(self, tool: str, args: dict[str, Any]) -> Decision:
        # Only "is the tool name known" and, for actions, "did the model say APPROVE".
        if tool == "simulate_action":
            if args.get("action") not in self.allowed_actions:
                return Decision(False, "action_not_allowlisted")
            if args.get("approval") != "APPROVE":
                return Decision(False, "no_approval")
        return Decision(True)

    @staticmethod
    def _schema_problem(tool: str, args: dict[str, Any]) -> str | None:
        schema = TOOLS[tool][1]
        extra = set(args) - set(schema)
        if extra:
            return f"unknown_params:{sorted(extra)}"
        for name, (kind, pattern, required) in schema.items():
            if name not in args:
                if required:
                    return f"missing:{name}"
                continue
            value = args[name]
            if not isinstance(value, kind) or isinstance(value, bool):
                return f"type:{name}"
            if pattern is not None and not pattern.fullmatch(value):
                return f"format:{name}"
        if tool == "search_logs" and "limit" in args and not 1 <= args["limit"] <= 50:
            return "range:limit"
        return None
