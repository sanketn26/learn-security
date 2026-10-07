"""An in-memory backend, so runs and evals need no network and no containers."""

from __future__ import annotations

import copy
from typing import Any

from agent_memory import Memory


class FakeBackend:
    """Serves alerts and playbooks from dicts and RECORDS every side effect."""

    def __init__(self, alerts: dict[str, dict[str, Any]], playbooks: dict[str, str], memory: Memory | None = None):
        self.alerts = alerts
        self.playbooks = playbooks
        self.memory = memory
        self.executed: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []
        self.remembered: list[str] = []

    async def get_alert(self, alert_id):
        return copy.deepcopy(self.alerts.get(alert_id, {"error": "not found"}))

    async def search_logs(self, q, limit):
        return [{"event": "login_failure", "username": q}][:limit]

    async def get_playbook(self, name):
        return {"name": name, "body": self.playbooks.get(name, "")}

    async def map_attack(self, rule_id):
        return {"technique": "lab"}

    async def propose_actions(self, alert_id):
        return [{"id": "snapshot_logs", "requires_approval": True}]

    async def enrich_ip(self, ip):
        return {"ip": ip, "verdict": "no reports (lab data)"}

    async def remember(self, text, author):
        self.remembered.append(text)
        if self.memory is not None:
            self.memory.add(text, source="agent", author=author)
        return {"saved": True}

    async def simulate_action(self, action, alert_id, actor, args):
        self.executed.append({"action": action, "alert_id": alert_id, "actor": actor, "args": args})
        return {"status": "simulated", "action": action}

    async def request_action(self, action, alert_id, requested_by, args):
        request = {"id": f"req{len(self.requests)}", "action": action, "alert_id": alert_id, "requested_by": requested_by, "args": args, "status": "pending"}
        self.requests.append(request)
        return request
