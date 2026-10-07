"""A pretend MCP-style tool server registry, loaded from JSON.

Real tool servers describe their tools in free text that the model reads.
That text is untrusted input from a third party, and it can change after you
approved it. This module lets the lab show both problems offline.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from approvals import canonical


def descriptor_hash(tool: dict[str, Any]) -> str:
    """Hash of everything the model would be told about a tool."""
    keys = ("name", "version", "description", "params")
    return hashlib.sha256(canonical({k: tool.get(k) for k in keys})).hexdigest()


def load_registry(path: str) -> dict[str, dict[str, Any]]:
    """tool name -> descriptor, with its server and hash attached."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    tools: dict[str, dict[str, Any]] = {}
    for server in data.get("servers", []):
        for tool in server.get("tools", []):
            tools[tool["name"]] = {**tool, "server": server["name"], "sha256": descriptor_hash(tool)}
    return tools


def run_enrich_ip(ip: str) -> dict[str, Any]:
    """Canned, offline answer. Never touches the network."""
    return {"ip": ip, "verdict": "no reports (lab data)", "source": "threat-intel-mcp"}
