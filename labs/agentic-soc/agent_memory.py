"""A small persistent memory, to show how a poisoned note outlives its source.

Every entry records WHO wrote it. Hardened runs only read analyst-written
entries; the unsafe run reads everything, so a note the agent saved after
reading attacker-controlled text shapes every later run.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any


class Memory:
    def __init__(self, path: str, ttl_seconds: int = 86400) -> None:
        self.path = path
        self.ttl = ttl_seconds

    def _load(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as handle:
            return json.load(handle)

    def add(self, text: str, *, source: str, author: str, now: float | None = None) -> dict[str, Any]:
        entry = {
            "id": uuid.uuid4().hex[:8],
            "ts": time.time() if now is None else now,
            "text": text[:300],
            "source": source,  # "analyst" (a human wrote it) or "agent" (derived from data)
            "author": author,
        }
        entries = self._load() + [entry]
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(entries, handle)
        return entry

    def entries(self, *, analyst_only: bool, now: float | None = None) -> list[dict[str, Any]]:
        current = time.time() if now is None else now
        live = [e for e in self._load() if current - e["ts"] <= self.ttl]
        return [e for e in live if e["source"] == "analyst"] if analyst_only else live

    def clear(self) -> None:
        if os.path.exists(self.path):
            os.remove(self.path)
