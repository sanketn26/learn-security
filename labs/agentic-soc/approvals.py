"""Bound, expiring, single-use approvals for response actions.

A legacy approval is the string "APPROVE" typed by whoever calls the API, so
anything that can reach the endpoint (including a model) can approve. A bound
approval is a token a human approver mints for ONE action on ONE alert with
THESE arguments, valid for a short time, usable once.

Lab secret and keys are dummies. In a real deployment the signing key lives in
a secrets manager and the receiving service (not just this agent) verifies it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any


class ApprovalError(Exception):
    """Raised with a short machine-readable reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sign(secret: str, body: str) -> str:
    return _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())


class NonceStore:
    """Append-only file of used nonces, so a restart does not re-open replay."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._seen: set[str] = set()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                self._seen = {line.strip() for line in handle if line.strip()}

    def seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def add(self, nonce: str) -> None:
        self._seen.add(nonce)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(nonce + "\n")


def mint(
    secret: str,
    *,
    action: str,
    alert_id: str,
    args: dict[str, Any],
    approver: str,
    requested_by: str | None,
    ttl: int,
    now: float | None = None,
) -> str:
    payload = {
        "action": action,
        "alert_id": alert_id,
        "args": args,
        "approver": approver,
        "requested_by": requested_by,
        "exp": int((time.time() if now is None else now) + ttl),
        "nonce": secrets.token_hex(8),
    }
    body = _b64(canonical(payload))
    return f"{body}.{_sign(secret, body)}"


def verify(
    secret: str,
    token: str,
    *,
    action: str,
    alert_id: str,
    args: dict[str, Any],
    store: NonceStore,
    now: float | None = None,
) -> dict[str, Any]:
    """Check a token for exactly this request, then burn its nonce."""
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        raise ApprovalError("malformed") from None
    if not hmac.compare_digest(sig, _sign(secret, body)):
        raise ApprovalError("bad_signature")
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        raise ApprovalError("malformed") from None
    if (time.time() if now is None else now) > payload.get("exp", 0):
        raise ApprovalError("expired")
    if payload.get("action") != action:
        raise ApprovalError("wrong_action")
    if payload.get("alert_id") != alert_id:
        raise ApprovalError("wrong_alert")
    if canonical(payload.get("args")) != canonical(args):
        raise ApprovalError("wrong_args")
    if store.seen(payload["nonce"]):
        raise ApprovalError("replayed")
    store.add(payload["nonce"])
    return payload
