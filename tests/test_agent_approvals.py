"""Hardened approvals: bound, expiring, single-use, authenticated, argument-checked."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import LABS, load_module

ALERT = {
    "id": "DET-001:127.0.0.1",
    "rule_id": "DET-001",
    "title": "Password guessing",
    "severity": "medium",
    "status": "new",
    "actor": "alice",
    "evidence": [{"event": "login_failure", "username": "alice"}],
}
RESP = {"X-Approver": "analyst-resp", "X-Approver-Key": "lab-approver-key-resp"}


@pytest.fixture
def agent(tmp_lab_env, monkeypatch):
    monkeypatch.setenv("AGENT_APPROVAL_MODE", "bound")
    module = load_module("agent_approvals_app", LABS / "agentic-soc" / "agent.py", tmp_lab_env)
    posted: list[dict] = []

    async def fake_get(path):
        return dict(ALERT) if path.startswith("/alerts/") else {"name": "x.md", "body": ""}

    async def fake_post(path, payload):
        posted.append(payload)
        return {"simulated": True, **payload}

    monkeypatch.setattr(module, "soc_get", fake_get)
    monkeypatch.setattr(module, "soc_post", fake_post)
    module.posted = posted
    with TestClient(module.app) as client:
        client.module = module
        yield client


def _body(**over):
    return {"alert_id": ALERT["id"], "action": "snapshot_logs", **over}


def _mint(client, headers=RESP, params=None, **over):
    return client.post("/approvals", headers=headers, params=params, json=_body(**over))


def test_health_reports_the_approval_mode(agent):
    assert agent.get("/health").json()["approval_mode"] == "bound"


def test_legacy_string_is_not_enough_in_bound_mode(agent):
    got = agent.post("/actions", json=_body(approval="APPROVE"))
    assert got.status_code == 403 and "approval_token" in got.json()["detail"]
    assert agent.module.posted == []


def test_minted_token_runs_exactly_once(agent):
    token = _mint(agent).json()["token"]
    first = agent.post("/actions", json=_body(approval_token=token))
    assert first.status_code == 200
    assert agent.module.posted[-1]["actor"] == "analyst-resp"  # the approver, not the caller
    again = agent.post("/actions", json=_body(approval_token=token))
    assert again.status_code == 403 and "replayed" in again.json()["detail"]
    assert len(agent.module.posted) == 1


def test_token_is_bound_to_the_action(agent):
    token = _mint(agent, action="snapshot_logs").json()["token"]
    got = agent.post("/actions", json=_body(action="disable_lab_mode", approval_token=token))
    assert got.status_code == 403 and "wrong_action" in got.json()["detail"]


def test_token_is_bound_to_the_alert(agent):
    token = _mint(agent).json()["token"]
    got = agent.post("/actions", json=_body(alert_id="DET-002:alice", approval_token=token))
    assert got.status_code == 403 and "wrong_alert" in got.json()["detail"]


def test_token_is_bound_to_the_arguments(agent):
    agent_alert = dict(ALERT, evidence=[{"username": "alice"}, {"username": "bob"}])

    async def fake_get(path):
        return dict(agent_alert) if path.startswith("/alerts/") else {}

    agent.module.soc_get = fake_get
    token = _mint(agent, action="block_actor", target_actor="alice").json()["token"]
    got = agent.post("/actions", json=_body(action="block_actor", target_actor="bob", approval_token=token))
    assert got.status_code == 403 and "wrong_args" in got.json()["detail"]


def test_expired_token_is_refused(agent, monkeypatch):
    token = _mint(agent).json()["token"]
    real = agent.module.approvals.time.time
    monkeypatch.setattr(agent.module.approvals.time, "time", lambda: real() + 3600)
    got = agent.post("/actions", json=_body(approval_token=token))
    assert got.status_code == 403 and "expired" in got.json()["detail"]


def test_forged_or_garbled_tokens_are_refused(agent):
    good = _mint(agent).json()["token"]
    body, sig = good.split(".")
    for bad, reason in ((body + "." + "A" * len(sig), "bad_signature"), ("nonsense", "malformed")):
        got = agent.post("/actions", json=_body(approval_token=bad))
        assert got.status_code == 403 and reason in got.json()["detail"], bad


def test_minting_needs_real_credentials(agent):
    assert _mint(agent, headers={}).status_code == 401
    wrong = {"X-Approver": "analyst-resp", "X-Approver-Key": "guess"}
    assert _mint(agent, headers=wrong).status_code == 401


def test_a_role_without_respond_cannot_approve(agent):
    ro = {"X-Approver": "analyst-ro", "X-Approver-Key": "lab-approver-key-ro"}
    got = _mint(agent, headers=ro)
    assert got.status_code == 403 and "cannot approve" in got.json()["detail"]


def test_requester_cannot_approve_their_own_request(agent):
    got = _mint(agent, params={"requested_by": "analyst-resp"})
    assert got.status_code == 403 and "own request" in got.json()["detail"]
    assert _mint(agent, params={"requested_by": "analyst-ro"}).status_code == 200


def test_protected_actor_cannot_be_blocked_even_with_a_valid_approval(agent):
    got = _mint(agent, action="block_actor", target_actor="admin")
    assert got.status_code == 403 and "protected" in got.json()["detail"]


def test_target_must_appear_in_the_alert_evidence(agent):
    got = _mint(agent, action="block_actor", target_actor="mallory")
    assert got.status_code == 403 and "evidence" in got.json()["detail"]


def test_block_actor_defaults_to_the_alert_actor(agent):
    minted = _mint(agent, action="block_actor").json()
    assert minted["binds"]["args"] == {"target_actor": "alice"}


def test_nonces_survive_a_restart(agent, tmp_lab_env, monkeypatch):
    token = _mint(agent).json()["token"]
    assert agent.post("/actions", json=_body(approval_token=token)).status_code == 200
    again = load_module("agent_approvals_restart", LABS / "agentic-soc" / "agent.py", tmp_lab_env)
    store = again.approvals.NonceStore(again.NONCE_PATH)
    payload_nonce = __import__("json").loads(
        again.approvals._unb64(token.split(".")[0])
    )["nonce"]
    assert store.seen(payload_nonce)


def test_approval_from_the_queue_takes_the_requester_from_the_queue(agent):
    """Leaving requested_by out must not let an approver approve their own request."""
    agent.module.PENDING_REQUESTS.clear()
    agent.module.PENDING_REQUESTS.append(
        {"id": "req1", "action": "snapshot_logs", "alert_id": ALERT["id"], "requested_by": "analyst-resp", "args": {}, "status": "pending"}
    )
    own = agent.post("/approvals?request_id=req1", headers=RESP, json=_body())
    assert own.status_code == 403 and "own request" in own.json()["detail"]
    agent.module.PENDING_REQUESTS[0]["requested_by"] = "analyst-ro"
    ok = agent.post("/approvals?request_id=req1", headers=RESP, json=_body())
    assert ok.status_code == 200 and agent.module.PENDING_REQUESTS[0]["status"] == "approved"
    again = agent.post("/approvals?request_id=req1", headers=RESP, json=_body())
    assert again.status_code == 404  # a request is approved once


def test_approval_must_match_the_queued_request(agent):
    agent.module.PENDING_REQUESTS.clear()
    agent.module.PENDING_REQUESTS.append(
        {"id": "req2", "action": "snapshot_logs", "alert_id": ALERT["id"], "requested_by": "analyst-ro", "args": {}, "status": "pending"}
    )
    got = agent.post("/approvals?request_id=req2", headers=RESP, json=_body(action="disable_lab_mode"))
    assert got.status_code == 422
    assert agent.post("/approvals?request_id=nope", headers=RESP, json=_body()).status_code == 404


def test_an_action_or_approval_must_name_an_alert_that_exists(agent):
    import httpx

    async def missing(path):
        raise httpx.HTTPError("404")

    agent.module.soc_get = missing
    assert _mint(agent, alert_id="DET-999:nobody").status_code == 404
    got = agent.post("/actions", json=_body(alert_id="DET-999:nobody", approval_token="x"))
    assert got.status_code == 404 and agent.module.posted == []
