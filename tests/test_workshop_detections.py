"""Real notes-api traffic must raise the workshop alerts through soc-lite.

Drives the vulnerable routes with benign payloads, then lets soc-lite ingest
the log notes-api actually wrote. Hand-written fixtures cannot catch a renamed
log field; this can.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import LABS, load_module


def _drive(tmp_path, lab_mode: str):
    env = {
        "LAB_MODE": lab_mode,
        "DATABASE_PATH": str(tmp_path / "notes.db"),
        "LOG_PATH": str(tmp_path / "notes-api.jsonl"),
        "SANDBOX_DIR": str(tmp_path / "sandbox"),
        "JWT_SECRET": "test-jwt-secret-not-for-prod-32b",
    }
    api = load_module(f"wd_notes_{lab_mode}", LABS / "notes-api" / "app.py", env)
    api.init_db()
    with TestClient(api.app) as client:
        token = client.post(
            "/login", json={"username": "alice", "password": "alice-lab-password"}
        ).json()["token"]
        auth = {"Authorization": f"Bearer {token}"}
        client.get("/search", params={"q": "zzz' UNION SELECT 1, username, password_hash FROM users --"}, headers=auth)
        note = client.post("/notes", headers=auth, json={"title": "t", "body": "<script>alert(1)</script>"})
        client.get(f"/notes/{note.json()['id']}/page", headers=auth)
        client.get("/files", params={"name": "../canary.txt"}, headers=auth)
        client.patch("/users/me", headers=auth, json={"role": "admin"})
        client.get("/notes/2/export", headers={**auth, "X-Tenant": "abc"})
    return api


def _alerts(tmp_path, log_path):
    env = {
        "LOG_PATH": str(log_path),
        "DB_PATH": str(tmp_path / "soc.db"),
        "RULES_PATH": str(LABS / "detections" / "rules.yaml"),
    }
    soc = load_module("wd_soc", LABS / "soc-lite" / "app.py", env)
    soc.init()
    soc.ingest()
    return {a.split(":")[0] for a in soc.evaluate()}


@pytest.mark.parametrize("lab_mode", ["true", "false"])
def test_attempts_alert_in_both_modes(tmp_path, lab_mode):
    """Detection is about the attempt, so secure mode must still alert."""
    api = _drive(tmp_path, lab_mode)
    fired = _alerts(tmp_path, api.LOG_PATH)
    assert {"DET-005", "DET-006", "DET-007", "DET-008"} <= fired


def test_fail_open_alert_only_when_the_app_fails_open(tmp_path):
    fired = {}
    for mode in ("true", "false"):
        workdir = tmp_path / mode
        workdir.mkdir()
        fired[mode] = _alerts(workdir, _drive(workdir, mode).LOG_PATH)
    assert "DET-009" in fired["true"]
    assert "DET-009" not in fired["false"]
