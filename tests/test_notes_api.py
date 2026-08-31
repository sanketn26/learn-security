"""Notes API: health, auth, authz, CRUD, LAB_MODE."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from tests.conftest import LABS, load_module


def _app(tmp_lab_env: dict[str, str], lab_mode: str):
    env = {**tmp_lab_env, "LAB_MODE": lab_mode}
    # Isolate sqlite/jsonl per mode so reloads do not share files incorrectly.
    suffix = "lab" if lab_mode == "true" else "secure"
    env["DATABASE_PATH"] = tmp_lab_env["DATABASE_PATH"] + f".{suffix}"
    env["LOG_PATH"] = tmp_lab_env["LOG_PATH"] + f".{suffix}"
    os.environ.update(env)
    module = load_module(f"notes_api_{suffix}", LABS / "notes-api" / "app.py", env)
    module.init_db()
    return module


@pytest.fixture
def lab_client(tmp_lab_env):
    module = _app(tmp_lab_env, "true")
    with TestClient(module.app) as client:
        yield client, module


@pytest.fixture
def secure_client(tmp_lab_env):
    module = _app(tmp_lab_env, "false")
    with TestClient(module.app) as client:
        yield client, module


def _login(client, username="alice", password="alice-lab-password"):
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def test_health_and_lab_banner(lab_client):
    client, _ = lab_client
    health = client.get("/health")
    assert health.status_code == 200
    body = health.json()
    assert body["ok"] is True
    assert body["lab_mode"] is True
    banner = client.get("/.well-known/lab")
    assert banner.status_code == 200
    assert "AUTHORIZED LAB USE ONLY" in banner.json()["warning"]


def test_login_failure_is_401(lab_client):
    client, module = lab_client
    response = client.post(
        "/login", json={"username": "alice", "password": "wrong-password"}
    )
    assert response.status_code == 401
    log = open(os.environ["LOG_PATH"], encoding="utf-8").read()
    assert "login_failure" in log


def test_missing_token_is_401(lab_client):
    client, _ = lab_client
    assert client.get("/notes").status_code == 401
    assert client.get("/notes/1").status_code == 401


def test_invalid_token_is_401(lab_client):
    client, _ = lab_client
    response = client.get("/notes", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


def test_crud_own_notes(lab_client):
    client, _ = lab_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    listed = client.get("/notes", headers=headers)
    assert listed.status_code == 200
    assert any(n["owner"] == "alice" for n in listed.json()["notes"])
    created = client.post(
        "/notes",
        headers=headers,
        json={"title": "lab note", "body": "dummy body"},
    )
    assert created.status_code == 200
    note_id = created.json()["id"]
    fetched = client.get(f"/notes/{note_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["body"] == "dummy body"


def test_lab_mode_allows_idor(lab_client):
    client, _ = lab_client
    token = _login(client, "alice")
    response = client.get("/notes/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["owner"] == "bob"


def test_secure_mode_blocks_idor(secure_client):
    client, module = secure_client
    assert module.LAB_MODE is False
    token = _login(client, "alice")
    response = client.get("/notes/2", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404


def test_lab_mode_allows_broken_function_authz(lab_client):
    client, _ = lab_client
    token = _login(client, "alice")
    response = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    names = {u["username"] for u in response.json()["users"]}
    assert {"alice", "bob", "admin"} <= names


def test_secure_mode_blocks_admin_for_user(secure_client):
    client, _ = secure_client
    token = _login(client, "alice")
    response = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_safety_rail_blocks_public_fetch_even_in_lab_mode(lab_client):
    client, _ = lab_client
    token = _login(client)
    response = client.get(
        "/fetch",
        headers={"Authorization": f"Bearer {token}"},
        params={"url": "http://example.com/"},
    )
    assert response.status_code == 400
    assert "safety rail" in response.json()["detail"]
