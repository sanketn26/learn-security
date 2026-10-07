"""Workshop routes: safety rails and the log fields the detections depend on."""

from __future__ import annotations

import json

from tests.test_notes_api import _login, lab_client, secure_client  # noqa: F401


def _events(module, name):
    with open(module.LOG_PATH, encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    return [r for r in records if r["event"] == name]


def _auth(client, user="alice"):
    return {"Authorization": f"Bearer {_login(client, user, f'{user}-lab-password')}"}


def test_lab_traversal_works_inside_sandbox_and_logs_it(lab_client):
    client, module = lab_client
    got = client.get("/files", params={"name": "../canary.txt"}, headers=_auth(client))
    assert got.status_code == 200 and "LABFAKE-canary" in got.json()["content"]
    event = _events(module, "file_access")[-1]
    assert event["traversal"] == "yes" and event["op"] == "read"


def test_safety_rail_blocks_traversal_outside_sandbox_even_in_lab_mode(lab_client):
    client, module = lab_client
    headers = _auth(client)
    for name in ("/etc/hosts", "../../../../../../etc/hosts", "../../notes.db"):
        got = client.get("/files", params={"name": name}, headers=headers)
        assert got.status_code == 400, name
        assert "safety rail" in got.json()["detail"]
    wrote = client.post("/files", headers=headers, json={"name": "/tmp/lab-escape", "content": "x"})
    assert wrote.status_code == 400
    assert _events(module, "file_blocked_safety_rail")


def test_secure_mode_isolates_files_per_user(secure_client):
    client, _ = secure_client
    alice, bob = _auth(client, "alice"), _auth(client, "bob")
    client.post("/files", headers=alice, json={"name": "mine.txt", "content": "alice only"})
    assert client.get("/files", params={"name": "mine.txt"}, headers=bob).status_code == 404
    for name in ("../canary.txt", "a/b.txt", ".hidden", "", "x" * 101):
        got = client.get("/files", params={"name": name}, headers=alice)
        assert got.status_code in (400, 404, 422), name


def test_mass_assignment_logs_privileged_attempt_in_both_modes(lab_client, secure_client):
    for client, module in (lab_client, secure_client):
        client.patch("/users/me", headers=_auth(client), json={"role": "admin"})
        event = _events(module, "privileged_field_update")[-1]
        assert event["fields"] == ["role"] and event["applied"] is module.LAB_MODE


def test_lab_mass_assignment_ignores_unlisted_columns(lab_client):
    client, module = lab_client
    client.patch("/users/me", headers=_auth(client), json={"password_hash": "x", "display_name": "A"})
    assert client.post("/login", json={"username": "alice", "password": "alice-lab-password"}).status_code == 200


def test_lab_mass_assignment_escalates_after_relogin(lab_client):
    client, _ = lab_client
    client.patch("/users/me", headers=_auth(client), json={"role": "admin"})
    assert client.get("/whoami", headers=_auth(client)).json()["role"] == "admin"


def test_render_logs_markup_kind_in_both_modes(lab_client, secure_client):
    for client, module in (lab_client, secure_client):
        headers = _auth(client)
        note = client.post("/notes", headers=headers, json={"title": "t", "body": "<img src=x onerror=alert(1)>"})
        client.get(f"/notes/{note.json()['id']}/page", headers=headers)
        assert _events(module, "note_render")[-1]["markup"] == "handler"


def test_secure_page_blocks_other_users_notes(secure_client):
    client, _ = secure_client
    assert client.get("/notes/2/page", headers=_auth(client)).status_code == 404


def test_fail_open_is_logged_in_lab_and_denied_in_secure(lab_client, secure_client):
    client, module = lab_client
    got = client.get("/notes/2/export", headers={**_auth(client), "X-Tenant": "abc"})
    assert got.status_code == 200
    assert _events(module, "authz_fail_open")[-1]["owner"] == "bob"
    client, module = secure_client
    got = client.get("/notes/2/export", headers={**_auth(client), "X-Tenant": "abc"})
    assert got.status_code == 403
    assert _events(module, "authz_error_denied")


def test_wrong_tenant_is_denied_in_both_modes(lab_client, secure_client):
    for client, _ in (lab_client, secure_client):
        got = client.get("/notes/1/export", headers={**_auth(client), "X-Tenant": "2"})
        assert got.status_code == 403


def test_init_db_migrates_a_pre_workshop_database(tmp_lab_env):
    """A lab volume created before display_name existed must keep working."""
    import sqlite3

    from tests.conftest import LABS, load_module

    env = {**tmp_lab_env, "LAB_MODE": "true"}
    conn = sqlite3.connect(env["DATABASE_PATH"])
    conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL)")
    conn.execute("INSERT INTO users VALUES ('alice', 'x', 'user')")
    conn.commit()
    conn.close()
    module = load_module("notes_api_migrate", LABS / "notes-api" / "app.py", env)
    module.init_db()
    module.init_db()  # idempotent
    with module.db() as db:
        columns = {r["name"] for r in db.execute("PRAGMA table_info(users)")}
        row = db.execute("SELECT display_name FROM users WHERE username = 'alice'").fetchone()
    assert "display_name" in columns and row["display_name"] == ""


def test_nul_byte_in_file_name_is_refused_not_a_server_error(lab_client, secure_client):
    for client, _ in (lab_client, secure_client):
        got = client.get("/files", params={"name": "a\x00b"}, headers=_auth(client))
        assert got.status_code == 400


def test_canary_is_restored_on_startup(lab_client):
    client, module = lab_client
    headers = _auth(client)
    client.post("/files", headers=headers, json={"name": "../canary.txt", "content": "overwritten"})
    module.init_sandbox()
    got = client.get("/files", params={"name": "../canary.txt"}, headers=headers)
    assert "LABFAKE-canary" in got.json()["content"]


def test_secure_export_does_not_reveal_which_note_ids_exist(lab_client, secure_client):
    client, _ = secure_client
    headers = _auth(client)
    other = client.get("/notes/2/export", headers=headers)
    missing = client.get("/notes/9999/export", headers=headers)
    assert (other.status_code, other.json()) == (missing.status_code, missing.json())
    client, _ = lab_client  # lab mode keeps the oracle on purpose: it is part of the weak design
    assert client.get("/notes/9999/export", headers=_auth(client)).status_code == 404


def test_logged_file_name_is_capped(lab_client):
    client, module = lab_client
    long_name = "a" * 5000
    client.get("/files", params={"name": long_name}, headers=_auth(client))
    event = _events(module, "file_access")[-1]
    assert len(event["name"]) == 200
