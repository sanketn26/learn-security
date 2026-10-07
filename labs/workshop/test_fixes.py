"""Module 4b exercises. Each test_exploit_* fails until its vulnerability is fixed.

    python3 -m pytest labs/workshop -q

test_legit_* tests must pass before AND after your fix: a fix that breaks the
feature is not a fix. Payloads are benign and only touch a temp directory.
"""

from __future__ import annotations

import json
from html.parser import HTMLParser

XSS = "<script>alert('lab')</script>"


def login(client, username="alice", password="alice-lab-password") -> dict[str, str]:
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


class _Text(HTMLParser):
    """Visible text of a page, the way a browser would see it (no scripts run)."""

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        self.scripts += tag == "script"

    def handle_data(self, data):
        self.parts.append(data)


def parse(page: str) -> _Text:
    parser = _Text()
    parser.feed(page)
    return parser


# --- Exercise 1: SQL injection, UNION based (A05:2025) ----------------------
UNION = "zzz' UNION SELECT 1, username, password_hash FROM users --"


def test_exploit_union_injection_cannot_read_other_tables(api):
    headers = login(api)
    found = api.get("/search", params={"q": UNION}, headers=headers)
    assert found.status_code == 200  # the payload is just a search string that matches nothing
    leaked = json.dumps(found.json())
    assert "bob" not in leaked and "admin" not in leaked


def test_legit_search_still_finds_own_notes(api):
    headers = login(api)
    found = api.get("/search", params={"q": "grocery"}, headers=headers)
    assert found.status_code == 200
    assert [r["title"] for r in found.json()["results"]] == ["Alice grocery list"]


# --- Exercise 2: stored XSS (A05:2025) --------------------------------------
def _store_note(api, headers, title="t", body=XSS):
    created = api.post("/notes", headers=headers, json={"title": title, "body": body})
    assert created.status_code == 200
    return created.json()["id"]


def test_exploit_stored_script_is_not_rendered_as_markup(api):
    headers = login(api)
    note_id = _store_note(api, headers)
    page = api.get(f"/notes/{note_id}/page", headers=headers)
    assert page.status_code == 200
    assert parse(page.text).scripts == 0


def test_legit_page_shows_note_text(api):
    headers = login(api)
    note_id = _store_note(api, headers, title="Plan", body="a < b & c")
    page = api.get(f"/notes/{note_id}/page", headers=headers)
    assert page.status_code == 200
    text = "".join(parse(page.text).parts)
    assert "Plan" in text and "a < b & c" in text


# --- Exercise 3: path traversal (A01:2025 / A05:2025) -----------------------
def test_exploit_traversal_cannot_read_outside_files_dir(api):
    headers = login(api)
    got = api.get("/files", params={"name": "../canary.txt"}, headers=headers)
    assert "LABFAKE-canary" not in got.text


def test_exploit_traversal_cannot_write_outside_files_dir(api):
    headers = login(api)
    api.post("/files", headers=headers, json={"name": "../pwned.txt", "content": "x"})
    assert not (api.sandbox / "pwned.txt").exists()


def test_legit_file_round_trip(api):
    headers = login(api)
    stored = api.post("/files", headers=headers, json={"name": "todo.txt", "content": "buy milk"})
    assert stored.status_code == 200
    got = api.get("/files", params={"name": "todo.txt"}, headers=headers)
    assert got.status_code == 200 and got.json()["content"] == "buy milk"


# --- Exercise 4: mass assignment (API3:2023) --------------------------------
def test_exploit_user_cannot_set_own_role(api):
    headers = login(api)
    api.patch("/users/me", headers=headers, json={"display_name": "A", "role": "admin"})
    me = api.get("/whoami", headers=login(api))
    assert me.json()["role"] == "user"
    assert api.get("/admin/users", headers=login(api)).status_code in (401, 403)


def test_legit_user_can_set_display_name(api):
    headers = login(api)
    updated = api.patch("/users/me", headers=headers, json={"display_name": "Alice A."})
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "Alice A."


# --- Exercise 5: failing open and verbose errors (A10:2025) -----------------
def test_exploit_policy_error_must_deny(api):
    headers = login(api)  # alice
    bob_note = 2
    got = api.get(f"/notes/{bob_note}/export", headers={**headers, "X-Tenant": "abc"})
    assert got.status_code == 403
    assert "LABFAKE" not in got.text and "bob-note" not in got.text


def test_exploit_errors_do_not_leak_internals(api):
    headers = login(api)
    got = api.get("/notes/1/export", params={"format": "pdf"}, headers=headers)
    assert "Traceback" not in got.text and "app.py" not in got.text


def test_legit_export_own_note(api):
    headers = login(api)
    got = api.get("/notes/1/export", headers=headers)
    assert got.status_code == 200 and got.json()["format"] == "json"
    assert api.get("/notes/2/export", headers=headers).status_code == 403
