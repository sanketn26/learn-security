"""Attack simulator: loopback guard and emitted HTTP operations."""

from __future__ import annotations

import json

import pytest

from tests.conftest import LABS, load_module


@pytest.fixture
def simulate():
    return load_module("attack_simulate", LABS / "attack-sim" / "simulate.py")


def test_refuses_non_loopback(simulate):
    with pytest.raises(SystemExit) as exc:
        simulate.assert_local("http://198.51.100.10:8080")
    assert "Refusing non-local target" in str(exc.value)


def test_refuses_https_even_on_localhost(simulate):
    with pytest.raises(SystemExit) as exc:
        simulate.assert_local("https://127.0.0.1:8080")
    assert "non-http" in str(exc.value)


def test_allows_loopback_http(simulate):
    simulate.assert_local("http://127.0.0.1:8080")
    simulate.assert_local("http://localhost:8080")


def test_idor_emits_get_notes_2(simulate, monkeypatch):
    calls: list[tuple] = []

    def fake_request(base, method, path, token=None, data=None, query=None):
        calls.append((method, path, token, data, query))
        if path == "/login":
            return 200, json.dumps({"token": "lab-token"})
        return 200, json.dumps({"id": 2, "owner": "bob"})

    monkeypatch.setattr(simulate, "request", fake_request)
    simulate.scenario_idor("http://127.0.0.1:8080")
    assert any(method == "GET" and path == "/notes/2" for method, path, *_ in calls)
    assert any(path == "/login" for _, path, *_ in calls)


def test_ssrf_emits_fetch_to_mock_imds(simulate, monkeypatch):
    calls: list[tuple] = []

    def fake_request(base, method, path, token=None, data=None, query=None):
        calls.append((method, path, token, data, query))
        if path == "/login":
            return 200, json.dumps({"token": "lab-token"})
        return 200, "{}"

    monkeypatch.setattr(simulate, "request", fake_request)
    simulate.scenario_ssrf("http://127.0.0.1:8080")
    fetch = [c for c in calls if c[1] == "/fetch"]
    assert fetch
    query = fetch[0][4]
    assert "mock-imds" in query["url"]


def test_brute_force_emits_six_failed_logins(simulate, monkeypatch):
    logins = []

    def fake_request(base, method, path, token=None, data=None, query=None):
        logins.append(data)
        return 401, "{}"

    monkeypatch.setattr(simulate, "request", fake_request)
    simulate.scenario_brute_force("http://127.0.0.1:8080")
    assert len(logins) == 6
    assert all(row["username"] == "alice" for row in logins)
