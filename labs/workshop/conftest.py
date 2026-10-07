"""Fixtures for the secure-coding workshop (Module 4b).

The tests in this directory describe SAFE behavior. Run against a LAB_MODE=true
app they fail until you patch the vulnerable branch in labs/notes-api/app.py.
WORKSHOP_LAB_MODE=false runs them against the reference fix instead.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from tests.conftest import LABS, load_module


@pytest.fixture
def api(tmp_path):
    lab_mode = os.getenv("WORKSHOP_LAB_MODE", "true").lower()
    env = {
        "LAB_MODE": lab_mode,
        "DATABASE_PATH": str(tmp_path / "notes.db"),
        "LOG_PATH": str(tmp_path / "notes-api.jsonl"),
        "SANDBOX_DIR": str(tmp_path / "sandbox"),
        "JWT_SECRET": "test-jwt-secret-not-for-prod-32b",
    }
    module = load_module("workshop_notes_api", LABS / "notes-api" / "app.py", env)
    module.init_db()
    with TestClient(module.app) as client:
        client.module = module
        client.sandbox = tmp_path / "sandbox"
        client.log = tmp_path / "notes-api.jsonl"
        yield client

