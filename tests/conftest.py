"""Shared fixtures for lab-platform tests. No live compose stack required."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"


def load_module(name: str, path: Path, env: dict[str, str] | None = None) -> ModuleType:
    """Load a lab file as a fresh module after applying env vars."""
    if env:
        os.environ.update(env)
    directory = str(path.parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def tmp_lab_env(tmp_path: Path) -> dict[str, str]:
    log_path = tmp_path / "notes-api.jsonl"
    db_path = tmp_path / "notes.db"
    cases_db = tmp_path / "soc.db"
    audit = tmp_path / "agent-audit.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return {
        "DATABASE_PATH": str(db_path),
        "LOG_PATH": str(log_path),
        "JWT_SECRET": "test-jwt-secret-not-for-prod-32b",
        "DB_PATH": str(cases_db),
        "RULES_PATH": str(LABS / "detections" / "rules.yaml"),
        "POLICY_PATH": str(LABS / "agentic-soc" / "policy.yaml"),
        "AUDIT_PATH": str(audit),
        "PLAYBOOK_DIR": str(LABS / "soc-lite" / "playbooks"),
        "LLM_BASE_URL": "",
        "LLM_MODEL": "",
        "LLM_API_KEY": "",
    }
