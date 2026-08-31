"""SOC Lite: malicious/benign fixtures, threshold, and window behavior."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.conftest import LABS, load_module


def _ts(offset_seconds: int) -> str:
    moment = datetime(2026, 8, 31, 14, 0, 0, tzinfo=timezone.utc) + timedelta(
        seconds=offset_seconds
    )
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


@pytest.fixture
def soc(tmp_path, tmp_lab_env):
    log_path = tmp_path / "events.jsonl"
    db_path = tmp_path / "soc.db"
    env = {
        **tmp_lab_env,
        "LOG_PATH": str(log_path),
        "DB_PATH": str(db_path),
        "RULES_PATH": str(LABS / "detections" / "rules.yaml"),
    }
    module = load_module("soc_lite_app", LABS / "soc-lite" / "app.py", env)
    module.init()
    return module, log_path


def test_malicious_login_burst_fires_det001(soc):
    module, log_path = soc
    rows = [
        {
            "ts": _ts(i),
            "event": "login_failure",
            "src_ip": "127.0.0.1",
            "username": "alice",
            "trace_id": f"bf-{i}",
        }
        for i in range(6)
    ]
    _write_jsonl(log_path, rows)
    added = module.ingest()
    assert added == 6
    created = module.evaluate()
    assert any(alert_id.startswith("DET-001:") for alert_id in created)


def test_benign_single_failure_does_not_fire_det001(soc):
    module, log_path = soc
    _write_jsonl(
        log_path,
        [
            {
                "ts": _ts(0),
                "event": "login_failure",
                "src_ip": "127.0.0.1",
                "username": "alice",
                "trace_id": "one",
            }
        ],
    )
    module.ingest()
    created = module.evaluate()
    assert not any(a.startswith("DET-001:") for a in created)


def test_failures_outside_window_do_not_meet_threshold(soc):
    module, log_path = soc
    # DET-001 window is 120s, threshold 5. Five failures spread over 10 minutes
    # should not count as one burst.
    rows = [
        {
            "ts": _ts(i * 180),
            "event": "login_failure",
            "src_ip": "127.0.0.1",
            "username": "alice",
            "trace_id": f"slow-{i}",
        }
        for i in range(5)
    ]
    _write_jsonl(log_path, rows)
    module.ingest()
    created = module.evaluate()
    assert not any(a.startswith("DET-001:") for a in created)


def test_idor_fixture_fires_det002(soc):
    module, log_path = soc
    _write_jsonl(
        log_path,
        [
            {
                "ts": _ts(0),
                "event": "cross_user_note_access",
                "actor": "alice",
                "note_id": 2,
                "owner": "bob",
                "trace_id": "idor-1",
            }
        ],
    )
    module.ingest()
    created = module.evaluate()
    assert any(a.startswith("DET-002:") for a in created)


def test_benign_own_note_read_does_not_fire_det002(soc):
    module, log_path = soc
    _write_jsonl(
        log_path,
        [
            {
                "ts": _ts(0),
                "event": "note_read",
                "actor": "alice",
                "note_id": 1,
                "owner": "alice",
                "trace_id": "own-1",
            }
        ],
    )
    module.ingest()
    created = module.evaluate()
    assert not any(a.startswith("DET-002:") for a in created)


def test_injection_regex_on_search(soc):
    module, log_path = soc
    _write_jsonl(
        log_path,
        [
            {
                "ts": _ts(0),
                "event": "search",
                "actor": "alice",
                "q": "' OR owner = 'bob",
                "trace_id": "inj-1",
            }
        ],
    )
    module.ingest()
    created = module.evaluate()
    assert any(a.startswith("DET-005:") for a in created)
