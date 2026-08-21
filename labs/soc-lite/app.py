"""Lightweight SOC: ingest JSONL logs, evaluate detection rules, manage cases."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

LOG_PATH = os.getenv("LOG_PATH", "/logs/notes-api.jsonl")
DB_PATH = os.getenv("DB_PATH", "/cases/soc.db")
RULES_PATH = os.getenv("RULES_PATH", "/app/rules.yaml")
PLAYBOOK_DIR = os.getenv("PLAYBOOK_DIR", "/app/playbooks")

app = FastAPI(title="SOC Lite", version="0.1.0")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            event TEXT,
            raw TEXT,
            fingerprint TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            rule_id TEXT,
            title TEXT,
            severity TEXT,
            actor TEXT,
            src_ip TEXT,
            technique_id TEXT,
            tactic TEXT,
            status TEXT,
            created_at TEXT,
            evidence TEXT
        );
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT,
            severity TEXT,
            status TEXT,
            alert_ids TEXT,
            timeline TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            actor TEXT,
            action TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS offsets (
            path TEXT PRIMARY KEY,
            pos INTEGER
        );
        """
    )
    conn.commit()
    conn.close()


def load_rules() -> list[dict[str, Any]]:
    with open(RULES_PATH, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data.get("rules", [])


def parse_ts(value: str | None) -> float:
    if not value:
        return time.time()
    try:
        return datetime.strptime(value[:26], "%Y-%m-%dT%H:%M:%S.%f").replace(
            tzinfo=timezone.utc
        ).timestamp()
    except ValueError:
        return time.time()


def fingerprint(record: dict[str, Any]) -> str:
    return "|".join(
        [
            str(record.get("ts", "")),
            str(record.get("event", "")),
            str(record.get("trace_id", "")),
            str(record.get("actor", "")),
            str(record.get("username", "")),
            str(record.get("note_id", "")),
            str(record.get("url", "")),
        ]
    )


def ingest() -> int:
    if not os.path.exists(LOG_PATH):
        return 0
    conn = connect()
    row = conn.execute("SELECT pos FROM offsets WHERE path = ?", (LOG_PATH,)).fetchone()
    pos = row["pos"] if row else 0
    added = 0
    with open(LOG_PATH, encoding="utf-8") as handle:
        handle.seek(pos)
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            fp = fingerprint(record)
            try:
                conn.execute(
                    "INSERT INTO events(ts, event, raw, fingerprint) VALUES (?, ?, ?, ?)",
                    (record.get("ts"), record.get("event"), json.dumps(record), fp),
                )
                added += 1
            except sqlite3.IntegrityError:
                continue
        new_pos = handle.tell()
    conn.execute(
        "INSERT INTO offsets(path, pos) VALUES (?, ?) ON CONFLICT(path) DO UPDATE SET pos = excluded.pos",
        (LOG_PATH, new_pos),
    )
    conn.commit()
    conn.close()
    return added


def group_key(record: dict[str, Any], fields: list[str]) -> str:
    return "|".join(str(record.get(field, record.get("username", ""))) for field in fields)


def evaluate() -> list[str]:
    rules = load_rules()
    conn = connect()
    events = [
        json.loads(row["raw"])
        for row in conn.execute("SELECT raw FROM events ORDER BY id").fetchall()
    ]
    created: list[str] = []
    now = time.time()
    for rule in rules:
        matching = [e for e in events if e.get("event") == rule["event"]]
        pattern = rule.get("match_regex")
        field = rule.get("match_field")
        if pattern and field:
            regex = re.compile(pattern, re.IGNORECASE)
            matching = [e for e in matching if regex.search(str(e.get(field, "")))]
        buckets: dict[str, list[dict[str, Any]]] = {}
        for event in matching:
            ts = parse_ts(event.get("ts"))
            if now - ts > rule.get("window_seconds", 3600) * 3:
                # keep a little history; still evaluate recent window below
                pass
            buckets.setdefault(group_key(event, rule.get("group_by", ["actor"])), []).append(event)
        for key, bucket in buckets.items():
            window = rule.get("window_seconds", 3600)
            # Event-time window: relative to the newest event in the bucket,
            # not wall clock. Delayed ingest still fires DET-001.
            latest = max(parse_ts(e.get("ts")) for e in bucket)
            recent = [
                e
                for e in bucket
                if latest - parse_ts(e.get("ts")) <= window
            ]
            if len(recent) < rule.get("threshold", 1):
                continue
            sample = recent[-1]
            actor = sample.get("actor") or sample.get("username") or key
            src_ip = sample.get("src_ip")
            alert_id = f"{rule['id']}:{key}"
            existing = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            evidence = json.dumps(recent[-10:])
            attack = rule.get("attack", {})
            if existing:
                conn.execute(
                    "UPDATE alerts SET evidence = ?, created_at = created_at WHERE id = ?",
                    (evidence, alert_id),
                )
                continue
            conn.execute(
                """
                INSERT INTO alerts(id, rule_id, title, severity, actor, src_ip, technique_id, tactic, status, created_at, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)
                """,
                (
                    alert_id,
                    rule["id"],
                    rule["name"],
                    rule.get("severity", "low"),
                    actor,
                    src_ip,
                    attack.get("technique_id"),
                    attack.get("tactic"),
                    utcnow(),
                    evidence,
                ),
            )
            created.append(alert_id)
    conn.commit()
    conn.close()
    return created


@app.on_event("startup")
def on_startup() -> None:
    init()
    ingest()
    evaluate()


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True}


@app.post("/ingest")
def run_ingest() -> dict[str, Any]:
    added = ingest()
    alerts = evaluate()
    return {"events_added": added, "new_alerts": alerts}


@app.get("/alerts")
def list_alerts(status: str | None = None) -> dict[str, Any]:
    ingest()
    evaluate()
    conn = connect()
    if status:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    conn.close()
    alerts = []
    for row in rows:
        item = dict(row)
        item["evidence"] = json.loads(item["evidence"]) if item["evidence"] else []
        alerts.append(item)
    return {"alerts": alerts}


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    conn = connect()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    item = dict(row)
    item["evidence"] = json.loads(item["evidence"]) if item["evidence"] else []
    return item


@app.get("/events")
def list_events(
    event: str | None = None,
    q: str | None = None,
    limit: int = 100,
    order: str = "desc",
) -> dict[str, Any]:
    ingest()
    conn = connect()
    sql = "SELECT ts, event, raw FROM events WHERE 1=1"
    args: list[Any] = []
    if event:
        sql += " AND event = ?"
        args.append(event)
    if q:
        sql += " AND raw LIKE ?"
        args.append(f"%{q}%")
    direction = "ASC" if order.lower() == "asc" else "DESC"
    sql += f" ORDER BY ts {direction}, id {direction} LIMIT ?"
    args.append(min(limit, 500))
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return {"events": [json.loads(r["raw"]) for r in rows]}


class CaseCreate(BaseModel):
    title: str
    alert_ids: list[str]
    severity: str = "medium"


@app.post("/cases")
def create_case(body: CaseCreate) -> dict[str, Any]:
    case_id = str(uuid.uuid4())[:8]
    now = utcnow()
    conn = connect()
    conn.execute(
        "INSERT INTO cases(id, title, severity, status, alert_ids, timeline, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            case_id,
            body.title,
            body.severity,
            "open",
            json.dumps(body.alert_ids),
            json.dumps([{"ts": now, "event": "case_opened", "detail": body.title}]),
            now,
            now,
        ),
    )
    for alert_id in body.alert_ids:
        conn.execute("UPDATE alerts SET status = 'cased' WHERE id = ?", (alert_id,))
    conn.execute(
        "INSERT INTO audit(ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now, "analyst", "create_case", case_id),
    )
    conn.commit()
    conn.close()
    return {"id": case_id, "status": "open"}


@app.get("/cases")
def list_cases() -> dict[str, Any]:
    conn = connect()
    rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    cases = []
    for row in rows:
        item = dict(row)
        item["alert_ids"] = json.loads(item["alert_ids"])
        item["timeline"] = json.loads(item["timeline"])
        cases.append(item)
    return {"cases": cases}


@app.get("/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    conn = connect()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    item = dict(row)
    item["alert_ids"] = json.loads(item["alert_ids"])
    item["timeline"] = json.loads(item["timeline"])
    return item


class CaseUpdate(BaseModel):
    status: str | None = None
    note: str | None = None
    actor: str = "analyst"


@app.post("/cases/{case_id}/update")
def update_case(case_id: str, body: CaseUpdate) -> dict[str, Any]:
    conn = connect()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="not found")
    timeline = json.loads(row["timeline"])
    now = utcnow()
    if body.note:
        timeline.append({"ts": now, "event": "note", "detail": body.note, "actor": body.actor})
    status = body.status or row["status"]
    if body.status:
        timeline.append({"ts": now, "event": "status", "detail": body.status, "actor": body.actor})
    conn.execute(
        "UPDATE cases SET status = ?, timeline = ?, updated_at = ? WHERE id = ?",
        (status, json.dumps(timeline), now, case_id),
    )
    conn.execute(
        "INSERT INTO audit(ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now, body.actor, "update_case", f"{case_id}:{status}"),
    )
    conn.commit()
    conn.close()
    return {"id": case_id, "status": status}


@app.get("/playbooks")
def list_playbooks() -> dict[str, Any]:
    if not os.path.isdir(PLAYBOOK_DIR):
        return {"playbooks": []}
    names = sorted(p for p in os.listdir(PLAYBOOK_DIR) if p.endswith(".md"))
    return {"playbooks": names}


@app.get("/playbooks/{name}")
def get_playbook(name: str) -> dict[str, str]:
    if "/" in name or "\\" in name or not name.endswith(".md"):
        raise HTTPException(status_code=400, detail="invalid name")
    path = os.path.join(PLAYBOOK_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="not found")
    with open(path, encoding="utf-8") as handle:
        return {"name": name, "body": handle.read()}


class SimulatedAction(BaseModel):
    action: str
    target: str
    approval: str
    actor: str = "analyst"


ALLOWED_ACTIONS = {
    "disable_lab_mode": "Set LAB_MODE=false and restart notes-api (operator performs this).",
    "revoke_token_notice": "Record that JWT_SECRET should be rotated.",
    "block_actor": "Record a local containment note for the actor. No network block is applied.",
    "snapshot_logs": "Recorded a simulated preservation note in SOC audit. Does not copy files; run labs/scripts/preserve-logs.sh.",
}


@app.post("/actions/simulate")
def simulate_action(body: SimulatedAction) -> dict[str, Any]:
    if body.approval != "APPROVE":
        raise HTTPException(status_code=403, detail="human approval required: send approval=APPROVE")
    if body.action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail="unknown action")
    now = utcnow()
    conn = connect()
    conn.execute(
        "INSERT INTO audit(ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now, body.actor, f"simulate:{body.action}", body.target),
    )
    conn.commit()
    conn.close()
    return {
        "status": "simulated",
        "action": body.action,
        "target": body.target,
        "effect": ALLOWED_ACTIONS[body.action],
        "warning": "No production system was changed. AUTHORIZED LAB USE ONLY.",
    }
