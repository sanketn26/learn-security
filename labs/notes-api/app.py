"""Intentionally dual-mode notes API.

LAB_MODE=true enables documented vulnerabilities for authorized local labs.
A hard safety rail still blocks non-lab fetch destinations.

This file is not production software.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import bcrypt
import httpx
import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from seed import NOTES, USERS

LAB_MODE = os.getenv("LAB_MODE", "true").lower() == "true"
JWT_SECRET = os.getenv("JWT_SECRET", "lab-jwt-secret-change-me-32b-min")
DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/notes.db")
LOG_PATH = os.getenv("LOG_PATH", "/logs/notes-api.jsonl")
MOCK_IMDS_URL = os.getenv("MOCK_IMDS_URL", "http://mock-imds")

# Lab safety rail: even in LAB_MODE, the process cannot fetch the public
# internet, file URLs, or the learner's host. This is not a production control.
LAB_FETCH_ALLOWLIST = {
    "mock-imds",
    "metadata.internal",
    "notes-api",
    "soc-lite",
    "agentic-soc",
}
# Optional extra names for the venv/no-Docker path. Never add public hosts.
LAB_FETCH_ALLOWLIST.update(
    h.strip().lower()
    for h in os.getenv("LAB_FETCH_EXTRA_HOSTS", "").split(",")
    if h.strip()
)

app = FastAPI(title="Lab Notes API", version="0.1.0")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def audit(event: str, **fields: Any) -> None:
    record = {
        "ts": utcnow(),
        "event": event,
        "service": "notes-api",
        "lab_mode": LAB_MODE,
        "trace_id": fields.pop("trace_id", str(uuid.uuid4())),
        **fields,
    }
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")


@contextmanager
def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DATABASE_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    if LAB_MODE:
        # Weak: unsalted SHA-256. Authorized lab use only.
        return hashlib.sha256(password.encode()).hexdigest()
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, stored: str) -> bool:
    if LAB_MODE:
        return hash_password(password) == stored
    return bcrypt.checkpw(password.encode(), stored.encode())


def init_db() -> None:
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                owner TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                visibility TEXT NOT NULL
            )
            """
        )
        if conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
            for user in USERS:
                conn.execute(
                    "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                    (user["username"], hash_password(user["password"]), user["role"]),
                )
            for note in NOTES:
                conn.execute(
                    "INSERT INTO notes(id, owner, title, body, visibility) VALUES (?, ?, ?, ?, ?)",
                    (note["id"], note["owner"], note["title"], note["body"], note["visibility"]),
                )


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    audit("service_start", lab_fetch_allowlist=sorted(LAB_FETCH_ALLOWLIST))


class LoginRequest(BaseModel):
    username: str
    password: str


class NoteCreate(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=4000)


def issue_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {"sub": username, "role": role, "iat": now}
    if not LAB_MODE:
        payload["exp"] = now + 900
        payload["iss"] = "notes-api"
        payload["aud"] = "notes-api"
    algorithm = "HS256"
    return jwt.encode(payload, JWT_SECRET, algorithm=algorithm)


def current_user(authorization: str | None) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = authorization.split(" ", 1)[1]
    try:
        options = {"require": []} if LAB_MODE else {"require": ["exp", "sub"]}
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options=options,
            audience="notes-api" if not LAB_MODE else None,
            issuer="notes-api" if not LAB_MODE else None,
        )
    except jwt.PyJWTError as exc:
        audit("authz_failure", reason="invalid_token", error=str(exc))
        raise HTTPException(status_code=401, detail="invalid token") from exc
    return {"username": payload["sub"], "role": payload.get("role", "user")}


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "lab_mode": LAB_MODE}


@app.get("/.well-known/lab")
def lab_banner() -> dict[str, str]:
    return {
        "warning": "AUTHORIZED LAB USE ONLY",
        "scope": "local Docker compose network learn-security-labnet",
        "do_not": "use against any system you do not own",
    }


@app.post("/login")
def login(body: LoginRequest, request: Request) -> dict[str, str]:
    src = request.client.host if request.client else "unknown"
    with db() as conn:
        row = conn.execute(
            "SELECT username, password_hash, role FROM users WHERE username = ?",
            (body.username,),
        ).fetchone()
    if row is None or not verify_password(body.password, row["password_hash"]):
        audit("login_failure", username=body.username, src_ip=src)
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = issue_token(row["username"], row["role"])
    audit("login_success", username=row["username"], role=row["role"], src_ip=src)
    return {"token": token, "username": row["username"], "role": row["role"]}


@app.get("/notes")
def list_notes(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = current_user(authorization)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, owner, title, visibility FROM notes WHERE owner = ?",
            (user["username"],),
        ).fetchall()
    audit("notes_list", actor=user["username"], count=len(rows))
    return {"notes": [dict(r) for r in rows]}


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = current_user(authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT id, owner, title, body, visibility FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    if not LAB_MODE and row["owner"] != user["username"] and user["role"] != "admin":
        audit(
            "authz_failure",
            reason="idor_blocked",
            actor=user["username"],
            note_id=note_id,
            owner=row["owner"],
        )
        raise HTTPException(status_code=404, detail="not found")
    if row["owner"] != user["username"]:
        audit(
            "cross_user_note_access",
            actor=user["username"],
            note_id=note_id,
            owner=row["owner"],
            lab_mode=LAB_MODE,
        )
    else:
        audit("note_read", actor=user["username"], note_id=note_id, owner=row["owner"])
    return dict(row)


@app.post("/notes")
def create_note(body: NoteCreate, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = current_user(authorization)
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO notes(owner, title, body, visibility) VALUES (?, ?, ?, ?)",
            (user["username"], body.title, body.body, "private"),
        )
        note_id = cur.lastrowid
    audit("note_create", actor=user["username"], note_id=note_id)
    return {"id": note_id, "owner": user["username"], "title": body.title}


@app.get("/search")
def search(q: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Search titles. In LAB_MODE the query is concatenated (injection demo)."""
    user = current_user(authorization)
    with db() as conn:
        if LAB_MODE:
            # AUTHORIZED LAB USE ONLY. Demonstrates A05:2025 Injection.
            sql = (
                "SELECT id, owner, title FROM notes "
                f"WHERE owner = '{user['username']}' AND title LIKE '%{q}%'"
            )
            try:
                rows = conn.execute(sql).fetchall()
            except sqlite3.Error as exc:
                audit("search_error", actor=user["username"], q=q, error=str(exc))
                raise HTTPException(status_code=400, detail="bad query") from exc
        else:
            rows = conn.execute(
                "SELECT id, owner, title FROM notes WHERE owner = ? AND title LIKE ?",
                (user["username"], f"%{q}%"),
            ).fetchall()
    audit("search", actor=user["username"], q=q, count=len(rows), injected=LAB_MODE)
    return {"results": [dict(r) for r in rows]}


@app.get("/admin/users")
def admin_users(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = current_user(authorization)
    if not LAB_MODE and user["role"] != "admin":
        audit("authz_failure", reason="admin_blocked", actor=user["username"])
        raise HTTPException(status_code=403, detail="forbidden")
    if user["role"] != "admin":
        audit("broken_function_authz", actor=user["username"], endpoint="/admin/users")
    with db() as conn:
        rows = conn.execute("SELECT username, role FROM users").fetchall()
    return {"users": [dict(r) for r in rows]}


def _lab_fetch_allowed(url: str) -> tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        return False, "scheme"
    host = (parsed.hostname or "").lower()
    if host not in LAB_FETCH_ALLOWLIST:
        return False, "host"
    return True, "ok"


@app.get("/fetch")
async def fetch(url: str, authorization: str | None = Header(default=None)) -> JSONResponse:
    """Server-side fetch used to teach SSRF.

    Application filter (the lesson):
      LAB_MODE=true  -> application does not block metadata.internal
      LAB_MODE=false -> application blocks metadata and non-allowlisted hosts

    Safety rail (always on): only lab compose hostnames, http, limited ports.
    """
    user = current_user(authorization)
    allowed, reason = _lab_fetch_allowed(url)
    if not allowed:
        audit("fetch_blocked_safety_rail", actor=user["username"], url=url, reason=reason)
        raise HTTPException(status_code=400, detail="destination blocked by lab safety rail")

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    is_metadata = host in {"mock-imds", "metadata.internal"} or "/latest/meta-data" in (
        parsed.path or ""
    )
    if not LAB_MODE and is_metadata:
        audit("ssrf_blocked", actor=user["username"], url=url)
        raise HTTPException(status_code=400, detail="destination blocked")

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        audit("fetch_error", actor=user["username"], url=url, error=str(exc))
        raise HTTPException(status_code=502, detail="fetch failed") from exc

    if is_metadata:
        audit(
            "ssrf_metadata_access",
            actor=user["username"],
            url=url,
            status=response.status_code,
        )
    else:
        audit("fetch_ok", actor=user["username"], url=url, status=response.status_code)

    return JSONResponse(
        {
            "url": url,
            "status": response.status_code,
            "body": response.text[:2000],
            "warning": "AUTHORIZED LAB USE ONLY",
        }
    )


@app.get("/whoami")
def whoami(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = current_user(authorization)
    return user
