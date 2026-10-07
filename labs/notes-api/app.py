"""Intentionally dual-mode notes API.

LAB_MODE=true enables documented vulnerabilities for authorized local labs.
A hard safety rail still blocks non-lab fetch destinations.

This file is not production software.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sqlite3
import time
import traceback
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import bcrypt
import httpx
import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from seed import NOTES, USERS

LAB_MODE = os.getenv("LAB_MODE", "true").lower() == "true"
JWT_SECRET = os.getenv("JWT_SECRET", "lab-jwt-secret-change-me-32b-min")
DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/notes.db")
LOG_PATH = os.getenv("LOG_PATH", "/logs/notes-api.jsonl")
MOCK_IMDS_URL = os.getenv("MOCK_IMDS_URL", "http://mock-imds")

# Lab safety rail for the file routes: even in LAB_MODE the path-traversal demo
# cannot touch anything outside this directory. Not a production control.
SANDBOX_DIR = os.getenv("SANDBOX_DIR", "/data/sandbox")
FILES_DIR = os.path.join(SANDBOX_DIR, "files")
CANARY_NAME = "canary.txt"
CANARY_TEXT = "LABFAKE-canary: reading this through /files means path traversal worked.\n"

# Lab safety rail: even in LAB_MODE, the process cannot fetch the public
# internet, file URLs, or the learner's host. This is not a production control.
LAB_FETCH_ALLOWLIST = {
    "mock-imds",
    "metadata.internal",
    "notes-api",
    "soc-lite",
    "agentic-soc",
}
LAB_FETCH_ALLOW_PORTS = {80, 8080, 8090, 8091}
# Optional extra names for the venv/no-Docker path. Never add public hosts.
LAB_FETCH_ALLOWLIST.update(
    h.strip().lower()
    for h in os.getenv("LAB_FETCH_EXTRA_HOSTS", "").split(",")
    if h.strip()
)

# OpenAPI UI is an extra attack surface. LAB_MODE leaves it on so you can
# see it; secure mode removes /docs, /redoc, and /openapi.json.
app = FastAPI(
    title="Lab Notes API",
    version="0.1.0",
    docs_url="/docs" if LAB_MODE else None,
    redoc_url="/redoc" if LAB_MODE else None,
    openapi_url="/openapi.json" if LAB_MODE else None,
)

# Browsers ignore HSTS on this loopback HTTP response. The value is what a
# TLS proxy in front of this app would forward.
_RESPONSE_HEADER_NAMES = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def _max_age_seconds(value: str) -> int:
    for part in value.split(";"):
        item = part.strip()
        if not item.lower().startswith("max-age="):
            continue
        raw = item.split("=", 1)[1].strip()
        try:
            return int(raw)
        except ValueError:
            return 0
    return 0


def describe_response_headers(headers: Any) -> dict[str, str]:
    """Classify six response headers as missing, weak, or set.

    Looks only at a header mapping you already have. It does not fetch a URL.
    "weak" means the header is present and does not do the job its name suggests.
    """
    folded = {str(key).lower(): str(value) for key, value in headers.items()}
    return {name: _describe_one_header(name, folded.get(name)) for name in _RESPONSE_HEADER_NAMES}


def _describe_one_header(name: str, value: str | None) -> str:
    if value is None or not value.strip():
        return "missing"
    text = value.strip().lower()
    if name == "strict-transport-security":
        return "set" if _max_age_seconds(text) > 0 else "weak"
    if name == "x-content-type-options":
        return "set" if text == "nosniff" else "weak"
    if name == "x-frame-options":
        return "set" if text in {"deny", "sameorigin"} else "weak"
    if name == "content-security-policy":
        sources = _default_src(text)
        return "weak" if sources is None or "*" in sources else "set"
    if name == "referrer-policy":
        return "set" if _effective_referrer_policy(text) in _STRICT_REFERRER_POLICIES else "weak"
    return "set"


_STRICT_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
}
_LEAKY_REFERRER_POLICIES = {"unsafe-url", "no-referrer-when-downgrade"}


def _default_src(policy: str) -> list[str] | None:
    """Source list of the first default-src directive, or None if there is none.

    Browsers use the first occurrence of a directive and ignore later ones.
    """
    for directive in policy.split(";"):
        tokens = directive.split()
        if tokens and tokens[0] == "default-src":
            return tokens[1:]
    return None


def _effective_referrer_policy(value: str) -> str | None:
    """The policy a browser applies: the last recognized token, or None.

    Unrecognized tokens are ignored by browsers, so garbage protects nothing.
    """
    known = _STRICT_REFERRER_POLICIES | _LEAKY_REFERRER_POLICIES
    recognized = [token.strip() for token in value.split(",") if token.strip() in known]
    return recognized[-1] if recognized else None


def _response_headers() -> dict[str, str]:
    if LAB_MODE:
        return {"Strict-Transport-Security": "max-age=0"}
    return {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }


@app.middleware("http")
async def attach_response_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in _response_headers().items():
        response.headers[name] = value
    return response


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
    try:
        return bcrypt.checkpw(password.encode(), stored.encode())
    except ValueError:
        # Stored verifier is not bcrypt (usually leftover LAB_MODE SHA-256).
        return False


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
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "display_name" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
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


def init_sandbox() -> None:
    os.makedirs(FILES_DIR, exist_ok=True)
    # Rewritten on every start: the traversal demo can overwrite it, and the
    # exercise output should not depend on what a previous run left behind.
    with open(os.path.join(SANDBOX_DIR, CANARY_NAME), "w", encoding="utf-8") as handle:
        handle.write(CANARY_TEXT)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    init_sandbox()
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
    port = parsed.port if parsed.port is not None else 80
    if port not in LAB_FETCH_ALLOW_PORTS:
        return False, "port"
    return True, "ok"


@app.get("/fetch")
async def fetch(url: str, authorization: str | None = Header(default=None)) -> JSONResponse:
    """Server-side fetch used to teach SSRF.

    Application filter (the lesson):
      LAB_MODE=true  -> application does not block metadata.internal
      LAB_MODE=false -> application blocks metadata and non-allowlisted hosts

    Safety rail (always on): only lab compose hostnames, http, ports 80/8080/8090/8091.
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


# ---------------------------------------------------------------------------
# Secure-coding workshop routes (Module 4b). Each has a LAB_MODE branch that is
# vulnerable on purpose and an else branch that is the reference fix.
# ---------------------------------------------------------------------------

_MARKUP_PATTERNS = (
    ("script", re.compile(r"<\s*script", re.IGNORECASE)),
    ("handler", re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)),
    ("js-url", re.compile(r"javascript:", re.IGNORECASE)),
)


def markup_kind(text: str) -> str:
    """Name the script-bearing markup in text, or "" if none. Used for logging only."""
    for kind, pattern in _MARKUP_PATTERNS:
        if pattern.search(text):
            return kind
    return ""


def _owned_note(note_id: int, user: dict[str, str]) -> sqlite3.Row:
    """Fetch a note; in secure mode, hide notes the caller may not read."""
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
    return row


@app.get("/notes/{note_id}/page", response_class=HTMLResponse)
def note_page(note_id: int, authorization: str | None = Header(default=None)) -> HTMLResponse:
    """Render a note as an HTML page. Teaches stored XSS (A05:2025, output encoding)."""
    user = current_user(authorization)
    row = _owned_note(note_id, user)
    audit(
        "note_render",
        actor=user["username"],
        note_id=note_id,
        owner=row["owner"],
        markup=markup_kind(row["title"] + " " + row["body"]),
    )
    if LAB_MODE:
        # AUTHORIZED LAB USE ONLY. Note text becomes HTML syntax.
        page = f"<html><body><h1>{row['title']}</h1><div>{row['body']}</div></body></html>"
    else:
        page = (
            f"<html><body><h1>{html.escape(row['title'])}</h1>"
            f"<div>{html.escape(row['body'])}</div></body></html>"
        )
    return HTMLResponse(page)


_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|^/|^[A-Za-z]:|%2e%2e)", re.IGNORECASE)
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def _in_sandbox(path: str) -> bool:
    root = os.path.realpath(SANDBOX_DIR)
    try:
        real = os.path.realpath(path)
    except ValueError:  # embedded NUL: not a path the lab will touch
        return False
    return real == root or real.startswith(root + os.sep)


def _file_target(user: dict[str, str], name: str) -> str:
    """Where a named file lives for this caller."""
    if LAB_MODE:
        # AUTHORIZED LAB USE ONLY. The caller's string chooses the path:
        # "../canary.txt" climbs out, and an absolute name replaces the base.
        return os.path.join(FILES_DIR, name)
    if not _SAFE_NAME_RE.fullmatch(name):
        audit("file_blocked", actor=user["username"], name=name, reason="bad_name")
        raise HTTPException(status_code=400, detail="invalid file name")
    base = os.path.join(FILES_DIR, user["username"])
    target = os.path.join(base, name)
    if os.path.commonpath([os.path.realpath(base), os.path.realpath(target)]) != os.path.realpath(base):
        audit("file_blocked", actor=user["username"], name=name, reason="outside_base")
        raise HTTPException(status_code=400, detail="invalid file name")
    return target


def _rail_check(user: dict[str, str], name: str, target: str) -> None:
    if not _in_sandbox(target):
        audit("file_blocked_safety_rail", actor=user["username"], name=name)
        raise HTTPException(status_code=400, detail="destination blocked by lab safety rail")


class FileUpload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    content: str = Field(max_length=10_000)


@app.post("/files")
def upload_file(body: FileUpload, authorization: str | None = Header(default=None)) -> dict[str, str]:
    """Store a small text file. Teaches path traversal (A01/A05:2025)."""
    user = current_user(authorization)
    # Log the attempt before validating it: a blocked probe is still a probe.
    audit(
        "file_access",
        actor=user["username"],
        op="write",
        name=body.name[:200],
        traversal="yes" if _TRAVERSAL_RE.search(body.name) else "",
    )
    target = _file_target(user, body.name)
    _rail_check(user, body.name, target)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(body.content)
    return {"name": body.name, "stored": os.path.relpath(target, SANDBOX_DIR)}


@app.get("/files")
def read_file(name: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    user = current_user(authorization)
    audit(
        "file_access",
        actor=user["username"],
        op="read",
        name=name[:200],
        traversal="yes" if _TRAVERSAL_RE.search(name) else "",
    )
    target = _file_target(user, name)
    _rail_check(user, name, target)
    if not os.path.isfile(target):
        raise HTTPException(status_code=404, detail="not found")
    with open(target, encoding="utf-8", errors="replace") as handle:
        return {"name": name, "content": handle.read(10_000)}


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(max_length=80)


_PRIVILEGED_FIELDS = {"role", "password_hash", "username"}
# Fixed statements, one per column. A safety rail: the lab's vulnerable branch
# can never let a caller choose a column name, only pick from these two.
_UPDATE_SQL = {
    "display_name": "UPDATE users SET display_name = ? WHERE username = ?",
    "role": "UPDATE users SET role = ? WHERE username = ?",
}


@app.patch("/users/me")
def update_me(
    body: dict[str, Any], authorization: str | None = Header(default=None)
) -> dict[str, str]:
    """Update your profile. Teaches mass assignment (API3:2023)."""
    user = current_user(authorization)
    fields = sorted(body)
    audit("profile_update", actor=user["username"], fields=fields)
    privileged = sorted(_PRIVILEGED_FIELDS & set(body))
    if privileged:
        audit(
            "privileged_field_update",
            actor=user["username"],
            fields=privileged,
            applied=LAB_MODE,
        )
    if LAB_MODE:
        # AUTHORIZED LAB USE ONLY. Every client-supplied key is trusted.
        updates = {k: v for k, v in body.items() if k in _UPDATE_SQL}
    else:
        try:
            updates = ProfileUpdate.model_validate(body).model_dump()
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="unknown or invalid field") from exc
    with db() as conn:
        for column, value in updates.items():
            conn.execute(_UPDATE_SQL[column], (value, user["username"]))
        row = conn.execute(
            "SELECT username, display_name, role FROM users WHERE username = ?",
            (user["username"],),
        ).fetchone()
    return dict(row)


_EXPORTERS = {
    "json": lambda row: json.dumps(dict(row)),
    "csv": lambda row: ",".join(str(row[k]) for k in ("id", "owner", "title")),
}
LAB_TENANT = 1


def _tenant_allows(user: dict[str, str], row: sqlite3.Row, x_tenant: str | None) -> bool:
    """Illustrative policy: the caller's tenant header must match, and the note must be theirs."""
    tenant = int(x_tenant) if x_tenant is not None else LAB_TENANT  # ValueError on "abc"
    return tenant == LAB_TENANT and (row["owner"] == user["username"] or user["role"] == "admin")


@app.get("/notes/{note_id}/export")
def export_note(
    note_id: int,
    format: str = "json",
    x_tenant: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Export a note. Teaches A10:2025: failing open, and leaking error detail."""
    user = current_user(authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT id, owner, title, body, visibility FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
    if row is None:
        # Secure mode answers "missing" and "not yours" identically, so the
        # route cannot be used to find out which note ids exist.
        raise HTTPException(
            status_code=404 if LAB_MODE else 403,
            detail="not found" if LAB_MODE else "forbidden",
        )
    try:
        allowed = _tenant_allows(user, row, x_tenant)
    except Exception as exc:  # noqa: BLE001 - the lesson is what this handler decides
        if LAB_MODE:
            # AUTHORIZED LAB USE ONLY. The policy crashed, so the code lets the request through.
            audit(
                "authz_fail_open",
                actor=user["username"],
                note_id=note_id,
                owner=row["owner"],
                error=repr(exc),
            )
            allowed = True
        else:
            audit("authz_error_denied", actor=user["username"], note_id=note_id, error=repr(exc))
            raise HTTPException(status_code=403, detail="forbidden") from exc
    if not allowed:
        audit("authz_failure", reason="export_denied", actor=user["username"], note_id=note_id)
        raise HTTPException(status_code=403, detail="forbidden")
    try:
        data = _EXPORTERS[format](row)
    except Exception:  # noqa: BLE001
        ref = uuid.uuid4().hex[:8]
        audit("export_error", actor=user["username"], note_id=note_id, format=format, ref=ref)
        if LAB_MODE:
            # AUTHORIZED LAB USE ONLY. Internals go to the client.
            return JSONResponse(
                status_code=500,
                content={"error": "export failed", "traceback": traceback.format_exc()},
            )
        raise HTTPException(status_code=400, detail=f"unsupported format (ref {ref})") from None
    return {"note_id": note_id, "format": format, "data": data}


@app.get("/whoami")
def whoami(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = current_user(authorization)
    return user
