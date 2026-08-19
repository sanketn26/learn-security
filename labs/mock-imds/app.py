"""Synthetic instance metadata service. Dummy credentials only."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

DUMMY_CREDS = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "LABFAKEACCESSKEYID",
    "SecretAccessKey": "lab-fake-secret-access-key-not-real",
    "Token": "lab-fake-session-token-not-real",
    "Expiration": "2099-01-01T00:00:00Z",
    "warning": "AUTHORIZED LAB USE ONLY — dummy values, not valid cloud credentials",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def _send(self, code: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/health":
            self._send(200, b"ok")
            return
        if path in {"/", "/latest/meta-data"}:
            self._send(200, b"iam/\nlocal-ipv4\n")
            return
        if path == "/latest/meta-data/iam/security-credentials":
            self._send(200, b"lab-role")
            return
        if path == "/latest/meta-data/iam/security-credentials/lab-role":
            self._send(200, json.dumps(DUMMY_CREDS).encode(), "application/json")
            return
        if path == "/latest/meta-data/local-ipv4":
            self._send(200, b"172.30.0.10")
            return
        self._send(404, b"not found")


if __name__ == "__main__":
    import os

    port = int(os.getenv("PORT", "80"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
