"""Tiny JSON API + static page using only the standard library.

Identity is the X-User header. That is deliberately a stand-in for real auth (SSO/MFA):
fine for an MVP demo, never for a plant. See README "What I'd do next".
"""
from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .service import GateKeeper, Result

STATIC = Path(__file__).parent / "static"
AUTHZ = {"NOT_VENDOR", "NOT_SUPERVISOR", "SELF_APPROVAL", "NOT_AUTHORISED"}
CONFLICT = {"NOT_PENDING", "ALREADY_APPROVED", "EXPIRED", "ACTIVE_GRANT_EXISTS", "NOT_REVOCABLE"}
ACTION = re.compile(r"^/api/requests/(\d+)/(approve|reject|revoke)$")


def http_status(r: Result) -> int:
    if r.ok:
        return 201 if r.code == "CREATED" else 200
    if r.code == "UNKNOWN_USER":
        return 401
    if r.code == "NOT_FOUND":
        return 404
    if r.code in AUTHZ:
        return 403
    return 409 if r.code in CONFLICT else 422


def make_handler(gk: GateKeeper):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # the audit log is the record; keep the console quiet
            pass

        def _send(self, status, payload, ctype="application/json"):
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _result(self, r: Result):
            self._send(http_status(r), {"ok": r.ok, "code": r.code, "reason": r.reason, "data": r.data})

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/":
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                self._send(200, gk.snapshot())
            elif url.path == "/api/audit":
                self._send(200, {"entries": gk.audit_entries(50), "chain": gk.verify_audit()})
            elif url.path == "/api/access-check":
                q = parse_qs(url.query)
                r = gk.access_check(q.get("vendor", [""])[0], q.get("asset", [""])[0])
                self._send(200, {"allowed": r.ok, "reason": r.reason})
            else:
                self._send(404, {"ok": False, "code": "NOT_FOUND", "reason": "No such route."})

        def do_POST(self):
            actor = self.headers.get("X-User", "")
            try:
                size = min(int(self.headers.get("Content-Length") or 0), 10_000)
                body = json.loads(self.rfile.read(size) or b"{}")
                body = body if isinstance(body, dict) else {}
            except (ValueError, UnicodeDecodeError):
                body = {}  # malformed body -> empty fields -> a logged, validated refusal
            path = urlparse(self.path).path
            m = ACTION.match(path)
            if path == "/api/requests":
                self._result(gk.request_access(actor, body.get("asset"), body.get("reason"),
                                               body.get("start"), body.get("minutes")))
            elif m:
                rid, verb = int(m.group(1)), m.group(2)
                self._result(getattr(gk, verb)(actor, rid))
            else:
                self._send(404, {"ok": False, "code": "NOT_FOUND", "reason": "No such route."})

    return Handler


def main():
    p = argparse.ArgumentParser(description="GateKeeper MVP")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--db", default="gatekeeper.db")
    args = p.parse_args()
    gk = GateKeeper(args.db)
    stop = threading.Event()

    def sweeper():  # expiry with nobody clicking anything
        while not stop.wait(1.0):
            gk.sweep()

    threading.Thread(target=sweeper, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(gk))
    print(f"GateKeeper running on http://127.0.0.1:{args.port}  (db: {args.db})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()


if __name__ == "__main__":
    main()
