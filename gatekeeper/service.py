"""GateKeeper service: SQLite persistence + hash-chained audit log around the pure rules.

Every public method runs under one lock and one DB transaction, so a state change and
its audit entry commit together or not at all. Refused actions are logged too (R5).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import rules
from .rules import Asset, Req, User, fmt_ts, parse_ts

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, org TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('vendor','supervisor','admin')));
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, risk TEXT NOT NULL CHECK (risk IN ('medium','high')));
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_id TEXT NOT NULL REFERENCES users(id),
  asset_id TEXT NOT NULL REFERENCES assets(id),
  reason TEXT NOT NULL, minutes INTEGER NOT NULL,
  start_ts TEXT NOT NULL, end_ts TEXT NOT NULL, created_ts TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','revoked','expired')));
-- R6 backstop: the database itself refuses a second live request per vendor+asset.
CREATE UNIQUE INDEX IF NOT EXISTS one_live_per_vendor_asset
  ON requests(vendor_id, asset_id) WHERE status IN ('pending','approved');
CREATE TABLE IF NOT EXISTS approvals (
  request_id INTEGER NOT NULL REFERENCES requests(id),
  supervisor_id TEXT NOT NULL REFERENCES users(id), ts TEXT NOT NULL,
  PRIMARY KEY (request_id, supervisor_id));  -- same supervisor cannot approve twice
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, request_id INTEGER, outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied')),
  reason TEXT NOT NULL, details TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

USERS = [
    ("asha", "Asha", "KVWB day shift", "supervisor"),
    ("joel", "Joel", "KVWB night shift", "supervisor"),
    ("karan", "Karan", "Aquilon Pumps", "vendor"),
    ("meera", "Meera", "Brightline Controls", "vendor"),
    ("admin", "Plant Admin", "KVWB", "admin"),
]
ASSETS = [
    ("PLC-03", "Filter backwash", "medium"),
    ("PLC-05", "Intake pumps", "medium"),
    ("PLC-07", "Chlorine dosing", "high"),
    ("HMI-02", "Operator screen", "high"),
]

SELECT_REQ = """SELECT r.*, v.name AS vendor_name, v.org AS org, a.name AS asset_name, a.risk AS risk
                FROM requests r JOIN users v ON v.id = r.vendor_id JOIN assets a ON a.id = r.asset_id"""


@dataclass
class Result:
    ok: bool
    code: str
    reason: str
    data: Any = None


def _digest(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


class GateKeeper:
    def __init__(self, path: str = ":memory:", clock: Callable[[], datetime] | None = None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        with self.db:
            self.db.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?)", USERS)
            self.db.executemany("INSERT OR IGNORE INTO assets VALUES (?,?,?)", ASSETS)

    # ------------------------------------------------------------------ time
    def _now(self) -> datetime:
        return self.clock().astimezone(timezone.utc).replace(microsecond=0)

    def _tick(self) -> datetime:
        """Read the clock and expire anything whose window has ended."""
        now = self._now()
        due = self.db.execute(
            "SELECT id, status, end_ts FROM requests WHERE status IN ('pending','approved') AND end_ts <= ?",
            (fmt_ts(now),)).fetchall()
        for r in due:
            self.db.execute("UPDATE requests SET status='expired' WHERE id=?", (r["id"],))
            kind = "grant.expired" if r["status"] == "approved" else "request.expired"
            self._log(now, "system", kind, "allowed", "Window ended; access removed automatically.",
                      r["id"], {"window_end": r["end_ts"], "was": r["status"]})
        return now

    def sweep(self) -> None:
        """Called by a background timer so expiry never waits for a click (R3).
        Correctness does not depend on it: is_active() checks the clock directly."""
        with self.lock, self.db:
            self._tick()

    # ----------------------------------------------------------------- audit
    def _log(self, now, actor, action, outcome, reason, request_id=None, details=None):
        last = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else GENESIS
        clean = {k: (v[:200] if isinstance(v, str) else v) for k, v in (details or {}).items()}
        d = json.dumps(clean, sort_keys=True, default=str)
        ts, actor = fmt_ts(now), str(actor)[:64]
        h = _digest(prev, ts, actor, action, request_id, outcome, reason, d)
        self.db.execute(
            "INSERT INTO audit (ts, actor, action, request_id, outcome, reason, details, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?,?)", (ts, actor, action, request_id, outcome, reason, d, prev, h))

    def _refuse(self, now, actor, action, decision, request_id=None, details=None) -> Result:
        self._log(now, actor, action, "denied", f"{decision.code}: {decision.reason}", request_id, details)
        return Result(False, decision.code, decision.reason)

    def audit_entries(self, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r, details=json.loads(r["details"])) for r in rows]

    def verify_audit(self) -> dict:
        """Recompute the whole hash chain; report the first broken entry, if any."""
        with self.lock:
            rows = self.db.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        prev = GENESIS
        for r in rows:
            expect = _digest(prev, r["ts"], r["actor"], r["action"], r["request_id"],
                             r["outcome"], r["reason"], r["details"])
            if r["prev_hash"] != prev or r["hash"] != expect:
                return {"ok": False, "entries": len(rows), "broken_at": r["seq"]}
            prev = r["hash"]
        return {"ok": True, "entries": len(rows), "broken_at": None}

    # --------------------------------------------------------------- lookups
    def _user(self, uid) -> User | None:
        row = self.db.execute("SELECT id, name, role FROM users WHERE id=?", (uid,)).fetchone() \
            if isinstance(uid, str) else None
        return User(**dict(row)) if row else None

    def _asset(self, aid) -> Asset | None:
        row = self.db.execute("SELECT id, name, risk FROM assets WHERE id=?", (aid,)).fetchone() \
            if isinstance(aid, str) else None
        return Asset(**dict(row)) if row else None

    def _req(self, row) -> Req:
        approvals = tuple(a["supervisor_id"] for a in self.db.execute(
            "SELECT supervisor_id FROM approvals WHERE request_id=? ORDER BY ts, supervisor_id", (row["id"],)))
        return Req(row["id"], row["vendor_id"], row["asset_id"], row["risk"],
                   parse_ts(row["start_ts"]), parse_ts(row["end_ts"]), row["status"], approvals)

    def _load(self, rid) -> Req | None:
        row = self.db.execute(SELECT_REQ + " WHERE r.id=?", (rid,)).fetchone()
        return self._req(row) if row else None

    def _live_requests(self, vendor_id, asset_id) -> list[Req]:
        rows = self.db.execute(
            SELECT_REQ + " WHERE r.vendor_id=? AND r.asset_id=? AND r.status IN ('pending','approved')",
            (vendor_id, asset_id)).fetchall()
        return [self._req(r) for r in rows]

    def _view(self, row, now) -> dict:
        req = self._req(row)
        who = self.db.execute("SELECT u.id, u.name, p.ts FROM approvals p JOIN users u ON u.id=p.supervisor_id "
                              "WHERE p.request_id=? ORDER BY p.ts, u.id", (row["id"],)).fetchall()
        return {
            "id": row["id"], "vendor": row["vendor_id"], "vendor_name": row["vendor_name"], "org": row["org"],
            "asset": row["asset_id"], "asset_name": row["asset_name"], "risk": row["risk"],
            "reason": row["reason"], "minutes": row["minutes"], "start": row["start_ts"], "end": row["end_ts"],
            "status": req.status, "phase": rules.phase(req, now), "active": rules.is_active(req, now),
            "approved_by": [dict(w) for w in who], "approvals_needed": rules.APPROVALS_NEEDED[row["risk"]],
        }

    def _view_id(self, rid, now) -> dict:
        return self._view(self.db.execute(SELECT_REQ + " WHERE r.id=?", (rid,)).fetchone(), now)

    # ------------------------------------------------------------ operations
    def request_access(self, actor_id, asset_id, reason, start, minutes) -> Result:
        details = {"asset": asset_id, "start": start, "minutes": minutes, "reason": reason}
        with self.lock, self.db:
            now = self._tick()
            user = self._user(actor_id)
            if user is None:
                return self._refuse(now, actor_id, "request.create",
                                    rules.no("UNKNOWN_USER", "Unknown user."), None, details)
            asset = self._asset(asset_id)
            start_dt = parse_ts(start)
            d = rules.decide_request(user, asset, reason, start_dt, minutes,
                                     self._live_requests(user.id, asset.id) if asset else [], now)
            if not d.allow:
                return self._refuse(now, user.id, "request.create", d, None, details)
            end_dt = start_dt + timedelta(minutes=minutes)
            cur = self.db.execute(
                "INSERT INTO requests (vendor_id, asset_id, reason, minutes, start_ts, end_ts, created_ts, status)"
                " VALUES (?,?,?,?,?,?,?, 'pending')",
                (user.id, asset.id, reason.strip(), minutes, fmt_ts(start_dt), fmt_ts(end_dt), fmt_ts(now)))
            rid = cur.lastrowid
            self._log(now, user.id, "request.create", "allowed", "Request submitted.", rid,
                      {**details, "start": fmt_ts(start_dt), "end": fmt_ts(end_dt), "risk": asset.risk})
            return Result(True, "CREATED", "Request submitted.", self._view_id(rid, now))

    def _act(self, actor_id, request_id, action, decide, apply) -> Result:
        with self.lock, self.db:
            now = self._tick()
            rid = request_id if isinstance(request_id, int) else None
            user = self._user(actor_id)
            if user is None:
                return self._refuse(now, actor_id, action, rules.no("UNKNOWN_USER", "Unknown user."), rid)
            req = self._load(rid) if rid is not None else None
            if req is None:
                return self._refuse(now, user.id, action, rules.no("NOT_FOUND", "No such request."), rid)
            d = decide(req, user, now)
            if not d.allow:
                return self._refuse(now, user.id, action, d, req.id)
            message, details = apply(req, user, now)
            self._log(now, user.id, action, "allowed", message, req.id, details)
            return Result(True, "OK", message, self._view_id(req.id, now))

    def approve(self, actor_id, request_id) -> Result:
        def apply(req, user, now):
            self.db.execute("INSERT INTO approvals VALUES (?,?,?)", (req.id, user.id, fmt_ts(now)))
            have, need = len(req.approvals) + 1, rules.APPROVALS_NEEDED[req.risk]
            details = {"approvals": have, "needed": need}
            if have >= need:
                self.db.execute("UPDATE requests SET status='approved' WHERE id=?", (req.id,))
                return "Approved. Access is active inside the requested window.", details
            return "First approval recorded; a second supervisor must approve.", details
        return self._act(actor_id, request_id, "request.approve", rules.decide_approval, apply)

    def reject(self, actor_id, request_id) -> Result:
        def apply(req, user, now):
            self.db.execute("UPDATE requests SET status='rejected' WHERE id=?", (req.id,))
            return "Request rejected.", {}
        return self._act(actor_id, request_id, "request.reject", rules.decide_reject, apply)

    def revoke(self, actor_id, request_id) -> Result:
        def apply(req, user, now):
            self.db.execute("UPDATE requests SET status='revoked' WHERE id=?", (req.id,))
            return "Grant revoked; access ended immediately.", {"revoked_at": fmt_ts(now)}
        return self._act(actor_id, request_id, "grant.revoke", rules.decide_revoke, apply)

    def access_check(self, vendor_id, asset_id) -> Result:
        """What a VPN gateway would call before letting a vendor reach an asset.
        Logged too (R5): it is the moment the access decision actually matters."""
        with self.lock, self.db:
            now = self._tick()
            active = any(rules.is_active(r, now) for r in self._live_requests(vendor_id, asset_id))
            reason = "Active grant." if active else "No active grant."
            self._log(now, "gateway", "access.check", "allowed" if active else "denied", reason,
                      None, {"vendor": vendor_id, "asset": asset_id})
            return Result(active, "ACTIVE" if active else "NO_ACTIVE_GRANT", reason)

    def snapshot(self) -> dict:
        with self.lock, self.db:
            now = self._tick()
            rows = self.db.execute(SELECT_REQ + " ORDER BY r.id DESC").fetchall()
            return {
                "now": fmt_ts(now),
                "users": [dict(r) for r in self.db.execute("SELECT id, name, org, role FROM users")],
                "assets": [dict(r) for r in self.db.execute("SELECT id, name, risk FROM assets")],
                "requests": [self._view(r, now) for r in rows],
            }
