"""Pure business rules for GateKeeper (R1-R6).

No I/O and no clock in here: every function receives `now`, so each rule is easy to
test at its edges. Each decision is Decision(allow, code, reason). The code is stable
(used by tests and the API); the reason is a sentence a person can read.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

MIN_MINUTES, MAX_MINUTES = 15, 240            # R1
MAX_LEAD = timedelta(hours=24)                # a request may start at most 24h ahead
START_GRACE = timedelta(minutes=2)            # tolerate slow typing / small clock skew
MAX_REASON_LEN = 500
APPROVALS_NEEDED = {"medium": 1, "high": 2}   # R2
LIVE = ("pending", "approved")                # statuses that can still lead to access
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class User:
    id: str
    name: str
    role: str  # vendor | supervisor | admin


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    risk: str  # medium | high


@dataclass(frozen=True)
class Req:
    id: int
    vendor_id: str
    asset_id: str
    risk: str
    start: datetime
    end: datetime
    status: str  # pending | approved | rejected | revoked | expired
    approvals: tuple = ()  # supervisor ids


@dataclass(frozen=True)
class Decision:
    allow: bool
    code: str
    reason: str


def _ok(reason: str = "Allowed.") -> Decision:
    return Decision(True, "OK", reason)


def no(code: str, reason: str) -> Decision:
    return Decision(False, code, reason)


def parse_ts(value) -> datetime | None:
    """ISO-8601 with an explicit timezone -> UTC, whole seconds. None if unusable."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:  # naive times are ambiguous; refuse rather than guess
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TS_FORMAT)


def is_active(req: Req, now: datetime) -> bool:
    """R3: access exists only for an approved grant, inside [start, end)."""
    return req.status == "approved" and req.start <= now < req.end


def phase(req: Req, now: datetime) -> str:
    """What a human should see for this request right now."""
    if req.status == "pending":
        return "awaiting_second" if req.approvals else "awaiting_first"
    if req.status == "approved":
        if now >= req.end:
            return "expired"
        return "active" if now >= req.start else "scheduled"
    return req.status


def decide_request(user, asset, reason, start, minutes, existing, now) -> Decision:
    """R1 + R6. `start` is already parsed (None if unparsable); `existing` is the
    vendor's live requests for this asset."""
    if user.role != "vendor":
        return no("NOT_VENDOR", "Only vendors can request access (R1).")
    if asset is None:
        return no("UNKNOWN_ASSET", "That asset does not exist.")
    if not isinstance(reason, str) or not reason.strip():
        return no("REASON_REQUIRED", "A reason is required.")
    if len(reason.strip()) > MAX_REASON_LEN:
        return no("REASON_TOO_LONG", f"Reason must be at most {MAX_REASON_LEN} characters.")
    if start is None:
        return no("BAD_START", "Start time must be ISO 8601 with a timezone, e.g. 2026-11-20T02:00:00Z.")
    if type(minutes) is not int or not MIN_MINUTES <= minutes <= MAX_MINUTES:
        return no("BAD_DURATION", f"Duration must be a whole number of minutes, {MIN_MINUTES}-{MAX_MINUTES} (R1).")
    if start < now - START_GRACE:
        return no("START_IN_PAST", "Start time is in the past.")
    if start > now + MAX_LEAD:
        return no("START_TOO_FAR", "Start time is more than 24 hours away.")
    for r in existing:
        if r.vendor_id == user.id and r.asset_id == asset.id and r.status in LIVE and now < r.end:
            return no("ACTIVE_GRANT_EXISTS",
                      f"You already have a {r.status} request/grant for {asset.id} (R6).")
    return _ok("Request is valid.")


def decide_approval(req: Req, approver: User, now: datetime) -> Decision:
    """R2 + R3: who may approve, and when."""
    if approver.id == req.vendor_id:
        return no("SELF_APPROVAL", "Nobody can approve their own request (R2).")
    if approver.role != "supervisor":
        return no("NOT_SUPERVISOR", "Only supervisors can approve (R2).")
    if req.status != "pending":
        return no("NOT_PENDING", f"This request is already {req.status}.")
    if now >= req.end:
        return no("EXPIRED", "The requested window has already ended (R3).")
    if approver.id in req.approvals:
        return no("ALREADY_APPROVED",
                  "You already approved this; a different supervisor must give the second approval (R2).")
    return _ok("Approval accepted.")


def decide_reject(req: Req, user: User, now: datetime) -> Decision:
    if user.role != "supervisor":
        return no("NOT_SUPERVISOR", "Only supervisors can reject requests.")
    if req.status != "pending":
        return no("NOT_PENDING", f"This request is already {req.status}.")
    if now >= req.end:
        return no("EXPIRED", "The requested window has already ended.")
    return _ok("Rejection accepted.")


def decide_revoke(req: Req, user: User, now: datetime) -> Decision:
    """R4."""
    if user.role not in ("supervisor", "admin"):
        return no("NOT_AUTHORISED", "Only a supervisor or admin can revoke (R4).")
    if req.status != "approved":
        return no("NOT_REVOCABLE", f"Only an approved grant can be revoked; this one is {req.status}.")
    if now >= req.end:
        return no("NOT_REVOCABLE", "This grant has already ended.")
    return _ok("Revocation accepted.")
