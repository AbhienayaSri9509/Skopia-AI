"""End-to-end behaviour: rules + database + clock + audit log."""
import sqlite3
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone

from gatekeeper import GateKeeper
from gatekeeper.rules import fmt_ts

T0 = datetime(2026, 11, 20, 2, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock(T0)
        self.gk = GateKeeper(":memory:", self.clock)

    def ask(self, asset="PLC-03", who="karan", start_in=5, minutes=60, reason="Replace worn seal"):
        start = fmt_ts(self.clock.t + timedelta(minutes=start_in))
        return self.gk.request_access(who, asset, reason, start, minutes)

    def ask_ok(self, **kw):
        r = self.ask(**kw)
        self.assertTrue(r.ok, r.reason)
        return r.data["id"]

    def approved(self, asset="PLC-03", **kw):
        rid = self.ask_ok(asset=asset, **kw)
        self.assertTrue(self.gk.approve("asha", rid).ok)
        if asset in ("PLC-07", "HMI-02"):
            self.assertTrue(self.gk.approve("joel", rid).ok)
        return rid

    def active(self, vendor="karan", asset="PLC-03"):
        return self.gk.access_check(vendor, asset).ok

    def status(self, rid):
        return next(r for r in self.gk.snapshot()["requests"] if r["id"] == rid)

    def log(self):
        return list(reversed(self.gk.audit_entries(1000)))

    def last(self):
        return self.log()[-1]


class R1_Requests(Base):
    def test_vendor_request_is_pending_not_active(self):
        rid = self.ask_ok()
        self.assertEqual(self.status(rid)["status"], "pending")
        self.clock.advance(minutes=10)
        self.assertFalse(self.active())

    def test_supervisor_and_admin_cannot_request(self):
        for who in ("asha", "admin"):
            self.assertEqual(self.ask(who=who).code, "NOT_VENDOR")

    def test_unknown_user_and_asset_and_bad_input_are_refused(self):
        self.assertEqual(self.ask(who="mallory").code, "UNKNOWN_USER")
        self.assertEqual(self.ask(asset="PLC-99").code, "UNKNOWN_ASSET")
        self.assertEqual(self.ask(minutes=10).code, "BAD_DURATION")
        self.assertEqual(self.ask(reason=" ").code, "REASON_REQUIRED")
        self.assertEqual(self.gk.request_access("karan", "PLC-03", "x", "not-a-time", 30).code, "BAD_START")
        self.assertEqual(self.gk.request_access("karan", {"a": 1}, "x", None, None).code, "UNKNOWN_ASSET")

    def test_nothing_was_stored_for_refused_requests(self):
        self.ask(minutes=10)
        self.assertEqual(self.gk.snapshot()["requests"], [])


class R2_Approvals(Base):
    def test_medium_risk_needs_one_supervisor(self):
        rid = self.ask_ok(asset="PLC-05")
        self.assertTrue(self.gk.approve("asha", rid).ok)
        self.assertEqual(self.status(rid)["status"], "approved")

    def test_vendors_and_admin_cannot_approve(self):
        rid = self.ask_ok()
        self.assertEqual(self.gk.approve("karan", rid).code, "SELF_APPROVAL")
        self.assertEqual(self.gk.approve("meera", rid).code, "NOT_SUPERVISOR")
        self.assertEqual(self.gk.approve("admin", rid).code, "NOT_SUPERVISOR")
        self.assertEqual(self.status(rid)["status"], "pending")

    def test_high_risk_needs_two_different_supervisors(self):
        rid = self.ask_ok(asset="PLC-07")
        first = self.gk.approve("asha", rid)
        self.assertTrue(first.ok)
        self.assertEqual(first.data["phase"], "awaiting_second")
        self.clock.advance(minutes=10)
        self.assertFalse(self.active(asset="PLC-07"))        # one approval is not access
        self.assertEqual(self.gk.approve("asha", rid).code, "ALREADY_APPROVED")
        self.assertEqual(self.status(rid)["status"], "pending")
        self.assertTrue(self.gk.approve("joel", rid).ok)
        self.assertTrue(self.active(asset="PLC-07"))

    def test_hmi_is_high_risk_too(self):
        rid = self.ask_ok(asset="HMI-02")
        self.gk.approve("joel", rid)
        self.assertEqual(self.status(rid)["status"], "pending")

    def test_reject_ends_request_and_frees_the_slot(self):
        rid = self.ask_ok()
        self.assertTrue(self.gk.reject("asha", rid).ok)
        self.assertEqual(self.gk.approve("joel", rid).code, "NOT_PENDING")
        self.assertTrue(self.ask().ok)

    def test_unknown_request(self):
        self.assertEqual(self.gk.approve("asha", 999).code, "NOT_FOUND")
        self.assertEqual(self.gk.approve("asha", "1; DROP TABLE requests").code, "NOT_FOUND")


class R3_Windows(Base):
    def test_active_only_inside_window(self):
        self.approved(start_in=5, minutes=60)               # 02:05 - 03:05
        self.assertFalse(self.active())                     # 02:00 before start
        self.clock.advance(minutes=5)
        self.assertTrue(self.active())                      # 02:05 exactly at start
        self.clock.advance(minutes=59, seconds=59)
        self.assertTrue(self.active())                      # 03:04:59
        self.clock.advance(seconds=1)
        self.assertFalse(self.active())                     # 03:05:00 end is exclusive

    def test_expiry_happens_with_nobody_clicking(self):
        rid = self.approved(start_in=1, minutes=15)
        self.clock.advance(minutes=16)
        self.gk.sweep()                                     # the background timer, nothing else
        self.assertEqual(self.status(rid)["status"], "expired")
        entry = next(e for e in self.log() if e["action"] == "grant.expired")
        self.assertEqual((entry["actor"], entry["request_id"], entry["outcome"]), ("system", rid, "allowed"))
        self.assertFalse(self.active())

    def test_expiry_is_logged_once(self):
        self.approved(start_in=1, minutes=15)
        self.clock.advance(hours=1)
        self.gk.sweep(); self.gk.sweep(); self.gk.snapshot()
        self.assertEqual([e["action"] for e in self.log()].count("grant.expired"), 1)

    def test_unapproved_requests_expire_too(self):
        rid = self.ask_ok(start_in=1, minutes=15)
        self.clock.advance(minutes=20)
        self.gk.sweep()
        self.assertEqual(self.status(rid)["status"], "expired")
        self.assertIn("request.expired", [e["action"] for e in self.log()])

    def test_half_approved_high_risk_request_expires_without_access(self):
        rid = self.ask_ok(asset="PLC-07", start_in=1, minutes=15)
        self.gk.approve("asha", rid)
        self.clock.advance(minutes=30)
        self.assertEqual(self.gk.approve("joel", rid).code, "NOT_PENDING")
        self.assertFalse(self.active(asset="PLC-07"))

    def test_late_approval_does_not_extend_the_window(self):
        rid = self.ask_ok(start_in=1, minutes=60)           # 02:01 - 03:01
        self.clock.advance(minutes=50)                      # approved at 02:50
        self.gk.approve("asha", rid)
        self.assertTrue(self.active())
        self.clock.advance(minutes=11)                      # 03:01
        self.assertFalse(self.active())

    def test_expired_grant_is_not_revocable_and_slot_is_free(self):
        rid = self.approved(start_in=1, minutes=15)
        self.clock.advance(minutes=30)
        self.assertEqual(self.gk.revoke("asha", rid).code, "NOT_REVOCABLE")
        self.assertTrue(self.ask().ok)


class R4_Revoke(Base):
    def test_supervisor_revokes_instantly(self):
        rid = self.approved(start_in=0, minutes=60)
        self.assertTrue(self.active())
        self.assertTrue(self.gk.revoke("joel", rid).ok)
        self.assertFalse(self.active())                     # same instant, no waiting
        self.assertEqual(self.status(rid)["status"], "revoked")

    def test_admin_can_revoke_but_vendor_cannot(self):
        rid = self.approved(start_in=0)
        self.assertEqual(self.gk.revoke("karan", rid).code, "NOT_AUTHORISED")
        self.assertTrue(self.active())
        self.assertTrue(self.gk.revoke("admin", rid).ok)
        self.assertFalse(self.active())

    def test_can_revoke_a_grant_that_has_not_started(self):
        rid = self.approved(start_in=30)
        self.assertTrue(self.gk.revoke("asha", rid).ok)
        self.clock.advance(minutes=45)
        self.assertFalse(self.active())

    def test_pending_cannot_be_revoked_and_double_revoke_refused(self):
        pending = self.ask_ok(who="meera")
        self.assertEqual(self.gk.revoke("asha", pending).code, "NOT_REVOCABLE")
        rid = self.approved()
        self.gk.revoke("asha", rid)
        self.assertEqual(self.gk.revoke("asha", rid).code, "NOT_REVOCABLE")


class R5_Audit(Base):
    def test_every_action_is_logged_including_refusals(self):
        rid = self.ask_ok()
        self.gk.approve("karan", rid)                        # refused
        self.gk.approve("asha", rid)                         # allowed
        self.gk.revoke("karan", rid)                         # refused
        self.gk.revoke("asha", rid)                          # allowed
        self.ask(minutes=5)                                  # refused
        self.gk.approve("asha", 4242)                        # refused
        got = [(e["actor"], e["action"], e["outcome"]) for e in self.log()]
        self.assertEqual(got, [
            ("karan", "request.create", "allowed"),
            ("karan", "request.approve", "denied"),
            ("asha", "request.approve", "allowed"),
            ("karan", "grant.revoke", "denied"),
            ("asha", "grant.revoke", "allowed"),
            ("karan", "request.create", "denied"),
            ("asha", "request.approve", "denied"),
        ])

    def test_refusal_entry_says_why(self):
        self.gk.request_access("karan", "PLC-03", "x", "bad", 30)
        self.assertIn("BAD_START", self.last()["reason"])

    def test_unknown_actors_are_logged_with_bounded_size(self):
        self.gk.approve("x" * 500, 1)
        self.assertEqual(len(self.last()["actor"]), 64)
        self.assertEqual(self.last()["outcome"], "denied")

    def test_gateway_checks_are_logged(self):
        self.active()
        self.assertEqual((self.last()["action"], self.last()["outcome"]), ("access.check", "denied"))

    def test_log_is_append_only(self):
        self.ask_ok()
        for sql in ("UPDATE audit SET reason='edited'", "DELETE FROM audit"):
            with self.assertRaises(sqlite3.DatabaseError):
                self.gk.db.execute(sql)

    def test_chain_verifies_and_detects_tampering(self):
        rid = self.ask_ok()
        self.gk.approve("asha", rid)
        self.assertEqual(self.gk.verify_audit(), {"ok": True, "entries": 2, "broken_at": None})
        self.gk.db.execute("DROP TRIGGER audit_no_update")   # an attacker with raw DB access
        self.gk.db.execute("UPDATE audit SET actor='joel' WHERE seq=2")
        self.assertEqual(self.gk.verify_audit(), {"ok": False, "entries": 2, "broken_at": 2})

    def test_state_change_and_log_commit_together(self):
        rid = self.ask_ok()
        before = len(self.log())
        with mock.patch.object(self.gk, "_log", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                self.gk.approve("asha", rid)                 # the log write fails mid-operation
        self.assertEqual(self.status(rid)["status"], "pending")
        self.assertEqual(self.status(rid)["approved_by"], [])  # the approval was rolled back too
        self.assertEqual(len(self.log()), before)


class R6_OneGrantPerAsset(Base):
    def test_second_request_blocked_while_pending_or_approved(self):
        rid = self.ask_ok()
        self.assertEqual(self.ask().code, "ACTIVE_GRANT_EXISTS")
        self.gk.approve("asha", rid)
        self.assertEqual(self.ask().code, "ACTIVE_GRANT_EXISTS")

    def test_other_asset_or_other_vendor_is_fine(self):
        self.ask_ok()
        self.assertTrue(self.ask(asset="PLC-05").ok)
        self.assertTrue(self.ask(who="meera").ok)

    def test_slot_frees_after_revoke_and_expiry(self):
        rid = self.approved(start_in=0, minutes=15)
        self.gk.revoke("asha", rid)
        rid2 = self.ask_ok()
        self.gk.approve("asha", rid2)
        self.clock.advance(minutes=90)
        self.assertTrue(self.ask().ok)

    def test_database_refuses_a_second_live_request_even_if_the_rules_were_bypassed(self):
        self.ask_ok()
        with self.assertRaises(sqlite3.IntegrityError):
            self.gk.db.execute(
                "INSERT INTO requests (vendor_id, asset_id, reason, minutes, start_ts, end_ts, created_ts, status)"
                " VALUES ('karan','PLC-03','x',30,'2026-11-20T03:00:00Z','2026-11-20T03:30:00Z','2026-11-20T02:00:00Z','pending')")


if __name__ == "__main__":
    unittest.main()
