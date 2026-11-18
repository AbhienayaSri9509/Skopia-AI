"""Edge cases of the pure rules (no database, no clock)."""
import unittest
from datetime import datetime, timedelta, timezone

from gatekeeper import rules
from gatekeeper.rules import Asset, Req, User

NOW = datetime(2026, 11, 20, 2, 0, tzinfo=timezone.utc)
VENDOR = User("karan", "Karan", "vendor")
ASHA = User("asha", "Asha", "supervisor")
JOEL = User("joel", "Joel", "supervisor")
ADMIN = User("admin", "Plant Admin", "admin")
MEDIUM, HIGH = Asset("PLC-03", "Filter backwash", "medium"), Asset("PLC-07", "Chlorine dosing", "high")


def req(status="pending", approvals=(), start_in=5, minutes=60, risk="medium"):
    start = NOW + timedelta(minutes=start_in)
    return Req(1, "karan", "PLC-03", risk, start, start + timedelta(minutes=minutes), status, approvals)


class RequestRules(unittest.TestCase):
    def ask(self, user=VENDOR, asset=MEDIUM, reason="Replace seal", start=NOW + timedelta(minutes=5),
            minutes=60, existing=()):
        return rules.decide_request(user, asset, reason, start, minutes, list(existing), NOW)

    def test_valid(self):
        self.assertTrue(self.ask().allow)

    def test_only_vendors_request(self):
        for u in (ASHA, ADMIN):
            self.assertEqual(self.ask(user=u).code, "NOT_VENDOR")

    def test_duration_bounds_are_inclusive(self):
        self.assertEqual(self.ask(minutes=14).code, "BAD_DURATION")
        self.assertTrue(self.ask(minutes=15).allow)
        self.assertTrue(self.ask(minutes=240).allow)
        self.assertEqual(self.ask(minutes=241).code, "BAD_DURATION")

    def test_duration_must_be_a_real_int(self):
        for bad in (True, 60.0, "60", None):
            self.assertEqual(self.ask(minutes=bad).code, "BAD_DURATION")

    def test_reason_required_and_bounded(self):
        for bad in ("", "   ", None, 123):
            self.assertEqual(self.ask(reason=bad).code, "REASON_REQUIRED")
        self.assertEqual(self.ask(reason="x" * 501).code, "REASON_TOO_LONG")

    def test_start_window(self):
        self.assertEqual(self.ask(start=None).code, "BAD_START")
        self.assertEqual(self.ask(start=NOW - timedelta(minutes=3)).code, "START_IN_PAST")
        self.assertTrue(self.ask(start=NOW - timedelta(minutes=1)).allow)  # inside grace
        self.assertTrue(self.ask(start=NOW + timedelta(hours=24)).allow)
        self.assertEqual(self.ask(start=NOW + timedelta(hours=24, seconds=1)).code, "START_TOO_FAR")

    def test_one_live_request_per_vendor_and_asset(self):
        self.assertEqual(self.ask(existing=[req()]).code, "ACTIVE_GRANT_EXISTS")
        self.assertEqual(self.ask(existing=[req("approved")]).code, "ACTIVE_GRANT_EXISTS")
        for done in ("rejected", "revoked", "expired"):
            self.assertTrue(self.ask(existing=[req(done)]).allow)

    def test_timestamp_parsing(self):
        self.assertIsNone(rules.parse_ts("2026-11-20T02:00:00"))  # naive: refused
        self.assertIsNone(rules.parse_ts("tomorrow"))
        self.assertEqual(rules.parse_ts("2026-11-20T07:30:00+05:30"), NOW)  # IST -> UTC


class ApprovalRules(unittest.TestCase):
    def test_supervisor_can_approve(self):
        self.assertTrue(rules.decide_approval(req(), ASHA, NOW).allow)

    def test_nobody_approves_their_own_request(self):
        self.assertEqual(rules.decide_approval(req(), VENDOR, NOW).code, "SELF_APPROVAL")
        own = Req(1, "asha", "PLC-03", "medium", NOW, NOW + timedelta(hours=1), "pending")
        self.assertEqual(rules.decide_approval(own, ASHA, NOW).code, "SELF_APPROVAL")

    def test_admin_cannot_approve(self):
        self.assertEqual(rules.decide_approval(req(), ADMIN, NOW).code, "NOT_SUPERVISOR")

    def test_same_supervisor_cannot_give_both_approvals(self):
        r = req(approvals=("asha",), risk="high")
        self.assertEqual(rules.decide_approval(r, ASHA, NOW).code, "ALREADY_APPROVED")
        self.assertTrue(rules.decide_approval(r, JOEL, NOW).allow)

    def test_cannot_approve_after_window_ends(self):
        r = req(start_in=5, minutes=15)  # ends 02:20
        self.assertTrue(rules.decide_approval(r, ASHA, r.end - timedelta(seconds=1)).allow)
        self.assertEqual(rules.decide_approval(r, ASHA, r.end).code, "EXPIRED")

    def test_only_pending_can_be_approved(self):
        for s in ("approved", "rejected", "revoked", "expired"):
            self.assertEqual(rules.decide_approval(req(s), ASHA, NOW).code, "NOT_PENDING")

    def test_approvals_needed_by_risk(self):
        self.assertEqual(rules.APPROVALS_NEEDED, {"medium": 1, "high": 2})


class WindowRules(unittest.TestCase):
    def test_active_only_inside_window_end_exclusive(self):
        r = req("approved", start_in=5, minutes=60)
        self.assertFalse(rules.is_active(r, r.start - timedelta(seconds=1)))
        self.assertTrue(rules.is_active(r, r.start))
        self.assertTrue(rules.is_active(r, r.end - timedelta(seconds=1)))
        self.assertFalse(rules.is_active(r, r.end))

    def test_pending_is_never_active(self):
        self.assertFalse(rules.is_active(req("pending"), NOW + timedelta(minutes=30)))

    def test_revoke(self):
        a = req("approved")
        self.assertTrue(rules.decide_revoke(a, ASHA, NOW).allow)
        self.assertTrue(rules.decide_revoke(a, ADMIN, NOW).allow)
        self.assertEqual(rules.decide_revoke(a, VENDOR, NOW).code, "NOT_AUTHORISED")
        self.assertEqual(rules.decide_revoke(req("pending"), ASHA, NOW).code, "NOT_REVOCABLE")
        self.assertEqual(rules.decide_revoke(a, ASHA, a.end).code, "NOT_REVOCABLE")

    def test_reject(self):
        self.assertTrue(rules.decide_reject(req(), ASHA, NOW).allow)
        self.assertEqual(rules.decide_reject(req(), ADMIN, NOW).code, "NOT_SUPERVISOR")
        self.assertEqual(rules.decide_reject(req("approved"), ASHA, NOW).code, "NOT_PENDING")


if __name__ == "__main__":
    unittest.main()
