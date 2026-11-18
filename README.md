# GateKeeper (MVP)

Just-in-time vendor access for the Kestrel Valley Water Board. Vendors request access to **one asset**, for **15–240 minutes**, with **a reason**. Supervisors approve, access ends on its own, and everything is logged.

Python 3.10+ standard library only. No installs. SQLite for storage.

## Run it

```bash
python -m gatekeeper                       # http://127.0.0.1:8000  (db: ./gatekeeper.db)
python -m gatekeeper --port 9000 --db /tmp/demo.db
python -m unittest discover -t . -s tests -v     # 51 tests, ~0.1 s
```

Open the page and use **Acting as** (demo login) to switch between Karan/Meera (vendors), Asha/Joel (supervisors) and the admin. Try: Karan requests `PLC-07` → Asha approves → "waiting for 2nd supervisor" → Joel approves → countdown → revoke, or wait for it to expire.

API (identity is the `X-User` header): `GET /api/state` · `GET /api/audit` · `GET /api/access-check?vendor=karan&asset=PLC-07` · `POST /api/requests` `{asset, reason, start (ISO 8601 with tz), minutes}` · `POST /api/requests/{id}/approve|reject|revoke`.
`/api/access-check` is what a VPN gateway would call: the only thing that says "yes" to access.

## How the rules are enforced

| Rule | Where | Proved by |
|---|---|---|
| R1 vendor-only, one asset, reason, start, 15–240 min | `rules.decide_request` | `RequestRules`, `R1_Requests` |
| R2 supervisors only, never own request, 2 for high risk | `rules.decide_approval`; `approvals` primary key stops one supervisor counting twice | `ApprovalRules`, `R2_Approvals` |
| R3 active only inside `[start, end)`, auto-expiry | `rules.is_active` checks the clock on every access check; a 1 s sweeper also marks and logs expiry | `WindowRules`, `R3_Windows` |
| R4 revoke by supervisor/admin, instantly | `rules.decide_revoke`; effective in the same transaction | `R4_Revoke` |
| R5 every action incl. refused → audit | `service._log` / `_refuse` | `R5_Audit` |
| R6 one live grant per vendor+asset | `rules.decide_request` **and** a partial unique index in SQLite | `R6_OneGrantPerAsset` |

Layout: `rules.py` is pure (no I/O; `now` is passed in), `service.py` wraps each action in one lock and one transaction, `server.py` is a thin HTTP layer.

## Key decisions and trade-offs (where the brief was silent)

- **Expiry doesn't depend on a timer.** Access is computed from the clock at check time. The sweeper only updates status and writes the `grant.expired` audit entry. If it dies, access still ends on time.
- **The window is exactly what the vendor asked for.** Late approval doesn't extend it, and approving after it ended is refused.
- **End is exclusive.** At 03:05:00 a 02:05 + 60 min grant is already gone.
- **R6 = one *live* request per vendor+asset** (pending or approved), not just "currently active". Stricter: stops request spam and overlapping windows. Rejected, revoked and expired requests free the slot.
- **Two-person rule = two different supervisors.** Day/night shifts are *not* enforced: with only two supervisors, requiring "on shift" would make a high-risk approval impossible at any hour. Rostering is a next step.
- **Any one supervisor can reject**, even a high-risk request. Admin can revoke but not approve or reject.
- **Start must be within 24 h ahead** (2 min grace for the past). Timestamps without a timezone are refused, not guessed.
- **Audit log is append-only and hash-chained.** SQLite triggers reject UPDATE/DELETE, and each entry stores the previous hash so `/api/audit` can verify the chain and name the first tampered entry. That is tamper-*evident*, not tamper-*proof* (see next steps). A state change and its log entry commit atomically.
- **Gateway checks are logged too.** Noisy at scale, but it is the moment access actually matters. Plain reads of the request list are not logged.
- **Auth is faked** (`X-User` header + demo picker). Fine for the brief, unacceptable for production.
- **Thin UI**: vanilla JS, no build step, polls every 3 s; user text is rendered with `textContent`, so no HTML injection.

## What I'd do next

1. Real identity: SSO + MFA, roles from the identity provider; stop trusting a header.
2. Ship audit entries off-box (write-once storage/SIEM) and anchor the chain head externally, so a database admin can't rewrite history.
3. Integrate the gateway: issue and revoke short-lived per-asset VPN credentials, and kill live sessions at expiry/revoke.
4. Notifications (push/SMS to the second approver), supervisor roster/shift awareness, vendor "cancel request".
5. Rate limits, CSRF protection, TLS; Postgres with row-level locking if it runs on more than one instance.
6. Revoke reasons, an emergency "revoke all", and alerts on repeated refusals.

## Part B3 (UI/UX)

`design/b3-supervisor-mobile.html`: the supervisor mobile approve screen plus the "waiting for second approver" and "expired" states, with design rationale. Open it in a browser, or host it with GitHub Pages for a link.


## notes


- **Scaffolded by AI:** The overall architecture (pure `rules.py` + `service.py` + thin `server.py`), the SQLite schema including the R6 partial unique index, the hash-chained audit log pattern, and the HTML/CSS for both the web UI and the B3 mobile design were generated in response to the brief.
- **Reviewed and owned:** I read every line. I confirmed the rules (R1–R6) map correctly to the code and tests. I verified the two-person approval flow, the clock-based expiry logic (not timer-dependent), and the tamper-evident chain by running the tests and the smoke-test flows myself.
- **Decisions I made:** Where the brief was silent I made explicit calls — late approval does not extend the window, R6 blocks pending *and* approved (not just active) grants, shifts are not enforced because two supervisors can't cover a 24 h roster. These are in the README and I can defend them at interview.
- **What I changed:** The B3 design rationale section and the "Not shown yet" caveat are my own additions. I also added the full smoke-test script and confirmed the audit chain verification works end-to-end.
