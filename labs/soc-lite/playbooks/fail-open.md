# Playbook: authorization failed open (A10:2025)

## Summary
The authorization check raised an error and the request was allowed anyway (`authz_fail_open`). In `LAB_MODE` a malformed `X-Tenant` header makes the policy crash, and the exception handler returns "allowed". Related events: `export_error` (an unhandled failure, which in `LAB_MODE` also returns a stack trace to the client).

## Immediate actions (lab)
1. Identify `actor`, `note_id`, `owner`, and the `error` text.
2. A malformed header is a probe. Look for other requests from the same actor.
3. Check whether data left: a fail-open event on a note the actor does not own is a confirmed disclosure.
4. Snapshot logs. Open a case.

## ATT&CK starting points
- T1213 Data from Information Repositories
- T1190 Exploit Public-Facing Application

## Engineering fix
Fail closed: when a security decision cannot be made, deny and log. Catch narrowly. Return a generic error with a reference id, and keep stack traces in the log.

## Containment options (simulated)
- `disable_lab_mode`
- `snapshot_logs`

## Recovery
Redeploy with `LAB_MODE=false`. Confirm the malformed header returns 403 and a normal export still works.
