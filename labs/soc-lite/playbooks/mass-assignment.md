# Playbook: privileged field in profile update (API3:2023)

## Summary
A `PATCH /users/me` body named a privileged field such as `role` (`privileged_field_update`). `applied` says whether the server accepted it. In `LAB_MODE` every client-supplied field is trusted, so a user can make themselves an admin.

## Immediate actions (lab)
1. Check `applied`. `false` means the secure-mode validator rejected it: an attempt, not an escalation.
2. If `applied` is true, the role changed in the database but the user's current token still says `user`. The new role takes effect at next login. Look for a `login_success` with `role=admin` after the update.
3. Check what the account did as admin (`/admin/users`).
4. Snapshot logs. Open a case.

## ATT&CK starting points
- T1098 Account Manipulation

## Engineering fix
Bind requests to an explicit schema with only the fields a user may change, and reject unknown fields. Never copy a request body onto a database row.

## Containment options (simulated)
- `disable_lab_mode`
- `revoke_token_notice`
- Reset the role in the database and re-issue tokens

## Recovery
Redeploy with `LAB_MODE=false`. Confirm the same request returns 422 and the role is unchanged.
