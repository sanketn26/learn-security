# Playbook: broken access control (A01:2025 / API1:2023)

## Summary
An authenticated user read another user's object (`cross_user_note_access`) or called `/admin/users` without an admin role.

## Immediate actions (lab)
1. Identify `actor`, `note_id`, `owner`.
2. Treat note `body` as sensitive even though it is dummy data.
3. Snapshot logs. Open a case.

## ATT&CK starting points
- T1213 Data from Information Repositories
- T1087 Account Discovery
- T1190 Exploit Public-Facing Application (if the IDOR is the access path)

Mappings need context. IDOR is an application weakness; ATT&CK describes the adversary behavior you observed.

## Containment options (simulated)
- `disable_lab_mode` (enables owner checks)
- `revoke_token_notice` (rotate JWT secret)
- Patch object-level authorization and add regression tests

## Recovery
Redeploy with `LAB_MODE=false`. Verify Alice cannot read note 2. Notify "users" (lab write-up only).
