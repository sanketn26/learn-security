# Playbook: path traversal in file access (A01:2025)

## Summary
A file name carried directory-climbing (`../`) or absolute-path syntax (`file_access` with `traversal` = `yes`). In `LAB_MODE` the name is joined onto the storage directory, so it can reach files outside it. The lab's safety rail stops anything outside its sandbox (`file_blocked_safety_rail`).

## Immediate actions (lab)
1. Identify `actor`, `op` (`read` or `write`), and `name`.
2. Look for `file_blocked_safety_rail` next to it: that means the attempt went past the sandbox and was stopped by the lab, not by the application.
3. A write is worse than a read. Check the sandbox for files you did not expect.
4. Snapshot logs. Open a case.

## ATT&CK starting points
- T1005 Data from Local System (read)
- T1190 Exploit Public-Facing Application

## Engineering fix
Never let the caller's string choose a path. Validate the name against an allowlist pattern, keep each user in their own directory, and verify the resolved path stays inside it. A generated storage name removes the problem entirely.

## Containment options (simulated)
- `disable_lab_mode`
- `snapshot_logs`

## Recovery
Redeploy with `LAB_MODE=false`. Confirm `../canary.txt` is rejected and that a normal upload and download still work.
