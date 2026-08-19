# Playbook: password guessing (T1110.001)

## Summary
Repeated `login_failure` events from one source against the notes API.

## Immediate actions (lab)
1. Confirm the destination is `127.0.0.1:8080` / `lab-notes-api`.
2. Identify username(s) and `src_ip`.
3. Open a case. Preserve JSONL logs (`labs/scripts/preserve-logs.sh` if present, else copy `/logs`).
4. Do not lock real accounts. In this lab, continue investigating.

## Enrichment
- Count failures vs successes for the same `src_ip`.
- Check whether any `login_success` follows the burst (possible credential compromise).

## Containment options (simulated)
- `block_actor` against the source identifier
- Rotate `JWT_SECRET` if a success occurred
- Rate-limit `/login` in the application (engineering fix)

## Recovery
Restart notes-api after enabling rate limits. Document residual risk: no MFA in the lab app.
