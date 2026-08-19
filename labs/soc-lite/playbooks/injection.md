# Playbook: injection in search (A05:2025)

## Summary
A search query contained SQL metacharacters. In `LAB_MODE` the query is concatenated into SQL.

## Immediate actions (lab)
1. Capture `actor`, `q`, and whether extra rows were returned.
2. Do not run additional destructive SQL. The lab payload should be benign.

## Engineering fix
Use parameterized queries. Never concatenate untrusted input into SQL, LDAP, OS commands, or prompt templates.

## Containment options (simulated)
- `disable_lab_mode`
- Snapshot logs
