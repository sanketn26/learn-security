# ATT&CK coverage matrix (draft)

Fill during module 8 and the capstone from **observed alerts**, then confirm
IDs on https://attack.mitre.org/. The rows below are a *shape example* from
`labs/detections/rules.yaml`, not a completed assignment. Coverage here is
**visibility of lab procedures**, not organizational security.

| Detection | Data source | Tactic | Technique ID | Technique | Confidence | Limitation / gap |
| --- | --- | --- | --- | --- | --- | --- |
| DET-001 | notes-api JSONL `login_failure` | Credential Access | T1110.001 | Password Guessing | high | Misses slow guessing; shared NAT src_ip |
| DET-002 | `cross_user_note_access` | Collection | T1213 | Data from Information Repositories | medium | Vulnerability is BOLA; T1190 also plausible |
| DET-003 | `ssrf_metadata_access` | Credential Access | T1552.005 | Cloud Instance Metadata API | high | Dummy IMDS; blocked attempts may not fire |
| DET-004 | `broken_function_authz` | Discovery | T1087 | Account Discovery | medium | Function-level bug; not OS account enum |
| DET-005 | `search` + SQL metacharacters | Initial Access | T1190 | Exploit Public-Facing Application | medium | Regex FP on legitimate titles |
| (gap) | none | Persistence | — | — | n/a | Not emulated; do not paint the cell |

Procedure notes:

- T1110.001 — six HTTP POSTs to `/login` with wrong passwords.
- T1213 / BOLA — `GET /notes/2` as alice.
- T1552.005 — `/fetch?url=http://mock-imds/...`
- T1087 — `GET /admin/users` as alice.
- T1190 — concatenated SQL in `/search` (benign payload).
