# Playbook: SSRF to instance metadata (T1552.005)

## Summary
The application fetched the synthetic metadata service. In a cloud environment this can yield temporary credentials.

## Immediate actions (lab)
1. Confirm the URL host is `mock-imds` or `metadata.internal`.
2. Treat returned keys as **compromised dummy credentials**.
3. Snapshot logs. Open a case with severity critical.

## Why this matters in production
Workload identity, IMDS hop limits, IMDSv2, and network policy exist because SSRF plus metadata is a common cloud credential path. See CISA and cloud provider IMDS guidance.

## Containment options (simulated)
- `disable_lab_mode` (application blocks metadata hosts)
- `revoke_token_notice`
- Restrict server-side fetch to an allowlist of business URLs (not metadata)

## Recovery
Rotate dummy secrets in the write-up. Keep the lab safety rail enabled. Add a regression test that `/fetch?url=http://mock-imds/...` returns 400.
