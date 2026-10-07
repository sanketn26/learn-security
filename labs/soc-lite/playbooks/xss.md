# Playbook: stored XSS in a rendered note (A05:2025)

## Summary
A note containing script-bearing markup was rendered by `GET /notes/{id}/page` (`note_render` with `markup` = `script`, `handler`, or `js-url`). In `LAB_MODE` the note text is spliced into HTML, so the markup would run in a viewer's browser.

## Immediate actions (lab)
1. Identify `actor`, `note_id`, and `owner`. The author and the viewer may differ; both matter.
2. Read the note body in the database, not in a browser.
3. Check whether anyone other than the author rendered it. That is the difference between a payload and an incident.
4. Snapshot logs. Open a case.

## ATT&CK starting points
- T1059.007 JavaScript (only if script actually executed in a victim browser)
- T1190 Exploit Public-Facing Application

A rendered payload is evidence of the weakness. Execution in a browser is a separate claim that needs separate evidence.

## Engineering fix
Encode for the output context (HTML escaping here). Treat a Content-Security-Policy as defense in depth, not the fix: secure mode sends `default-src 'none'` and also escapes.

## Containment options (simulated)
- `disable_lab_mode` (enables output encoding)
- `snapshot_logs`
- Add a regression test that stores a script payload and parses the response

## Recovery
Redeploy with `LAB_MODE=false`. Re-render the note and confirm the page contains text, not an element.
