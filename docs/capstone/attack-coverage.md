---
description: "Blank ATT&CK coverage matrix template for the capstone: one row per detection, mapped from the alerts you observed, with confidence and limitations."
---

# ATT&CK coverage matrix (fill in)

Start this in the Module 8 lab. Copy it to
`docs/capstone/work/attack-coverage.md` and fill in the copy, not this file.

Fill each row from an **observed alert**, then check the ID on
https://attack.mitre.org/. Coverage here means you can see the lab's
procedures. It says nothing about the security of a whole organisation.

The capstone needs eight detections: DET-001–005 plus three you write
yourself (see the [capstone brief](README.md)). Give every detection its own
row in this table rather than starting a second one. Add at least one gap row
for a behaviour the sim never generates.

| Detection | Data source | Tactic | Technique ID | Technique | Confidence | Limitation / gap |
| --- | --- | --- | --- | --- | --- | --- |
| DET-00X | `<event name>` in notes-api JSONL | | T#### | | low / medium / high | What this rule misses, and why the mapping might be wrong |
| (gap) | none | | — | — | n/a | Not emulated. Write “no data source” rather than colouring the cell in. |

## Procedure notes

One line per technique: the request or action you actually saw in the lab
that justifies the mapping.

-
