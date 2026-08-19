# One-page condensed learning plan

**Goal:** In ~90 hours, go from “strong engineer, weak security ops” to
shipping a tiny defensive platform you can explain end to end.

**Daily habit (30–45 min):** read one ATT&CK technique *or* threat-model one
PR. Do not install a new tool instead.

| Block | Hours | You can leave when… |
| --- | --- | --- |
| Ethics + lab up | 2 | Loopback health 200; you can reset volumes |
| Foundations + net/OS | 8 | Trust diagram; you know what your logs/ports are |
| IAM + app/API | 12 | You fixed IDOR/search/admin in LAB_MODE=false |
| Cloud/containers + crypto | 10 | You can explain IMDS + password hashing |
| Logs + ATT&CK | 10 | Five mapped detections |
| Red/blue/purple + SOC | 12 | Purple report; a case with a timeline |
| Detections + IR | 10 | Incident report + RCA |
| Agentic SOC | 8 | 403 without APPROVE; grounded summary |
| Architecture + future | 6 | Review + judgment memo |
| Capstone polish | 12 | Rubric ≥ 80 |

**Do:** local only; dummy data; write residual risk.
**Do not:** scan the internet; paste prod logs into models; skip AuthZ
because “we have detections.”

**Commands you will actually use:**

```bash
make lab-up
python3 labs/attack-sim/simulate.py --scenario all
curl -s -X POST http://127.0.0.1:8090/ingest
curl -s http://127.0.0.1:8091/investigate -H 'Content-Type: application/json' \
  -d '{"alert_id":"<id>"}'
make lab-reset
```
