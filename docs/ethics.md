# Ethics, scope, and lab safety

This course is **defensive**. Every technical exercise is restricted to an
intentionally vulnerable local lab that you control. The goal is to understand
how attacks work so you can design, detect, and respond — not to practice
unauthorized access.

## Binding rules

1. **Only attack systems you own or that this lab starts for you.**
   The provided applications, containers, and synthetic logs are in scope.
   Your employer’s systems, classmates’ machines, public websites, and cloud
   accounts you do not fully control are **out of scope**.

2. **No instructions in this course are authorization to test a real system.**
   Written authorization, a defined scope, and rules of engagement are required
   before any security test outside this lab. “I was learning” is not a defense.

3. **Do not reuse lab payloads, scanners, or scripts against production.**
   Lab exploits are simplified, instrumented, and safety-railed. They are not
   a pentest toolkit.

4. **Do not steal credentials, deploy malware, or evade law enforcement.**
   Simulated “secrets” in this repo are dummy values (`lab-secret-*`). Treat
   even dummy secrets as if they were real while they live on disk.

5. **Mark offensive material as authorized lab use only.**
   Scripts under `labs/attack-sim/` refuse non-local targets. Do not patch
   that check out.

6. **Clean up.** Every lab has rollback instructions. Stop containers, delete
   volumes, and remove generated logs when you finish a session.

## What “authorized lab use only” means

When you see that phrase, the step demonstrates adversary-like behavior
**inside the isolated compose network**. The behavior is:

- generated against `127.0.0.1` published ports or Docker-internal hostnames
- instrumented so defenders can see it
- constrained by a **lab safety rail** that blocks outbound internet and
  non-lab destinations even when the application is in `LAB_MODE=true`

The safety rail is a teaching control. Do not confuse it with a production
control. In production you still need application allowlists, identity,
network policy, and detection.

## Data handling

- Prefer synthetic logs and dummy tokens.
- Do not paste real production logs, customer data, or live credentials into
  the lab, into an LLM prompt, or into issue trackers.
- If you optionally use a hosted LLM for the agentic SOC lab, assume prompts
  may be retained by the provider. Use only lab data.

## Cleanup and rollback (global)

From the repository root:

```bash
./labs/scripts/lab-down.sh          # stop containers
./labs/scripts/lab-reset.sh         # stop, delete volumes, wipe local state
docker compose -f labs/compose.yaml down -v
```

If a lab process is running on the host (not in Docker):

```bash
pkill -f "uvicorn app:app" || true
rm -rf labs/data labs/logs labs/cases
```

## Reporting issues

If a lab step would require bypassing the local-only check, accessing a
non-lab host, or disabling TLS verification against a real service, **stop**.
That step is out of scope. Open an issue against the course materials instead.
