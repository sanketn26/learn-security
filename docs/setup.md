# Setup and first lab

The first success criterion is intentionally small: start the local system,
read its safety declaration, and identify its components. Do not run attack
scenarios until the safety check passes.

## Choose a setup

| Path | Use when | What you need |
| --- | --- | --- |
| Standard | You can run containers | Docker or Podman with Compose, Python 3, curl |
| Read-only preview | You want to learn before installing tools | A browser; read the examples below |
| Lightweight host path | Containers are unavailable | Python virtual environments; see [lab guide](lab-guide.md) |

Git and `jq` are helpful but not required. Kubernetes, packet-capture tools,
image scanners, and an LLM are optional later.

## Standard setup

From the repository root:

```bash
docker info
python3 --version
curl --version
chmod +x labs/scripts/*.sh
make lab-up
```

Expected: Compose starts `notes-api`, `mock-imds`, `soc-lite`, and
`agentic-soc`. First build may take several minutes.

Verify the safety boundary:

```bash
curl -s http://127.0.0.1:8080/.well-known/lab
curl -s http://127.0.0.1:8080/health
```

Typical bodies (keys may be reordered):

```json
{"warning":"AUTHORIZED LAB USE ONLY","scope":"local Docker compose network learn-security-labnet","do_not":"use against any system you do not own"}
{"ok":true,"lab_mode":true}
```

Checklist, not JSON fields:

- the URL host is loopback (`127.0.0.1` or `localhost`);
- `lab_mode` is true on `/health`;
- credentials in later labs are synthetic only.

Stop if the target is not loopback. Read the
[ethics and scope rules](ethics.md) before generating abnormal behavior.

## Your first observation

```bash
docker compose -f labs/compose.yaml ps
docker logs lab-notes-api --tail 5
```

Answer:

1. Which ports are published?
2. Are they bound to loopback?
3. Which process emits application events?
4. Where will a detection engine receive those events?

You have now completed a security task: you verified exposure and identified
an evidence path before testing the system.

## Read-only preview

If you cannot run containers yet, inspect these files in the repository:

- `labs/compose.yaml`: services, networks, volumes, and loopback bindings;
- `labs/notes-api/app.py`: routes and audit events;
- `labs/detections/rules.yaml`: events converted into alerts;
- `labs/agentic-soc/policy.yaml`: permitted and approval-gated actions.

Then draw:

```text
caller -> API -> data
            |
            v
          events -> detection -> alert
```

This is enough to begin Module 1 on paper. Modules 2–3 are richer with the
stack up; return to the runnable lab no later than Module 4.

Next: [How defenders think](how-defenders-think.md), then
[Module 1](modules/01-security-foundations.md).

## Troubleshooting

| Symptom | Check | Recovery |
| --- | --- | --- |
| `docker` not found | Docker/Podman installation | Use read-only preview meanwhile |
| Port already in use | `docker compose -f labs/compose.yaml ps` and local services | Stop only the conflicting service or change the lab port deliberately |
| Health endpoint not ready | `docker compose -f labs/compose.yaml logs notes-api` | Wait for build/startup; retry health |
| Login data behaves unexpectedly | Previous volumes/mode | `make lab-reset`, then `make lab-up` (wipes lab-only state) |
| Laptop is resource constrained | Memory/CPU use | Run only the default stack; skip kind and local LLM |

## Cleanup and rollback

```bash
make lab-down     # stop; preserve volumes
make lab-reset    # stop and wipe lab-only volumes
```

`make lab-reset` is destructive to the local lab state, including generated
alerts and cases. It does **not** delete host copies under `labs/evidence/`
created by `preserve-logs.sh`. Preserve first when a later exercise asks you
to, then reset.

Next: [How defenders think](how-defenders-think.md), then
[Module 1 — Security foundations](modules/01-security-foundations.md).

