---
description: Set up the local Docker security lab, verify its safety declaration, and identify its components before running any attack scenarios.
---

# Setup and first lab

The first success criterion is intentionally small: start the local system,
read its safety declaration, and identify its components. Do not run attack
scenarios until the safety check passes.

## Choose a setup

| Path | Use when | What you need |
| --- | --- | --- |
| Standard | You can run containers | Docker or Podman with Compose, Python 3, curl |
| Read-only preview | You want to learn before installing tools | A browser; read the examples below |
| Lightweight host path | Containers are unavailable | Python virtual environments and [`requirements-labs.txt`](https://github.com/sanketn26/learn-security/blob/main/requirements-labs.txt); see [lab guide](lab-guide.md) |

Git and `jq` are helpful but not required. Kubernetes, packet-capture tools,
image scanners, and an LLM are optional later — or skip installing them
entirely and use the [optional toolbox image](#optional-toolbox-image)
below, which has them preloaded.

## Standard setup

One command checks your required dependencies, starts the stack, and
verifies the safety banner:

```bash
make check-setup
```

It fails fast with an install hint if Docker, `docker compose`, Python 3,
or curl is missing, so you know what to fix before anything starts. Expected
on success: Compose starts `notes-api`, `mock-imds`, `soc-lite`, and
`agentic-soc`, and the script prints the safety banner and `lab_mode: true`.
First build may take several minutes.

To do the same steps by hand instead:

```bash
docker info
python3 --version
curl --version
chmod +x labs/scripts/*.sh
make lab-up
```

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

## No git installed? Skip the clone

`check-setup.sh` only needs the `labs/` files on disk — the stack is built
from source, not pulled as pre-built images — so a plain tarball works
just as well as `git clone` and doesn't require `git` at all:

```bash
curl -fsSL https://github.com/sanketn26/learn-security/archive/refs/heads/main.tar.gz | tar -xz
cd learn-security-main
./labs/scripts/check-setup.sh
```

This downloads and extracts an archive, then runs a script that's already
sitting on your disk for you to read first — not a blind `curl | bash`.
If you plan to come back and contribute changes, `git clone` is still the
better choice; this is for a fast first look.

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

## Host path (no Docker)

**Docker Compose is preferred.** Use this path only when you cannot run
containers. It is the same lab, less isolation: you are responsible for
binding to loopback and for not pointing fetch allowlists at non-lab hosts.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-labs.txt
```

`requirements-labs.txt` unifies the pins from `labs/notes-api`,
`labs/soc-lite`, and `labs/agentic-soc`, plus `pytest` for the Module 4
assignment. Do not add extra packages to “make the host path work.”

Then follow the [lab guide](lab-guide.md) no-Docker notes: run `mock-imds`
on `PORT=18080`, set `LAB_FETCH_EXTRA_HOSTS=127.0.0.1` only on your
workstation, and bind notes-api, soc-lite, and agentic-soc to `127.0.0.1`.

## Optional toolbox image

Modules 2, 5, and 8 mention optional tools (`tshark`/`tcpdump`, `trivy`,
`kubectl`, `jq`, `sqlite3`) you don't need to install on your host. A
preloaded Alpine image has them, gated behind a compose profile so it never
starts by default:

```bash
cd labs
docker compose --profile toolbox run --rm toolbox
```

See [labs/toolbox/README.md](https://github.com/sanketn26/learn-security/blob/main/labs/toolbox/README.md)
for what's in it and what's deliberately left out (no Docker socket, no
LLM runtime).

## Troubleshooting

| Symptom | Check | Recovery |
| --- | --- | --- |
| `docker` not found | Docker/Podman installation | Use read-only preview meanwhile |
| Port already in use | `docker compose -f labs/compose.yaml ps` and local services | Stop only the conflicting service or change the lab port deliberately |
| Health endpoint not ready | `docker compose -f labs/compose.yaml logs notes-api` | Wait for build/startup; retry health |
| Login data behaves unexpectedly | Previous volumes/mode | `make lab-reset`, then `make lab-up` (wipes lab-only state) |
| Laptop is resource constrained | Memory/CPU use | Run only the default stack; skip kind and local LLM |
| Container fails to start with a bind-mount error mentioning a `rules.yaml` or similar file | You extracted/cloned the repo under `/tmp` or another path your Docker VM doesn't share (common with Colima; Docker Desktop usually shares the whole filesystem) | Move the repo under your home directory and retry — `docker compose up` |

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

