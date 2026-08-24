# Lab toolbox (optional)

An Alpine-based image with the CLI tools this course's optional steps ask
for — `trivy`, `tshark`/`tcpdump`, `kubectl`, `jq`, `sqlite3`, `python3` —
already installed, so you don't have to install them on your host. Nothing
in the required path (`docs/setup.md`) depends on this image.

Published to `ghcr.io/sanketn26/learn-security-toolbox`.

## Use with the lab stack

The toolbox is on the same networks as `notes-api`, `soc-lite`, and
`agentic-soc`, so it can reach them by service name. It is gated behind a
compose **profile** so `make lab-up` / `docker compose up` never starts it
by default:

```bash
cd labs
docker compose --profile toolbox run --rm toolbox
# inside the container:
curl -s http://notes-api:8080/health
sqlite3 --version
trivy --version
```

## Use standalone

```bash
docker run --rm -it ghcr.io/sanketn26/learn-security-toolbox:latest
```

## What's intentionally not in here

No `docker` CLI and no mounted Docker socket — the toolbox never gets
control of the host's containers, only network access to the lab services.
No Ollama/LLM runtime — that stays a host-level optional install per
Module 12. If you need `kind` (Module 5's optional Kubernetes step), run it
on the host; a nested `kind`-in-container setup is out of scope here.
