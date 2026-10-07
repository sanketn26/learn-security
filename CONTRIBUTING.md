# Contributing

Thanks for helping. This is a defensive-security course; the labs are local
and intentionally vulnerable only behind `LAB_MODE`.

## Ground rules
- Offensive steps are labelled **AUTHORIZED LAB USE ONLY**, run against the
  loopback-bound compose stack, and use benign payloads. Do not weaken
  `assert_local` in `labs/attack-sim/simulate.py`.
- No real credentials or production logs. Dummy secrets use `lab-secret-*`,
  `lab-jwt-*`, or `LABFAKE`.
- Read [docs/ethics.md](docs/ethics.md) first.

## Setup
```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-docs.txt -r requirements-labs.txt
pip install -r requirements-workshop.txt   # only for the Semgrep workshop exercise
make test        # pytest, including doc front-matter and link checks
make docs-build  # mkdocs build --strict
```

## Docs changes
- Every page starts with YAML front matter containing a quoted `description`.
- Module pages also carry `last_reviewed: YYYY-MM-DD`. Bump it when you
  re-read the page against current sources.
- If you change what a module or lab exercises, update
  [docs/owasp-coverage.md](docs/owasp-coverage.md) in the same PR.
- Cite standards by ID and verify the ID against the source.

## Lab changes
- Any new vulnerable behavior sits behind `LAB_MODE`, has a secure-mode fix,
  and has a test proving secure mode blocks it.
- Add or update a detection and playbook if the change should be visible to
  the SOC modules.

## Pull requests
Use the PR template. CI runs the docs build, compose validation, shell checks,
the test suite, and CodeQL. Alerts CodeQL raises on intentionally vulnerable
lab code should be dismissed with a note, not silenced in code.

See [ROADMAP.md](ROADMAP.md) for planned work.
